use std::borrow::Cow;
use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use jwt::{AlgorithmType, Header, ToBase64};
use jwt::header::HeaderType;
use rust_util::{util_msg, util_time, XResult};
use rust_util::util_clap::{Command, CommandError};
use serde_json::{Map, Number, Value};
use yubikey::{Certificate, YubiKey};
use yubikey::piv::{AlgorithmId, sign_data};

use crate::{digest, pinutil, pivutil, rsautil, util};

const SEPARATOR: &str = ".";

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "sign-jwt" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("Sign JWT subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).help("PIV card user PIN"))
            .arg(Arg::with_name("slot").short("s").long("slot").takes_value(true).help("PIV slot, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e"))
            .arg(Arg::with_name("key-id").short("K").long("key-id").takes_value(true).help("Header key ID"))
            .arg(Arg::with_name("claims").short("C").long("claims").takes_value(true).multiple(true).help("Claims, key:value"))
            .arg(Arg::with_name("payload").short("P").long("payload").takes_value(true).help("Claims in JSON"))
            .arg(Arg::with_name("jti").long("jti").help("Claims jti"))
            .arg(Arg::with_name("validity").long("validity").takes_value(true).help("Claims validity period e.g. 10m means 10 minutes (s - second, m - minute, h - hour, d - day)"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let mut json = BTreeMap::<&'_ str, String>::new();

        let pin_opt = sub_arg_matches.value_of("pin");
        let pin_opt = pinutil::get_pin(pin_opt);
        let pin_opt = pin_opt.as_deref();
        let slot = opt_value_result!(
            sub_arg_matches.value_of("slot"), "--slot must assigned, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e");

        let key_id = sub_arg_matches.value_of("key-id");
        let claims = sub_arg_matches.values_of("claims");
        let payload = sub_arg_matches.value_of("payload");
        let validity = sub_arg_matches.value_of("validity");
        let jti = sub_arg_matches.is_present("jti");

        let header = Header {
            key_id: key_id.map(ToString::to_string),
            type_: Some(HeaderType::JsonWebToken),
            ..Default::default()
        };
        let mut jwt_claims = Map::new();
        if let Some(payload) = payload {
            match serde_json::from_str::<Value>(payload) {
                Ok(Value::Object(claims_map)) => {
                    claims_map.into_iter().for_each(|(k, v)| {
                        jwt_claims.insert(k, v);
                    });
                }
                Ok(value) => { warning!("Not valid payload map: {}", value); }
                Err(e) => { warning!("Not valid payload value: {}", e); }
            };
        }

        match (payload, claims) {
            (Some(_), None) => {}
            (_, Some(claims)) => {
                for claim in claims {
                    match split_claim(claim) {
                        None => { warning!("Claim '{}' do not contains ':'", claim); }
                        Some((k, v)) => { jwt_claims.insert(k, v); }
                    }
                }
                if !jwt_claims.contains_key("sub") {
                    return simple_error!("Claim sub is not assigned.");
                }
            }
            _ => return simple_error!("Payload or Claims is required."),
        }

        // set jti, iat and sub
        if jti && !jwt_claims.contains_key("jti") {
            jwt_claims.insert("jti".to_string(), Value::String(format!("jti-{}", util_time::get_current_millis())));
        }
        if let Some(validity) = validity {
            match util_time::parse_duration(validity) {
                None => { warning!("Bad validity: {}", validity) }
                Some(validity) => {
                    let current_secs = (util_time::get_current_millis() / 1000) as u64;
                    jwt_claims.insert("iat".to_string(), Value::Number(Number::from(current_secs)));
                    jwt_claims.insert("exp".to_string(), Value::Number(Number::from(current_secs + validity.as_secs())));
                }
            }
        }

        let token_string = sign_jwt(slot, &pin_opt, header, &payload, &jwt_claims)?;
        success!("Singed JWT: {}", token_string);
        if json_output { json.insert("token", token_string.clone()); }

        if json_output {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        Ok(None)
    }
}


fn sign_jwt(slot: &str, pin_opt: &Option<&str>, mut header: Header, payload: &Option<&str>, claims: &Map<String, Value>) -> XResult<String> {
    let mut yk = opt_result!(YubiKey::open(), "Find YubiKey failed: {}");
    let slot_id = opt_result!(pivutil::get_slot_id(slot), "Get slot id failed: {}");

    if let Some(pin) = pin_opt {
        opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");
    }

    let cert = match Certificate::read(&mut yk, slot_id) {
        Ok(c) => c,
        Err(e) => return simple_error!("Read YubiKey certificate failed: {}", e),
    };
    let piv_algorithm_id = pivutil::get_algorithm_id(&cert.cert.tbs_certificate.subject_public_key_info)?;

    let (jwt_algorithm, yk_algorithm) = match piv_algorithm_id {
        AlgorithmId::Rsa1024 => return simple_error!("RSA 1024 bits not supported."),
        AlgorithmId::Rsa2048 => (AlgorithmType::Rs256, AlgorithmId::Rsa2048),
        AlgorithmId::EccP256 => (AlgorithmType::Es256, AlgorithmId::EccP256),
        AlgorithmId::EccP384 => (AlgorithmType::Es384, AlgorithmId::EccP384),
    };

    header.algorithm = jwt_algorithm;
    debugging!("Header: {:?}", header);
    debugging!("Claims: {:?}", claims);

    let header = opt_result!(header.to_base64(), "Header to base64 failed: {}");
    let claims = match (payload, claims.is_empty()) {
        (Some(payload), true) => Cow::Owned(util::base64_encode_url_safe_no_pad(payload.as_bytes())),
        (_, _) => opt_result!(claims.to_base64(), "Claims to base64 failed: {}"),
    };

    let mut tobe_signed = vec![];
    tobe_signed.extend_from_slice(header.as_bytes());
    tobe_signed.extend_from_slice(SEPARATOR.as_bytes());
    tobe_signed.extend_from_slice(claims.as_bytes());
    let raw_in = match jwt_algorithm {
        AlgorithmType::Rs256 => rsautil::pkcs15_sha256_rsa_2048_padding_for_sign(
            &digest::sha256_bytes(&tobe_signed)),
        AlgorithmType::Es256 => digest::sha256_bytes(&tobe_signed),
        AlgorithmType::Es384 => digest::sha384_bytes(&tobe_signed),
        _ => return simple_error!("SHOULD NOT HAPPEN: {:?}", jwt_algorithm),
    };

    let signed_data = opt_result!(
        sign_data(&mut yk, &raw_in, yk_algorithm, slot_id), "Sign YubiKey failed: {}");

    let signature = util::base64_encode_url_safe_no_pad(signed_data);

    Ok([&*header, &*claims, &signature].join(SEPARATOR))
}

fn split_claim(claim: &str) -> Option<(String, Value)> {
    let mut k = String::new();
    let mut v = String::new();

    let mut claim_chars = claim.chars().peekable();
    let ty = if let Some('^') = claim_chars.peek() {
        let _ = claim_chars.next();
        claim_chars.next()
    } else {
        None
    };
    let mut is_k = true;
    for c in claim_chars {
        if is_k {
            if c == ':' {
                is_k = false;
            } else {
                k.push(c);
            }
        } else {
            v.push(c);
        }
    }

    if is_k {
        return None;
    }

    match ty {
        None | Some('s') => Some((k, Value::String(v))),
        Some('b') => Some((k, Value::Bool(["true", "yes", "1"].contains(&v.as_str())))),
        Some('i') | Some('n') => {
            if let Ok(i) = v.parse::<i64>() {
                return Some((k, Value::Number(Number::from(i))));
            }
            if let Ok(f) = v.parse::<f64>() {
                if let Some(number_f64) = Number::from_f64(f) {
                    return Some((k, Value::Number(number_f64)));
                }
            }
            warning!("Bad number: {} in claim: {}", v, claim);
            None
        }
        _ => {
            warning!("Unknown type: {} in claim: {}", ty.unwrap(), claim);
            None
        }
    }
}
