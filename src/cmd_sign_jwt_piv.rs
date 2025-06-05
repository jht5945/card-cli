use std::borrow::Cow;
use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use jwt::header::HeaderType;
use jwt::{AlgorithmType, Header, ToBase64};
use rust_util::util_clap::{Command, CommandError};
use rust_util::{util_time, XResult};
use serde_json::{Map, Number, Value};
use yubikey::piv::{sign_data, AlgorithmId, SlotId};
use yubikey::{Certificate, YubiKey};

use crate::ecdsautil::parse_ecdsa_to_rs;
use crate::{cmdutil, digestutil, pivutil, rsautil, util};

const SEPARATOR: &str = ".";

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "sign-jwt-piv"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        let app = SubCommand::with_name(self.name()).about("Sign JWT(PIV) subcommand")
            .arg(cmdutil::build_slot_arg())
            .arg(cmdutil::build_pin_arg())
            .arg(cmdutil::build_no_pin_arg())
            .arg(cmdutil::build_json_arg());
        fill_sign_jwt_app_args(app)
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let slot = opt_value_result!(
            sub_arg_matches.value_of("slot"),
            "--slot must assigned, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e"
        );

        let (header, payload, jwt_claims) = build_jwt_parts(sub_arg_matches)?;

        let mut yk = opt_result!(YubiKey::open(), "Find YubiKey failed: {}");
        let slot_id = opt_result!(pivutil::get_slot_id(slot), "Get slot id failed: {}");
        let pin_opt = pivutil::check_read_pin(&mut yk, slot_id, sub_arg_matches);

        let token_string = sign_jwt(&mut yk, slot_id, &pin_opt, header, &payload, &jwt_claims)?;
        print_jwt_token(json_output, token_string);

        Ok(None)
    }
}

pub fn print_jwt_token(json_output: bool, token_string: String) {
    if json_output {
        debugging!("Singed JWT: {}", token_string);

        let mut json = BTreeMap::<&'_ str, String>::new();
        json.insert("token", token_string.clone());

        util::print_pretty_json(&json);
    } else {
        success!("Singed JWT: {}", token_string);
    }
}

pub fn fill_sign_jwt_app_args<'a>(app: App<'a, 'a>) -> App<'a, 'a> {
    app.arg(Arg::with_name("key-id").short("K").long("key-id").takes_value(true).help("Header key ID"))
        .arg(Arg::with_name("claims").short("C").long("claims").takes_value(true).multiple(true).help("Claims, key:value"))
        .arg(Arg::with_name("payload").short("P").long("payload").takes_value(true).help("Claims in JSON"))
        .arg(Arg::with_name("jti").long("jti").help("Claims jti"))
        .arg(Arg::with_name("validity").long("validity").takes_value(true)
            .help("Claims validity period e.g. 10m means 10 minutes (s - second, m - minute, h - hour, d - day)"))
}

fn sign_jwt(
    yk: &mut YubiKey,
    slot_id: SlotId,
    pin_opt: &Option<String>,
    mut header: Header,
    payload: &Option<String>,
    claims: &Map<String, Value>,
) -> XResult<String> {
    if let Some(pin) = pin_opt {
        opt_result!(
            yk.verify_pin(pin.as_bytes()),
            "YubiKey verify pin failed: {}"
        );
    }
    let cert = match Certificate::read(yk, slot_id) {
        Ok(c) => c,
        Err(e) => return simple_error!("Read YubiKey certificate failed: {}", e),
    };
    let piv_algorithm_id =
        pivutil::get_algorithm_id(&cert.cert.tbs_certificate.subject_public_key_info)?;

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
    let claims = merge_payload_claims(payload, claims)?;
    let tobe_signed = merge_header_claims(header.as_bytes(), claims.as_bytes());

    let raw_in = digest_by_jwt_algorithm(jwt_algorithm, &tobe_signed)?;

    let signed_data = opt_result!(
        sign_data(yk, &raw_in, yk_algorithm, slot_id),
        "Sign YubiKey failed: {}"
    );
    let signed_data = match jwt_algorithm {
        AlgorithmType::Rs256 => signed_data.to_vec(),
        AlgorithmType::Es256 | AlgorithmType::Es384 => parse_ecdsa_to_rs(signed_data.as_slice())?,
        _ => return simple_error!("SHOULD NOT HAPPEN: {:?}", jwt_algorithm),
    };

    let signature = util::base64_encode_url_safe_no_pad(&signed_data);

    Ok([&*header, &*claims, &signature].join(SEPARATOR))
}

pub fn digest_by_jwt_algorithm(jwt_algorithm: AlgorithmType, tobe_signed: &[u8]) -> XResult<Vec<u8>> {
    Ok(match jwt_algorithm {
        AlgorithmType::Rs256 => {
            rsautil::pkcs15_sha256_rsa_2048_padding_for_sign(&digestutil::sha256_bytes(tobe_signed))
        }
        AlgorithmType::Es256 => digestutil::sha256_bytes(tobe_signed),
        AlgorithmType::Es384 => digestutil::sha384_bytes(tobe_signed),
        AlgorithmType::Es512 => digestutil::sha512_bytes(tobe_signed),
        _ => return simple_error!("SHOULD NOT HAPPEN: {:?}", jwt_algorithm),
    })
}

pub fn merge_header_claims(header: &[u8], claims: &[u8]) -> Vec<u8> {
    let mut tobe_signed = vec![];
    tobe_signed.extend_from_slice(header);
    tobe_signed.extend_from_slice(SEPARATOR.as_bytes());
    tobe_signed.extend_from_slice(claims);
    tobe_signed
}

pub fn merge_payload_claims<'a>(
    payload: &'a Option<String>,
    claims: &'a Map<String, Value>,
) -> XResult<Cow<'a, str>> {
    Ok(match (payload, claims.is_empty()) {
        (Some(payload), true) => {
            Cow::Owned(util::base64_encode_url_safe_no_pad(payload.as_bytes()))
        }
        (_, _) => opt_result!(claims.to_base64(), "Claims to base64 failed: {}"),
    })
}

pub fn build_jwt_parts(
    sub_arg_matches: &ArgMatches,
) -> XResult<(Header, Option<String>, Map<String, Value>)> {
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
            Ok(value) => {
                warning!("Not valid payload map: {}", value);
            }
            Err(e) => {
                warning!("Not valid payload value: {}", e);
            }
        };
    }

    match (payload, claims) {
        (Some(_), None) => {}
        (_, Some(claims)) => {
            for claim in claims {
                match split_claim(claim) {
                    None => {
                        warning!("Claim '{}' do not contains ':'", claim);
                    }
                    Some((k, v)) => {
                        jwt_claims.insert(k, v);
                    }
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
        jwt_claims.insert(
            "jti".to_string(),
            Value::String(format!("jti-{}", util_time::get_current_millis())),
        );
    }
    if let Some(validity) = validity {
        match util_time::parse_duration(validity) {
            None => {
                warning!("Bad validity: {}", validity)
            }
            Some(validity) => {
                let current_secs = (util_time::get_current_millis() / 1000) as u64;
                jwt_claims.insert("iat".to_string(), Value::Number(Number::from(current_secs)));
                jwt_claims.insert(
                    "exp".to_string(),
                    Value::Number(Number::from(current_secs + validity.as_secs())),
                );
            }
        }
    }
    Ok((header, payload.map(ToString::to_string), jwt_claims))
}

pub fn split_claim(claim: &str) -> Option<(String, Value)> {
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
