use clap::{App, Arg, ArgMatches, SubCommand};
use jwt::{AlgorithmType, Header, ToBase64};
use rust_util::util_clap::{Command, CommandError};
use rust_util::XResult;
use serde_json::{Map, Value};

use crate::cmd_sign_jwt_piv::{build_jwt_parts, digest_by_jwt_algorithm, merge_header_claims, merge_payload_claims, print_jwt_token};
use crate::keychain::{KeychainKey, KeychainKeyValue};
use crate::{cmd_hmac_decrypt, cmd_sign_jwt_piv, cmdutil, ecdsautil, keychain, util};
use crate::ecdsautil::{EcdsaAlgorithm, EcdsaSignType};

const SEPARATOR: &str = ".";

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "sign-jwt-soft"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        let app = SubCommand::with_name(self.name()).about("Sign JWT(Soft EC) subcommand")
            .arg(Arg::with_name("private-key").short("k").long("private-key").takes_value(true).help("Private key PKCS#8"))
            .arg(cmdutil::build_json_arg());
        cmd_sign_jwt_piv::fill_sign_jwt_app_args(app)
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let private_key = opt_value_result!(
            sub_arg_matches.value_of("private-key"),
            "Private key PKCS#8 DER base64 encoded or PEM"
        );

        let private_key = cmd_hmac_decrypt::try_decrypt(&mut None, private_key)?;

        let private_key = if keychain::is_keychain_key_uri(&private_key) {
            debugging!("Private key keychain key URI: {}", &private_key);
            let keychain_key = KeychainKey::parse_key_uri(&private_key)?;
            let keychain_key_value_bytes = opt_value_result!(
                keychain_key.get_password()?,
                "Keychain key URI: {} not found",
                &private_key
            );
            let keychain_key_value: KeychainKeyValue =
                serde_json::from_slice(&keychain_key_value_bytes)?;
            debugging!("Keychain key value {:?}", &keychain_key_value);
            keychain_key_value.pkcs8_base64
        } else {
            private_key
        };

        let (header, payload, jwt_claims) = build_jwt_parts(sub_arg_matches)?;

        let token_string = sign_jwt(&private_key, header, &payload, &jwt_claims)?;
        print_jwt_token(json_output, token_string);

        Ok(None)
    }
}

fn sign_jwt(
    private_key: &str,
    mut header: Header,
    payload: &Option<String>,
    claims: &Map<String, Value>,
) -> XResult<String> {
    let (jwt_algorithm, private_key_d) = parse_ecdsa_private_key(private_key)?;

    header.algorithm = jwt_algorithm;
    debugging!("Header: {:?}", header);
    debugging!("Claims: {:?}", claims);

    let header = opt_result!(header.to_base64(), "Header to base64 failed: {}");
    let claims = merge_payload_claims(payload, claims)?;
    let tobe_signed = merge_header_claims(header.as_bytes(), claims.as_bytes());

    let raw_in = digest_by_jwt_algorithm(jwt_algorithm, &tobe_signed)?;
    let ecdsa_algorithm = convert_jwt_algorithm_to_ecdsa_algorithm(jwt_algorithm)?;
    let signed_data = ecdsautil::ecdsa_sign(ecdsa_algorithm, &private_key_d, &raw_in, EcdsaSignType::Rs)?;

    let signature = util::base64_encode_url_safe_no_pad(&signed_data);

    Ok([&*header, &*claims, &signature].join(SEPARATOR))
}

pub fn convert_jwt_algorithm_to_ecdsa_algorithm(jwt_algorithm: AlgorithmType) -> XResult<EcdsaAlgorithm> {
    match jwt_algorithm {
        AlgorithmType::Es256 => Ok(EcdsaAlgorithm::P256),
        AlgorithmType::Es384 => Ok(EcdsaAlgorithm::P384),
        AlgorithmType::Es512 => Ok(EcdsaAlgorithm::P521),
        _ => simple_error!("SHOULD NOT HAPPEN: {:?}", jwt_algorithm),
    }
}

pub fn parse_ecdsa_private_key(private_key: &str) -> XResult<(AlgorithmType, Vec<u8>)> {
    let p256_private_key_d = ecdsautil::parse_p256_private_key(private_key).ok();
    let p384_private_key_d = ecdsautil::parse_p384_private_key(private_key).ok();
    let p521_private_key_d = ecdsautil::parse_p521_private_key(private_key).ok();

    let (jwt_algorithm, private_key_d) = match (p256_private_key_d, p384_private_key_d, p521_private_key_d) {
        (Some(p256_private_key_d), None, None) => (AlgorithmType::Es256, p256_private_key_d),
        (None, Some(p384_private_key_d), None) => (AlgorithmType::Es384, p384_private_key_d),
        (None, None, Some(p521_private_key_d)) => (AlgorithmType::Es512, p521_private_key_d),
        _ => return simple_error!("Invalid private key: {}", private_key),
    };
    Ok((jwt_algorithm, private_key_d))
}
