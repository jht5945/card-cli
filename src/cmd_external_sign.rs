use crate::cmd_sign_jwt_piv::digest_by_jwt_algorithm;
use crate::cmd_sign_jwt_soft::{convert_jwt_algorithm_to_ecdsa_algorithm, parse_ecdsa_private_key};
use crate::ecdsautil::EcdsaSignType;
use crate::keyutil::{parse_key_uri, KeyAlgorithmId, KeyUri, KeyUsage, YubikeyPivKey};
use crate::pivutil::ToStr;
use crate::rsautil::RsaSignAlgorithm;
use crate::util::{base64_decode, base64_encode};
use crate::{cmd_hmac_decrypt, cmdutil, ecdsautil, pivutil, rsautil, seutil, util, yubikeyutil};
use clap::{App, ArgMatches, SubCommand};
use jwt::AlgorithmType;
use rsa::RsaPrivateKey;
use rust_util::util_clap::{Command, CommandError};
use rust_util::XResult;
use serde_json::Value;
use std::collections::BTreeMap;
use yubikey::piv::sign_data;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "external_sign"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("External sign subcommand")
            .arg(cmdutil::build_alg_arg())
            .arg(cmdutil::build_parameter_arg())
            .arg(cmdutil::build_message_arg())
            .arg(cmdutil::build_pin_arg())
            .arg(cmdutil::build_serial_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let alg = sub_arg_matches.value_of("alg").unwrap();
        let parameter = sub_arg_matches.value_of("parameter").unwrap();
        let message_base64 = sub_arg_matches.value_of("message-base64").unwrap();
        let message_bytes = base64_decode(message_base64)?;

        let mut json = BTreeMap::new();
        let key_uri = parse_key_uri(parameter)?;
        match sign(alg, &message_bytes, key_uri, sub_arg_matches) {
            Ok(signature_bytes) => {
                json.insert("success", Value::Bool(true));
                json.insert("signature_base64", base64_encode(&signature_bytes).into());
            }
            Err(e) => {
                json.insert("success", Value::Bool(false));
                json.insert("error", e.to_string().into());
            }
        }

        util::print_pretty_json(&json);
        Ok(None)
    }
}

pub fn sign(alg: &str, message: &[u8], key_uri: KeyUri, sub_arg_matches: &ArgMatches) -> XResult<Vec<u8>> {
    match key_uri {
        KeyUri::SecureEnclaveKey(key) => {
            if "ES256" != alg {
                return simple_error!("Invalid alg: {}", alg);
            }
            if key.usage != KeyUsage::Singing {
                return simple_error!("Not singing key");
            }
            let private_key = cmd_hmac_decrypt::try_decrypt(&mut None, &key.private_key)?;
            seutil::secure_enclave_p256_sign(&private_key, message)
        }
        KeyUri::YubikeyPivKey(key) => {
            let mut yk = yubikeyutil::open_yubikey_with_args(sub_arg_matches)?;
            let pin_opt = pivutil::check_read_pin(&mut yk, key.slot, sub_arg_matches);

            // FIXME Check YubiKey slot algorithm
            let jwt_algorithm = get_jwt_algorithm(&key, alg)?;

            if let Some(pin) = pin_opt {
                opt_result!(
                    yk.verify_pin(pin.as_bytes()),
                    "YubiKey verify pin failed: {}"
                );
            }

            let algorithm = opt_value_result!(
                KeyAlgorithmId::to_algorithm_id(key.algorithm),
                "Yubikey not supported algorithm: {}",
                key.algorithm.to_str()
            );
            let raw_in = digest_by_jwt_algorithm(jwt_algorithm, message)?;
            let signed_data = opt_result!(
                sign_data(&mut yk, &raw_in, algorithm, key.slot),
                "Sign YubiKey failed: {}"
            );
            Ok(signed_data.to_vec())
        }
        KeyUri::YubikeyHmacEncSoftKey(key) => {
            if key.algorithm.is_ecc() {
                let private_key = cmd_hmac_decrypt::try_decrypt(&mut None, &key.hmac_enc_private_key)?;
                let (jwt_algorithm, private_key_d) = parse_ecdsa_private_key(&private_key)?;

                let raw_in = digest_by_jwt_algorithm(jwt_algorithm, message)?;
                let ecdsa_algorithm = convert_jwt_algorithm_to_ecdsa_algorithm(jwt_algorithm)?;
                let signed_data = ecdsautil::ecdsa_sign(
                    ecdsa_algorithm,
                    &private_key_d,
                    &raw_in,
                    EcdsaSignType::Der,
                )?;

                Ok(signed_data)
            } else if key.algorithm.is_rsa() {
                use rsa::pkcs8::DecodePrivateKey;
                let private_key = cmd_hmac_decrypt::try_decrypt(&mut None, &key.hmac_enc_private_key)?;
                let private_key_der = base64_decode(&private_key)?;
                let rsa_private_key = RsaPrivateKey::from_pkcs8_der(&private_key_der)?;

                let rsa_sign_algorithm =
                    opt_value_result!(RsaSignAlgorithm::from_str(alg), "Invalid --alg: {}", alg);
                rsautil::sign(&rsa_private_key, rsa_sign_algorithm, message)
            } else {
                simple_error!("Invalid algorithm: {}", key.algorithm.to_str())
            }
        }
        KeyUri::ExternalCommandKey(key) => {
            let parameter = cmd_hmac_decrypt::try_decrypt(&mut None, &key.parameter)?;
            let alg = key.algorithm.to_jwa_name();
            let signature = external_command_rs::external_sign(&key.external_command, &parameter, alg, message)?;
            Ok(signature)
        }
    }
}

fn get_jwt_algorithm(key: &YubikeyPivKey, alg: &str) -> XResult<AlgorithmType> {
    let jwt_algorithm = match alg {
        "ES256" => AlgorithmType::Es256,
        "ES384" => AlgorithmType::Es384,
        "ES512" => AlgorithmType::Es512,
        "RS256" => AlgorithmType::Rs256,
        _ => return simple_error!("Invalid alg: {}", alg),
    };
    if key.algorithm == KeyAlgorithmId::Rsa1024 {
        return simple_error!("Invalid algorithm: RSA1024");
    }
    let is_p256_mismatch =
        key.algorithm == KeyAlgorithmId::EccP256 && jwt_algorithm != AlgorithmType::Es256;
    let is_p384_mismatch =
        key.algorithm == KeyAlgorithmId::EccP384 && jwt_algorithm != AlgorithmType::Es384;
    let is_p521_mismatch =
        key.algorithm == KeyAlgorithmId::EccP521 && jwt_algorithm != AlgorithmType::Es512;
    let is_rsa_mismatch =
        key.algorithm == KeyAlgorithmId::Rsa2048 && jwt_algorithm != AlgorithmType::Rs256;

    if is_p256_mismatch || is_p384_mismatch || is_p521_mismatch || is_rsa_mismatch {
        return simple_error!("Invalid algorithm: {} vs {}", key.algorithm.to_str(), alg);
    }
    Ok(jwt_algorithm)
}
