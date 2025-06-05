use crate::keyutil::{parse_key_uri, KeyAlgorithmId, KeyUri, KeyUsage};
use crate::pivutil::ToStr;
use crate::{cmd_hmac_decrypt, cmd_se_ecdh, cmdutil, ecdhutil, pivutil, seutil, util, yubikeyutil};
use clap::{App, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::XResult;
use serde_json::Value;
use std::collections::BTreeMap;
use yubikey::piv::{decrypt_data, AlgorithmId};
use crate::util::try_decode;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "external_ecdh"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("External ECDH subcommand")
            .arg(cmdutil::build_parameter_arg())
            .arg(cmdutil::build_epk_arg())
            .arg(cmdutil::build_pin_arg())
            .arg(cmdutil::build_serial_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let parameter = sub_arg_matches.value_of("parameter").unwrap();
        let epk = sub_arg_matches.value_of("epk").unwrap();
        let ephemeral_public_key_der_bytes = cmd_se_ecdh::parse_epk(epk)?;

        let mut json = BTreeMap::new();
        let key_uri = parse_key_uri(parameter)?;

        match ecdh(&ephemeral_public_key_der_bytes, key_uri, sub_arg_matches) {
            Ok(shared_secret_bytes) => {
                json.insert("success", Value::Bool(true));
                json.insert(
                    "shared_secret_hex",
                    hex::encode(&shared_secret_bytes).into(),
                );
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

pub fn ecdh(
    ephemeral_public_key_bytes: &[u8],
    key_uri: KeyUri,
    sub_arg_matches: &ArgMatches,
) -> XResult<Vec<u8>> {
    match key_uri {
        KeyUri::SecureEnclaveKey(key) => {
            if key.usage != KeyUsage::Singing {
                return simple_error!("Not singing key");
            }
            let private_key = cmd_hmac_decrypt::try_decrypt(&mut None, &key.private_key)?;
            seutil::secure_enclave_p256_dh(&private_key, ephemeral_public_key_bytes)
        }
        KeyUri::YubikeyPivKey(key) => {
            let mut yk = yubikeyutil::open_yubikey_with_args(sub_arg_matches)?;
            let pin_opt = pivutil::check_read_pin(&mut yk, key.slot, sub_arg_matches);

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

            let epk_bytes = match algorithm {
                AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => {
                    return simple_error!("Algorithm is not supported: {:?}", algorithm)
                }
                AlgorithmId::EccP256 => {
                    use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
                    use spki::DecodePublicKey;
                    let public_key = opt_result!(PublicKey::from_public_key_der(
                        ephemeral_public_key_bytes),"Parse P256 ephemeral public key failed: {}");
                    public_key.to_encoded_point(false).as_bytes().to_vec()
                }
                AlgorithmId::EccP384 => {
                    use p384::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
                    use spki::DecodePublicKey;
                    let public_key = opt_result!(PublicKey::from_public_key_der(
                        ephemeral_public_key_bytes), "Parse P384 ephemeral public key failed: {}");
                    public_key.to_encoded_point(false).as_bytes().to_vec()
                }
            };
            let decrypted_shared_secret = opt_result!(
                decrypt_data(&mut yk, &epk_bytes, algorithm, key.slot,),
                "Decrypt piv failed: {}"
            );

            Ok(decrypted_shared_secret.to_vec())
        }
        KeyUri::YubikeyHmacEncSoftKey(key) => {
            if key.algorithm.is_ecc() {
                let private_key = cmd_hmac_decrypt::try_decrypt(&mut None, &key.hmac_enc_private_key)?;
                let private_key_bytes = try_decode(&private_key)?;

                if let Ok(shared_secret) = ecdhutil::parse_p256_private_and_ecdh(&private_key_bytes, ephemeral_public_key_bytes) {
                    return Ok(shared_secret.to_vec());
                }
                if let Ok(shared_secret) = ecdhutil::parse_p384_private_and_ecdh(&private_key_bytes, ephemeral_public_key_bytes) {
                    return Ok(shared_secret.to_vec());
                }
                if let Ok(shared_secret) = ecdhutil::parse_p521_private_and_ecdh(&private_key_bytes, ephemeral_public_key_bytes) {
                    return Ok(shared_secret.to_vec());
                }

                simple_error!("Invalid private key and/or ephemeral public key")
            } else {
                simple_error!("Invalid algorithm: {}", key.algorithm.to_str())
            }
        }
        KeyUri::ExternalCommandKey(key) => {
            let parameter = cmd_hmac_decrypt::try_decrypt(&mut None, &key.parameter)?;
            external_command_rs::external_ecdh(&key.external_command, &parameter, ephemeral_public_key_bytes)
        }
    }
}
