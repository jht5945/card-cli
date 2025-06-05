use crate::ecdsautil::EcdsaAlgorithm;
use crate::keychain::{KeychainKey, KeychainKeyValue};
use crate::keyutil::{KeyAlgorithmId, KeyUri, YubikeyHmacEncSoftKey};
use crate::pivutil::FromStr;
use crate::util::base64_encode;
use crate::{cmd_hmac_encrypt, cmdutil, ecdsautil, hmacutil, pbeutil, rsautil, util, yubikeyutil};
use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use std::collections::BTreeMap;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "keypair-generate"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Generate software keypair")
            .arg(
                Arg::with_name("type")
                    .long("type")
                    .required(true)
                    .takes_value(true)
                    .help("Key type (e.g. p256, p384, p521, rsa1024, rsa2048, rsa3072, rsa4096)"),
            )
            .arg(cmdutil::build_with_hmac_encrypt_arg())
            .arg(cmdutil::build_with_pbe_encrypt_arg())
            .arg(cmdutil::build_double_pin_check_arg())
            .arg(cmdutil::build_pbe_iteration_arg())
            .arg(cmdutil::build_keychain_name_arg())
            .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let key_type = sub_arg_matches.value_of("type").unwrap().to_lowercase();
        let keychain_name = sub_arg_matches.value_of("keychain-name");

        if let Some(keychain_name) = keychain_name {
            let keychain_key = KeychainKey::from_key_name_default(keychain_name);
            if keychain_key.get_password()?.is_some() {
                return simple_error!("Keychain key URI: {} exists", keychain_key.to_key_uri());
            }
        }

        let ecdsa_algorithm = match key_type.as_str() {
            "p256" => Some(EcdsaAlgorithm::P256),
            "p384" => Some(EcdsaAlgorithm::P384),
            "p521" => Some(EcdsaAlgorithm::P521),
            _ => None,
        };
        let rsa_bit_size: Option<usize> = match key_type.as_str() {
            "rsa1024" => Some(1024),
            "rsa2048" => Some(2048),
            "rsa3072" => Some(3072),
            "rsa4096" => Some(4096),
            _ => None,
        };

        let (pkcs8_base64, secret_key_pem, public_key_pem, public_key_der, jwk_key) =
            if let Some(ecdsa_algorithm) = ecdsa_algorithm {
                ecdsautil::generate_ecdsa_keypair(ecdsa_algorithm)?
            } else if let Some(rsa_bit_size) = rsa_bit_size {
                rsautil::generate_rsa_keypair(rsa_bit_size)?
            } else {
                return simple_error!("Unsupported key type: {}", key_type);
            };

        let mut password_opt = None;
        let (pkcs8_base64, secret_key_pem) = (
            cmd_hmac_encrypt::do_encrypt(&pkcs8_base64, &mut password_opt, sub_arg_matches)?,
            cmd_hmac_encrypt::do_encrypt(&secret_key_pem, &mut password_opt, sub_arg_matches)?,
        );
        let public_key_base64 = base64_encode(&public_key_der);

        let keychain_key_uri = if let Some(keychain_name) = keychain_name {
            let keychain_key_value = KeychainKeyValue {
                keychain_name: keychain_name.to_string(),
                pkcs8_base64: pkcs8_base64.clone(),
                secret_key_pem: secret_key_pem.clone(),
                public_key_pem: public_key_pem.clone(),
                public_key_jwk: jwk_key.clone(),
            };
            let keychain_key_value_json = serde_json::to_string(&keychain_key_value)?;

            let keychain_key = KeychainKey::from_key_name_default(keychain_name);
            keychain_key.set_password(keychain_key_value_json.as_bytes())?;
            Some(keychain_key.to_key_uri())
        } else {
            None
        };

        let algorithm_id = KeyAlgorithmId::from_str(&key_type);

        let with_encrypt = hmacutil::is_hmac_encrypted(&pkcs8_base64)
            || pbeutil::is_simple_pbe_encrypted(&pkcs8_base64);
        let yubikey_hmac_enc_soft_key_uri =
            if let (true, Some(algorithm_id)) = (with_encrypt, algorithm_id) {
                let yubikey_name = match yubikeyutil::open_yubikey() {
                    Ok(yk) => format!("yubikey{}-{}", yk.version().major, yk.serial().0),
                    Err(_) => "yubikey-unknown".to_string(),
                };
                let yubikey_hmac_enc_soft_key = YubikeyHmacEncSoftKey {
                    key_name: yubikey_name,
                    algorithm: algorithm_id,
                    hmac_enc_private_key: pkcs8_base64.clone(),
                };
                Some(KeyUri::YubikeyHmacEncSoftKey(yubikey_hmac_enc_soft_key).to_string())
            } else {
                None
            };

        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();
            match keychain_key_uri {
                None => {
                    json.insert("private_key_base64", pkcs8_base64);
                    json.insert("private_key_pem", secret_key_pem);

                    if let Some(yubikey_hmac_enc_soft_key_uri) = yubikey_hmac_enc_soft_key_uri {
                        json.insert("key_uri", yubikey_hmac_enc_soft_key_uri.to_string());
                    }
                }
                Some(keychain_key_uri) => {
                    json.insert("keychain_key_uri", keychain_key_uri);
                }
            }
            json.insert("public_key_pem", public_key_pem);
            json.insert("public_key_base64", public_key_base64);
            json.insert("public_key_jwk", jwk_key);

            util::print_pretty_json(&json);
        } else {
            match keychain_key_uri {
                None => {
                    information!("Private key base64:\n{}\n", pkcs8_base64);
                    information!("Private key PEM:\n{}\n", secret_key_pem);

                    if let Some(yubikey_hmac_enc_soft_key_uri) = yubikey_hmac_enc_soft_key_uri {
                        information!("Key URI:\n{}\n", yubikey_hmac_enc_soft_key_uri);
                    }
                }
                Some(keychain_key_uri) => {
                    information!("Keychain key URI:\n{}\n", keychain_key_uri);
                }
            }
            information!("Public key PEM:\n{}", public_key_pem);
            information!("Public key Base64:\n{}\n", public_key_base64);
            information!("Public key JWK:\n{}", jwk_key);
        }

        Ok(None)
    }
}
