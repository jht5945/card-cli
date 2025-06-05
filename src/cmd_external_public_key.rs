use crate::keyutil::{parse_key_uri, KeyUri, KeyUsage};
use crate::util::{base64_decode, base64_encode};
use crate::yubikeyutil::find_key_or_error;
use crate::{cmd_hmac_decrypt, cmdutil, ecdsautil, seutil, util, yubikeyutil};
use clap::{App, ArgMatches, SubCommand};
use ecdsa::elliptic_curve::pkcs8::der::Encode;
use rust_util::util_clap::{Command, CommandError};
use rust_util::XResult;
use serde_json::Value;
use std::collections::BTreeMap;
use rsa::RsaPrivateKey;
use spki::EncodePublicKey;
use x509_parser::parse_x509_certificate;
use crate::pivutil::ToStr;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "external_public_key"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("External public key subcommand")
            .arg(cmdutil::build_parameter_arg())
            .arg(cmdutil::build_serial_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let parameter = sub_arg_matches.value_of("parameter").unwrap();
        let serial_opt = sub_arg_matches.value_of("serial");

        let mut json = BTreeMap::new();
        match fetch_public_key(parameter, &serial_opt) {
            Ok(public_key_bytes) => {
                json.insert("success", Value::Bool(true));
                json.insert("public_key_base64", base64_encode(&public_key_bytes).into());
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

fn fetch_public_key(parameter: &str, serial_opt: &Option<&str>) -> XResult<Vec<u8>> {
    let key_uri = parse_key_uri(parameter)?;
    match key_uri {
        KeyUri::SecureEnclaveKey(key) => {
            if key.usage != KeyUsage::Singing {
                simple_error!("Not singing key")
            } else {
                let private_key = cmd_hmac_decrypt::try_decrypt(&mut None, &key.private_key)?;
                let (_, public_key_der, _) =
                    seutil::recover_secure_enclave_p256_public_key(&private_key, true)?;
                Ok(public_key_der)
            }
        }
        KeyUri::YubikeyPivKey(key) => {
            let mut yk = yubikeyutil::open_yubikey_with_serial(serial_opt)?;
            if let Some(key) = find_key_or_error(&mut yk, &key.slot)? {
                let cert_der = key.certificate().cert.to_der()?;
                let x509_certificate = parse_x509_certificate(cert_der.as_slice()).unwrap().1;
                let public_key_bytes = x509_certificate.public_key().raw;
                return Ok(public_key_bytes.to_vec());
            }
            simple_error!("Slot {} not found", key.slot)
        }
        KeyUri::YubikeyHmacEncSoftKey(key) => {
            if key.algorithm.is_ecc() {
                let private_key = cmd_hmac_decrypt::try_decrypt(&mut None, &key.hmac_enc_private_key)?;
                let p256_public_key = ecdsautil::parse_p256_private_key_to_public_key(&private_key).ok();
                let p384_public_key = ecdsautil::parse_p384_private_key_to_public_key(&private_key).ok();
                let p521_public_key = ecdsautil::parse_p521_private_key_to_public_key(&private_key).ok();

                if let Some(p256_public_key) = p256_public_key {
                    return Ok(p256_public_key);
                }
                if let Some(p384_public_key) = p384_public_key {
                    return Ok(p384_public_key);
                }
                if let Some(p521_public_key) = p521_public_key {
                    return Ok(p521_public_key);
                }
                simple_error!("Invalid hmac enc private key")
            } else if key.algorithm.is_rsa() {
                use rsa::pkcs8::DecodePrivateKey;
                let private_key = cmd_hmac_decrypt::try_decrypt(&mut None, &key.hmac_enc_private_key)?;
                let private_key_der = base64_decode(&private_key)?;
                let rsa_private_key = RsaPrivateKey::from_pkcs8_der(&private_key_der)?;
                Ok(rsa_private_key.to_public_key().to_public_key_der()?.to_vec())
            } else {
                simple_error!("Invalid algorithm: {}", key.algorithm.to_str())
            }
        }
        KeyUri::ExternalCommandKey(key) => {
            let parameter = cmd_hmac_decrypt::try_decrypt(&mut None, &key.parameter)?;
            external_command_rs::external_public_key(&key.external_command, &parameter)
        }
    }
}
