use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::{util_msg, XResult};
use rust_util::util_clap::{Command, CommandError};
use yubikey::{Key, YubiKey};
use yubikey::piv::{AlgorithmId, SlotId};

use crate::{argsutil, ecdsautil, pivutil};
use crate::ecdsautil::EcdsaAlgorithm;
use crate::pivutil::slot_equals;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-verify" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV verify subcommand")
            .arg(Arg::with_name("slot").short("s").long("slot").takes_value(true).help("PIV slot, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e"))
            .arg(Arg::with_name("signature-hex").short("t").long("signature-hex").takes_value(true).help("Signature"))
            .arg(Arg::with_name("file").short("f").long("file").takes_value(true).help("Input file"))
            .arg(Arg::with_name("input").short("i").long("input").takes_value(true).help("Input"))
            .arg(Arg::with_name("hash-hex").short("x").long("hash-hex").takes_value(true).help("Hash"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let hash_bytes = argsutil::get_sha256_digest_or_hash(sub_arg_matches)?;
        let signature = if let Some(signature_hex) = sub_arg_matches.value_of("signature-hex") {
            opt_result!(hex::decode(signature_hex), "Parse signature-hex failed: {}")
        } else {
            return simple_error!("--signature-hex required.");
        };

        let mut json = BTreeMap::<&'_ str, String>::new();

        let slot = opt_value_result!(sub_arg_matches.value_of("slot"), "--slot must assigned, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e");

        let slot_id = pivutil::get_slot_id(slot)?;
        json.insert("slot", pivutil::to_slot_hex(&slot_id));
        if let Some(key) = find_key(&slot_id)? {
            let certificate = key.certificate();
            let tbs_certificate = &certificate.cert.tbs_certificate;
            if let Ok(algorithm_id) = pivutil::get_algorithm_id(&tbs_certificate.subject_public_key_info) {
                let public_key_bit_string = &tbs_certificate.subject_public_key_info.subject_public_key;
                match algorithm_id {
                    AlgorithmId::EccP256 | AlgorithmId::EccP384 => {
                        let pk_point = public_key_bit_string.raw_bytes();
                        debugging!("ECDSA public key point: {}", hex::encode(pk_point));
                        information!("Pre hash: {}", hex::encode(&hash_bytes));
                        debugging!("Signature: {}", hex::encode(&signature));
                        if json_output {
                            json.insert("public_key_hex", hex::encode(pk_point));
                            json.insert("hash_hex", hex::encode(&hash_bytes));
                            json.insert("signature_hex", hex::encode(&signature));
                        }

                        let algorithm = iff!(algorithm_id == AlgorithmId::EccP256, EcdsaAlgorithm::P256, EcdsaAlgorithm::P384);
                        match ecdsautil::ecdsaverify(algorithm, pk_point, &hash_bytes, &signature) {
                            Ok(_) => {
                                success!("Verify ECDSA succeed.");
                                if json_output {
                                    json.insert("success", "true".to_string());
                                }
                            }
                            Err(e) => {
                                failure!("Verify ECDSA failed: {}", &e);
                                if json_output {
                                    json.insert("success", "false".to_string());
                                    json.insert("message", format!("{}", e));
                                }
                            }
                        }
                    }
                    AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => {
                        let pk_rsa = public_key_bit_string.raw_bytes();
                        // TODO ...
                        debugging!("RSA public key pem: {}", hex::encode(pk_rsa));
                        failure!("Current NOT supported.");
                    }
                }
            }
        }

        if json_output {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        Ok(None)
    }
}

fn find_key(slot_id: &SlotId) -> XResult<Option<Key>> {
    let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
    match Key::list(&mut yk) {
        Err(e) => warning!("List keys failed: {}", e),
        Ok(keys) => for k in keys {
            let slot_str = format!("{:x}", Into::<u8>::into(k.slot()));
            if slot_equals(&slot_id, &slot_str) {
                return Ok(Some(k));
            }
        },
    }
    Ok(None)
}
