use std::collections::BTreeMap;
use std::fs;

use clap::{App, Arg, ArgMatches, SubCommand};
use rand::rngs::OsRng;
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use yubikey::{PinPolicy, YubiKey};
use yubikey::piv::{AlgorithmId, decrypt_data, metadata};

use crate::{ecdhutil, pinutil, pivutil};
use crate::pivutil::get_algorithm_id;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-ecdh" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV ECDH subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).help("PIV card user PIN"))
            .arg(Arg::with_name("slot").short("s").long("slot").takes_value(true).help("PIV slot, e.g. 82, 83 ..."))
            .arg(Arg::with_name("public-256").long("public-256").help("Public key (P-256)"))
            .arg(Arg::with_name("public-384").long("public-384").help("Public key (P-384)"))
            .arg(Arg::with_name("private").long("private").help("Private key(PIV)"))
            .arg(Arg::with_name("epk").long("epk").takes_value(true).help("E-Public key"))
            .arg(Arg::with_name("public-key").long("public-key").takes_value(true).help("Public key"))
            .arg(Arg::with_name("public-key-file").long("public-key-file").takes_value(true).help("Public key"))
            .arg(Arg::with_name("public-key-point-hex").long("public-key-point-hex").takes_value(true).help("Public key point hex"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let public256 = sub_arg_matches.is_present("public-256");
        let public384 = sub_arg_matches.is_present("public-384");
        let public = public256 || public384;
        if public256 && public384 {
            failure_and_exit!("--public-256 and --public-384 only allow one");
        }
        let private = sub_arg_matches.is_present("private");
        if !public && !private {
            failure_and_exit!("--public-256, --public-384 or --private requires one");
        } else if public && private {
            failure_and_exit!("--public-256, --public-384 and --private only allow one");
        }

        let mut json = BTreeMap::<&'_ str, String>::new();
        if public {
            let public_key_pem_opt = sub_arg_matches.value_of("public-key").map(ToString::to_string)
                .or_else(|| match sub_arg_matches.value_of("public-key-file") {
                    None => None,
                    Some(file) => match fs::read_to_string(file) {
                        Err(e) => failure_and_exit!("Read from file: {}, failed: {}", file, e),
                        Ok(key) => Some(key),
                    }
                });

            if let Some(public_key_pem) = &public_key_pem_opt {
                debugging!("Public key: {}", public_key_pem);
            }

            if public256 {
                ecdhutil::piv_ecdh!(p256, public_key_pem_opt, sub_arg_matches, json, json_output);
            } else {
                ecdhutil::piv_ecdh!(p384, public_key_pem_opt, sub_arg_matches, json, json_output);
            }
        }

        if private {
            let pin_opt = sub_arg_matches.value_of("pin");
            let pin_opt = pinutil::get_pin(pin_opt);
            let pin_opt = pin_opt.as_deref();

            let slot = opt_value_result!(sub_arg_matches.value_of("slot"), "--slot must assigned, e.g. 82, 83 ...");
            let epk = opt_value_result!(sub_arg_matches.value_of("epk"), "--epk must assigned");

            let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
            let slot_id = pivutil::get_slot_id(slot)?;
            debugging!("Slot id: {}", slot_id);
            if let Ok(meta) = metadata(&mut yk, slot_id) {
                debugging!("PIV meta: {:?}", meta);
                if let Some((pin_policy, _touch_policy)) = meta.policy {
                    match pin_policy {
                        PinPolicy::Never => {}
                        _ => if pin_opt.is_none() {
                            failure_and_exit!("Slot pin is required");
                        }
                    }
                }
                if let Some(public_key) = &meta.public {
                    let algorithm_id = opt_result!(get_algorithm_id(public_key), "Get algorithm id failed: {}");
                    match algorithm_id {
                        AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => {
                            failure_and_exit!("Not supported algorithm: {:?}", algorithm_id);
                        }
                        AlgorithmId::EccP256 | AlgorithmId::EccP384 => {
                            if let Some(public) = &meta.public {
                                json.insert("pk_point_hex", hex::encode(public.subject_public_key.raw_bytes()));
                            }
                        }
                    }
                }
            } else {
                warning!("Get slot: {} meta data failed", slot);
            }

            if let Some(pin) = pin_opt {
                opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");
            }

            let epk_bytes = opt_result!(hex::decode(epk), "Parse epk failed: {}");
            let epk_bits = ((epk_bytes.len() - 1) / 2) * 8;
            debugging!("Epk {} bits", epk_bits);
            let decrypted_shared_secret = opt_result!(decrypt_data(
                &mut yk,
                &epk_bytes,
               iff!(epk_bits == 256, AlgorithmId::EccP256, AlgorithmId::EccP384),
                slot_id,
            ), "Decrypt piv failed: {}");

            if json_output {
                json.insert("shared_secret_hex", hex::encode(&decrypted_shared_secret));
            } else {
                information!("Shared secret: {}", hex::encode(&decrypted_shared_secret));
            }
        }

        if json_output {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        Ok(None)
    }
}
