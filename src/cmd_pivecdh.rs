use std::collections::BTreeMap;
use std::fs;
use std::str::FromStr;

use clap::{App, Arg, ArgMatches, SubCommand};
use p256::{EncodedPoint, PublicKey};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand::rngs::OsRng;
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use yubikey::{PinPolicy, YubiKey};
use yubikey::piv::{AlgorithmId, decrypt_data, metadata, RetiredSlotId, SlotId};

use crate::pivutil::get_algorithm_id;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-ecdh" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV ECDH subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).help("PIV card user pin"))
            .arg(Arg::with_name("slot").short("s").long("slot").takes_value(true).help("PIV slot, e.g. 82, 83 ..."))
            .arg(Arg::with_name("public").long("public").help("Public key"))
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

        let public = sub_arg_matches.is_present("public");
        let private = sub_arg_matches.is_present("private");
        if !public && !private {
            failure_and_exit!("--public and --private requires one");
        } else if public && private {
            failure_and_exit!("--public and --private only allow one");
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

            let public_key;
            if let Some(public_key_pem) = public_key_pem_opt {
                public_key = opt_result!(public_key_pem.parse::<PublicKey>(), "Parse public key failed: {}");
            } else {
                let public_key_point_hex = sub_arg_matches.value_of("public-key-point-hex").unwrap_or_else(||
                    failure_and_exit!("--public-key, --public-key-file or --public-key-point-hex must require one"));
                let public_key_point_bytes = opt_result!(hex::decode(public_key_point_hex), "Parse public key point hex failed: {}");
                let encoded_point = opt_result!(EncodedPoint::from_bytes(&public_key_point_bytes), "Parse public key point failed: {}");
                public_key = PublicKey::from_encoded_point(&encoded_point).unwrap();
            };

            let esk = EphemeralSecret::random(&mut OsRng);
            let epk = esk.public_key();
            let epk_bytes = EphemeralKeyBytes::from_public_key(&epk);

            let public_key_encoded_point = public_key.to_encoded_point(false);

            let shared_secret = esk.diffie_hellman(&public_key);
            if json_output {
                json.insert("shared_secret_hex", hex::encode(shared_secret.raw_secret_bytes()));
                json.insert("epk_point_hex", hex::encode(epk_bytes.decompress().as_bytes()));
                json.insert("pk_point_hex", hex::encode(public_key_encoded_point.as_bytes()));
            } else {
                information!("Shared secret: {}", hex::encode(shared_secret.raw_secret_bytes()));
                information!("EPK point: {}", hex::encode(epk_bytes.decompress().as_bytes()));
                information!("Public key point: {}", hex::encode(public_key_encoded_point.as_bytes()));
            }
        }

        if private {
            let pin_opt = sub_arg_matches.value_of("pin");

            let slot = opt_value_result!(sub_arg_matches.value_of("slot"), "--slot must assigned, e.g. 82, 83 ...");
            let epk = opt_value_result!(sub_arg_matches.value_of("epk"), "--epk must assigned");

            let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
            let retired_slot_id = opt_result!(RetiredSlotId::from_str(slot), "Slot not found: {}");
            debugging!("Slot id: {}", retired_slot_id);
            let slot_id = SlotId::Retired(retired_slot_id);
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
                    let algorithm_id = opt_result!(get_algorithm_id(&public_key), "Get algorithm id failed: {}");
                    match algorithm_id {
                        AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 | AlgorithmId::EccP384 => {
                            failure_and_exit!("Not supported algorithm: {:?}", algorithm_id);
                        }
                        AlgorithmId::EccP256 => {
                            match algorithm_id {
                                AlgorithmId::EccP256 => if let Some(public) = &meta.public {
                                    json.insert("pk_point_hex", hex::encode(public.subject_public_key.raw_bytes()));
                                }
                                _ => {}
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
            let decrypted_shared_secret = opt_result!(decrypt_data(
                &mut yk,
                &epk_bytes,
                AlgorithmId::EccP256,
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

// const EPK_BYTES: usize = 33;

#[derive(Debug)]
pub struct EphemeralKeyBytes(EncodedPoint);

impl EphemeralKeyBytes {
    fn from_public_key(epk: &PublicKey) -> Self {
        EphemeralKeyBytes(epk.to_encoded_point(true))
    }

    fn decompress(&self) -> EncodedPoint {
        // EphemeralKeyBytes is a valid compressed encoding by construction.
        let p = PublicKey::from_encoded_point(&self.0).unwrap();
        p.to_encoded_point(false)
    }
}
