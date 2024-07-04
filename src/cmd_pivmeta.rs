use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use p256::pkcs8::der::Encode;
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use rust_util::util_msg::MessageType;
use x509_parser::parse_x509_certificate;
use yubikey::{Key, YubiKey};
use yubikey::piv::{AlgorithmId, metadata};

use crate::pivutil;
use crate::pivutil::{get_algorithm_id_by_certificate, slot_equals, ToStr};
use crate::pkiutil::bytes_to_pem;
use crate::sshutil::SshVecWriter;
use crate::util::base64_encode;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-meta" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV meta subcommand")
            .arg(Arg::with_name("slot").short("s").long("slot").takes_value(true).help("PIV slot, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let mut json = BTreeMap::<&'_ str, String>::new();

        let slot = opt_value_result!(sub_arg_matches.value_of("slot"), "--slot must assigned, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e");

        let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");

        let slot_id = pivutil::get_slot_id(slot)?;
        json.insert("slot", pivutil::to_slot_hex(&slot_id));
        if let Ok(meta) = metadata(&mut yk, slot_id) {
            debugging!("PIV meta: {:?}", meta);
            let algorithm_str = meta.algorithm.to_str();
            if json_output {
                json.insert("algorithm", algorithm_str.to_string());
            } else {
                information!("Algorithm: {}", algorithm_str);
            }

            if let Some((pin_policy, touch_policy)) = meta.policy {
                let pin_policy_str = pin_policy.to_str();
                let touch_policy_str = touch_policy.to_str();
                if json_output {
                    json.insert("pin_policy", pin_policy_str.to_string());
                    json.insert("touch_policy", touch_policy_str.to_string());
                } else {
                    information!("PIN policy: {}", pin_policy_str);
                    information!("Touch policy: {}", touch_policy_str);
                }
            }

            let origin_str = meta.origin.to_str();
            if json_output {
                json.insert("origin", origin_str.to_string());
            } else {
                information!("Origin: {}", origin_str);
            }
        } else {
            warning!("Get slot: {} meta data failed", slot);
        }

        match Key::list(&mut yk) {
            Err(e) => warning!("List keys failed: {}", e),
            Ok(keys) => for k in &keys {
                let cert = &k.certificate().cert.tbs_certificate;
                let slot_str = format!("{:x}", Into::<u8>::into(k.slot()));
                if slot_equals(&slot_id, &slot_str) {
                    if let Ok(algorithm_id) = get_algorithm_id_by_certificate(k.certificate()) {
                        let algorithm_str = algorithm_id.to_str();
                        json.insert("algorithm", algorithm_str.to_string());

                        let public_key_bit_string = &cert.subject_public_key_info.subject_public_key;
                        match algorithm_id {
                            AlgorithmId::EccP256 | AlgorithmId::EccP384 => {
                                let ec_bit_len = iff!(matches!(algorithm_id, AlgorithmId::EccP256), 256, 384);
                                let pk_point_hex = public_key_bit_string.raw_bytes();
                                json.insert("pk_point_hex", hex::encode(pk_point_hex));
                                if pk_point_hex[0] == 0x04 {
                                    json.insert(
                                        "pk_point_hex_compressed",
                                        format!("02{}", hex::encode(&pk_point_hex[1..(pk_point_hex.len() / 2) + 1])),
                                    );
                                }

                                let mut ssh_public_key = vec![];
                                ssh_public_key.write_string(format!("ecdsa-sha2-nistp{}", ec_bit_len).as_bytes());
                                ssh_public_key.write_string(format!("nistp{}", ec_bit_len).as_bytes());
                                ssh_public_key.write_string(pk_point_hex);
                                let ssh_public_key_str = format!(
                                    "ecdsa-sha2-nistp{} {} PIV:{}", ec_bit_len, base64_encode(ssh_public_key), slot_id);
                                json.insert("ssh_public_key", ssh_public_key_str.to_string());
                            }
                            _ => {}
                        }
                    }
                    let serial_lower = cert.serial_number.to_string().to_lowercase();
                    json.insert("serial", if serial_lower.starts_with("00:") { serial_lower.chars().skip(3).collect() } else { serial_lower });
                    let cert_der = k.certificate().cert.to_der()?;
                    json.insert("certificate_hex", hex::encode(&cert_der));
                    json.insert("certificate_pem", bytes_to_pem("CERTIFICATE", cert_der.as_slice()));

                    let x509_certificate = parse_x509_certificate(cert_der.as_slice()).unwrap().1;
                    let public_key_bytes = x509_certificate.public_key().raw;

                    json.insert("subject", x509_certificate.subject.to_string());
                    json.insert("issuer", x509_certificate.issuer.to_string());
                    json.insert("public_key_hex", hex::encode(public_key_bytes));
                    json.insert("public_key_pem", bytes_to_pem("PUBLIC KEY", public_key_bytes));

                    if !json_output {
                        information!("Subject: {}", x509_certificate.subject.to_string());
                        information!("Certificate: {}", bytes_to_pem("CERTIFICATE", cert_der.as_slice()));
                        information!("Public key: {}", bytes_to_pem("PUBLIC KEY", public_key_bytes));
                    }
                } else {
                    util_msg::when(MessageType::DEBUG, || {
                        let cert_der = cert.to_der().unwrap();
                        debugging!("Slot: {:x}", Into::<u8>::into(k.slot()));
                        let public_key_bytes = cert.subject_public_key_info.subject_public_key.raw_bytes();
                        debugging!("Certificate: {}", hex::encode(&cert_der));
                        debugging!("Public key: {}", hex::encode(public_key_bytes));
                    });
                }
            },
        }

        if json_output {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        Ok(None)
    }
}
