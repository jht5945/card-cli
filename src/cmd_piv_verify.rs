use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use openssl::rsa::{Padding, Rsa};
use rust_util::util_clap::{Command, CommandError};
use yubikey::piv::AlgorithmId;

use crate::{argsutil, cmdutil, ecdsautil, pivutil, util, yubikeyutil};
use crate::ecdsautil::EcdsaAlgorithm;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-verify" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV verify subcommand")
            .arg(cmdutil::build_slot_arg())
            .arg(Arg::with_name("signature-hex").short("t").long("signature-hex").takes_value(true).help("Signature"))
            .arg(Arg::with_name("file").short("f").long("file").takes_value(true).help("Input file"))
            .arg(Arg::with_name("input").short("i").long("input").takes_value(true).help("Input"))
            .arg(Arg::with_name("hash-hex").short("x").long("hash-hex").takes_value(true).help("Hash"))
            .arg(cmdutil::build_json_arg())
            .arg(cmdutil::build_serial_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

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
        if let Some(key) = yubikeyutil::open_and_find_key(&slot_id, sub_arg_matches)? {
            let certificate = key.certificate();
            let tbs_certificate = &certificate.cert.tbs_certificate;
            if let Ok(algorithm_id) = pivutil::get_algorithm_id_by_certificate(certificate) {
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
                        match ecdsautil::ecdsa_verify(algorithm, pk_point, &hash_bytes, &signature) {
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

                        let keypair = opt_result!(Rsa::public_key_from_der_pkcs1(pk_rsa), "Parse RSA failed: {}");
                        // let pub_key_der = opt_result!(keypair.public_key_to_der(), "RSA public key to der failed: {}");
                        // let pub_key_fingerprint = hex::encode(sha256_bytes(&pub_key_der));
                        let mut dmesg = vec![0; ((keypair.n().num_bits() + 7) / 8) as usize];
                        let len = opt_result!(keypair.public_decrypt(&signature, &mut dmesg, Padding::NONE), "RSA public key calc failed: {}");
                        debugging!("RSA public key pem: {}", hex::encode(pk_rsa));
                        debugging!("Public key calc: {}, len: {}", hex::encode(&dmesg), len);

                        // TODO SHOULD IMPROVE VERIFICATION METHOD IN THE FUTURE
                        if hex::encode(dmesg).ends_with(&hex::encode(&hash_bytes)) {
                            success!("Verify RSA Sign succeed.");
                        } else {
                            failure!("Verify RSA Sign failed.");
                        }
                    }
                }
            }
        }

        if json_output {
            util::print_pretty_json(&json);
        }
        Ok(None)
    }
}
