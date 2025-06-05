use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use x509_parser::nom::AsBytes;
use yubikey::piv::{metadata, sign_data, AlgorithmId, ManagementAlgorithmId};

use crate::util::base64_encode;
use crate::{argsutil, cmdutil, pivutil, util, yubikeyutil};
use crate::digestutil::DigestAlgorithm;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-ecsign" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV EC sign(with SHA256/SHA384) subcommand")
            .arg(cmdutil::build_slot_arg())
            .arg(cmdutil::build_pin_arg())
            .arg(cmdutil::build_no_pin_arg())
            .arg(Arg::with_name("algorithm").short("a").long("algorithm").takes_value(true).help("Algorithm, p256 or p384"))
            .arg(Arg::with_name("file").short("f").long("file").takes_value(true).help("Input file"))
            .arg(Arg::with_name("input").short("i").long("input").takes_value(true).help("Input"))
            .arg(Arg::with_name("hash-hex").short("x").long("hash-hex").takes_value(true).help("Hash"))
            .arg(cmdutil::build_json_arg())
            .arg(cmdutil::build_serial_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let mut json = BTreeMap::<&'_ str, String>::new();

        let slot = opt_value_result!(sub_arg_matches.value_of("slot"), "--slot must assigned, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e");
        let (algorithm, algorithm_str, digest_algorithm) = match sub_arg_matches.value_of("algorithm") {
            None | Some("p256") => (AlgorithmId::EccP256, "ecdsa_p256_with_sha256", DigestAlgorithm::Sha256),
            Some("p384") => (AlgorithmId::EccP384, "ecdsa_p384_with_sha384", DigestAlgorithm::Sha384),
            Some(unknown_algorithm) => return simple_error!("Unknown algorithm {}, e.g. p256 or p384", unknown_algorithm),
        };
        let hash_bytes = argsutil::get_digest_or_hash(sub_arg_matches, digest_algorithm)?;

        let mut yk = yubikeyutil::open_yubikey_with_args(sub_arg_matches)?;
        let slot_id = pivutil::get_slot_id(slot)?;
        let pin_opt = pivutil::check_read_pin(&mut yk, slot_id, sub_arg_matches);

        if let Some(pin) = &pin_opt {
            opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");
        }

        if let Ok(slot_metadata) = metadata(&mut yk, slot_id) {
            match slot_metadata.algorithm {
                ManagementAlgorithmId::PinPuk | ManagementAlgorithmId::ThreeDes => {
                    return simple_error!("Slot not supports PIV sign: {:?}", slot_metadata.algorithm);
                }
                ManagementAlgorithmId::Asymmetric(slot_algorithm) => {
                    if AlgorithmId::Rsa1024 == slot_algorithm || AlgorithmId::Rsa2048 == algorithm {
                        return simple_error!("Slot supports PIV RSA sign: {:?}, but requires ECDSA", slot_metadata.algorithm);
                    }
                    if slot_algorithm != algorithm {
                        return simple_error!("Slot supported PIV sign not match: {:?}", slot_metadata.algorithm);
                    }
                }
            }
        }

        let signed_data = opt_result!(sign_data(&mut yk, &hash_bytes, algorithm, slot_id), "Sign PIV failed: {}");

        if json_output {
            json.insert("slot", slot_id.to_string());
            json.insert("algorithm", algorithm_str.to_string());
            json.insert("hash_hex", hex::encode(&hash_bytes));
            json.insert("signed_data_hex", hex::encode(signed_data.as_bytes()));
            json.insert("signed_data_base64", base64_encode(signed_data.as_bytes()));
        } else {
            information!("Slot: {:?}", slot_id);
            information!("Algorithm: {}", algorithm_str);
            information!("Hash hex: {}", hex::encode(&hash_bytes));
            information!("Signed data base64: {}", base64_encode(signed_data.as_bytes()));
            information!("Signed data hex: {}", hex::encode(signed_data.as_bytes()));
        }

        if json_output {
            util::print_pretty_json(&json);
        }
        Ok(None)
    }
}
