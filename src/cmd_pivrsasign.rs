use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_msg;
use rust_util::util_clap::{Command, CommandError};
use yubikey::{piv, YubiKey};
use yubikey::piv::{AlgorithmId, SlotId};

use crate::rsautil;
use crate::util::base64_encode;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-sign" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV RSA Sign(with SHA256) subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).default_value("123456").help("OpenPGP card user pin"))
            .arg(Arg::with_name("sha256").short("2").long("sha256").takes_value(true).help("Digest SHA256 HEX"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let pin_opt = sub_arg_matches.value_of("pin");
        let pin = opt_value_result!(pin_opt, "User pin must be assigned");

        let sha256_hex_opt = sub_arg_matches.value_of("sha256").map(|s| s.to_string());

        let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
        opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");

        if let Some(sha256_hex) = sha256_hex_opt {
            let sha256 = opt_result!(hex::decode(sha256_hex), "Decode sha256 failed: {}");
            let raw_in = rsautil::pkcs15_rsa_2048_sign_padding(&sha256);
            let sign_result = piv::sign_data(&mut yk, &raw_in, AlgorithmId::Rsa2048, SlotId::Signature);
            let sign = opt_result!(sign_result, "Sign data failed: {}");
            let sign_bytes = sign.as_slice();

            if json_output {
                let mut json = BTreeMap::<&'_ str, String>::new();
                json.insert("hash_hex", hex::encode(&sha256));
                json.insert("sign_hex", hex::encode(sign_bytes));
                json.insert("sign_base64", base64_encode(sign_bytes));
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            } else {
                success!("Signature HEX: {}", hex::encode(sign_bytes));
                success!("Signature base64: {}", base64_encode(sign_bytes));
            }
        }
        Ok(None)
    }
}

