use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use yubikey::piv;
use yubikey::piv::{AlgorithmId, SlotId};

use crate::{cmdutil, pinutil, pivutil, rsautil, util, yubikeyutil};
use crate::util::base64_encode;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-sign" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV RSA sign(with SHA256) subcommand")
            .arg(cmdutil::build_slot_arg())
            .arg(cmdutil::build_pin_arg())
            .arg(cmdutil::build_no_pin_arg())
            .arg(Arg::with_name("sha256").short("2").long("sha256").takes_value(true).help("Digest SHA256 HEX"))
            .arg(cmdutil::build_json_arg())
            .arg(cmdutil::build_serial_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let pin_opt = pinutil::read_pin(sub_arg_matches);

        let sha256_hex_opt = sub_arg_matches.value_of("sha256").map(|s| s.to_string());

        let mut yk = yubikeyutil::open_yubikey_with_args(sub_arg_matches)?;
        if let Some(pin) = &pin_opt {
            opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");
        }

        let slot_id = match sub_arg_matches.value_of("slot") {
            None => SlotId::Signature,
            Some(slot) => pivutil::get_slot_id(slot)?,
        };
        information!("Using slot: {}", slot_id);

        if let Some(sha256_hex) = sha256_hex_opt {
            let sha256 = opt_result!(hex::decode(sha256_hex), "Decode sha256 failed: {}");
            let raw_in = rsautil::pkcs15_sha256_rsa_2048_padding_for_sign(&sha256);
            let sign_result = piv::sign_data(&mut yk, &raw_in, AlgorithmId::Rsa2048, slot_id);
            let sign = opt_result!(sign_result, "Sign data failed: {}");
            let sign_bytes = sign.as_slice();

            if json_output {
                let mut json = BTreeMap::<&'_ str, String>::new();
                json.insert("slot", pivutil::to_slot_hex(&slot_id));
                json.insert("hash_hex", hex::encode(&sha256));
                json.insert("sign_hex", hex::encode(sign_bytes));
                json.insert("sign_base64", base64_encode(sign_bytes));

                util::print_pretty_json(&json);
            } else {
                success!("Signature HEX: {}", hex::encode(sign_bytes));
                success!("Signature base64: {}", base64_encode(sign_bytes));
            }
        }
        Ok(None)
    }
}

