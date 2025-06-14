use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use yubikey::piv::AlgorithmId;

use crate::{cmdutil, pinutil, pivutil, util, yubikeyutil};
use crate::util::{read_stdin, try_decode};

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-decrypt" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV decrypt(RSA) subcommand")
            .arg(cmdutil::build_slot_arg())
            .arg(cmdutil::build_pin_arg())
            .arg(cmdutil::build_no_pin_arg())
            .arg(Arg::with_name("ciphertext").long("ciphertext").short("c").takes_value(true).help("Encrypted data (HEX or Base64)"))
            .arg(Arg::with_name("stdin").long("stdin").help("Standard input (Ciphertext)"))
            .arg(cmdutil::build_json_arg())
            .arg(cmdutil::build_serial_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let slot = opt_value_result!(sub_arg_matches.value_of("slot"), "--slot must assigned, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e");

        let pin_opt = pinutil::read_pin(sub_arg_matches);

        let encrypted_data = if let Some(ciphertext) = sub_arg_matches.value_of("ciphertext") {
            opt_result!(try_decode(ciphertext), "Decode --ciphertext failed: {}")
        } else if sub_arg_matches.is_present("stdin") {
            read_stdin()?
        } else {
            return simple_error!("Argument --ciphertext must be assigned");
        };

        let mut yk = yubikeyutil::open_yubikey_with_args(sub_arg_matches)?;
        if let Some(pin) = &pin_opt {
            opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");
        }

        let slot_id = pivutil::get_slot_id(slot)?;
        let decrypt_result = yubikey::piv::decrypt_data(&mut yk, &encrypted_data,
                                                        AlgorithmId::Rsa2048, slot_id);
        let decrypted_data = opt_result!(decrypt_result, "Decrypt data failed: {}");
        let decrypted_data_bytes = decrypted_data.as_slice();

        information!("Decrypted raw data: {}", hex::encode(decrypted_data_bytes));
        if !(decrypted_data_bytes[0] == 0x00 && decrypted_data_bytes[1] == 0x02) {
            return simple_error!("Not valid encrypted data, prefix: {}", hex::encode(&decrypted_data_bytes[0..2]));
        }
        let mut index_of_00_from_index_1 = 0;
        for (i, byte) in decrypted_data_bytes.iter().enumerate().skip(1) {
            if *byte == 0x00 {
                index_of_00_from_index_1 = i + 1;
                break;
            }
        }
        if index_of_00_from_index_1 == 0 {
            return simple_error!("Not valid encrypted data, cannot find 0x00");
        }
        let clear_data = &decrypted_data_bytes[index_of_00_from_index_1..];
        success!("Decrypt data: {}", hex::encode(clear_data));
        success!("Decrypt data in UTF-8: {}", String::from_utf8_lossy(clear_data));

        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();
            json.insert("encrypted_data_hex", hex::encode(&encrypted_data));
            json.insert("decrypted_data_hex", hex::encode(decrypted_data_bytes));
            json.insert("clear_data_hex", hex::encode(clear_data));
            json.insert("clear_data", String::from_utf8_lossy(clear_data).to_string());

            util::print_pretty_json(&json);
        }
        Ok(None)
    }
}
