use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use yubikey::piv::{AlgorithmId, SlotId};
use yubikey::YubiKey;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-decrypt" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV Decrypt(RSA) subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).default_value("123456").help("OpenPGP card user pin"))
            .arg(Arg::with_name("encrypted-data").long("encrypted-data").takes_value(true).help("Encrypted data"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let pin_opt = sub_arg_matches.value_of("pin");
        let pin = opt_value_result!(pin_opt, "User pin must be assigned");

        let encrypted_data = if let Some(encrypted_data_hex) = sub_arg_matches.value_of("encrypted-data") {
            opt_result!(hex::decode(encrypted_data_hex), "Decode --encrypted-data failed: {}")
        } else {
            return simple_error!("Argument --data or --data-hex must assign one");
        };

        let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
        opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");

        let sign_result = yubikey::piv::sign_data(&mut yk, &encrypted_data, AlgorithmId::Rsa2048, SlotId::KeyManagement);
        let decrypted_data = opt_result!(sign_result, "Decrypt data failed: {}");
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
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        Ok(None)
    }
}
