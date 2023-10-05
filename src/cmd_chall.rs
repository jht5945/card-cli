use std::collections::BTreeMap;
use std::ops::Deref;

use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use yubico_manager::config::{Config, Mode, Slot};
use yubico_manager::Yubico;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "chall" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("YubiKey challenge-response HMAC")
            .arg(Arg::with_name("challenge").short("c").long("challenge").takes_value(true).help("Challenge"))
            .arg(Arg::with_name("challenge-hex").short("x").long("challenge-hex").takes_value(true).help("Challenge HEX"))
            .arg(Arg::with_name("sha1").short("1").long("sha1").help("Output SHA1"))
            .arg(Arg::with_name("sha256").short("2").long("sha256").help("Output SHA256"))
            .arg(Arg::with_name("sha384").short("3").long("sha384").help("Output SHA256"))
            .arg(Arg::with_name("sha512").short("5").long("sha512").help("Output SHA256"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let sha1_output = sub_arg_matches.is_present("sha1");
        let sha256_output = sub_arg_matches.is_present("sha256");
        let sha384_output = sub_arg_matches.is_present("sha384");
        let sha512_output = sub_arg_matches.is_present("sha512");
        let challenge_bytes: Vec<u8> = if let Some(challenge) = sub_arg_matches.value_of("challenge") {
            challenge.as_bytes().to_vec()
        } else if let Some(challenge_hex) = sub_arg_matches.value_of("challenge-hex") {
            opt_result!(hex::decode(challenge_hex), "Decode challenge hex: {}, failed: {}", challenge_hex)
        } else {
            return simple_error!("Challenge must assigned");
        };

        // Challenge can not be greater than 64 bytes
        if challenge_bytes.len() > 64 {
            return simple_error!("Challenge bytes is: {}, more than 64", challenge_bytes.len());
        }

        let mut yubi = Yubico::new();

        if let Ok(device) = yubi.find_yubikey() {
            success!("Found key, Vendor ID: {:?}, Product ID: {:?}", device.vendor_id, device.product_id);

            let config = Config::default()
                .set_vendor_id(device.vendor_id)
                .set_product_id(device.product_id)
                .set_variable_size(true)
                .set_mode(Mode::Sha1)
                .set_slot(Slot::Slot2);

            // In HMAC Mode, the result will always be the SAME for the SAME provided challenge
            let hmac_result = opt_result!(yubi.challenge_response_hmac(&challenge_bytes, config), "Challenge HMAC failed: {}");

            // Just for debug, lets check the hex
            let v: &[u8] = hmac_result.deref();
            let hex_string = hex::encode(v);
            let hex_sha1 = iff!(sha1_output, Some(crate::digest::sha1_bytes(v)), None);
            let hex_sha256 = iff!(sha256_output, Some(crate::digest::sha256_bytes(v)), None);
            let hex_sha384 = iff!(sha384_output, Some(crate::digest::sha384_bytes(v)), None);
            let hex_sha512 = iff!(sha512_output, Some(crate::digest::sha512_bytes(v)), None);

            if json_output {
                let mut json = BTreeMap::<&'_ str, String>::new();
                json.insert("challenge_hex", hex::encode(challenge_bytes));
                json.insert("response_hex", hex_string);
                hex_sha1.map(|hex_sha1| json.insert("response_sha1_hex", hex::encode(hex_sha1)));
                hex_sha256.map(|hex_sha256| json.insert("response_sha256_hex", hex::encode(hex_sha256)));
                hex_sha384.map(|hex_sha384| json.insert("response_sha384_hex", hex::encode(hex_sha384)));
                hex_sha512.map(|hex_sha512| json.insert("response_sha512_hex", hex::encode(hex_sha512)));

                println!("{}", serde_json::to_string_pretty(&json).expect("Convert to JSON failed!"));
            } else {
                success!("Challenge HEX: {}", hex::encode(challenge_bytes));
                success!("Response HEX: {}", hex_string);
                if let Some(hex_sha256) = hex_sha256 { success!("Response SHA256 HEX: {}", hex::encode(hex_sha256)); }
                if let Some(hex_sha384) = hex_sha384 { success!("Response SHA384 HEX: {}", hex::encode(hex_sha384)); }
                if let Some(hex_sha512) = hex_sha512 { success!("Response SHA512 HEX: {}", hex::encode(hex_sha512)); }
            }
        } else {
            warning!("YubiKey not found");
            return Ok(Some(1));
        }

        Ok(None)
    }
}
