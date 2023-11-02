use std::ops::Deref;

use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use yubico_manager::config::{Config, Mode, Slot};
use yubico_manager::Yubico;

use crate::hmacutil;

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

        let challenge_bytes = hmacutil::get_challenge_bytes(sub_arg_matches)?;

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

            hmacutil::output_hmac_result(sub_arg_matches, json_output, challenge_bytes, hmac_result.deref());
        } else {
            warning!("YubiKey not found");
            return Ok(Some(1));
        }

        Ok(None)
    }
}
