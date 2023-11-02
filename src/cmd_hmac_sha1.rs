use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::{util_msg, XResult};
use rust_util::util_clap::{Command, CommandError};

use crate::hmacutil;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "hmac-sha1" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("YubiKey HMAC-SHA1")
            .arg(Arg::with_name("secret").short("s").long("secret").takes_value(true).help("Secret in HEX"))
            .arg(Arg::with_name("variable").long("variable").help("Variable"))
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

        let variable = sub_arg_matches.is_present("variable");
        let secret_bytes = get_secret_bytes(sub_arg_matches)?;
        let challenge_bytes = hmacutil::get_challenge_bytes(sub_arg_matches)?;

        let hmac_result = hmacutil::calculate_hmac_sha1_result(&secret_bytes, &challenge_bytes, variable);

        hmacutil::output_hmac_result(sub_arg_matches, json_output, challenge_bytes, &hmac_result);
        Ok(None)
    }
}

fn get_secret_bytes(sub_arg_matches: &ArgMatches) -> XResult<Vec<u8>> {
    let secret_bytes: Vec<u8> = if let Some(secret) = sub_arg_matches.value_of("secret") {
        opt_result!(hex::decode(secret), "Decode secret hex: {}, failed: {}", secret)
    } else {
        return simple_error!("Secret must assigned");
    };
    if secret_bytes.len() != 20 {
        return simple_error!("Secret length must be 20, actual is: {}", secret_bytes.len());
    }
    Ok(secret_bytes)
}
