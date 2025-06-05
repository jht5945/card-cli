use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};

use crate::{cmdutil, hmacutil};

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "chall" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("YubiKey challenge-response HMAC")
            .arg(Arg::with_name("challenge").short("c").long("challenge").takes_value(true).help("Challenge"))
            .arg(Arg::with_name("challenge-hex").short("x").long("challenge-hex").takes_value(true).help("Challenge HEX"))
            .arg(Arg::with_name("sha1").short("1").long("sha1").help("Output SHA1"))
            .arg(Arg::with_name("sha256").short("2").long("sha256").help("Output SHA256"))
            .arg(Arg::with_name("sha384").short("3").long("sha384").help("Output SHA384"))
            .arg(Arg::with_name("sha512").short("5").long("sha512").help("Output SHA512"))
            .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let challenge_bytes = hmacutil::get_challenge_bytes(sub_arg_matches)?;
        let hmac_result = hmacutil::compute_yubikey_hmac(&challenge_bytes)?;
        hmacutil::output_hmac_result(sub_arg_matches, json_output, challenge_bytes, &hmac_result);

        Ok(None)
    }
}
