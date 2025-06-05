use crate::{ecutil, rsautil, util};
use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use serde_json::Value;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "convert-pem-to-jwk"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Convert PEM to JWK")
            .arg(
                Arg::with_name("public-key")
                    .long("public-key")
                    .required(true)
                    .takes_value(true)
                    .help("Public key (PEM, base64(DER) format)"),
            )
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let public_key = sub_arg_matches.value_of("public-key").unwrap();

        let jwk = match ecutil::convert_ec_public_key_to_jwk(public_key) {
            Ok(jwk) => jwk,
            Err(_) => match rsautil::convert_rsa_to_jwk(public_key) {
                Ok(jwk) => jwk,
                Err(_) => return simple_error!("Invalid public key."),
            },
        };

        let jwk_value: Value = serde_json::from_str(&jwk).unwrap();

        util::print_pretty_json(&jwk_value);

        Ok(None)
    }
}
