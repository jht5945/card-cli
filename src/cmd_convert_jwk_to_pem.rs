use crate::util::base64_encode;
use crate::{cmdutil, ecutil, util};
use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use std::collections::BTreeMap;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "convert-jwk-to-pem"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Convert PEM to JWK")
            .arg(
                Arg::with_name("jwk")
                    .long("jwk")
                    .required(true)
                    .takes_value(true)
                    .help("JWK"),
            )
            .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let jwk = sub_arg_matches.value_of("jwk").unwrap();
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let (public_key_pem, public_ker_der) = ecutil::convert_ec_jwk_to_public_key(jwk)?;

        let mut json = BTreeMap::<&'_ str, String>::new();
        if json_output {
            json.insert("public_key_pem", public_key_pem);
            json.insert("public_key_base64", base64_encode(&public_ker_der));

            util::print_pretty_json(&json);
        } else {
            information!("Public key PEM:\n{}", &public_key_pem);
            information!("\nPublic key base64:\n{}", base64_encode(&public_ker_der));
        }

        Ok(None)
    }
}
