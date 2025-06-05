use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};

use rust_util::util_clap::{Command, CommandError};
use crate::{cmdutil, util};
use crate::ecdsautil::parse_ecdsa_r_and_s;
use crate::util::try_decode;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "parse-ecdsa-signature"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Parse ECDSA signature")
            .arg(
                Arg::with_name("signature")
                    .long("signature")
                    .required(true)
                    .takes_value(true)
                    .help("ECDSA signature"),
            )
            .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let mut json = BTreeMap::<&'_ str, String>::new();

        let signature = sub_arg_matches.value_of("signature").unwrap();

        let signature_der = try_decode(signature)?;

        let (r, s) = parse_ecdsa_r_and_s(&signature_der)?;
        let mut r_and_s = r.clone();
        r_and_s.extend_from_slice(&s);

        if json_output {
            json.insert("r", hex::encode(&r));
            json.insert("s", hex::encode(&s));
            json.insert("rs", hex::encode(&r_and_s));
        } else {
            information!("R: {}", hex::encode(&r));
            information!("S: {}", hex::encode(&s));
            information!("RS: {}", hex::encode(&r_and_s));
        }

        if json_output {
            util::print_pretty_json(&json);
        }
        Ok(None)
    }
}
