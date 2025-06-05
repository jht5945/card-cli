use crate::util;
use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use serde_json::Value;
use std::collections::BTreeMap;

pub struct CommandImpl;

// https://openwebstandard.org/rfc1
impl Command for CommandImpl {
    fn name(&self) -> &str {
        "external_spec"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("External spec subcommand")
            .arg(Arg::with_name("external-command").long("external-command").takes_value(true).help("External command"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let external_command_opt = sub_arg_matches.value_of("external-command");

        if let Some(external_command) = external_command_opt {
            let spec = external_command_rs::external_spec(external_command)?;
            util::print_pretty_json(&spec);
        } else {
            let mut json = BTreeMap::new();
            json.insert("success", Value::Bool(true));
            json.insert(
                "agent",
                format!("card-external-provider/{}", env!("CARGO_PKG_VERSION")).into(),
            );
            json.insert("specification", "External/1.0.0-alpha".into());
            json.insert("commands", vec!["external_public_key", "external_sign", "external_ecdh"].into());

            util::print_pretty_json(&json);
        }
        Ok(None)
    }
}
