use crate::{cmdutil, seutil, util};
use clap::{App, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use std::collections::BTreeMap;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "se"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Secure Enclave subcommand")
            .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        if let Err(_) = which::which("swift-secure-enclave-tool") {
            failure!("Secure Enclave tool not found.");
        }

        if json_output {
            let mut json = BTreeMap::new();
            json.insert("se_supported", seutil::is_support_se());

            util::print_pretty_json(&json);
        } else {
            success!(
                "Secure Enclave is {}supported.",
                iff!(seutil::is_support_se(), "", "NOT ")
            );
        }
        Ok(None)
    }
}
