use crate::seutil;
use clap::{App, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "se"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("Secure Enclave subcommand")
        // .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, _sub_arg_matches: &ArgMatches) -> CommandError {
        if seutil::is_support_se() {
            success!("Secure Enclave is supported.")
        } else {
            failure!("Secure Enclave is NOT supported.")
        }
        Ok(None)
    }
}
