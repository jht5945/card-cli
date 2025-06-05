use crate::util;
use clap::{App, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use serde_json::Value;
use std::collections::BTreeMap;
use yubikey::Context;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "yubikey"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("Yubikey subcommand")
    }

    fn run(&self, _arg_matches: &ArgMatches, _sub_arg_matches: &ArgMatches) -> CommandError {
        util_msg::set_logger_std_out(false);

        let mut list = vec![];
        let mut readers = Context::open()?;
        for reader in readers.iter()? {
            let yubikey = match reader.open() {
                Ok(yk) => yk,
                Err(e) => {
                    warning!("Error opening YubiKey: {}", e);
                    continue;
                }
            };

            let mut key = BTreeMap::new();
            key.insert("serial", Value::Number(yubikey.serial().0.into()));
            key.insert("version", yubikey.version().to_string().into());
            key.insert("name", yubikey.name().into());

            list.push(key);
        }
        util::print_pretty_json(&list);
        Ok(None)
    }
}
