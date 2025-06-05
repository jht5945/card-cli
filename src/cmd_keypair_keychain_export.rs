use crate::{cmdutil, util};
use crate::keychain::{KeychainKey, KeychainKeyValue};
use clap::{App, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "keypair-keychain-export"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Export software keypair from keychain")
            .arg(cmdutil::build_keychain_name_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let keychain_name = sub_arg_matches.value_of("keychain-name");

        if let Some(keychain_name) = keychain_name {
            let keychain_key = KeychainKey::from_key_name_default(keychain_name);
            if let Some(keychain_key_value_bytes) = keychain_key.get_password()? {
                let keychain_key_value: KeychainKeyValue =
                    serde_json::from_slice(&keychain_key_value_bytes)?;
                util_msg::set_logger_std_out(false);
                information!("Keychain key URI: {}", keychain_key.to_key_uri());
                util::print_pretty_json(&keychain_key_value);
            } else {
                return simple_error!("Keychain key URI: {} not found", keychain_key.to_key_uri());
            }
        }

        Ok(None)
    }
}
