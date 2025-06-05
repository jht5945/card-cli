use crate::cmdutil;
use crate::keychain::KeychainKey;
use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "keypair-keychain-import"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Import software keypair to keychain")
            .arg(cmdutil::build_keychain_name_arg())
            .arg(
                Arg::with_name("import-key-value")
                    .long("import-key-value")
                    .takes_value(true)
                    .help("Import key value"),
            )
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let keychain_name = sub_arg_matches.value_of("keychain-name");
        let import_key_value = sub_arg_matches.value_of("import-key-value");

        if let Some(keychain_name) = keychain_name {
            let keychain_key = KeychainKey::from_key_name_default(keychain_name);
            if keychain_key.get_password()?.is_some() {
                return simple_error!("Keychain key URI: {} exists", keychain_key.to_key_uri());
            }

            if let Some(import_key_value) = import_key_value {
                keychain_key.set_password(import_key_value.as_bytes())?;
            }
        }

        Ok(None)
    }
}
