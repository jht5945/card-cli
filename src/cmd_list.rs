use std::collections::BTreeMap;

use clap::{App, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use serde_json::Value;
use crate::{cmdutil, util, yubikeyutil};

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "list" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("YubiKey list")
            .arg(cmdutil::build_json_arg())
            .arg(cmdutil::build_serial_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let mut yk = yubikeyutil::open_yubikey_with_args(sub_arg_matches)?;

        if json_output {
            let mut json = BTreeMap::<&'_ str, Value>::new();
            json.insert("name", yk.name().into());
            json.insert("version", yk.version().to_string().into());
            json.insert("serial", yk.serial().0.into());
            if let Ok(pin_retries) = yk.get_pin_retries() {
                json.insert("pin_retries", pin_retries.into());
            }
            if let Ok(chuid) = yk.chuid() {
                json.insert("chuid", chuid.to_string().into());
            }
            if let Ok(ccuid) = yk.cccid() {
                json.insert("ccuid", ccuid.to_string().into());
            }
            if let Ok(piv_keys) = yk.piv_keys() {
                let key_list = piv_keys.iter().map(|k| Value::String(format!("{}", k.slot()))).collect::<Vec<_>>();
                json.insert("key_list", key_list.into());
                let keys = piv_keys.iter().map(|k| format!("{}", k.slot())).collect::<Vec<_>>().join(", ");
                json.insert("keys", keys.into());
            }

            util::print_pretty_json(&json);
        } else {
            success!("Name: {}", yk.name());
            success!("Version: {}", yk.version());
            success!("Serial: {}", yk.serial().0);
            // success!("{:?}", yk.config());
            if let Ok(pin_retries) = yk.get_pin_retries() {
                success!("PIN retries: {}", pin_retries);
            }
            if let Ok(config) = yk.config() {
                information!("Protected data available: {}", config.protected_data_available);
                information!("PIN last changed: {:?}", config.pin_last_changed);
                information!("PUK blocked: {}", config.puk_blocked);
                information!("PUK noblock on upgrade: {}", config.puk_noblock_on_upgrade);
                information!("PUK mgm type: {:?}", config.mgm_type);
            }
            if let Ok(chuid) = yk.chuid() {
                information!("Chuid: {}", chuid)
            }
            if let Ok(ccuid) = yk.cccid() {
                information!("Ccuid: {}", ccuid)
            }
            if let Ok(piv_keys) = yk.piv_keys() {
                information!("PIV keys: {}, slots: [{}]",
                    piv_keys.len(),
                    piv_keys.iter().map(|k| format!("{}", k.slot())).collect::<Vec<_>>().join(", ")
                );
            }
        }

        Ok(None)
    }
}
