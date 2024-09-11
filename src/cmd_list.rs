use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use yubikey::YubiKey;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "list" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("YubiKey list")
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");

        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();
            json.insert("name", yk.name().to_string());
            json.insert("version", yk.version().to_string());
            json.insert("serial", yk.serial().0.to_string());
            if let Ok(pin_retries) = yk.get_pin_retries() {
                json.insert("pin_retries", pin_retries.to_string());
            }
            if let Ok(chuid) = yk.chuid() {
                json.insert("chuid", chuid.to_string());
            }
            if let Ok(ccuid) = yk.cccid() {
                json.insert("ccuid", ccuid.to_string());
            }
            if let Ok(piv_keys) = yk.piv_keys() {
                json.insert("keys", piv_keys.iter().map(|k| format!("{}", k.slot())).collect::<Vec<_>>().join(", "));
            }

            println!("{}", serde_json::to_string_pretty(&json).expect("Convert to JSON failed!"));
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
