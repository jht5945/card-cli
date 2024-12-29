use std::{env, fs};
use clap::ArgMatches;
use pinentry::PassphraseInput;
use secrecy::ExposeSecret;

const PIN_ENTRY_ENV: &str = "PIN_ENTRY_CMD";
const PIN_ENTRY_1: &str = "/usr/local/MacGPG2/libexec/pinentry-mac.app/Contents/MacOS/pinentry-mac";
const PIN_ENTRY_DEFAULT: &str = "pinentry";

pub fn read_pin(sub_arg_matches: &ArgMatches) -> Option<String> {
     if sub_arg_matches.is_present("no-pin") {
        None
    } else {
        let pin_opt = sub_arg_matches.value_of("pin");
        get_pin(pin_opt)
    }
}

pub fn get_pin(pin_opt: Option<&str>) -> Option<String> {
    if let Some(pin) = pin_opt {
        return Some(pin.to_string());
    }
    let pin_entry = get_pin_entry();

    if let Some(mut input) = PassphraseInput::with_binary(pin_entry) {
        let secret = input
            .with_description("Please input PIN.")
            .with_prompt("PIN: ")
            .interact();
        match secret {
            Ok(secret_string) => Some(secret_string.expose_secret().to_string()),
            Err(e) => {
                warning!("Input PIN failed: {}", e);
                None
            }
        }
    } else {
        match rpassword::prompt_password("Please input PIN: ") {
            Ok(pin) => Some(pin),
            Err(e) => {
                warning!("Input PIN failed: {}", e);
                None
            }
        }
    }
}

fn get_pin_entry() -> String {
    if let Ok(pin_entry) = env::var(PIN_ENTRY_ENV) {
        return pin_entry;
    }
    if let Ok(m) = fs::metadata(PIN_ENTRY_1) {
        if m.is_file() {
            return PIN_ENTRY_1.to_string();
        }
    }
    PIN_ENTRY_DEFAULT.to_string()
}