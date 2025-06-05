use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use std::collections::BTreeMap;
use rust_util::XResult;
use crate::{cmdutil, pbeutil, util};
use crate::hmacutil::{hmac_decrypt_to_string, is_hmac_encrypted};

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "hmac-decrypt"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("YubiKey HMAC decrypt")
            .arg(Arg::with_name("ciphertext").long("ciphertext").short("t").takes_value(true).required(true).help("Ciphertext"), )
            .arg(Arg::with_name("auto-pbe").long("auto-pbe").help("Auto PBE decryption"))
            .arg(Arg::with_name("password").long("password").short("P").takes_value(true).help("Password"))
            .arg(Arg::with_name("outputs-password").long("outputs-password").help("Outputs password"))
            .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let ciphertext = sub_arg_matches.value_of("ciphertext").unwrap();
        let mut pin_opt = sub_arg_matches.value_of("password").map(|p| p.to_string());
        let auto_pbe = sub_arg_matches.is_present("auto-pbe");
        let outputs_password = sub_arg_matches.is_present("outputs-password");

        let text = try_decrypt_with_pbe_option(&mut pin_opt, ciphertext, auto_pbe)?;

        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();
            json.insert("plaintext", text);
            if let (true, Some(pin)) = (outputs_password, pin_opt.as_ref()) {
                json.insert("password", pin.to_string());
            }
            util::print_pretty_json(&json);
        } else {
            success!("Plaintext: {}", text);
        }
        Ok(None)
    }
}

pub fn try_decrypt(pin_opt: &mut Option<String>,ciphertext: &str) -> XResult<String> {
    try_decrypt_with_pbe_option(pin_opt, ciphertext, true)
}

pub fn try_decrypt_with_pbe_option(pin_opt: &mut Option<String>, ciphertext: &str, auto_pbe: bool) -> XResult<String> {
    if is_hmac_encrypted(ciphertext) {
        hmac_decrypt(pin_opt, ciphertext, auto_pbe)
    } else if pbeutil::is_simple_pbe_encrypted(ciphertext) {
        pbeutil::simple_pbe_decrypt_with_prompt_to_string(pin_opt,&ciphertext)
    } else {
        Ok(ciphertext.to_string())
    }
}

pub fn hmac_decrypt(pin_opt: &mut Option<String>, ciphertext: &str, auto_pbe: bool) -> XResult<String> {
    let text = hmac_decrypt_to_string(ciphertext)?;
    if auto_pbe && pbeutil::is_simple_pbe_encrypted(&text) {
        pbeutil::simple_pbe_decrypt_with_prompt_to_string(pin_opt, &text)
    } else {
        Ok(text)
    }
}
