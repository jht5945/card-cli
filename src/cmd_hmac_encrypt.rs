use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use std::collections::BTreeMap;
use rust_util::XResult;
use crate::{cmdutil, hmacutil, pbeutil, util};

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "hmac-encrypt"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("YubiKey HMAC encrypt")
            .arg(Arg::with_name("plaintext").long("plaintext").short("t").takes_value(true).required(true).help("Plaintext"))
            .arg(Arg::with_name("password").long("password").short("P").takes_value(true).help("Password"))
            .arg(cmdutil::build_with_pbe_encrypt_arg())
            .arg(cmdutil::build_double_pin_check_arg())
            .arg(cmdutil::build_pbe_iteration_arg())
            .arg(Arg::with_name("without-hmac-encrypt").long("without-hmac-encrypt").help("Without HMAC encrypt"))
            .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);
        let without_hmac_encrypt = sub_arg_matches.is_present("without-hmac-encrypt");
        if without_hmac_encrypt && !sub_arg_matches.is_present("with-pbe-encrypt") {
            return simple_error!("hmac and pbe encryption must present at least one");
        }

        let text = sub_arg_matches.value_of("plaintext").unwrap().to_string();
        let mut pin_opt = sub_arg_matches.value_of("password").map(|p| p.to_string());
        let ciphertext = do_encrypt(&text, &mut pin_opt, sub_arg_matches)?;

        let ciphertext = if without_hmac_encrypt {
            ciphertext
        } else {
            hmacutil::hmac_encrypt_from_string(&ciphertext)?
        };

        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();
            json.insert("ciphertext", ciphertext);

            util::print_pretty_json(&json);
        } else {
            success!("HMAC encrypt ciphertext: {}", ciphertext);
        }

        Ok(None)
    }
}

pub fn do_encrypt(text: &str, password_opt: &mut Option<String>, sub_arg_matches: &ArgMatches) -> XResult<String> {
    let with_hmac_encrypt = sub_arg_matches.is_present("with-hmac-encrypt");
    let with_pbe_encrypt = sub_arg_matches.is_present("with-pbe-encrypt");
    let text = if with_pbe_encrypt {
        let double_pin_check = sub_arg_matches.is_present("double-pin-check");
        let iteration = sub_arg_matches.value_of("pbe-iteration")
            .map(|x| x.parse::<u32>().unwrap()).unwrap_or(100000);
        pbeutil::simple_pbe_encrypt_with_prompt_from_string(iteration, &text, password_opt, double_pin_check)?
    } else {
        text.to_string()
    };
    if with_hmac_encrypt {
        Ok(hmacutil::hmac_encrypt_from_string(&text)?)
    } else {
        Ok(text)
    }
}
