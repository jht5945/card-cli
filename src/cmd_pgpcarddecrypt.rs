use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use openpgp_card::crypto_data::Cryptogram;
use rust_util::{util_msg, XResult};
use rust_util::util_clap::{Command, CommandError};

use crate::{pgpcardutil, pinutil};
use crate::util::{base64_encode, read_stdin, try_decode};

#[derive(Debug, Clone, Copy)]
enum EncryptAlgo {
    Rsa,
    Ecdh,
}

impl EncryptAlgo {
    fn from_str(algo: &str) -> XResult<Self> {
        match algo {
            "rsa" => Ok(Self::Rsa),
            "x25519" | "ecdh" => Ok(Self::Ecdh),
            _ => simple_error!("Unknown algo: {}", algo),
        }
    }
}

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "pgp-card-decrypt" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("OpenPGP Card decrypt subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).help("OpenPGP card user pin"))
            .arg(Arg::with_name("pass").long("pass").takes_value(true).help("[deprecated] now OpenPGP card user pin"))
            .arg(Arg::with_name("ciphertext").short("c").long("ciphertext").takes_value(true).help("Cipher text (HEX or Base64)"))
            .arg(Arg::with_name("stdin").long("stdin").help("Standard input (Ciphertext)"))
            .arg(Arg::with_name("algo").long("algo").takes_value(true).help("Algo: RSA, X25519/ECDH"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let pin_opt = sub_arg_matches.value_of("pass").or_else(|| sub_arg_matches.value_of("pin"));
        let pin_opt = pinutil::get_pin(pin_opt);
        let pin_opt = pin_opt.as_deref();
        let pin = opt_value_result!(pin_opt, "User pin must be assigned");
        if pin.len() < 6 { return simple_error!("User pin length:{}, must >= 6!", pin.len()); }

        let ciphertext = sub_arg_matches.value_of("ciphertext");

        let algo = sub_arg_matches.value_of("algo").unwrap_or("rsa").to_lowercase();
        let algo = EncryptAlgo::from_str(&algo)?;

        let ciphertext_bytes = if let Some(ciphertext) = ciphertext {
            opt_result!(try_decode(ciphertext), "Decode cipher failed: {}")
        } else if sub_arg_matches.is_present("stdin") {
            read_stdin()?
        } else {
            return simple_error!("--ciphertext must be assigned");
        };

        let mut pgp = pgpcardutil::get_openpgp_card()?;
        let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");

        opt_result!(trans.verify_pw1_user(pin.as_ref()), "User pin verify failed: {}");
        success!("User pin verify success!");

        let text = match algo {
            EncryptAlgo::Rsa => trans.decipher(Cryptogram::RSA(&ciphertext_bytes))?,
            EncryptAlgo::Ecdh => trans.decipher(Cryptogram::ECDH(&ciphertext_bytes))?,
        };
        success!("Clear text HEX: {}", hex::encode(&text));
        success!("Clear text base64: {}", base64_encode(&text));
        let text_opt = String::from_utf8(text.clone()).ok();
        if let Some(text) = &text_opt {
            success!("Clear text UTF-8: {}", text);
        }

        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();
            json.insert("cipher_hex", hex::encode(&ciphertext_bytes));
            json.insert("cipher_base64", base64_encode(&ciphertext_bytes));
            json.insert("text_hex", hex::encode(&text));
            json.insert("text_base64", base64_encode(&text));
            if let Some(text) = text_opt {
                json.insert("text_utf8", text);
            }

            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        Ok(None)
    }
}
