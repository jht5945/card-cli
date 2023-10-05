use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use openpgp_card::crypto_data::Cryptogram;
use openpgp_card::OpenPgp;
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;

use crate::util::{base64_decode, base64_encode};

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "pgp-card-decrypt" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("OpenPGP Card Decrypt subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).default_value("123456").help("OpenPGP card user pin"))
            .arg(Arg::with_name("pass").long("pass").takes_value(true).help("[deprecated] now OpenPGP card user pin"))
            .arg(Arg::with_name("cipher").short("c").long("cipher").takes_value(true).help("Cipher text HEX"))
            .arg(Arg::with_name("cipher-base64").short("b").long("cipher-base64").takes_value(true).help("Cipher text base64"))
            .arg(Arg::with_name("algo").long("algo").takes_value(true).help("Algo: RSA, X25519/ECDH"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let pin_opt = sub_arg_matches.value_of("pass").or_else(|| sub_arg_matches.value_of("pin"));
        let pin = opt_value_result!(pin_opt, "User pin must be assigned");
        if pin.len() < 6 { return simple_error!("User pin length:{}, must >= 6!", pin.len()); }

        let cipher = sub_arg_matches.value_of("cipher");
        let cipher_base64 = sub_arg_matches.value_of("cipher-base64");

        let algo = sub_arg_matches.value_of("algo").unwrap_or("rsa").to_lowercase();

        let cipher_bytes = if let Some(cipher) = cipher {
            opt_result!(hex::decode(cipher), "Decode cipher failed: {}")
        } else if let Some(cipher_base64) = cipher_base64 {
            opt_result!(base64_decode(cipher_base64), "Decode cipher-base64 failed: {}")
        } else {
            return simple_error!("cipher or cipher-base64 must assign one");
        };

        let card = crate::pgpcardutil::get_card()?;
        let mut pgp = OpenPgp::new(card);
        let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");

        opt_result!(trans.verify_pw1_user(pin.as_ref()), "User pin verify failed: {}");
        success!("User pin verify success!");

        let text = match algo.as_str() {
            "rsa" => trans.decipher(Cryptogram::RSA(&cipher_bytes))?,
            "x25519" | "ecdh" => trans.decipher(Cryptogram::ECDH(&cipher_bytes))?,
            _ => return simple_error!("Unknown algo: {}", &algo),
        };
        // let text = trans.decipher(Cryptogram::RSA(&cipher_bytes))?;
        success!("Clear text HEX: {}", hex::encode(&text));
        success!("Clear text base64: {}", base64_encode(&text));
        success!("Clear text UTF-8: {}", String::from_utf8_lossy(&text));

        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();
            json.insert("cipher_hex", hex::encode(&cipher_bytes));
            json.insert("cipher_base64", base64_encode(&cipher_bytes));
            json.insert("text_hex", hex::encode(&text));
            json.insert("text_base64", base64_encode(&text));
            json.insert("text_utf8", String::from_utf8_lossy(&text).to_string());

            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        Ok(None)
    }
}
