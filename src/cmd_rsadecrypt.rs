use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use openssl::bn::{BigNum, BigNumContext};
use openssl::encrypt::Decrypter;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use rust_util::util_msg::MessageType;

pub struct CommandImpl;

// https://docs.rs/openssl/0.10.36/openssl/encrypt/index.html
impl Command for CommandImpl {
    fn name(&self) -> &str { "rsa-decrypt" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("RSA Decrypt subcommand")
            .arg(Arg::with_name("pri-key-in").long("pri-key-in").takes_value(true).help("Private key in"))
            .arg(Arg::with_name("encrypted").long("encrypted").takes_value(true).help("Encrypted data"))
            .arg(Arg::with_name("padding").long("padding").takes_value(true)
                .possible_values(&["pkcs1", "oaep", "pss", "none"]).help("Padding"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let pri_key_in = opt_value_result!(sub_arg_matches.value_of("pri-key-in"), "Require private key in");
        let pri_key_bytes = opt_result!(std::fs::read(pri_key_in), "Read file: {}, failed: {}", pri_key_in);

        let padding_opt = sub_arg_matches.value_of("padding");
        let padding = crate::rsautil::parse_padding(padding_opt)?;
        let padding_str = crate::rsautil::padding_to_string(padding);

        let mut json = BTreeMap::new();

        let keypair = opt_result!(Rsa::private_key_from_pem(&pri_key_bytes), "Parse RSA failed: {}");
        let keypair = opt_result!(PKey::from_rsa(keypair), "RSA to PKey failed: {}");

        let encrypted = if let Some(encrypted) = sub_arg_matches.value_of("encrypted") {
            opt_result!(hex::decode(encrypted), "Decode encrypted HEX failed: {}")
        } else {
            return simple_error!("Data is required, --data-hex or --data argument!");
        };

        util_msg::when(MessageType::DEBUG, || {
            let rsa = keypair.rsa().unwrap();
            let n = rsa.n();
            let d = rsa.d();
            let m = BigNum::from_slice(&encrypted).unwrap();
            let mut r = BigNum::new().unwrap();
            r.mod_exp(&m, d, n, &mut BigNumContext::new().unwrap()).unwrap();
            let v = r.to_vec();
            debugging!("Encrypted raw HEX: 00{}", hex::encode(&v));
            let pos = v.iter().position(|b| *b == 0x00);
            if let Some(pos) = pos {
                debugging!("Encrypted text HEX: {}", hex::encode(&v[pos+1..]));
            }
        });

        let mut decrypter = opt_result!(Decrypter::new(&keypair), "Decrypter new failed: {}");
        opt_result!(decrypter.set_rsa_padding(padding), "Set RSA padding failed: {}");
        let buffer_len = opt_result!(decrypter.decrypt_len(&encrypted), "Decrypt len failed: {}");
        let mut data = vec![0; buffer_len];
        let decrypted_len = opt_result!(decrypter.decrypt(&encrypted, &mut data), "Decrypt failed: {}");
        data.truncate(decrypted_len);

        let encrypted_hex = hex::encode(&encrypted);
        information!("Padding: {}", padding_str);
        success!("Message HEX: {}", hex::encode(&data));
        success!("Message: {}", String::from_utf8_lossy(&data));
        if json_output {
            json.insert("data", hex::encode(&data));
            json.insert("padding", padding_str.to_string());
            json.insert("encrypted", encrypted_hex);
        }

        if json_output {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }

        Ok(None)
    }
}
