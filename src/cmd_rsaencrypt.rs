use std::fs;
use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use openssl::encrypt::Encrypter;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;

use crate::digest::sha256_bytes;

pub struct CommandImpl;

// https://docs.rs/openssl/0.10.36/openssl/encrypt/index.html
impl Command for CommandImpl {
    fn name(&self) -> &str { "rsa-encrypt" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("RSA encrypt subcommand")
            .arg(Arg::with_name("pub-key-in").long("pub-key-in").takes_value(true).help("Public key in"))
            .arg(Arg::with_name("data").long("data").takes_value(true).help("Data"))
            .arg(Arg::with_name("data-hex").long("data-hex").takes_value(true).help("Data in HEX"))
            .arg(Arg::with_name("padding").long("padding").takes_value(true)
                .possible_values(&["pkcs1", "oaep", "pss", "none"]).help("Padding"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let pub_key_in = opt_value_result!(sub_arg_matches.value_of("pub-key-in"), "Require public key in");
        let pub_key_bytes = opt_result!(fs::read(pub_key_in), "Read file: {}, failed: {}", pub_key_in);

        let padding_opt = sub_arg_matches.value_of("padding");
        let padding = crate::rsautil::parse_padding(padding_opt)?;
        let padding_str = crate::rsautil::padding_to_string(padding);

        let mut json = BTreeMap::new();

        let keypair = opt_result!(Rsa::public_key_from_pem(&pub_key_bytes), "Parse RSA failed: {}");
        let pub_key_der = opt_result!(keypair.public_key_to_der(), "RSA public key to der failed: {}");
        let pub_key_fingerprint = hex::encode(sha256_bytes(&pub_key_der));
        let keypair = opt_result!(PKey::from_rsa(keypair), "RSA to PKey failed: {}");

        let data = if let Some(data_hex) = sub_arg_matches.value_of("data-hex") {
            opt_result!(hex::decode(data_hex), "Decode data HEX failed: {}")
        } else if let Some(data) = sub_arg_matches.value_of("data") {
            data.as_bytes().to_vec()
        } else {
            return simple_error!("Data is required, --data-hex or --data argument!");
        };

        let mut encrypter = opt_result!(Encrypter::new(&keypair), "Encrypter new failed: {}");
        opt_result!(encrypter.set_rsa_padding(padding), "Set RSA padding failed: {}");
        let buffer_len = opt_result!(encrypter.encrypt_len(&data), "Encrypt len failed: {}");
        let mut encrypted = vec![0; buffer_len];
        let encrypted_len = opt_result!(encrypter.encrypt(&data, &mut encrypted), "Encrypt failed: {}");
        encrypted.truncate(encrypted_len);

        let encrypted_hex = hex::encode(&encrypted);
        information!("Message: {}", String::from_utf8_lossy(&data));
        information!("Message HEX: {}", hex::encode(&data));
        information!("Padding: {}", padding_str);
        information!("Public key fingerprint: {}", pub_key_fingerprint);
        success!("Encrypted message: {}", encrypted_hex);
        if json_output {
            json.insert("data", hex::encode(&data));
            json.insert("public_key_fingerprint", pub_key_fingerprint);
            json.insert("padding", padding_str.to_string());
            json.insert("encrypted", encrypted_hex);
        }

        if json_output {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }

        Ok(None)
    }
}
