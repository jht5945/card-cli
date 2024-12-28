use crate::keyutil::{parse_key_uri, KeyUri, KeyUsage};
use crate::pkiutil::bytes_to_pem;
use crate::seutil;
use crate::util::base64_encode;
use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use std::collections::BTreeMap;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "se-recover"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Secure Enclave recover subcommand")
            .arg(
                Arg::with_name("key")
                    .long("key")
                    .required(true)
                    .takes_value(true)
                    .help("Key uri"),
            )
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        if !seutil::is_support_se() {
            return simple_error!("Secure Enclave is NOT supported.");
        }
        let key = sub_arg_matches.value_of("key").unwrap();

        let json_output = sub_arg_matches.is_present("json");
        if json_output {
            util_msg::set_logger_std_out(false);
        }

        let KeyUri::SecureEnclaveKey(se_key_uri) = parse_key_uri(key)?;
        debugging!("Secure enclave key URI: {:?}", se_key_uri);

        let (public_key_point, public_key_der, _private_key) =
            seutil::recover_secure_enclave_p256_public_key(
                &se_key_uri.private_key,
                se_key_uri.usage == KeyUsage::Singing,
            )?;

        let public_key_point_hex = hex::encode(&public_key_point);
        let public_key_pem = bytes_to_pem("PUBLIC KEY", &*public_key_der);
        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();
            json.insert("public_key_point", public_key_point_hex);
            json.insert("public_key_pem", base64_encode(&*public_key_der));
            json.insert("key", key.to_string());

            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            success!("Public key(point): {}", public_key_point_hex);
            success!("Public key PEM: \n{}", public_key_pem);
            success!("Key: {}", key);
        }

        Ok(None)
    }
}
