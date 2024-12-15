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
        "se-generate"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Secure Enclave generate subcommand")
            .arg(
                Arg::with_name("type")
                    .long("type")
                    .required(true)
                    .takes_value(true)
                    .help("Type signing or key_agreement"),
            )
            .arg(
                Arg::with_name("host")
                    .long("host")
                    .required(false)
                    .takes_value(true)
                    .help("Host name"),
            )
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        if !seutil::is_support_se() {
            return simple_error!("Secure Enclave is NOT supported.");
        }
        let ty = sub_arg_matches.value_of("type").unwrap();
        let host = sub_arg_matches.value_of("host").unwrap_or("macbook");
        let json_output = sub_arg_matches.is_present("json");
        if json_output {
            util_msg::set_logger_std_out(false);
        }

        let sign = match ty {
            "signing" | "ecsign" | "sign" => true,
            "key_agreement" | "ecdh" | "dh" => false,
            _ => return simple_error!("Invalid type: {}", ty),
        };

        let (public_key_point, public_key_der, private_key) =
            seutil::generate_secure_enclave_p256_keypair(sign)?;

        let public_key_point_hex = hex::encode(&public_key_point);
        let public_key_pem = bytes_to_pem("PUBLIC KEY", &*public_key_der);
        let key = format!(
            "key://{}:se/p256:{}:{}",
            host,
            iff!(sign, "signing", "key_agreement"),
            private_key,
        );
        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();
            json.insert("public_key_point", public_key_point_hex);
            json.insert("public_key_pem", base64_encode(&*public_key_der));
            json.insert("key", key);

            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            success!("Public key(point): {}", public_key_point_hex);
            success!("Public key PEM: \n{}", public_key_pem);
            success!("Key: {}", key);
        }

        Ok(None)
    }
}
