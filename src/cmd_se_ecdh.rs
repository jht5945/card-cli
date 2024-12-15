use crate::keyutil::{parse_key_uri, KeyUri};
use crate::seutil;
use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use std::collections::BTreeMap;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "se-ecdh"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Secure Enclave ECDH subcommand")
            .arg(
                Arg::with_name("key")
                    .long("key")
                    .required(true)
                    .takes_value(true)
                    .help("Key uri"),
            )
            .arg(
                Arg::with_name("epk")
                    .long("epk")
                    .required(true)
                    .takes_value(true)
                    .help("E-Public key"),
            )
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        if !seutil::is_support_se() {
            return simple_error!("Secure Enclave is NOT supported.");
        }
        let key = sub_arg_matches.value_of("key").unwrap();
        let epk = sub_arg_matches.value_of("epk").unwrap();

        let json_output = sub_arg_matches.is_present("json");
        if json_output {
            util_msg::set_logger_std_out(false);
        }

        let KeyUri::SecureEnclaveKey(se_key_uri) = parse_key_uri(key)?;
        debugging!("Secure enclave key URI: {:?}", se_key_uri);

        let ephemeral_public_key_bytes = hex::decode(epk)?;
        let dh =
            seutil::secure_enclave_p256_dh(&se_key_uri.private_key, &ephemeral_public_key_bytes)?;
        let dh_hex = hex::encode(&dh);

        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();

            json.insert("shared_secret_hex", dh_hex);
        } else {
            information!("Shared secret: {}", dh_hex);
        }

        Ok(None)
    }
}
