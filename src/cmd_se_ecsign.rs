use crate::keyutil::{parse_key_uri, KeyUri};
use crate::seutil;
use crate::util::{base64_decode, base64_encode};
use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use std::collections::BTreeMap;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "se-ecsign"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Secure Enclave EC sign subcommand")
            .arg(
                Arg::with_name("key")
                    .long("key")
                    .required(true)
                    .takes_value(true)
                    .help("Key uri"),
            )
            .arg(
                Arg::with_name("input")
                    .short("i")
                    .long("input")
                    .takes_value(true)
                    .help("Input"),
            )
            .arg(
                Arg::with_name("input-base64")
                    .long("input-base64")
                    .takes_value(true)
                    .help("Input in base64"),
            )
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        if !seutil::is_support_se() {
            return simple_error!("Secure Enclave is NOT supported.");
        }
        let key = sub_arg_matches.value_of("key").unwrap();
        let input_bytes = match sub_arg_matches.value_of("input") {
            None => match sub_arg_matches.value_of("input-base64") {
                None => return simple_error!("Argument --input or --input-base64 is required"),
                Some(input_base64) => base64_decode(input_base64)?,
            },
            Some(input) => input.as_bytes().to_vec(),
        };
        let json_output = sub_arg_matches.is_present("json");
        if json_output {
            util_msg::set_logger_std_out(false);
        }

        let KeyUri::SecureEnclaveKey(se_key_uri) = parse_key_uri(key)?;
        debugging!("Secure enclave key URI: {:?}", se_key_uri);

        let signature = seutil::secure_enclave_p256_sign(&se_key_uri.private_key, &input_bytes)?;

        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();
            json.insert("signature_base64", base64_encode(&signature));
            json.insert("signature_hex", hex::encode(&signature));

            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            success!("Signature: {}", base64_encode(&signature));
        }

        Ok(None)
    }
}
