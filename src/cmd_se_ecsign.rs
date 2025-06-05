use crate::keyutil::parse_key_uri;
use crate::{cmd_hmac_decrypt, cmdutil, seutil, util};
use crate::util::{base64_decode, base64_encode};
use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use std::collections::BTreeMap;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "se-ecsign"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Secure Enclave EC sign subcommand")
            .arg(cmdutil::build_key_uri_arg())
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
            .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        seutil::check_se_supported()?;
        let key = sub_arg_matches.value_of("key").unwrap();
        let input_bytes = match sub_arg_matches.value_of("input") {
            None => match sub_arg_matches.value_of("input-base64") {
                None => return simple_error!("Argument --input or --input-base64 is required"),
                Some(input_base64) => base64_decode(input_base64)?,
            },
            Some(input) => input.as_bytes().to_vec(),
        };

        let key_uri = parse_key_uri(&key)?;
        let se_key_uri = key_uri.as_secure_enclave_key()?;
        debugging!("Secure enclave key URI: {:?}", se_key_uri);

        let private_key = cmd_hmac_decrypt::try_decrypt(&mut None, &se_key_uri.private_key)?;
        let signature = seutil::secure_enclave_p256_sign(&private_key, &input_bytes)?;

        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();
            json.insert("signature_base64", base64_encode(&signature));
            json.insert("signature_hex", hex::encode(&signature));

            util::print_pretty_json(&json);
        } else {
            success!("Signature: {}", base64_encode(&signature));
        }

        Ok(None)
    }
}
