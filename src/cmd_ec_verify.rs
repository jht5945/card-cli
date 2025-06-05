use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
 use rust_util::util_clap::{Command, CommandError};

use crate::ecdsautil::EcdsaAlgorithm;
use crate::{argsutil, cmdutil, ecdsautil, util};

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "ec-verify" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("ECDSA verify subcommand")
            .arg(Arg::with_name("public-key-hex").short("k").long("public-key-hex").takes_value(true).help("Public key hex (starts with 04)"))
            .arg(Arg::with_name("signature-hex").short("t").long("signature-hex").takes_value(true).help("Signature"))
            .arg(Arg::with_name("file").short("f").long("file").takes_value(true).help("Input file"))
            .arg(Arg::with_name("input").short("i").long("input").takes_value(true).help("Input"))
            .arg(Arg::with_name("hash-hex").short("x").long("hash-hex").takes_value(true).help("Hash"))
            .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let hash_bytes = argsutil::get_sha256_digest_or_hash(sub_arg_matches)?;
        let public_key = if let Some(public_key_hex) = sub_arg_matches.value_of("public-key-hex") {
            opt_result!(hex::decode(public_key_hex), "Parse public-key-hex failed: {}")
        } else {
            return simple_error!("--public-hex required.");
        };
        let signature = if let Some(signature_hex) = sub_arg_matches.value_of("signature-hex") {
            opt_result!(hex::decode(signature_hex), "Parse signature-hex failed: {}")
        } else {
            return simple_error!("--signature-hex required.");
        };

        let ecdsa_algorithm = match public_key.len() {
            65 => EcdsaAlgorithm::P256,
            97 => EcdsaAlgorithm::P384,
            _ => return simple_error!("Invalid public key: {}", hex::encode(&public_key)),
        };

        let mut json = BTreeMap::<&'_ str, String>::new();

        debugging!("ECDSA public key point: {}", hex::encode(&public_key));
        information!("Pre hash: {}", hex::encode(&hash_bytes));
        debugging!("Signature: {}", hex::encode(&signature));
        if json_output {
            json.insert("public_key_hex", hex::encode(&public_key));
            json.insert("hash_hex", hex::encode(&hash_bytes));
            json.insert("signature_hex", hex::encode(&signature));
        }

        match ecdsautil::ecdsa_verify(ecdsa_algorithm, &public_key, &hash_bytes, &signature) {
            Ok(_) => {
                success!("Verify ECDSA succeed.");
                if json_output {
                    json.insert("success", "true".to_string());
                }
            }
            Err(e) => {
                failure!("Verify ECDSA failed: {}", &e);
                if json_output {
                    json.insert("success", "false".to_string());
                    json.insert("message", format!("{}", e));
                }
            }
        }

        if json_output {
            util::print_pretty_json(&json);
        }
        Ok(None)
    }
}
