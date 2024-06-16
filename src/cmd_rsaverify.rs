use std::fs;
use std::io;
use std::fs::File;

use clap::{App, Arg, ArgMatches, SubCommand};
use openssl::bn::{BigNum, BigNumContext};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Verifier;
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg::MessageType;
use rust_util::{util_msg, XResult};

use crate::digest::sha256_bytes;

pub struct CommandImpl;

// https://docs.rs/openssl/0.10.36/openssl/encrypt/index.html
impl Command for CommandImpl {
    fn name(&self) -> &str { "rsa-verify" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("RSA verify subcommand")
            .arg(Arg::with_name("pub-key-in").long("pub-key-in").takes_value(true).help("Public key in"))
            .arg(Arg::with_name("signature").long("signature").takes_value(true).help("Signature HEX"))
            .arg(Arg::with_name("in").short("i").long("in").takes_value(true).help("File in"))
            .arg(Arg::with_name("hash").long("hash").takes_value(true).possible_values(&[
                "sha256", "sha384", "sha512"
            ]).default_value("sha256").help("Hash"))
        // .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        // let json_output = sub_arg_matches.is_present("json");
        // if json_output { rust_util::util_msg::set_logger_std_out(false); }

        let pub_key_in = opt_value_result!(sub_arg_matches.value_of("pub-key-in"), "Require public key in");
        let pub_key_bytes = opt_result!(fs::read(pub_key_in), "Read file: {}, failed: {}", pub_key_in);

        // let mut json = BTreeMap::new();

        let keypair = opt_result!(Rsa::public_key_from_pem(&pub_key_bytes), "Parse RSA failed: {}");
        let pub_key_der = opt_result!(keypair.public_key_to_der(), "RSA public key to der failed: {}");
        let pub_key_fingerprint = hex::encode(sha256_bytes(&pub_key_der));
        let keypair = opt_result!(PKey::from_rsa(keypair), "RSA to PKey failed: {}");

        let signature = if let Some(signature) = sub_arg_matches.value_of("signature") {
            opt_result!(hex::decode(signature), "Decode signature HEX failed: {}")
        } else {
            return simple_error!("Signature is required, --signature argument!");
        };

        util_msg::when(MessageType::DEBUG, || {
            let rsa = keypair.rsa().unwrap();
            let n = rsa.n();
            let e = rsa.e();
            let m = BigNum::from_slice(&signature).unwrap();
            let mut r = BigNum::new().unwrap();
            r.mod_exp(&m, e, n, &mut BigNumContext::new().unwrap()).unwrap();
            debugging!("Signature raw HEX: 00{}", hex::encode(r.to_vec()));
        });

        let file_in = opt_value_result!(sub_arg_matches.value_of("in"), "File in --in required");
        information!("File in: {}", file_in);
        information!("Public key fingerprint: {}", pub_key_fingerprint);
        let hashes = sub_arg_matches.values_of("hash").expect("Cannot get hashes");
        for hash in hashes {
            information!("Hash: {}", hash);
            let digest = get_digest(hash)?;
            let mut verifier = opt_result!(Verifier::new(digest, &keypair), "Verifier new failed: {}");
            let mut f = opt_result!(File::open(file_in), "Open file: {}, failed: {}", file_in);
            opt_result!(io::copy(&mut f, &mut verifier), "Verifier failed: {}");
            let result = opt_result!(verifier.verify(&signature), "Verifier verify failed: {}");
            if result {
                success!("Verify success");
            } else {
                failure!("Verify failed")
            }
        }

        // if json_output {
        //     println!("{}", serde_json::to_string_pretty(&json).unwrap());
        // }

        Ok(None)
    }
}

fn get_digest(hash: &str) -> XResult<MessageDigest> {
    Ok(match hash {
        "sha256" => MessageDigest::sha256(),
        "sha384" => MessageDigest::sha384(),
        "sha512" => MessageDigest::sha512(),
        _ => return simple_error!("Unknown hash: {}", hash),
    })
}
