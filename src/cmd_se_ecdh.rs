use crate::keyutil::{parse_key_uri, KeyUri};
use crate::seutil;
use clap::{App, Arg, ArgMatches, SubCommand};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey};
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use spki::EncodePublicKey;
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

        let ephemeral_public_key_der_bytes;
        if epk.starts_with("04") {
            let ephemeral_public_key_point_bytes = opt_result!(
                hex::decode(epk),
                "Decode public key point from hex failed: {}"
            );
            let encoded_point = opt_result!(
                EncodedPoint::from_bytes(ephemeral_public_key_point_bytes),
                "Parse public key point failed: {}"
            );
            let public_key_opt = PublicKey::from_encoded_point(&encoded_point);
            if public_key_opt.is_none().into() {
                return simple_error!("Parse public key failed.");
            }
            let public_key = public_key_opt.unwrap();
            ephemeral_public_key_der_bytes = public_key.to_public_key_der()?.as_bytes().to_vec();
        } else {
            ephemeral_public_key_der_bytes =
                opt_result!(hex::decode(epk), "Decode public key from hex failed: {}");
        }

        let dh = seutil::secure_enclave_p256_dh(
            &se_key_uri.private_key,
            &ephemeral_public_key_der_bytes,
        )?;
        let dh_hex = hex::encode(&dh);

        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();
            json.insert("shared_secret_hex", dh_hex);

            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            information!("Shared secret: {}", dh_hex);
        }

        Ok(None)
    }
}
