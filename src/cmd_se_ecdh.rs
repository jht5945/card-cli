use crate::keyutil::parse_key_uri;
use crate::{cmd_hmac_decrypt, cmdutil, seutil, util};
use clap::{App, ArgMatches, SubCommand};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey};
use rust_util::util_clap::{Command, CommandError};
use spki::EncodePublicKey;
use std::collections::BTreeMap;
use rust_util::XResult;
use crate::util::base64_decode;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "se-ecdh"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Secure Enclave ECDH subcommand")
            .arg(cmdutil::build_key_uri_arg())
            .arg(cmdutil::build_epk_arg())
            .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        seutil::check_se_supported()?;
        let key = sub_arg_matches.value_of("key").unwrap();
        let epk = sub_arg_matches.value_of("epk").unwrap();

        let key_uri = parse_key_uri(&key)?;
        let se_key_uri = key_uri.as_secure_enclave_key()?;
        debugging!("Secure enclave key URI: {:?}", se_key_uri);

        let ephemeral_public_key_der_bytes = parse_epk(epk)?;

        let private_key = cmd_hmac_decrypt::try_decrypt(&mut None, &se_key_uri.private_key)?;
        let dh = seutil::secure_enclave_p256_dh(
            &private_key,
            &ephemeral_public_key_der_bytes,
        )?;
        let dh_hex = hex::encode(&dh);

        if json_output {
            let mut json = BTreeMap::<&'_ str, String>::new();
            json.insert("shared_secret_hex", dh_hex);

            util::print_pretty_json(&json);
        } else {
            information!("Shared secret: {}", dh_hex);
        }

        Ok(None)
    }
}

pub fn parse_epk(epk: &str) -> XResult<Vec<u8>> {
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
        Ok(public_key.to_public_key_der()?.as_bytes().to_vec())
    } else {
        match hex::decode(epk) {
            Ok(epk_bytes) => Ok(epk_bytes),
            Err(e) => match base64_decode(&epk) {
                Ok(epk_bytes) => Ok(epk_bytes),
                Err(_) => simple_error!("Decode public key from hex failed: {}", e)
            }
        }
    }
}
