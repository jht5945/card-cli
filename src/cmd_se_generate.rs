use crate::cmd_hmac_encrypt;
use crate::pkiutil::bytes_to_pem;
use crate::util::base64_encode;
use crate::{cmdutil, seutil, util};
use clap::{App, Arg, ArgMatches, SubCommand};
use p256::PublicKey;
use rust_util::util_clap::{Command, CommandError};
use spki::DecodePublicKey;
use std::collections::BTreeMap;
use swift_secure_enclave_tool_rs::ControlFlag;

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
            .arg(
                Arg::with_name("control-flag")
                    .long("control-flag")
                    .required(true)
                    .takes_value(true)
                    .help("Control flag, e.g. none, user-presence, device-passcode, biometry-any, biometry-current-set"),
            )
            .arg(cmdutil::build_with_hmac_encrypt_arg())
            .arg(cmdutil::build_with_pbe_encrypt_arg())
            .arg(cmdutil::build_double_pin_check_arg())
            .arg(cmdutil::build_pbe_iteration_arg())
            .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        seutil::check_se_supported()?;
        let ty = sub_arg_matches.value_of("type").unwrap();
        let host = sub_arg_matches.value_of("host").unwrap_or("macbook");

        let sign = match ty {
            "signing" | "ecsign" | "sign" => true,
            "key_agreement" | "ecdh" | "dh" => false,
            _ => return simple_error!("Invalid type: {}", ty),
        };
        let control_flag = sub_arg_matches.value_of("control-flag").unwrap();
        let control_flag = match control_flag {
            "none" => ControlFlag::None,
            "user-presence" | "up" => ControlFlag::UserPresence,
            "device-passcode" | "passcode" | "pass" => ControlFlag::DevicePasscode,
            "biometry-any" | "bio-any" => ControlFlag::BiometryAny,
            "biometry-current-set" | "bio-current" => ControlFlag::BiometryCurrentSet,
            _ => return simple_error!("Invalid control flag: {}", control_flag),
        };

        let (public_key_point, public_key_der, private_key) =
            seutil::generate_secure_enclave_p256_keypair(sign, control_flag)?;

        let private_key = cmd_hmac_encrypt::do_encrypt(&private_key, &mut None, sub_arg_matches)?;
        let key_uri = format!(
            "key://{}:se/p256:{}:{}",
            host,
            iff!(sign, "signing", "key_agreement"),
            private_key,
        );

        print_se_key(json_output, &public_key_point, &public_key_der, &key_uri);
        Ok(None)
    }
}

pub fn print_se_key(
    json_output: bool,
    public_key_point: &[u8],
    public_key_der: &[u8],
    key_uri: &str,
) {
    let public_key_point_hex = hex::encode(public_key_point);
    let public_key_pem = bytes_to_pem("PUBLIC KEY", public_key_der);
    let public_key = PublicKey::from_public_key_pem(&public_key_pem).ok();
    let public_key_jwk = public_key.map(|key| key.to_jwk_string());

    if json_output {
        let mut json = BTreeMap::<&'_ str, String>::new();
        json.insert("public_key_point", public_key_point_hex);
        json.insert("public_key_pem", base64_encode(public_key_der));
        if let Some(public_key_jwk) = public_key_jwk {
            json.insert("public_key_jwk", base64_encode(public_key_jwk));
        }
        json.insert("key_uri", key_uri.to_string());

        util::print_pretty_json(&json);
    } else {
        success!("Public key(point): {}", public_key_point_hex);
        success!("Public key PEM: \n{}", public_key_pem);
        if let Some(public_key_jwk) = public_key_jwk {
            success!("Public key JWK: \n{}", &public_key_jwk);
        }
        success!("Key: {}", key_uri);
    }
}
