use std::collections::BTreeMap;
use std::sync::mpsc::channel;

use authenticator::authenticatorservice::AuthenticatorService;
use authenticator::RegisterFlags;
use authenticator::statecallback::StateCallback;
use clap::{App, Arg, ArgMatches, SubCommand};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use rust_util::util_clap::{Command, CommandError};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::{cmdutil, digestutil, util};
use crate::fidoutil;
use crate::fidoutil::{U2fRegistrationData, U2fV2Challenge};
use crate::util::base64_encode;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "u2f-register" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("FIDO U2F register subcommand")
            .arg(Arg::with_name("app-id").short("a").long("app-id").default_value("https://example.com").help("App id"))
            .arg(Arg::with_name("timeout").short("t").long("timeout").default_value("30").help("Timeout in seconds"))
            .arg(Arg::with_name("challenge").long("challenge").takes_value(true).help("Challenge HEX"))
            .arg(Arg::with_name("challenge-with-timestamp-prefix").long("challenge-with-timestamp-prefix").help("Challenge with timestamp prefix"))
            .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let timeout_ms = match sub_arg_matches.value_of("timeout").unwrap().parse::<u32>() {
            Ok(t) => (t * 1000) as u64,
            Err(e) => return simple_error!("Timeout should be a number: {}", e),
        };

        let app_id = sub_arg_matches.value_of("app-id").unwrap();

        let challenge_hex = sub_arg_matches.value_of("challenge");
        let challenge_with_timestamp_prefix = sub_arg_matches.is_present("challenge-with-timestamp-prefix");
        let u2fv2_challenge = U2fV2Challenge::new_challenge(challenge_hex, app_id, challenge_with_timestamp_prefix)?;
        let u2fv2_challenge_str = u2fv2_challenge.to_json();

        let app_id_hash = digestutil::sha256(app_id);
        let challenge_hash = digestutil::sha256(&u2fv2_challenge_str);

        let flags = RegisterFlags::empty();

        let status_tx = fidoutil::start_status_updater();

        let (register_tx, register_rx) = channel();
        let callback = StateCallback::new(Box::new(move |rv| {
            register_tx.send(rv).unwrap();
        }));

        information!("App id: {}, Start U2F register...", app_id);
        debugging!("Wait timeout: {} ms", timeout_ms);
        let mut manager = opt_result!(AuthenticatorService::new(), "Create authenticator service failed: {}");
        manager.add_u2f_usb_hid_platform_transports();
        if let Err(e) = manager.register(
            flags,
            timeout_ms,
            challenge_hash.clone(),
            app_id_hash.clone(),
            vec![],
            status_tx,
            callback,
        ) {
            return simple_error!("Couldn't register: {:?}", e);
        };

        let register_result = opt_result!(register_rx.recv()?, "Register U2F failed: {}");

        let u2f_registration_data = opt_result!(
            U2fRegistrationData::from(app_id, &u2fv2_challenge_str, &register_result), "Parse registration data failed: {}");

        // +------+-------------------+-----------------+------------+--------------------+
        // + 0x00 | application (32B) | challenge (32B) | key handle | User pub key (65B) |
        // +------+-------------------+-----------------+------------+--------------------+
        let mut signed_message = Vec::with_capacity(200);
        signed_message.push(0x00);
        signed_message.extend_from_slice(&app_id_hash);
        signed_message.extend_from_slice(&challenge_hash);
        signed_message.extend_from_slice(&u2f_registration_data.key_handle);
        signed_message.extend_from_slice(&u2f_registration_data.pub_key);
        // +------+--------------------+---------------------+------------+------------+------+
        // + 0x05 | User pub key (65B) | key handle len (1B) | key handle | X.509 Cert | Sign |
        // +------+--------------------+---------------------+------------+------------+------+
        let sign_prefix_len = 1 + 65 + 1
            + u2f_registration_data.key_handle.len()
            + u2f_registration_data.attestation_cert.as_ref().map(|c| c.len()).unwrap_or(0);
        let sign = &register_result.0[sign_prefix_len..];

        if json_output {
            let mut json = BTreeMap::new();
            // println!("{}", serde_json::to_string_pretty(&u2f_registration_data).unwrap());
            if let Some(device_name) = u2f_registration_data.device_name {
                json.insert("device_name", device_name);
            }
            if let Some(attestation_cert_pem) = u2f_registration_data.attestation_cert_pem {
                json.insert("attestation_cert_pem", attestation_cert_pem);
            }
            json.insert("device_info", format!("{}", u2f_registration_data.device_info));
            json.insert("pub_key", hex::encode(&u2f_registration_data.pub_key));
            json.insert("key_handle", hex::encode(&u2f_registration_data.key_handle));
            json.insert("signature", hex::encode(sign));
            json.insert("signed_message", hex::encode(&signed_message));
            json.insert("registration_data", hex::encode(&register_result.0));
            json.insert("app_id", app_id.to_string());
            json.insert("app_id_hash", hex::encode(&app_id_hash));
            json.insert("challenge", u2fv2_challenge_str);
            json.insert("challenge_hash", hex::encode(&challenge_hash));

            util::print_pretty_json(&json);
        } else {
            success!("Device info: {}", u2f_registration_data.device_info);
            information!("Register challenge: {}", u2fv2_challenge_str);
            information!("Register challenge base64: {}", base64_encode(&u2fv2_challenge_str));
            if let Some(cert) = u2f_registration_data.attestation_cert_pem {
                information!("Attestation certificate: {}", cert);
            }
            if let Some(device_name) = u2f_registration_data.device_name {
                information!("Device name: {}", device_name);
            }
            success!("Public key: {}", hex::encode(&u2f_registration_data.pub_key));
            success!("Key handle: {}", hex::encode(&u2f_registration_data.key_handle));
            debugging!("Registration data: {}", hex::encode(&register_result.0));
            information!("Signed message: {}", hex::encode(&signed_message));
            information!("Signature: {}", hex::encode(sign));

            if let Some(attestation_cert) = &u2f_registration_data.attestation_cert {
                let cert = opt_result!(X509Certificate::from_der(attestation_cert), "Parse attestation cert failed: {}");
                debugging!("Attestation public key: {:?}", cert.1.public_key().subject_public_key);
                let pkey = opt_result!(PKey::public_key_from_der(cert.1.public_key().raw), "Parse public key failed: {}");
                let mut verifier = opt_result!(Verifier::new(MessageDigest::sha256(), &pkey), "Verifier new failed: {}");
                verifier.update(&signed_message)?;
                let verify_result = opt_result!(verifier.verify(sign), "Verifier verify failed: {}");
                if verify_result {
                    success!("Verify success");
                } else {
                    failure!("Verify failed");
                }
            } else {
                warning!("Cannot find attestation cert!");
            }
        }
        Ok(None)
    }
}
