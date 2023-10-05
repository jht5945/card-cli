use std::collections::BTreeMap;
use std::sync::mpsc::channel;

use authenticator::{AuthenticatorTransports, KeyHandle, SignFlags};
use authenticator::authenticatorservice::AuthenticatorService;
use authenticator::statecallback::StateCallback;
use clap::{App, Arg, ArgMatches, SubCommand};
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use rust_util::util_clap::{Command, CommandError};

use crate::digest;
use crate::fido;
use crate::fido::U2fV2Challenge;
use crate::util::base64_encode;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "u2f-sign" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("FIDO U2F Sign subcommand")
            .arg(Arg::with_name("app-id").short("a").long("app-id").default_value("https://example.com").help("App id"))
            .arg(Arg::with_name("timeout").short("t").long("timeout").default_value("30").help("Timeout in seconds"))
            .arg(Arg::with_name("public-key-hex").long("public-key-hex").takes_value(true).help("Public key hex"))
            .arg(Arg::with_name("challenge").long("challenge").takes_value(true).help("Challenge HEX"))
            .arg(Arg::with_name("challenge-with-timestamp-prefix").long("challenge-with-timestamp-prefix").help("Challenge with timestamp prefix"))
            .arg(Arg::with_name("key-handle").short("k").long("key-handle").takes_value(true).multiple(true).help("Key handle"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { rust_util::util_msg::set_logger_std_out(false); }

        let timeout_ms = match sub_arg_matches.value_of("timeout").unwrap().parse::<u32>() {
            Ok(t) => (t * 1000) as u64,
            Err(e) => return simple_error!("Timeout should be a number: {}", e),
        };

        let app_id = sub_arg_matches.value_of("app-id").unwrap();

        let key_handles = opt_value_result!( sub_arg_matches.values_of("key-handle"), "Key handle is required");
        let mut request_key_handles = vec![];
        for kh in key_handles {
            match hex::decode(kh) {
                Ok(k) => request_key_handles.push(KeyHandle {
                    credential: k,
                    transports: AuthenticatorTransports::empty(),
                }),
                Err(e) => warning!("Parse key handle: {}, failed: {}", kh, e),
            }
        }
        if request_key_handles.is_empty() {
            return simple_error!("No valid key handle provided");
        }

        let flags = SignFlags::empty();
        let (sign_tx, sign_rx) = channel();

        let callback = StateCallback::new(Box::new(move |rv| {
            sign_tx.send(rv).unwrap();
        }));

        let challenge_hex = sub_arg_matches.value_of("challenge");
        let challenge_with_timestamp_prefix = sub_arg_matches.is_present("challenge-with-timestamp-prefix");
        let u2fv2_challenge = U2fV2Challenge::new_challenge(challenge_hex, app_id, challenge_with_timestamp_prefix)?;
        let u2fv2_challenge_str = u2fv2_challenge.to_json();

        let app_id_hash = digest::sha256(app_id);
        let challenge_hash = digest::sha256(&u2fv2_challenge_str);

        let status_tx = fido::start_status_updater();

        information!("App id: {}, Start sign...", app_id);
        debugging!("Wait timeout: {} ms", timeout_ms);
        let mut manager = opt_result!(AuthenticatorService::new(), "Create authenticator service failed: {}");
        manager.add_u2f_usb_hid_platform_transports();
        if let Err(e) = manager.sign(
            flags,
            timeout_ms,
            challenge_hash.clone(),
            vec![app_id_hash.clone()],
            request_key_handles,
            status_tx,
            callback,
        ) {
            return simple_error!("Couldn't sign: {:?}", e);
        }

        let sign_result = opt_result!(sign_rx.recv(), "Problem receiving, unable to continue: {}");
        let (_, handle_used, sign_data, device_info) = opt_result!(sign_result, "Sign failed: {}");

        let user_presence_flag = &sign_data[0];
        let counter = &sign_data[1..=4];
        let signature = &sign_data[5..];

        let counter_u32 = u32::from_be_bytes([counter[0], counter[1], counter[2], counter[3]]);
        // application (32B) + user presence (1B) + counter (4B) + client data hash (32B)
        let mut signed_message = Vec::with_capacity(128);
        signed_message.extend_from_slice(&app_id_hash);
        signed_message.push(*user_presence_flag);
        signed_message.extend_from_slice(counter);
        signed_message.extend_from_slice(&challenge_hash);

        success!("Device info: {}", &device_info);
        let mut json = BTreeMap::new();
        if json_output {
            json.insert("app_id", app_id.to_string());
            json.insert("app_id_hash", hex::encode(&app_id_hash));
            json.insert("challenge", u2fv2_challenge_str.to_string());
            json.insert("challenge_hash", hex::encode(&challenge_hash));
            json.insert("device_info", format!("{}", &device_info));
            json.insert("signature", hex::encode(&signature));
            json.insert("signed_message", hex::encode(&signed_message));
            json.insert("key_handle", hex::encode(&handle_used));
            json.insert("sign_data", hex::encode(&sign_data));
            json.insert("user_presence_flag", format!("{}", *user_presence_flag));
            json.insert("counter", format!("{}", counter_u32));
        } else {
            information!("Sign challenge: {}", u2fv2_challenge_str);
            information!("Sign challenge base64: {}", base64_encode(&u2fv2_challenge_str));
            information!("Sign result : {}", base64_encode(&sign_data));
            information!("- presence : {}", user_presence_flag);
            information!("- counter  : {}", counter_u32);
            information!("- signature: {}", hex::encode(&signature));
            information!("Key handle: {}", hex::encode(&handle_used));
            information!("Signed message: {}", hex::encode(&signed_message));
        }

        if let Some(public_key_hex) = sub_arg_matches.value_of("public-key-hex") {
            let public_key = opt_result!(hex::decode(public_key_hex), "Parse public key hex failed: {}");
            if json_output {
                json.insert("pub_key", hex::encode(&public_key));
            } else {
                information!("Public key: {}", hex::encode(&public_key));
                let authorization_result = u2f::authorization::parse_sign_response(
                    app_id.to_string(),
                    u2fv2_challenge_str.as_bytes().to_vec(),
                    public_key.clone(),
                    sign_data.clone(),
                );
                let authorization = opt_result!(authorization_result, "Parse authorization failed: {}");
                success!("Parse authorization success, counter: {}", authorization.counter);

                let ec_group = opt_result!(EcGroup::from_curve_name(Nid::X9_62_PRIME256V1), "New secp256r1 EC group failed: {}");
                let ec_point = opt_result!(EcPoint::from_bytes(&ec_group, &public_key, &mut BigNumContext::new().unwrap()), "Parse from secp256r1 point failed: {}");
                let ec_key = opt_result!(EcKey::from_public_key(&ec_group, &ec_point), "Parse secp256r1 public key failed: {}");
                let ec_pkey = opt_result!(PKey::from_ec_key(ec_key), "EC secp256r1 key to PKey failed: {}");
                let mut verifier = opt_result!(Verifier::new(MessageDigest::sha256(), &ec_pkey), "Verifier new failed: {}");
                verifier.update(&signed_message)?;
                let verify_result = opt_result!(verifier.verify(signature), "Verifier verify failed: {}");
                if verify_result {
                    success!("Verify success");
                } else {
                    failure!("Verify failed");
                }
            }
        }
        if json_output {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        Ok(None)
    }
}