use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::{util_msg, XResult};
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg::MessageType;
use yubikey::{piv, YubiKey};
use yubikey::piv::{AlgorithmId, SlotId};

use crate::util::base64_encode;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-sign" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV RSA Sign(with SHA256) subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).default_value("123456").help("OpenPGP card user pin"))
            .arg(Arg::with_name("sha256").short("2").long("sha256").takes_value(true).help("Digest SHA256 HEX"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let pin_opt = sub_arg_matches.value_of("pin");
        let pin = opt_value_result!(pin_opt, "User pin must be assigned");

        let sha256_hex_opt = sub_arg_matches.value_of("sha256").map(|s| s.to_string());

        let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
        opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");

        // https://www.ibm.com/docs/en/zos/2.2.0?topic=cryptography-pkcs-1-formats
        // MD5  X’3020300C 06082A86 4886F70D 02050500 0410’ || 16-byte hash value
        // SHA-1  X'30213009 06052B0E 03021A05 000414’ || 20-byte hash value
        // SHA-224  X’302D300D 06096086 48016503 04020405 00041C’ || 28-byte hash value
        // SHA-256  X’3031300D 06096086 48016503 04020105 000420’ || 32-byte hash value
        // SHA-384  X’3041300D 06096086 48016503 04020205 000430’ || 48-byte hash value
        // SHA-512  X’3051300D 06096086 48016503 04020305 000440’ || 64-byte hash value
        let sha256_der_prefix = hex::decode("3031300d060960864801650304020105000420").unwrap();

        if let Some(sha256_hex) = sha256_hex_opt {
            let hash = opt_result!(hex::decode(sha256_hex), "Decode sha256 failed: {}");

            let mut hash_with_oid = Vec::with_capacity(128);
            hash_with_oid.extend_from_slice(&sha256_der_prefix);
            hash_with_oid.extend_from_slice(&hash);
            let hash_padding = pkcs1_padding_for_sign(&hash_with_oid, 2048).unwrap();
            util_msg::when(MessageType::DEBUG, || {
                debugging!("Hash: {}", hex::encode(&hash));
                debugging!("Hash with OID: {}", hex::encode(&hash_with_oid));
                debugging!("PKCS1 padding: {}", hex::encode(&hash_padding));
            });
            let raw_in = crate::digest::copy_rsa2048(&hash_padding).unwrap();
            let sign_result = piv::sign_data(&mut yk, &raw_in, AlgorithmId::Rsa2048, SlotId::Signature);
            let sign = opt_result!(sign_result, "Sign data failed: {}");
            let sign_bytes = sign.as_slice();

            if json_output {
                let mut json = BTreeMap::<&'_ str, String>::new();
                json.insert("hash_hex", hex::encode(&hash));
                json.insert("sign_hex", hex::encode(&sign_bytes));
                json.insert("sign_base64", base64_encode(&sign_bytes));
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            } else {
                success!("Signature HEX: {}", hex::encode(sign_bytes));
                success!("Signature base64: {}", base64_encode(sign_bytes));
            }
        }
        Ok(None)
    }
}

fn pkcs1_padding_for_sign(bs: &[u8], bit_len: usize) -> XResult<Vec<u8>> {
    let byte_len = bit_len / 8;
    let max_len = byte_len - (1 + 1 + 8 + 2);
    if bs.len() > max_len {
        return simple_error!("Length is too large: {} > {}", bs.len(), max_len);
    }
    let mut output = Vec::<u8>::with_capacity(byte_len);
    output.push(0x00);
    output.push(0x01);
    let ps_len = byte_len - bs.len() - (1 + 1 + 1);
    output.extend_from_slice(&vec![0xff_u8; ps_len]);
    output.push(0x00);
    output.extend_from_slice(bs);
    Ok(output)
}
