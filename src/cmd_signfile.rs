use std::fs;
use std::time::SystemTime;

use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::{util_msg, XResult};
use rust_util::util_clap::{Command, CommandError};
use serde::Deserialize;
use spki::der::Encode;
use x509_parser::nom::AsBytes;
use yubikey::{Key, YubiKey};
use yubikey::piv::{sign_data, SlotId};

use crate::{argsutil, pinutil, pivutil};
use crate::digest::sha256_bytes;
use crate::signfile::{CERTIFICATES_SEARCH_URL, HASH_ALGORITHM_SHA256, SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA, SignFileRequest, SIMPLE_SIG_SCHEMA, SimpleSignFile, SimpleSignFileSignature};
use crate::util::base64_encode;

pub struct CommandImpl;

// Format:
// {
//   "schema": "https://openwebstandard.org/simple-sign-file/v1",
//   "version": "v1",
//   "filename": "example.zip",
//   "digest": "sha256-HEX(SHA256(filename-content))",
//   "timestamp": 1700964163340,
//   "attributes": "****",
//   "comment": "***",
//   "signatures": [{
//     "algorithm": "SHA256withECDSA",
//     "signature": "Base64(Sign(SHA256("v1"||TLV(filename)||TLV(timestamp)||TLV(attributes)||TLV(comment)||TLV(digest))))",
//     "certificates": ["-----BEGIN CERTIFICATE-----\n*****\n-----END CERTIFICATE-----", ...]
//   }]
// }
// v1 only support SHA256
// all hex is in lower case default
// file ext: *.simple-sig
impl Command for CommandImpl {
    fn name(&self) -> &str { "sign-file" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV sign(with SHA256) subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).help("PIV card user PIN"))
            .arg(Arg::with_name("slot").short("s").long("slot")
                .takes_value(true).required(true).help("PIV slot, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e"))
            .arg(Arg::with_name("file").short("f").long("file").takes_value(true).required(true).help("Input file"))
            .arg(Arg::with_name("filename").short("n").long("filename").takes_value(true).help("Filename"))
            .arg(Arg::with_name("sign-file").short("S").long("sign-file").takes_value(false).help("Sign file"))
            .arg(Arg::with_name("comment").short("c").long("comment").takes_value(true).help("Comment"))
            .arg(Arg::with_name("attributes").short("a").long("attributes").takes_value(true).help("Attributes"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        util_msg::set_logger_std_out(false);

        let filename_opt = sub_arg_matches.value_of("filename").map(ToString::to_string);
        let comment_opt = sub_arg_matches.value_of("comment").map(ToString::to_string);
        let attributes_opt = sub_arg_matches.value_of("attributes").map(ToString::to_string);

        let pin_opt = sub_arg_matches.value_of("pin");
        let pin_opt = pinutil::get_pin(pin_opt);
        let pin_opt = pin_opt.as_deref();

        let slot = opt_value_result!(sub_arg_matches.value_of("slot"), "--slot must assigned, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e");
        // TODO read from stream not in memory
        let file_digest = argsutil::get_sha256_digest_or_hash(sub_arg_matches)?;
        debugging!("File digest: {}", hex::encode(&file_digest));

        let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");

        let slot_id = pivutil::get_slot_id(slot)?;
        let key = find_key(&mut yk, &slot_id)?;
        let key = opt_value_result!(key, "Cannot find key in slot: {}", slot_id);

        let certificate = key.certificate();
        let tbs_certificate = &certificate.cert.tbs_certificate;
        let spki_der = opt_result!(tbs_certificate.subject_public_key_info.to_der(), "SPKI to DER failed: {}");
        debugging!("Slot public DER: {}", hex::encode(&spki_der));
        let spki_der_fingerprint = hex::encode(sha256_bytes(&spki_der));
        debugging!("Slot public fingerprint: {}", &spki_der_fingerprint);
        let certificates = fetch_certificates(&spki_der_fingerprint)?;

        let algorithm_id = opt_result!(
            pivutil::get_algorithm_id_by_certificate(certificate), "Get slot key algorithm failed: {}");
        debugging!("PIV algorithm: {:?}", algorithm_id);
        if let Some(pin) = pin_opt {
            debugging!("PIN is assigned.");
            opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");
        }

        let filename_opt = match filename_opt {
            Some(filename) => Some(filename),
            None => sub_arg_matches.value_of("file").map(|f| {
                if f.contains('/') {
                    f.split('/').last().unwrap().to_string()
                } else {
                    f.to_string()
                }
            }),
        };
        let sign_file = sub_arg_matches.value_of("sign-file").map(ToString::to_string).or_else(|| {
            filename_opt.clone().map(|f| format!("{}.simple-sig", f))
        });

        let sign_file_request = SignFileRequest {
            filename: match filename_opt {
                None => None,
                Some(filename) => iff!(filename.is_empty(), None, Some(filename)),
            },
            digest: file_digest.clone(),
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as i64,
            attributes: attributes_opt,
            comment: comment_opt,
        };
        let tobe_signed = sign_file_request.get_tobe_signed();
        debugging!("Tobe signed: {}", hex::encode(&tobe_signed));
        let tobe_signed_digest = sha256_bytes(&tobe_signed);
        debugging!("Tobe signed digest: {}", hex::encode(&tobe_signed_digest));

        let signed_data = opt_result!(sign_data(&mut yk, &tobe_signed_digest, algorithm_id, slot_id), "Sign PIV failed: {}");
        let signature_bytes = signed_data.as_slice();
        debugging!("Tobe signed signature: {}", hex::encode(signature_bytes));

        let signature = SimpleSignFileSignature {
            algorithm: SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA.to_string(),
            signature: base64_encode(signature_bytes),
            certificates,
        };
        let simple_sig = SimpleSignFile {
            schema: SIMPLE_SIG_SCHEMA.to_string(),
            filename: sign_file_request.filename.clone(),
            digest: format!("{}-{}", HASH_ALGORITHM_SHA256, hex::encode(&sign_file_request.digest)),
            timestamp: sign_file_request.timestamp,
            attributes: sign_file_request.attributes.clone(),
            comment: sign_file_request.comment.clone(),
            signatures: vec![signature],
        };

        let sign_file_content = serde_json::to_string_pretty(&simple_sig).unwrap();
        if let Some(sign_file) = sign_file {
            if fs::read(&sign_file).is_ok() {
                warning!("Simple sign file: {} exists", sign_file);
            } else {
                match fs::write(&sign_file, &sign_file_content) {
                    Ok(_) => success!("Write simple sign file: {} succeed", sign_file),
                    Err(e) => failure!("Write simple sign file: {} failed: {}", sign_file, e),
                }
            }
        }

        println!("{}", sign_file_content);
        Ok(None)
    }
}

#[derive(Deserialize)]
struct FetchCertificateResponseData {
    pub certificates: Vec<String>,
}

#[derive(Deserialize)]
struct FetchCertificateResponse {
    pub status: i32,
    pub message: String,
    pub data: Option<FetchCertificateResponseData>,
}

fn fetch_certificates(fingerprint: &str) -> XResult<Vec<String>> {
    let url = format!("{}{}", CERTIFICATES_SEARCH_URL, fingerprint);
    let certificates_response = opt_result!( reqwest::blocking::get(url), "Fetch certificates failed: {}");
    let certificates_response_bytes = opt_result!(certificates_response.bytes(), "Fetch certificates failed: {}");
    let response = opt_result!(
        serde_json::from_slice::<FetchCertificateResponse>(certificates_response_bytes.as_bytes()),
        "Parse fetch certificates response failed: {}");
    if response.status != 200 {
        return simple_error!("Fetch certificates failed, status: {}, message: {}", response.status, response.message);
    }
    match response.data {
        None => simple_error!("Fetch certificates failed, empty."),
        Some(data) => Ok(data.certificates),
    }
}

fn find_key(yk: &mut YubiKey, slot_id: &SlotId) -> XResult<Option<Key>> {
    match Key::list(yk) {
        Err(e) => warning!("List keys failed: {}", e),
        Ok(keys) => for k in keys {
            let slot_str = format!("{:x}", Into::<u8>::into(k.slot()));
            if pivutil::slot_equals(slot_id, &slot_str) {
                return Ok(Some(k));
            }
        }
    }
    Ok(None)
}
