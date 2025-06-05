use std::time::Duration;

use chrono::Local;
use clap::{App, Arg, ArgMatches, SubCommand};
use digest::Digest;
use rust_util::util_clap::{Command, CommandError};
use rust_util::XResult;
use sha2::Sha256;
use spki::der::Encode;
use x509_parser::parse_x509_certificate;
use yubikey::{Certificate, YubiKey};
use yubikey::piv::SlotId;
use crate::{cmdutil, yubikeyutil};
use crate::pivutil::get_algorithm_id;
use crate::pkiutil::{bytes_to_pem, get_pki_algorithm};

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV subcommand")
            .arg(Arg::with_name("detail").long("detail").help("Detail output"))
            .arg(Arg::with_name("show-config").long("show-config").help("Show config output"))
            .arg(cmdutil::build_serial_arg())
        // .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let detail_output = sub_arg_matches.is_present("detail");
        let show_config = sub_arg_matches.is_present("show-config");

        let mut yk = yubikeyutil::open_yubikey_with_args(sub_arg_matches)?;
        success!("Name: {}", yk.name());
        information!("Version: {}", yk.version());
        information!("Serial: {}", yk.serial());
        match yk.chuid() {
            Ok(chuid) => information!("CHUID: {}",chuid.to_string()),
            Err(e) => warning!("CHUID: <none> {}", e),
        }
        match yk.cccid() {
            Ok(cccid) => information!("CCCID: {}",cccid.to_string()),
            Err(e) => warning!("CCCID: <none> {}", e),
        }
        match yk.get_pin_retries() {
            Ok(pin_retries) => information!("PIN retries: {}",pin_retries),
            Err(e) => warning!("PIN retries: <none> {}", e),
        }
        if show_config {
            let config = yk.config();
            information!("Config: {:#?}", config);
        }

        match yk.piv_keys() {
            Ok(mut keys) => {
                information!("Found {} PIV keys", keys.len());
                keys.sort_by_key(|a| u8::from(a.slot()));
                for k in keys {
                    information!(
                        "Found PIV #{:x} @{}, subject: {}, signature: {}",
                        u8::from(k.slot()),
                        k.slot(),
                        k.certificate().subject(),
                        k.certificate().cert.signature_algorithm.oid
                    );
                    if detail_output {
                        debugging!("Found key: {:?}", k);
                    }
                }
            }
            Err(e) => failure!("Get PIV keys failed: {}", e)
        }

        // replace of yubikey::piv::SLOTS
        let slots = vec![SlotId::Authentication, SlotId::Signature,
                         SlotId::KeyManagement, SlotId::CardAuthentication];
        for slot in slots {
            print_cert_info(&mut yk, slot, detail_output).ok();
        }
        Ok(None)
    }
}

fn print_cert_info(yubikey: &mut YubiKey, slot: SlotId, detail_output: bool) -> XResult<()> {
    let cert = match Certificate::read(yubikey, slot) {
        Ok(c) => c,
        Err(e) => {
            let slot_id: u8 = slot.into();
            debugging!("error reading certificate in slot {:?}, id: {:x}: {}", slot, slot_id, e);
            return simple_error!("error reading certificate in slot {:?}: {}", slot, e);
        }
    };
    let buf_vec = cert.cert.to_der()?;
    let buf: &[u8] = buf_vec.as_ref();
    if !buf.is_empty() {
        information!("{}", "-".repeat(88));
        let certificate_fingerprint_sha256 = Sha256::digest(buf);

        let slot_id: u8 = slot.into();
        let algorithm_id = get_algorithm_id(&cert.cert.tbs_certificate.subject_public_key_info)
            .map(|aid| format!("{:?}", aid))
            .unwrap_or_else(|e| format!("Error: {}", e));
        success!("Slot: {:?}, id: {:x}, algorithm: {}",  slot, slot_id, algorithm_id);

        if detail_output {
            information!("{}", bytes_to_pem("CERTIFICATE", buf));
        }

        match parse_x509_certificate(buf) {
            Ok((_rem, cert)) => {
                debugging!("Algorithm: {:?}", &cert.tbs_certificate.subject_pki.algorithm);
                information!("Algorithm: {:?}", get_pki_algorithm(&cert.tbs_certificate.subject_pki.algorithm));

                debugging!("Public key: {}", hex::encode(&cert.tbs_certificate.subject_pki.subject_public_key));

                let public_key_fingerprint_sha256 = Sha256::digest(cert.tbs_certificate.subject_pki.raw);

                if detail_output {
                    information!("{}", bytes_to_pem("PUBLIC KEY", cert.tbs_certificate.subject_pki.raw));
                }

                information!("Subject: {}", cert.tbs_certificate.subject);
                information!("Issuer: {}", cert.tbs_certificate.issuer);
                information!("Certificate fingerprint(SHA256): {}", hex::encode(certificate_fingerprint_sha256));
                information!("Public key fingerprint(SHA256): {}", hex::encode(public_key_fingerprint_sha256));
                information!("Not Before: {}", cert.tbs_certificate.validity.not_before.to_rfc2822().unwrap_or_else(|e| format!("Err: {}", e)));

                let mut not_after_desc = String::new();
                let not_after_timestamp = cert.tbs_certificate.validity.not_after.timestamp();
                let now_timestamp = Local::now().timestamp();
                if not_after_timestamp < now_timestamp {
                    let expired_time = simpledateformat::format_human(Duration::from_secs((now_timestamp - not_after_timestamp) as u64));
                    not_after_desc.push_str(&format!("(EXPIRED {})", expired_time));
                } else {
                    let valid_time = simpledateformat::format_human(Duration::from_secs((not_after_timestamp - now_timestamp) as u64));
                    not_after_desc.push_str(&format!("(left {})", valid_time));
                }
                information!("Not After: {}  {}",
                    cert.tbs_certificate.validity.not_after.to_rfc2822().unwrap_or_else(|e| format!("Err: {}", e)),
                    not_after_desc
                );
            }
            _ => {
                warning!("Failed to parse certificate");
                return Ok(());
            }
        };
    }

    Ok(())
}
