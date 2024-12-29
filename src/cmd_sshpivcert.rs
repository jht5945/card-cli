use clap::{App, Arg, ArgMatches, SubCommand};
use ecdsa::elliptic_curve::pkcs8::der::Encode;
use rand::random;
use rust_util::util_clap::{Command, CommandError};
use rust_util::{util_time, XResult};
use sshcerts::ssh::{CurveKind, PublicKeyKind, SSHCertificateSigner};
use sshcerts::utils::format_signature_for_ssh;
use sshcerts::x509::extract_ssh_pubkey_from_x509_certificate;
use sshcerts::{CertType, Certificate, PublicKey};
use std::fs;
use std::sync::Mutex;
use std::time::SystemTime;
use yubikey::piv::{sign_data, AlgorithmId, SlotId};
use yubikey::{Key, YubiKey};

use crate::digest::{sha256_bytes, sha384_bytes};
use crate::pivutil::slot_equals;
use crate::{pinutil, pivutil, util};

pub struct CommandImpl;


// https://github.com/RustCrypto/SSH
// https://github.com/obelisk/sshcerts/
impl Command for CommandImpl {
    fn name(&self) -> &str { "ssh-piv-cert" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("SSH PIV sign cert subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).help("PIV card user PIN"))
            .arg(Arg::with_name("no-pin").long("no-pin").help("No PIN"))
            .arg(Arg::with_name("slot").short("s").long("slot").takes_value(true).help("PIV slot, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e"))
            .arg(Arg::with_name("key-id").short("k").long("key-id").takes_value(true).default_value("default_key_id").help("SSH user CA key id"))
            .arg(Arg::with_name("principal").short("P").long("principal").takes_value(true).default_value("root").multiple(true).help("SSH user CA principal"))
            .arg(Arg::with_name("pub").short("f").long("pub").alias("pub-file").required(true).takes_value(true).help("SSH public key file"))
            .arg(Arg::with_name("out").short("o").long("out").takes_value(true).help("CA out key file"))
            .arg(Arg::with_name("type").short("t").long("type").takes_value(true).default_value("user").help("CA type (user or host)"))
            .arg(Arg::with_name("validity").long("validity").takes_value(true).default_value("1h").help("CA validity period e.g. 10m means 10 minutes (s - second, m - minute, h - hour, d - day)"))
            .arg(Arg::with_name("force").long("force").help("Force write SSH CA file"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let ssh_pub_file = sub_arg_matches.value_of("pub").unwrap();
        let ssh_pub_bytes = util::read_file_or_stdin(ssh_pub_file)?;
        let ssh_pub_str = String::from_utf8(ssh_pub_bytes).expect("Read SSh pub file failed: {}");

        let slot = opt_value_result!(sub_arg_matches.value_of("slot"), "--slot must assigned, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e");
        let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
        let slot_id = pivutil::get_slot_id(slot)?;

        let serial: u64 = random();
        let key_id = sub_arg_matches.value_of("key-id").unwrap();
        let principals = sub_arg_matches.values_of("principal")
            .map(|ps| ps.map(|p| p.to_string()).collect::<Vec<_>>())
            .unwrap_or_else(|| vec!["root".to_string()]);

        let ca_type = sub_arg_matches.value_of("type").unwrap();
        let cert_type = match ca_type.to_lowercase().as_str() {
            "user" => CertType::User,
            "host" => CertType::Host,
            _ => return simple_error!("Invalid CA type: {}",ca_type),
        };

        let now_secs = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let validity = sub_arg_matches.value_of("validity").unwrap();
        let validity_u64 = util_time::parse_duration(validity).map(|t| t.as_secs()).unwrap();

        let output = sub_arg_matches.value_of("out");
        let ssh_cert_file = match output {
            None  if ssh_pub_file.ends_with(".pub") => {
                Some(format!("{}-cert.pub", String::from_utf8(ssh_pub_file.as_bytes()[0..ssh_pub_file.len() - 4].to_vec()).unwrap()))
            }
            None => None,
            Some("-") => None,
            Some(output) => Some(output.to_string()),
        };
        if let Some(ssh_cert_file) = &ssh_cert_file {
            let force_write = sub_arg_matches.is_present("force");
            if fs::metadata(ssh_cert_file).is_ok() && !force_write {
                return simple_error!("Target file: {} exists", & ssh_cert_file);
            }
        }

        information!("Serial: {}", serial);
        information!("Key ID: {}", key_id);
        information!("Principals: {:?}", principals);
        information!("Validity: {} seconds", validity_u64);

        let pin_opt = pinutil::read_pin(sub_arg_matches);

        let cert_der = find_cert(&mut yk, slot_id)?;
        let ca_ssh_pub_key = opt_result!(extract_ssh_pubkey_from_x509_certificate(&cert_der), "Extract SSH public key failed: {}");
        debugging!("SSH CA: {}", ca_ssh_pub_key);
        debugging!("SSH CA fingerprint: {}", ca_ssh_pub_key.fingerprint());

        let ca_ssh_pub_algorithm_id = get_ssh_key_type(&ca_ssh_pub_key)?;
        let ssh_yubikey_signer = SshYubikeySinger::new(
            yk,
            pin_opt,
            slot_id,
            ca_ssh_pub_key.clone(),
            ca_ssh_pub_algorithm_id,
        );

        let tobe_signed_ssh_pub_key = opt_result!(PublicKey::from_string(&ssh_pub_str), "Parse tobe signed SSH public key failed: {}");
        let user_cert_result = Certificate::builder(&tobe_signed_ssh_pub_key, cert_type, &ca_ssh_pub_key)
            .unwrap()
            .serial(serial)
            .key_id(key_id)
            .set_principals(&principals)
            .valid_after(now_secs - 1)
            .valid_before(now_secs + validity_u64)
            .set_extensions(Certificate::standard_extensions())
            .sign(&ssh_yubikey_signer);

        // View *-cert.pub:
        // ssh-keygen -L -f *-cert.pub
        let user_cert = opt_result!(user_cert_result, "Sign SSH user CA failed: {}");

        match ssh_cert_file {
            None => println!("{}", user_cert),
            Some(ssh_cert_file) => {
                opt_result!(fs::write( & ssh_cert_file, user_cert.to_string()), "Write file: {} failed: {}", &ssh_cert_file);
            }
        }

        Ok(None)
    }
}

fn find_cert(yk: &mut YubiKey, slot_id: SlotId) -> XResult<Vec<u8>> {
    match Key::list(yk) {
        Err(e) => warning!("List keys failed: {}", e),
        Ok(keys) => {
            for k in &keys {
                let slot_str = format!("{:x}", Into::<u8>::into(k.slot()));
                if slot_equals(&slot_id, &slot_str) {
                    let cert_der = k.certificate().cert.to_der()?;
                    return Ok(cert_der);
                }
            }
        }
    }
    simple_error!("Cannot find slot: {}", slot_id)
}

pub fn get_ssh_key_type(public_key: &PublicKey) -> XResult<AlgorithmId> {
    match &public_key.kind {
        PublicKeyKind::Ecdsa(x) => match x.curve.kind {
            CurveKind::Nistp256 => Ok(AlgorithmId::EccP256),
            CurveKind::Nistp384 => Ok(AlgorithmId::EccP384),
            CurveKind::Nistp521 => simple_error!("NIST P521 is not supported."),
        },
        PublicKeyKind::Rsa(_) => simple_error!("RSA is not supported."),
        PublicKeyKind::Ed25519(_) => simple_error!("Ed25519 is not supported."),
    }
}

struct SshYubikeySinger {
    yubikey: Mutex<YubiKey>,
    pin_opt: Option<String>,
    ca_ssh_pub_slot_id: SlotId,
    ca_ssh_pub_key: PublicKey,
    ca_ssh_pub_algorithm_id: AlgorithmId,
}

impl SshYubikeySinger {
    fn new(yubikey: YubiKey, pin_opt: Option<String>, ca_ssh_pub_slot_id: SlotId, ca_ssh_pub_key: PublicKey, ca_ssh_pub_algorithm_id: AlgorithmId) -> Self {
        Self {
            yubikey: Mutex::new(yubikey),
            pin_opt,
            ca_ssh_pub_slot_id,
            ca_ssh_pub_key,
            ca_ssh_pub_algorithm_id,
        }
    }
}

impl SSHCertificateSigner for SshYubikeySinger {
    fn sign(&self, buffer: &[u8]) -> Option<Vec<u8>> {
        let digest = match self.ca_ssh_pub_algorithm_id {
            AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => { panic!("Should not reach here.") }
            AlgorithmId::EccP256 => sha256_bytes(buffer),
            AlgorithmId::EccP384 => sha384_bytes(buffer),
        };
        let mut yubikey = self.yubikey.lock().unwrap();
        if let Some(pin) = &self.pin_opt {
            yubikey.verify_pin(pin.as_bytes()).expect("Verify PIN failed: {}");
        }

        let signature = sign_data(&mut yubikey, &digest, self.ca_ssh_pub_algorithm_id, self.ca_ssh_pub_slot_id).expect("SSH user CA sign failed: {}");

        format_signature_for_ssh(&self.ca_ssh_pub_key, signature.as_ref())
    }
}
