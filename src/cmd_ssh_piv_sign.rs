use clap::{App, Arg, ArgMatches, SubCommand};
use der_parser::ber::BerObjectContent;
use pem::Pem;
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use yubikey::{Key, YubiKey};
use yubikey::piv::{AlgorithmId, sign_data};

use crate::{cmdutil, pinutil, pivutil, util};
use crate::pivutil::{get_algorithm_id_by_certificate, slot_equals, ToStr};
use crate::sshutil::SshVecWriter;

pub struct CommandImpl;

// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
impl Command for CommandImpl {
    fn name(&self) -> &str { "ssh-piv-sign" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("SSH piv sign subcommand")
            .arg(cmdutil::build_slot_arg())
            .arg(cmdutil::build_pin_arg())
            .arg(cmdutil::build_no_pin_arg())
            .arg(Arg::with_name("namespace").short("n").long("namespace").takes_value(true).help("Namespace"))
            .arg(Arg::with_name("in").long("in").required(true).takes_value(true).help("In file, - for stdin"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        util_msg::set_logger_std_out(false);

        let namespace_opt = sub_arg_matches.value_of("namespace");
        let namespace = match namespace_opt {
            None => return simple_error!("Namespace required"),
            Some(namespace) => namespace,
        };
        let data = util::read_file_or_stdin(sub_arg_matches.value_of("in").unwrap())?;

        let slot = opt_value_result!(sub_arg_matches.value_of("slot"), "--slot must assigned, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e");
        let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
        let slot_id = pivutil::get_slot_id(slot)?;

        let pin_opt = pinutil::read_pin(sub_arg_matches);

        let mut algorithm_id_opt = None;
        let mut ec_key_point = vec![];
        match Key::list(&mut yk) {
            Err(e) => warning!("List keys failed: {}", e),
            Ok(keys) => for k in &keys {
                let slot_str = format!("{:x}", Into::<u8>::into(k.slot()));
                if slot_equals(&slot_id, &slot_str) {
                    let cert = &k.certificate().cert.tbs_certificate;
                    let certificate = k.certificate();
                    if let Ok(algorithm_id) = get_algorithm_id_by_certificate(certificate) {
                        match algorithm_id {
                            AlgorithmId::EccP256 | AlgorithmId::EccP384 => {
                                let public_key_bit_string = &cert.subject_public_key_info.subject_public_key;
                                ec_key_point.extend_from_slice(public_key_bit_string.raw_bytes());
                                algorithm_id_opt = Some(algorithm_id);
                            }
                            _ => return simple_error!("Not P256/384 key: {}", algorithm_id.to_str()),
                        }
                    }
                }
            }
        }
        let algorithm_id = match algorithm_id_opt {
            None => return simple_error!("Slot key not found!"),
            Some(algorithm_id) => algorithm_id,
        };
        let ec_bit_len = iff!(matches!(algorithm_id, AlgorithmId::EccP256), 256, 384);

        let mut buffer = vec![];
        buffer.write_bytes("SSHSIG".as_bytes());
        buffer.write_u32(1);

        let mut public_key = vec![];
        public_key.write_string(format!("ecdsa-sha2-nistp{}", ec_bit_len).as_bytes());
        public_key.write_string(format!("nistp{}", ec_bit_len).as_bytes());
        public_key.write_string(&ec_key_point);
        buffer.write_string(&public_key);
        buffer.write_string(namespace.as_bytes());
        buffer.write_string("".as_bytes());
        // The supported hash algorithms are "sha256" and "sha512".
        buffer.write_string("sha512".as_bytes());

        let mut signature = vec![];
        signature.write_string(format!("ecdsa-sha2-nistp{}", ec_bit_len).as_bytes());

        let mut sign_message = vec![];
        sign_message.write_bytes("SSHSIG".as_bytes());
        sign_message.write_string(namespace.as_bytes());
        sign_message.write_string("".as_bytes());
        sign_message.write_string("sha512".as_bytes());
        let data_digest = crate::digestutil::sha512_bytes(&data);
        debugging!("Data digest: {} (sha512)", hex::encode(&data_digest));
        sign_message.write_string(&data_digest);
        debugging!("Singed message: {}", hex::encode(&sign_message));
        let tobe_signed_data = if ec_bit_len == 256 {
            crate::digestutil::sha256_bytes(&sign_message)
        } else {
            crate::digestutil::sha384_bytes(&sign_message)
        };
        debugging!("Digest of signed message: {}", hex::encode(&tobe_signed_data));

        if let Some(pin) = &pin_opt {
            opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");
        }
        let mut signature_value = vec![];
        let signed_data = opt_result!(sign_data(&mut yk, &tobe_signed_data, algorithm_id, slot_id), "Sign PIV failed: {}");
        debugging!("Signature: {}", hex::encode(signed_data.as_slice()));
        let (_, parsed_signature) = opt_result!(der_parser::parse_der(signed_data.as_slice()), "Parse signature failed: {}");
        match parsed_signature.content {
            BerObjectContent::Sequence(seq) => {
                match &seq[0].content {
                    BerObjectContent::Integer(r) => {
                        debugging!("Signature r: {}", hex::encode(r));
                        signature_value.write_string(r);
                    }
                    _ => return simple_error!("Parse signature failed: [0]not integer"),
                }
                match &seq[1].content {
                    BerObjectContent::Integer(s) => {
                        debugging!("Signature s: {}", hex::encode(s));
                        signature_value.write_string(s);
                    }
                    _ => return simple_error!("Parse signature failed: [1]not integer"),
                }
            }
            _ => return simple_error!("Parse signature failed: not sequence"),
        }
        signature.write_string(&signature_value);
        buffer.write_string(&signature);

        let ssh_sig = Pem::new("SSH SIGNATURE", buffer);
        let ssh_sig_pem = ssh_sig.to_string();
        println!("{}", ssh_sig_pem);

        Ok(None)
    }
}
