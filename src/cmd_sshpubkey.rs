use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use yubikey::piv::AlgorithmId;
use yubikey::{Key, YubiKey};

use crate::pivutil;
use crate::pivutil::{get_algorithm_id_by_certificate, slot_equals, ToStr};
use crate::sshutil::SshVecWriter;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "ssh-pub-key" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("SSH public key subcommand")
            .arg(Arg::with_name("slot").short("s").long("slot").takes_value(true).help("PIV slot, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let slot = opt_value_result!(sub_arg_matches.value_of("slot"), "--slot must assigned, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e");
        let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
        let slot_id = pivutil::get_slot_id(slot)?;

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

        let ssh_algorithm = match algorithm_id {
            AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => panic!("Not supported."),
            AlgorithmId::EccP256 => "nistp256",
            AlgorithmId::EccP384 => "nistp384",
        };

        information!("SSH algorithm: {}", ssh_algorithm);
        information!("ECDSA public key: {}", hex::encode(&ec_key_point));
        println!();

        // ECDSA SSH public key format:
        // string ecdsa-sha2-[identifier]
        // byte[n] ecc_key_blob
        //
        // ecc_key_blob:
        // string [identifier]
        // string Q
        //
        // [identifier] will be nistp256 or nistp384
        let mut ssh_pub_key = vec![];
        ssh_pub_key.write_string(&format!("ecdsa-sha2-{}", ssh_algorithm).as_bytes());
        let mut ecc_key_blob = vec![];
        ecc_key_blob.write_string(ssh_algorithm.as_bytes());
        ecc_key_blob.write_string(&ec_key_point);
        ssh_pub_key.write_bytes(&ecc_key_blob);

        println!("ecdsa-sha2-{} {} Yubikey-PIV-{}", ssh_algorithm, STANDARD.encode(&ssh_pub_key), slot_id);

        Ok(None)
    }
}
