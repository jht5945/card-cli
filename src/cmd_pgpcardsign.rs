use std::collections::BTreeMap;
use std::fs::File;
use std::io::{ErrorKind, Read};

use clap::{App, Arg, ArgMatches, SubCommand};
use digest::Digest;
use openpgp_card::crypto_data::Hash;
use openpgp_card::OpenPgp;
use rust_util::util_clap::{Command, CommandError};
use rust_util::{util_msg, XResult};
use sha2::{Sha256, Sha384, Sha512};
use crate::util::base64_encode;

const BUFF_SIZE: usize = 512 * 1024;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "pgp-card-sign" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("OpenPGP Card Sign subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).default_value("123456").help("OpenPGP card user pin"))
            .arg(Arg::with_name("pass").long("pass").takes_value(true).help("[deprecated] now OpenPGP card user pin"))
            .arg(Arg::with_name("sha256").short("2").long("sha256").takes_value(true).help("Digest SHA256 HEX"))
            .arg(Arg::with_name("sha384").short("3").long("sha384").takes_value(true).help("Digest SHA384 HEX"))
            .arg(Arg::with_name("sha512").short("5").long("sha512").takes_value(true).help("Digest SHA512 HEX"))
            .arg(Arg::with_name("in").short("i").long("in").takes_value(true).help("File in"))
            .arg(Arg::with_name("use-sha256").long("use-sha256").help("Use SHA256 for file in"))
            .arg(Arg::with_name("use-sha384").long("use-sha384").help("Use SHA384 for file in"))
            .arg(Arg::with_name("use-sha512").long("use-sha512").help("Use SHA512 for file in"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let pin_opt = sub_arg_matches.value_of("pass").or_else(|| sub_arg_matches.value_of("pin"));
        let pin = opt_value_result!(pin_opt, "User pin must be assigned");
        if pin.len() < 6 { return simple_error!("User pin length:{}, must >= 6!", pin.len()); }

        let mut sha256 = sub_arg_matches.value_of("sha256").map(|s| s.to_string());
        let mut sha384 = sub_arg_matches.value_of("sha384").map(|s| s.to_string());
        let mut sha512 = sub_arg_matches.value_of("sha512").map(|s| s.to_string());
        let file_in_opt = sub_arg_matches.value_of("in");

        let mut json = BTreeMap::new();
        if let Some(file_in) = file_in_opt {
            if sha256.is_some() || sha384.is_some() || sha512.is_some() { return simple_error!("Conflict --in vs --sha256, --sha384, --sha512 args"); }

            let use_sha256 = sub_arg_matches.is_present("use-sha256");
            let use_sha384 = sub_arg_matches.is_present("use-sha384");
            let use_sha512 = sub_arg_matches.is_present("use-sha512");

            if !use_sha256 && !use_sha384 && !use_sha512 {
                return simple_error!("Must has one option --use-sha256, --use-sha384, --use-sha512");
            }

            if use_sha256 {
                let hash = opt_result!(calc_file_digest::<Sha256>(file_in), "Calc file: {} SHA256 failed: {}", file_in);
                sha256 = Some(hex::encode(hash));
            }
            if use_sha384 {
                let hash = opt_result!(calc_file_digest::<Sha384>(file_in), "Calc file: {} SHA384 failed: {}", file_in);
                sha384 = Some(hex::encode(hash));
            }
            if use_sha512 {
                let hash = opt_result!(calc_file_digest::<Sha512>(file_in), "Calc file: {} SHA512 failed: {}", file_in);
                sha512 = Some(hex::encode(hash));
            }

            let mut entry = BTreeMap::new();
            entry.insert("file", file_in.to_string());
            json.insert("meta", entry);
        }

        if sha256.is_none() && sha384.is_none() && sha512.is_none() {
            return simple_error!("SHA256, SHA384 or SHA512 must assign at least one");
        }

        let card = crate::pgpcardutil::get_card()?;
        let mut pgp = OpenPgp::new(card);
        let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");

        if let Some(sha256) = sha256 {
            let sha256_hex = opt_result!(hex::decode(sha256.trim()), "Decode sha256 failed: {}");
            let sha256_hex = crate::digest::copy_sha256(&sha256_hex)?;
            opt_result!(trans.verify_pw1_sign(pin.as_ref()), "User sign pin verify failed: {}");
            success!("User sign pin verify success!");
            let sig = trans.signature_for_hash(Hash::SHA256(sha256_hex))?;
            success!("SHA256 signature HEX: {}", hex::encode(&sig));
            success!("SHA256 signature base64: {}", base64_encode(&sig));
            if json_output {
                let mut entry = BTreeMap::new();
                entry.insert("digest", hex::encode(&sha256_hex));
                entry.insert("signature", hex::encode(&sig));
                json.insert("sha256", entry);
            }
        }
        if let Some(sha384) = sha384 {
            let sha384_hex = opt_result!(hex::decode(sha384.trim()), "Decode sha384 failed: {}");
            let sha384_hex = crate::digest::copy_sha384(&sha384_hex)?;
            opt_result!(trans.verify_pw1_sign(pin.as_ref()), "User sign pin verify failed: {}");
            success!("User sign pin verify success!");
            let sig = trans.signature_for_hash(Hash::SHA384(sha384_hex))?;
            success!("SHA384 signature HEX: {}", hex::encode(&sig));
            success!("SHA384 signature base64: {}", base64_encode(&sig));
            if json_output {
                let mut entry = BTreeMap::new();
                entry.insert("digest", hex::encode(&sha384_hex));
                entry.insert("signature", hex::encode(&sig));
                json.insert("sha384", entry);
            }
        }
        if let Some(sha512) = sha512 {
            let sha512_hex = opt_result!(hex::decode(sha512.trim()), "Decode sha512 failed: {}");
            let sha512_hex = crate::digest::copy_sha512(&sha512_hex)?;
            opt_result!(trans.verify_pw1_sign(pin.as_ref()), "User sign pin verify failed: {}");
            success!("User sign pin verify success!");
            let sig = trans.signature_for_hash(Hash::SHA512(sha512_hex))?;
            success!("SHA512 signature HEX: {}", hex::encode(&sig));
            success!("SHA512 signature base64: {}", base64_encode(&sig));
            if json_output {
                let mut entry = BTreeMap::new();
                entry.insert("digest", hex::encode(&sha512_hex));
                entry.insert("signature", hex::encode(&sig));
                json.insert("sha512", entry);
            }
        }

        if json_output {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }

        Ok(None)
    }
}

fn calc_file_digest<D>(file_name: &str) -> XResult<Vec<u8>> where D: Digest {
    let mut hasher = D::new();
    let mut buf: [u8; BUFF_SIZE] = [0u8; BUFF_SIZE];
    let mut f = File::open(file_name)?;
    let file_len = f.metadata()?.len();
    debugging!("File: {}, length: {}", file_name, file_len);
    loop {
        let len = match f.read(&mut buf) {
            Ok(0) => return Ok(hasher.finalize().as_slice().to_vec()),
            Ok(len) => len,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return simple_error!("Calc file digest failed: {}", e),
        };
        hasher.update(&buf[..len]);
    }
}
