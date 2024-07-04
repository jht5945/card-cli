use std::io::{Cursor, Read};
use std::str::FromStr;

use clap::{App, Arg, ArgMatches, SubCommand};
use pem::Pem;
use rust_util::util_clap::{Command, CommandError};
use rust_util::XResult;

use crate::util;

trait CursorReader {
    fn read_bytes(&mut self, len: usize) -> XResult<Vec<u8>>;
    fn read_u32(&mut self) -> XResult<u32>;
    fn read_string(&mut self) -> XResult<Vec<u8>>;
}

impl CursorReader for Cursor<Vec<u8>> {
    fn read_bytes(&mut self, len: usize) -> XResult<Vec<u8>> {
        let mut buff = vec![0_u8; len];
        Cursor::read_exact(self, &mut buff)?;
        Ok(buff)
    }

    fn read_u32(&mut self) -> XResult<u32> {
        let mut num = [0_u8; 4];
        num.copy_from_slice(&self.read_bytes(4)?);
        Ok(u32::from_be_bytes(num))
    }

    fn read_string(&mut self) -> XResult<Vec<u8>> {
        let len = self.read_u32()?;
        if len == 0 {
            return Ok(Vec::new());
        }
        self.read_bytes(len as usize)
    }
}

pub struct CommandImpl;

// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
impl Command for CommandImpl {
    fn name(&self) -> &str { "ssh-parse-sign" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("SSH parse sign subcommand")
            .arg(Arg::with_name("in").long("in").required(true).takes_value(true).help("In file, - for stdin"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let file_in = sub_arg_matches.value_of("in").unwrap();
        let bytes_in = util::read_file_or_stdin(file_in)?;
        let pem_in = opt_result!(String::from_utf8(bytes_in), "Parse SSH sign failed: {}");

        let pem = opt_result!( Pem::from_str(&pem_in), "Parse SSH sign pem failed: {}");
        debugging!("PEM: {:?}", pem);

        if pem.tag() != "SSH SIGNATURE" {
            return simple_error!("Not SSH signature file.");
        }

        let ssh_signature = pem.contents().to_vec();
        let mut cursor = Cursor::new(ssh_signature);

        let magic_preamble = String::from_utf8(cursor.read_bytes(6)?)?;
        if magic_preamble != "SSHSIG" {
            return simple_error!("Bad SSH signature file: magic");
        }
        let ssh_signature_version = cursor.read_u32()?;
        if ssh_signature_version != 1 {
            return simple_error!("Bad SSH signature file: version");
        }
        let public_key = cursor.read_string()?;
        debugging!("Public key: {}", hex::encode(&public_key));
        let namespace = String::from_utf8(cursor.read_string()?)?;
        debugging!("Namespace: {}", namespace);
        let reserved = cursor.read_string()?;
        debugging!("Reserved: {}", hex::encode(&reserved));
        let hash_algorithm = String::from_utf8(cursor.read_string()?)?;
        debugging!("Hash algorithm: {}", hash_algorithm);
        let signature = cursor.read_string()?;
        debugging!("Signature: {}", hex::encode(&signature));

        let mut public_key_cursor = Cursor::new(public_key);
        let public_key_algorithm = String::from_utf8(public_key_cursor.read_string()?)?;
        debugging!("Public key algorithm: {}", public_key_algorithm);
        let public_key_algorithm2 = String::from_utf8(public_key_cursor.read_string()?)?;
        debugging!("Public key algorithm(2): {}", public_key_algorithm2);
        let public_key_value = public_key_cursor.read_string()?;
        debugging!("Public key value: {}", hex::encode(&public_key_value));

        let mut signature_cursor = Cursor::new(signature);
        let signature_algorithm = String::from_utf8(signature_cursor.read_string()?)?;
        debugging!("Signature algorithm: {}", signature_algorithm);
        let signature_value = signature_cursor.read_string()?;
        debugging!("Signature value: {}", hex::encode(&signature_value));

        println!("Public Key:\n> {}", public_key_algorithm);
        println!("  > {}", public_key_algorithm2);
        println!("  > {}", hex::encode(public_key_value));
        println!("Namespace: {}", namespace);
        println!("Reserved: {}", hex::encode(&reserved));
        println!("Hash Algorithm: {}", &hash_algorithm);
        println!("Signature:\n> {}", signature_algorithm);
        if signature_algorithm.starts_with("ecdsa-") {
            let mut signature_value_cursor = Cursor::new(signature_value);
            let signature_value_x = signature_value_cursor.read_string()?;
            let signature_value_y = signature_value_cursor.read_string()?;
            println!("  > {}", hex::encode(signature_value_x));
            println!("  > {}", hex::encode(signature_value_y));
        } else if signature_algorithm.starts_with("rsa-") {
            println!("  > {}", hex::encode(signature_value));
        } else {
            failure!("Unknown signature algorithm: {}", signature_algorithm);
        }

        Ok(None)
    }
}
