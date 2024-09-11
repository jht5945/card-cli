use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use sshcerts::ssh::PublicKeyKind;
use sshcerts::{Certificate, PrivateKey, PublicKey};
use std::fs;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "ssh-parse" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("SSH public key subcommand")
            .arg(Arg::with_name("file").short("f").long("file").required(true).takes_value(true).help("SSH file"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let file = sub_arg_matches.value_of("file").unwrap();
        let content = opt_result!(fs::read(file), "Read file: {} failed: {}", file);
        let content_str = opt_result!(String::from_utf8(content), "Read file(UTF-8): {} failed: {}", file);

        let mut parsed = false;
        if let Ok(private_key) = PrivateKey::from_string(&content_str) {
            parsed = true;
            success!("Parse private key success.");
            println!("{:?}", private_key);
        }
        if let Ok(public_key) = PublicKey::from_string(&content_str) {
            parsed = true;
            success!("Parse public key success.");
            println!("Key type: {}", public_key.key_type);
            match public_key.kind {
                PublicKeyKind::Rsa(rsa) => {
                    println!(" - e: {}", hex::encode(&rsa.e));
                    println!(" - n: {}", hex::encode(&rsa.n));
                }
                PublicKeyKind::Ecdsa(ecdsa) => {
                    println!(" - curve: {} ({:?})", ecdsa.curve.identifier, ecdsa.curve.kind);
                    println!(" - key: {}", hex::encode(&ecdsa.key));
                    println!(" - sk application: {:?}", ecdsa.sk_application);
                }
                PublicKeyKind::Ed25519(ed12219) => {
                    println!(" - key: {}", hex::encode(&ed12219.key));
                    println!(" - sk application: {:?}", ed12219.sk_application);
                }
            }
            println!("Comment: {:?}", public_key.comment);
        }
        if let Ok(certificate) = Certificate::from_string(&content_str) {
            parsed = true;
            success!("Parse certificate success.");
            println!("{:#?}", certificate);
        }

        if !parsed {
            return simple_error!("Parse SSH file failed, not private key, public key or certificate.");
        }

        Ok(None)
    }
}
