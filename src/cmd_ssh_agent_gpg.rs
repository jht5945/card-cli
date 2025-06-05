use std::error::Error;
use std::fs::remove_file;
use std::path::PathBuf;
use std::sync::Mutex;

use clap::{App, Arg, ArgMatches, SubCommand};
use openpgp_card::{KeyType, OpenPgp};
use openpgp_card::crypto_data::{Hash, PublicKeyMaterial};
use openssl::hash::MessageDigest;
use rust_util::util_clap::{Command, CommandError};
use rust_util::XResult;
use ssh_agent::Agent;
use ssh_agent::proto::{from_bytes, RsaPublicKey, signature, Signature, to_bytes};
use ssh_agent::proto::message::{self, Message};
use ssh_agent::proto::public_key::PublicKey;

use crate::digestutil::{copy_sha256, copy_sha512};
use crate::pinutil;
use crate::sshutil::{generate_ssh_string, with_sign};

struct SshAgent {
    open_pgp: Mutex<OpenPgp>,
    use_sign: bool,
    pin: String,
    public_key: PublicKey,
    comment: String,
    ssh_string: String,
}

impl SshAgent {
    fn new(pin: String, use_sign: bool) -> XResult<Self> {
        let card = crate::pgpcardutil::get_card()?;
        let (public_key, comment, ssh_string, open_pgp) = {
            let mut pgp = OpenPgp::new(card);
            let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");
            let serial = trans.application_related_data()
                .map(|d| d.application_id().map(|i| i.serial()))
                .unwrap_or_else(|_| Ok(0)).unwrap_or(0);
            let serial = hex::encode(serial.to_be_bytes());
            let public_key = opt_result!(trans.public_key(iff!(use_sign, KeyType::Signing, KeyType::Authentication)), "Cannot find signing key: {}");
            let rsa_public_key = match public_key {
                PublicKeyMaterial::E(_) => return simple_error!("Not supports ec key"),
                PublicKeyMaterial::R(rsa_public_key) => rsa_public_key,
                _ => return simple_error!("Unknown key type"),
            };
            let e = rsa_public_key.v();
            let n = rsa_public_key.n();

            let public_key = PublicKey::Rsa(RsaPublicKey {
                e: with_sign(e.to_vec()),
                n: with_sign(n.to_vec()),
            });
            let comment = format!("pgp-card:{}:{}", iff!(use_sign, "sign", "auth"), serial);
            drop(trans);
            (public_key, comment.clone(), generate_ssh_string(e, n, &comment), pgp)
        };
        Ok(Self {
            open_pgp: Mutex::new(open_pgp),
            use_sign,
            pin,
            public_key,
            comment,
            ssh_string,
        })
    }

    fn handle_message(&self, request: Message) -> Result<Message, Box<dyn Error>> {
        debugging!("Request: {:?}", request);
        let response = match request {
            Message::RequestIdentities => {
                let identities = vec![message::Identity {
                    pubkey_blob: to_bytes(&self.public_key)?,
                    comment: self.comment.clone(),
                }];
                Ok(Message::IdentitiesAnswer(identities))
            }
            Message::RemoveIdentity(ref _identity) => {
                Err(From::from(format!("Not supported message: {:?}", request)))
            }
            Message::AddIdentity(ref _identity) => {
                Err(From::from(format!("Not supported message: {:?}", request)))
            }
            Message::SignRequest(sign_request) => {
                let pubkey: PublicKey = from_bytes(&sign_request.pubkey_blob)?;
                if self.public_key != pubkey {
                    return Err(From::from(format!("Unknown public key: {:?}", sign_request)));
                }
                debugging!("To be signed data: {:?}", &sign_request.data);

                let (algorithm, hash) = if sign_request.flags & signature::RSA_SHA2_512 != 0 {
                    let hash = opt_result!(openssl::hash::hash(MessageDigest::sha512(), &sign_request.data), "Calc digest failed: {}");
                    ("rsa-sha2-512", Hash::SHA512(copy_sha512(&hash).unwrap()))
                } else if sign_request.flags & signature::RSA_SHA2_256 != 0 {
                    let hash = opt_result!(openssl::hash::hash(MessageDigest::sha256(), &sign_request.data), "Calc digest failed: {}");
                    ("rsa-sha2-256", Hash::SHA256(copy_sha256(&hash).unwrap()))
                } else {
                    return Err(From::from(format!("Not supported sign flags: {:?}", sign_request.flags)));
                };

                information!("SSH request, algorithm: {}", algorithm);
                let mut pgp = self.open_pgp.lock().unwrap();
                // let mut pgp = OpenPgp::new(*card_mut);
                let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");
                let sig = if self.use_sign {
                    debugging!("User pin verify for pw1 sign, use sign: {}", self.use_sign);
                    opt_result!(trans.verify_pw1_sign(self.pin.as_bytes()), "User sign pin verify failed: {}");
                    opt_result!(trans.signature_for_hash(hash), "Sign OpenPGP card failed: {}")
                } else {
                    debugging!("User pin verify for pw1 user, use sign: {}", self.use_sign);
                    opt_result!(trans.verify_pw1_user(self.pin.as_bytes()), "User user pin verify failed: {}");
                    opt_result!(trans.authenticate_for_hash(hash), "Auth OpenPGP card failed: {}")
                };

                debugging!("Signature: {:?}", sig);
                success!("SSH request sign success");
                Ok(Message::SignResponse(to_bytes(&Signature {
                    algorithm: algorithm.to_string(),
                    blob: sig,
                })?))
            }
            _ => Err(From::from(format!("Unknown message: {:?}", request)))
        };
        debugging!("Response {:?}", response);
        response
    }
}

impl Agent for SshAgent {
    type Error = ();

    fn handle(&self, message: Message) -> Result<Message, ()> {
        self.handle_message(message).or_else(|error| {
            warning!("Error handling message - {:?}", error);
            Ok(Message::Failure)
        })
    }
}

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "ssh-agent-gpg" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("SSH-Agent OpenPGP card subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").default_value("123456").help("OpenPGP card user pin"))
            .arg(Arg::with_name("pgp").long("pgp").help("Use PGP"))
            .arg(Arg::with_name("pgp-sign").long("pgp-sign").help("Use PGP sign"))
            .arg(Arg::with_name("pgp-auth").long("pgp-auth").help("Use PGP auth"))
            .arg(Arg::with_name("piv").long("piv").help("Use PIV"))
            .arg(Arg::with_name("sock-file").long("sock-file").default_value("connect.ssh").help("Sock file, usage SSH_AUTH_SOCK=sock-file ssh ..."))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let use_pgp = sub_arg_matches.is_present("pgp");
        let use_piv = sub_arg_matches.is_present("piv");
        if !(use_pgp ^ use_piv) {
            return simple_error!("Args --pgp or --piv must have one selection");
        }
        let use_pgp_sign = sub_arg_matches.is_present("pgp-sign");
        let use_pgp_auth = sub_arg_matches.is_present("pgp-auth");
        if use_pgp && !(use_pgp_sign ^ use_pgp_auth) {
            return simple_error!("Args --pgp-sign or --pgp-auth must have one selection when use --pgp");
        }
        let pin_opt = sub_arg_matches.value_of("pin");
        let pin_opt = pinutil::get_pin(pin_opt);
        let pin = pin_opt.as_deref().unwrap();

        let sock_file = sub_arg_matches.value_of("sock-file").unwrap();
        information!("Sock file: {}", sock_file);

        let sock_file_path = PathBuf::from(".");
        match std::fs::canonicalize(sock_file_path) {
            Ok(canonicalized_sock_file_path) => information!("SSH_AUTH_SOCK={}/{}",
                    canonicalized_sock_file_path.to_str().unwrap_or("-"), sock_file),
            Err(e) => warning!("Get canonicalized sock file path failed: {}", e),
        }

        if use_pgp {
            let ssh_agent = SshAgent::new(pin.to_string(), use_pgp_sign)?;
            information!("{}", &ssh_agent.ssh_string);

            let _ = remove_file(sock_file);

            information!("Start unix socket: {}", sock_file);
            opt_result!(ssh_agent.run_unix(sock_file), "Run unix socket: {}, failed: {}", sock_file);
        }

        information!("card-cli ssh-agent...");

        Ok(None)
    }
}
