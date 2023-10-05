use std::ops::Deref;

use chrono::{DateTime, Local};
use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use sequoia_openpgp::Packet;
use sequoia_openpgp::packet::{Body, Key, PKESK, SEIP, Signature};
use sequoia_openpgp::packet::signature::subpacket::{SubpacketTag, SubpacketValue};
use sequoia_openpgp::parse::{PacketParser, PacketParserResult};
use sequoia_openpgp::parse::Parse;

use crate::pkiutil::sequoia_openpgp_public_key_pem as public_key_pem;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "pgp" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("OpenPGP subcommand")
            .arg(Arg::with_name("in").short("i").long("in").takes_value(true).help("File input, *.pgp or *.asc"))
            .arg(Arg::with_name("detail").long("detail").help("Detail output"))
            .arg(Arg::with_name("verbose").long("verbose").help("Verbose output"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let in_file = sub_arg_matches.value_of("in");
        let show_verbose = sub_arg_matches.is_present("verbose");
        let show_detail = show_verbose || sub_arg_matches.is_present("detail");

        let in_file = opt_value_result!(in_file, "Input file must assined");

        let in_file_bytes = opt_result!(std::fs::read(in_file), "Read file: {}, failed: {}", in_file);
        let p = PacketParser::from_bytes(&in_file_bytes);
        let mut ppr = opt_result!(p, "Parse file: {}, failed: {}", in_file);
        while let PacketParserResult::Some(pp) = ppr {
            match &pp.packet {
                Packet::Signature(signature) => {
                    debugging!("Found signature: {:?}", signature);
                    match signature {
                        Signature::V4(sig) => {
                            // information!("-----> {:?}",  sig.hashed_area());
                            if show_verbose {
                                sig.hashed_area().iter().for_each(|sub_package| {
                                    information!("Hashed area, sub package: {:?}", sub_package);
                                });
                                sig.unhashed_area().iter().for_each(|sub_package| {
                                    information!("Unhashed area, sub package: {:?}", sub_package);
                                });
                            }
                            if let Some(sub_package) = sig.hashed_area().subpacket(SubpacketTag::KeyFlags) {
                                if let SubpacketValue::KeyFlags(key_flags) = sub_package.value() {
                                    let mut key_flags_vec = vec![];
                                    if key_flags.for_certification() { key_flags_vec.push("Certificate") }
                                    if key_flags.for_signing() { key_flags_vec.push("Signing") }
                                    if key_flags.for_transport_encryption() { key_flags_vec.push("TransportEncryption") }
                                    if key_flags.for_storage_encryption() { key_flags_vec.push("StorageEncryption") }
                                    if key_flags.for_authentication() { key_flags_vec.push("Authentication") }
                                    if key_flags.is_split_key() { key_flags_vec.push("SplitKey") }
                                    if key_flags.is_group_key() { key_flags_vec.push("GroupKey") }
                                    debugging!("Found sub key flags: {:?}", sub_package);
                                    let authenticated = sub_package.authenticated();
                                    information!("Found sub key flags: [{}], {} authenticated", key_flags_vec.join(", "), iff!(authenticated, "is", "not"));
                                } else {
                                    information!("Found sub key flags: {:?}", sub_package);
                                }
                            }
                        }
                        unknown => warning!("Unknown signature: {:?}", unknown),
                    }
                    information!("Found signature: {:?} - {:?} [{:?}]", signature.get_issuers(), signature.hash_algo(), signature.features());
                }
                Packet::OnePassSig(one_pass_sig) => {
                    information!("Found one pass sig: {:?}", one_pass_sig);
                }
                Packet::PublicKey(public_key) => {
                    information!("{}", "-".repeat(88));
                    debugging!("Found public key: {:?}", public_key);
                    match public_key {
                        Key::V4(key4) => {
                            let mut public_key4 = String::with_capacity(512);
                            public_key4.push_str(&format!("\n\tKey ID: {:?}", key4.keyid()));
                            public_key4.push_str(&format!("\n\tFinger print {:?}", key4.fingerprint()));
                            public_key4.push_str(&format!("\n\tHash algo security: {:?}", key4.hash_algo_security()));
                            // public_key4.push_str(&format!("\n\tKey handle {:?}", key4.key_handle()));
                            let creation_time: DateTime<Local> = DateTime::from(key4.creation_time());
                            let creation_time_str = simpledateformat::fmt("yyyy-MM-dd HH:mm:ss").unwrap().format(&creation_time);
                            public_key4.push_str(&format!("\n\tCreation time {}", creation_time_str));
                            public_key4.push_str(&format!("\n\tPublic algo: {:?}", key4.pk_algo()));
                            if show_detail {
                                if let Some((pubkey_sha256, pubkey_pem)) = public_key_pem(key4.mpis()) {
                                    public_key4.push_str(&format!("\n\tPublic key sha256: {}", hex::encode(pubkey_sha256)));
                                    public_key4.push_str(&format!("\n\tPublic key PEM: {}", pubkey_pem));
                                }
                            }
                            information!("Found public key: {}", public_key4);
                        }
                        unknown => warning!("Unknown key: {:?}", unknown),
                    }
                }
                Packet::PublicSubkey(public_sub_key) => {
                    information!("{}", "-".repeat(88));
                    debugging!("Found public sub key: {:?}", public_sub_key);
                    match public_sub_key {
                        Key::V4(key4) => {
                            let mut public_key4 = String::with_capacity(512);
                            public_key4.push_str(&format!("\n\tKey ID: {:?}", key4.keyid()));
                            public_key4.push_str(&format!("\n\tFinger print {:?}", key4.fingerprint()));
                            public_key4.push_str(&format!("\n\tHash algo security: {:?}", key4.hash_algo_security()));
                            let creation_time: DateTime<Local> = DateTime::from(key4.creation_time());
                            let creation_time_str = simpledateformat::fmt("yyyy-MM-dd HH:mm:ss").unwrap().format(&creation_time);
                            public_key4.push_str(&format!("\n\tCreation time {}", creation_time_str));
                            public_key4.push_str(&format!("\n\tPublic algo: {:?}", key4.pk_algo()));
                            if show_detail {
                                if let Some((pubkey_sha256, pub_key_pem)) = public_key_pem(key4.mpis()) {
                                    public_key4.push_str(&format!("\n\tPublic key sha256: {}", hex::encode(pubkey_sha256)));
                                    public_key4.push_str(&format!("\n\tPublic key PEM: {}", pub_key_pem));
                                }
                            }
                            information!("Found public sub key: {}", public_key4);
                        }
                        unknown => warning!("Unknown key: {:?}", unknown),
                    }
                }
                Packet::SecretKey(secret_key) => {
                    information!("Found secret key: {:?}", secret_key);
                }
                Packet::SecretSubkey(secret_sub_key) => {
                    information!("Found secret sub key: {:?}", secret_sub_key);
                }
                Packet::Marker(marker) => {
                    information!("Found marker: {:?}", marker);
                }
                Packet::Trust(trust) => {
                    information!("Found trust: {:?}", trust);
                }
                Packet::UserID(user_id) => {
                    information!("Found user ID: {}", String::from_utf8_lossy(user_id.value()));
                }
                Packet::UserAttribute(user_attribute) => {
                    information!("Found user attribute: {:?}", user_attribute);
                }
                Packet::Literal(literal) => {
                    information!("Found literal: {:?}", literal);
                }
                Packet::CompressedData(compressed_data) => {
                    information!("Found compressed data: {:?}", compressed_data);
                }
                Packet::PKESK(pkesk) => {
                    debugging!("Found PKESK: {:?}", pkesk);
                    match pkesk {
                        PKESK::V3(pkesk3) => {
                            information!("Found public key encrypted session key, key ID: {}, alog: {}", pkesk3.recipient(), pkesk3.pk_algo());
                        }
                        unknown => warning!("Unknown PKESK: {:?}", unknown),
                    }
                }
                Packet::SKESK(skesk) => {
                    information!("Found SKESK: {:?}", skesk);
                }
                Packet::SEIP(seip) => {
                    debugging!("Found SEIP: {:?}", seip);
                    match seip {
                        SEIP::V1(seip1) => match seip1.deref().body() {
                            Body::Processed(b) | Body::Unprocessed(b) => information!("Found encrypted data, len: {} byte(s)", b.len()),
                            Body::Structured(b) => information!("Found encrypted data packages, len: {}", b.len()),
                        }
                    }
                }
                Packet::MDC(mdc) => {
                    information!("Found MDC: {:?}", mdc);
                }
                Packet::AED(aed) => {
                    information!("Found AED: {:?}", aed);
                }
                Packet::Unknown(unknown) => {
                    warning!("Found unknown: {:?}", unknown);
                }
                unknown => {
                    warning!("Found UNKNOWN: {:?}", unknown);
                }
            }

            ppr = pp.recurse()?.1;
        }

        if let PacketParserResult::EOF(eof) = ppr {
            debugging!("{:?}", eof);
            if eof.is_message().is_ok() {
                information!("FILE IS MESSAGE");
            } else if eof.is_cert().is_ok() {
                information!("FILE IS CERT");
            } else if eof.is_keyring().is_ok() {
                information!("FILE IS KEYRING");
            } else {
                information!("FILE IS OTHER");
            }
        }
        Ok(None)
    }
}
