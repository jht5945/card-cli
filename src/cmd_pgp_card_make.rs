use std::time::SystemTime;

use clap::{App, Arg, ArgMatches, SubCommand};
use openpgp::crypto::mpi::ProtectedMPI;
use openpgp::crypto::mpi::PublicKey as MpiPublicKey;
use openpgp::crypto::Password;
use openpgp::Fingerprint;
use openpgp::KeyID;
use openpgp::Packet;
use openpgp::packet::Key;
use openpgp::packet::key::{SecretKeyMaterial, SecretParts};
use openpgp::packet::key::SubordinateRole;
use openpgp::packet::Signature;
use openpgp::packet::signature::subpacket::{SubpacketTag, SubpacketValue};
use openpgp::parse::{PacketParser, PacketParserResult, Parse};
use openpgp_card::{Error, KeyType, OpenPgp};
use openpgp_card::card_do::KeyGenerationTime;
use openpgp_card::crypto_data::{CardUploadableKey, PrivateKeyMaterial, RSAKey};
use openssl::bn::BigNum;
use rust_util::util_clap::{Command, CommandError};
use rust_util::XResult;
use sequoia_openpgp as openpgp;

use crate::pinutil;
use crate::rsautil::RsaCrt;

#[derive(Debug)]
struct PgpRsaPrivateKeySet {
    signing: Option<PgpRsaPrivateKey>,
    encryption: Option<PgpRsaPrivateKey>,
    authentication: Option<PgpRsaPrivateKey>,
}

impl PgpRsaPrivateKeySet {
    fn new() -> Self {
        PgpRsaPrivateKeySet {
            signing: None,
            encryption: None,
            authentication: None,
        }
    }
}

#[derive(Debug)]
struct PgpRsaPrivateKey {
    creation_time_secs: u32,
    key_id: KeyID,
    fingerprint: Fingerprint,
    rsa_private_key: RsaCrt,
}

#[derive(Debug)]
struct RsaKeyCrt {
    e: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    pq: Vec<u8>,
    dp1: Vec<u8>,
    dq1: Vec<u8>,
    n: Vec<u8>,
}

impl RsaKeyCrt {
    fn from(rsa_crt: &RsaCrt) -> Self {
        Self {
            e: rsa_crt.public_exponent.to_vec(),
            p: rsa_crt.prime1.to_vec(),
            q: rsa_crt.prime2.to_vec(),
            pq: rsa_crt.coefficient.to_vec(),
            dp1: rsa_crt.exponent1.to_vec(),
            dq1: rsa_crt.exponent2.to_vec(),
            n: rsa_crt.modulus.to_vec(),
        }
    }
}

impl RSAKey for RsaKeyCrt {
    fn e(&self) -> &[u8] {
        self.e.as_slice()
    }

    fn p(&self) -> &[u8] {
        self.p.as_slice()
    }

    fn q(&self) -> &[u8] {
        self.q.as_slice()
    }

    fn pq(&self) -> Box<[u8]> {
        self.pq.clone().into()
    }

    fn dp1(&self) -> Box<[u8]> {
        self.dp1.clone().into()
    }

    fn dq1(&self) -> Box<[u8]> {
        self.dq1.clone().into()
    }

    fn n(&self) -> &[u8] {
        self.n.as_slice()
    }
}

impl CardUploadableKey for PgpRsaPrivateKey {
    fn private_key(&self) -> Result<PrivateKeyMaterial, Error> {
        Ok(PrivateKeyMaterial::R(Box::new(RsaKeyCrt::from(&self.rsa_private_key))))
    }

    fn timestamp(&self) -> KeyGenerationTime {
        KeyGenerationTime::from(self.creation_time_secs)
    }

    fn fingerprint(&self) -> Result<openpgp_card::card_do::Fingerprint, Error> {
        if let Fingerprint::V4(fingerprint_v4) = self.fingerprint {
            Ok(openpgp_card::card_do::Fingerprint::from(fingerprint_v4))
        } else {
            Err(Error::InternalError("Not supported fingerprint version".to_string()))
        }
    }
}

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "pgp-card-make" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("OpenPGP Card make subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).help("OpenPGP card admin pin"))
            .arg(Arg::with_name("pass").long("pass").takes_value(true).required(false).help("Password for PGP secret key"))
            .arg(Arg::with_name("in").long("in").takes_value(true).required(false).help("PGP file in"))
            .arg(Arg::with_name("force-make").long("force-make").help("Force make OpenPGP card"))
            .arg(Arg::with_name("print-public-keys").long("print-public-keys").help("Print public keys"))
            .arg(Arg::with_name("print-private-keys").long("print-private-keys").help("Print private keys"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let pin_opt = sub_arg_matches.value_of("pin");
        let pin_opt = pinutil::get_pin(pin_opt);
        let pin_opt = pin_opt.as_deref();
        let pin = opt_value_result!(pin_opt, "Pin must be assigned");
        if pin.len() < 8 { return simple_error!("Admin pin length:{}, must >= 8!", pin.len()); }

        let pass = opt_value_result!(sub_arg_matches.value_of("pass"), "Pass must assigned!");
        let password = Password::from(pass);
        let pgp_in_file = opt_value_result!(sub_arg_matches.value_of("in"), "PGP in file must assigned!");

        let mut pgp_rsa_private_key_set = PgpRsaPrivateKeySet::new();
        let mut ppr = PacketParser::from_file(pgp_in_file)?;
        let mut last_pgp_rsa_private_key = None;
        while let PacketParserResult::Some(pp) = ppr {
            if let Packet::SecretKey(key) = &pp.packet {
                let key = key.role_as_subordinate();
                let pgp_rsa_private_key = parse_security_sub_key_to_pgp_rsa_private_key(key, &password)?;
                if last_pgp_rsa_private_key.is_some() { return simple_error!("Last PGP RSA private key is not none"); }
                last_pgp_rsa_private_key.replace(pgp_rsa_private_key);
            } else if let Packet::SecretSubkey(key) = &pp.packet {
                let pgp_rsa_private_key = parse_security_sub_key_to_pgp_rsa_private_key(key, &password)?;
                if last_pgp_rsa_private_key.is_some() { return simple_error!("Last PGP RSA private key is not none"); }
                last_pgp_rsa_private_key.replace(pgp_rsa_private_key);
            } else if let Packet::Signature(signature) = &pp.packet {
                if let Signature::V3(_signature_v3) = signature {
                    failure!("Signature v3 is not supported.");
                }
                if let Signature::V4(signature_v4) = signature {
                    if let Some(sub_package) = signature_v4.hashed_area().subpacket(SubpacketTag::KeyFlags) {
                        if let SubpacketValue::KeyFlags(key_flags) = sub_package.value() {
                            if last_pgp_rsa_private_key.is_none() {
                                return simple_error!("Last PGP RSA private key is none, for signature flag: {:?}", key_flags);
                            }
                            if key_flags.for_certification() || key_flags.for_signing() {
                                pgp_rsa_private_key_set.signing = last_pgp_rsa_private_key.take();
                            } else if key_flags.for_transport_encryption() || key_flags.for_storage_encryption() {
                                pgp_rsa_private_key_set.encryption = last_pgp_rsa_private_key.take();
                            } else if key_flags.for_authentication() {
                                pgp_rsa_private_key_set.authentication = last_pgp_rsa_private_key.take();
                            } else {
                                return simple_error!("Unknown signature flags: {:?}", key_flags);
                            }
                        }
                    }
                }
            }
            // Start parsing the next packet, recursing.
            ppr = pp.recurse()?.1;
        }

        debugging!("Found PGP RSA private key set: {:?}", pgp_rsa_private_key_set);

        if pgp_rsa_private_key_set.signing.is_none()
            || pgp_rsa_private_key_set.encryption.is_none()
            || pgp_rsa_private_key_set.authentication.is_none() {
            warning!("PGP RSA private keys is not complete!");
        }
        success!("Found PGP RSA private keys, signing: {}, encryption: {}, authentication: {}",
                pgp_rsa_private_key_set.signing.is_some(),
                pgp_rsa_private_key_set.encryption.is_some(),
                pgp_rsa_private_key_set.authentication.is_some());

        let print_private_keys = sub_arg_matches.is_present("print-private-keys");
        let print_public_keys = sub_arg_matches.is_present("print-public-keys");
        if let Some(signing_key) = &pgp_rsa_private_key_set.signing {
            if print_private_keys {
                let signing_key_pem = opt_result!(signing_key.rsa_private_key.to_pem(), "Signing private key to pem failed: {}");
                information!("Signing key: {}", signing_key_pem);
            }
            if print_public_keys {
                let signing_public_key_pem = opt_result!(signing_key.rsa_private_key.to_public_key_pem(), "Signing public key to pem failed: {}");
                information!("Signing public key: {}", signing_public_key_pem);
            }
        }
        if let Some(encryption_key) = &pgp_rsa_private_key_set.encryption {
            if print_private_keys {
                let encryption_key_pem = opt_result!(encryption_key.rsa_private_key.to_pem(), "Encryption private key to pem failed: {}");
                information!("Encryption key: {}", encryption_key_pem);
            }
            if print_public_keys {
                let encryption_public_key_pem = opt_result!(encryption_key.rsa_private_key.to_public_key_pem(), "Encryption public key to pem failed: {}");
                information!("Encryption public key: {}", encryption_public_key_pem);
            }
        }
        if let Some(authentication_key) = &pgp_rsa_private_key_set.authentication {
            if print_private_keys {
                let authentication_key_pem = opt_result!(authentication_key.rsa_private_key.to_pem(), "Authentication private key to pem failed: {}");
                information!("Authentication key: {}", authentication_key_pem);
            }
            if print_public_keys {
                let authentication_public_key_pem = opt_result!(authentication_key.rsa_private_key.to_public_key_pem(), "Authentication public key to pem failed: {}");
                information!("Authentication public key: {}", authentication_public_key_pem);
            }
        }

        let force_make = sub_arg_matches.is_present("force-make");
        if !force_make {
            warning!("Force make is OFF, add argument --force-make to open, skip write private keys to card!");
            return Ok(None);
        }

        warning!("Force make is ON, try to write private keys to card!");
        let card = crate::pgpcardutil::get_card()?;
        let mut pgp = OpenPgp::new(card);
        let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");

        opt_result!(trans.verify_pw3(pin.as_ref()), "Admin pin verify failed: {}");
        success!("Admin pin verify success!");

        if let Some(signing_key) = pgp_rsa_private_key_set.signing {
            let signing_key_id = signing_key.key_id.clone();
            information!("Prepare write PGP signing key, key id: {}", signing_key_id);
            opt_result!(trans.key_import(Box::new(signing_key), KeyType::Signing), "Write PGP signing key failed: {}");
            success!("Write PGP signing key success, key id: {}", signing_key_id);
        }

        if let Some(encryption_key) = pgp_rsa_private_key_set.encryption {
            let encryption_key_id = encryption_key.key_id.clone();
            information!("Prepare write PGP encryption key, key id: {}", encryption_key_id);
            opt_result!(trans.key_import(Box::new(encryption_key), KeyType::Decryption), "Write PGP encryption key failed: {}");
            success!("Write PGP encryption key success, key id: {}", encryption_key_id);
        }

        if let Some(authentication_key) = pgp_rsa_private_key_set.authentication {
            let authentication_key_id = authentication_key.key_id.clone();
            information!("Prepare write PGP authentication key, key id: {}", authentication_key_id);
            opt_result!(trans.key_import(Box::new(authentication_key), KeyType::Authentication), "Write PGP authentication key failed: {}");
            success!("Write PGP authentication key success, key id: {}", authentication_key_id);
        }

        Ok(None)
    }
}

fn parse_security_sub_key_to_pgp_rsa_private_key(key: &Key<SecretParts, SubordinateRole>, password: &Password) -> XResult<PgpRsaPrivateKey> {
    information!("Public key, key id: {}, fingerprint: {}", key.keyid(), key.fingerprint());
    let e = if let MpiPublicKey::RSA { e, n: _ } = key.mpis() {
        e.clone()
    } else {
        return simple_error!("Not RSA public key");
    };
    // default PGP implementation SHOULD encrypt private keys
    // TODO information!("{:?}", key.secret());
    let private_key = if key.has_unencrypted_secret() {
        key.clone()
    } else {
        opt_result!(key.clone().decrypt_secret(password), "Decrypt private key failed: {}")
    };
    let (p, q) = if let Key::V4(private_key4) = private_key {
        if let SecretKeyMaterial::Unencrypted(unencrypted) = private_key4.secret() {
            unencrypted.map(|f| {
                let p_and_q_result: XResult<(ProtectedMPI, ProtectedMPI)> = if let openpgp::crypto::mpi::SecretKeyMaterial::RSA { d: _, p, q, u: _ } = f {
                    Ok((p.clone(), q.clone()))
                } else {
                    simple_error!("Not RSA private key")
                };
                p_and_q_result
            })?
        } else {
            return simple_error!("Not unencrypted private key");
        }
    } else {
        return simple_error!("Not Key::V4 private key");
    };
    let p = BigNum::from_slice(p.value()).unwrap();
    let q = BigNum::from_slice(q.value()).unwrap();
    let e = BigNum::from_slice(e.value()).unwrap();
    let rsa_crt = opt_result!(RsaCrt::from(p, q, e), "Parse RSA crt failed: {}");
    let creation_time_secs = key.creation_time().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as u32;
    Ok(PgpRsaPrivateKey {
        creation_time_secs,
        key_id: key.keyid(),
        fingerprint: key.fingerprint(),
        rsa_private_key: rsa_crt,
    })
}
