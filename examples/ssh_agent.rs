use std::error::Error;
use std::fs::remove_file;
use std::sync::RwLock;

use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use rust_util::{debugging, information};
use ssh_agent::agent::Agent;
use ssh_agent::proto::{from_bytes, RsaPublicKey, to_bytes};
use ssh_agent::proto::message::{self, Message, SignRequest};
use ssh_agent::proto::private_key::{PrivateKey, RsaPrivateKey};
use ssh_agent::proto::public_key::PublicKey;
use ssh_agent::proto::signature::{self, Signature};

#[derive(Clone, PartialEq, Debug)]
struct Identity {
    pubkey: PublicKey,
    privkey: PrivateKey,
    comment: String,
}

struct KeyStorage {
    identities: RwLock<Vec<Identity>>,
}

impl KeyStorage {
    fn new() -> Self {
        let rsa = Rsa::generate(2048).unwrap();
        let pubkey = PublicKey::Rsa(RsaPublicKey {
            e: with_sign(rsa.e().to_vec()),
            n: with_sign(rsa.n().to_vec()),
        });
        let privkey = PrivateKey::Rsa(RsaPrivateKey {
            e: with_sign(rsa.e().to_vec()),
            n: with_sign(rsa.n().to_vec()),
            d: with_sign(rsa.d().to_vec()),
            iqmp: with_sign(rsa.iqmp().unwrap().to_vec()),
            p: with_sign(rsa.p().unwrap().to_vec()),
            q: with_sign(rsa.q().unwrap().to_vec()),
        });
        let ident = Identity {
            pubkey,
            privkey,
            comment: "testkey".to_string(),
        };

        let mut ssh_key = vec![];
        let ssh_rsa_bytes = "ssh-rsa".as_bytes();
        ssh_key.extend_from_slice(&(ssh_rsa_bytes.len() as u32).to_be_bytes()[..]);
        ssh_key.extend_from_slice(ssh_rsa_bytes);
        let e = with_sign(rsa.e().to_vec());
        ssh_key.extend_from_slice(&(e.len() as u32).to_be_bytes()[..]);
        ssh_key.extend_from_slice(&e);
        let n = with_sign(rsa.n().to_vec());
        ssh_key.extend_from_slice(&(n.len() as u32).to_be_bytes()[..]);
        ssh_key.extend_from_slice(&n);
        debugging!("{:?}", ssh_key);
        information!("ssh-rsa {} {}", base64::encode(&ssh_key), ident.comment);
        Self {
            identities: RwLock::new(vec![ident])
        }
    }

    fn identity_index_from_pubkey(
        identities: &Vec<Identity>,
        pubkey: &PublicKey,
    ) -> Option<usize> {
        for (index, identity) in identities.iter().enumerate() {
            if &identity.pubkey == pubkey {
                return Some(index);
            }
        }
        return None;
    }

    fn identity_from_pubkey(&self, pubkey: &PublicKey) -> Option<Identity> {
        let identities = self.identities.read().unwrap();

        let index = Self::identity_index_from_pubkey(&identities, pubkey)?;
        Some(identities[index].clone())
    }

    fn identity_add(&self, identity: Identity) {
        let mut identities = self.identities.write().unwrap();
        if Self::identity_index_from_pubkey(&identities, &identity.pubkey) == None {
            identities.push(identity);
        }
    }

    fn identity_remove(&self, pubkey: &PublicKey) -> Result<(), Box<dyn Error>> {
        let mut identities = self.identities.write().unwrap();

        if let Some(index) = Self::identity_index_from_pubkey(&identities, &pubkey) {
            identities.remove(index);
            Ok(())
        } else {
            Err(From::from("Failed to remove identity: identity not found"))
        }
    }

    fn sign(&self, sign_request: &SignRequest) -> Result<Signature, Box<dyn Error>> {
        let pubkey: PublicKey = from_bytes(&sign_request.pubkey_blob)?;

        if let Some(identity) = self.identity_from_pubkey(&pubkey) {
            match identity.privkey {
                PrivateKey::Rsa(ref key) => {
                    let algorithm;
                    let digest;

                    if sign_request.flags & signature::RSA_SHA2_512 != 0 {
                        algorithm = "rsa-sha2-512";
                        digest = MessageDigest::sha512();
                    } else if sign_request.flags & signature::RSA_SHA2_256 != 0 {
                        algorithm = "rsa-sha2-256";
                        digest = MessageDigest::sha256();
                    } else {
                        algorithm = "ssh-rsa";
                        digest = MessageDigest::sha1();
                    }

                    let keypair = PKey::from_rsa(rsa_openssl_from_ssh(key)?)?;
                    let mut signer = Signer::new(digest, &keypair)?;
                    signer.update(&sign_request.data)?;

                    Ok(Signature {
                        algorithm: algorithm.to_string(),
                        blob: signer.sign_to_vec()?,
                    })
                }
                _ => Err(From::from("Signature for key type not implemented"))
            }
        } else {
            Err(From::from("Failed to create signature: identity not found"))
        }
    }

    fn handle_message(&self, request: Message) -> Result<Message, Box<dyn Error>> {
        information!("Request: {:?}", request);
        let response = match request {
            Message::RequestIdentities => {
                let mut identities = vec![];
                for identity in self.identities.read().unwrap().iter() {
                    identities.push(message::Identity {
                        pubkey_blob: to_bytes(&identity.pubkey)?,
                        comment: identity.comment.clone(),
                    })
                }
                identities.iter().for_each(|i| {
                    information!("ssh-rsa {} {}", base64::encode(&i.pubkey_blob), &i.comment);
                    // information!(">> {}", String::from_utf8_lossy(&i.pubkey_blob));
                });

                Ok(Message::IdentitiesAnswer(identities))
            }
            Message::RemoveIdentity(identity) => {
                let pubkey: PublicKey = from_bytes(&identity.pubkey_blob)?;
                self.identity_remove(&pubkey)?;
                Ok(Message::Success)
            }
            Message::AddIdentity(identity) => {
                self.identity_add(Identity {
                    pubkey: PublicKey::from(&identity.privkey),
                    privkey: identity.privkey,
                    comment: identity.comment,
                });
                Ok(Message::Success)
            }
            Message::SignRequest(request) => {
                let signature = to_bytes(&self.sign(&request)?)?;
                Ok(Message::SignResponse(signature))
            }
            _ => Err(From::from(format!("Unknown message: {:?}", request)))
        };
        information!("Response {:?}", response);
        return response;
    }
}

impl Agent for KeyStorage {
    type Error = ();

    fn handle(&self, message: Message) -> Result<Message, ()> {
        self.handle_message(message).or_else(|error| {
            println!("Error handling message - {:?}", error);
            Ok(Message::Failure)
        })
    }
}


fn rsa_openssl_from_ssh(ssh_rsa: &RsaPrivateKey) -> Result<Rsa<Private>, Box<dyn Error>> {
    let n = BigNum::from_slice(&ssh_rsa.n)?;
    let e = BigNum::from_slice(&ssh_rsa.e)?;
    let d = BigNum::from_slice(&ssh_rsa.d)?;
    let qi = BigNum::from_slice(&ssh_rsa.iqmp)?;
    let p = BigNum::from_slice(&ssh_rsa.p)?;
    let q = BigNum::from_slice(&ssh_rsa.q)?;
    let dp = &d % &(&p - &BigNum::from_u32(1)?);
    let dq = &d % &(&q - &BigNum::from_u32(1)?);

    Ok(Rsa::from_private_components(n, e, d, p, q, dp, dq, qi)?)
}

// SSH_AUTH_SOCK=connect.sock ssh root@example.com
// SSH_AUTH_SOCK=connect.sock ssh-add -l
fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let agent = KeyStorage::new();
    let socket = "connect.sock";
    let _ = remove_file(socket);

    information!("Start unix socket: {}", socket);
    agent.run_unix(socket)?;
    Ok(())
}

pub fn with_sign(mut vec: Vec<u8>) -> Vec<u8> {
    if vec.len() > 0 && vec[0] >= 128 {
        vec.insert(0, 0x00);
    }
    vec
}