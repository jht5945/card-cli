use std::fs::remove_file;
use std::path::PathBuf;

use crate::ecdsautil::{
    generate_ecdsa_keypair, parse_ec_public_key_to_point, parse_ecdsa_r_and_s, EcdsaAlgorithm,
};
use crate::util::base64_encode;
use clap::{App, Arg, ArgMatches, SubCommand};
use rsa::RsaPublicKey;
use rust_util::util_clap::{Command, CommandError};
use rust_util::XResult;
use spki::DecodePublicKey;
use ssh_agent_lib::agent::{listen, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Extension, Identity, SignRequest};
use ssh_agent_lib::ssh_encoding::Encode;
use ssh_agent_lib::ssh_key::public::KeyData;
use ssh_agent_lib::ssh_key::{Algorithm, Signature};
use ssh_key::public::EcdsaPublicKey;
use ssh_key::{EcdsaCurve, Mpint};
use std::convert::TryFrom;
use tokio::net::UnixListener as Listener;

#[derive(Default, Clone)]
struct MySshAgent {
    private_key_pem: String,
    comment: String,
}

impl MySshAgent {
    fn new() -> XResult<Self> {
        let (_, private_key_pem, _, _, _) = generate_ecdsa_keypair(EcdsaAlgorithm::P256)?;
        Ok(MySshAgent {
            private_key_pem,
            comment: "test".to_string(),
        })
    }
}

#[ssh_agent_lib::async_trait]
impl Session for MySshAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        information!("request_identities");
        // let p256_private_key_d = ecdsautil::parse_p256_private_key(&self.private_key_pem).unwrap();
        let public_key_point = hex::decode(
            "04\
f17326c188b9d0cffeddd8ff935f24f2074bbef128ac5b04b9cac05de967df5dbfd065698dce3b8c1f451bb9a1593ace\
13360bbc49c51f5213777fd873932efa44763bfcc1c764b122a8a8977bcb3e0ad099d652e63db1c5a1bda02120a16dc5",
        )
        .unwrap();
        let identity = Identity {
            pubkey: KeyData::Ecdsa(EcdsaPublicKey::from_sec1_bytes(&public_key_point).unwrap()),
            comment: "test".to_string(),
        };
        let mut writer = vec![];
        identity.pubkey.encode(&mut writer).unwrap();
        println!("{}", base64_encode(&writer));
        Ok(vec![identity])
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        information!("sign, request: {:?}", request);

        let algorithm = &request.pubkey.algorithm();
        match algorithm {
            Algorithm::Ecdsa { curve: _ } => {}
            Algorithm::Rsa { hash: _ } => {}
            Algorithm::Ed25519 => {
                debugging!("Algorithm::Ed25519 not supported");
                return Err(AgentError::Failure);
            }
            Algorithm::Dsa => {
                debugging!("Algorithm::Dsa not supported");
                return Err(AgentError::Failure);
            }
            Algorithm::SkEcdsaSha2NistP256 => {
                debugging!("Algorithm::SkEcdsaSha2NistP256 not supported");
                return Err(AgentError::Failure);
            }
            Algorithm::SkEd25519 => {
                debugging!("Algorithm::SkEd25519 not supported");
                return Err(AgentError::Failure);
            }
            Algorithm::Other(algorithm_name) => {
                debugging!(
                    "Algorithm::Other not supported, name: {}",
                    algorithm_name.as_str()
                );
                return Err(AgentError::Failure);
            }
            &_ => {
                debugging!("Algorithm::Unknown not supported");
                return Err(AgentError::Failure);
            }
        }

        let signature = external_command_rs::external_sign(
            "card-cli",
            "key://yubikey4-5010220:piv/p384::authentication",
            "ES384",
            &request.data,
        )
        .unwrap();
        information!("{}", hex::encode(&signature));
        let (r, s) = parse_ecdsa_r_and_s(signature.as_slice()).unwrap();
        let mut ssh_signature = vec![];
        let r_mpint = Mpint::from_bytes(&r).unwrap();
        let s_mpint = Mpint::from_bytes(&s).unwrap();
        r_mpint.encode(&mut ssh_signature).unwrap();
        s_mpint.encode(&mut ssh_signature).unwrap();
        Ok(Signature::new(
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            ssh_signature,
        )
        .map_err(AgentError::other)?)
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        information!("extension: {:?}", extension);
        Ok(None)
    }
}

fn get_identity(uri: &str) -> XResult<Identity> {
    let public_key_bytes = external_command_rs::external_public_key("card-cli", uri)?;

    let ec_point = parse_ec_public_key_to_point(&public_key_bytes).unwrap(); // TODO ...
    let identity = Identity {
        pubkey: KeyData::Ecdsa(EcdsaPublicKey::from_sec1_bytes(&ec_point).unwrap()),
        comment: "test".to_string(),
    };

    let rsa_public_key = RsaPublicKey::from_public_key_der(&public_key_bytes).unwrap();
    let identity = Identity {
        pubkey: KeyData::Rsa(ssh_key::public::RsaPublicKey::try_from(&rsa_public_key).unwrap()),
        comment: "test".to_string(),
    };

    simple_error!("Unknown uri algorithm: {}", uri)
}

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "ssh-agent"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("SSH-Agent subcommand")
            .arg(
                Arg::with_name("sock-file")
                    .long("sock-file")
                    .default_value("connect.ssh")
                    .help("Sock file, usage SSH_AUTH_SOCK=sock-file ssh ..."),
            )
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        warning!("Not works yet.");

        debugging!("Sub args: {:?}", sub_arg_matches);

        let sock_file = sub_arg_matches.value_of("sock-file").unwrap();
        information!("Sock file: {}", sock_file);

        let sock_file_path = PathBuf::from(".");
        match std::fs::canonicalize(sock_file_path) {
            Ok(canonicalized_sock_file_path) => information!(
                "SSH_AUTH_SOCK={}/{}",
                canonicalized_sock_file_path.to_str().unwrap_or("-"),
                sock_file
            ),
            Err(e) => warning!("Get canonicalized sock file path failed: {}", e),
        }

        // let ssh_agent = SshAgent::new()?;
        // // TODO information!("{}", &ssh_agent.ssh_string);

        let _ = remove_file(sock_file);

        information!("Start unix socket: {}", sock_file);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            listen(
                Listener::bind(sock_file).unwrap(),
                MySshAgent::new().unwrap(),
            )
            .await
            .unwrap();
        });

        // opt_result!(
        //     ssh_agent.run_unix(sock_file),
        //     "Run unix socket: {}, failed: {}",
        //     sock_file
        // );

        Ok(None)
    }
}
