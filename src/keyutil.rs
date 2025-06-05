use crate::pivutil::{FromStr, ToStr};
use jwt::AlgorithmType;
use percent_encoding::NON_ALPHANUMERIC;
use regex::Regex;
use rust_util::XResult;
use yubikey::piv::{AlgorithmId, SlotId};

// reference: https://git.hatter.ink/hatter/card-cli/issues/6
#[derive(Debug)]
pub enum KeyUri {
    SecureEnclaveKey(SecureEnclaveKey),
    YubikeyPivKey(YubikeyPivKey),
    YubikeyHmacEncSoftKey(YubikeyHmacEncSoftKey),
    ExternalCommandKey(ExternalCommandKey),
}

impl KeyUri {
    pub fn as_secure_enclave_key(&self) -> XResult<&SecureEnclaveKey> {
        match self {
            KeyUri::SecureEnclaveKey(key) => Ok(key),
            _ => simple_error!("Not a  secure enclave key."),
        }
    }

    pub fn get_preferred_algorithm_type(&self) -> AlgorithmType {
        let algorithm_id = match &self {
            KeyUri::SecureEnclaveKey(_) => return AlgorithmType::Es256,
            KeyUri::YubikeyPivKey(key) => key.algorithm,
            KeyUri::YubikeyHmacEncSoftKey(key) => key.algorithm,
            KeyUri::ExternalCommandKey(key) => key.algorithm,
        };
        match algorithm_id {
            KeyAlgorithmId::Rsa1024
            | KeyAlgorithmId::Rsa2048
            | KeyAlgorithmId::Rsa3072
            | KeyAlgorithmId::Rsa4096 => AlgorithmType::Rs256,
            KeyAlgorithmId::EccP256 => AlgorithmType::Es256,
            KeyAlgorithmId::EccP384 => AlgorithmType::Es384,
            KeyAlgorithmId::EccP521 => AlgorithmType::Es512,
        }
    }
}

impl ToString for KeyUri {
    fn to_string(&self) -> String {
        let mut key_uri = String::with_capacity(64);
        key_uri.push_str("key://");
        match self {
            // key://hatter-mac-pro:se/p256:signing:BASE64(dataRepresentation)
            // key://hatter-mac-pro:se/p256:key_agreement:BASE64(dataRepresentation)
            KeyUri::SecureEnclaveKey(key) => {
                key_uri.push_str(&key.host);
                key_uri.push_str(":se/p256:");
                key_uri.push_str(&key.usage.to_string());
                key_uri.push_str(":");
                key_uri.push_str(&key.private_key);
            }
            // key://yubikey-5n:piv/p256::9a
            KeyUri::YubikeyPivKey(key) => {
                key_uri.push_str(&key.key_name);
                key_uri.push_str(":piv/");
                key_uri.push_str(key.algorithm.to_str());
                key_uri.push_str("::");
                key_uri.push_str(key.slot.to_str());
            }
            // key://-:soft/p256::hmac_enc:...
            KeyUri::YubikeyHmacEncSoftKey(key) => {
                key_uri.push_str(&key.key_name);
                key_uri.push_str(":soft/");
                key_uri.push_str(key.algorithm.to_str());
                key_uri.push_str("::");
                key_uri.push_str(key.hmac_enc_private_key.as_str());
            }
            // key://external-command-file-name:external_command/p256::parameter
            KeyUri::ExternalCommandKey(key) => {
                let encoded_external_command =
                    percent_encoding::utf8_percent_encode(&key.external_command, NON_ALPHANUMERIC)
                        .to_string();
                key_uri.push_str(&encoded_external_command);
                key_uri.push_str(":external_command/");
                key_uri.push_str(key.algorithm.to_str());
                key_uri.push_str("::");
                key_uri.push_str(&key.parameter);
            }
        }
        key_uri
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithmId {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EccP256,
    EccP384,
    EccP521,
}

impl KeyAlgorithmId {
    pub fn from_algorithm_id(algorithm_id: AlgorithmId) -> Self {
        match algorithm_id {
            AlgorithmId::Rsa1024 => Self::Rsa1024,
            AlgorithmId::Rsa2048 => Self::Rsa2048,
            AlgorithmId::EccP256 => Self::EccP256,
            AlgorithmId::EccP384 => Self::EccP384,
        }
    }

    pub fn to_algorithm_id(self) -> Option<AlgorithmId> {
        match self {
            KeyAlgorithmId::Rsa1024 => Some(AlgorithmId::Rsa1024),
            KeyAlgorithmId::Rsa2048 => Some(AlgorithmId::Rsa2048),
            KeyAlgorithmId::Rsa3072 => None,
            KeyAlgorithmId::Rsa4096 => None,
            KeyAlgorithmId::EccP256 => Some(AlgorithmId::EccP256),
            KeyAlgorithmId::EccP384 => Some(AlgorithmId::EccP384),
            KeyAlgorithmId::EccP521 => None,
        }
    }

    pub fn is_rsa(&self) -> bool {
        match self {
            KeyAlgorithmId::Rsa1024
            | KeyAlgorithmId::Rsa2048
            | KeyAlgorithmId::Rsa3072
            | KeyAlgorithmId::Rsa4096 => true,
            KeyAlgorithmId::EccP256 | KeyAlgorithmId::EccP384 | KeyAlgorithmId::EccP521 => false,
        }
    }

    pub fn is_ecc(&self) -> bool {
        match self {
            KeyAlgorithmId::Rsa1024
            | KeyAlgorithmId::Rsa2048
            | KeyAlgorithmId::Rsa3072
            | KeyAlgorithmId::Rsa4096 => false,
            KeyAlgorithmId::EccP256 | KeyAlgorithmId::EccP384 | KeyAlgorithmId::EccP521 => true,
        }
    }

    pub fn to_jwa_name(&self) -> &str {
        match self {
            KeyAlgorithmId::Rsa1024
            | KeyAlgorithmId::Rsa2048
            | KeyAlgorithmId::Rsa3072
            | KeyAlgorithmId::Rsa4096 => "RS256",
            KeyAlgorithmId::EccP256 => "ES256,",
            KeyAlgorithmId::EccP384 => "ES384",
            KeyAlgorithmId::EccP521 => "ES512",
        }
    }
}

impl FromStr for KeyAlgorithmId {
    fn from_str(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        match s {
            "rsa1024" => Some(KeyAlgorithmId::Rsa1024),
            "rsa2048" => Some(KeyAlgorithmId::Rsa2048),
            "rsa3072" => Some(KeyAlgorithmId::Rsa3072),
            "rsa4096" => Some(KeyAlgorithmId::Rsa4096),
            "p256" => Some(KeyAlgorithmId::EccP256),
            "p384" => Some(KeyAlgorithmId::EccP384),
            "p521" => Some(KeyAlgorithmId::EccP521),
            _ => None,
        }
    }
}

impl ToStr for KeyAlgorithmId {
    fn to_str(&self) -> &str {
        match self {
            KeyAlgorithmId::Rsa1024 => "rsa1024",
            KeyAlgorithmId::Rsa2048 => "rsa2048",
            KeyAlgorithmId::Rsa3072 => "rsa3072",
            KeyAlgorithmId::Rsa4096 => "rsa4096",
            KeyAlgorithmId::EccP256 => "p256",
            KeyAlgorithmId::EccP384 => "p384",
            KeyAlgorithmId::EccP521 => "p521",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyUsage {
    Any,
    Singing,
    KeyAgreement,
}

impl KeyUsage {
    pub fn from(usage: &str) -> Option<Self> {
        match usage {
            "signing" => Some(Self::Singing),
            "key_agreement" => Some(Self::KeyAgreement),
            "*" => Some(Self::Any),
            _ => None,
        }
    }
}

impl ToString for KeyUsage {
    fn to_string(&self) -> String {
        match self {
            KeyUsage::Any => "*",
            KeyUsage::Singing => "signing",
            KeyUsage::KeyAgreement => "key_agreement",
        }
        .to_string()
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SecureEnclaveKey {
    pub host: String,
    pub usage: KeyUsage,
    pub private_key: String,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct YubikeyPivKey {
    pub key_name: String,
    pub algorithm: KeyAlgorithmId,
    pub slot: SlotId,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct YubikeyHmacEncSoftKey {
    pub key_name: String,
    pub algorithm: KeyAlgorithmId,
    pub hmac_enc_private_key: String,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ExternalCommandKey {
    pub external_command: String,
    pub algorithm: KeyAlgorithmId,
    pub parameter: String,
}

pub fn parse_key_uri(key_uri: &str) -> XResult<KeyUri> {
    let regex = Regex::new(r##"^key://([0-9a-zA-Z\-\._]*):(\w+)/(\w+):((?:\w+)?):(.*)$"##).unwrap();
    let captures = match regex.captures(key_uri) {
        None => return simple_error!("Invalid key uri: {}", key_uri),
        Some(captures) => captures,
    };
    let host_or_name = captures.get(1).unwrap().as_str();
    let module = captures.get(2).unwrap().as_str();
    let algorithm = captures.get(3).unwrap().as_str();
    let usage = captures.get(4).unwrap().as_str();
    let left_part = captures.get(5).unwrap().as_str();

    match module {
        "se" => {
            if "p256" != algorithm {
                return simple_error!("Key uri's algorithm must be p256.");
            }
            let key_usage = match KeyUsage::from(usage) {
                None | Some(KeyUsage::Any) => {
                    return simple_error!("Key uri's usage must be signing or key_agreement.")
                }
                Some(key_usage) => key_usage,
            };
            let parsed_key_uri = KeyUri::SecureEnclaveKey(SecureEnclaveKey {
                host: host_or_name.to_string(),
                usage: key_usage,
                private_key: left_part.to_string(),
            });
            debugging!("Parsed key uri: {:?}", parsed_key_uri);
            Ok(parsed_key_uri)
        }
        "piv" => {
            if "" != usage {
                return simple_error!("Key uri's usage must be empty.");
            }
            let algorithm = opt_value_result!(
                KeyAlgorithmId::from_str(algorithm),
                "Invalid algorithm id: {}",
                algorithm
            );
            let slot = opt_value_result!(
                SlotId::from_str(left_part),
                "Invalid slot id: {}",
                left_part
            );
            let parsed_key_uri = KeyUri::YubikeyPivKey(YubikeyPivKey {
                key_name: host_or_name.to_string(),
                algorithm,
                slot,
            });
            debugging!("Parsed key uri: {:?}", parsed_key_uri);
            Ok(parsed_key_uri)
        }
        "soft" => {
            if "" != usage {
                return simple_error!("Key uri's usage must be empty.");
            }
            let algorithm = opt_value_result!(
                KeyAlgorithmId::from_str(algorithm),
                "Invalid algorithm id: {}",
                algorithm
            );
            let hmac_enc_private_key = left_part.to_string();
            let parsed_key_uri = KeyUri::YubikeyHmacEncSoftKey(YubikeyHmacEncSoftKey {
                key_name: host_or_name.to_string(),
                algorithm,
                hmac_enc_private_key,
            });
            debugging!("Parsed key uri: {:?}", parsed_key_uri);
            Ok(parsed_key_uri)
        }
        "external_command" => {
            if "" != usage {
                return simple_error!("Key uri's usage must be empty.");
            }
            let external_command = opt_result!(
                percent_encoding::percent_decode_str(host_or_name).decode_utf8(),
                "Decode external command failed: {}"
            );
            let algorithm = opt_value_result!(
                KeyAlgorithmId::from_str(algorithm),
                "Invalid algorithm id: {}",
                algorithm
            );
            let parameter = left_part.to_string();
            let parsed_key_uri = KeyUri::ExternalCommandKey(ExternalCommandKey {
                external_command: external_command.to_string(),
                algorithm,
                parameter,
            });
            debugging!("Parsed key uri: {:?}", parsed_key_uri);
            Ok(parsed_key_uri)
        }
        _ => simple_error!("Key uri's module must be se."),
    }
}

#[test]
fn test_parse_key_uri_01() {
    let se_key_uri =
        parse_key_uri("key://hatter-mac-pro:se/p256:signing:BASE64(dataRepresentation)").unwrap();
    assert_eq!(
        "key://hatter-mac-pro:se/p256:signing:BASE64(dataRepresentation)",
        se_key_uri.to_string()
    );
    match se_key_uri {
        KeyUri::SecureEnclaveKey(se_key_uri) => {
            assert_eq!("hatter-mac-pro", se_key_uri.host);
            assert_eq!(KeyUsage::Singing, se_key_uri.usage);
            assert_eq!("BASE64(dataRepresentation)", se_key_uri.private_key);
        }
        _ => {
            panic!("Key uri not parsed")
        }
    }
}

#[test]
fn test_parse_key_uri_02() {
    let se_key_uri =
        parse_key_uri("key://hatter-mac-m1:se/p256:key_agreement:BASE64(dataRepresentation)")
            .unwrap();
    assert_eq!(
        "key://hatter-mac-m1:se/p256:key_agreement:BASE64(dataRepresentation)",
        se_key_uri.to_string()
    );
    match se_key_uri {
        KeyUri::SecureEnclaveKey(se_key_uri) => {
            assert_eq!("hatter-mac-m1", se_key_uri.host);
            assert_eq!(KeyUsage::KeyAgreement, se_key_uri.usage);
            assert_eq!("BASE64(dataRepresentation)", se_key_uri.private_key);
        }
        _ => {
            panic!("Key uri not parsed")
        }
    }
}

#[test]
fn test_parse_key_uri_03() {
    let se_key_uri = parse_key_uri("key://yubikey-5n:piv/p256::9a").unwrap();
    assert_eq!(
        "key://yubikey-5n:piv/p256::authentication",
        se_key_uri.to_string()
    );
    match se_key_uri {
        KeyUri::YubikeyPivKey(piv_key_uri) => {
            assert_eq!("yubikey-5n", piv_key_uri.key_name);
            assert_eq!(KeyAlgorithmId::EccP256, piv_key_uri.algorithm);
            assert_eq!(SlotId::Authentication, piv_key_uri.slot);
        }
        _ => {
            panic!("Key uri not parsed")
        }
    }
}
