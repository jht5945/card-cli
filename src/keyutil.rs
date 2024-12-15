use regex::Regex;
use rust_util::XResult;

// reference: https://git.hatter.ink/hatter/card-cli/issues/6
#[derive(Debug)]
pub enum KeyUri {
    SecureEnclaveKey(SecureEnclaveKey),
}

// #[derive(Debug, PartialEq, Eq)]
// pub enum KeyModule {
//     SecureEnclave,
//     OpenPgpCard,
//     PersonalIdentityVerification,
// }
//
// impl KeyModule {
//     pub fn from(module: &str) -> Option<Self> {
//         match module {
//             "se" => Some(Self::SecureEnclave),
//             "pgp" => Some(Self::OpenPgpCard),
//             "piv" => Some(Self::PersonalIdentityVerification),
//             _ => None,
//         }
//     }
// }

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

#[allow(dead_code)]
#[derive(Debug)]
pub struct SecureEnclaveKey {
    pub host: String,
    pub usage: KeyUsage,
    pub private_key: String,
}

pub fn parse_key_uri(key_uri: &str) -> XResult<KeyUri> {
    let regex = Regex::new(r##"^key://([a-zA-Z\-\._]*):(\w+)/(\w+):(\w+)?:(.*)$"##).unwrap();
    let captures = match regex.captures(key_uri) {
        None => return simple_error!("Invalid key uri: {}", key_uri),
        Some(captures) => captures,
    };
    let host = captures.get(1).unwrap().as_str();
    let module = captures.get(2).unwrap().as_str();
    let algorithm = captures.get(3).unwrap().as_str();
    let usage = captures.get(4).unwrap().as_str();
    let left_part = captures.get(5).unwrap().as_str();

    if "se" != module {
        return simple_error!("Key uri's module must be se.");
    }
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
        host: host.to_string(),
        usage: key_usage,
        private_key: left_part.to_string(),
    });

    debugging!("Parsed key uri: {:?}", parsed_key_uri);
    Ok(parsed_key_uri)
}

#[test]
fn test_parse_key_uri_01() {
    let se_key_uri =
        parse_key_uri("key://hatter-mac-pro:se/p256:signing:BASE64(dataRepresentation)").unwrap();
    match se_key_uri {
        KeyUri::SecureEnclaveKey(se_key_uri) => {
            assert_eq!("hatter-mac-pro", se_key_uri.host);
            assert_eq!(KeyUsage::Singing, se_key_uri.usage);
            assert_eq!("BASE64(dataRepresentation)", se_key_uri.private_key);
        }
    }
}

#[test]
fn test_parse_key_uri_02() {
    let se_key_uri =
        parse_key_uri("key://hatter-mac-pro:se/p256:key_agreement:BASE64(dataRepresentation)")
            .unwrap();
    match se_key_uri {
        KeyUri::SecureEnclaveKey(se_key_uri) => {
            assert_eq!("hatter-mac-pro", se_key_uri.host);
            assert_eq!(KeyUsage::KeyAgreement, se_key_uri.usage);
            assert_eq!("BASE64(dataRepresentation)", se_key_uri.private_key);
        }
    }
}
