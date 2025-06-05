use rust_util::{util_file, XResult};
use security_framework::os::macos::keychain::{CreateOptions, SecKeychain};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const KEYCHAIN_KEY_PREFIX: &str = "keychain:";
const DEFAULT_SERVICE_NAME: &str = "card-cli";

pub struct KeychainKey {
    pub keychain_name: String,
    pub service_name: String,
    pub key_name: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct KeychainKeyValue {
    pub keychain_name: String,
    pub pkcs8_base64: String,
    pub secret_key_pem: String,
    pub public_key_pem: String,
    pub public_key_jwk: String,
}

pub fn is_keychain_key_uri(name: &str) -> bool {
    name.starts_with(KEYCHAIN_KEY_PREFIX)
}

impl KeychainKey {
    pub fn from_key_name_default(key_name: &str) -> Self {
        Self::from("", DEFAULT_SERVICE_NAME, key_name)
    }

    pub fn from(keychain_name: &str, service_name: &str, key_name: &str) -> Self {
        debugging!(
            "Keychain key: {} - {} - {}",
            keychain_name,
            service_name,
            key_name
        );
        Self {
            keychain_name: keychain_name.to_string(),
            service_name: service_name.to_string(),
            key_name: key_name.to_string(),
        }
    }

    pub fn parse_key_uri(keychain_key: &str) -> XResult<Self> {
        if !keychain_key.starts_with(KEYCHAIN_KEY_PREFIX) {
            return simple_error!("Not a valid keychain key: {}", keychain_key);
        }
        //keychain:keychain_name:service_name:key_name
        let keychain_key_parts = keychain_key.split(':').collect::<Vec<_>>();
        if keychain_key_parts.len() != 4 {
            return simple_error!("Not a valid keychain key: {}", keychain_key);
        }
        Ok(Self {
            keychain_name: keychain_key_parts[1].to_string(),
            service_name: keychain_key_parts[2].to_string(),
            key_name: keychain_key_parts[3].to_string(),
        })
    }

    pub fn to_key_uri(&self) -> String {
        let mut s = String::new();
        s.push_str(KEYCHAIN_KEY_PREFIX);
        s.push_str(&self.keychain_name);
        s.push(':');
        s.push_str(&self.service_name);
        s.push(':');
        s.push_str(&self.key_name);
        s
    }

    pub fn get_password(&self) -> XResult<Option<Vec<u8>>> {
        let sec_keychain = self.get_keychain()?;
        debugging!(
            "Try find generic password: {}.{}",
            &self.service_name,
            &self.key_name
        );
        match sec_keychain.find_generic_password(&self.service_name, &self.key_name) {
            Ok((item_password, _keychain_item)) => Ok(Some(item_password.as_ref().to_vec())),
            Err(e) => {
                debugging!("Get password: {} failed: {}", &self.to_key_uri(), e);
                Ok(None)
            }
        }
    }

    pub fn set_password(&self, password: &[u8]) -> XResult<()> {
        let sec_keychain = self.get_keychain()?;
        if sec_keychain
            .find_generic_password(&self.service_name, &self.key_name)
            .is_ok()
        {
            return simple_error!("Password {}.{} exists", &self.service_name, &self.key_name);
        }
        opt_result!(
            sec_keychain.set_generic_password(&self.service_name, &self.key_name, password),
            "Set password {}.{} error: {}",
            &self.service_name,
            &self.key_name
        );
        Ok(())
    }

    fn get_keychain(&self) -> XResult<SecKeychain> {
        if !self.keychain_name.is_empty() {
            let keychain_file_name = format!("{}.keychain", &self.keychain_name);
            debugging!("Open or create keychain: {}", &keychain_file_name);
            let keychain_exists = check_keychain_exists(&keychain_file_name);
            if keychain_exists {
                Ok(opt_result!(
                    SecKeychain::open(&keychain_file_name),
                    "Open keychain: {}, failed: {}",
                    &keychain_file_name
                ))
            } else {
                match CreateOptions::new()
                    .prompt_user(true)
                    .create(&keychain_file_name)
                {
                    Ok(sec_keychain) => Ok(sec_keychain),
                    Err(ce) => match SecKeychain::open(&keychain_file_name) {
                        Ok(sec_keychain) => Ok(sec_keychain),
                        Err(oe) => simple_error!(
                            "Create keychain: {}, failed: {}, open also failed: {}",
                            &self.keychain_name,
                            ce,
                            oe
                        ),
                    },
                }
            }
        } else {
            Ok(opt_result!(
                SecKeychain::default(),
                "Get keychain failed: {}"
            ))
        }
    }
}

fn check_keychain_exists(keychain_file_name: &str) -> bool {
    let keychain_path = PathBuf::from(util_file::resolve_file_path("~/Library/Keychains/"));
    match keychain_path.read_dir() {
        Ok(read_dir) => {
            for dir in read_dir {
                match dir {
                    Ok(dir) => {
                        if let Some(file_name) = dir.file_name().to_str() {
                            if file_name.starts_with(keychain_file_name) {
                                debugging!("Found key chain file: {:?}", dir);
                                return true;
                            }
                        }
                    }
                    Err(e) => {
                        debugging!("Read path sub dir: {:?} failed: {}", keychain_path, e);
                    }
                }
            }
        }
        Err(e) => {
            debugging!("Read path: {:?} failed: {}", keychain_path, e);
        }
    }
    false
}
