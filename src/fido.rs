use std::fmt;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::SystemTime;

use authenticator::{RegisterResult, StatusUpdate};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use rust_util::XResult;
use serde::{Deserialize, Serialize};

use crate::pkiutil::bytes_to_pem;
use crate::util::base64_encode;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct U2FDeviceInfo {
    pub vendor_name: String,
    pub device_name: String,
    pub version_interface: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub version_build: u8,
    pub cap_flags: u8,
}

impl U2FDeviceInfo {
    fn from(register_result: &authenticator::RegisterResult) -> Self {
        let i = &register_result.1;
        Self {
            vendor_name: String::from_utf8_lossy(&i.vendor_name).to_string(),
            device_name: String::from_utf8_lossy(&i.device_name).to_string(),
            version_interface: i.version_interface,
            version_major: i.version_major,
            version_minor: i.version_minor,
            version_build: i.version_build,
            cap_flags: i.cap_flags,
        }
    }
}

impl fmt::Display for U2FDeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Vendor: {}, Device: {}, Interface: {}, Firmware: v{}.{}.{}, Capabilities: {}",
            self.vendor_name,
            self.device_name,
            &self.version_interface,
            &self.version_major,
            &self.version_minor,
            &self.version_build,
            to_hex(&[self.cap_flags], ":"),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct U2fRegistrationData {
    pub app_id: String,
    pub device_info: U2FDeviceInfo,
    pub device_name: Option<String>,
    pub client_data: String,
    pub registration_data: String,
    pub attestation_cert: Option<Vec<u8>>,
    pub attestation_cert_pem: Option<String>,
    pub pub_key: Vec<u8>,
    pub key_handle: Vec<u8>,
}

impl U2fRegistrationData {
    pub fn from(app_id: &str, client_data: &str, register_result: &RegisterResult) -> XResult<Self> {
        let registration = opt_result!(
            u2f::register::parse_registration(app_id.to_string(), client_data.as_bytes().to_vec(), register_result.0.to_vec()),
            "Parse registration data failed: {}");
        Ok(Self {
            app_id: app_id.to_string(),
            device_info: U2FDeviceInfo::from(register_result),
            device_name: registration.device_name,
            client_data: client_data.into(),
            registration_data: base64_encode(&register_result.0),
            attestation_cert: registration.attestation_cert.clone(),
            attestation_cert_pem: registration.attestation_cert.map(|cert| {
                bytes_to_pem("CERTIFICATE", cert)
            }),
            pub_key: registration.pub_key,
            key_handle: registration.key_handle,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct U2fV2Challenge {
    challenge: String,
    version: String,
    #[serde(rename = "appId")]
    app_id: String,
}

impl U2fV2Challenge {
    pub fn new_challenge(challenge_hex: Option<&str>, app_id: &str, with_time_stamp_prefix: bool) -> XResult<U2fV2Challenge> {
        Ok(match challenge_hex {
            None => U2fV2Challenge::new_random(app_id, with_time_stamp_prefix),
            Some(challenge_hex) => {
                let challenge_bytes = opt_result!(hex::decode(challenge_hex), "Decode challenge hex failed: {}");
                let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);
                U2fV2Challenge::new(challenge, app_id)
            }
        })
    }

    pub fn new_random<S>(app_id: S, with_time_stamp_prefix: bool) -> Self where S: Into<String> {
        let mut rng = rand::thread_rng();
        let mut rand_bytes = [0_u8; 32];
        for c in &mut rand_bytes {
            let b: u8 = rng.gen();
            *c = b;
        }
        if with_time_stamp_prefix {
            let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64;
            let timestamp_be_bytes = timestamp.to_be_bytes();
            rand_bytes[..8].clone_from_slice(&timestamp_be_bytes[..8]);
        }

        let challenge = URL_SAFE_NO_PAD.encode(rand_bytes);
        Self::new(challenge, app_id)
    }

    pub fn new<S1, S2>(challenge: S1, app_id: S2) -> Self where S1: Into<String>, S2: Into<String> {
        Self {
            challenge: challenge.into(),
            version: "U2F_V2".into(),
            app_id: app_id.into(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

pub fn start_status_updater() -> Sender<StatusUpdate> {
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::DeviceAvailable { dev_info }) => {
                debugging!("STATUS: device available: {}", dev_info)
            }
            Ok(StatusUpdate::DeviceUnavailable { dev_info }) => {
                debugging!("STATUS: device unavailable: {}", dev_info)
            }
            Ok(StatusUpdate::Success { dev_info }) => {
                debugging!("STATUS: success using device: {}", dev_info);
            }
            Err(_) => {
                debugging!("STATUS: end");
                return;
            }
        }
    });
    status_tx
}

pub fn to_hex(data: &[u8], joiner: &str) -> String {
    let parts: Vec<String> = data.iter().map(|byte| format!("{:02x}", byte)).collect();
    parts.join(joiner)
}
