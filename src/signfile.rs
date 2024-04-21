use serde::{Deserialize, Serialize};

pub const SIMPLE_SIG_V1: &str = "v1";
pub const SIMPLE_SIG_SCHEMA: &str = "https://openwebstandard.org/simple-sign-file/v1";
pub const HASH_ALGORITHM_SHA256: &str = "sha256";
pub const SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA: &str = "SHA256withECDSA";
pub const CERTIFICATES_SEARCH_URL: &str = "https://hatter.ink/ca/fetch_certificates.json?fingerprint=";

pub struct SignFileRequest {
    pub filename: Option<String>,
    pub digest: Vec<u8>,
    pub timestamp: i64,
    pub attributes: Option<String>,
    pub comment: Option<String>,
}

impl SignFileRequest {
    pub fn get_tobe_signed(&self) -> Vec<u8> {
        let mut tobe_signed = vec![];
        // "v1"||TLV(filename)||TLV(timestamp)||TLV(attributes)||TLV(comment)||TLV(digest)
        debugging!("Tobe signed version: {}", SIMPLE_SIG_V1);
        tobe_signed.extend_from_slice(SIMPLE_SIG_V1.as_bytes());
        let tobe_signed_filename = SignFileTlv::Filename(self.filename.clone()).to_byes();
        debugging!("Tobe signed filename: {} ({:?})", hex::encode(&tobe_signed_filename), &self.filename);
        tobe_signed.extend_from_slice(&tobe_signed_filename);
        let tobe_signed_timestamp = SignFileTlv::Timestamp(self.timestamp).to_byes();
        debugging!("Tobe signed timestamp: {} ({})", hex::encode(&tobe_signed_timestamp), &self.timestamp);
        tobe_signed.extend_from_slice(&tobe_signed_timestamp);
        let tobe_signed_attributes = SignFileTlv::Attributes(self.attributes.clone()).to_byes();
        debugging!("Tobe signed attributes: {} ({:?})", hex::encode(&tobe_signed_attributes), &self.attributes);
        tobe_signed.extend_from_slice(&tobe_signed_attributes);
        let tobe_signed_comment = SignFileTlv::Comment(self.comment.clone()).to_byes();
        debugging!("Tobe signed comment: {} ({:?})", hex::encode(&tobe_signed_comment), &self.comment);
        tobe_signed.extend_from_slice(&tobe_signed_comment);
        let tobe_signed_digest = SignFileTlv::Digest(self.digest.clone()).to_byes();
        debugging!("Tobe signed file digest: {}", hex::encode(&tobe_signed_digest));
        tobe_signed.extend_from_slice(&tobe_signed_digest);
        tobe_signed
    }
}

pub enum SignFileTlv {
    Filename(Option<String>),
    Timestamp(i64),
    Attributes(Option<String>),
    Comment(Option<String>),
    Digest(Vec<u8>),
}

impl SignFileTlv {
    pub fn tag(&self) -> u8 {
        match self {
            SignFileTlv::Filename(_) => 0,
            SignFileTlv::Timestamp(_) => 1,
            SignFileTlv::Attributes(_) => 2,
            SignFileTlv::Comment(_) => 3,
            SignFileTlv::Digest(_) => 254,
        }
    }

    pub fn to_byes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.push(self.tag());
        match self {
            SignFileTlv::Timestamp(timestamp) => {
                bytes.extend_from_slice(&timestamp.to_be_bytes());
            }
            SignFileTlv::Filename(value)
            | SignFileTlv::Attributes(value)
            | SignFileTlv::Comment(value) => {
                Self::write_bytes(&mut bytes, match value {
                    None => &[],
                    Some(value) => value.as_bytes(),
                });
            }
            SignFileTlv::Digest(digest) => {
                Self::write_bytes(&mut bytes, digest);
            }
        }
        bytes
    }

    fn write_bytes(bytes: &mut Vec<u8>, b: &[u8]) {
        if b.len() > u16::MAX as usize {
            panic!("Cannot more than: {}", u16::MAX);
        }
        bytes.extend_from_slice(&(b.len() as u16).to_be_bytes());
        bytes.extend_from_slice(b);
    }
}

#[derive(Serialize, Deserialize)]
pub struct SimpleSignFileSignature {
    pub algorithm: String,
    pub signature: String,
    pub certificates: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SimpleSignFile {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    pub digest: String,
    pub timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub signatures: Vec<SimpleSignFileSignature>,
}
