use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

pub enum DigestAlgorithm {
    Sha256,
    #[allow(dead_code)]
    Sha384,
}

impl DigestAlgorithm {
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            DigestAlgorithm::Sha256 => sha256_bytes(data),
            DigestAlgorithm::Sha384 => sha384_bytes(data),
        }
    }

    pub fn digest_str(&self, s: &str) -> Vec<u8> {
        self.digest(s.as_bytes())
    }
}

pub fn sha256(input: &str) -> Vec<u8> {
    sha256_bytes(input.as_bytes())
}

pub fn sha1_bytes(input: &[u8]) -> Vec<u8> {
    let mut digest = Sha1::default();
    digest.update(input);
    digest.finalize().to_vec()
}

pub fn sha256_bytes(input: &[u8]) -> Vec<u8> {
    digest_bytes::<Sha256>(input)
}

pub fn sha384_bytes(input: &[u8]) -> Vec<u8> {
    digest_bytes::<Sha384>(input)
}

pub fn sha512_bytes(input: &[u8]) -> Vec<u8> {
    digest_bytes::<Sha512>(input)
}

pub fn digest_bytes<D>(input: &[u8]) -> Vec<u8> where D: Digest + Default {
    let mut digest: D = Default::default();
    Digest::update(&mut digest, input);
    digest.finalize().to_vec()
}

macro_rules! define_copy_array {
    ($fn_name: ident, $len: tt) => (
        pub fn $fn_name(in_arr: &[u8]) -> rust_util::XResult<[u8; $len]> {
            if in_arr.len() != $len {
                return simple_error!("Array length is not: {}, but is: {}", $len, in_arr.len());
            }
            let mut out_arr = [0_u8; $len];
            for i in 0..$len {
                out_arr[i] = in_arr[i];
            }
            Ok(out_arr)
        }
    )
}

define_copy_array!(copy_sha256, 0x20);
define_copy_array!(copy_sha384, 0x30);
define_copy_array!(copy_sha512, 0x40);

// define_copy_array!(copy_rsa2048, 0x100);
