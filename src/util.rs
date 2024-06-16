use std::io::Read;

use base64::{DecodeError, Engine};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rust_util::XResult;

pub fn base64_encode<T: AsRef<[u8]>>(input: T) -> String {
    STANDARD.encode(input)
}

pub fn base64_encode_url_safe_no_pad<T: AsRef<[u8]>>(input: T) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

pub fn base64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    STANDARD.decode(input)
}

pub fn try_decode(input: &str) -> XResult<Vec<u8>> {
    match hex::decode(input) {
        Ok(v) => Ok(v),
        Err(_) => match base64_decode(input) {
            Ok(v) => Ok(v),
            Err(e) => simple_error!("decode hex or base64 error: {}", e),
        }
    }
}

pub fn read_stdin() -> XResult<Vec<u8>> {
    let mut buffer = vec![];
    let mut stdin = std::io::stdin();
    opt_result!(stdin.read_to_end(&mut buffer), "Read stdin failed: {}");
    Ok(buffer)
}
