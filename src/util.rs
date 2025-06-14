use std::fs;
use std::io::Read;

use base64::{DecodeError, Engine};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rust_util::XResult;
use serde::Serialize;

pub fn base64_encode<T: AsRef<[u8]>>(input: T) -> String {
    STANDARD.encode(input)
}

pub fn base64_encode_url_safe_no_pad<T: AsRef<[u8]>>(input: T) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

pub fn base64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    STANDARD.decode(input)
}

pub fn base64_uri_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    URL_SAFE_NO_PAD.decode(input)
}

pub fn try_decode(input: &str) -> XResult<Vec<u8>> {
    match hex::decode(input) {
        Ok(v) => Ok(v),
        Err(_) => match base64_decode(input) {
            Ok(v) => Ok(v),
            Err(_) => match base64_uri_decode(input) {
                Ok(v) => Ok(v),
                Err(e) => simple_error!("decode hex or base64 error: {}", e),
            },
        }
    }
}

pub fn read_stdin() -> XResult<Vec<u8>> {
    let mut buffer = vec![];
    let mut stdin = std::io::stdin();
    opt_result!(stdin.read_to_end(&mut buffer), "Read stdin failed: {}");
    Ok(buffer)
}

pub fn read_file_or_stdin(file: &str) -> XResult<Vec<u8>> {
    if file == "-" {
        read_stdin()
    } else {
        Ok(opt_result!(fs::read(file), "Read file: {} failed: {}", file))
    }
}

pub fn print_pretty_json<T>(value: &T)
where
    T: ?Sized + Serialize,
{
    println!("{}", serde_json::to_string_pretty(value).unwrap());
}
