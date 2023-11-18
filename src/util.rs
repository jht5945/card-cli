use base64::{DecodeError, Engine};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

pub fn base64_encode<T: AsRef<[u8]>>(input: T) -> String {
    STANDARD.encode(input)
}

pub fn base64_encode_url_safe_no_pad<T: AsRef<[u8]>>(input: T) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

pub fn base64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    STANDARD.decode(input)
}
