use base64::{DecodeError, Engine};
use base64::engine::general_purpose::STANDARD;

pub fn base64_encode<T: AsRef<[u8]>>(input: T) -> String {
    STANDARD.encode(input)
}

pub fn base64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    STANDARD.decode(input)
}
