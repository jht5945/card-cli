use crate::util::base64_decode;
use p256::pkcs8::LineEnding;
use rust_util::XResult;
use spki::{DecodePublicKey, EncodePublicKey};

pub fn convert_ec_public_key_to_jwk(public_key: &str) -> XResult<String> {
    if let Ok(jwk) = convert_ec_public_key_p256_to_jwk(public_key) {
        return Ok(jwk);
    }
    if let Ok(jwk) = convert_ec_public_key_p384_to_jwk(public_key) {
        return Ok(jwk);
    }
    simple_error!("Parse public key failed, MUST be pem or base64 encoded DER.")
}

pub fn convert_ec_public_key_p256_to_jwk(public_key: &str) -> XResult<String> {
    let public_key_p256 = if public_key.contains("BEGIN PUBLIC KEY") {
        debugging!("Try parse P256 public key PEM.");
        p256::PublicKey::from_public_key_pem(public_key)?
    } else {
        debugging!("Try parse P256 public key DER.");
        let der = base64_decode(public_key)?;
        p256::PublicKey::from_public_key_der(&der)?
    };
    Ok(public_key_p256.to_jwk_string())
}

pub fn convert_ec_public_key_p384_to_jwk(public_key: &str) -> XResult<String> {
    let public_key_p384 = if public_key.contains("BEGIN PUBLIC KEY") {
        debugging!("Try parse P384 public key PEM.");
        p384::PublicKey::from_public_key_pem(public_key)?
    } else {
        debugging!("Try parse P384 public key DER.");
        let der = base64_decode(public_key)?;
        p384::PublicKey::from_public_key_der(&der)?
    };
    Ok(public_key_p384.to_jwk_string())
}

pub fn convert_ec_jwk_to_public_key(jwk: &str) -> XResult<(String, Vec<u8>)> {
    if let Ok(public_key) = convert_ec_jwk_p256_to_public_key(jwk) {
        return Ok(public_key);
    }
    if let Ok(public_key) = convert_ec_jwk_p384_to_public_key(jwk) {
        return Ok(public_key);
    }
    simple_error!("Parse JWK failed, MUST be P256 or P384.")
}

pub fn convert_ec_jwk_p256_to_public_key(jwk: &str) -> XResult<(String, Vec<u8>)> {
    debugging!("Try parse P256 JWK.");
    let public_key = p256::PublicKey::from_jwk_str(jwk)?;
    Ok((
        public_key.to_public_key_pem(LineEnding::LF)?,
        public_key.to_public_key_der()?.to_vec(),
    ))
}

pub fn convert_ec_jwk_p384_to_public_key(jwk: &str) -> XResult<(String, Vec<u8>)> {
    debugging!("Try parse P384 JWK.");
    let public_key = p384::PublicKey::from_jwk_str(jwk)?;
    Ok((
        public_key.to_public_key_pem(LineEnding::LF)?,
        public_key.to_public_key_der()?.to_vec(),
    ))
}
