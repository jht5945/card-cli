use der_parser::ber::BerObjectContent;
use ecdsa::elliptic_curve::pkcs8::LineEnding;
use ecdsa::VerifyingKey;
use p256::NistP256;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p384::NistP384;
use p256::pkcs8::EncodePrivateKey;
use p521::NistP521;
use rust_util::XResult;
use spki::EncodePublicKey;
use crate::util::{base64_encode, try_decode};

#[derive(Copy, Clone)]
pub enum EcdsaAlgorithm {
    P256,
    P384,
    P521,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum EcdsaSignType {
    Der, Rs,
}

pub fn parse_ecdsa_to_rs(signature_der: &[u8]) -> XResult<Vec<u8>> {
    let (mut r, s)= parse_ecdsa_r_and_s(signature_der)?;
    r.extend_from_slice(&s);
    Ok(r)
}

pub fn parse_ecdsa_r_and_s(signature_der: &[u8]) -> XResult<(Vec<u8>, Vec<u8>)> {
    let vec_r: Vec<u8>;
    let vec_s: Vec<u8>;
    let (_, parsed_signature) = opt_result!(der_parser::parse_der(signature_der), "Parse signature failed: {}");
    match parsed_signature.content {
        BerObjectContent::Sequence(seq) => {
            match &seq[0].content {
                BerObjectContent::Integer(r) => {
                    debugging!("Signature r: {}", hex::encode(r));
                    vec_r = trim_ecdsa_point_coord(r);
                }
                _ => return simple_error!("Parse signature failed: [0]not integer"),
            }
            match &seq[1].content {
                BerObjectContent::Integer(s) => {
                    debugging!("Signature s: {}", hex::encode(s));
                    vec_s = trim_ecdsa_point_coord(s);
                }
                _ => return simple_error!("Parse signature failed: [1]not integer"),
            }
        }
        _ => return simple_error!("Parse signature failed: not sequence"),
    }
    Ok((vec_r, vec_s))
}

const P256_LEN: usize = 32;
const P384_LEN: usize = 48;
const P521_LEN: usize = 66;

fn trim_ecdsa_point_coord(p: &[u8]) -> Vec<u8> {
    if p.len() == (P256_LEN + 1) || p.len() == (P384_LEN + 1) || p.len() == (P521_LEN + 1) {
        p[1..].to_vec()
    } else if p.len() == (P256_LEN - 1) || p.len() == (P384_LEN - 1) || p.len() == (P521_LEN - 1) {
        let mut v = vec![];
        v.push(0_u8);
        v.extend_from_slice(p);
        v
    } else {
        p.to_vec()
    }
}


macro_rules! generate_inner_ecdsa_keypair {
    ($algo: tt) => ({
        use $algo::SecretKey;

        let secret_key = SecretKey::random(&mut rand::thread_rng());
        let secret_key_der_base64 = base64_encode(secret_key.to_pkcs8_der()?.as_bytes());
        let secret_key_pem = secret_key.to_pkcs8_pem(LineEnding::LF)?.to_string();
        let public_key_pem = secret_key.public_key().to_public_key_pem(LineEnding::LF)?;
        let public_key_der = secret_key.public_key().to_public_key_der()?.to_vec();
        let jwk_ec_key = secret_key.public_key().to_jwk().to_string();
        Ok((secret_key_der_base64, secret_key_pem, public_key_pem, public_key_der, jwk_ec_key))
    })
}

pub fn generate_ecdsa_keypair(algo: EcdsaAlgorithm) -> XResult<(String, String, String, Vec<u8>, String)> {
    match algo {
        EcdsaAlgorithm::P256 => generate_inner_ecdsa_keypair!(p256),
        EcdsaAlgorithm::P384 => generate_inner_ecdsa_keypair!(p384),
        EcdsaAlgorithm::P521 => generate_inner_ecdsa_keypair!(p521),
    }
}

pub fn parse_ec_public_key_to_point(public_key_bytes: &[u8]) -> XResult<Vec<u8>> {
    match parse_p521_public_key_to_point(public_key_bytes) {
        Ok(point) => Ok(point),
        Err(_) => match parse_p384_public_key_to_point(public_key_bytes) {
            Ok(point) => Ok(point),
            Err(_) => parse_p256_public_key_to_point(public_key_bytes),
        }
    }
}

pub fn parse_p256_public_key_to_point(public_key_bytes: &[u8]) -> XResult<Vec<u8>> {
    use p256::{PublicKey, elliptic_curve::sec1::ToEncodedPoint};
    use spki::DecodePublicKey;
    let public_key = PublicKey::from_public_key_der(public_key_bytes)?;
    Ok(public_key.to_encoded_point(false).as_bytes().to_vec())
}

pub fn parse_p384_public_key_to_point(public_key_bytes: &[u8]) -> XResult<Vec<u8>> {
    use p384::{PublicKey, elliptic_curve::sec1::ToEncodedPoint};
    use spki::DecodePublicKey;
    let public_key = PublicKey::from_public_key_der(public_key_bytes)?;
    Ok(public_key.to_encoded_point(false).as_bytes().to_vec())
}

pub fn parse_p521_public_key_to_point(public_key_bytes: &[u8]) -> XResult<Vec<u8>> {
    use p521::{PublicKey, elliptic_curve::sec1::ToEncodedPoint};
    use spki::DecodePublicKey;
    let public_key = PublicKey::from_public_key_der(public_key_bytes)?;
    Ok(public_key.to_encoded_point(false).as_bytes().to_vec())
}

macro_rules! parse_ecdsa_private_key_to_public_key {
    ($algo: tt, $parse_ecdsa_private_key: tt) => ({
        use $algo::{SecretKey, pkcs8::DecodePrivateKey};

        let secret_key = match SecretKey::from_pkcs8_pem($parse_ecdsa_private_key) {
            Ok(secret_key) => secret_key,
            Err(_) => match try_decode($parse_ecdsa_private_key) {
                Ok(private_key_der) => match SecretKey::from_pkcs8_der(&private_key_der) {
                    Ok(secret_key) => secret_key,
                    Err(e) => return simple_error!("Invalid PKCS#8 private key {}, error: {}", $parse_ecdsa_private_key, e),
                }
                Err(_) => return simple_error!("Invalid PKCS#8 private key: {}", $parse_ecdsa_private_key),
            }
        };
        let public_key_document = opt_result!(secret_key.public_key().to_public_key_der(), "Conver to public key failed: {}");
        Ok(public_key_document.to_vec())
    })
}

pub fn parse_p256_private_key_to_public_key(private_key_pkcs8: &str) -> XResult<Vec<u8>> {
    parse_ecdsa_private_key_to_public_key!(p256, private_key_pkcs8)
}

pub fn parse_p384_private_key_to_public_key(private_key_pkcs8: &str) -> XResult<Vec<u8>> {
    parse_ecdsa_private_key_to_public_key!(p384, private_key_pkcs8)
}

pub fn parse_p521_private_key_to_public_key(private_key_pkcs8: &str) -> XResult<Vec<u8>> {
    parse_ecdsa_private_key_to_public_key!(p521, private_key_pkcs8)
}


macro_rules! parse_ecdsa_private_key {
    ($algo: tt, $parse_ecdsa_private_key: tt) => ({
        use $algo::{SecretKey, pkcs8::DecodePrivateKey};

        let secret_key = match SecretKey::from_pkcs8_pem($parse_ecdsa_private_key) {
            Ok(secret_key) => secret_key,
            Err(_) => match try_decode($parse_ecdsa_private_key) {
                Ok(private_key_der) => match SecretKey::from_pkcs8_der(&private_key_der) {
                    Ok(secret_key) => secret_key,
                    Err(e) => return simple_error!("Invalid PKCS#8 private key {}, error: {}", $parse_ecdsa_private_key, e),
                }
                Err(_) => return simple_error!("Invalid PKCS#8 private key: {}", $parse_ecdsa_private_key),
            }
        };
        Ok(secret_key.to_bytes().to_vec())
    })
}

pub fn parse_p256_private_key(private_key_pkcs8: &str) -> XResult<Vec<u8>> {
    parse_ecdsa_private_key!(p256, private_key_pkcs8)
}

pub fn parse_p384_private_key(private_key_pkcs8: &str) -> XResult<Vec<u8>> {
    parse_ecdsa_private_key!(p384, private_key_pkcs8)
}

pub fn parse_p521_private_key(private_key_pkcs8: &str) -> XResult<Vec<u8>> {
    parse_ecdsa_private_key!(p521, private_key_pkcs8)
}


macro_rules! sign_ecdsa_rs_or_der {
    ($algo: tt, $private_key_d: tt, $pre_hash: tt, $is_rs: tt) => ({
        use $algo::ecdsa::{SigningKey, Signature, signature::hazmat::PrehashSigner};

        let signing_key = SigningKey::from_slice($private_key_d)?;
        let signature: Signature = signing_key.sign_prehash($pre_hash)?;

        if $is_rs {
            Ok(signature.to_bytes().to_vec())
        } else {
            Ok(signature.to_der().as_bytes().to_vec())
        }
    })
}

pub fn ecdsa_sign(algo: EcdsaAlgorithm, private_key_d: &[u8], pre_hash: &[u8], sign_type: EcdsaSignType) -> XResult<Vec<u8>> {
    let is_rs = sign_type == EcdsaSignType::Rs;
    match algo {
        EcdsaAlgorithm::P256 => sign_ecdsa_rs_or_der!(p256, private_key_d, pre_hash, is_rs),
        EcdsaAlgorithm::P384 => sign_ecdsa_rs_or_der!(p384, private_key_d, pre_hash, is_rs),
        EcdsaAlgorithm::P521 => sign_ecdsa_rs_or_der!(p521, private_key_d, pre_hash, is_rs),
    }
}


macro_rules! ecdsa_verify_signature {
    ($algo: tt, $pk_point: tt, $prehash: tt, $signature: tt) => ({
        use ecdsa::Signature;
        let verifying_key: VerifyingKey<$algo> = opt_result!(VerifyingKey::<$algo>::from_sec1_bytes($pk_point), "Parse public key failed: {}");
        let sign = if let Ok(signature) = Signature::from_der($signature) {
            signature
        } else if let Ok(signature) = Signature::from_slice($signature) {
            signature
        } else {
            return simple_error!("Parse signature failed: {}", hex::encode($signature));
        };
        opt_result!(verifying_key.verify_prehash($prehash, &sign), "Verify signature failed: {}");
    })
}

pub fn ecdsa_verify(algo: EcdsaAlgorithm, pk_point: &[u8], prehash: &[u8], signature: &[u8]) -> XResult<()> {
    match algo {
        EcdsaAlgorithm::P256 => ecdsa_verify_signature!(NistP256, pk_point, prehash, signature),
        EcdsaAlgorithm::P384 => ecdsa_verify_signature!(NistP384, pk_point, prehash, signature),
        EcdsaAlgorithm::P521 => ecdsa_verify_signature!(NistP521, pk_point, prehash, signature),
    }
    Ok(())
}