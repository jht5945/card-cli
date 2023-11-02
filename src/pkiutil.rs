use openpgp_card::crypto_data::PublicKeyMaterial;
use openssl::bn::BigNum;
use openssl::rsa::Rsa;
use pem::Pem;
use rust_util::XResult;
use sequoia_openpgp::crypto::mpi::PublicKey;
use x509_parser::x509::AlgorithmIdentifier;

use crate::digest::sha256_bytes;

#[derive(Clone, Copy, Debug)]
pub enum PkiAlgorithm {
    Rsa,
    P256,
    P384,
    P521,
}

pub fn get_pki_algorithm(algorithm_identifier: &AlgorithmIdentifier) -> XResult<PkiAlgorithm> {
    let algorithm_id_string = algorithm_identifier.algorithm.to_id_string();
    if "1.2.840.113549.1.1.1" == algorithm_id_string {
        return Ok(PkiAlgorithm::Rsa);
    }
    if "1.2.840.10045.2.1" == algorithm_id_string {
        if let Some(parameters) = &algorithm_identifier.parameters {
            if let Ok(parameter_oid) = parameters.as_oid() {
                let parameter_oid_id_string = parameter_oid.to_id_string();
                return match parameter_oid_id_string.as_str() {
                    "1.2.840.10045.3.1.7" => Ok(PkiAlgorithm::P256),
                    "1.3.132.0.34" => Ok(PkiAlgorithm::P384),
                    "1.3.132.0.35" => Ok(PkiAlgorithm::P521),
                    unknown_ec_oid => simple_error!("Unknown EC curve: {}", unknown_ec_oid),
                };
            }
        }
    }
    simple_error!("Unknown pki algorithm: {}", algorithm_id_string)
}

pub fn bytes_to_pem<T>(tag: &str, contents: T) -> String where T: Into<Vec<u8>> {
    let cert_public_key_pem_obj = Pem::new(tag, contents);
    pem::encode(&cert_public_key_pem_obj).trim().to_string()
}

pub fn sequoia_openpgp_public_key_pem(public_key: &PublicKey) -> Option<(Vec<u8>, String)> {
    match public_key {
        PublicKey::RSA { e, n } => {
            Some(rsa_public_key_pem(n.value(), e.value()))
        }
        _ => {
            warning!("Not RSA public key: {:?}", public_key);
            None
        }
    }
}

pub fn openpgp_card_public_key_pem(public_key: &PublicKeyMaterial) -> Option<(Vec<u8>, String)> {
    match public_key {
        PublicKeyMaterial::R(rsa_pub) => {
            Some(rsa_public_key_pem(rsa_pub.n(), rsa_pub.v()))
        }
        PublicKeyMaterial::E(ecc_pub) => {
            let ecc_pub_key_bytes_sha256 = sha256_bytes(ecc_pub.data());
            Some((ecc_pub_key_bytes_sha256, format!("hex:{}", hex::encode(ecc_pub.data()))))
        }
        _ => {
            warning!("Unknown public key: {:?}", public_key);
            None
        }
    }
}

pub fn rsa_public_key_pem(n: &[u8], e: &[u8]) -> (Vec<u8>, String) {
    let rsa_pub_key = Rsa::from_public_components(
        BigNum::from_slice(n).unwrap(),
        BigNum::from_slice(e).unwrap(),
    );
    let rsa_pub_key_bytes = rsa_pub_key.unwrap().public_key_to_der().unwrap();
    let rsa_pub_key_bytes_sha256 = sha256_bytes(&rsa_pub_key_bytes);
    (rsa_pub_key_bytes_sha256, bytes_to_pem("PUBLIC KEY", rsa_pub_key_bytes))
}

