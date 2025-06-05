use std::collections::HashMap;
use ecdsa::elliptic_curve::rand_core::OsRng;
use openssl::bn::{BigNum, BigNumContext};
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use rust_util::{util_msg, XResult};
use rust_util::util_msg::MessageType;
use spki::DecodePublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::PublicKeyParts;
use spki::EncodePublicKey;
use rsa::pkcs1::LineEnding;
use rsa::pkcs8::EncodePrivateKey;
use sha2::{Sha256, Sha384, Sha512};
use crate::digestutil;
use crate::util::{base64_decode, base64_encode};

pub enum RsaSignAlgorithm {
    Rs256,
    Rs384,
    Rs512,
}

impl RsaSignAlgorithm {
    pub fn from_str(alg: &str) -> Option<RsaSignAlgorithm> {
        match alg {
            "RS256" => Some(RsaSignAlgorithm::Rs256),
            "RS384" => Some(RsaSignAlgorithm::Rs384),
            "RS512" => Some(RsaSignAlgorithm::Rs512),
            _ => None
        }
    }
}

pub fn sign(rsa_private_key: &RsaPrivateKey, rsa_sign_algorithm: RsaSignAlgorithm, message: &[u8]) -> XResult<Vec<u8>> {
    match rsa_sign_algorithm {
        RsaSignAlgorithm::Rs256 => {
            let raw_in = digestutil::sha256_bytes(&message);
            Ok(rsa_private_key.sign(Pkcs1v15Sign::new::<Sha256>(), &raw_in)?)
        }
        RsaSignAlgorithm::Rs384 => {
            let raw_in = digestutil::sha384_bytes(&message);
            Ok(rsa_private_key.sign(Pkcs1v15Sign::new::<Sha384>(), &raw_in)?)
        }
        RsaSignAlgorithm::Rs512 => {
            let raw_in = digestutil::sha512_bytes(&message);
            Ok(rsa_private_key.sign(Pkcs1v15Sign::new::<Sha512>(), &raw_in)?)
        }
    }
}

pub fn generate_rsa_keypair(bit_size: usize) -> XResult<(String, String, String, Vec<u8>, String)> {
    let rsa_private_key = opt_result!(RsaPrivateKey::new(&mut OsRng, bit_size), "Generate RSA private key failed: {}");
    let rsa_public_key = rsa_private_key.to_public_key();
    let secret_key_der_base64 = base64_encode(rsa_private_key.to_pkcs8_der()?.as_bytes());
    let secret_key_pem = rsa_private_key.to_pkcs8_pem(LineEnding::LF)?.to_string();
    let public_key_pem = rsa_public_key.to_public_key_pem(LineEnding::LF)?;
    let public_key_der = rsa_public_key.to_public_key_der()?.to_vec();
    let jwk_ec_key = rsa_public_key_to_jwk(&rsa_public_key)?;
    Ok((secret_key_der_base64, secret_key_pem, public_key_pem, public_key_der, jwk_ec_key))
}

#[derive(Debug)]
pub struct RsaCrt {
    // n = p * q
    pub modulus: BigNum,
    // e
    pub public_exponent: BigNum,
    // d = e mod inverse ((p - 1) * (q - 1))
    pub private_exponent: BigNum,
    // p
    pub prime1: BigNum,
    // q
    pub prime2: BigNum,
    // dp = d mod (p−1)
    pub exponent1: BigNum,
    // dq = d mod (q−1)
    pub exponent2: BigNum,
    // qinv = q^−1 mod p
    pub coefficient: BigNum,
}

impl RsaCrt {
    pub fn from(p: BigNum, q: BigNum, e: BigNum) -> XResult<RsaCrt> {
        Ok(opt_result!( inner_from(p, q, e), "Calc RsaCrt failed: {}"))
    }

    pub fn to_public_key_pem(&self) -> XResult<String> {
        Ok(crate::pkiutil::rsa_public_key_pem(
            clone_big_num(&self.modulus)?.to_vec().as_slice(),
            clone_big_num(&self.public_exponent)?.to_vec().as_slice(),
        ).1)
    }

    pub fn to_pem(&self) -> XResult<String> {
        let private_key = opt_result!(Rsa::from_private_components(
            clone_big_num(&self.modulus)?,
            clone_big_num(&self.public_exponent)?,
            clone_big_num(&self.private_exponent)?,
            clone_big_num(&self.prime1)?,
            clone_big_num(&self.prime2)?,
            clone_big_num(&self.exponent1)?,
            clone_big_num(&self.exponent2)?,
            clone_big_num(&self.coefficient)?,
        ), "From private components failed: {}");
        let private_pkey = opt_result!(PKey::from_rsa(private_key), "From rsa to pkey failed: {}");
        // let k = private_key.private_key_to_pem_passphrase(Cipher::aes_128_gcm(), passphrase);
        let private_key_pem = opt_result!(private_pkey.private_key_to_pem_pkcs8(), "Private key to pem failed: {}");

        Ok(opt_result!(String::from_utf8(private_key_pem), "Pem to string failed: {}").trim().to_string())
    }
}

pub fn clone_big_num(n: &BigNum) -> XResult<BigNum> {
    Ok(opt_result!(BigNum::from_slice(n.to_vec().as_slice()), "Clone big num:{}, failed: {}", n))
}

pub fn parse_padding(padding_opt: Option<&str>) -> XResult<Padding> {
    Ok(match padding_opt {
        Some("oaep") | Some("pkcs1_oaep") => Padding::PKCS1_OAEP,
        Some("pss") | Some("pkcs1_pss") => Padding::PKCS1_PSS,
        Some("none") => Padding::NONE,
        Some("pkcs1") | None => Padding::PKCS1,
        Some(p) => return simple_error!("Not supported padding: {}", p),
    })
}

pub fn padding_to_string(padding: Padding) -> &'static str {
    match padding {
        Padding::NONE => "none",
        Padding::PKCS1 => "pkcs1",
        Padding::PKCS1_PSS => "pkcs1_pss",
        Padding::PKCS1_OAEP => "pkcs1_oaep",
        _ => "unknown",
    }
}

fn inner_from(p: BigNum, q: BigNum, e: BigNum) -> XResult<RsaCrt> {
    let mut n = BigNum::new()?;
    n.checked_mul(&p, &q, &mut BigNumContext::new().unwrap())?;

    let mut p_m1 = clone_big_num(&p)?;
    p_m1.sub_word(1)?;
    let mut q_m1 = clone_big_num(&q)?;
    q_m1.sub_word(1)?;
    let mut m = BigNum::new()?;
    m.checked_mul(&p_m1, &q_m1, &mut BigNumContext::new().unwrap())?;

    let mut d = BigNum::new()?;
    d.mod_inverse(&e, &m, &mut BigNumContext::new().unwrap())?;

    let mut dp = BigNum::new()?;
    dp.nnmod(&d, &p_m1, &mut BigNumContext::new().unwrap())?;

    let mut dq = BigNum::new()?;
    dq.nnmod(&d, &q_m1, &mut BigNumContext::new().unwrap())?;

    let mut qinv = BigNum::new()?;
    qinv.mod_inverse(&q, &p, &mut BigNumContext::new().unwrap())?;

    Ok(RsaCrt {
        modulus: n,
        public_exponent: e,
        private_exponent: d,
        prime1: p,
        prime2: q,
        exponent1: dp,
        exponent2: dq,
        coefficient: qinv,
    })
}

pub fn pkcs15_sha256_rsa_2048_padding_for_sign(sha256: &[u8]) -> Vec<u8> {
    // https://www.ibm.com/docs/en/zos/2.2.0?topic=cryptography-pkcs-1-formats
    // MD5  X’3020300C 06082A86 4886F70D 02050500 0410’ || 16-byte hash value
    // SHA-1  X'30213009 06052B0E 03021A05 000414’ || 20-byte hash value
    // SHA-224  X’302D300D 06096086 48016503 04020405 00041C’ || 28-byte hash value
    // SHA-256  X’3031300D 06096086 48016503 04020105 000420’ || 32-byte hash value
    // SHA-384  X’3041300D 06096086 48016503 04020205 000430’ || 48-byte hash value
    // SHA-512  X’3051300D 06096086 48016503 04020305 000440’ || 64-byte hash value
    let sha256_der_prefix = hex::decode("3031300d060960864801650304020105000420").unwrap();

    let mut hash_with_oid = Vec::with_capacity(128);
    hash_with_oid.extend_from_slice(&sha256_der_prefix);
    hash_with_oid.extend_from_slice(sha256);
    let hash_padding = pkcs1_padding_for_sign(&hash_with_oid, 2048).unwrap();
    util_msg::when(MessageType::DEBUG, || {
        debugging!("Hash: {}", hex::encode(sha256));
        debugging!("Hash with OID: {}", hex::encode(&hash_with_oid));
        debugging!("PKCS1 padding: {}", hex::encode(&hash_padding));
    });
    hash_padding
}

fn pkcs1_padding_for_sign(bs: &[u8], bit_len: usize) -> XResult<Vec<u8>> {
    let byte_len = bit_len / 8;
    let max_len = byte_len - (1 + 1 + 8 + 2);
    if bs.len() > max_len {
        return simple_error!("Length is too large: {} > {}", bs.len(), max_len);
    }
    let mut output = Vec::<u8>::with_capacity(byte_len);
    output.push(0x00);
    output.push(0x01);
    let ps_len = byte_len - bs.len() - (1 + 1 + 1);
    output.extend_from_slice(&vec![0xff_u8; ps_len]);
    output.push(0x00);
    output.extend_from_slice(bs);
    Ok(output)
}

pub fn convert_rsa_to_jwk(public_key: &str) -> XResult<String> {
    let rsa_public_key = try_parse_rsa(public_key)?;
    rsa_public_key_to_jwk(&rsa_public_key)
}

pub fn rsa_public_key_to_jwk(rsa_public_key: &RsaPublicKey) -> XResult<String> {
    let e_bytes = rsa_public_key.e().to_bytes_be();
    let n_bytes = rsa_public_key.n().to_bytes_be();

    let mut jwk = HashMap::new();
    jwk.insert("kty", "RSA".to_string());
    jwk.insert("n", base64_encode(&n_bytes));
    jwk.insert("e", base64_encode(&e_bytes));

    Ok(serde_json::to_string(&jwk).unwrap())
}

pub fn try_parse_rsa(public_key: &str) -> XResult<RsaPublicKey> {
    debugging!("Try parse RSA public key PEM.");
    // parse RSA public key PEM not works? why?
    if let Ok(rsa_public_key) = RsaPublicKey::from_public_key_pem(public_key) {
        return Ok(rsa_public_key);
    }
    debugging!("Try parse RSA PKCS#1 public key PEM.");
    if let Ok(rsa_public_key) = RsaPublicKey::from_pkcs1_pem(public_key) {
        return Ok(rsa_public_key);
    }
    if let Ok(public_key_der) = base64_decode(public_key) {
        debugging!("Try parse RSA public key DER.");
        if let Ok(rsa_public_key) = RsaPublicKey::from_public_key_der(&public_key_der) {
            return Ok(rsa_public_key);
        }
        debugging!("Try parse RSA PKCS#1 public key DER.");
        if let Ok(rsa_public_key) = RsaPublicKey::from_pkcs1_der(&public_key_der) {
            return Ok(rsa_public_key);
        }
    }
    simple_error!("Invalid RSA public key.")
}
