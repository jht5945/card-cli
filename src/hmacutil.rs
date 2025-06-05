use clap::ArgMatches;
use rust_util::XResult;
use std::collections::BTreeMap;
use std::ops::Deref;
use aes_gcm_stream::{Aes256GcmStreamDecryptor, Aes256GcmStreamEncryptor};
use rand::random;
use yubico_manager::config::{Config, Mode, Slot};
use yubico_manager::hmacmode::HmacKey;
use yubico_manager::sec::hmac_sha1;
use yubico_manager::Yubico;
use crate::digestutil::{copy_sha256, sha256_bytes};
use crate::util;
use crate::util::{base64_decode, base64_encode, base64_encode_url_safe_no_pad, base64_uri_decode};

const HMAC_ENC_PREFIX: &str = "hmac_enc:";

// hmac encrypt, format: hmac_enc:<HMAC-NONCE>:<AES-GCM-NONCE>:<ENCRYPTED>
pub fn hmac_encrypt_from_string(plaintext: &str) -> XResult<String> {
    hmac_encrypt(plaintext.as_bytes())
}

pub fn hmac_encrypt(plaintext: &[u8]) -> XResult<String> {
    let hmac_nonce: [u8; 16] = random();
    let aes_gcm_nonce: [u8; 16] = random();

    let hmac_key = compute_yubikey_hmac(&hmac_nonce)?;
    let key = copy_sha256(&sha256_bytes(&hmac_key))?;

    let mut encryptor = Aes256GcmStreamEncryptor::new(key, &aes_gcm_nonce);
    let mut ciphertext = encryptor.update(plaintext);
    let (final_part, tag) = encryptor.finalize();
    ciphertext.extend_from_slice(&final_part);
    ciphertext.extend_from_slice(&tag);

    Ok(format!("{}{}:{}:{}",
               HMAC_ENC_PREFIX,
               base64_encode_url_safe_no_pad(hmac_nonce),
               base64_encode_url_safe_no_pad(aes_gcm_nonce),
               base64_encode(&ciphertext)
    ))
}

pub fn is_hmac_encrypted(ciphertext: &str) -> bool {
    ciphertext.starts_with(HMAC_ENC_PREFIX)
}

pub fn hmac_decrypt_to_string(ciphertext: &str) -> XResult<String> {
    let plaintext = hmac_decrypt(ciphertext)?;
    Ok(String::from_utf8(plaintext)?)
}

pub fn hmac_decrypt(ciphertext: &str) -> XResult<Vec<u8>> {
    if !is_hmac_encrypted(ciphertext) {
        return simple_error!("Invalid ciphertext: {}", ciphertext);
    }
    let parts = ciphertext.split(":").collect::<Vec<_>>();
    let hmac_nonce = try_decode_hmac_val(parts[1])?;
    let aes_gcm_nonce = try_decode_hmac_val(parts[2])?;
    let ciphertext = base64_decode(parts[3])?;

    let hmac_key = compute_yubikey_hmac(&hmac_nonce)?;
    let key = copy_sha256(&sha256_bytes(&hmac_key))?;

    let mut decryptor = Aes256GcmStreamDecryptor::new(key, &aes_gcm_nonce);
    let mut plaintext = decryptor.update(&ciphertext);
    let final_part = decryptor.finalize()?;
    plaintext.extend_from_slice(&final_part);

    Ok(plaintext)
}

pub fn try_decode_hmac_val(s: &str) -> XResult<Vec<u8>> {
    match hex::decode(s) {
        Ok(v) => Ok(v),
        Err(e) => match base64_uri_decode(s) {
            Ok(v) => Ok(v),
            Err(_) => simple_error!("Try decode failed: {}", e)
        }
    }
}

pub fn compute_yubikey_hmac(challenge_bytes: &[u8]) -> XResult<Vec<u8>> {
    let mut yubi = Yubico::new();
    let device = match yubi.find_yubikey() {
        Ok(device) => device,
        Err(_) => {
            return simple_error!("YubiKey not found");
        }
    };
    debugging!("Found key, Vendor ID: {:?}, Product ID: {:?}", device.vendor_id, device.product_id);
    let config = Config::default()
        .set_vendor_id(device.vendor_id)
        .set_product_id(device.product_id)
        .set_variable_size(true)
        .set_mode(Mode::Sha1)
        .set_slot(Slot::Slot2);

    let hmac_result = opt_result!(yubi.challenge_response_hmac(challenge_bytes, config), "Challenge HMAC failed: {}");
    Ok(hmac_result.deref().to_vec())
}

pub fn get_challenge_bytes(sub_arg_matches: &ArgMatches) -> XResult<Vec<u8>> {
    let challenge_bytes: Vec<u8> = if let Some(challenge) = sub_arg_matches.value_of("challenge") {
        challenge.as_bytes().to_vec()
    } else if let Some(challenge_hex) = sub_arg_matches.value_of("challenge-hex") {
        opt_result!(hex::decode(challenge_hex), "Decode challenge hex: {}, failed: {}", challenge_hex)
    } else {
        return simple_error!("Challenge must assigned");
    };
    if challenge_bytes.len() > 64 {
        return simple_error!("Challenge bytes is: {}, more than 64", challenge_bytes.len());
    }
    Ok(challenge_bytes)
}

pub fn calculate_hmac_sha1_result(secret_bytes: &[u8], challenge_bytes: &[u8], variable: bool) -> [u8; 20] {
    let hmac_key = HmacKey::from_slice(secret_bytes);
    let mut challenge = [0; 64];
    if variable && challenge_bytes.last() == Some(&0) {
        challenge = [0xff; 64];
    }
    challenge[..challenge_bytes.len()].copy_from_slice(challenge_bytes);
    hmac_sha1(&hmac_key, &challenge)
}


pub fn output_hmac_result(sub_arg_matches: &ArgMatches, json_output: bool, challenge_bytes: Vec<u8>, result: &[u8]) {
    let sha1_output = sub_arg_matches.is_present("sha1");
    let sha256_output = sub_arg_matches.is_present("sha256");
    let sha384_output = sub_arg_matches.is_present("sha384");
    let sha512_output = sub_arg_matches.is_present("sha512");

    let hex_string = hex::encode(result);
    let hex_sha1 = iff!(sha1_output, Some(crate::digestutil::sha1_bytes(result)), None);
    let hex_sha256 = iff!(sha256_output, Some(crate::digestutil::sha256_bytes(result)), None);
    let hex_sha384 = iff!(sha384_output, Some(crate::digestutil::sha384_bytes(result)), None);
    let hex_sha512 = iff!(sha512_output, Some(crate::digestutil::sha512_bytes(result)), None);

    if json_output {
        let mut json = BTreeMap::<&'_ str, String>::new();
        json.insert("challenge_hex", hex::encode(challenge_bytes));
        json.insert("response_hex", hex_string);
        hex_sha1.map(|hex_sha1| json.insert("response_sha1_hex", hex::encode(hex_sha1)));
        hex_sha256.map(|hex_sha256| json.insert("response_sha256_hex", hex::encode(hex_sha256)));
        hex_sha384.map(|hex_sha384| json.insert("response_sha384_hex", hex::encode(hex_sha384)));
        hex_sha512.map(|hex_sha512| json.insert("response_sha512_hex", hex::encode(hex_sha512)));

        util::print_pretty_json(&json);
    } else {
        success!("Challenge HEX: {}", hex::encode(challenge_bytes));
        success!("Response HEX: {}", hex_string);
        if let Some(hex_sha256) = hex_sha256 { success!("Response SHA256 HEX: {}", hex::encode(hex_sha256)); }
        if let Some(hex_sha384) = hex_sha384 { success!("Response SHA384 HEX: {}", hex::encode(hex_sha384)); }
        if let Some(hex_sha512) = hex_sha512 { success!("Response SHA512 HEX: {}", hex::encode(hex_sha512)); }
    }
}

