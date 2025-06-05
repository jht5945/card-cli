use crate::digestutil::{copy_sha256, sha256_bytes};
use crate::pinutil;
use crate::util::{base64_decode, base64_encode, base64_encode_url_safe_no_pad};
use aes_gcm_stream::{Aes256GcmStreamDecryptor, Aes256GcmStreamEncryptor};
use rand::random;
use rust_util::XResult;
use secrecy::Zeroize;

const PBE_ENC_PREFIX: &str = "pbe_enc:";

pub fn simple_pbe_encrypt_with_prompt_from_string(iteration: u32, plaintext: &str, passowrd: &mut Option<String>, password_double_check: bool) -> XResult<String> {
    simple_pbe_encrypt_with_prompt(iteration, plaintext.as_bytes(), passowrd, password_double_check)
}

pub fn simple_pbe_decrypt_with_prompt_to_string(pin_opt: &mut Option<String>, ciphertext: &str) -> XResult<String> {
    let plaintext = simple_pbe_decrypt_with_prompt(pin_opt, ciphertext)?;
    Ok(String::from_utf8(plaintext)?)
}

pub fn simple_pbe_encrypt_with_prompt(iteration: u32, plaintext: &[u8], password_opt: &mut Option<String>, password_double_check: bool) -> XResult<String> {
    let mut pin = match password_opt {
        None => {
            let pin1 = opt_value_result!(pinutil::get_pin(None), "Simple PBE password required");
            if password_double_check {
                let mut pin2 = opt_value_result!(pinutil::get_pin(None), "Simple PBE password required");
                if pin1 != pin2 {
                    return simple_error!("Two PINs mismatch");
                }
                pin2.zeroize();
            }
            *password_opt = Some(pin1.clone());
            pin1
        }
        Some(pin) => pin.clone(),
    };
    let encrypt_result = simple_pbe_encrypt(&pin, iteration, plaintext);
    pin.zeroize();
    encrypt_result
}

pub fn simple_pbe_decrypt_with_prompt(pin_opt: &mut Option<String>, ciphertext: &str) -> XResult<Vec<u8>> {
    let mut pin = opt_value_result!(pinutil::get_pin(pin_opt.clone().as_deref()), "Simple PBE password required");
    pin_opt.zeroize();
    *pin_opt = Some(pin.clone());
    let decrypt_result = simple_pbe_decrypt(&pin, ciphertext);
    pin.zeroize();
    decrypt_result
}

pub fn simple_pbe_encrypt(password: &str, iteration: u32, plaintext: &[u8]) -> XResult<String> {
    let pbe_salt: [u8; 16] = random();
    let key = simple_pbe_kdf(password, &pbe_salt, iteration)?;
    let aes_gcm_nonce: [u8; 16] = random();

    let mut encryptor = Aes256GcmStreamEncryptor::new(key, &aes_gcm_nonce);
    let mut ciphertext = encryptor.update(plaintext);
    let (final_part, tag) = encryptor.finalize();
    ciphertext.extend_from_slice(&final_part);
    ciphertext.extend_from_slice(&tag);

    Ok(format!(
        "{}{}:{}:{}:{}",
        PBE_ENC_PREFIX,
        iteration,
        base64_encode_url_safe_no_pad(pbe_salt),
        base64_encode_url_safe_no_pad(aes_gcm_nonce),
        base64_encode(&ciphertext)
    ))
}

pub fn simple_pbe_decrypt(password: &str, ciphertext: &str) -> XResult<Vec<u8>> {
    if !is_simple_pbe_encrypted(ciphertext) {
        return simple_error!("Invalid ciphertext: {}", ciphertext);
    }
    let parts = ciphertext.split(":").collect::<Vec<_>>();
    let iteration: u32 = parts[1].parse()?;
    let pbe_salt = crate::hmacutil::try_decode_hmac_val(parts[2])?;
    let aes_gcm_nonce = crate::hmacutil::try_decode_hmac_val(parts[3])?;
    let ciphertext = base64_decode(parts[4])?;

    let key = simple_pbe_kdf(password, &pbe_salt, iteration)?;

    let mut decryptor = Aes256GcmStreamDecryptor::new(key, &aes_gcm_nonce);
    let mut plaintext = decryptor.update(&ciphertext);
    let final_part = decryptor.finalize()?;
    plaintext.extend_from_slice(&final_part);

    Ok(plaintext)
}

pub fn is_simple_pbe_encrypted(ciphertext: &str) -> bool {
    ciphertext.starts_with(PBE_ENC_PREFIX)
}

fn simple_pbe_kdf(password: &str, pbe_salt: &[u8], iteration: u32) -> XResult<[u8; 32]> {
    let mut init_data = password.as_bytes().to_vec();
    init_data.extend_from_slice(&pbe_salt);
    let mut loop_hash = sha256_bytes(&init_data);
    for i in 0..iteration {
        let i_to_bytes = i.to_be_bytes();
        for x in 0..4 {
            loop_hash[x] = i_to_bytes[x];
        }
        loop_hash = sha256_bytes(&loop_hash);
    }
    let key = copy_sha256(&sha256_bytes(&loop_hash))?;

    Ok(key)
}
