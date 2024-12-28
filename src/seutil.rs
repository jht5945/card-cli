use crate::util::{base64_decode, base64_encode};
use rust_util::XResult;
use swift_rs::swift;
use swift_rs::{Bool, SRString};

swift!(fn is_support_secure_enclave() -> Bool);
swift!(fn generate_secure_enclave_p256_ecdh_keypair() -> SRString);
swift!(fn generate_secure_enclave_p256_ecsign_keypair() -> SRString);
swift!(fn compute_secure_enclave_p256_ecdh(private_key_base64: SRString, ephemera_public_key_base64: SRString) -> SRString);
swift!(fn compute_secure_enclave_p256_ecsign(private_key_base64: SRString, content: SRString) -> SRString);
swift!(fn recover_secure_enclave_p256_ecsign_public_key(private_key_base64: SRString) -> SRString);
swift!(fn recover_secure_enclave_p256_ecdh_public_key(private_key_base64: SRString) -> SRString);

pub fn is_support_se() -> bool {
    unsafe { is_support_secure_enclave() }
}

pub fn generate_secure_enclave_p256_keypair(sign: bool) -> XResult<(Vec<u8>, Vec<u8>, String)> {
    let p256_keypair_result = if sign {
        unsafe { generate_secure_enclave_p256_ecsign_keypair() }
    } else {
        unsafe { generate_secure_enclave_p256_ecdh_keypair() }
    };
    parse_p256_keypair_result(p256_keypair_result.as_str())
}

pub fn recover_secure_enclave_p256_public_key(
    private_key: &str,
    sign: bool,
) -> XResult<(Vec<u8>, Vec<u8>, String)> {
    let p256_keypair_result = if sign {
        unsafe { recover_secure_enclave_p256_ecsign_public_key(SRString::from(private_key)) }
    } else {
        unsafe { recover_secure_enclave_p256_ecdh_public_key(SRString::from(private_key)) }
    };
    parse_p256_keypair_result(p256_keypair_result.as_str())
}

pub fn secure_enclave_p256_dh(
    private_key: &str,
    ephemeral_public_key_bytes: &[u8],
) -> XResult<Vec<u8>> {
    let dh_result = unsafe {
        compute_secure_enclave_p256_ecdh(
            SRString::from(private_key),
            SRString::from(base64_encode(ephemeral_public_key_bytes).as_str()),
        )
    };
    let dh_result_str = dh_result.as_str();
    debugging!("DH result: {}", &dh_result_str);
    if !dh_result_str.starts_with("ok:SharedSecret:") {
        return simple_error!("ECDH P256 in secure enclave failed: {}", dh_result_str);
    }

    let shared_secret_hex = dh_result_str
        .chars()
        .skip("ok:SharedSecret:".len())
        .collect::<String>();
    let shared_secret_hex = shared_secret_hex.trim();

    Ok(opt_result!(
        hex::decode(shared_secret_hex),
        "Decrypt shared secret hex: {}, failed: {}",
        shared_secret_hex
    ))
}

pub fn secure_enclave_p256_sign(private_key: &str, content: &[u8]) -> XResult<Vec<u8>> {
    let signature_result = unsafe {
        compute_secure_enclave_p256_ecsign(
            SRString::from(private_key),
            SRString::from(base64_encode(content).as_str()),
        )
    };
    let signature_result_str = signature_result.as_str();
    debugging!("Signature result: {}", &signature_result_str);
    if !signature_result_str.starts_with("ok:") {
        return simple_error!(
            "Sign P256 in secure enclave failed: {}",
            signature_result_str
        );
    }
    let signature = signature_result_str.chars().skip(3).collect::<String>();
    debugging!("Signature: {}", &signature);
    Ok(base64_decode(&signature)?)
}

fn parse_p256_keypair_result(p256_keypair_result_str: &str) -> XResult<(Vec<u8>, Vec<u8>, String)> {
    if !p256_keypair_result_str.starts_with("ok:") {
        return simple_error!(
            "Generate P256 in secure enclave failed: {}",
            p256_keypair_result_str
        );
    }
    let public_key_and_private_key = p256_keypair_result_str.chars().skip(3).collect::<String>();
    let public_key_and_private_keys = public_key_and_private_key.split(',').collect::<Vec<_>>();
    if public_key_and_private_keys.len() != 3 {
        return simple_error!(
            "Generate P256 in secure enclave result is bad: {}",
            public_key_and_private_key
        );
    }
    let public_key_point = opt_result!(
        base64_decode(public_key_and_private_keys[0]),
        "Public key point is not base64 encoded: {}"
    );
    let public_key_der = opt_result!(
        base64_decode(public_key_and_private_keys[1]),
        "Public key der is not base64 encoded: {}"
    );
    let private_key = public_key_and_private_keys[2].to_string();
    Ok((public_key_point, public_key_der, private_key))
}
