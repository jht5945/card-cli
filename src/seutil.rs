use crate::util::{base64_decode, base64_encode};
use rust_util::XResult;
use se_tool::KeyPurpose;
use swift_secure_enclave_tool_rs as se_tool;
use swift_secure_enclave_tool_rs::ControlFlag;

pub fn is_support_se() -> bool {
    se_tool::is_secure_enclave_supported().unwrap_or_else(|e| {
        failure!("Invoke command swift-secure-enclave-tool failed: {}", e);
        false
    })
}

pub fn check_se_supported() -> XResult<()> {
    if !is_support_se() {
        simple_error!("Secure Enclave is NOT supported.")
    } else {
        Ok(())
    }
}

pub fn generate_secure_enclave_p256_keypair(
    sign: bool,
    control_flag: ControlFlag,
) -> XResult<(Vec<u8>, Vec<u8>, String)> {
    let key_material = if sign {
        se_tool::generate_keypair(KeyPurpose::Signing, control_flag)?
    } else {
        se_tool::generate_keypair(KeyPurpose::KeyAgreement, control_flag)?
    };
    Ok((
        key_material.public_key_point,
        key_material.public_key_der,
        base64_encode(&key_material.private_key_representation),
    ))
}

pub fn recover_secure_enclave_p256_public_key(
    private_key: &str,
    sign: bool,
) -> XResult<(Vec<u8>, Vec<u8>, String)> {
    let private_key_representation = base64_decode(private_key)?;
    let key_material = if sign {
        se_tool::recover_keypair(KeyPurpose::Signing, &private_key_representation)
    } else {
        se_tool::recover_keypair(KeyPurpose::KeyAgreement, &private_key_representation)
    }?;
    Ok((
        key_material.public_key_point,
        key_material.public_key_der,
        base64_encode(&key_material.private_key_representation),
    ))
}

pub fn secure_enclave_p256_dh(
    private_key: &str,
    ephemeral_public_key_bytes: &[u8],
) -> XResult<Vec<u8>> {
    let private_key_representation = base64_decode(private_key)?;
    let shared_secret =
        se_tool::private_key_ecdh(&private_key_representation, ephemeral_public_key_bytes)?;
    Ok(shared_secret)
}

pub fn secure_enclave_p256_sign(private_key: &str, content: &[u8]) -> XResult<Vec<u8>> {
    let private_key_representation = base64_decode(private_key)?;
    let signature = se_tool::private_key_sign(&private_key_representation, content)?;
    Ok(signature)
}
