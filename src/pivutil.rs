use rust_util::XResult;
use spki::{ObjectIdentifier, SubjectPublicKeyInfoOwned};
use spki::der::{Decode, Encode};
use x509_parser::prelude::FromDer;
use x509_parser::public_key::RSAPublicKey;
use yubikey::{PinPolicy, TouchPolicy};
use yubikey::piv::{AlgorithmId, ManagementAlgorithmId, ManagementSlotId, Origin, RetiredSlotId};
use yubikey::piv::SlotId;

const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const ECC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

// NIST recommended curves
// secp192r1 – {1.2.840.10045.3.1.1}
// secp224r1 – {1.3.132.0.33}
// secp256r1 – {1.2.840.10045.3.1.7}
// secp384r1 – {1.3.132.0.34}
// secp521r1 – {1.3.132.0.35}
const ECC_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const ECC_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

pub const ORDERED_SLOTS: [SlotId; 28] = [
    SlotId::Management(ManagementSlotId::Pin),
    SlotId::Management(ManagementSlotId::Puk),
    SlotId::Retired(RetiredSlotId::R1),
    SlotId::Retired(RetiredSlotId::R2),
    SlotId::Retired(RetiredSlotId::R3),
    SlotId::Retired(RetiredSlotId::R4),
    SlotId::Retired(RetiredSlotId::R5),
    SlotId::Retired(RetiredSlotId::R6),
    SlotId::Retired(RetiredSlotId::R7),
    SlotId::Retired(RetiredSlotId::R8),
    SlotId::Retired(RetiredSlotId::R9),
    SlotId::Retired(RetiredSlotId::R10),
    SlotId::Retired(RetiredSlotId::R11),
    SlotId::Retired(RetiredSlotId::R12),
    SlotId::Retired(RetiredSlotId::R13),
    SlotId::Retired(RetiredSlotId::R14),
    SlotId::Retired(RetiredSlotId::R15),
    SlotId::Retired(RetiredSlotId::R16),
    SlotId::Retired(RetiredSlotId::R17),
    SlotId::Retired(RetiredSlotId::R18),
    SlotId::Retired(RetiredSlotId::R19),
    SlotId::Retired(RetiredSlotId::R20),
    SlotId::Authentication,
    SlotId::Management(ManagementSlotId::Management),
    SlotId::Signature,
    SlotId::KeyManagement,
    SlotId::CardAuthentication,
    SlotId::Attestation,
];

pub trait ToStr {
    fn to_str(&self) -> &str;
}

impl ToStr for PinPolicy {
    fn to_str(&self) -> &str {
        match self {
            PinPolicy::Default => "default",
            PinPolicy::Never => "never",
            PinPolicy::Once => "once",
            PinPolicy::Always => "always",
        }
    }
}

impl ToStr for TouchPolicy {
    fn to_str(&self) -> &str {
        match self {
            TouchPolicy::Default => "default",
            TouchPolicy::Never => "never",
            TouchPolicy::Always => "always",
            TouchPolicy::Cached => "cached",
        }
    }
}

impl ToStr for AlgorithmId {
    fn to_str(&self) -> &str {
        match self {
            AlgorithmId::Rsa1024 => "rsa1024",
            AlgorithmId::Rsa2048 => "rsa2048",
            AlgorithmId::EccP256 => "p256",
            AlgorithmId::EccP384 => "p384",
        }
    }
}

impl ToStr for ManagementAlgorithmId {
    fn to_str(&self) -> &str {
        match self {
            ManagementAlgorithmId::PinPuk => "pin_puk",
            ManagementAlgorithmId::ThreeDes => "three_des",
            ManagementAlgorithmId::Asymmetric(algo_id) => algo_id.to_str(),
        }
    }
}

impl ToStr for Origin {
    fn to_str(&self) -> &str {
        match self {
            Origin::Imported => "imported",
            Origin::Generated => "generated",
        }
    }
}

pub fn get_algorithm_id(public_key_info: &SubjectPublicKeyInfoOwned) -> XResult<AlgorithmId> {
    if public_key_info.algorithm.oid == RSA {
        let rsa_public_key = opt_result!(
            RSAPublicKey::from_der(public_key_info.subject_public_key.raw_bytes()), "Parse public key failed: {}");
        let starts_with_0 = rsa_public_key.1.modulus.starts_with(&[0]);
        let public_key_bits = (rsa_public_key.1.modulus.len() - if starts_with_0 { 1 } else { 0 }) * 8;
        if public_key_bits == 1024 {
            return Ok(AlgorithmId::Rsa1024);
        }
        if public_key_bits == 2048 {
            return Ok(AlgorithmId::Rsa2048);
        }
        return simple_error!("Unknown rsa bits: {}", public_key_bits);
    }
    if public_key_info.algorithm.oid == ECC {
        if let Some(any) = &public_key_info.algorithm.parameters {
            let any_parameter_der = opt_result!(any.to_der(), "Bad any parameter: {}");
            let any_parameter_oid = opt_result!(ObjectIdentifier::from_der(&any_parameter_der), "Bad any parameter der: {}");
            if any_parameter_oid == ECC_P256 {
                return Ok(AlgorithmId::EccP256);
            }
            if any_parameter_oid == ECC_P384 {
                return Ok(AlgorithmId::EccP384);
            }
            return simple_error!("Unknown any parameter oid: {}", any_parameter_oid);
        }
    }
    simple_error!("Unknown algorithm: {}", public_key_info.algorithm.oid)
}

pub fn slot_equals(slot_id: &SlotId, slot: &str) -> bool {
    get_slot_id(slot).map(|sid| &sid == slot_id).unwrap_or(false)
}

pub fn to_slot_hex(slot: &SlotId) -> String {
    let slot_id: u8 = (*slot).into();
    format!("{:x}", slot_id)
}

pub fn get_slot_id(slot: &str) -> XResult<SlotId> {
    let slot_lower = slot.to_lowercase();
    Ok(match slot_lower.as_str() {
        "9a" | "auth" | "authentication" => SlotId::Authentication,
        "9c" | "sign" | "signature" => SlotId::Signature,
        "9d" | "keym" | "keymanagement" => SlotId::KeyManagement,
        "9e" | "card" | "cardauthentication" => SlotId::CardAuthentication,
        "r1" | "82" => SlotId::Retired(RetiredSlotId::R1),
        "r2" | "83" => SlotId::Retired(RetiredSlotId::R2),
        "r3" | "84" => SlotId::Retired(RetiredSlotId::R3),
        "r4" | "85" => SlotId::Retired(RetiredSlotId::R4),
        "r5" | "86" => SlotId::Retired(RetiredSlotId::R5),
        "r6" | "87" => SlotId::Retired(RetiredSlotId::R6),
        "r7" | "88" => SlotId::Retired(RetiredSlotId::R7),
        "r8" | "89" => SlotId::Retired(RetiredSlotId::R8),
        "r9" | "8a" => SlotId::Retired(RetiredSlotId::R9),
        "r10" | "8b" => SlotId::Retired(RetiredSlotId::R10),
        "r11" | "8c" => SlotId::Retired(RetiredSlotId::R11),
        "r12" | "8d" => SlotId::Retired(RetiredSlotId::R12),
        "r13" | "8e" => SlotId::Retired(RetiredSlotId::R13),
        "r14" | "8f" => SlotId::Retired(RetiredSlotId::R14),
        "r15" | "90" => SlotId::Retired(RetiredSlotId::R15),
        "r16" | "91" => SlotId::Retired(RetiredSlotId::R16),
        "r17" | "92" => SlotId::Retired(RetiredSlotId::R17),
        "r18" | "93" => SlotId::Retired(RetiredSlotId::R18),
        "r19" | "94" => SlotId::Retired(RetiredSlotId::R19),
        "r20" | "95" => SlotId::Retired(RetiredSlotId::R20),
        _ => return simple_error!("Unknown slot: {}", slot),
    })
}