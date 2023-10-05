use std::str::FromStr;

use rust_util::XResult;
use spki::der::{Decode, Encode};
use spki::{ObjectIdentifier, SubjectPublicKeyInfoOwned};
use x509_parser::prelude::FromDer;
use x509_parser::public_key::RSAPublicKey;
use yubikey::piv::{AlgorithmId, RetiredSlotId};
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

pub fn get_slot_id(slot: &str) -> XResult<SlotId> {
    Ok(match slot {
        "9a" => SlotId::Authentication,
        "9c" => SlotId::Signature,
        "9d" => SlotId::KeyManagement,
        "9e" => SlotId::CardAuthentication,
        "r1" | "R1" => SlotId::Retired(RetiredSlotId::R1),
        "r2" | "R2" => SlotId::Retired(RetiredSlotId::R2),
        "r3" | "R3" => SlotId::Retired(RetiredSlotId::R3),
        "r4" | "R4" => SlotId::Retired(RetiredSlotId::R4),
        "r5" | "R5" => SlotId::Retired(RetiredSlotId::R5),
        "r6" | "R6" => SlotId::Retired(RetiredSlotId::R6),
        "r7" | "R7" => SlotId::Retired(RetiredSlotId::R7),
        "r8" | "R8" => SlotId::Retired(RetiredSlotId::R8),
        "r9" | "R9" => SlotId::Retired(RetiredSlotId::R9),
        "r10" | "R10" => SlotId::Retired(RetiredSlotId::R10),
        "r11" | "R11" => SlotId::Retired(RetiredSlotId::R11),
        "r12" | "R12" => SlotId::Retired(RetiredSlotId::R12),
        "r13" | "R13" => SlotId::Retired(RetiredSlotId::R13),
        "r14" | "R14" => SlotId::Retired(RetiredSlotId::R14),
        "r15" | "R15" => SlotId::Retired(RetiredSlotId::R15),
        "r16" | "R16" => SlotId::Retired(RetiredSlotId::R16),
        "r17" | "R17" => SlotId::Retired(RetiredSlotId::R17),
        "r18" | "R18" => SlotId::Retired(RetiredSlotId::R18),
        "r19" | "R19" => SlotId::Retired(RetiredSlotId::R19),
        "r20" | "R20" => SlotId::Retired(RetiredSlotId::R20),
        _ => {
            let retired_slot_id = opt_result!(RetiredSlotId::from_str(slot), "Slot not found: {}");
            debugging!("Retried slot id: {}", retired_slot_id);
            SlotId::Retired(retired_slot_id)
        }
    })
}