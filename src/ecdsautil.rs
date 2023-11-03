use ecdsa::VerifyingKey;
use p256::NistP256;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p384::NistP384;
use ecdsa::Signature;
use rust_util::XResult;

#[derive(Copy, Clone)]
pub enum EcdsaAlgorithm {
    P256,
    P384,
}

macro_rules! ecdsa_verify_signature {
    ($algo: tt, $pk_point: tt, $prehash: tt, $signature: tt) => ({
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

pub fn ecdsaverify(algo: EcdsaAlgorithm, pk_point: &[u8], prehash: &[u8], signature: &[u8]) -> XResult<()> {
    match algo {
        EcdsaAlgorithm::P256 => ecdsa_verify_signature!(NistP256, pk_point, prehash, signature),
        EcdsaAlgorithm::P384 => ecdsa_verify_signature!(NistP384, pk_point, prehash, signature),
    }
    Ok(())
}