
macro_rules! piv_ecdh {
    ($p_algo: tt, $public_key_pem_opt: expr, $sub_arg_matches: expr, $json: expr, $json_output: expr) => ({
        use $p_algo::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
        use $p_algo::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
        let public_key;
        if let Some(public_key_pem) = $public_key_pem_opt {
            public_key = opt_result!(public_key_pem.parse::<PublicKey>(), "Parse public key failed: {}");
        } else {
            let public_key_point_hex = $sub_arg_matches.value_of("public-key-point-hex").unwrap_or_else(||
                failure_and_exit!("--public-key, --public-key-file or --public-key-point-hex must require one"));
            let public_key_point_bytes = opt_result!(hex::decode(public_key_point_hex), "Parse public key point hex failed: {}");
            let encoded_point = opt_result!(EncodedPoint::from_bytes(public_key_point_bytes), "Parse public key point failed: {}");
            public_key = PublicKey::from_encoded_point(&encoded_point).unwrap();
        };
        let public_key_encoded_point = public_key.to_encoded_point(false);

        let esk = EphemeralSecret::random(&mut OsRng);
        let epk = esk.public_key();
        let epk_compress_point = epk.to_encoded_point(true);
        let epk_point = PublicKey::from_encoded_point(&epk_compress_point).unwrap();
        let epk_uncompressed_point = epk_point.to_encoded_point(false);

        let shared_secret = esk.diffie_hellman(&public_key);
        if $json_output {
            $json.insert("shared_secret_hex", hex::encode(shared_secret.raw_secret_bytes()));
            $json.insert("epk_point_hex", hex::encode(epk_uncompressed_point.as_bytes()));
            $json.insert("pk_point_hex", hex::encode(public_key_encoded_point.as_bytes()));
        } else {
            information!("Shared secret: {}", hex::encode(shared_secret.raw_secret_bytes()));
            information!("EPK point: {}", hex::encode(epk_uncompressed_point.as_bytes()));
            information!("Public key point: {}", hex::encode(public_key_encoded_point.as_bytes()));
        }
    })
}

macro_rules! parse_private_and_ecdh {
    ($algo: tt, $private_key_bytes: tt, $ephemeral_public_key_bytes: tt) => ({
        use $algo::{SecretKey, PublicKey, ecdh::diffie_hellman, pkcs8::DecodePrivateKey};
        use spki::DecodePublicKey;
        let secret_key= SecretKey::from_pkcs8_der($private_key_bytes)?;
        let public_key = opt_result!(PublicKey::from_public_key_der(
                $ephemeral_public_key_bytes),"Parse ephemeral public key failed: {}");

        let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
        Ok(shared_secret.raw_secret_bytes().to_vec())
    })
}

pub fn parse_p256_private_and_ecdh(private_key_bytes: &[u8], ephemeral_public_key_bytes: &[u8]) -> XResult<Vec<u8>> {
    parse_private_and_ecdh!(p256, private_key_bytes, ephemeral_public_key_bytes)
}

pub fn parse_p384_private_and_ecdh(private_key_bytes: &[u8], ephemeral_public_key_bytes: &[u8]) -> XResult<Vec<u8>> {
    parse_private_and_ecdh!(p384, private_key_bytes, ephemeral_public_key_bytes)
}

pub fn parse_p521_private_and_ecdh(private_key_bytes: &[u8], ephemeral_public_key_bytes: &[u8]) -> XResult<Vec<u8>> {
    parse_private_and_ecdh!(p521, private_key_bytes, ephemeral_public_key_bytes)
}

use rust_util::XResult;
pub(crate) use piv_ecdh;