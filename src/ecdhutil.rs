
macro_rules! piv_ecdh {
    ($p_algo: tt, $public_key_pem_opt: expr, $sub_arg_matches: expr, $json: expr, $json_output: expr) => ({
        use $p_algo::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
        use $p_algo::ecdh::EphemeralSecret;
        use $p_algo::{EncodedPoint, PublicKey};
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

pub(crate) use piv_ecdh;