use std::collections::BTreeMap;

use clap::ArgMatches;
use rust_util::XResult;
use yubico_manager::hmacmode::HmacKey;
use yubico_manager::sec::hmac_sha1;

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
    let hex_sha1 = iff!(sha1_output, Some(crate::digest::sha1_bytes(result)), None);
    let hex_sha256 = iff!(sha256_output, Some(crate::digest::sha256_bytes(result)), None);
    let hex_sha384 = iff!(sha384_output, Some(crate::digest::sha384_bytes(result)), None);
    let hex_sha512 = iff!(sha512_output, Some(crate::digest::sha512_bytes(result)), None);

    if json_output {
        let mut json = BTreeMap::<&'_ str, String>::new();
        json.insert("challenge_hex", hex::encode(challenge_bytes));
        json.insert("response_hex", hex_string);
        hex_sha1.map(|hex_sha1| json.insert("response_sha1_hex", hex::encode(hex_sha1)));
        hex_sha256.map(|hex_sha256| json.insert("response_sha256_hex", hex::encode(hex_sha256)));
        hex_sha384.map(|hex_sha384| json.insert("response_sha384_hex", hex::encode(hex_sha384)));
        hex_sha512.map(|hex_sha512| json.insert("response_sha512_hex", hex::encode(hex_sha512)));

        println!("{}", serde_json::to_string_pretty(&json).expect("Convert to JSON failed!"));
    } else {
        success!("Challenge HEX: {}", hex::encode(challenge_bytes));
        success!("Response HEX: {}", hex_string);
        if let Some(hex_sha256) = hex_sha256 { success!("Response SHA256 HEX: {}", hex::encode(hex_sha256)); }
        if let Some(hex_sha384) = hex_sha384 { success!("Response SHA384 HEX: {}", hex::encode(hex_sha384)); }
        if let Some(hex_sha512) = hex_sha512 { success!("Response SHA512 HEX: {}", hex::encode(hex_sha512)); }
    }
}

