use rust_util::{opt_result, XResult};
use yubico_manager::hmacmode::HmacKey;
use yubico_manager::sec::hmac_sha1;

fn main() -> XResult<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.len() != 2 && args.len() != 3 {
        println!("cargo r --example hmac_sha1 <hmac_key_hex;20bytes> <challenge_hex> [variable;bool]");
        return Ok(());
    }

    let hmac_key_bytes = opt_result!(hex::decode(&args[0]), "Decode hmac key hex failed: {}");
    let challenge_bytes = opt_result!(hex::decode(&args[1]), "Decode challenge hex failed: {}");
    let variable = if args.len() == 3 { "true" == &args[2] } else { false };

    let hmac_key = HmacKey::from_slice(&hmac_key_bytes);

    let mut challenge = [0; 64];
    if variable && challenge_bytes.last() == Some(&0) {
        challenge = [0xff; 64];
    }
    (&mut challenge[..challenge_bytes.len()]).copy_from_slice(&challenge_bytes);

    let hmac_sha_result = hmac_sha1(&hmac_key, &challenge);

    println!("Variable: {}", variable);
    println!("Hmac challenge: {}", hex::encode(&challenge));
    println!("Hmac_Sha1: {}", hex::encode(&hmac_sha_result));
    Ok(())
}