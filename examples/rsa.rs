use base64::Engine;
use rand::rngs::OsRng;
use rsa::pkcs1::LineEnding;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use spki::EncodePublicKey;

fn main() {
    let key = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
    let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
    println!("{}", pem.as_str());

    let key2 = RsaPrivateKey::from_pkcs8_pem(pem.as_ref()).unwrap();

    let pub_key = key2.to_public_key();
    let public_key_pem = pub_key.to_public_key_pem(LineEnding::LF).unwrap();
    println!("{}", public_key_pem);

    let n = pub_key.n();
    let e = pub_key.e();
    let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    println!("n: {}", url_safe.encode(&n.to_bytes_be()));
    println!("e: {}", url_safe.encode(&e.to_bytes_be()));
}
