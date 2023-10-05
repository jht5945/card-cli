use openpgp::crypto::Password;
use openpgp::Packet;
use openpgp::packet::Key;
use openpgp::packet::key::{PrimaryRole, SecretKeyMaterial, SecretParts};
use openpgp::parse::{PacketParser, PacketParserResult, Parse};
use openssl::bn::{BigNum, BigNumContext};
use rust_util::XResult;
use sequoia_openpgp as openpgp;
use sequoia_openpgp::packet::key::SubordinateRole;

fn main() -> XResult<()> {
    let pass = std::env::var("PASS").expect("PASS is not set");
    let password = Password::from(pass.as_str());

    let mut ppr = PacketParser::from_file("/Users/hatterjiang/key.asc")?;
    while let PacketParserResult::Some(pp) = ppr {
        // println!("{:?}", pp);
        if let Packet::SecretKey(sk) = &pp.packet {
            print_key(sk, &password);
        } else if let Packet::SecretSubkey(ssk) = &pp.packet {
            print_key2(ssk, &password);
        }
        // Start parsing the next packet, recursing.
        ppr = pp.recurse()?.1;
    }
    Ok(())
}

fn print_key(key: &Key<SecretParts, PrimaryRole>, password: &Password) {
    let is_encrypted = key.has_secret() && !key.has_unencrypted_secret();
    println!("\n\nFound key, has secret: {}, encrypted: {}, key id: {}, fingerprint: {}", key.has_secret(), is_encrypted, key.keyid(), key.fingerprint());
    println!(" - create time: {:?}", key.creation_time());
    println!(" - public key : {:?}", key.mpis());
    let a = key.clone().decrypt_secret(&password).unwrap();
    println!("----------- {:?}", a);
    if let Key::V4(key4) = a {
        let secret = key4.secret();
        if let SecretKeyMaterial::Unencrypted(unencrypted) = secret {
            unencrypted.map(|f| {
                // println!("<><> {:?}", f);
                if let openpgp::crypto::mpi::SecretKeyMaterial::RSA { d, p, q, u } = f {
                    println!(">>>> {:?}", d);
                    println!(">>>> {:?}", p);
                    println!(">>>> {:?}", q);
                    println!(">>>> {:?}", u);
                }
            });
        }
    }
}

fn print_key2(key: &Key<SecretParts, SubordinateRole>, password: &Password) {
    let is_encrypted = key.has_secret() && !key.has_unencrypted_secret();
    println!("\n\nFound key, has secret: {}, encrypted: {}, key id: {}, fingerprint: {}", key.has_secret(), is_encrypted, key.keyid(), key.fingerprint());
    println!(" - create time: {:?}", key.creation_time());
    println!(" - public key : {:?}", key.mpis());
    let decrypted_key = key.clone().decrypt_secret(&password).unwrap();
    if let Key::V4(key4) = decrypted_key {
        let secret = key4.secret();
        if let SecretKeyMaterial::Unencrypted(unencrypted) = secret {
            unencrypted.map(|f| {
                // println!("<><> {:?}", f);
                if let openpgp::crypto::mpi::SecretKeyMaterial::RSA { d, p, q, u } = f {
                    println!(">>>> {:?}", d);
                    println!(">>>> {:?}", p);
                    println!(">>>> {:?}", q);
                    println!(">>>> {:?}", u);
                    let p = BigNum::from_slice(p.value()).unwrap();
                    let q = BigNum::from_slice(q.value()).unwrap();
                    let e = BigNum::from_u32(65537).unwrap();

                    let mut n = BigNum::new().unwrap();
                    n.checked_mul(&p, &q, &mut BigNumContext::new().unwrap()).unwrap();
                    println!(">>>> n: {}", hex::encode(&n.to_vec()).to_uppercase());

                    let mut p_m1 = BigNum::from_slice(p.to_vec().as_slice()).unwrap();
                    p_m1.sub_word(1).unwrap();
                    let mut q_m1 = BigNum::from_slice(q.to_vec().as_slice()).unwrap();
                    q_m1.sub_word(1).unwrap();
                    let mut m = BigNum::new().unwrap();
                    m.checked_mul(&p_m1, &q_m1, &mut BigNumContext::new().unwrap()).unwrap();
                    println!(">>>> m: {}", hex::encode(&m.to_vec()).to_uppercase());

                    let mut d = BigNum::new().unwrap();
                    d.mod_inverse(&e, &m, &mut BigNumContext::new().unwrap()).unwrap();
                    println!(">>>> d: {}", hex::encode(&d.to_vec()).to_uppercase());

                    let mut dp = BigNum::new().unwrap();
                    dp.nnmod(&d, &p_m1, &mut BigNumContext::new().unwrap()).unwrap();
                    println!(">>>> dp: {}", hex::encode(&dp.to_vec()).to_uppercase());

                    let mut dq = BigNum::new().unwrap();
                    dq.nnmod(&d, &q_m1, &mut BigNumContext::new().unwrap()).unwrap();
                    println!(">>>> dq: {}", hex::encode(&dq.to_vec()).to_uppercase());

                    let mut qinv = BigNum::new().unwrap();
                    qinv.mod_inverse(&q, &p, &mut BigNumContext::new().unwrap()).unwrap();
                    println!(">>>> qinv: {}", hex::encode(&qinv.to_vec()).to_uppercase());
                }
            });
        }
    }
}