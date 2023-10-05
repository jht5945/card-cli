use openssl::bn::{BigNum, BigNumContext};

// modulus:
//     00:af:49:c0:89:17:c1:83:78:17:f9:a1:c3:02:54:
//     b6:c1:2b:d2:34:94:31:c8:76:fe:59:8a:e9:dc:9e:
//     b2:ca:75:99:8b:58:2e:1a:81:a9:14:5f:43:9b:9c:
//     42:37:56:d5:56:6d:0f:65:a3:77:62:06:de:59:0b:
//     1c:71:3b:22:8a:e2:06:bd:96:76:f3:6f:fb:fe:c0:
//     9c:03:aa:14:e3:1e:3d:10:9a:9f:8d:85:21:08:da:
//     68:82:05:f1:31:d0:98:b3:2d:02:a7:0c:c1:f1:2d:
//     3b:63:37:a4:0a:cb:4e:3b:4e:70:40:fb:6c:94:bb:
//     23:48:fb:90:09:ab:e8:05:4f
// publicExponent: 5 (0x5)
// privateExponent:
//     23:0e:c0:1b:6b:26:b3:e4:d1:98:53:8d:66:dd:be:
//     26:a2:5d:3d:b7:3d:28:17:cc:78:4e:fb:92:86:23:
//     c2:17:85:1b:de:6f:9e:e6:bb:6a:79:73:eb:ec:0d:
//     3e:44:91:11:49:03:14:53:e4:ad:34:92:de:9b:d2:
//     7d:0b:d3:b5:0b:3c:ed:f9:db:96:28:cb:08:34:16:
//     d9:68:20:52:54:bd:47:b3:2d:35:4c:ad:bf:05:45:
//     2e:0a:b7:30:34:58:c8:2b:35:86:c2:84:c1:0f:06:
//     5b:95:72:4f:d8:5e:38:88:4e:43:5c:ad:57:fa:d0:
//     56:f6:12:6b:4f:76:26:c5
// prime1:
//     00:ea:5f:f0:9b:37:7f:ca:92:fb:88:98:58:84:39:
//     76:e4:6f:d6:ab:b2:3c:9f:26:54:16:16:53:68:24:
//     56:74:ea:f6:41:8b:20:0a:90:7e:6b:7d:da:8f:19:
//     a2:42:e0:73:cf:de:3c:02:d8:92:c7:36:be:16:2a:
//     56:12:0a:35:5b
// prime2:
//     00:bf:76:27:19:f5:84:d9:71:da:33:91:6c:1d:39:
//     d0:92:1a:d3:6f:0b:46:66:95:f9:a9:f8:48:68:38:
//     ea:55:f1:d4:13:6b:e5:35:99:ad:76:9d:be:bd:4e:
//     d9:4e:96:ac:d5:0a:b4:29:31:4a:0d:da:d8:17:09:
//     9b:0c:8f:0e:1d
// exponent1:
//     00:8c:9f:f6:c3:87:b3:13:24:fd:51:f5:01:e8:ef:
//     47:55:dc:b4:00:9e:24:5f:7d:65:a6:da:32:0b:49:
//     00:ac:8c:fa:27:53:79:9f:f0:4b:da:18:4f:ef:75:
//     c7:c1:b9:df:16:52:24:01:b5:24:dd:ed:a5:40:7f:
//     cd:3e:06:20:03
// exponent2:
//     72:e0:7d:dc:60:1c:82:77:82:eb:bd:a7:44:bc:49:
//     f1:43:4b:a9:06:c3:d7:26:c8:ff:94:f8:3e:88:8c:
//     99:f7:7f:3e:da:56:53:5c:34:e0:c5:0c:0b:2f:4f:
//     2f:27:34:7f:d3:38:e5:83:f9:3b:83:4e:74:38:f6:
//     a1:22:a2:11
// coefficient:
//     00:c2:ee:8a:96:0e:f3:5f:d5:31:86:c7:1f:9a:9c:
//     b4:27:5b:04:82:e2:56:e4:2d:cb:bd:5f:62:ec:e9:
//     d5:8e:5a:87:47:ec:bf:94:b3:96:d6:15:c7:51:3a:
//     c0:a1:5b:63:33:ad:32:60:46:51:6c:7a:e4:38:7e:
//     d4:9e:42:d5:35
fn main() {
    let p = BigNum::from_hex_str("00ea5ff09b377fca92fb889858843976e46fd6abb23c9f265416165368245674eaf6418b200a907e6b7dda8f19a242e073cfde3c02d892c736be162a56120a355b").unwrap();
    let q = BigNum::from_hex_str("00bf762719f584d971da33916c1d39d0921ad36f0b466695f9a9f8486838ea55f1d4136be53599ad769dbebd4ed94e96acd50ab429314a0ddad817099b0c8f0e1d").unwrap();
    let e = BigNum::from_u32(5).unwrap();

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

    let rsa_crt = crate::rsautil::RsaCrt::from(p, q, e);
}