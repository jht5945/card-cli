use openssl::encrypt::Encrypter;
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};
use rust_util::information;

fn main() {
    let data = b"hello, world!";
    let rsa = Rsa::public_key_from_pem(
        b"-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApUM8M+QRMUw0dIvXISFx
43j4h9CK38Y9HD6kPcc3Z0dCGPiFy7Ze0OQebPWHyUZ2YmqsdyzFuOQuV9P2pxxj
/WLIgRqZV8Jk8tWhtAjOOvm0MTc2rg+EJHfa+zhX4eFEMsj4DvQBMJDXiKnpXTM/
j7oMKpIUQHqfXBwsEJHLmHZTLeEBEYKcZXTAmuu3WdxK5jvEc02Xt2hZ1fBs0M9e
/2EMe3t69aH4/rabiBjF2h9Jde15wrJMxXaCCWJqYhbBS0CJ3BdjkAqOIpcqPXva
xiJN1pNpK8ejA9Q4Nmx7pxnvfv+hCPkWXZS3r/BWZ9lFZc8uErQEbB4gLgko8jOl
fQF7cYqtZEs69qY8nnIUBsqZYfAp+bQd2xCFSbEZAl+OrtGzfVjD9YFMPy02+xRg
v2N3KT3KHHvuU7WxrvffrshP2fwDuG2MBlmcq1suAKxA0cYPSyajceEqw/3ogSp7
7SYx41rT8EWLmTvU0CHzCsuf/O7sDWZRfxatAzWhBBhnKCPqzizpOQOqm8XhCt74
FfnabPpHM9XUjoQIPrTssyS3eWqynzJiAqez6v2LK2fhL7IkcLtvt5p59Y+KY4I6
YQ09iUh7lKJHRhkgTomUurJHieVHMWFGIHofEC+nU6pGIUh0P7Nr0Gz45GJTwWGd
hW53WfImja+b5kwwyqUikyMCAwEAAQ==
-----END PUBLIC KEY-----");
    let pub_key = PKey::from_rsa(rsa.unwrap()).unwrap();

    // Encrypt the data with RSA PKCS1
    let mut encrypter = Encrypter::new(&pub_key).unwrap();
    encrypter.set_rsa_padding(Padding::PKCS1).unwrap();
    // Create an output buffer
    let buffer_len = encrypter.encrypt_len(data).unwrap();
    let mut encrypted = vec![0; buffer_len];
    // Encrypt and truncate the buffer
    let encrypted_len = encrypter.encrypt(data, &mut encrypted).unwrap();
    encrypted.truncate(encrypted_len);

    information!("Clear text: {}", String::from_utf8_lossy(data));
    information!("Encrypted message base64: {}", base64::encode(&encrypted));
}