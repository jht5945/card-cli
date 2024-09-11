# card-cli

> FIDO(U2F, WebAuthn), YubiKey, OpenPGP command line tool

Install:
```shell
cargo install --git https://git.hatter.ink/hatter/card-cli.git
```

Compile without features:
```shell
cargo build --release --no-default-features
```

# PGP

## encrypt & decrypt

sample encrypt public key
```
-----BEGIN PUBLIC KEY-----
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
-----END PUBLIC KEY-----
```

encrypt
```shell
$ openssl rsautl -encrypt -pubin -inkey enc_key.pem -in test.txt -out enc.txt -pkcs

OR

$ openssl pkeyutl -encrypt -inkey enc_key.pem -pubin -in a.txt -out enc.txt
```

decrypt
```shell
$ card-cli pgp-card-decrypt -c $(cat enc.txt | xxd -ps -c 11111)

OR

$ card-cli piv-decrypt -s r3 -c "$(cat enc.txt | base64)"
```

## sign & verify

sign
```shell
$ card-cli pgp-card-sign -2 $(shasum -a 256 test.txt | awk '{print $1}')

OR

$ card-cli pgp-card-sign --in test.txt --use-sha256
```

verify
```shell
$ openssl dgst -sha256 -verify sign_key.pem -signature sig test.txt 
Verified OK
```

# sample public keys

```
[INFO ] Authentication fingerprint: EB0A43A10BFC6E58323F7650BA42AE533FDCE10E
[INFO ] Authentication public key sha256: ac97c7f9f500f3fbab635536096311c62698f8c22abd9e9687de7893932bc15b
[INFO ] Authentication public key: -----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA8Kg5fg47YilT/xFOZ7xK
17T47cfwzS6L/4IRtTjcygvmOVSdOISihQxVfsygpxhThRQ3pjqhFGqH9LUIpry/
a8hWfPMZYolYywBvdx5S6UGDUeRf2zLcRYrQo+Fs9oxdhxPE05HhWl9L5ORn4HWz
RZSkNfh7PDKPJRUaJV85uB6Fyvt0GGY14pmINZ7NRLLi2ubYBlp3CLSh7XdleVE8
/Q6gya501INhXUksuwHXdPYtcXF3l+VIdMc6YJTxivFLtujqiEAfEwauuv+1GzsN
ZDOg6JfSc+1d7iZMixU4RrKtzM57ZwGX0bAK3MQdP6iT20DOYq/BDJTXJuhQBWgE
6pIDiTJF4q/If0ZLxU+kxstAEg0fuD+wOg/+4W1BSn5D3hSdvVOxgj3hWtPudAVp
QucP8LKnq5B0oy4LdGqXXAQYJ2Q+ln0N9By2T8N/P37HOsR7yJLl8cM2FptCoo4x
ViGzmIbir8EyZ6VQmoi8fqOP4x9nH5XeNA2JCVLEc0o6n5PJ4IitYYCb0NGOPTHV
FEz2qzxkQDJxS5oC7GddWQB/pa4Jq0EL9dEabB2oPyvYBAmmE0HzZWLl3T1kR1dJ
fAXuqgShFcZLXa1SFUpLzlJi3jARuxoaUeHnKP3xeAd8o5WPBwzXM7LL47nTueNa
uFZKwHs/e9x4EszQ/qFo2uECAwEAAQ==
-----END PUBLIC KEY-----
[INFO ] Encryption fingerprint: E48EC98FE6CAE85AAFD5A68AC37A909EAF1BFB00
[INFO ] Encryption public key sha256: de5a99c239a82adf039982cb6319abcb95f44cfc76a5027ae6f7819cfc5fde7c
[INFO ] Encryption public key: -----BEGIN PUBLIC KEY-----
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
-----END PUBLIC KEY-----
[INFO ] Signature fingerprint: 6FAFC0E0170985AA71545483C794B1646A886CD6
[INFO ] Signature public key sha256: d65831b0316a03828eeb31fe6a51e6eec59e7092eb6d3477404ad2f5fa08e903
[INFO ] Signature public key: -----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7kVYTHxFjZD9kT+w97B
GiHfqlyoulJ10cRqaWwX3/mZKfoeGJkBDglFnLfgtHhXivPqRSn73sCX6M0HCzSq
9M/drkms/H8cecM08SoZdZTM0TVr/c8w0ZA7Ipoder9K/9LdGpIgoc3qa8hdY2nH
TwGYJ53aQv32neOcg3p/vzqdzgmwbk4JLjcIMhOuTUj4xM8OMnkxRpyy9+Ghi22X
oZXDxu8meI2Pc8jM+zpRYb0wd06dd231m03CK80LAwSvIn7dGFAr+xTF5XKopXHY
vuT+9SshszbP4+pSqbEHZhJOX1/os+Uo8KKfysifJBKfKCVvVWho8QCWoXgiNuOJ
3cYoThfWwUpIS1S51el/fPPSk3K295jlZAON9yEszdzKHGVGOrtJ7e9XSxKIXqhG
us2XA14eMvhQdaOgd/bscXIYe4YzqvaqvVRiDUP8bzA+4w0ctB0w9HRFGK5lajTn
/QQvkKP9JQXm6Tb2GB+wjuU3wPXhKRWscEzbHVwMq2WiaYH5vWVhHI6lbqXcWkvZ
i2gZXQPyrAKzUau1Z2lBN2xi2cv5+9JJth5pHebuLOWbuf1WV4nR1fdSNdG7GGmj
G951w/1bTqIlzN4Vl6kdore4u45U4kO4Xf7Hq8b8k8ys107ENpgO7lB9KLoMMFKS
vjG+EPEF3g8ywKaS8mZQX+sCAwEAAQ==
-----END PUBLIC KEY-----
```

# piv-ecdh

```shell
$ card-cli piv-ecdh --public-256 --public-key-point-hex 04dd3eebd906c9cf00b08ec29f7ed61804d1cc1d1352d9257b628191e08fc3717c4fae3298cd5c4829cec8bf3a946e7db60b7857e1287f6a0bae6b3f2342f007d0 --json
{
  "epk_point_hex": "04bbb6a458e81d2c646587118abfb029ff715db366f92a1d0468887f9947f176c11961eccebd5b9cbbb8b67e33fa8d3f0010a4aaf5010d0f419f1f99b4c2d7aa56",
  "pk_point_hex": "04dd3eebd906c9cf00b08ec29f7ed61804d1cc1d1352d9257b628191e08fc3717c4fae3298cd5c4829cec8bf3a946e7db60b7857e1287f6a0bae6b3f2342f007d0",
  "shared_secret_hex": "58069f1b2ce85c4f2232070567bef99f71b45f69ab321c4c782e599813b56f25"
}

$ card-cli piv-ecdh --private --slot 82 --epk 04bbb6a458e81d2c646587118abfb029ff715db366f92a1d0468887f9947f176c11961eccebd5b9cbbb8b67e33fa8d3f0010a4aaf5010d0f419f1f99b4c2d7aa56 --json
[WARN ] Get slot: 82 meta data failed
{
  "shared_secret_hex": "58069f1b2ce85c4f2232070567bef99f71b45f69ab321c4c782e599813b56f25"
}
```

# piv-ecsign

```shell
$ card-cli piv-ecsign -s 82 --hash-hex 8f25018489d6fe0dec34a352314c38dc146247b7de65735790f4398a92afa84b --json

{
  "hash_hex": "8f25018489d6fe0dec34a352314c38dc146247b7de65735790f4398a92afa84b",
  "signed_data_base64": "MEUCICdes5Y0Id7KBNL23ZsTXXXGAzmsWYyDa6szQwjCxhCJAiEAhJotD2dPK/fWNjNrwkrPd0F20MpGgIY3WiKDR7YgJbk=",
  "signed_data_hex": "30450220275eb3963421deca04d2f6dd9b135d75c60339ac598c836bab334308c2c61089022100849a2d0f674f2bf7d636336bc24acf774176d0ca468086375a228347b62025b9",
  "slot": "82"
}
```

# import private key to PIV card &amp; generate certificate

```shell
$ ykman piv keys import --pin-policy NEVER --touch-policy CACHED 82 private_key.pem
```

| Parameter | Description                                                      |
| ---- |------------------------------------------------------------------|
| --pin-policy | \[ DEFAULT \| NEVER \| ONCE \| ALWAYS \] PIN policy for slot     |
| --touch-policy | \[ DEFAULT \| NEVER \| ALWAYS \| CACHED \] touch policy for slot |

```shell
$ ykman piv certificates generate 82 public_key.pem -s 'O=age-plugin-yubikey,OU=0.3.3,CN=hatter-yk'
```

# age

## pgp-age-address

```shell
$ card-cli pgp-age-address
[INFO ] Found 1 card(s)
[OK   ] Found card #0: Ok(ApplicationIdentifier { application: 1, version: 772, manufacturer: 6, serial: 370378374 })
[OK   ] Age address: age10l464vxcpnkjguctvylnmp5jg4swhncn4quda0qxta3ud8pycc0qeaj2te
```

# sign-jwt

Sign a JWT:
```shell
card-cli sign-jwt -s r3 \
    -C iss:****** \
    -C sub:****** \
    -C aud:client_gard****** \
    -K KEY=ID \
    --jti \
    --validity 10m --json
```

# SSH CA

## Generate SSH root CA

```shell
card-cli ssh-pub-key --ca -s r15
```

Outputs:
```
cert-authority,principals="root" ecdsa-sha2-nistp384 AAAAE2VjZHNh****** Yubikey-PIV-R15
```

> `principals` can be multiple items, split by `,`, e.g. `root,hatterink`

## Generate SSH user CA

```shell
ssh-keygen -f id_user

card-cli ssh-piv-cert --pub id_user.pub -s r15
```

Show SSH CA cert details:
```shell
ssh-keygen -L -f id_user-cert.pub
```

SSH to server:
```shell
ssh -i id_user root@example.com
```


<br><br>

Downloads:
* https://developers.yubico.com/yubikey-manager/

<br>

Related projects:
* https://crates.io/crates/openpgp-card-tools
* https://github.com/sekey/sekey
* https://github.com/str4d/age-plugin-yubikey
