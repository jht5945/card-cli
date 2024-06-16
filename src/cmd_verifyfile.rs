use std::fs;
use std::ops::Add;
use std::time::{Duration, SystemTime};

use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;
use x509_parser::public_key::PublicKey;
use x509_parser::time::ASN1Time;

use crate::argsutil;
use crate::digest::sha256_bytes;
use crate::signfile::{SignFileRequest, SIMPLE_SIG_SCHEMA, SimpleSignFile};
use crate::util::base64_decode;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "verify-file" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV verify(with SHA256) subcommand")
            .arg(Arg::with_name("file").short("f").long("file").takes_value(true).required(false).help("Input file"))
            .arg(Arg::with_name("sign-file").short("S").long("sign-file").takes_value(true).help("Sign file"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        util_msg::set_logger_std_out(false);

        let sign_file = sub_arg_matches.value_of("sign-file").map(ToString::to_string).unwrap();
        let sign_file_content = opt_result!(fs::read_to_string(&sign_file), "Read file: {}, failed: {}", sign_file);
        let simple_sign_file: SimpleSignFile = opt_result!(serde_json::from_str(&sign_file_content), "Parse file: {}, failed: {}", sign_file);

        if SIMPLE_SIG_SCHEMA != simple_sign_file.schema {
            return simple_error!("File: {} format error: bad schema", sign_file);
        }
        information!("File name: {}", simple_sign_file.filename.as_deref().unwrap_or("<none>"));
        information!("Digest: {}", &simple_sign_file.digest);
        let sign_time = SystemTime::UNIX_EPOCH.add(Duration::from_millis(simple_sign_file.timestamp as u64));
        let format_time = simpledateformat::fmt("yyyy-MM-dd HH:mm:ssz").unwrap().format_local(sign_time);
        information!("Timestamp: {}", format_time);
        if let Some(attributes) = &simple_sign_file.attributes {
            information!("Attributes: {}", attributes);
        }
        if let Some(comment) = &simple_sign_file.comment {
            information!("Comment: {}", comment);
        }
        let file_digest = argsutil::get_sha256_digest_or_hash_with_file_opt(sub_arg_matches, &simple_sign_file.filename)?;
        debugging!("File digest: {}", hex::encode(&file_digest));
        let file_digest_with_prefix = format!("sha256-{}", hex::encode(&file_digest));
        if file_digest_with_prefix != simple_sign_file.digest {
            failure!("File digest mismatch\nexpected: {}\nactual  : {}", simple_sign_file.digest, file_digest_with_prefix);
            return simple_error!("File digest mismatch");
        }

        let sign_file_request = SignFileRequest {
            filename: simple_sign_file.filename.clone(),
            digest: file_digest.clone(),
            timestamp: simple_sign_file.timestamp,
            attributes: simple_sign_file.attributes.clone(),
            comment: simple_sign_file.comment.clone(),
        };
        let tobe_signed = sign_file_request.get_tobe_signed();
        debugging!("Tobe signed: {}", hex::encode(&tobe_signed));
        let tobe_signed_digest = sha256_bytes(&tobe_signed);
        debugging!("Tobe signed digest: {}", hex::encode(&tobe_signed_digest));

        if simple_sign_file.signatures.is_empty() {
            failure!("No signatures found.");
            return simple_error!("No signatures found");
        }
        information!("Found {} signature(s)", simple_sign_file.signatures.len());
        for (i, signature) in simple_sign_file.signatures.iter().enumerate() {
            // check tobe_signed_digest by signature_bytes
            information!("Check signature #{} of {}", i, simple_sign_file.signatures.len());
            let signature_bytes = opt_result!(base64_decode(&signature.signature), "Parse signatures.signature failed: {}");
            debugging!("Signature #{}: {}", i, hex::encode(&signature_bytes));

            let mut cert_pems = vec![];
            for certificate in &signature.certificates {
                let (_, cert_pem) = opt_result!(parse_x509_pem(certificate.as_bytes()), "Parse certificate PEM failed: {}");
                cert_pems.push(cert_pem);
            }
            let mut certificates = vec![];
            for cert_pem in &cert_pems {
                let (_, cert) = opt_result!(parse_x509_certificate(&cert_pem.contents), "Parse certificate failed: {}");
                debugging!("Found certificate, subject: {}, issuer : {}", cert.subject.to_string(), cert.issuer.to_string());
                let asn1_timestamp = opt_result!(ASN1Time::from_timestamp(simple_sign_file.timestamp/1000), "ASN1Time failed: {}");
                if !cert.validity.is_valid_at(asn1_timestamp) {
                    failure!("Certificate validity is out of cate: {:?}", cert.validity);
                    return simple_error!("Certificate is invalid: {}, out of date", cert.subject.to_string());
                }
                certificates.push(cert);
            }
            let certificates_count = certificates.len();
            for i in 0..certificates.len() {
                let cert1 = &certificates[i];
                let cert2_public_key = iff!(i < certificates_count -1, Some(certificates[i + 1].public_key()), None);
                match cert1.verify_signature(cert2_public_key) {
                    Ok(_) => success!("Cert #{}: {} verify success", i, cert1.subject.to_string()),
                    Err(e) => failure!("Cert #{}: {} verify failed: {}", i, cert1.subject.to_string(), e),
                }
            }

            let leaf_certificate = &certificates[0];
            let leaf_public_key = opt_result!(leaf_certificate.public_key().parsed(), "Parse leaf certificate public key failed: {}");
            match leaf_public_key {
                // PublicKey::RSA(_) => {}
                PublicKey::EC(ec_point) => {
                    if ec_point.key_size() != 384 {
                        return simple_error!("Current only support p384");
                    }
                    use p384::ecdsa::{DerSignature, signature::hazmat::PrehashVerifier, VerifyingKey};
                    let p384_verifying_key = opt_result!(VerifyingKey::from_sec1_bytes(ec_point.data()), "Parse public key failed: {}");
                    let sig = opt_result!(DerSignature::from_bytes(&signature_bytes), "Parse signature failed: {}");
                    match p384_verifying_key.verify_prehash(&tobe_signed_digest, &sig) {
                        Ok(_) => success!("Verify leaf certificate signature success"),
                        Err(e) => return simple_error!("Verify leaf certificate signature failed: {}", e),
                    }
                }
                _ => return simple_error!("Not supported public key: {:?}", leaf_public_key),
            }
        }

        Ok(None)
    }
}
