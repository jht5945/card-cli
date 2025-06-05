use std::fs;
use std::fs::File;
use std::io::Read;

use clap::ArgMatches;
use rust_util::XResult;

use crate::digestutil::DigestAlgorithm;


pub fn get_sha256_digest_or_hash(sub_arg_matches: &ArgMatches) -> XResult<Vec<u8>> {
    get_sha256_digest_or_hash_with_file_opt(sub_arg_matches, &None)
}

pub fn get_digest_or_hash(sub_arg_matches: &ArgMatches, digest: DigestAlgorithm) -> XResult<Vec<u8>> {
    get_digest_or_hash_with_file_opt(sub_arg_matches, &None, digest)
}

pub fn get_sha256_digest_or_hash_with_file_opt(sub_arg_matches: &ArgMatches, file_opt: &Option<String>) -> XResult<Vec<u8>> {
    get_digest_or_hash_with_file_opt(sub_arg_matches, file_opt, DigestAlgorithm::Sha256)
}

pub fn get_digest_or_hash_with_file_opt(sub_arg_matches: &ArgMatches, file_opt: &Option<String>, digest: DigestAlgorithm) -> XResult<Vec<u8>> {
    let file_opt = file_opt.as_ref().map(String::as_str);
    if let Some(file) = sub_arg_matches.value_of("file").or(file_opt) {
        let metadata = opt_result!(fs::metadata(file), "Read file: {} metadata filed: {}", file);
        if !metadata.is_file() {
            return simple_error!("Not a file: {}", file);
        }
        if metadata.len() > 1024 * 1024 * 1024 {
            return simple_error!("File: {} too large", file);
        }
        if metadata.len() > 100 * 1024 * 1024 {
            warning!("File: {} is a large file, size: {} byte(s)", file, metadata.len());
        }
        let mut f = opt_result!(File::open(file), "Open file: {} failed: {}", file);
        let mut content = vec![];
        opt_result!(f.read_to_end(&mut content), "Read file: {} failed: {}", file);
        Ok(digest.digest(&content))
    } else if let Some(input) = sub_arg_matches.value_of("input") {
        Ok(digest.digest_str(input))
    } else if let Some(hash_hex) = sub_arg_matches.value_of("hash-hex") {
        Ok(opt_result!(hex::decode(hash_hex), "Parse hash-hex failed: {}"))
    } else {
        simple_error!("--file, --input or --hash-hex must assign at least one")
    }
}