use clap::{App, ArgMatches, SubCommand};

use jwt::{AlgorithmType, Header, ToBase64};
use rust_util::util_clap::{Command, CommandError};
use rust_util::XResult;
use serde_json::{Map, Value};

use crate::cmd_sign_jwt_piv::{build_jwt_parts, merge_header_claims, merge_payload_claims, print_jwt_token};
use crate::ecdsautil::parse_ecdsa_to_rs;
use crate::keyutil::parse_key_uri;
use crate::{cmd_hmac_decrypt, cmd_sign_jwt_piv, cmdutil, util};
use crate::util::base64_decode;

const SEPARATOR: &str = ".";

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "sign-jwt-se"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        let app = SubCommand::with_name(self.name()).about("Sign JWT(SE) subcommand")
            .arg(cmdutil::build_key_uri_arg())
            .arg(cmdutil::build_json_arg());
        cmd_sign_jwt_piv::fill_sign_jwt_app_args(app)
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let private_key = opt_value_result!(
            sub_arg_matches.value_of("key"),
            "Private key PKCS#8 DER base64 encoded or PEM"
        );
        let private_key = cmd_hmac_decrypt::try_decrypt(&mut None, private_key)?;
        let key_uri = parse_key_uri(&private_key)?;
        let se_key_uri = key_uri.as_secure_enclave_key()?;
        debugging!("Secure enclave key URI: {:?}", se_key_uri);

        let (header, payload, jwt_claims) = build_jwt_parts(sub_arg_matches)?;

        let token_string = sign_jwt(&se_key_uri.private_key, header, &payload, &jwt_claims)?;
        print_jwt_token(json_output, token_string);

        Ok(None)
    }
}

fn sign_jwt(
    private_key: &str,
    mut header: Header,
    payload: &Option<String>,
    claims: &Map<String, Value>,
) -> XResult<String> {
    header.algorithm = AlgorithmType::Es256;
    debugging!("Header: {:?}", header);
    debugging!("Claims: {:?}", claims);

    let header = opt_result!(header.to_base64(), "Header to base64 failed: {}");
    let claims = merge_payload_claims(payload, claims)?;
    let tobe_signed = merge_header_claims(header.as_bytes(), claims.as_bytes());

    let private_key_representation = base64_decode(private_key)?;
    let signed_data_der =
        swift_secure_enclave_tool_rs::private_key_sign(&private_key_representation, &tobe_signed)?;

    let signed_data = parse_ecdsa_to_rs(signed_data_der.as_slice())?;

    let signature = util::base64_encode_url_safe_no_pad(&signed_data);

    Ok([&*header, &*claims, &signature].join(SEPARATOR))
}
