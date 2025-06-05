use crate::cmd_sign_jwt_piv::{
    build_jwt_parts, fill_sign_jwt_app_args, merge_header_claims,
    merge_payload_claims, print_jwt_token,
};
use crate::ecdsautil::parse_ecdsa_to_rs;
use crate::keyutil::parse_key_uri;
use crate::{cmd_external_sign, cmdutil, util};
use clap::{App, ArgMatches, SubCommand};
use jwt::ToBase64;
use jwt::{AlgorithmType, Header};
use rust_util::util_clap::{Command, CommandError};
use rust_util::XResult;
use serde_json::{Map, Value};
use crate::pivutil::ToStr;

const SEPARATOR: &str = ".";

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "sign-jwt"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        let app = SubCommand::with_name(self.name())
            .about("Sign JWT subcommand")
            .arg(cmdutil::build_key_uri_arg().required(false))
            .arg(cmdutil::build_parameter_arg().required(false))
            .arg(cmdutil::build_pin_arg())
            .arg(cmdutil::build_serial_arg())
            .arg(cmdutil::build_json_arg());
        fill_sign_jwt_app_args(app)
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let (header, payload, jwt_claims) = build_jwt_parts(sub_arg_matches)?;
        let token_string = sign_jwt(header, &payload, &jwt_claims, sub_arg_matches)?;
        print_jwt_token(json_output, token_string);

        Ok(None)
    }
}

fn sign_jwt(
    mut header: Header,
    payload: &Option<String>,
    claims: &Map<String, Value>,
    sub_arg_matches: &ArgMatches,
) -> XResult<String> {
    let key = match sub_arg_matches.value_of("key") {
        Some(key) => key,
        None => match sub_arg_matches.value_of("parameter") {
            Some(parameter) => parameter,
            None => return simple_error!("Parameter --key or --parameter required"),
        }
    };
    let key_uri = parse_key_uri(key)?;

    let jwt_algorithm = key_uri.get_preferred_algorithm_type();

    header.algorithm = jwt_algorithm;
    debugging!("Header: {:?}", header);
    debugging!("Claims: {:?}", claims);

    let header = opt_result!(header.to_base64(), "Header to base64 failed: {}");
    let claims = merge_payload_claims(payload, claims)?;
    let tobe_signed = merge_header_claims(header.as_bytes(), claims.as_bytes());

    let signature = cmd_external_sign::sign(jwt_algorithm.to_str(), &tobe_signed, key_uri, sub_arg_matches)?;

    let signed_data = match jwt_algorithm {
        AlgorithmType::Rs256 => signature,
        AlgorithmType::Es256 | AlgorithmType::Es384 | AlgorithmType::Es512 => {
            parse_ecdsa_to_rs(signature.as_slice())?
        }
        _ => return simple_error!("SHOULD NOT HAPPEN: {:?}", jwt_algorithm),
    };

    let signature = util::base64_encode_url_safe_no_pad(&signed_data);

    Ok([&*header, &*claims, &signature].join(SEPARATOR))
}
