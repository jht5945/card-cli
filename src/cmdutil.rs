use clap::{Arg, ArgMatches};
use rust_util::util_msg;

pub fn build_slot_arg() -> Arg<'static, 'static> {
    Arg::with_name("slot")
        .short("s")
        .long("slot")
        .takes_value(true)
        .help("PIV slot, e.g. 82, 83 ... 95, 9a, 9c, 9d, 9e")
}

pub fn build_with_hmac_encrypt_arg() -> Arg<'static, 'static> {
    Arg::with_name("with-hmac-encrypt").long("with-hmac-encrypt").help("With HMAC encrypt")
}

pub fn build_with_pbe_encrypt_arg() -> Arg<'static, 'static> {
    Arg::with_name("with-pbe-encrypt").long("with-pbe-encrypt").help("With PBE encryption")
}

pub fn build_double_pin_check_arg() -> Arg<'static, 'static> {
    Arg::with_name("double-pin-check").long("double-pin-check").help("Double PIN check")
}

pub fn build_pbe_iteration_arg() -> Arg<'static, 'static> {
    Arg::with_name("pbe-iteration").long("pbe-iteration").takes_value(true).help("PBE iteration, default 100000")
}

pub fn build_serial_arg() -> Arg<'static, 'static> {
    Arg::with_name("serial").long("serial").takes_value(true).help("Serial number")
}

pub fn build_key_uri_arg() -> Arg<'static, 'static> {
    Arg::with_name("key").long("key").required(true).takes_value(true).help("Key uri")
}

pub fn build_pin_arg() -> Arg<'static, 'static> {
    Arg::with_name("pin").short("p").long("pin").takes_value(true).help("PIV card user PIN")
}

pub fn build_alg_arg() -> Arg<'static, 'static> {
    Arg::with_name("alg").long("alg").takes_value(true).required(true).help("Algorithm, e.g. RS256, ES256, ES384")
}

pub fn build_parameter_arg() -> Arg<'static, 'static> {
    Arg::with_name("parameter").long("parameter").takes_value(true).required(true).help("Parameter")
}

pub fn build_epk_arg() -> Arg<'static, 'static> {
    Arg::with_name("epk").long("epk").required(true).takes_value(true).help("E-Public key")
}

pub fn build_message_arg() -> Arg<'static, 'static> {
    Arg::with_name("message-base64").long("message-base64").takes_value(true).required(true).help("Message in base64")
}

pub fn build_no_pin_arg() -> Arg<'static, 'static> {
    Arg::with_name("no-pin").long("no-pin").help("No PIN")
}

pub fn build_keychain_name_arg() -> Arg<'static, 'static> {
    Arg::with_name("keychain-name")
        .long("keychain-name")
        .takes_value(true)
        .help("Key chain name")
}

pub fn build_json_arg() -> Arg<'static, 'static> {
    Arg::with_name("json").long("json").help("JSON output")
}

pub fn check_json_output(sub_arg_matches: &ArgMatches) -> bool {
    let json_output = sub_arg_matches.is_present("json");
    if json_output {
        util_msg::set_logger_std_out(false);
    }
    json_output
}
