#[macro_use]
extern crate rust_util;

use clap::{App, AppSettings, ArgMatches};
use rust_util::util_clap::{Command, CommandError};

mod argsutil;
mod cmd_chall;
mod cmd_chall_config;
mod cmd_convert_jwk_to_pem;
mod cmd_convert_pem_to_jwk;
mod cmd_ec_verify;
mod cmd_external_ecdh;
mod cmd_external_public_key;
mod cmd_external_sign;
mod cmd_external_spec;
mod cmd_file_sign;
mod cmd_file_verify;
mod cmd_hmac_decrypt;
mod cmd_hmac_encrypt;
mod cmd_hmac_sha1;
mod cmd_keypair_generate;
mod cmd_keypair_keychain_export;
mod cmd_keypair_keychain_import;
mod cmd_list;
mod cmd_parseecdsasignature;
#[cfg(feature = "with-sequoia-openpgp")]
mod cmd_pgp;
mod cmd_pgp_age_address;
mod cmd_pgp_card_admin;
mod cmd_pgp_card_decrypt;
mod cmd_pgp_card_list;
#[cfg(feature = "with-sequoia-openpgp")]
mod cmd_pgp_card_make;
mod cmd_pgp_card_sign;
mod cmd_piv;
mod cmd_piv_decrypt;
mod cmd_piv_ecdh;
mod cmd_piv_ecsign;
mod cmd_piv_generate;
mod cmd_piv_meta;
mod cmd_piv_rsasign;
mod cmd_piv_summary;
mod cmd_piv_verify;
mod cmd_rsa_decrypt;
mod cmd_rsa_encrypt;
mod cmd_rsa_verify;
mod cmd_se;
mod cmd_se_ecdh;
mod cmd_se_ecsign;
mod cmd_se_generate;
mod cmd_se_recover;
mod cmd_sign_jwt;
mod cmd_sign_jwt_piv;
mod cmd_sign_jwt_se;
mod cmd_sign_jwt_soft;
mod cmd_ssh_agent;
mod cmd_ssh_agent_gpg;
mod cmd_ssh_parse;
mod cmd_ssh_parse_sign;
mod cmd_ssh_piv_cert;
mod cmd_ssh_piv_sign;
mod cmd_ssh_pub_key;
mod cmd_u2f_register;
mod cmd_u2f_sign;
mod cmdutil;
mod digestutil;
mod ecdhutil;
mod ecdsautil;
mod ecutil;
mod fidoutil;
mod hmacutil;
mod keychain;
mod keyutil;
mod pbeutil;
mod pgpcardutil;
mod pinutil;
mod pivutil;
mod pkiutil;
mod rsautil;
mod seutil;
mod signfile;
mod sshutil;
mod util;
mod yubikeyutil;
mod cmd_yubikey;

pub struct DefaultCommandImpl;

impl DefaultCommandImpl {
    pub fn process_command<'a>(app: App<'a, 'a>) -> App<'a, 'a> {
        app
    }
    pub fn run(_arg_matches: &ArgMatches) -> CommandError {
        information!("Card(WebAuthn, OpenPGP, YubiKey) cli, use --help for help");
        Ok(None)
    }
}

fn main() {
    // Run with: RUST_LOG=debug, for more: https://docs.rs/env_logger/0.10.0/env_logger/
    #[cfg(debug_assertions)]
    env_logger::init();

    match inner_main() {
        Err(e) => failure_and_exit!("Run cli error: {}", e),
        Ok(Some(code)) => std::process::exit(code),
        Ok(None) => (),
    }
}

fn inner_main() -> CommandError {
    let commands: Vec<Box<dyn Command>> = vec![
        Box::new(cmd_list::CommandImpl),
        Box::new(cmd_chall::CommandImpl),
        Box::new(cmd_hmac_sha1::CommandImpl),
        Box::new(cmd_hmac_encrypt::CommandImpl),
        Box::new(cmd_hmac_decrypt::CommandImpl),
        Box::new(cmd_chall_config::CommandImpl),
        Box::new(cmd_rsa_encrypt::CommandImpl),
        Box::new(cmd_rsa_decrypt::CommandImpl),
        Box::new(cmd_rsa_verify::CommandImpl),
        #[cfg(feature = "with-sequoia-openpgp")]
        Box::new(cmd_pgp::CommandImpl),
        Box::new(cmd_pgp_card_admin::CommandImpl),
        Box::new(cmd_pgp_card_list::CommandImpl),
        Box::new(cmd_pgp_card_sign::CommandImpl),
        Box::new(cmd_pgp_card_decrypt::CommandImpl),
        #[cfg(feature = "with-sequoia-openpgp")]
        Box::new(cmd_pgp_card_make::CommandImpl),
        Box::new(cmd_piv::CommandImpl),
        Box::new(cmd_piv_summary::CommandImpl),
        Box::new(cmd_piv_meta::CommandImpl),
        Box::new(cmd_piv_verify::CommandImpl),
        Box::new(cmd_piv_rsasign::CommandImpl),
        Box::new(cmd_piv_ecdh::CommandImpl),
        Box::new(cmd_piv_ecsign::CommandImpl),
        Box::new(cmd_piv_decrypt::CommandImpl),
        Box::new(cmd_piv_generate::CommandImpl),
        Box::new(cmd_u2f_register::CommandImpl),
        Box::new(cmd_u2f_sign::CommandImpl),
        Box::new(cmd_ssh_agent::CommandImpl),
        Box::new(cmd_ssh_agent_gpg::CommandImpl),
        Box::new(cmd_ssh_parse_sign::CommandImpl),
        Box::new(cmd_ssh_piv_sign::CommandImpl),
        Box::new(cmd_ssh_piv_cert::CommandImpl),
        Box::new(cmd_ssh_pub_key::CommandImpl),
        Box::new(cmd_ssh_parse::CommandImpl),
        Box::new(cmd_pgp_age_address::CommandImpl),
        Box::new(cmd_sign_jwt_piv::CommandImpl),
        Box::new(cmd_sign_jwt_soft::CommandImpl),
        Box::new(cmd_sign_jwt_se::CommandImpl),
        Box::new(cmd_sign_jwt::CommandImpl),
        Box::new(cmd_file_sign::CommandImpl),
        Box::new(cmd_file_verify::CommandImpl),
        Box::new(cmd_se::CommandImpl),
        Box::new(cmd_se_generate::CommandImpl),
        Box::new(cmd_se_recover::CommandImpl),
        Box::new(cmd_se_ecsign::CommandImpl),
        Box::new(cmd_se_ecdh::CommandImpl),
        Box::new(cmd_ec_verify::CommandImpl),
        Box::new(cmd_parseecdsasignature::CommandImpl),
        Box::new(cmd_keypair_generate::CommandImpl),
        Box::new(cmd_keypair_keychain_import::CommandImpl),
        Box::new(cmd_keypair_keychain_export::CommandImpl),
        Box::new(cmd_convert_pem_to_jwk::CommandImpl),
        Box::new(cmd_convert_jwk_to_pem::CommandImpl),
        Box::new(cmd_external_spec::CommandImpl),
        Box::new(cmd_external_public_key::CommandImpl),
        Box::new(cmd_external_sign::CommandImpl),
        Box::new(cmd_external_ecdh::CommandImpl),
        Box::new(cmd_yubikey::CommandImpl),
    ];

    #[allow(clippy::vec_init_then_push)]
    let features = {
        let mut features: Vec<&str> = vec![];
        #[cfg(feature = "with-sequoia-openpgp")]
        features.push("sequoia-openpgp");
        features
    };
    let about = format!(
        "{}, features: [{}]",
        "Card Cli is a command tool for WebAuthn, OpenPGP, YubiKey ... smart cards",
        features.join(", "),
    );

    let mut app = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .long_about(about.as_str())
        .setting(AppSettings::ColoredHelp);
    app = DefaultCommandImpl::process_command(app);
    for command in &commands {
        app = app.subcommand(command.subcommand());
    }
    let matches = app.get_matches();
    for command in &commands {
        if let Some(sub_cmd_matches) = matches.subcommand_matches(command.name()) {
            return command.run(&matches, sub_cmd_matches);
        }
    }
    DefaultCommandImpl::run(&matches)
}
