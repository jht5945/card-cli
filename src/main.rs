#[macro_use]
extern crate rust_util;

use clap::{App, AppSettings, ArgMatches};
use rust_util::util_clap::{Command, CommandError};

mod argsutil;
mod cmd_chall;
mod cmd_challconfig;
mod cmd_ecverify;
mod cmd_hmac_sha1;
mod cmd_list;
#[cfg(feature = "with-sequoia-openpgp")]
mod cmd_pgp;
mod cmd_pgpageaddress;
mod cmd_pgpcardadmin;
mod cmd_pgpcarddecrypt;
mod cmd_pgpcardlist;
#[cfg(feature = "with-sequoia-openpgp")]
mod cmd_pgpcardmake;
mod cmd_pgpcardsign;
mod cmd_piv;
mod cmd_pivdecrypt;
mod cmd_pivecdh;
mod cmd_pivecsign;
mod cmd_pivgenerate;
mod cmd_pivmeta;
mod cmd_pivrsasign;
mod cmd_pivsummary;
mod cmd_pivverify;
mod cmd_rsadecrypt;
mod cmd_rsaencrypt;
mod cmd_rsaverify;
#[cfg(feature = "with-secure-enclave")]
mod cmd_se;
#[cfg(feature = "with-secure-enclave")]
mod cmd_se_ecdh;
#[cfg(feature = "with-secure-enclave")]
mod cmd_se_ecsign;
#[cfg(feature = "with-secure-enclave")]
mod cmd_se_generate;
#[cfg(feature = "with-secure-enclave")]
mod cmd_se_recover;
mod cmd_signfile;
mod cmd_signjwt;
mod cmd_sshagent;
mod cmd_sshparse;
mod cmd_sshparsesign;
mod cmd_sshpivcert;
mod cmd_sshpivsign;
mod cmd_sshpubkey;
mod cmd_u2fregister;
mod cmd_u2fsign;
mod cmd_verifyfile;
mod digest;
mod ecdhutil;
mod ecdsautil;
mod fido;
mod hmacutil;
mod keyutil;
mod pgpcardutil;
mod pinutil;
mod pivutil;
mod pkiutil;
mod rsautil;
#[cfg(feature = "with-secure-enclave")]
mod seutil;
mod signfile;
mod sshutil;
mod util;

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
        Box::new(cmd_challconfig::CommandImpl),
        Box::new(cmd_rsaencrypt::CommandImpl),
        Box::new(cmd_rsadecrypt::CommandImpl),
        Box::new(cmd_rsaverify::CommandImpl),
        #[cfg(feature = "with-sequoia-openpgp")]
        Box::new(cmd_pgp::CommandImpl),
        Box::new(cmd_pgpcardadmin::CommandImpl),
        Box::new(cmd_pgpcardlist::CommandImpl),
        Box::new(cmd_pgpcardsign::CommandImpl),
        Box::new(cmd_pgpcarddecrypt::CommandImpl),
        #[cfg(feature = "with-sequoia-openpgp")]
        Box::new(cmd_pgpcardmake::CommandImpl),
        Box::new(cmd_piv::CommandImpl),
        Box::new(cmd_pivsummary::CommandImpl),
        Box::new(cmd_pivmeta::CommandImpl),
        Box::new(cmd_pivverify::CommandImpl),
        Box::new(cmd_pivrsasign::CommandImpl),
        Box::new(cmd_pivecdh::CommandImpl),
        Box::new(cmd_pivecsign::CommandImpl),
        Box::new(cmd_pivdecrypt::CommandImpl),
        Box::new(cmd_pivgenerate::CommandImpl),
        Box::new(cmd_u2fregister::CommandImpl),
        Box::new(cmd_u2fsign::CommandImpl),
        Box::new(cmd_sshagent::CommandImpl),
        Box::new(cmd_sshparsesign::CommandImpl),
        Box::new(cmd_sshpivsign::CommandImpl),
        Box::new(cmd_sshpivcert::CommandImpl),
        Box::new(cmd_sshpubkey::CommandImpl),
        Box::new(cmd_sshparse::CommandImpl),
        Box::new(cmd_pgpageaddress::CommandImpl),
        Box::new(cmd_signjwt::CommandImpl),
        Box::new(cmd_signfile::CommandImpl),
        Box::new(cmd_verifyfile::CommandImpl),
        #[cfg(feature = "with-secure-enclave")]
        Box::new(cmd_se::CommandImpl),
        #[cfg(feature = "with-secure-enclave")]
        Box::new(cmd_se_generate::CommandImpl),
        #[cfg(feature = "with-secure-enclave")]
        Box::new(cmd_se_recover::CommandImpl),
        #[cfg(feature = "with-secure-enclave")]
        Box::new(cmd_se_ecsign::CommandImpl),
        #[cfg(feature = "with-secure-enclave")]
        Box::new(cmd_se_ecdh::CommandImpl),
        Box::new(cmd_ecverify::CommandImpl),
    ];

    #[allow(clippy::vec_init_then_push)]
    let features = {
        let mut features: Vec<&str> = vec![];
        #[cfg(feature = "with-sequoia-openpgp")]
        features.push("sequoia-openpgp");
        #[cfg(feature = "with-secure-enclave")]
        features.push("secure-enclave");
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
