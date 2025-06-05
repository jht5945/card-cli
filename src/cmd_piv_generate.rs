use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use yubikey::{PinPolicy, piv, TouchPolicy};
use yubikey::piv::{AlgorithmId, SlotId};

use crate::{cmdutil, pinutil, yubikeyutil};

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-generate" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV generate subcommand")
            .arg(cmdutil::build_pin_arg())
            .arg(Arg::with_name("force").long("force").help("Force generate"))
            .arg(cmdutil::build_serial_arg())
            // .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        warning!("This feature is not works");
        let pin_opt = sub_arg_matches.value_of("pin");
        let pin_opt = pinutil::get_pin(pin_opt);
        let pin_opt = pin_opt.as_deref();
        let pin = opt_value_result!(pin_opt, "User pin must be assigned");

        if !sub_arg_matches.is_present("force") {
            failure_and_exit!("--force must be assigned");
        }

        let mut yk = yubikeyutil::open_yubikey_with_args(sub_arg_matches)?;
        opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");

        let public_key_info = opt_result!(piv::generate(&mut yk,SlotId::Signature, AlgorithmId::Rsa2048,
            PinPolicy::Default, TouchPolicy::Default), "Generate key failed: {}");

        success!("Generate key success: {:?}", public_key_info);

        Ok(None)
    }
}
