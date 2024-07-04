use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;
use yubikey::{PinPolicy, piv, TouchPolicy, YubiKey};
use yubikey::piv::{AlgorithmId, SlotId};

use crate::pinutil;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-generate" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV generate subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).help("PIV card user PIN"))
            .arg(Arg::with_name("force").long("force").help("Force generate"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        warning!("This feature is not works");
        let pin_opt = sub_arg_matches.value_of("pin");
        let pin_opt = pinutil::get_pin(pin_opt);
        let pin_opt = pin_opt.as_deref();
        let pin = opt_value_result!(pin_opt, "User pin must be assigned");

        if !sub_arg_matches.is_present("force") {
            failure_and_exit!("--force must be assigned");
        }

        let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
        opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");

        let public_key_info = opt_result!(piv::generate(&mut yk,SlotId::Signature, AlgorithmId::Rsa2048,
            PinPolicy::Default, TouchPolicy::Default), "Generate key failed: {}");

        success!("Generate key success: {:?}", public_key_info);


        Ok(None)
    }
}
