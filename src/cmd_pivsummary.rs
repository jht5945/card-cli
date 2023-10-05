use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::XResult;
use spki::der::Encode;
use tabled::{Table, Tabled};
use tabled::settings::Style;
use x509_parser::parse_x509_certificate;
use yubikey::{Certificate, YubiKey};
use yubikey::piv::SlotId;

use crate::pivutil::get_algorithm_id;

#[derive(Tabled)]
struct PivSlot {
    name: String,
    id: String,
    algorithm: String,
    subject: String,
}


pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-summary" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV subcommand")
            .arg(Arg::with_name("table").long("table").help("Show table"))
            .arg(Arg::with_name("all").long("all").help("Show all"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let show_table = sub_arg_matches.is_present("table");
        let show_all = sub_arg_matches.is_present("all");

        let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
        success!("Name: {}", yk.name());
        information!("Version: {}", yk.version());
        information!("Serial: {}", yk.serial());
        match yk.chuid() {
            Ok(chuid) => information!("CHUID: {}",chuid.to_string()),
            Err(e) => warning!("CHUID: <none> {}", e),
        }
        match yk.cccid() {
            Ok(cccid) => information!("CCCID: {}",cccid.to_string()),
            Err(e) => warning!("CCCID: <none> {}", e),
        }
        match yk.get_pin_retries() {
            Ok(pin_retries) => information!("PIN retries: {}",pin_retries),
            Err(e) => warning!("PIN retries: <none> {}", e),
        }

        match yk.piv_keys() {
            Ok(keys) => {
                information!("Found {} PIV keys", keys.len());
            }
            Err(e) => failure!("Get PIV keys failed: {}", e)
        }

        let mut piv_slots = vec![];
        for slot in yubikey::piv::SLOTS {
            print_summary_info(&mut yk, slot, &mut piv_slots, show_all, show_table).ok();
        }
        if show_table {
            let mut table = Table::new(piv_slots);
            table.with(Style::rounded());
            println!("{}", table.to_string());
        }
        Ok(None)
    }
}

fn print_summary_info(yubikey: &mut YubiKey, slot: SlotId, piv_slots: &mut Vec<PivSlot>, show_all: bool, show_table: bool) -> XResult<()> {
    let slot_id: u8 = slot.into();
    let cert = match Certificate::read(yubikey, slot) {
        Ok(c) => c,
        Err(e) => {
            if show_all {
                if show_table {
                    piv_slots.push(PivSlot {
                        name: slot.to_string(),
                        id: format!("{:x}", slot_id),
                        algorithm: "N/A".to_string(),
                        subject: "N/A".to_string(),
                    });
                } else {
                    warning!("Slot: {:?}, id: {:x}, certificate not found",  slot, slot_id);
                }
            }
            return simple_error!("error reading certificate in slot {:?}: {}", slot, e);
        }
    };
    let buf_vec = cert.cert.to_der()?;
    let algorithm_id = get_algorithm_id(&cert.cert.tbs_certificate.subject_public_key_info)
        .map(|aid| format!("{:?}", aid))
        .unwrap_or_else(|e| format!("Error: {}", e));
    let cert_subject = match parse_x509_certificate(&buf_vec) {
        Ok((_rem, cert)) => cert.subject.to_string(),
        _ => cert.cert.tbs_certificate.subject.to_string(),
    };
    if show_table {
        piv_slots.push(PivSlot {
            name: slot.to_string(),
            id: format!("{:x}", slot_id),
            algorithm: algorithm_id,
            subject: cert_subject,
        });
    } else {
        success!("Slot: {:x},  algorithm: {}, name: {:?},subject: {}", slot_id, algorithm_id, slot, cert_subject);
    }

    Ok(())
}
