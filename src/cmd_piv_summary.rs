use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use rust_util::XResult;
use serde::Serialize;
use serde_json::{Map, Value};
use spki::der::Encode;
use tabled::settings::Style;
use tabled::{Table, Tabled};
use x509_parser::parse_x509_certificate;
use yubikey::piv::{metadata, SlotId};
use yubikey::{Certificate, YubiKey};
use crate::{cmdutil, util, yubikeyutil};
use crate::pivutil::{get_algorithm_id_by_certificate, ToStr, ORDERED_SLOTS};

const NA: &str = "N/A";

#[derive(Tabled, Serialize)]
struct PivSlot {
    name: String,
    id: String,
    algorithm: String,
    origin: String,
    retries: String,
    subject: String,
    pin_policy: String,
    touch_policy: String,
}


pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "piv-summary" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("PIV subcommand")
            .arg(Arg::with_name("table").long("table").help("Show table"))
            .arg(Arg::with_name("all").long("all").help("Show all"))
            .arg(Arg::with_name("ordered").long("ordered").help("Show ordered"))
            .arg(cmdutil::build_json_arg())
            .arg(cmdutil::build_serial_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        let show_table = sub_arg_matches.is_present("table");
        let show_all = sub_arg_matches.is_present("all");
        let show_ordered = sub_arg_matches.is_present("ordered");

        let mut output = Map::new();
        let mut yk = yubikeyutil::open_yubikey_with_args(sub_arg_matches)?;

        success!("Name: {}", yk.name());
        information!("Version: {}", yk.version());
        information!("Serial: {}", yk.serial());
        output.insert("name".to_string(), Value::String(yk.name().to_string()));
        output.insert("version".to_string(), Value::String(yk.version().to_string()));
        output.insert("serial".to_string(), Value::String(yk.serial().to_string()));

        match yk.chuid() {
            Ok(chuid) => {
                information!("CHUID: {}",chuid.to_string());
                output.insert("chuid".to_string(), Value::String(chuid.to_string()));
            }
            Err(e) => warning!("CHUID: <none> {}", e),
        }
        match yk.cccid() {
            Ok(cccid) => {
                information!("CCCID: {}",cccid.to_string());
                output.insert("cccid".to_string(), Value::String(cccid.to_string()));
            }
            Err(e) => warning!("CCCID: <none> {}", e),
        }
        match yk.get_pin_retries() {
            Ok(pin_retries) => {
                information!("PIN retries: {}",pin_retries);
                output.insert("pin_retries".to_string(), Value::String(pin_retries.to_string()));
            }
            Err(e) => warning!("PIN retries: <none> {}", e),
        }

        match yk.piv_keys() {
            Ok(keys) => information!("Found {} PIV keys of {}", keys.len(), ORDERED_SLOTS.len()),
            Err(e) => failure!("Get PIV keys failed: {}", e)
        }

        let mut piv_slots = vec![];
        for slot in iff!(show_ordered, ORDERED_SLOTS, yubikey::piv::SLOTS) {
            print_summary_info(&mut yk, slot, &mut piv_slots, show_all, show_table, json_output).ok();
        }
        
        if show_table {
            let mut table = Table::new(piv_slots);
            table.with(Style::rounded());
            println!("{}", table);
        } else if json_output {
            let piv_slots_json = serde_json::to_string(&piv_slots).unwrap();
            let piv_slots_values: Vec<Value> = serde_json::from_str(&piv_slots_json).unwrap();
            output.insert("piv_slots".to_string(), Value::Array(piv_slots_values));
        }
        if json_output {
            util::print_pretty_json(&output);
        }

        Ok(None)
    }
}

fn print_summary_info(yubikey: &mut YubiKey, slot: SlotId, piv_slots: &mut Vec<PivSlot>, show_all: bool, show_table: bool, json_output: bool) -> XResult<()> {
    let slot_id: u8 = slot.into();
    let mut origin = NA.to_string();
    let mut retries = NA.to_string();
    let mut pin_policy = NA.to_string();
    let mut touch_policy = NA.to_string();
    if let Ok(metadata) = metadata(yubikey, slot) {
        if let Some((p_policy, t_policy)) = &metadata.policy {
            pin_policy = p_policy.to_str().to_string();
            touch_policy = t_policy.to_str().to_string();
        }
        if let Some(o) = &metadata.origin {
            origin = o.to_str().to_string();
        }
        if let Some(r) = &metadata.retries {
            retries = format!("{}/{}", r.retry_count, r.remaining_count);
        }
    }
    let cert = match Certificate::read(yubikey, slot) {
        Ok(c) => c,
        Err(e) => {
            if show_all {
                if show_table || json_output {
                    piv_slots.push(PivSlot {
                        name: slot.to_string(),
                        id: format!("{:x}", slot_id),
                        algorithm: NA.to_string(),
                        origin: origin.to_string(),
                        retries: retries.to_string(),
                        subject: NA.to_string(),
                        pin_policy: pin_policy.to_string(),
                        touch_policy: touch_policy.to_string(),
                    });
                } else {
                    warning!("Slot: {:?}, id: {:x}, certificate not found",  slot, slot_id);
                }
            }
            return simple_error!("error reading certificate in slot {:?}: {}", slot, e);
        }
    };
    let buf_vec = cert.cert.to_der()?;
    let algorithm_id = get_algorithm_id_by_certificate(&cert)
        .map(|aid| format!("{:?}", aid))
        .unwrap_or_else(|e| format!("Error: {}", e));
    let cert_subject = match parse_x509_certificate(&buf_vec) {
        Ok((_rem, cert)) => cert.subject.to_string(),
        _ => cert.cert.tbs_certificate.subject.to_string(),
    };
    if show_table || json_output {
        piv_slots.push(PivSlot {
            name: slot.to_string(),
            id: format!("{:x}", slot_id),
            algorithm: algorithm_id,
            origin: origin.to_string(),
            retries: retries.to_string(),
            subject: cert_subject,
            pin_policy: pin_policy.to_string(),
            touch_policy: touch_policy.to_string(),
        });
    } else {
        success!("Slot: {:x},  algorithm: {}, name: {:?}, origin: {}, subject: {}, pin policy: {}, touch policy: {}",
            slot_id,
            algorithm_id,
            slot,
            &origin,
            &cert_subject,
            &pin_policy,
            &touch_policy,
        );
    }

    Ok(())
}
