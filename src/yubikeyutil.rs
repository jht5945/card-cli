use crate::pivutil::slot_equals;
use clap::ArgMatches;
use rust_util::XResult;
use yubikey::piv::SlotId;
use yubikey::{Key, Serial, YubiKey};

pub fn open_yubikey_with_args(sub_arg_matches: &ArgMatches) -> XResult<YubiKey> {
    let serial_opt = sub_arg_matches.value_of("serial");
    open_yubikey_with_serial(&serial_opt)
}

pub fn open_yubikey_with_serial(serial_opt: &Option<&str>) -> XResult<YubiKey> {
    match serial_opt {
        None => open_yubikey(),
        Some(serial) => {
            let serial_no: u32 = opt_result!(serial.parse(), "{}");
            Ok(opt_result!(
                YubiKey::open_by_serial(Serial(serial_no)),
                "YubiKey with serial: {} not found: {}",
                serial
            ))
        }
    }
}

pub fn open_yubikey() -> XResult<YubiKey> {
    Ok(opt_result!(YubiKey::open(), "YubiKey not found: {}"))
}

pub fn open_and_find_key(slot_id: &SlotId, sub_arg_matches: &ArgMatches) -> XResult<Option<Key>> {
    let mut yk = open_yubikey_with_args(sub_arg_matches)?;
    find_key(&mut yk, slot_id)
}

pub fn find_key(yk: &mut YubiKey, slot_id: &SlotId) -> XResult<Option<Key>> {
    match Key::list(yk) {
        Err(e) => warning!("List keys failed: {}", e),
        Ok(keys) => return Ok(filter_key(keys, slot_id)),
    }
    Ok(None)
}

pub fn find_key_or_error(yk: &mut YubiKey, slot_id: &SlotId) -> XResult<Option<Key>> {
    match Key::list(yk) {
        Err(e) => simple_error!("List keys failed: {}", e),
        Ok(keys) => Ok(filter_key(keys, slot_id)),
    }
}

fn filter_key(keys: Vec<Key>, slot_id: &SlotId) -> Option<Key> {
    for k in keys {
        let slot_str = format!("{:x}", Into::<u8>::into(k.slot()));
        if slot_equals(slot_id, &slot_str) {
            return Some(k);
        }
    }
    None
}
