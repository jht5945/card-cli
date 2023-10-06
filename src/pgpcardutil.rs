use openpgp_card::OpenPgp;
use openpgp_card_pcsc::PcscBackend;
use rust_util::XResult;

pub fn get_openpgp_card() -> XResult<OpenPgp> {
    let card = get_card()?;
    Ok(OpenPgp::new(card))
}

pub fn get_card() -> XResult<PcscBackend> {
    let card_list = opt_result!(PcscBackend::cards(None), "Read OpenPGP card list failed: {}");
    if card_list.is_empty() {
        return simple_error!("Cannot find any card");
    }
    if card_list.len() > 1 {
        warning!("Find {} OpenPGP cards, will use first card", card_list.len());
    }
    Ok(opt_value_result!(card_list.into_iter().next(), "SHOULD NOT HAPPEN, CANNOT FIND ANY CARD"))
}
