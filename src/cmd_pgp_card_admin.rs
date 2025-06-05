use clap::{App, Arg, ArgMatches, SubCommand};
use openpgp_card::card_do::{Lang, Sex};
use rust_util::util_clap::{Command, CommandError};

use crate::{pgpcardutil, pinutil};

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "pgp-card-admin" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("OpenPGP Card admin subcommand")
            .arg(Arg::with_name("pin").short("p").long("pin").takes_value(true).help("OpenPGP card admin pin"))
            .arg(Arg::with_name("pass").long("pass").takes_value(true).help("[deprecated] now OpenPGP card admin pin"))
            .arg(Arg::with_name("name").short("n").long("name").takes_value(true).required(false).help("Set name"))
            .arg(Arg::with_name("url").long("url").takes_value(true).required(false).help("Set URL"))
            .arg(Arg::with_name("lang").long("lang").takes_value(true).required(false).help("Set lang"))
            .arg(Arg::with_name("sex").long("sex").takes_value(true).required(false).help("Set sex, f or m"))
            .arg(Arg::with_name("reset").long("reset").help("Reset card"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let pin_opt = sub_arg_matches.value_of("pass").or_else(|| sub_arg_matches.value_of("pin"));
        let pin_opt = pinutil::get_pin(pin_opt);
        let pin_opt = pin_opt.as_deref();
        let pin = opt_value_result!(pin_opt, "Pin must be assigned");
        if pin.len() < 8 { return simple_error!("Admin pin length:{}, must >= 8!", pin.len()); }

        let mut pgp = pgpcardutil::get_openpgp_card()?;
        let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");

        if sub_arg_matches.is_present("reset") {
            warning!("Start reset card...");
            opt_result!(trans.factory_reset(), "Reset failed: {}");
            success!("Reset success");
            return Ok(None);
        }

        opt_result!(trans.verify_pw3(pin.as_ref()), "Admin pin verify failed: {}");
        success!("Admin pin verify success!");

        if let Some(name) = sub_arg_matches.value_of("name") {
            information!("Set name to: {}", name);
            opt_result!(trans.set_name(name.as_bytes()), "Set name failed: {}");
            success!("Set name success");
        }

        if let Some(url) = sub_arg_matches.value_of("url") {
            information!("Set URL to: {}", url);
            opt_result!(trans.set_url(url.as_bytes()), "Set URL failed: {}");
            success!("Set URL success");
        }

        if let Some(lang) = sub_arg_matches.value_of("lang") {
            information!("Set lang to: {}", lang);
            let lang_bytes = lang.as_bytes();
            opt_result!(trans.set_lang(&[Lang::Value([lang_bytes[0], lang_bytes[1]])]), "Set lang failed: {}");
            success!("Set lang success");
        }

        if let Some(sex) = sub_arg_matches.value_of("sex") {
            let sex = sex.to_lowercase();
            let s = if "f" == sex || "female" == sex {
                Some(Sex::Female)
            } else if "m" == sex || "male" == sex {
                Some(Sex::Male)
            } else {
                warning!("Invalid sex: {}", sex);
                None
            };
            if let Some(s) = s {
                information!("Set sex to: {:?}", s);
                opt_result!(trans.set_sex(s), "Set lang failed: {}");
                success!("Set sex success");
            }
        }

        Ok(None)
    }
}
