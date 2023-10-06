use std::collections::BTreeMap;

use clap::{App, Arg, ArgMatches, SubCommand};
use openpgp_card::{KeyType, OpenPgp};
use openpgp_card_pcsc::PcscBackend;
use rust_util::util_clap::{Command, CommandError};
use rust_util::util_msg;

use crate::pkiutil::openpgp_card_public_key_pem as public_key_pem;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "pgp-card-list" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("OpenPGP Card List subcommand")
            .arg(Arg::with_name("detail").long("detail").help("Detail output"))
            .arg(Arg::with_name("json").long("json").help("JSON output"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let detail_output = sub_arg_matches.is_present("detail");
        let json_output = sub_arg_matches.is_present("json");
        if json_output { util_msg::set_logger_std_out(false); }

        let mut jsons = vec![];
        let cards = opt_result!(PcscBackend::cards(None), "Failed to list OpenPGP cards: {}");

        information!("Found {} card(s)", cards.len());
        for (i, card) in cards.into_iter().enumerate() {
            let mut json = BTreeMap::new();
            let mut pgp = OpenPgp::new(card);
            let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");
            if let Ok(application_related_data) = trans.application_related_data() {
                success!("Found card #{}: {:?}", i, application_related_data.application_id());
                debugging!("Historical: {:?}", application_related_data.historical_bytes());
                debugging!("Extended length information: {:?}", application_related_data.extended_length_information());
                debugging!("Extended capabilities: {:?}", application_related_data.extended_capabilities());
                debugging!("Key generation times: {:?}", application_related_data.key_generation_times());
                debugging!("PW status bytes: {:?}", application_related_data.pw_status_bytes());
                debugging!(r#"Algorithm attributes:
- Signing: {:?}
- Decryption: {:?}
- Authentication: {:?}
- Attestation: {:?}"#,
                               application_related_data.algorithm_attributes(KeyType::Signing),
                               application_related_data.algorithm_attributes(KeyType::Decryption),
                               application_related_data.algorithm_attributes(KeyType::Authentication),
                               application_related_data.algorithm_attributes(KeyType::Attestation));
                debugging!("Fingerprints: {:?}", application_related_data.fingerprints());
                if json_output {
                    if let Ok(application_identifier) = application_related_data.application_id() {
                        json.insert("application".to_string(), format!("{}", application_identifier.application()));
                        json.insert("version".to_string(), format!("{}", application_identifier.version()));
                        json.insert("serial".to_string(), format!("{}", application_identifier.serial()));
                        json.insert("manufacturer".to_string(), format!("{}", application_identifier.manufacturer()));
                        json.insert("ident".to_string(), application_identifier.ident());
                    }
                }
            }
            information!("Feature pin pad, verify: {}, modify: {}",
                           trans.feature_pinpad_verify(), trans.feature_pinpad_modify());
            if json_output {
                json.insert("feature_pinpad_verify".to_string(), format!("{}", trans.feature_pinpad_verify()));
                json.insert("feature_pinpad_modify".to_string(), format!("{}", trans.feature_pinpad_modify()));
            }

            if let Ok(security_supported_template) = trans.security_support_template() {
                debugging!("Security support template: {:?}", security_supported_template);
            }
            if let Ok(cardholder_certificate) = trans.cardholder_certificate() {
                debugging!("Cardholder certificate: {:?}", cardholder_certificate);
            }
            // debugging!("Security support template: {:?}", trans.security_support_template());
            // debugging!("Security support template: {:?}", trans.cardholder_certificate());
            if let Ok(url) = trans.url() {
                information!("URL: {}", iff!(url.is_empty(), "<empty>".to_string(), String::from_utf8_lossy(&url).to_string()));
            }
            if let Ok(card_holder) = trans.cardholder_related_data() {
                debugging!("Card holder: {:?}", card_holder);
                let mut card_holder_outputs = vec![];
                if let Some(name) = card_holder.name() {
                    card_holder_outputs.push(format!("name: {}", String::from_utf8_lossy(name)));
                }
                if let Some(lang) = card_holder.lang() {
                    card_holder_outputs.push(format!(
                        "lang: {}",
                        lang.iter().map(|l| l.to_string()).collect::<Vec<String>>().join(" ")));
                }
                if let Some(sex) = card_holder.sex() {
                    card_holder_outputs.push(format!("sex: {:?}", sex));
                }
                information!("Card holder, {}",
                    iff!(card_holder_outputs.is_empty(), "".to_string(), card_holder_outputs.join(", ")));
            }
            if let Ok(Some(algo_info)) = trans.algorithm_information() {
                debugging!("Algo info: {}", algo_info);
            }
            if let Ok(application_related_data) = trans.application_related_data() {
                if let Ok(fingerprints) = application_related_data.fingerprints() {
                    let fingerprints = vec![
                        ("Authentication", "authentication", KeyType::Authentication, fingerprints.authentication()),
                        ("Decryption", "encryption", KeyType::Decryption, fingerprints.decryption()),
                        ("Signature", "signature", KeyType::Signing, fingerprints.signature()),
                    ];
                    for (tag1, tag2, key_type, fingerprint) in fingerprints {
                        let fingerprint = match fingerprint {
                            Some(fingerprint) => fingerprint,
                            None => continue
                        };
                        if let Ok(algo) = application_related_data.algorithm_attributes(key_type) {
                            information!("{} algo: {:?}", tag1, algo);
                        }
                        information!("{} fingerprint: {}", tag1, fingerprint);
                        if json_output {
                            json.insert(format!("{}_fingerprint", tag2), fingerprint.to_string());
                        }
                        if detail_output {
                            if let Ok(public_key) = trans.public_key(key_type) {
                                if let Some((public_key_sha256, public_key_pem)) = public_key_pem(&public_key) {
                                    information!("{} public key sha256: {}", tag1, hex::encode(&public_key_sha256));
                                    information!("{} public key: {}", tag1, public_key_pem.trim());
                                    information!("{} public key: {}", tag1, public_key);
                                    if json_output {
                                        json.insert(format!("{}_public_key_sha256", tag2), hex::encode(&public_key_sha256));
                                        json.insert(format!("{}_public_key_pem", tag2), public_key_pem);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            jsons.push(json);
        }

        if json_output {
            println!("{}", serde_json::to_string_pretty(&jsons).unwrap());
        }
        Ok(None)
    }
}
