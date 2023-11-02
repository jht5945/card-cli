use bech32::{ToBase32, Variant};
use clap::{App, ArgMatches, SubCommand};
use openpgp_card::{KeyType, OpenPgp};
use openpgp_card::algorithm::{Algo, Curve};
use openpgp_card::crypto_data::{EccType, PublicKeyMaterial};
use openpgp_card_pcsc::PcscBackend;
use rust_util::util_clap::{Command, CommandError};

const AGE_PUBLIC_KEY_PREFIX: &str = "age";

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "pgp-age-address" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("OpenPGP Card Encryption key to age address")
    }

    fn run(&self, _arg_matches: &ArgMatches, _sub_arg_matches: &ArgMatches) -> CommandError {
        let cards = opt_result!(PcscBackend::cards(None), "Failed to list OpenPGP cards: {}");

        information!("Found {} card(s)", cards.len());
        for (i, card) in cards.into_iter().enumerate() {
            let mut pgp = OpenPgp::new(card);
            let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");
            if let Ok(application_related_data) = trans.application_related_data() {
                success!("Found card #{}: {:?}", i, application_related_data.application_id());
            }
            let encryption_public_key = match trans.public_key(KeyType::Decryption) {
                Ok(pub_key) => pub_key,
                Err(e) => {
                    failure!("Get decryption public key failed: {}", e);
                    continue;
                }
            };
            if let PublicKeyMaterial::E(ecc_pub) = &encryption_public_key {
                if let Algo::Ecc(ecc) = ecc_pub.algo() {
                    if let (EccType::ECDH, Curve::Cv25519) = (ecc.ecc_type(), ecc.curve()) {
                        let pub_key_bytes = ecc_pub.data();
                        let age_address = opt_result!(bech32::encode(
                            AGE_PUBLIC_KEY_PREFIX,
                            pub_key_bytes.to_base32(),
                            Variant::Bech32,
                        ), "Generate age address failed: {}");
                        success!("Age address: {}", age_address);
                    }
                }
            } else {
                failure!("Not supported encryption key: {}", encryption_public_key);
            }
        }
        Ok(None)
    }
}
