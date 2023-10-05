use clap::{App, Arg, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};
use yubico_manager::config::Config;
use yubico_manager::configure::DeviceModeConfig;
use yubico_manager::hmacmode::HmacKey;
use yubico_manager::Yubico;

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str { "chall-config" }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name()).about("YubiKey challenge-response HMAC configuration")
            .arg(Arg::with_name("secret").short("s").long("secret").takes_value(true).help("Secret"))
            .arg(Arg::with_name("secret-hex").short("x").long("secret-hex").takes_value(true).help("Secret HEX"))
            .arg(Arg::with_name("button-press").long("button-press").help("Require button press"))
            .arg(Arg::with_name("yes-config-chall").long("yes-config-chall").help("Config challenge-response key"))
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        if !sub_arg_matches.is_present("yes-config-chall") {
            return simple_error!("--yes-config-chall is not configed");
        }
        let secret_bytes: Vec<u8> = if let Some(secret) = sub_arg_matches.value_of("secret") {
            secret.as_bytes().to_vec()
        } else if let Some(secret_hex) = sub_arg_matches.value_of("secret-hex") {
            opt_result!(hex::decode(secret_hex), "Decode secret-hex failed: {}")
        } else {
            return simple_error!("Secret must assigned");
        };

        // Secret must have 20 bytes
        if secret_bytes.len() != 20 {
            return simple_error!("Challenge bytes is: {}, is not 20", secret_bytes.len());
        }

        let mut yubi = Yubico::new();
        if let Ok(device) = yubi.find_yubikey() {
            success!("Found key, Vendor ID: {:?} Product ID {:?}", device.vendor_id, device.product_id);

            let config = Config::default()
                .set_vendor_id(device.vendor_id)
                .set_product_id(device.product_id)
                .set_command(yubico_manager::config::Command::Configuration2);

            let hmac_key: HmacKey = HmacKey::from_slice(&secret_bytes);
            let button_press = sub_arg_matches.is_present("button-press");
            information!("Button press: {}", button_press);

            let mut device_config = DeviceModeConfig::default();
            device_config.challenge_response_hmac(&hmac_key, false, button_press);

            if let Err(err) = yubi.write_config(config, &mut device_config) {
                failure!("Config device failed: {:?}", err);
            } else {
                success!("Device configured");
            }
        } else {
            warning!("YubiKey not found");
            return Ok(Some(1));
        }

        Ok(None)
    }
}
