use crate::cmd_se_generate::print_se_key;
use crate::keyutil::{parse_key_uri, KeyUsage};
use crate::{cmd_hmac_decrypt, cmdutil, seutil};
use clap::{App, ArgMatches, SubCommand};
use rust_util::util_clap::{Command, CommandError};

pub struct CommandImpl;

impl Command for CommandImpl {
    fn name(&self) -> &str {
        "se-recover"
    }

    fn subcommand<'a>(&self) -> App<'a, 'a> {
        SubCommand::with_name(self.name())
            .about("Secure Enclave recover subcommand")
            .arg(cmdutil::build_key_uri_arg())
            .arg(cmdutil::build_json_arg())
    }

    fn run(&self, _arg_matches: &ArgMatches, sub_arg_matches: &ArgMatches) -> CommandError {
        let json_output = cmdutil::check_json_output(sub_arg_matches);

        seutil::check_se_supported()?;
        let key = sub_arg_matches.value_of("key").unwrap();
        let key_uri = parse_key_uri(&key)?;
        let se_key_uri = key_uri.as_secure_enclave_key()?;
        debugging!("Secure enclave key URI: {:?}", se_key_uri);

        let private_key = cmd_hmac_decrypt::try_decrypt(&mut None, &se_key_uri.private_key)?;
        let (public_key_point, public_key_der, _private_key) =
            seutil::recover_secure_enclave_p256_public_key(
                &private_key,
                se_key_uri.usage == KeyUsage::Singing,
            )?;

        print_se_key(json_output, &public_key_point, &public_key_der, &key);

        Ok(None)
    }
}
