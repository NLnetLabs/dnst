use clap::builder::ValueParser;
use domain::base::iana::SecAlg;
use domain::base::name::Name;

use crate::error::Error;
use crate::parse::parse_name;

#[derive(Clone, Debug, clap::Args)]
pub struct Keygen {
    /// The hashing algorithm to use
    #[arg(
        long,
        short = 'a',
        value_name = "NUMBER_OR_MNEMONIC",
        value_parser = ValueParser::new(Keygen::parse_key_alg)
    )]
    algorithm: SecAlg,

    /// Set the flags to 257; key signing key
    #[arg(short = 'k', default_value_t = false)]
    make_ksk: bool,

    /// The domain name to generate a key for
    #[arg(value_name = "domain name", value_parser = ValueParser::new(parse_name))]
    name: Name<Vec<u8>>,
}

impl Keygen {
    pub fn execute(self) -> Result<(), Error> {
        // let hash = nsec3_hash(&self.name, self.algorithm, self.iterations, &self.salt)
        //     .to_string()
        //     .to_lowercase();
        // println!("{}.", hash);
        Ok(())
    }

    pub fn parse_key_alg(arg: &str) -> Result<SecAlg, Error> {
        if arg == "list" {
            println!("Possible algorithms:");
            // TODO: I thought about listing all mnemonics from SecAlg, but it has
            // lots of values we don't want to show the user or don't support, so
            // maybe a curated list that we actually know we support is a better way
            // to go.
            // for num in 0..u8::MAX {
            //     let alg = SecAlg::from_int(num);
            //     match alg {
            //         SecAlg::INDIRECT | SecAlg::PRIVATEDNS | SecAlg::PRIVATEOID => {
            //             continue;
            //         }

            //         alg => {
            //             if let Some(mnemonic) = alg.to_mnemonic() {
            //                 println!("{}", std::str::from_utf8(mnemonic).unwrap());
            //             }
            //         }
            //     }
            // }

            // TODO: Errm, yeuch... no, find a better way.
            Err(Error::from(""))
        } else if let Ok(num) = arg.parse() {
            let alg = SecAlg::from_int(num);
            if alg.to_mnemonic().is_some() {
                Ok(alg)
            } else {
                Err(Error::from("unknown algorithm number"))
            }
        } else {
            SecAlg::from_mnemonic(arg.as_bytes()).ok_or(Error::from("unknown algorithm mnemonic"))
        }
    }
}
