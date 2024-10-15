use std::str::FromStr;

use clap::builder::ValueParser;
use domain::base::iana::nsec3::Nsec3HashAlg;
use domain::base::name::Name;
use domain::rdata::nsec3::Nsec3Salt;
use domain::sign::ring::nsec3_hash;

use crate::error::Error;

#[derive(Clone, Debug, clap::Args)]
pub struct Nsec3Hash {
    /// The hashing algorithm to use
    #[arg(
        long,
        short = 'a',
        value_name = "NUMBER_OR_MNEMONIC",
        default_value_t = Nsec3HashAlg::SHA1,
        value_parser = ValueParser::new(Nsec3Hash::parse_nsec_alg)
    )]
    algorithm: Nsec3HashAlg,

    /// The number of hash iterations
    #[arg(
        long,
        short = 'i',
        visible_short_alias = 't',
        value_name = "NUMBER",
        default_value_t = 1
    )]
    iterations: u16,

    /// The salt in hex representation
    #[arg(short = 's', long, value_name = "HEX_STRING", default_value_t = Nsec3Salt::empty())]
    salt: Nsec3Salt<Vec<u8>>,

    /// The domain name to hash
    #[arg(value_name = "DOMAIN_NAME", value_parser = ValueParser::new(Nsec3Hash::parse_name))]
    name: Name<Vec<u8>>,
}

impl Nsec3Hash {
    pub fn parse_name(arg: &str) -> Result<Name<Vec<u8>>, Error> {
        Name::from_str(&arg.to_lowercase()).map_err(|e| Error::from(e.to_string()))
    }

    pub fn parse_nsec_alg(arg: &str) -> Result<Nsec3HashAlg, Error> {
        if let Ok(num) = arg.parse() {
            let alg = Nsec3HashAlg::from_int(num);
            // check for valid algorithm here, to be consistent with error messages
            // if domain::validator::nsec::supported_nsec3_hash(alg) {
            if alg.to_mnemonic().is_some() {
                Ok(alg)
            } else {
                Err(Error::from("unknown algorithm number"))
            }
        } else {
            Nsec3HashAlg::from_mnemonic(arg.as_bytes())
                .ok_or(Error::from("unknown algorithm mnemonic"))
        }
    }
}

impl Nsec3Hash {
    pub fn execute(self) -> Result<(), Error> {
        let hash =
            nsec3_hash::<_, _, Vec<u8>>(&self.name, self.algorithm, self.iterations, &self.salt)
                .expect("Error while generating NSEC3 hash")
                .to_string()
                .to_lowercase();
        println!("{}.", hash);
        Ok(())
    }
}
