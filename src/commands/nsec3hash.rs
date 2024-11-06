use std::str::FromStr;

use clap::builder::ValueParser;
use domain::base::iana::nsec3::Nsec3HashAlg;
use domain::base::name::Name;
use domain::rdata::nsec3::Nsec3Salt;
use domain::validate::nsec3_hash;

use crate::error::Error;

#[derive(Clone, Debug, clap::Args)]
pub struct Nsec3Hash {
    /// The hashing algorithm to use
    #[arg(
        long,
        short = 'a',
        value_name = "algorithm",
        default_value = "SHA-1",
        value_parser = ValueParser::new(Nsec3Hash::parse_nsec3_alg)
    )]
    algorithm: Nsec3HashAlg,

    /// The number of hash iterations
    // TODO: Default to 0 when run as dnst instead of as ldns-nsec3-hash
    #[arg(long, short = 't', value_name = "number", default_value_t = 1)]
    iterations: u16,

    /// The salt in hex representation
    #[arg(
        long,
        short = 's',
        value_name = "string",
        default_value_t = Nsec3Salt::empty(),
        value_parser = ValueParser::new(Nsec3Hash::parse_salt)
    )]
    salt: Nsec3Salt<Vec<u8>>,

    /// The domain name to hash
    #[arg(value_name = "domain name", value_parser = ValueParser::new(Nsec3Hash::parse_name))]
    name: Name<Vec<u8>>,
}

impl Nsec3Hash {
    pub fn parse_name(arg: &str) -> Result<Name<Vec<u8>>, Error> {
        Name::from_str(&arg.to_lowercase()).map_err(|e| Error::from(e.to_string()))
    }

    pub fn parse_salt(arg: &str) -> Result<Nsec3Salt<Vec<u8>>, Error> {
        if arg.len() >= 512 {
            Err(Error::from("Salt too long"))
        } else {
            Nsec3Salt::<Vec<u8>>::from_str(arg).map_err(|err| Error::from(err.to_string()))
        }
    }

    pub fn parse_nsec3_alg(arg: &str) -> Result<Nsec3HashAlg, Error> {
        if let Ok(num) = arg.parse() {
            let alg = Nsec3HashAlg::from_int(num);
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
                .expect("Error creating NSEC3 hash")
                .to_string()
                .to_lowercase();
        println!("{}.", hash);
        Ok(())
    }
}
