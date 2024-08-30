use crate::error::Error;
use clap::builder::ValueParser;
use domain::base::iana::nsec3::Nsec3HashAlg;
use domain::base::name::Name;
use domain::base::ToName;
use domain::rdata::nsec3::{Nsec3Salt, OwnerHash};
// use domain::validator::nsec::nsec3_hash;
use octseq::OctetsBuilder;
use ring::digest;
use std::str::FromStr;

// ldns-nsec3-hash [OPTIONS] <domain name>
//   prints the NSEC3 hash of the given domain name
// -a [algorithm] hashing algorithm
// -t [number] number of hash iterations
// -s [string] salt

#[derive(Clone, Debug, clap::Args)]
pub struct Nsec3Hash {
    /// The hashing algorithm to use
    #[arg(
        long,
        short = 'a',
        value_name = "NUMBER",
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
        let hash = nsec3_hash(&self.name, self.algorithm, self.iterations, &self.salt)
            .to_string()
            .to_lowercase();
        println!("{}.", hash);
        Ok(())
    }
}

// XXX: This is a verbatim copy of the nsec3_hash function from domain::validator::nsec.
// TODO: when exposed/available, replace with implementation from domain::validator::nsec
fn nsec3_hash<N, HashOcts>(
    owner: N,
    algorithm: Nsec3HashAlg,
    iterations: u16,
    salt: &Nsec3Salt<HashOcts>,
) -> OwnerHash<Vec<u8>>
where
    N: ToName,
    HashOcts: AsRef<[u8]>,
{
    let mut buf = Vec::new();

    owner.compose_canonical(&mut buf).expect("infallible");
    buf.append_slice(salt.as_slice()).expect("infallible");

    let digest_type = if algorithm == Nsec3HashAlg::SHA1 {
        &digest::SHA1_FOR_LEGACY_USE_ONLY
    } else {
        // totest, unsupported NSEC3 hash algorithm
        // Unsupported.
        panic!("should not be called with an unsupported algorithm");
    };

    let mut ctx = digest::Context::new(digest_type);
    ctx.update(&buf);
    let mut h = ctx.finish();

    for _ in 0..iterations {
        buf.truncate(0);
        buf.append_slice(h.as_ref()).expect("infallible");
        buf.append_slice(salt.as_slice()).expect("infallible");

        let mut ctx = digest::Context::new(digest_type);
        ctx.update(&buf);
        h = ctx.finish();
    }

    // For normal hash algorithms this should not fail.
    OwnerHash::from_octets(h.as_ref().to_vec()).expect("should not fail")
}
