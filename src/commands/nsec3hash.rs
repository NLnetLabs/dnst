use crate::env::Env;
use crate::error::Error;
use clap::builder::ValueParser;
use domain::base::iana::nsec3::Nsec3HashAlg;
use domain::base::name::{self, Name};
use domain::base::ToName;
use domain::rdata::nsec3::{Nsec3Salt, OwnerHash};
use lexopt::Arg;
// use domain::validator::nsec::nsec3_hash;
use octseq::OctetsBuilder;
use ring::digest;
use std::ffi::OsString;
use std::str::FromStr;

use super::{parse_os, parse_os_with, LdnsCommand};

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

const LDNS_HELP: &str = "\
ldns-nsec3-hash [OPTIONS] <domain name>
  prints the NSEC3 hash of the given domain name

  -a <algorithm> hashing algorithm number
  -t <number>    iterations
  -s <string>    salt in hex\
";

impl LdnsCommand for Nsec3Hash {
    const HELP: &'static str = LDNS_HELP;

    fn parse_ldns<I: IntoIterator<Item = OsString>>(args: I) -> Result<Self, Error> {
        let mut algorithm = Nsec3HashAlg::SHA1;
        let mut iterations = 1;
        let mut salt = Nsec3Salt::empty();
        let mut name = None;

        let mut parser = lexopt::Parser::from_args(args);

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Short('a') => {
                    let val = parser.value()?;
                    algorithm = parse_os_with("algorithm (-a)", &val, Nsec3Hash::parse_nsec_alg)?;
                }
                Arg::Short('s') => {
                    let val = parser.value()?;
                    salt = parse_os("salt (-s)", &val)?;
                }
                Arg::Short('t') => {
                    let val = parser.value()?;
                    iterations = parse_os("iterations (-t)", &val)?;
                }
                Arg::Value(val) => {
                    // Strange ldns compatibility case: only the first
                    // domain name is used.
                    if name.is_some() {
                        continue;
                    }
                    name = Some(parse_os("domain name", &val)?);
                }
                Arg::Short(x) => return Err(format!("Invalid short option: -{x}").into()),
                Arg::Long(x) => {
                    return Err(format!("Long options are not supported, but `--{x}` given").into())
                }
            }
        }

        let Some(name) = name else {
            return Err("Missing domain name argument".into());
        };

        Ok(Self {
            algorithm,
            iterations,
            salt,
            name,
        })
    }
}

impl Nsec3Hash {
    pub fn parse_name(arg: &str) -> Result<Name<Vec<u8>>, name::FromStrError> {
        Name::from_str(&arg.to_lowercase())
    }

    pub fn parse_nsec_alg(arg: &str) -> Result<Nsec3HashAlg, &'static str> {
        if let Ok(num) = arg.parse() {
            let alg = Nsec3HashAlg::from_int(num);
            // check for valid algorithm here, to be consistent with error messages
            // if domain::validator::nsec::supported_nsec3_hash(alg) {
            if alg.to_mnemonic().is_some() {
                Ok(alg)
            } else {
                Err("unknown algorithm number")
            }
        } else {
            Nsec3HashAlg::from_mnemonic(arg.as_bytes()).ok_or("unknown algorithm mnemonic")
        }
    }
}

impl Nsec3Hash {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        let hash = nsec3_hash(&self.name, self.algorithm, self.iterations, &self.salt)
            .to_string()
            .to_lowercase();

        let mut out = env.stdout();
        writeln!(out, "{}.", hash);
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

#[cfg(test)]
mod test {
    use crate::env::fake::FakeCmd;

    #[test]
    fn dnst_parse() {
        let cmd = FakeCmd::new(["dnst", "nsec3-hash"]);

        assert!(cmd.parse().is_err());
        assert!(cmd.args(["-a"]).parse().is_err());
    }

    #[test]
    fn dnst_run() {
        let cmd = FakeCmd::new(["dnst", "nsec3-hash"]);

        let res = cmd.run();
        assert_eq!(res.exit_code, 2);

        let res = cmd.args(["example.test"]).run();
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.stdout, "o09614ibh1cq1rcc86289olr22ea0fso.\n")
    }

    #[test]
    fn ldns_parse() {
        let cmd = FakeCmd::new(["ldns-nsec3-hash"]);

        assert!(cmd.parse().is_err());
        assert!(cmd.args(["-a"]).parse().is_err());
    }
}
