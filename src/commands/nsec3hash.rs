use std::io::Write;
use std::str::FromStr;

use clap::builder::ValueParser;
use domain::base::iana::nsec3::Nsec3HashAlg;
use domain::base::name::Name;
use domain::rdata::nsec3::Nsec3Salt;
use domain::validate::nsec3_hash;

use crate::error::Error;

#[derive(Clone, Debug, clap::Args)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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
    pub fn execute<W: Write>(self, writer: &mut W) -> Result<(), Error> {
        let hash =
            nsec3_hash::<_, _, Vec<u8>>(&self.name, self.algorithm, self.iterations, &self.salt)
                .map_err(|err| format!("Error creating NSEC3 hash: {err}"))?
                .to_string()
                .to_lowercase();
        writeln!(writer, "{}.", hash)
            .map_err(|err| Error::from(format!("Error writing to output: {err}")))
    }
}

// These are just basic tests as there is very little code in this module, the
// actual NSEC3 generation should be tested as part of the domain crate. See
// also: fuzz/fuzz_targets/nsec3-hash.rs.
#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::Args;

    use super::*;
    use core::str;

    // The types we use are provided by the domain crate and construction of
    // them from bad inputs should be tested there.
    #[test]
    fn accept_good_inputs() {
        // We don't test all permutations as that would take too long (~20 seconds)
        #[allow(clippy::single_element_loop)]
        for algorithm in ["SHA-1"] {
            let algorithm = Nsec3HashAlg::from_mnemonic(algorithm.as_bytes())
                .unwrap_or_else(|| panic!("Algorithm '{algorithm}' was expected to be okay"));
            let nsec3_hash = Nsec3Hash {
                algorithm,
                iterations: 0,
                salt: Nsec3Salt::empty(),
                name: Name::root(),
            };
            nsec3_hash.execute(&mut std::io::sink()).unwrap();
        }

        for iterations in [0, 1, u16::MAX - 1, u16::MAX] {
            let nsec3_hash = Nsec3Hash {
                algorithm: Nsec3HashAlg::SHA1,
                iterations,
                salt: Nsec3Salt::empty(),
                name: Name::root(),
            };
            nsec3_hash.execute(&mut std::io::sink()).unwrap();
        }

        for salt in ["", "-", "aa", "aabb", "aa".repeat(255).as_str()] {
            let salt = Nsec3Salt::from_str(salt)
                .unwrap_or_else(|err| panic!("Salt '{salt}' was expected to be okay: {err}"));
            let nsec3_hash = Nsec3Hash {
                algorithm: Nsec3HashAlg::SHA1,
                iterations: 0,
                salt,
                name: Name::root(),
            };
            nsec3_hash.execute(&mut std::io::sink()).unwrap();
        }

        for name in [
            ".", "a", "a.", "ab", "ab.", "a.ab", "a.ab.", "ab.ab", "ab.ab.", "a.ab.ab", "a.ab.ab.",
        ] {
            let name = Name::from_str(name)
                .unwrap_or_else(|err| panic!("Name '{name}' was expected to be okay: {err}"));
            let nsec3_hash = Nsec3Hash {
                algorithm: Nsec3HashAlg::SHA1,
                iterations: 0,
                salt: Nsec3Salt::empty(),
                name,
            };
            nsec3_hash.execute(&mut std::io::sink()).unwrap();
        }
    }

    #[test]
    fn reject_bad_inputs() {
        assert_arg_parse_failure(&[]);
        assert_arg_parse_failure(&[""]);

        assert_arg_parse_failure(&["-a"]);
        assert_arg_parse_failure(&["-a", "nlnetlabs.nl"]);
        assert_arg_parse_failure(&["-a", "", "nlnetlabs.nl"]);
        assert_arg_parse_failure(&["-a", "2", "nlnetlabs.nl"]);
        assert_arg_parse_failure(&["-a", "SHA-256", "nlnetlabs.nl"]);

        assert_arg_parse_failure(&["-t", "nlnetlabs.nl"]);
        assert_arg_parse_failure(&["-t", "", "nlnetlabs.nl"]);
        assert_arg_parse_failure(&["-t", "-1", "nlnetlabs.nl"]);
        assert_arg_parse_failure(&["-t", "abc", "nlnetlabs.nl"]);
        assert_arg_parse_failure(&["-t", &((u16::MAX as u32) + 1).to_string(), "nlnetlabs.nl"]);

        assert_arg_parse_failure(&["-s"]);
        assert_arg_parse_failure(&["-s", "nlnetlabs.nl"]);
        assert_arg_parse_failure(&["-s", "NOTHEX", "nlnetlabs.nl"]);
        assert_arg_parse_failure(&["-s", &"aa".repeat(256), "nlnetlabs.nl"]);
    }

    #[test]
    fn check_defaults() {
        // Equivalent to ldns-nsec-hash -t 1 nlnetlabs.nl
        let args = parse_cmd_line(&["nlnetlabs.nl"]).unwrap();

        let mut captured_stdout = vec![];
        assert!(args.execute(&mut captured_stdout).is_ok());
        assert_eq!(
            str::from_utf8(&captured_stdout),
            Ok("e3dbcbo05tvq0u7po4emvbu79c8vpcgk.\n")
        );
    }

    //------------ Helper functions ------------------------------------------

    fn parse_cmd_line(args: &[&str]) -> Result<Args, clap::error::Error> {
        Args::try_parse_from(["dnst", "nsec3-hash"].iter().chain(args))
    }

    fn assert_arg_parse_failure(args: &[&str]) {
        if parse_cmd_line(args).is_ok() {
            panic!("Expected error with arguments: {args:?}");
        }
    }
}
