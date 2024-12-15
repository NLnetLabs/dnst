use std::ffi::OsString;
use std::str::FromStr;

use clap::builder::ValueParser;
use domain::base::iana::nsec3::Nsec3HashAlg;
use domain::base::name::Name;
use domain::rdata::nsec3::Nsec3Salt;
use domain::validate::nsec3_hash;
use lexopt::Arg;

use crate::env::Env;
use crate::error::Error;
use crate::parse::parse_name;
use crate::Args;

use super::{parse_os, parse_os_with, Command, LdnsCommand};

#[derive(Clone, Debug, clap::Args)]
pub struct Nsec3Hash {
    /// The hashing algorithm to use
    #[arg(
        long = "algorithm",
        short = 'a',
        value_name = "NUMBER OR MNEMONIC",
        default_value = "SHA-1",
        value_parser = ValueParser::new(Nsec3Hash::parse_nsec3_alg)
    )]
    algorithm: Nsec3HashAlg,

    /// The number of hash iterations
    #[arg(
        long = "iterations",
        short = 'i',
        visible_short_alias = 't',
        value_name = "NUMBER",
        default_value_t = 0
    )]
    iterations: u16,

    /// The salt in hex representation
    #[arg(
        long = "salt",
        short = 's',
        value_name = "HEX STRING",
        default_value_t = Nsec3Salt::empty(),
        value_parser = ValueParser::new(Nsec3Hash::parse_salt)
    )]
    salt: Nsec3Salt<Vec<u8>>,

    /// The domain name to hash
    #[arg(value_name = "DOMAIN NAME", value_parser = ValueParser::new(parse_name))]
    name: Name<Vec<u8>>,
}

const LDNS_HELP: &str = "\
ldns-nsec3-hash [OPTIONS] <domain name>
  prints the NSEC3 hash of the given domain name
-a [algorithm] hashing algorithm
-t [number] number of hash iterations
-s [string] salt
";

impl LdnsCommand for Nsec3Hash {
    const NAME: &'static str = "nsec3-hash";
    const HELP: &'static str = LDNS_HELP;
    const COMPATIBLE_VERSION: &'static str = "1.8.4";

    fn parse_ldns<I: IntoIterator<Item = OsString>>(args: I) -> Result<Args, Error> {
        let mut algorithm = Nsec3HashAlg::SHA1;
        let mut iterations = 0;
        let mut salt = Nsec3Salt::empty();
        let mut name = None;

        let mut parser = lexopt::Parser::from_args(args);

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Short('a') => {
                    let val = parser.value()?;
                    algorithm =
                        parse_os_with("algorithm (-a)", &val, Nsec3Hash::parse_nsec3_alg_as_num)?;
                }
                Arg::Short('s') => {
                    let val = parser.value()?;
                    salt = parse_os_with("salt (-s)", &val, Nsec3Hash::parse_salt)?;
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

        Ok(Args::from(Command::Nsec3Hash(Self {
            algorithm,
            iterations,
            salt,
            name,
        })))
    }
}

impl Nsec3Hash {
    // Note: This function is only necessary until
    // https://github.com/NLnetLabs/domain/pull/431 is merged.
    pub fn parse_salt(arg: &str) -> Result<Nsec3Salt<Vec<u8>>, Error> {
        if arg.len() >= 512 {
            Err(Error::from("Salt too long"))
        } else {
            Nsec3Salt::<Vec<u8>>::from_str(arg).map_err(|err| Error::from(err.to_string()))
        }
    }

    pub fn parse_nsec3_alg(arg: &str) -> Result<Nsec3HashAlg, &'static str> {
        if let Ok(num) = arg.parse() {
            Self::num_to_nsec3_alg(num)
        } else {
            Nsec3HashAlg::from_mnemonic(arg.as_bytes()).ok_or("unknown algorithm mnemonic")
        }
    }

    pub fn parse_nsec3_alg_as_num(arg: &str) -> Result<Nsec3HashAlg, &'static str> {
        match arg.parse() {
            Ok(num) => Self::num_to_nsec3_alg(num),
            Err(_) => Err("malformed algorithm number"),
        }
    }

    pub fn num_to_nsec3_alg(num: u8) -> Result<Nsec3HashAlg, &'static str> {
        let alg = Nsec3HashAlg::from_int(num);
        match alg.to_mnemonic() {
            Some(_) => Ok(alg),
            None => Err("unknown algorithm number"),
        }
    }
}

impl Nsec3Hash {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        let hash =
            nsec3_hash::<_, _, Vec<u8>>(&self.name, self.algorithm, self.iterations, &self.salt)
                .map_err(|err| format!("Error creating NSEC3 hash: {err}"))?
                .to_string()
                .to_lowercase();

        writeln!(env.stdout(), "{}.", hash);
        Ok(())
    }
}

// These are just basic tests as there is very little code in this module, the
// actual NSEC3 generation should be tested as part of the domain crate.
#[cfg(test)]
mod tests {
    mod without_cli {
        use core::str::FromStr;

        use domain::base::iana::Nsec3HashAlg;
        use domain::base::Name;
        use domain::rdata::nsec3::Nsec3Salt;

        use crate::commands::nsec3hash::Nsec3Hash;
        use crate::env::fake::{FakeCmd, FakeEnv, FakeStream};

        // Note: For the types we use that are provided by the domain crate,
        // construction of them from bad inputs should be tested in that
        // crate, not here. This test exercises the just the actual
        // functionalty of this module without the outer layer of CLI argument
        // parsing which is independent of whether we are invoked as `dnst
        // nsec3-hash`` or as `ldns-nsec3-hash`.
        #[test]
        fn execute() {
            let env = FakeEnv {
                cmd: FakeCmd::new(["unused"]),
                stdout: FakeStream::default(),
                stderr: FakeStream::default(),
                stelline: None,
            };

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
                nsec3_hash.execute(&env).unwrap();
            }

            for iterations in [0, 1, u16::MAX - 1, u16::MAX] {
                let nsec3_hash = Nsec3Hash {
                    algorithm: Nsec3HashAlg::SHA1,
                    iterations,
                    salt: Nsec3Salt::empty(),
                    name: Name::root(),
                };
                nsec3_hash.execute(&env).unwrap();
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
                nsec3_hash.execute(&env).unwrap();
            }

            for name in [
                ".", "a", "a.", "ab", "ab.", "a.ab", "a.ab.", "ab.ab", "ab.ab.", "a.ab.ab",
                "a.ab.ab.",
            ] {
                let name = Name::from_str(name)
                    .unwrap_or_else(|err| panic!("Name '{name}' was expected to be okay: {err}"));
                let nsec3_hash = Nsec3Hash {
                    algorithm: Nsec3HashAlg::SHA1,
                    iterations: 0,
                    salt: Nsec3Salt::empty(),
                    name,
                };
                nsec3_hash.execute(&env).unwrap();
            }
        }
    }

    mod with_dnst_cli {
        use core::str;

        use crate::env::fake::FakeCmd;
        use crate::error::Error;
        use crate::Args;

        #[test]
        fn accept_good_cli_args() {
            assert_cmd_eq(&["nlnetlabs.nl"], "asqe4ap6479d7085ljcs10a2fpb2do94.\n");
            assert_cmd_eq(
                &["-a", "1", "nlnetlabs.nl"],
                "asqe4ap6479d7085ljcs10a2fpb2do94.\n",
            );
            assert_cmd_eq(
                &["-a", "SHA-1", "nlnetlabs.nl"],
                "asqe4ap6479d7085ljcs10a2fpb2do94.\n",
            );
            assert_cmd_eq(
                &["-i", "0", "nlnetlabs.nl"],
                "asqe4ap6479d7085ljcs10a2fpb2do94.\n",
            );
            assert_cmd_eq(
                &["-i", "1", "nlnetlabs.nl"],
                "e3dbcbo05tvq0u7po4emvbu79c8vpcgk.\n",
            );
            assert_cmd_eq(
                &["-s", "", "nlnetlabs.nl"],
                "asqe4ap6479d7085ljcs10a2fpb2do94.\n",
            );
            assert_cmd_eq(
                &["-s", "DEADBEEF", "nlnetlabs.nl"],
                "dfucs7bmmtsil9gij77k1kmocclg5d8a.\n",
            );
        }

        #[test]
        fn reject_bad_cli_args() {
            assert!(parse_cmd_line(&[]).is_err());
            assert!(parse_cmd_line(&[""]).is_err());

            assert!(parse_cmd_line(&["-a"]).is_err());
            assert!(parse_cmd_line(&["-a", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-a", "", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-a", "2", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-a", "SHA1", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-a", "SHA-256", "nlnetlabs.nl"]).is_err());

            assert!(parse_cmd_line(&["-i"]).is_err());
            assert!(parse_cmd_line(&["-i", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-i", "", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-i", "-1", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-i", "abc", "nlnetlabs.nl"]).is_err());
            assert!(
                parse_cmd_line(&["-i", &((u16::MAX as u32) + 1).to_string(), "nlnetlabs.nl"])
                    .is_err()
            );

            assert!(parse_cmd_line(&["-s"]).is_err());
            assert!(parse_cmd_line(&["-s", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-s", "NOTHEX", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-s", &"aa".repeat(256), "nlnetlabs.nl"]).is_err());
        }

        //------------ Helper functions ------------------------------------------

        fn parse_cmd_line(args: &[&str]) -> Result<Args, Error> {
            FakeCmd::new(["dnst", "nsec3-hash"]).args(args).parse()
        }

        fn assert_cmd_eq(args: &[&str], expected_output: &str) {
            let result = FakeCmd::new(["dnst", "nsec3-hash"]).args(args).run();
            assert_eq!(result.exit_code, 0);
            assert_eq!(result.stdout, expected_output);
            assert_eq!(result.stderr, "");
        }
    }

    mod with_ldns_cli {
        use core::str;

        use crate::env::fake::FakeCmd;
        use crate::error::Error;
        use crate::Args;

        #[test]
        fn accept_good_cli_args() {
            assert_cmd_eq(&["nlnetlabs.nl"], "asqe4ap6479d7085ljcs10a2fpb2do94.\n");
            assert_cmd_eq(
                &["-a", "1", "nlnetlabs.nl"],
                "asqe4ap6479d7085ljcs10a2fpb2do94.\n",
            );
            assert_cmd_eq(
                &["-t", "0", "nlnetlabs.nl"],
                "asqe4ap6479d7085ljcs10a2fpb2do94.\n",
            );
            assert_cmd_eq(
                &["-t", "1", "nlnetlabs.nl"],
                "e3dbcbo05tvq0u7po4emvbu79c8vpcgk.\n",
            );
            assert_cmd_eq(
                &["-s", "", "nlnetlabs.nl"],
                "asqe4ap6479d7085ljcs10a2fpb2do94.\n",
            );
            assert_cmd_eq(
                &["-s", "DEADBEEF", "nlnetlabs.nl"],
                "dfucs7bmmtsil9gij77k1kmocclg5d8a.\n",
            );
        }

        #[test]
        fn reject_bad_cli_args() {
            assert!(parse_cmd_line(&[]).is_err());
            assert!(parse_cmd_line(&[""]).is_err());

            assert!(parse_cmd_line(&["-a"]).is_err());
            assert!(parse_cmd_line(&["-a", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-a", "", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-a", "2", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-a", "SHA1", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-a", "SHA-1", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-a", "SHA-256", "nlnetlabs.nl"]).is_err());

            assert!(parse_cmd_line(&["-t"]).is_err());
            assert!(parse_cmd_line(&["-t", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-t", "", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-t", "-1", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-t", "abc", "nlnetlabs.nl"]).is_err());
            assert!(
                parse_cmd_line(&["-t", &((u16::MAX as u32) + 1).to_string(), "nlnetlabs.nl"])
                    .is_err()
            );

            assert!(parse_cmd_line(&["-s"]).is_err());
            assert!(parse_cmd_line(&["-s", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-s", "NOTHEX", "nlnetlabs.nl"]).is_err());
            assert!(parse_cmd_line(&["-s", &"aa".repeat(256), "nlnetlabs.nl"]).is_err());
        }

        //------------ Helper functions ------------------------------------------

        fn parse_cmd_line(args: &[&str]) -> Result<Args, Error> {
            FakeCmd::new(["ldns-nsec3-hash"]).args(args).parse()
        }

        #[track_caller]
        fn assert_cmd_eq(args: &[&str], expected_output: &str) {
            let result = FakeCmd::new(["ldns-nsec3-hash"]).args(args).run();
            assert_eq!(result.exit_code, 0);
            assert_eq!(result.stdout, expected_output);
            assert_eq!(result.stderr, "");
        }
    }
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
        assert_eq!(res.stdout, "jbas736chung3bb701jkjdhqkqlhvug7.\n")
    }

    #[test]
    fn ldns_parse() {
        let cmd = FakeCmd::new(["ldns-nsec3-hash"]);

        assert!(cmd.parse().is_err());
        assert!(cmd.args(["-a"]).parse().is_err());
    }
}
