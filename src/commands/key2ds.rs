use std::ffi::OsString;
use std::io::{self, Write as _};
use std::path::PathBuf;

use clap::builder::ValueParser;
use clap::Parser;
use domain::base::iana::{DigestAlg, SecAlg};
use domain::base::zonefile_fmt::ZonefileFmt;
use domain::base::Record;
use domain::rdata::Ds;
use domain::validate::DnskeyExt;
use domain::zonefile::inplace::{Entry, ScannedRecordData};
use lexopt::Arg;

use crate::env::Env;
use crate::error::Error;

use super::LdnsCommand;

#[derive(Clone, Debug, Parser)]
#[command(version)]
pub struct Key2ds {
    /// ignore SEP flag (i.e. make DS records for any key)
    #[arg(long = "ignore-sep")]
    ignore_sep: bool,

    /// do not write DS records to file(s) but to stdout
    #[arg(short = 'n')]
    write_to_stdout: bool,

    /// Overwrite existing DS files
    #[arg(short = 'f', long = "force")]
    force_overwrite: bool,

    /// algorithm to use for digest
    #[arg(
        short = 'a',
        long = "algorithm",
        value_parser = ValueParser::new(parse_digest_alg)
    )]
    algorithm: Option<DigestAlg>,

    /// Keyfile to read
    #[arg()]
    keyfile: PathBuf,
}

pub fn parse_digest_alg(arg: &str) -> Result<DigestAlg, Error> {
    if let Ok(num) = arg.parse() {
        let alg = DigestAlg::from_int(num);
        if alg.to_mnemonic().is_some() {
            Ok(alg)
        } else {
            Err(Error::from("unknown algorithm number"))
        }
    } else {
        DigestAlg::from_mnemonic(arg.as_bytes()).ok_or(Error::from("unknown algorithm mnemonic"))
    }
}

const LDNS_HELP: &str = "\
ldns-key2ds [-fn] [-1|-2|-4] keyfile
  Generate a DS RR from the DNSKEYS in keyfile
  The following file will be created for each key:
  `K<name>+<alg>+<id>.ds`. The base name `K<name>+<alg>+<id>`
  will be printed to stdout.

Options:
  -f: ignore SEP flag (i.e. make DS records for any key)
  -n: do not write DS records to file(s) but to stdout
  (default) use similar hash to the key algorithm
  -1: use SHA1 for the DS hash
  -2: use SHA256 for the DS hash
  -4: use SHA384 for the DS hash\
";

impl LdnsCommand for Key2ds {
    const HELP: &'static str = LDNS_HELP;

    fn parse_ldns<I: IntoIterator<Item = OsString>>(args: I) -> Result<Self, Error> {
        let mut ignore_sep = false;
        let mut write_to_stdout = false;
        let mut algorithm = None;
        let mut keyfile = None;

        let mut parser = lexopt::Parser::from_args(args);

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Short('1') => algorithm = Some(DigestAlg::SHA1),
                Arg::Short('2') => algorithm = Some(DigestAlg::SHA256),
                Arg::Short('4') => algorithm = Some(DigestAlg::SHA384),
                Arg::Short('f') => ignore_sep = true,
                Arg::Short('n') => write_to_stdout = true,
                Arg::Value(val) => {
                    if keyfile.is_some() {
                        return Err("Only one keyfile is allowed".into());
                    }
                    keyfile = Some(val);
                }
                Arg::Short(x) => return Err(format!("Invalid short option: -{x}").into()),
                Arg::Long(x) => {
                    return Err(format!("Long options are not supported, but `--{x}` given").into())
                }
            }
        }

        let Some(keyfile) = keyfile else {
            return Err("No keyfile given".into());
        };

        Ok(Self {
            ignore_sep,
            write_to_stdout,
            algorithm,
            // Preventing overwritten files is a dnst feature that is not
            // present in the ldns version of this command.
            force_overwrite: true,
            keyfile: keyfile.into(),
        })
    }
}

impl Key2ds {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        let mut file = env.file_open(&self.keyfile).map_err(|e| {
            format!(
                "Failed to open public key file \"{}\": {e}",
                self.keyfile.display()
            )
        })?;
        let zonefile = domain::zonefile::inplace::Zonefile::load(&mut file).unwrap();
        for entry in zonefile {
            let entry = entry.map_err(|e| {
                format!(
                    "Error while reading public key from file \"{}\": {e}",
                    self.keyfile.display()
                )
            })?;

            // We only care about records in a zonefile
            let Entry::Record(record) = entry else {
                continue;
            };

            let class = record.class();
            let ttl = record.ttl();
            let owner = record.owner();

            // Of the records that we see, we only care about DNSKEY records
            let ScannedRecordData::Dnskey(dnskey) = record.data() else {
                continue;
            };

            // if ignore_sep is specified, we accept any key
            // otherwise, we only want SEP keys
            if !self.ignore_sep && !dnskey.is_secure_entry_point() {
                continue;
            }

            let key_tag = dnskey.key_tag();
            let sec_alg = dnskey.algorithm();
            let digest_alg = self
                .algorithm
                .unwrap_or_else(|| determine_hash_from_sec_alg(sec_alg));

            if digest_alg == DigestAlg::GOST {
                return Err("Error: the GOST algorithm is deprecated and must not be used. Try a different algorithm.".into());
            }

            let digest = dnskey
                .digest(&owner, digest_alg)
                .map_err(|e| format!("Error computing digest: {e}"))?;

            let ds = Ds::new(key_tag, sec_alg, digest_alg, digest).expect(
                "Infallible because the digest won't be too long since it's a valid digest",
            );

            let rr = Record::new(owner, class, ttl, ds);

            if self.write_to_stdout {
                writeln!(env.stdout(), "{}", rr.display_zonefile(false));
            } else {
                let owner = owner.fmt_with_dot();
                let sec_alg = sec_alg.to_int();
                let filename = format!("K{owner}+{sec_alg:03}+{key_tag:05}.ds");

                let res = if self.force_overwrite {
                    env.file_create(&filename)
                } else {
                    let res = env.file_create_new(&filename);

                    // Create a bit of a nicer message than a "File exists" IO
                    // error.
                    if let Err(e) = &res {
                        if e.kind() == io::ErrorKind::AlreadyExists {
                            return Err(format!(
                                "The file '{filename}' already exists, use the --force to overwrite"
                            )
                            .into());
                        }
                    }

                    res
                };

                let mut out_file =
                    res.map_err(|e| format!("Could not create file \"{filename}\": {e}"))?;

                writeln!(out_file, "{}", rr.display_zonefile(false))
                    .map_err(|e| format!("Could not write to file \"{filename}\": {e}"))?;

                // This is different from ldns, but I think writing out the
                // filename we wrote to is useful:
                writeln!(env.stdout(), "Wrote DS record to: {filename}");
            }
        }

        Ok(())
    }
}

fn determine_hash_from_sec_alg(sec_alg: SecAlg) -> DigestAlg {
    match sec_alg {
        SecAlg::RSASHA256
        | SecAlg::RSASHA512
        | SecAlg::ED25519
        | SecAlg::ED448
        | SecAlg::ECDSAP256SHA256 => DigestAlg::SHA256,
        SecAlg::ECDSAP384SHA384 => DigestAlg::SHA384,
        SecAlg::ECC_GOST => DigestAlg::GOST,
        _ => DigestAlg::SHA1,
    }
}

#[cfg(test)]
mod test {
    use tempfile::TempDir;

    use crate::env::fake::FakeCmd;
    use std::fs::File;
    use std::io::Write;

    fn run_setup() -> TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        let mut file = File::create(dir.path().join("key1.key")).unwrap();
        file
            .write_all(b"example.test.	IN	DNSKEY	257 3 15 8AWQIqSo35guqX6WPIFsUlOnbiqGC5sydeBTVMdLGMs= ;{id = 60136 (ksk), size = 256b}\n")
            .unwrap();
        file.flush().unwrap();

        dir
    }

    #[test]
    fn file_with_single_key() {
        let dir = run_setup();

        let res = FakeCmd::new(["dnst", "key2ds", "key1.key"]).cwd(&dir).run();

        assert_eq!(res.exit_code, 0, "{res:?}");
        assert_eq!(
            res.stdout,
            "Wrote DS record to: Kexample.test.+015+60136.ds\n"
        );
        assert_eq!(res.stderr, "");

        let out = std::fs::read_to_string(dir.path().join("Kexample.test.+015+60136.ds")).unwrap();
        assert_eq!(out, "example.test. 3600 IN DS 60136 15 2 52BD3BF40C8220BF1A3E2A3751C423BC4B69BCD7F328D38C4CD021A85DE65AD4\n");
    }

    #[test]
    fn print_to_stdout() {
        let dir = run_setup();

        let res = FakeCmd::new(["dnst", "key2ds", "-n", "key1.key"])
            .cwd(&dir)
            .run();

        assert_eq!(res.exit_code, 0);
        assert_eq!(
            res.stdout,
            "example.test. 3600 IN DS 60136 15 2 52BD3BF40C8220BF1A3E2A3751C423BC4B69BCD7F328D38C4CD021A85DE65AD4\n"
        );
        assert_eq!(res.stderr, "");
    }

    #[test]
    fn overwrite_file() {
        let dir = run_setup();

        // Make sure the file already exists
        File::create(dir.path().join("Kexample.test.+015+60136.ds")).unwrap();

        let res = FakeCmd::new(["dnst", "key2ds", "key1.key"]).cwd(&dir).run();

        assert_eq!(res.exit_code, 1);
        assert_eq!(res.stdout, "");
        assert!(res.stderr.contains(
            "The file 'Kexample.test.+015+60136.ds' already exists, use the --force to overwrite"
        ));

        let res = FakeCmd::new(["dnst", "key2ds", "--force", "key1.key"])
            .cwd(&dir)
            .run();

        assert_eq!(res.exit_code, 0);
        assert_eq!(
            res.stdout,
            "Wrote DS record to: Kexample.test.+015+60136.ds\n"
        );
        assert_eq!(res.stderr, "");
    }
}
