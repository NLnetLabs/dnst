use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use domain::{
    base::{
        iana::{DigestAlg, SecAlg},
        Record,
    },
    rdata::Ds,
    validate::DnskeyExt,
    zonefile::inplace::{Entry, ScannedRecordData},
};

use crate::error::Error;

#[derive(Clone, Debug, Parser)]
#[command(version)]
pub struct Key2ds {
    /// ignore SEP flag (i.e. make DS records for any key)
    #[arg(short = 'f')]
    ignore_sep: bool,

    /// do not write DS records to file(s) but to stdout
    #[arg(short = 'n')]
    write_to_stdout: bool,

    /// use SHA1 for the DS hash
    #[arg(short = '1', overrides_with_all = ["one", "two", "four"])]
    one: bool,

    /// use SHA256 for the DS hash
    #[arg(short = '2', overrides_with_all = ["one", "two", "four"])]
    two: bool,

    /// use SHA384 for the DS hash
    #[arg(short = '4', overrides_with_all = ["one", "two", "four"])]
    four: bool,

    /// Keyfile to read
    #[arg()]
    keyfile: PathBuf,
}

impl Key2ds {
    pub fn execute(self) -> Result<(), Error> {
        let mut file = std::fs::File::open(&self.keyfile).unwrap();
        let zonefile = domain::zonefile::inplace::Zonefile::load(&mut file).unwrap();
        for entry in zonefile {
            let entry = entry.unwrap();

            let Entry::Record(record) = entry else {
                continue;
            };

            let class = record.class();
            let ttl = record.ttl();
            let owner = record.owner();

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
            let digest_alg = self.determine_hash(sec_alg);

            let digest = dnskey.digest(&owner, digest_alg).unwrap();

            let ds = Ds::new(key_tag, sec_alg, digest_alg, digest).unwrap();

            let rr = Record::new(owner, class, ttl, ds);

            if self.write_to_stdout {
                println!("{}", rr);
            } else {
                let owner = owner.fmt_with_dot();
                let sec_alg = sec_alg.to_int();
                let mut out_file =
                    File::create(format!("K{owner}+{sec_alg:03}+{key_tag:05}.ds")).unwrap();
                writeln!(out_file, "{rr}").unwrap();
            }
        }

        Ok(())
    }

    fn determine_hash(&self, sec_alg: SecAlg) -> DigestAlg {
        // If a specific algorithm was set, use that
        if self.one {
            return DigestAlg::SHA1;
        } else if self.two {
            return DigestAlg::SHA256;
        } else if self.four {
            return DigestAlg::SHA384;
        }

        // Otherwise we try to determine a similar hash to the key
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
}
