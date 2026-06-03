use core::clone::Clone;

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::PathBuf;

use clap::Parser;

use domain::new::base::name::RevNameBuf;
use domain::new::base::RType;
use domain::new::zonefile::simple::Entry;
use domain::new::zonefile::simple::ZonefileScanner;

use crate::env::Env;
use crate::error::Error;
use crate::Args;

use super::{Command, LdnsCommand};

//------------ Constants -----------------------------------------------------
// TODO: Update
const DNSSEC_TYPES: [RType; 4] = [RType::DNSKEY, RType::NSEC, RType::NSEC3, RType::RRSIG];
//------------ ReadZone ------------------------------------------------------

#[derive(Clone, Debug, clap::Parser, PartialEq)]
// TODO
#[clap(after_help = "Read-Zone dnst HELP")]
pub struct ReadZone {
    // -----------------------------------------------------------------------
    // Original ldns-read-zone options in ldns-read-zone -h order:
    // -----------------------------------------------------------------------
    /// Canonicalize all resource records in the zone before printing
    #[arg(short = 'c', default_value_t = false)]
    canonicalize: bool,

    /// Only print DNSSEC data from the zone. This option skips every record
    /// that is not of type NSEC, NSEC3, RRSIG or DNSKEY. DS records are not
    /// printed.
    #[arg(short = 'd', default_value_t = false)]
    print_only_dnssec: bool,

    /// Print a (null) for the RRSIG inception, expiry and key data. This option
    /// can be used when comparing different signing systems that use the same
    /// DNSKEYs for signing but would have a slightly different timings/jitter.
    #[arg(short = 'O', default_value_t = false)]
    print_rrsig_null: bool,

    /// Do not print the SOA record
    #[arg(short = 'n', default_value_t = false)]
    print_not_soa: bool,

    /// Pad the SOA serial number with spaces so the number and the spaces
    /// together take ten characters. This is useful for in file serial number
    /// increments.
    #[arg(short = 'p', default_value_t = false)]
    pad_soa_serial: bool,

    /// Strip DNSSEC data from the zone. This option skips every record that is
    /// of type NSEC, NSEC3, RRSIG or DNSKEY. DS records are still printed.
    #[arg(short = 's', default_value_t = false)]
    print_not_dnssec: bool,

    /// Set serial number to the given number, or when preceded by a sign,
    /// offset the exisiting number with it. When giving the literal strings
    /// YYYYMMDDxx or unixtime, the serial number is tried to be reset in
    /// datecounter or in unixtime format respectively. Though is the updated
    /// serial number is smaller than the original one, the original one is
    /// simply increased by one.
    #[arg(short = 'S', required = false)]
    manipulate_serial: Option<String>,

    // TODO: I don't think that -z implies -c. Because you can sort the records
    // even though you print them in the original form i.e. with some capital
    // letters.
    /// Sort the zone before printing (this implies -c)
    #[arg(short = 'z', default_value_t = false)]
    canonical_sort: bool,

    // -----------------------------------------------------------------------
    // Extra options not supported by the original ldns-signzone:
    // -----------------------------------------------------------------------
    /// Origin for the zone.
    #[arg(short = 'o', value_name = "domain", required = false)]
    origin: Option<RevNameBuf>,

    // -----------------------------------------------------------------------
    // Original ldns-signzone positional arguments in position order:
    // -----------------------------------------------------------------------
    /// The zonefile to sign.
    #[arg(value_name = "zonefile")]
    zonefile_path: PathBuf,

    // -----------------------------------------------------------------------
    // Non-command line argument fields:
    // -----------------------------------------------------------------------
    /// Whether or not we were invoked as `ldns-signzone`.
    #[arg(skip)]
    invoked_as_ldns: bool,
}

// TODO: FIX Help use from repository
const LDNS_HELP: &str = r###"ldns-read-zone [OPTIONS] <zonefile>
    Reads the zonefile and prints it.
    The RR count of the zone is printed to stderr.
    -0 zeroize timestamps and signature in RRSIG records.
    -b include Bubble Babble encoding of DS's.
    -c canonicalize all rrs in the zone.
    -d only show DNSSEC data from the zone
    -e <rr type>
            Do not print RRs of the given <rr type>.
            This option may be given multiple times.
            -e is not meant to be used together with -E.
    -E <rr type>
            Print only RRs of the given <rr type>.
            This option may be given multiple times.
            -E is not meant to be used together with -e.
    -h show this text
    -n do not print the SOA record
    -p prepend SOA serial with spaces so it takes exactly ten characters.
    -s strip DNSSEC data from the zone
    -S [[+|-]<number> | YYYYMMDDxx |  unixtime ]
            Set serial number to <number> or, when preceded by a sign,
            offset the existing number with <number>.  With YYYYMMDDxx
            the serial is formatted as a datecounter, and with unixtime as
            the number of seconds since 1-1-1970.  However, on serial
            number decrease, +1 is used in stead.  (implies -s)
    -u <rr type>
            Mark <rr type> for printing in unknown type format.
            This option may be given multiple times.
            -u is not meant to be used together with -U.
    -U <rr type>
            Mark <rr type> for not printing in unknown type format.
            This option may be given multiple times.
            The first occurrence of the -U option marks all RR types for
            printing in unknown type format except for the given <rr type>.
            Subsequent -U options will clear the mark for those <rr type>s
            too, so that only the given <rr type>s will be printed in the
            presentation format specific for those <rr type>s.
            -U is not meant to be used together with -u.
    -v shows the version and exits
    -z sort the zone (implies -c).

if no file is given standard input is read
"###;

impl LdnsCommand for ReadZone {
    const NAME: &'static str = "read-zone";
    const HELP: &'static str = LDNS_HELP;
    const COMPATIBLE_VERSION: &'static str = "1.8.4"; // TODO

    fn parse_ldns<I: IntoIterator<Item = OsString>>(_unargs: I) -> Result<Args, Error> {
        let args = ReadZone::parse();
        println!("{:?}", args);

        Ok(Args::from(Command::ReadZone(Self {
            canonicalize: args.canonicalize,
            print_only_dnssec: args.print_only_dnssec,
            print_rrsig_null: args.print_rrsig_null,
            print_not_soa: args.print_not_soa,
            pad_soa_serial: args.pad_soa_serial,
            print_not_dnssec: args.print_not_dnssec,
            manipulate_serial: args.manipulate_serial,
            canonical_sort: args.canonical_sort,
            origin: args.origin,
            zonefile_path: args.zonefile_path,
            invoked_as_ldns: args.invoked_as_ldns,
        })))
    }
}

impl ReadZone {
    pub fn execute(&self, env: impl Env) -> Result<(), Error> {
        // Read the zone file.

        // Had to impl From<std::io::Error> here
        // I do the reading of the Zonefile here because then I can test the
        // output of the zonefile without creating a file for it.
        let zonefile_buf = BufReader::new(File::open(&self.zonefile_path)?);

        self.go_through_zone(zonefile_buf, &env.stdout())?;

        Ok(())
    }

    // TODO: Better name
    // pub (super) for testing
    pub(super) fn go_through_zone<R, W>(&self, zf_buf: R, mut out: W) -> Result<(), Error>
    where
        R: io::BufRead,
        W: io::Write,
    {
        let mut zf = ZonefileScanner::new(zf_buf, self.origin.as_deref());
        loop {
            let entry = match zf.scan() {
                Ok(Some(entry)) => entry,
                Ok(None) => break, // no more left
                Err(e) => return Err(Error::new(&e.to_string())),
            };
            let Entry::Record(record) = entry else {
                eprintln!("Skipping non-Record entries");
                continue;
            };

            //--- Only print DNSSEC data
            if self.print_only_dnssec && is_dnssec_data(record.rtype) {
                continue;
            }
            //--- Do not print DNSSEC data
            if self.print_not_dnssec && !is_dnssec_data(record.rtype) {
                continue;
                // Check if ldns checks for apex
            }
            //--- Do not print SOA
            // Check if ldns checks for apex
            if self.print_not_soa && record.rtype == RType::SOA {
                continue;
            }

            match out.write_all(format!("{:?}", record).as_bytes()) {
                Ok(_) => (),
                Err(e) => eprintln!("Error while writing to Writer {:?}", e),
            }
        }
        out.flush()?;
        Ok(())
    }
}

fn is_dnssec_data(rtype: RType) -> bool {
    DNSSEC_TYPES.contains(&rtype)
}
//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;

    use std::str::FromStr;

    use domain::new::base::name::{NameParseError, RevNameBuf};

    use crate::commands::readzone::PathBuf;
    use crate::commands::Command;
    use crate::env::fake::FakeCmd;

    #[track_caller]
    fn parse(args: FakeCmd) -> ReadZone {
        let res = args.parse().unwrap();
        let Command::ReadZone(x) = res.command else {
            panic!("Not a ReadZone!");
        };
        x
    }

    #[track_caller]
    fn get_default_readzone(path_str: &str) -> ReadZone {
        ReadZone {
            canonicalize: false,
            print_only_dnssec: false,
            print_rrsig_null: false,
            manipulate_serial: None,
            origin: None,
            pad_soa_serial: false,
            print_not_dnssec: false,
            print_not_soa: false,
            canonical_sort: false,
            zonefile_path: PathBuf::from(path_str),
            invoked_as_ldns: false,
        }
    }

    #[test]
    fn dnst_parse_successes() {
        let cmd = FakeCmd::new(["dnst", "read-zone"]);

        // Check the defaults
        let path = "example.org.zone";
        let base = ReadZone {
            ..get_default_readzone(path)
        };
        assert_eq!(parse(cmd.args(["-o", "example.org", path])), base);
    }

    #[test]
    fn check_revnamebuf() {
        let name = "example.org.";
        let rnb: Result<RevNameBuf, NameParseError> = name.parse();
        assert!(rnb.is_ok());
    }

    fn verify_readzone_output(readzone: ReadZone, zonefile: &str, output: &str) {
        let mut vec_buf: Vec<u8> = Vec::new();
        let result = readzone.go_through_zone(zonefile.as_bytes(), &mut vec_buf);
        assert!(result.is_ok());

        let is_equal = vec_buf == output.as_bytes();
        println!("{:?}", String::from_utf8(vec_buf));
        assert!(is_equal)
    }

    #[test]
    fn not_print_soa() {
        let zonefile = "example.com. 42 IN SOA master.example.com. noc.example.com. 1 1 1 1 1";

        let readzone = ReadZone {
            print_not_soa: true,
            ..get_default_readzone("path-does-not-matter-here.txt")
        };
        verify_readzone_output(readzone, zonefile, "");
    }

    #[test]
    fn simple_readzone() {
        let res1 = FakeCmd::new([
            "dnst",
            "read-zone",
            "-c",
            "-o",
            "example.com",
            "test-data/example.org",
        ])
        .run();

        println!("{:?}", res1.stdout);
        assert_eq!(res1.stderr, "");
        assert_eq!(res1.exit_code, 0);
    }

    #[test]
    fn name_canonicalization() {
        use bytes::Bytes;

        use domain::base::iana::Class;
        use domain::base::name::Name;
        use domain::base::Record;
        use domain::base::Ttl;
        use domain::new;
        use domain::rdata::Mx;
        use domain::rdata::ZoneRecordData;

        let owner: Name<bytes::Bytes> = Name::<bytes::Bytes>::from_str("EXAMPLE.com.").unwrap();
        let class = Class::IN;
        let ttl = Ttl::from_hours(1);
        let exchange: Name<bytes::Bytes> =
            Name::<bytes::Bytes>::from_str("mail.example.com.").unwrap();
        let data: ZoneRecordData<Bytes, Name<Bytes>> = ZoneRecordData::Mx(Mx::new(10, exchange));

        let record: Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>;
        record = Record::new(owner, class, ttl, data);

        let name: new::base::name::NameBuf = "EXAMPLE.com".parse().unwrap();
        let rtype: new::base::RType = new::base::RType::MX;
        let rclass = new::base::RClass::IN;
        let ttl = new::base::TTL::from(3600);
        let preference = new::base::wire::U16::new(10);
        let exchange: new::base::name::NameBuf = "MAIL.example.com".parse().unwrap();

        let rdata: new::rdata::RecordData<new::base::name::NameBuf> =
            new::rdata::RecordData::Mx(new::rdata::Mx {
                preference,
                exchange,
            });

        let new_record = new::base::Record::new(
            name,
            rtype.clone(),
            rclass.clone(),
            ttl.clone(),
            rdata.clone(),
        );

        let name: new::base::name::NameBuf = "example.com".parse().unwrap();

        let other_new_record = new::base::Record::new(name, rtype, rclass, ttl, rdata);

        println!(
            "{:?} {:?} {:?}",
            new_record.rname,
            new_record.rname.cmp(&other_new_record.rname),
            other_new_record.rname
        );

        let mut target = Vec::<u8>::new();

        record
            .compose_canonical(&mut target)
            .expect("This is fine!");

        println!("{:?}", record);

        println!("{:?}", String::from_utf8(target));
    }
}
