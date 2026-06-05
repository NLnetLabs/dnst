use core::clone::Clone;

use chrono::Datelike;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::PathBuf;

use clap::Parser;

use domain::new::base::name::RevNameBuf;
use domain::new::base::{RType, Serial};
use domain::new::rdata::RecordData;
use domain::new::zonefile::scanner::{Scan, ScanError, Scanner};
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
    /// Print a (null) for the RRSIG inception, expiry and key data. This option
    /// can be used when comparing different signing systems that use the same
    /// DNSKEYs for signing but would have a slightly different timings/jitter.
    #[arg(short = '0', default_value_t = false)]
    print_rrsig_null: bool,

    /// Include Bubble Babble encoding of DS's.
    #[arg(short = 'b', default_value_t = false)]
    print_ds_bubble_babble: bool,

    /// Canonicalize all resource records in the zone before printing
    #[arg(short = 'c', default_value_t = false)]
    canonicalize: bool,

    /// Only print DNSSEC data from the zone. This option skips every record
    /// that is not of type NSEC, NSEC3, RRSIG or DNSKEY. DS records are not
    /// printed.
    #[arg(short = 'd', default_value_t = false)]
    print_only_dnssec: bool,

    /// -e <rr type>
    /// Do not print RRs of the given <rr type>.
    /// This option may be given multiple times.
    /// -e is not meant to be used together with -E.
    #[arg(short = 'e')]
    rrtype_exclude: Vec<String>,

    /// -E <rr type>
    /// Print only RRs of the given <rr type>.
    /// This option may be given multiple times.
    /// -E is not meant to be used together with -e.
    #[arg(short = 'E', action = clap::ArgAction::Append)]
    rrtype_include: Vec<String>,

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
    #[arg(short = 'S', required = false, allow_negative_numbers = true)]
    manipulate_serial: Option<String>,

    /// -u <rr type>
    /// Mark <rr type> for printing in unknown type format.
    /// This option may be given multiple times.
    /// -u is not meant to be used together with -U.
    #[arg(short = 'u')]
    rrtype_mark_unknown_include: Vec<String>,

    /// -U <rr type>
    /// Mark <rr type> for not printing in unknown type format.
    /// This option may be given multiple times.
    /// The first occurrence of the -U option marks all RR types for
    /// printing in unknown type format except for the given <rr type>.
    /// Subsequent -U options will clear the mark for those <rr type>s
    /// too, so that only the given <rr type>s will be printed in the
    /// presentation format specific for those <rr type>s.
    /// -U is not meant to be used together with -u.
    #[arg(short = 'U', action = clap::ArgAction::Append)]
    rrtype_mark_unknown_exclude: Vec<String>,

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
            print_ds_bubble_babble: args.print_ds_bubble_babble,
            rrtype_exclude: args.rrtype_exclude,
            rrtype_include: args.rrtype_include,
            rrtype_mark_unknown_include: args.rrtype_mark_unknown_include,
            rrtype_mark_unknown_exclude: args.rrtype_mark_unknown_exclude,
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

        let mut rrtype_exclude: Vec<RType> = Vec::new();
        for rr in &self.rrtype_exclude {
            rrtype_exclude.push(scan_rtype(rr.as_bytes())?);
        }
        let mut rrtype_include: Vec<RType> = Vec::new();
        for rr in &self.rrtype_include {
            rrtype_include.push(scan_rtype(rr.as_bytes())?);
        }
        loop {
            let entry = match zf.scan() {
                Ok(Some(entry)) => entry,
                Ok(None) => break, // no more left
                Err(e) => return Err(Error::new(&e.to_string())),
            };
            let Entry::Record(mut record) = entry else {
                eprintln!("Skipping non-Record entries");
                continue;
            };

            if let Some(serial_arg) = &self.manipulate_serial {
                if let RecordData::Soa(soa) = &mut record.rdata {
                    soa.serial = manipulate_serial(soa.serial, serial_arg)?;
                }
            }
            if !rrtype_include.is_empty() && !rrtype_include.contains(&record.rtype) {
                continue;
            }
            if !rrtype_exclude.is_empty() && rrtype_exclude.contains(&record.rtype) {
                continue;
            }
            //--- Through error when trying print_rrsig_null
            if self.print_rrsig_null {
                return Err(Error::new(
                    "The option -0 is not implemented. Do you need it?",
                ));
            }
            if self.print_ds_bubble_babble {
                return Err(Error::new(
                    "The option -b is not implemented. Do you need it?",
                ));
            }
            //--- Only print DNSSEC data
            if self.print_only_dnssec && !is_dnssec_data(record.rtype) {
                continue;
            }
            //--- Do not print DNSSEC data
            if self.print_not_dnssec && is_dnssec_data(record.rtype) {
                continue;
                // Check if ldns checks for apex
            }
            //--- Do not print SOA
            // Check if ldns checks for apex
            if self.print_not_soa && record.rtype == RType::SOA {
                continue;
            }

            match out.write_all(format!("{:?}\n", record).as_bytes()) {
                Ok(()) => (),
                Err(e) => eprintln!("Error while writing to Writer {:?}", e),
            }
        }
        out.flush()?;
        Ok(())
    }
}

fn manipulate_serial(current: Serial, arg: &str) -> Result<Serial, Error> {
    let cand = match arg.to_lowercase().as_str() {
        "unixtime" => get_unixtime_serial()?,
        "yyyymmddxx" => get_yyyymmddxx_serial(),
        s if s.chars().next() == Some('+') => return Ok(current.inc((s[1..]).parse::<i32>()?)),
        s if s.chars().next() == Some('-') => {
            return Ok(Serial::from(
                Into::<u32>::into(current).wrapping_sub_signed((s[1..]).parse::<i32>()?),
            ));
        }
        s => return Ok((s.parse::<u32>())?.into()),
    };
    let current_plus1 = current.inc(1);
    if cand < current_plus1 {
        return Ok(current_plus1);
    }
    Ok(cand)
}

fn get_unixtime_serial() -> Result<Serial, Error> {
    Ok(Serial::unix_time())
}

fn get_yyyymmddxx_serial() -> Serial {
    let now = chrono::Utc::now();
    let yyyy = (now.year() * 1_000_000) as u32;
    let mm = now.month() * 10_000;
    let dd = now.day() * 100;
    (yyyy + mm + dd).into()
}
fn scan_rtype(buf: &[u8]) -> Result<RType, ScanError> {
    let mut scanner = Scanner::new(buf, None);
    let alloc = bumpalo::Bump::new();
    let mut buffer = Vec::new();
    RType::scan(&mut scanner, &alloc, &mut buffer)
}

fn is_dnssec_data(rtype: RType) -> bool {
    DNSSEC_TYPES.contains(&rtype)
}
//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;

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

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    struct TestCase {
        info: String,
        config: Vec<String>,
        input: String,
        output: String,
    }
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    struct TestCaseCollection {
        tests: Vec<TestCase>,
    }

    #[test]
    fn verify_readzone_json() {
        let cmd = FakeCmd::new(["dnst", "read-zone"]);

        // Check the defaults
        let test_case_collection: TestCaseCollection =
            serde_json::from_str(include_str!("../../test-data/verify-readzone.json"))
                .expect("JSON was not well-formatted");

        for (index, test) in test_case_collection.tests.iter().enumerate() {
            println!("# start test {} - {}", index, test.info);

            let readzone_config: ReadZone = parse(cmd.args(&test.config));

            println!("Input\n{:?}", test.input);
            println!("Expected Output\n{:?}", test.output);

            let mut vec_buf: Vec<u8> = Vec::new();
            let result = readzone_config.go_through_zone(test.input.as_bytes(), &mut vec_buf);

            println!("Function Result\n{:?}", result);
            match result {
                Ok(_) => {
                    let is_equal = vec_buf == test.output.as_bytes();
                    println!("Resulting Output\n{:?}", String::from_utf8(vec_buf));
                    assert!(is_equal);
                }
                Err(e) => {
                    println!("Resulting Error\n{:?}", String::from_utf8(vec_buf));
                    assert_eq!(e.to_string(), test.output);
                }
            }
            println!("# end test {} - {}", index, test.info);
        }
    }

    #[track_caller]
    fn get_default_readzone(path_str: &str) -> ReadZone {
        ReadZone {
            canonicalize: false,
            print_only_dnssec: false,
            print_rrsig_null: false,
            print_ds_bubble_babble: false,
            rrtype_exclude: Vec::new(),
            rrtype_include: Vec::new(),
            rrtype_mark_unknown_include: Vec::new(),
            rrtype_mark_unknown_exclude: Vec::new(),
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
            origin: Some("example.org".parse().unwrap()),
            ..get_default_readzone(path)
        };
        assert_eq!(parse(cmd.args(["-o", "example.org", path])), base);
    }

    #[test]
    fn check_revnamebuf() {
        let name = "example.org.";
        let rnb: Result<RevNameBuf, NameParseError> = name.parse();
        assert!(rnb.is_err());
        let name = "example.org";
        let rnb: Result<RevNameBuf, NameParseError> = name.parse();
        assert!(rnb.is_ok());
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
    fn test_serial_manipulation() {
        assert_eq!(
            manipulate_serial(Serial::from(1), "10").unwrap(),
            Serial::from(10),
            "Increase serial to absolute value"
        );
        assert_eq!(
            manipulate_serial(Serial::from(1000), "+42").unwrap(),
            Serial::from(1042),
            "Increase serial with relative operation +"
        );
        assert_eq!(
            manipulate_serial(Serial::from(1000), "42").unwrap(),
            Serial::from(42),
            "Decrease serial with absolute number"
        );
        assert_eq!(
            manipulate_serial(Serial::from(1052), "-10").unwrap(),
            Serial::from(1042),
            "Decrease serial with relative operation -"
        );
        assert_eq!(
            manipulate_serial(Serial::from(10), "-10").unwrap(),
            Serial::from(0),
            "Decrease serial with relative operation -"
        );
        assert_eq!(
            manipulate_serial(Serial::from(9), "-10").unwrap(),
            Serial::from(u32::MAX),
            "Decrease serial with relative operation -"
        );
        assert_eq!(
            manipulate_serial(Serial::from(8), "-10").unwrap(),
            Serial::from(u32::MAX - 1),
            "Decrease serial with relative operation -"
        );
        assert_eq!(
            manipulate_serial(Serial::from(0), "-1").unwrap(),
            Serial::from(4294967295),
            "Decrease serial with relative operation -"
        );
        assert_eq!(
            manipulate_serial(Serial::from(4294967295), "+1").unwrap(),
            Serial::from(0),
            "Decrease serial with relative operation -"
        );
    }
}
