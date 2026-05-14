use core::clone::Clone;
use core::cmp::Ordering;
use core::fmt::Write;

use std::ffi::OsString;
use std::fmt::{self};
use std::fs::File;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};

use bytes::BufMut;

use clap::Parser;
use domain::base::name::FlattenInto;
use domain::base::zonefile_fmt::ZonefileFmt;
use domain::base::{CanonicalOrd, Record, ToName};
use domain::dnssec::sign::records::SortedRecords;
use domain::rdata::ZoneRecordData;
use domain::zonefile::inplace::{self, Entry};
use domain::zonetree::types::StoredRecordData;
use domain::zonetree::{StoredName, StoredRecord};
use rayon::slice::ParallelSliceMut;

use crate::env::{Env, Stream};
use crate::error::{Context, Error};
use crate::{Args, DISPLAY_KIND};

use super::{Command, LdnsCommand};

//------------ Constants -----------------------------------------------------

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
    origin: Option<StoredName>,

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

// TODO
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

    fn parse_ldns<I: IntoIterator<Item = OsString>>(unargs: I) -> Result<Args, Error> {
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
        // let mut parser = lexopt::Parser::from_args(args);

        // while let Some(arg) = parser.next()? {
        //     match arg {
        //         Arg::Short('o') => {
        //             let val = parser.value()?;
        //             origin = Some(parse_os("-o", &val)?);
        //         }
        //         Arg::Value(val) => {
        //             if zonefile.is_none() {
        //                 zonefile = Some(parse_os("zonefile", &val)?);
        //             }
        //         }
        //         Arg::Short(x) => return Err(format!("Invalid short option: -{x}").into()),
        //         Arg::Long(x) => {
        //             return Err(format!("Long options are not supported, but `--{x}` given").into())
        //         }
        //     }
        // }

        // let Some(zonefile_path) = zonefile else {
        //     return Err("Missing zonefile argument".into());
        // };

        // Ok(Args::from(Command::ReadZone(Self {
        //     origin,
        //     zonefile_path,
        //     invoked_as_ldns: true,
        // })))
    }
}

impl ReadZone {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        // Read the zone file.
        let records: SortedRecords<
            domain::base::Name<bytes::Bytes>,
            ZoneRecordData<bytes::Bytes, domain::base::Name<bytes::Bytes>>,
            MultiThreadedSorter,
        > = self.load_zone(&env.in_cwd(&self.zonefile_path))?;

        let mut writer: FileOrStdout<BufWriter<File>, _> = FileOrStdout::Stdout(env.stdout());

        for rr in records.iter() {
            if self.canonicalize {
                // TODO: there is no way to modify the owner inplace?
                let name: domain::base::Name<bytes::Bytes> = rr.owner().to_canonical_name();
                println!("{:?}", name);
            }
            self.writeln_rr(&mut writer, rr)?;
        }

        Ok(())
    }

    fn write_rr<W, N, O: AsRef<[u8]>>(
        &self,
        writer: &mut W,
        rr: &Record<N, ZoneRecordData<O, N>>,
    ) -> std::fmt::Result
    where
        N: ToName,
        W: Write,
        ZoneRecordData<O, N>: ZonefileFmt,
    {
        writer.write_fmt(format_args!("{}", rr.display_zonefile(DISPLAY_KIND)))
    }

    fn writeln_rr<W, N, O: AsRef<[u8]>>(
        &self,
        writer: &mut W,
        rr: &Record<N, ZoneRecordData<O, N>>,
    ) -> std::fmt::Result
    where
        N: ToName,
        W: Write,
        ZoneRecordData<O, N>: ZonefileFmt,
    {
        self.write_rr(writer, rr)?;
        writer.write_char('\n')
    }

    fn load_zone(
        &self,
        zonefile_path: &Path,
    ) -> Result<SortedRecords<StoredName, StoredRecordData, MultiThreadedSorter>, Error> {
        // Don't use Zonefile::load() as it knows nothing about the size of
        // the original file so uses default allocation which allocates more
        // bytes than are needed. Instead control the allocation size based on
        // our knowledge of the file size.
        let mut zone_file = File::open(zonefile_path)
            .map_err(|e| format!("error opening file: {e}").into())
            .context(&format!(
                "loading zone file from path '{}'",
                zonefile_path.display(),
            ))?;
        let zone_file_len = zone_file
            .metadata()
            .map_err(|e| {
                format!(
                    "error getting metadata from zonefile {}: {e}",
                    zonefile_path.display()
                )
            })?
            .len();
        let mut buf = inplace::Zonefile::with_capacity(zone_file_len as usize).writer();
        std::io::copy(&mut zone_file, &mut buf).map_err(|e| {
            format!(
                "error copying from zonefile {}: {e}",
                zonefile_path.display()
            )
        })?;
        let mut reader = buf.into_inner();

        if let Some(origin) = &self.origin {
            reader.set_origin(origin.clone());
        }

        // Push records to an unsorted vec, then sort at the end, as this is faster than
        // sorting one record at a time.
        let mut records = vec![];

        for entry in reader {
            let entry = entry.map_err(|err| format!("Invalid zone file: {err}"))?;
            match entry {
                Entry::Record(record) => {
                    let record: StoredRecord = record.flatten_into();
                    records.push(record);
                }
                Entry::Include { .. } => {
                    return Err(Error::from(
                        "Invalid zone file: $INCLUDE directive is not supported",
                    ));
                }
            }
        }

        // Use a multi-threaded parallel sorter to sort our unsorted vec into
        // a `SortedRecords` type.
        let records = SortedRecords::<_, _, MultiThreadedSorter>::from(records);

        Ok(records)
    }
}

//------------ FileOrStdout --------------------------------------------------

enum FileOrStdout<T: io::Write, U: io::Write> {
    File(T), // TODO: Fix this. Just use Stdout but impl fmt::Write for it.
    Stdout(Stream<U>),
}

impl<T: io::Write, U: io::Write> fmt::Write for FileOrStdout<T, U> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        match self {
            FileOrStdout::File(f) => f.write_all(s.as_bytes()).map_err(|_| fmt::Error),
            FileOrStdout::Stdout(f) => {
                write!(f, "{s}");
                Ok(())
            }
        }
    }

    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        match self {
            FileOrStdout::File(f) => f.write_fmt(args).map_err(|_| fmt::Error),
            FileOrStdout::Stdout(o) => {
                o.write_fmt(args);
                Ok(())
            }
        }
    }
}

//------------ MultiThreadedSorter -------------------------------------------

/// A parallelized sort implementation for use with [`SortedRecords`].
///
/// TODO: Should we add a `-j` (jobs) command line argument to override the
/// default Rayon behaviour of using as many threads as their are CPU cores?
struct MultiThreadedSorter;

impl domain::dnssec::sign::records::Sorter for MultiThreadedSorter {
    fn sort_by<N, D, F>(records: &mut Vec<Record<N, D>>, compare: F)
    where
        F: Fn(&Record<N, D>, &Record<N, D>) -> Ordering + Sync,
        Record<N, D>: CanonicalOrd + Send,
    {
        records.par_sort_by(compare);
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::commands::readzone::PathBuf;
    use crate::commands::readzone::StoredName;
    use crate::commands::Command;
    use crate::env::fake::FakeCmd;

    use super::ReadZone;

    #[track_caller]
    fn parse(args: FakeCmd) -> ReadZone {
        let res = args.parse().unwrap();
        let Command::ReadZone(x) = res.command else {
            panic!("Not a ReadZone!");
        };
        x
    }

    #[test]
    fn dnst_parse_successes() {
        let cmd = FakeCmd::new(["dnst", "read-zone"]);

        let base = ReadZone {
            canonicalize: false,
            print_only_dnssec: false,
            print_rrsig_null: false,
            manipulate_serial: None,
            origin: Some(StoredName::from_str("example.org").unwrap()),
            pad_soa_serial: false,
            print_not_dnssec: false,
            print_not_soa: false,
            canonical_sort: false,
            zonefile_path: PathBuf::from("example.org.zone"),
            invoked_as_ldns: false,
        };

        // Check the defaults
        assert_eq!(parse(cmd.args(["-oexample.org", "example.org.zone"])), base);
    }

    #[test]
    fn simple_readzone() {
        let res1 = FakeCmd::new([
            "dnst",
            "read-zone",
            "-c",
            "-o example.com.",
            "test-data/example.org",
        ])
        .run();

        println!("{}", res1.stdout);
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
