use core::clone::Clone;
use core::cmp::Ordering;
use core::fmt::Write;
use core::str::FromStr;

use std::ffi::OsString;
use std::fmt::{self};
use std::fs::File;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};

use bytes::BufMut;

use domain::base::name::FlattenInto;
use domain::base::zonefile_fmt::ZonefileFmt;
use domain::base::{CanonicalOrd, Record, ToName};
use domain::dnssec::sign::records::SortedRecords;
use domain::rdata::ZoneRecordData;
use domain::zonefile::inplace::{self, Entry};
use domain::zonetree::types::StoredRecordData;
use domain::zonetree::{StoredName, StoredRecord};
use lexopt::Arg;
use rayon::slice::ParallelSliceMut;

use crate::env::{Env, Stream};
use crate::error::{Context, Error};
use crate::{Args, DISPLAY_KIND};

use super::{parse_os, Command, LdnsCommand};

//------------ Constants -----------------------------------------------------

//------------ ReadZone ------------------------------------------------------

#[derive(Clone, Debug, clap::Args, PartialEq)]
// TODO
#[clap(after_help = "Read-Zone dnst HELP")]
pub struct ReadZone {
    /// Origin for the zone (REQUIRED).
    #[arg(short = 'o', value_name = "domain")]
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
const LDNS_HELP: &str = r###"
Read-Zone LDNS HELP
"###;

impl LdnsCommand for ReadZone {
    const NAME: &'static str = "read-zone";
    const HELP: &'static str = LDNS_HELP;
    const COMPATIBLE_VERSION: &'static str = "1.8.4"; // TODO

    fn parse_ldns<I: IntoIterator<Item = OsString>>(args: I) -> Result<Args, Error> {
        let mut origin = Option::<StoredName>::None;
        let mut zonefile = Option::<PathBuf>::None;

        let mut parser = lexopt::Parser::from_args(args);

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Short('o') => {
                    let val = parser.value()?;
                    origin = Some(parse_os("-o", &val)?);
                }
                Arg::Value(val) => {
                    if zonefile.is_none() {
                        zonefile = Some(parse_os("zonefile", &val)?);
                    }
                }
                Arg::Short(x) => return Err(format!("Invalid short option: -{x}").into()),
                Arg::Long(x) => {
                    return Err(format!("Long options are not supported, but `--{x}` given").into())
                }
            }
        }

        let Some(zonefile_path) = zonefile else {
            return Err("Missing zonefile argument".into());
        };

        Ok(Args::from(Command::ReadZone(Self {
            origin,
            zonefile_path,
            invoked_as_ldns: true,
        })))
    }
}

impl ReadZone {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        // Read the zone file.
        let records = self.load_zone(&env.in_cwd(&self.zonefile_path))?;

        let mut writer: FileOrStdout<BufWriter<File>, _> = FileOrStdout::Stdout(env.stdout());

        for rr in records.iter() {
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

    use domain::base::CanonicalOrd;
    use pretty_assertions::assert_eq;

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
        let cmd = FakeCmd::new(["dnst", "readzone"]);

        let base = ReadZone {
            origin: Some(StoredName::from_str("example.org").unwrap()),
            zonefile_path: PathBuf::from("example.org.zone"),
            invoked_as_ldns: false,
        };

        // Check the defaults
        assert_eq!(
            parse(cmd.args(["-oexample.org", "example.org.zone", "anykey"])),
            base
        );
    }

    #[test]
    fn simple_readzone() {
        let res1 = FakeCmd::new([
            "dnst",
            "readzone",
            // "-o example.com.",
            "test-data/example.org",
            "-f-",
        ])
        .run();

        println!("{}", res1.stdout);
        assert_eq!(res1.stderr, "");
        assert_eq!(res1.exit_code, 0);
    }

    #[test]
    fn name_canonicalization() {
        use domain::base::name::Name;
        let name1: Name<bytes::Bytes> = Name::<bytes::Bytes>::from_str("0.example.com.").unwrap();
        println!("{:?}", "0.example.com.".as_bytes());
        let name2: Name<bytes::Bytes> = Name::<bytes::Bytes>::from_str("1.example.com.").unwrap();
        println!("{:?}", "1.example.com.".as_bytes());
        println!("{:?}", name1.as_octets());

        println!("{:?}", name1.canonical_cmp(&name2));
    }
}
