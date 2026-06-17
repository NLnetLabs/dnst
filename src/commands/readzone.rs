use chrono::Datelike;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use clap::Parser;

use domain::new::base::build::BuildBytes;
use domain::new::base::name::RevNameBuf;
use domain::new::base::name::{Name, NameBuf, RevName};
use domain::new::base::{CharStr, RType, Serial};
use domain::new::base::{RClass, Record};
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

        // I do the reading of the zonefile here because then I can test the
        // output of the zonefile without creating a file for it.
        let zonefile_buf = io::BufReader::new(File::open(&self.zonefile_path)?);

        self.go_through_zone(zonefile_buf, &env.stdout())?;

        Ok(())
    }

    pub(super) fn go_through_zone<R, W>(&self, zf_buf: R, mut out: W) -> Result<(), Error>
    where
        R: io::BufRead,
        W: io::Write,
    {
        //--- Throw error when trying print_rrsig_null
        if self.print_ds_bubble_babble {
            return Err(Error::new("The option -b is not implemented."));
        }

        // `ldns-read-zone` prints only one SOA record. Keep track to only print
        // one record.
        let mut soa_is_printed = false;
        let mut warning_at_the_end: Vec<String> = Vec::new();
        let mut zf = ZonefileScanner::new(zf_buf, self.origin.as_deref());

        // --- In/Exclude RTypes from printing -------------------------------
        let rrtype_exclude: Vec<RType> = self
            .rrtype_exclude
            .iter()
            .map(|f| scan_rtype(f.as_bytes()).expect("Unable to parse RType in include args."))
            .collect();

        let rrtype_include: Vec<RType> = self
            .rrtype_include
            .iter()
            .map(|f| scan_rtype(f.as_bytes()).expect("Unable to parse RType in include args."))
            .collect();

        // --- Print RType in Unknown Format ---------------------------------
        let rrtype_mark_unknown_include: Vec<RType> = self
            .rrtype_mark_unknown_include
            .iter()
            .map(|f| {
                scan_rtype(f.as_bytes())
                    .expect("Unable to parse RType in mark unknown include args.")
            })
            .collect();

        let rrtype_mark_unknown_exclude: Vec<RType> = self
            .rrtype_mark_unknown_exclude
            .iter()
            .map(|f| {
                scan_rtype(f.as_bytes())
                    .expect("Unable to parse RType in mark unknown exclude args.")
            })
            .collect();

        let mark_unknown = match (
            rrtype_mark_unknown_include.len(),
            rrtype_mark_unknown_exclude.len(),
        ) {
            (0, 0) => RRTypeMarkUnknown::TruelyUnknown,
            (_, 0) => RRTypeMarkUnknown::Only(&rrtype_mark_unknown_include),
            (0, _) => RRTypeMarkUnknown::AllExcept(&rrtype_mark_unknown_exclude),
            (_, _) => return Err(Error::new("-u and -U should not be mixed together!")),
        };

        // --- Iterate over all entries in the zonefile. ---------------------
        let mut first_entry = true;
        loop {
            let entry = match zf.scan() {
                Ok(Some(entry)) => entry,
                Ok(None) => break, // no more left
                Err(e) => return Err(Error::new(&e.to_string())),
            };
            let Entry::Record(mut record) = entry else {
                // Skipping non record entries
                warning_at_the_end
                    .push("Warning: Non-record entry skipped during parsing!".to_string());
                continue;
            };

            if first_entry {
                first_entry = false;
                if record.rtype != RType::SOA {
                    warning_at_the_end
                        .push("Warning: First record was not SOA record!".to_string());
                }
            }

            if !rrtype_include.is_empty() && !rrtype_include.contains(&record.rtype) {
                continue;
            }
            if !rrtype_exclude.is_empty() && rrtype_exclude.contains(&record.rtype) {
                continue;
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
            if soa_is_printed || (self.print_not_soa && record.rtype == RType::SOA) {
                continue;
            }
            if let Some(serial_arg) = &self.manipulate_serial {
                if let RecordData::Soa(soa) = &mut record.rdata {
                    soa.serial = manipulate_serial(soa.serial, serial_arg)?;
                }
            }
            if record.rtype == RType::SOA {
                soa_is_printed = true;
            }

            // --- Display Record --------------------------------------------
            writeln!(
                &mut out,
                "{}",
                dns_display(&record, &mark_unknown, self.print_rrsig_null)
            )?;
        }
        out.flush()?;
        Ok(())
    }
}

/// Representation of which resource record types should be printed in unknown mode.
enum RRTypeMarkUnknown<'a, T = Vec<RType>> {
    AllExcept(&'a T),
    Only(&'a T),
    TruelyUnknown,
}

impl RRTypeMarkUnknown<'_> {
    /// Returns information, if the `other` type must be printed in unknown
    /// format.
    fn is_unknown(&self, other: &RType) -> bool {
        match self {
            Self::AllExcept(v) => !v.contains(other),
            Self::Only(v) => v.contains(other),
            Self::TruelyUnknown => false, // no special care
        }
    }
}

fn manipulate_serial(current: Serial, arg: &str) -> Result<Serial, Error> {
    let cand = match arg.to_lowercase().as_str() {
        "unixtime" => get_unixtime_serial()?,
        "yyyymmddxx" => get_yyyymmddxx_serial(),

        // Notice the return, these functions return the `Serial` no matter if
        // bigger or smaller than the current `Serial`.
        s if s.starts_with('+') => return Ok(current.inc((s[1..]).parse::<i32>()?)),
        s if s.starts_with('-') => {
            // TODO: What are we doing here; how do I fix that?
            return Ok(current
                .inc(i32::MAX)
                .inc(i32::MAX - (s[1..]).parse::<i32>()?)
                .inc(2));
        }
        s => return Ok((s.parse::<u32>())?.into()),
    };
    let current_plus1 = current.inc(1);
    if cand < current_plus1 {
        return Ok(current_plus1);
    }
    Ok(cand)
}

/// Collect `&CharStr` into escaped ([`std::ascii::escape_default`]) String
fn dns_display_charstr(charstr: &CharStr) -> String {
    charstr
        .octets
        .iter()
        .map(|c| std::ascii::escape_default(*c).to_string())
        .collect()
}

/// Return mnemonic representation of [`RType`]. If [`RType`] is unknown or
/// `unkown_type` flag is passed, then the returned string contains the type
/// in the unknown format as defined in Section 5 in [RFC3597].
///
/// [RFC3597]: https://datatracker.ietf.org/doc/html/rfc3597#section-5
fn dns_display_type(rtype: RType, unknown_type: bool) -> String {
    if unknown_type {
        return format!("TYPE{}", rtype.code);
    }

    let value = match rtype {
        RType::A => "A",
        RType::NS => "NS",
        RType::CNAME => "CNAME",
        RType::SOA => "SOA",
        RType::PTR => "PTR",
        RType::HINFO => "HINFO",
        RType::MX => "MX",
        RType::TXT => "TXT",
        RType::RP => "RP",
        RType::AAAA => "AAAA",
        RType::SRV => "SRV",
        RType::DNAME => "DNAME",
        RType::OPT => "OPT",
        RType::DS => "DS",
        RType::RRSIG => "RRSIG",
        RType::NSEC => "NSEC",
        RType::DNSKEY => "DNSKEY",
        RType::NSEC3 => "NSEC3",
        RType::NSEC3PARAM => "NSEC3PARAM",
        RType::CDS => "CDS",
        RType::CDNSKEY => "CDNSKEY",
        RType::ZONEMD => "ZONEMD",
        RType::TSIG => "TSIG",
        _ => return format!("TYPE{}", rtype.code),
    };
    value.into()
}

/// Return mnemonic representation of [`RClass`]. If [`RClass`] is unknown,
/// then the returned string contains the class in the unknown format as
/// defined in Section 5 in [RFC3597].
///
/// [RFC3597]: https://datatracker.ietf.org/doc/html/rfc3597#section-5
fn dns_display_class(value: RClass) -> String {
    match value {
        RClass::IN => "IN".into(),
        RClass::CH => "CH".into(),
        _ => format!("CLASS{}", value.code.get()),
    }
}

/// Return DateTime format representation of [`Serial`] primarily used for
/// RRSIGs `inception` and `expiration`.
fn dns_display_datetime(serial: Serial) -> String {
    format!(
        "{}",
        // NOTE: from_timestamp_secs is not yet in MSRV
        chrono::DateTime::from_timestamp(Into::<u32>::into(serial) as i64, 0)
            .expect("DateTime was out of range.")
            .format("%Y%m%d%H%M%S")
    )
}

/// Return [`RecordData`] as a valid DNS string.
fn dns_display_record_data(
    data: &RecordData<'_, &Name>,
    rrtype_mark_unknown: &RRTypeMarkUnknown,
    print_rrsig_null: bool,
) -> String {
    let rdata: String = match data {
        // TODO: MSRV 1.91.0: [`Ipv4Addr::from_octets()`]
        RecordData::A(a) => format!("{}", Ipv4Addr::from_bits(u32::from_be_bytes(a.octets))),
        RecordData::Mx(mx) => format!("{} {}", mx.preference, mx.exchange),
        RecordData::Ns(ns) => format!("{}", ns.server),
        RecordData::Soa(soa) => format!(
            "{} {} {} {} {} {} {}",
            soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
        ),
        RecordData::CName(cn) => format!("{}", cn.name),
        RecordData::Ptr(ptr) => format!("{}", ptr.name),
        RecordData::HInfo(hi) => format!(
            "\"{}\" \"{}\"",
            dns_display_charstr(hi.cpu),
            dns_display_charstr(hi.os)
        ),
        RecordData::Txt(txt) => format!(
            "\"{}\"",
            txt.iter()
                .map(dns_display_charstr)
                .collect::<Vec<String>>()
                .join("\" \"")
        ),
        RecordData::Rp(rp) => format!("{} {}", rp.mailbox, rp.texts),
        RecordData::Aaaa(aaaa) => {
            // TODO: MSRV 1.91.0: [`Ipv6Addr::from_octets()`]
            format!("{}", Ipv6Addr::from_bits(u128::from_be_bytes(aaaa.octets)))
        }
        RecordData::DName(dn) => format!("{}", &dn.name),
        RecordData::Opt(_opt) => unimplemented!("OPT record is not implemented"),
        RecordData::Ds(ds) => format!(
            "{} {} {} {}",
            ds.keytag,
            ds.algorithm.code,
            ds.digest_type.code,
            // TODO: port encoding into `new`
            domain::utils::base16::encode_display(&ds.digest),
        ),
        RecordData::RRSig(sig) => {
            if print_rrsig_null {
                format!(
                    "{} {} {} {} (null) (null) {} {} (null)",
                    dns_display_type(sig.rtype, rrtype_mark_unknown.is_unknown(&sig.rtype)),
                    sig.algorithm.code,
                    sig.labels,
                    sig.ttl.value,
                    sig.keytag,
                    sig.signer,
                )
            } else {
                format!(
                    "{} {} {} {} {} {} {} {} {}",
                    dns_display_type(sig.rtype, rrtype_mark_unknown.is_unknown(&sig.rtype)),
                    sig.algorithm.code,
                    sig.labels,
                    sig.ttl.value,
                    dns_display_datetime(sig.expiration),
                    dns_display_datetime(sig.inception),
                    sig.keytag,
                    sig.signer,
                    domain::utils::base64::encode_display(&sig.signature),
                )
            }
        }
        RecordData::NSec(nsec) => format!(
            "{} {}",
            nsec.types
                .iter()
                // Print the RType in compatibilty if it is desired
                .map(|t| dns_display_type(t, rrtype_mark_unknown.is_unknown(&t)))
                .collect::<Vec<String>>()
                .join(" "),
            nsec.next
        ),
        RecordData::DNSKey(dnskey) => format!(
            "{} {} {} {}",
            dnskey.flags.bits(),
            dnskey.protocol,
            dnskey.algorithm.code,
            // TODO: move to new, and ?Size is missing in the encode_display
            domain::utils::base64::encode_string(&dnskey.key),
        ),
        RecordData::NSec3(nsec3) => format!(
            "{} {} {} {} {} {}",
            nsec3.algorithm.code,
            nsec3.flags.bits(),
            nsec3.iterations,
            domain::utils::base16::encode_display(&nsec3.salt),
            domain::utils::base16::encode_display(&nsec3.next),
            nsec3
                .types
                .iter()
                .map(|t| dns_display_type(t, rrtype_mark_unknown.is_unknown(&t)))
                .collect::<Vec<String>>()
                .join(" "),
        ),
        RecordData::NSec3Param(param) => {
            let salt = if param.salt.is_empty() {
                domain::utils::base16::encode_string(&param.salt)
            } else {
                "-".into()
            };
            format!(
                "{} {} {} {}",
                param.algorithm.code,
                param.flags.bits(),
                param.iterations,
                salt,
            )
        }
        RecordData::ZoneMD(zonemd) => format!(
            "{} {} {} {}",
            zonemd.serial,
            zonemd.scheme.code,
            zonemd.hash_alg.code,
            domain::utils::base16::encode_display(&zonemd.digest),
        ),
        RecordData::Unknown(_, data) => format!(
            "\\# {} {}",
            data.octets.len(),
            domain::utils::base16::encode_display(&data.octets)
        ),
        &_ => unimplemented!("Type found that is not implemented!"),
    };
    rdata
}

fn dns_display(
    record: &Record<&RevName, RecordData<'_, &Name>>,
    rrtype_mark_unknown: &RRTypeMarkUnknown,
    print_rrsig_null: bool,
) -> String {
    // Copy RevName into NameBuf for Display trait.
    let name: NameBuf = RevNameBuf::copy_from(record.rname).into();

    // if RType should be printed as unkown also print RData in unkonw format.
    let data = if rrtype_mark_unknown.is_unknown(&record.rtype) {
        let buf_len = record.rdata.built_bytes_size();
        let mut bytes_data = vec![0u8; buf_len];
        record
            .rdata
            .build_bytes(&mut bytes_data)
            .expect(".built_bytes_size produced insufficient buffer size!");

        format!(
            "\\# {} {}",
            bytes_data.len(),
            domain::utils::base16::encode_display(&bytes_data)
        )
    } else {
        dns_display_record_data(&record.rdata, rrtype_mark_unknown, print_rrsig_null)
    };

    format!(
        "{} {} {} {} {}",
        name,
        record.ttl.value.get(),
        dns_display_class(record.rclass),
        dns_display_type(record.rtype, rrtype_mark_unknown.is_unknown(&record.rtype)),
        data,
    )
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

// This is currently the only way to parse RTypes from a string.
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
    use std::io::BufRead;

    use super::*;

    use domain::new::base::name::{NameParseError, RevNameBuf};
    use domain::new::base::wire::U16;
    use domain::new::base::{RClass, TTL};
    use domain::new::rdata;

    use crate::commands::readzone::PathBuf;
    use crate::commands::Command;
    use crate::env::fake::FakeCmd;

    #[test]
    fn print_dns_record() {
        let name = "example.com".parse::<RevNameBuf>().unwrap();
        let mx_exchange = "mail.example.com".parse::<NameBuf>().unwrap();
        let a_record: Record<&RevName, RecordData<'_, &Name>> = Record {
            rname: &name,
            rtype: RType::A,
            rclass: RClass::IN,
            ttl: TTL::from(3600),
            rdata: rdata::RecordData::<&Name>::A(rdata::A {
                octets: [1, 1, 1, 1],
            }),
        };
        let mx_record: Record<&RevName, RecordData<'_, &Name>> = Record {
            rname: &name,
            rtype: RType::MX,
            rclass: RClass::IN,
            ttl: TTL::from(3600),
            rdata: rdata::RecordData::Mx(rdata::Mx {
                preference: U16::from(10),
                exchange: &mx_exchange,
            }),
        };
        assert_eq!(
            dns_display(&a_record, &RRTypeMarkUnknown::TruelyUnknown, false),
            "example.com. 3600 IN A 1.1.1.1"
        );
        assert_eq!(
            dns_display(&mx_record, &RRTypeMarkUnknown::TruelyUnknown, false),
            "example.com. 3600 IN MX 10 mail.example.com."
        );
    }

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

    fn compare_lines(lhs: &[u8], rhs: &[u8]) -> bool {
        let blhs: io::BufReader<&[u8]> = io::BufReader::new(lhs);
        let brhs: io::BufReader<&[u8]> = io::BufReader::new(rhs);
        brhs.lines()
            .map(|r| r.unwrap())
            .eq(blhs.lines().map(|l| l.unwrap()))
    }

    #[test]
    fn verify_readzone_json() {
        let cmd = FakeCmd::new(["dnst", "read-zone"]);

        // Check the defaults
        let test_case_collection: TestCaseCollection =
            toml::from_str(include_str!("../../test-data/verify-readzone.toml"))
                .expect("TOML was not well-formatted");

        for (index, test) in test_case_collection.tests.iter().enumerate() {
            println!("# start test {} - {}", index, test.info);

            let readzone_config: ReadZone = parse(cmd.args(&test.config));

            println!("Input\n{:?}", test.input);
            println!("Expected Output: {:?}", test.output);

            let mut vec_buf: Vec<u8> = Vec::new();
            let result = readzone_config.go_through_zone(test.input.as_bytes(), &mut vec_buf);

            println!("Function Result: {:?}", result);
            match result {
                Ok(_) => {
                    let is_equal = compare_lines(vec_buf.as_slice(), test.output.as_bytes());
                    println!("Resulting Output\n{:?}", String::from_utf8(vec_buf));
                    assert!(is_equal);
                }
                Err(e) => {
                    println!("Resulting Output: {:?}", String::from_utf8(vec_buf));
                    assert!(compare_lines(
                        e.to_string().as_bytes(),
                        test.output.as_bytes()
                    ));
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
    fn test_dns_display_datetime() {
        assert_eq!("19700101000000", dns_display_datetime(Serial::from(0)));
        assert_eq!(
            "20260102030405",
            dns_display_datetime(Serial::from(1767323045))
        );
    }

    #[test]
    fn test_dns_manipulate_serial() {
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
        assert_eq!(
            manipulate_serial(Serial::from(10), "+0").unwrap(),
            Serial::from(10),
            "Add 0 to serial"
        );
        assert_eq!(
            manipulate_serial(Serial::from(10), "-0").unwrap(),
            Serial::from(10),
            "Subtract 0 to serial"
        );
    }
}
