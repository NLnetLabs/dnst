use core::cmp::Ordering;
use core::fmt::Write;
use core::ops::Add;
use core::str::FromStr;

use std::cmp::min;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::hash::RandomState;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};

// TODO: use a re-export from domain?
use bytes::{Bytes, BytesMut};
use clap::builder::ValueParser;
use domain::base::iana::nsec3::Nsec3HashAlg;
use domain::base::name::FlattenInto;
use domain::base::zonefile_fmt::ZonefileFmt;
use domain::base::{Name, NameBuilder, Record, Rtype, Serial, Ttl};
use domain::rdata::dnssec::Timestamp;
use domain::rdata::nsec3::Nsec3Salt;
use domain::rdata::{Dnskey, Nsec3, Nsec3param, Soa, ZoneRecordData};
use domain::sign::common::KeyPair;
use domain::sign::records::{
    Family, FamilyName, Nsec3OptOut, Nsec3Records, RecordsIter, SortedRecords,
};
use domain::sign::{SecretKeyBytes, SigningKey};
use domain::validate::Key;
use domain::zonefile::inplace::{self, Entry};
use domain::zonetree::types::StoredRecordData;
use domain::zonetree::{StoredName, StoredRecord};
use lexopt::Arg;

use crate::env::{Env, Stream};
use crate::error::Error;

use super::nsec3hash::Nsec3Hash;
use super::{parse_os, parse_os_with, LdnsCommand};

//------------ Constants -----------------------------------------------------

const FOUR_WEEKS: u32 = 2419200;

//------------ SignZone ------------------------------------------------------

#[derive(Clone, Debug, clap::Args)]
#[clap(
    after_help = "Keys must be specified by their base name (usually K<name>+<alg>+<id>), i.e. WITHOUT the .private or .key extension. Both .private and .key files are required.

A date can be a timestamp (seconds since the epoch), or of the form <YYYYMMdd[hhmmss]>
"
)]
pub struct SignZone {
    // -----------------------------------------------------------------------
    // Original ldns-signzone options in ldns-signzone -h order:
    // -----------------------------------------------------------------------
    /// Use layout in signed zone and print comments on DNSSEC records
    #[arg(short = 'b', default_value_t = false)]
    extra_comments: bool,

    /// Used keys are not added to the zone
    #[arg(short = 'd', default_value_t = false)]
    do_not_add_keys_to_zone: bool,

    /// Expiration date [default: 4 weeks from now]
    // Default is not documented in ldns-signzone -h or man ldns-signzone but
    // in code (see ldns/dnssec_sign.c::ldns_create_empty_rrsig()) LDNS uses
    // now + 4 weeks if no expiration timestamp is specified.
    #[arg(
        short = 'e',
        value_name = "date",
        default_value_t = Timestamp::now().into_int().add(FOUR_WEEKS).into(),
        hide_default_value = true,
        value_parser = ValueParser::new(SignZone::parse_timestamp),
    )]
    expiration: Timestamp,

    /// Output zone to file [default: <zonefile>.signed]
    ///
    /// Use '-f -' to output to stdout.
    #[arg(short = 'f', value_name = "file")]
    out_file: Option<PathBuf>,

    /// Inception date [default: now]
    // Default is not documented in ldns-signzone -h or man ldns-signzone but
    // in code (see ldns/dnssec_sign.c::ldns_create_empty_rrsig()) LDNS uses
    // now if no inception timestamp is specified.
    #[arg(
        short = 'i',
        value_name = "date",
        default_value_t = Timestamp::now(),
        hide_default_value = true,
        value_parser = ValueParser::new(SignZone::parse_timestamp),
    )]
    inception: Timestamp,

    /// Origin for the zone (for zonefiles with relative names and no $ORIGIN)
    #[arg(short = 'o', value_name = "domain")]
    origin: Option<Name<Bytes>>,

    /// Set SOA serial to the number of seconds since Jan 1st 1970
    ///
    /// If this would NOT result in the SOA serial increasing it will be
    /// incremented instead.
    #[arg(short = 'u', default_value_t = false)]
    set_soa_serial_to_epoch_time: bool,

    // SKIPPED: -v
    // This should be handled at the dnst top level, not per subcommand.

    // Add ZONEMD resource record
    // Can occur more than once.
    //#[arg(short = 'z', group = "zonemd")]
    // TODO

    // Allow ZONEMDs to be added without signing
    //#[arg(short = 'Z', value_name = "[scheme]:hash", requires = "zonemd")]
    // TODO

    // Sign DNSKEY with all keys instead of minimal
    //#[arg(short = 'A', default_value_t = false)]
    // TODO: sign_dnskey_with_all_keys: bool,

    // Sign with every unique algorithm in the provided keys
    //#[arg(short = 'U', default_value_t = false)]
    // TODO: sign_with_every_unique_algorithm: bool,
    /// Use NSEC3 instead of NSEC
    #[arg(short = 'n', default_value_t = false, group = "nsec3")]
    use_nsec3: bool,

    /// Hashing algorithm
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 'a',
        value_name = "algorithm",
        default_value = "SHA-1",
        value_parser = ValueParser::new(Nsec3Hash::parse_nsec3_alg),
        requires = "nsec3"
    )]
    algorithm: Nsec3HashAlg,

    /// Number of hash iterations
    // TODO: make the default for dnst-signzone be 0 (to match best practice)
    // while leaving the default for ldns-signzone be 1 (to match ldns), or
    // maybe even change the default for both to 0.
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 't',
        value_name = "number",
        default_value_t = 0,
        requires = "nsec3"
    )]
    iterations: u16,

    /// Salt
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 's',
        value_name = "string",
        default_value_t = Nsec3Salt::empty(),
        requires = "nsec3"
    )]
    salt: Nsec3Salt<Bytes>,

    /// Set the opt-out flag on all NSEC3 RRs
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 'p',
        default_value_t = false,
        requires = "nsec3",
        conflicts_with = "nsec3_opt_out"
    )]
    nsec3_opt_out_flags_only: bool,

    // -----------------------------------------------------------------------
    // Extra options not supported by the original ldns-signzone:
    // -----------------------------------------------------------------------
    /// Set the opt-out flag on all NSEC3 RRs and skip unsigned delegations
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 'A', // Matches BIND dnssec-signzone
        default_value_t = false,
        requires = "nsec3",
        conflicts_with = "nsec3_opt_out_flags_only"
    )]
    nsec3_opt_out: bool,

    /// Hash only, don't sign
    #[arg(short = 'H', default_value_t = false)]
    hash_only: bool,

    /// Do not require that key names match the apex.
    #[arg(short = 'M', default_value_t = false)]
    no_require_keys_match_apex: bool,

    // -----------------------------------------------------------------------
    // Original ldns-signzone positional arguments in position order:
    // -----------------------------------------------------------------------
    /// The zonefile to sign
    #[arg(value_name = "zonefile")]
    zonefile_path: PathBuf,

    /// The keys to sign the zone with
    #[arg(value_name = "key")]
    key_paths: Vec<PathBuf>,
}

const LDNS_HELP: &str = r###"ldns-signzone [OPTIONS] zonefile key [key [key]]
  signs the zone with the given key(s)
  -b            use layout in signed zone and print comments DNSSEC records
  -d            used keys are not added to the zone
  -e <date>     expiration date
  -f <file>     output zone to file (default <name>.signed)
  -i <date>     inception date
  -o <domain>   origin for the zone
  -u            set SOA serial to the number of seconds since 1-1-1970
  -v            print version and exit
  -z <[scheme:]hash>    Add ZONEMD resource record
                <scheme> should be "simple" (or 1)
                <hash> should be "sha384" or "sha512" (or 1 or 2)
                this option can be given more than once
  -Z            Allow ZONEMDs to be added without signing
  -A            sign DNSKEY with all keys instead of minimal
  -U            Sign with every unique algorithm in the provided keys
  -n            use NSEC3 instead of NSEC.
                If you use NSEC3, you can specify the following extra options:
                -a [algorithm] hashing algorithm
                -t [number] number of hash iterations
                -s [string] salt
                -p set the opt-out flag on all nsec3 rrs

  keys must be specified by their base name (usually K<name>+<alg>+<id>),
  i.e. WITHOUT the .private or .key extension.
  A date can be a timestamp (seconds since the epoch), or of
  the form <YYYYMMdd[hhmmss]>
"###;

impl LdnsCommand for SignZone {
    const HELP: &'static str = LDNS_HELP;

    fn parse_ldns<I: IntoIterator<Item = OsString>>(args: I) -> Result<Self, Error> {
        let mut extra_comments = false;
        let mut do_not_add_keys_to_zone = false;
        let mut expiration = Timestamp::now().into_int().add(FOUR_WEEKS).into();
        let mut out_file = Option::<PathBuf>::None;
        let mut inception = Timestamp::now();
        let mut origin = Option::<Name<Bytes>>::None;
        let mut set_soa_serial_to_epoch_time = false;
        let mut use_nsec3 = false;
        let mut algorithm = Nsec3HashAlg::SHA1;
        let mut iterations = 1u16;
        let mut salt = Nsec3Salt::<Bytes>::empty();
        let mut nsec3_opt_out = false;
        let mut key_paths = Vec::<PathBuf>::new();
        let mut zonefile = Option::<PathBuf>::None;

        let mut parser = lexopt::Parser::from_args(args);

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Short('b') => {
                    extra_comments = true;
                }
                Arg::Short('d') => {
                    do_not_add_keys_to_zone = true;
                }
                Arg::Short('e') => {
                    let val = parser.value()?;
                    expiration = parse_os_with("-e", &val, SignZone::parse_timestamp)?;
                }
                Arg::Short('f') => {
                    let val = parser.value()?;
                    out_file = Some(parse_os("-f", &val)?);
                }
                Arg::Short('i') => {
                    let val = parser.value()?;
                    inception = parse_os_with("-i", &val, SignZone::parse_timestamp)?;
                }
                Arg::Short('o') => {
                    let val = parser.value()?;
                    origin = Some(parse_os("-o", &val)?);
                }
                Arg::Short('u') => {
                    set_soa_serial_to_epoch_time = true;
                }
                Arg::Short('v') => {
                    let version = clap::crate_version!();
                    println!("zone signer version {version} (dnst version {version})");
                    std::process::exit(0);
                }
                Arg::Short('n') => {
                    use_nsec3 = true;
                }
                Arg::Short('a') => {
                    let val = parser.value()?;
                    algorithm = parse_os_with("-a", &val, Nsec3Hash::parse_nsec3_alg)?;
                }
                Arg::Short('t') => {
                    let val = parser.value()?;
                    iterations = parse_os("-t", &val)?;
                }
                Arg::Short('s') => {
                    let val = parser.value()?;
                    salt = parse_os("-s", &val)?;
                }
                Arg::Short('p') => {
                    nsec3_opt_out = true;
                }
                Arg::Value(val) => {
                    if zonefile.is_none() {
                        zonefile = Some(parse_os("zonefile", &val)?);
                    } else {
                        key_paths.push(parse_os("key", &val)?);
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

        if let Some(out_file) = &out_file {
            if out_file.as_os_str() == "-" {
                extra_comments = false;
            }
        }

        if key_paths.is_empty() {
            return Err("Missing key argument".into());
        };

        Ok(Self {
            extra_comments,
            do_not_add_keys_to_zone,
            expiration,
            out_file,
            inception,
            origin,
            set_soa_serial_to_epoch_time,
            use_nsec3,
            algorithm,
            iterations,
            salt,
            nsec3_opt_out_flags_only: true,
            nsec3_opt_out,
            hash_only: false,
            zonefile_path,
            key_paths,
            no_require_keys_match_apex: false,
        })
    }
}

impl SignZone {
    pub fn parse_timestamp(arg: &str) -> Result<Timestamp, Error> {
        // We can't just use Timestamp::from_str from the domain crate because
        // ldns-signzone treats YYYYMMDD as a special case and domain does
        // not. For invalid values this YYYYMMDDD prevents use of valid Unix
        // timestamps that have the same value, e.g. ldns-signzone complains
        // that for 99999999 "The month must be in the range 1 to 12". There's
        // also no checking that an expiration timestamp is in the future of
        // an inception timestamp (which for serial numbers is hard to say for
        // sure but for YYYYMMDD or YYYYMMDDHHmmSS we could check).
        let res = if arg.len() == 8 && arg.parse::<u32>().is_ok() {
            // This can give strange errors, e.g. 99999999 warns about illegal
            // signature time, but the alternative would be to add a
            // dependency on chrono and parse the value ourselves in order to
            // produce a better error message. Given that this only happens
            // for very old or far future Unix timestamps we don't attempt to
            // do better than this for now.
            Timestamp::from_str(&format!("{arg}000000"))
        } else {
            Timestamp::from_str(arg)
        };

        res.map_err(|err| Error::from(format!("Invalid timestamp: {err}")))
    }

    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        // Post-process arguments.
        // TODO: Can Clap do this for us?
        let opt_out = if self.nsec3_opt_out {
            Nsec3OptOut::OptOut
        } else if self.nsec3_opt_out_flags_only {
            Nsec3OptOut::OptOutFlagsOnly
        } else {
            Nsec3OptOut::NoOptOut
        };

        let signing_mode = if self.hash_only {
            SigningMode::HashOnly
        } else {
            SigningMode::HashAndSign
        };

        if self.key_paths.is_empty() && !self.hash_only {
            return Err("Missing key argument".into());
        };

        let out_file = if let Some(out_file) = &self.out_file {
            out_file.clone()
        } else {
            let out_file = format!("{}.signed", self.zonefile_path.display());
            PathBuf::from_str(&out_file)
                .map_err(|err| format!("Cannot write to {out_file}: {err}"))?
        };

        let mut writer = if out_file.as_os_str() == "-" {
            FileOrStdout::Stdout(env.stdout())
        } else {
            let file = File::create(env.in_cwd(&out_file))?;
            let file = BufWriter::new(file);
            FileOrStdout::File(file)
        };

        // Import the specified keys and check that the keys are all for the same zone.
        let mut keys: Vec<SigningKey<Bytes, KeyPair>> = vec![];

        if self.key_paths.is_empty() {
            return Err("No keys to sign with. Aborting.".into());
        }

        let mut first_key_owner = None;

        for key_path in &self.key_paths {
            let key = Self::load_key_pair(key_path)?;

            if !self.no_require_keys_match_apex {
                if first_key_owner.is_none() {
                    first_key_owner.replace(key.owner().clone());
                }

                for key in &keys {
                    // Check the key name against the specified origin, if any,
                    if let Some(origin) = &self.origin {
                        if origin != key.owner() {
                            return Err(format!("{}.key has different name ({}) than the specified origin ({origin})", key_path.display(), key.owner()).into());
                        }
                    }

                    if Some(key.owner()) != first_key_owner.as_ref() {
                        return Err(format!(
                            "{}.key has different name ({}) to key {} ({})",
                            key_path.display(),
                            key.owner(),
                            self.key_paths[0].display(),
                            first_key_owner.unwrap()
                        )
                        .into());
                    }
                }
            }

            keys.push(key);
        }

        // Read the zone file.
        let mut records = self.load_zone(&env, first_key_owner.as_ref())?;

        // Change the SOA serial.
        if self.set_soa_serial_to_epoch_time {
            Self::bump_soa_serial(&mut records)?;
        }

        // Find the apex.
        let (apex, ttl) = Self::find_apex(&records).unwrap();

        // Hash the zone with NSEC or NSEC3.
        let hashes = if self.use_nsec3 {
            let params = Nsec3param::new(self.algorithm, 0, self.iterations, self.salt.clone());
            let Nsec3Records {
                recs,
                param,
                hashes,
            } = records
                .nsec3s::<_, BytesMut>(
                    &apex,
                    ttl,
                    params,
                    opt_out,
                    !self.do_not_add_keys_to_zone,
                    self.extra_comments,
                )
                .unwrap();
            records.extend(recs.into_iter().map(Record::from_record));
            records.insert(Record::from_record(param)).unwrap();
            hashes
        } else {
            let nsecs = records.nsecs::<Bytes>(&apex, ttl, !self.do_not_add_keys_to_zone);
            records.extend(nsecs.into_iter().map(Record::from_record));
            None
        };

        // Sign the zone unless disabled.
        if signing_mode == SigningMode::HashAndSign {
            let extra_records = records
                .sign(
                    &apex,
                    self.expiration,
                    self.inception,
                    keys.as_slice(),
                    !self.do_not_add_keys_to_zone,
                )
                .unwrap();
            records.extend(extra_records.into_iter().map(Record::from_record));
        }

        // Output the resulting zone, with comments if enabled.
        if self.extra_comments {
            writer.write_fmt(format_args!(";; Zone: {}\n;\n", apex.owner()))?;
        }

        if let Some(record) = records.iter().find(|r| r.rtype() == Rtype::SOA) {
            writer.write_fmt(format_args!("{}\n", record.display_zonefile(false, true)))?;
            if let Some(record) = records.iter().find(|r| {
                if let ZoneRecordData::Rrsig(rrsig) = r.data() {
                    rrsig.type_covered() == Rtype::SOA
                } else {
                    false
                }
            }) {
                writer.write_fmt(format_args!("{}\n", record.display_zonefile(false, true)))?;
            }
            if self.extra_comments {
                writer.write_str(";\n")?;
            }
        }

        let hashes_ref = hashes.as_ref();
        let apex = &apex;
        let nsec3_cs = Nsec3CommentState { hashes_ref, apex };

        // The signed RRs are in DNSSEC canonical order by owner name. For
        // compatibility with ldns-signzone, re-order them to be in canonical
        // order by unhashed owner name and so that hashed names come after
        // equivalent unhashed names.
        //
        // INCOMAPATIBILITY WARNING: Unlike ldns-signzone, we only apply this
        // ordering if `-b` is specified.
        //
        // Note: Family refers to the underlying record data, so while we are
        // creating a new Vec, it only contains references to the original
        // data so it's indiividual are not the records themselves.
        let mut families;
        let family_iter: AnyFamiliesIter = if self.extra_comments && hashes_ref.is_some() {
            families = records.families().collect::<Vec<_>>();
            let Some(hashes) = hashes_ref else {
                unreachable!();
            };
            families.sort_unstable_by(|a, b| {
                let mut hashed_count = 0;
                let unhashed_a = if let Some(unhashed_owner) = hashes.get(a.owner()) {
                    hashed_count += 1;
                    unhashed_owner
                } else {
                    a.owner()
                };
                let unhashed_b = if let Some(unhashed_owner) = hashes.get(b.owner()) {
                    hashed_count += 2;
                    unhashed_owner
                } else {
                    b.owner()
                };

                match unhashed_a.cmp(unhashed_b) {
                    Ordering::Less => Ordering::Less,
                    Ordering::Equal => match hashed_count {
                        0 | 3 => Ordering::Equal,
                        1 => Ordering::Greater,
                        2 => Ordering::Less,
                        _ => unreachable!(),
                    },
                    Ordering::Greater => Ordering::Greater,
                }
            });
            families.iter().into()
        } else {
            records.families().into()
        };

        for family in family_iter {
            if let Some(hashes_ref) = hashes_ref {
                // If this is family contains an NSEC3 RR and the number of
                // RRs in the RRSET of the unhashed owner name is zero, then
                // the NSEC3 was generated for an empty non-terminal.
                if family.rrsets().any(|rrset| rrset.rtype() == Rtype::NSEC3) {
                    if let Some(unhashed_name) = hashes_ref.get(family.owner()) {
                        if !records
                            .families()
                            .any(|family| family.owner() == unhashed_name)
                        {
                            writer.write_fmt(format_args!(
                                ";; Empty nonterminal: {unhashed_name}\n"
                            ))?;
                        }
                    } else {
                        // ??? Every hashed name must correspond to an unhashed name?
                    }
                }
            }

            for rrset in family.rrsets() {
                if rrset.rtype() == Rtype::SOA {
                    // This is output separately above as the very first RRset.
                    continue;
                }

                if rrset.rtype() == Rtype::RRSIG {
                    // We output RRSIGs only after the RRset that they cover.
                    continue;
                }

                // For each non-RRSIG RRSET RR of a given type.
                for rr in rrset.iter() {
                    writer.write_fmt(format_args!("{}", rr.display_zonefile(false, true)))?;
                    match rr.data() {
                        ZoneRecordData::Nsec3(nsec3) if self.extra_comments => {
                            nsec3.comment(&mut writer, rr, nsec3_cs)?
                        }
                        ZoneRecordData::Dnskey(dnskey) => dnskey.comment(&mut writer, rr, ())?,
                        _ => { /* Nothing to do */ }
                    }
                    writer.write_str("\n")?;
                }

                // Now attempt to print the RRSIG that covers the RTYPE of this RRSET.
                if let Some(covering_rrsig_rr) = family
                    .rrsets()
                    .filter(|this_rrset| this_rrset.rtype() == Rtype::RRSIG)
                    .find_map(|this_rrset| this_rrset.iter().find(|rr| matches!(rr.data(), ZoneRecordData::Rrsig(rrsig) if rrsig.type_covered() == rrset.rtype())))
                {
                    writer.write_fmt(format_args!("{}", covering_rrsig_rr.display_zonefile(false, true)))?;
                    // rrsig.comment(&mut writer, rr, ())?;
                    writer.write_str("\n")?;
                    let ZoneRecordData::Rrsig(rrsig) = covering_rrsig_rr.data() else {
                        unreachable!();
                    };
                    if self.extra_comments && rrsig.type_covered() == Rtype::NSEC3 {
                        writer.write_str(";\n")?;
                    }
                }
            }
        }

        Ok(())
    }

    fn load_zone(
        &self,
        env: &impl Env,
        expected_apex: Option<&Name<Bytes>>,
    ) -> Result<SortedRecords<StoredName, StoredRecordData>, Error> {
        let mut zone_file = File::open(env.in_cwd(&self.zonefile_path))?;
        let mut reader = inplace::Zonefile::load(&mut zone_file)?;
        if let Some(origin) = &self.origin {
            reader.set_origin(origin.clone());
        }
        let mut records = SortedRecords::new();
        for entry in reader {
            let entry = entry.map_err(|err| format!("Invalid zone file: {err}"))?;
            match entry {
                Entry::Record(record) => {
                    let record: StoredRecord = record.flatten_into();
                    if let Some(expected_apex) = expected_apex {
                        if record.rtype() == Rtype::SOA && record.owner() != expected_apex {
                            return Err(format!(
                                "Zone apex ({}) does not match the expected apex ({expected_apex})",
                                record.owner()
                            )
                            .into());
                        }
                    }

                    records.insert(record).map_err(|record| {
                        format!("Invalid zone file: Duplicate record detected: {record:?}")
                    })?;
                }
                Entry::Include { .. } => {
                    return Err(Error::from(
                        "Invalid zone file: $INCLUDE directive is not supported",
                    ));
                }
            }
        }
        Ok(records)
    }

    fn find_apex(
        records: &SortedRecords<StoredName, StoredRecordData>,
    ) -> Result<(FamilyName<Name<Bytes>>, Ttl), Error> {
        let soa = match records.find_soa() {
            Some(soa) => soa,
            None => {
                return Err(Error::from("Invalid zone file: Cannot find SOA record"));
            }
        };

        let ttl = match *soa.first().data() {
            ZoneRecordData::Soa(ref soa_data) => {
                // RFC 9077 updated RFC 4034 (NSEC) and RFC 5155 (NSSE3) to
                // say that the "TTL of the NSEC(3) RR that is returned MUST be
                // the lesser of the MINIMUM field of the SOA record and the
                // TTL of the SOA itself".
                min(soa_data.minimum(), soa.ttl())
            }
            _ => unreachable!(),
        };

        Ok((soa.family_name().cloned(), ttl))
    }

    fn bump_soa_serial(
        records: &mut SortedRecords<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>,
    ) -> Result<(), Error> {
        let Some(old_soa_rr) = records.find_soa() else {
            return Err(Error::from("Error reading zonefile: missing SOA record"));
        };
        let ZoneRecordData::Soa(old_soa) = old_soa_rr.first().data() else {
            return Err(Error::from("Error reading zonefile: missing SOA record"));
        };

        // Undocumented behaviour in ldns-signzone: it doesn't just set the
        // SOA serial to the current unix timestamp as is documented for '-u'
        // but rather only does that if the resulting value would be larger
        // than the current unix timestamp, otherwise it increments it. I
        // assume it does that to ensure that the SOA serial advances on zone
        // change per expectations defined in RFC 1034, though it is assuming
        // that the SOA serial can be interpreted as a unix timestamp which
        // may not be the intention of the zone owner.

        let now = Serial::now();
        let new_serial = if now > old_soa.serial() {
            now
        } else {
            old_soa.serial().add(1)
        };

        let new_soa = Soa::new(
            old_soa.mname().clone(),
            old_soa.rname().clone(),
            new_serial,
            old_soa.refresh(),
            old_soa.retry(),
            old_soa.expire(),
            old_soa.minimum(),
        );
        records.replace_soa(new_soa);

        Ok(())
    }

    /// Given a BIND style key pair path prefix load the keys from disk.
    ///
    /// Expects a path that is the common prefix in BIND style of a pair of '.key'
    /// (public) and '.private' key files, i.e. given
    /// /path/to/K<zone_name>.+<algorithm>+<key tag> load and parse the following
    /// files:
    ///
    ///   - /path/to/K<zone_name>.+<algorithm>+<key tag>.key
    ///   - /path/to/K<zone_name>.+<algorithm>+<key tag>.private
    ///
    /// However, this function is not strict about the format of the prefix, it
    /// will attempt to load files with suffixes '.key' and '.private' irrespective
    /// of the format of the rest of the path.
    fn load_key_pair(key_path: &Path) -> Result<SigningKey<Bytes, KeyPair>, Error> {
        let key_path_str = key_path.to_string_lossy();
        let public_key_path = PathBuf::from(format!("{key_path_str}.key"));
        let private_key_path = PathBuf::from(format!("{key_path_str}.private"));

        let private_data = std::fs::read_to_string(&private_key_path).map_err(|err| {
            format!(
                "Unable to load private key from file '{}': {}",
                private_key_path.display(),
                err
            )
        })?;

        let public_data = std::fs::read_to_string(&public_key_path).map_err(|err| {
            format!(
                "Unable to load public key from file '{}': {}",
                public_key_path.display(),
                err
            )
        })?;

        let secret_key = SecretKeyBytes::parse_from_bind(&private_data).map_err(|err| {
            format!(
                "Unable to parse BIND formatted private key file '{}': {}",
                private_key_path.display(),
                err
            )
        })?;

        let public_key_info = Key::parse_from_bind(&public_data).map_err(|err| {
            format!(
                "Unable to parse BIND formatted public key file '{}': {}",
                public_key_path.display(),
                err
            )
        })?;

        let key_pair =
            KeyPair::from_bytes(&secret_key, public_key_info.raw_public_key()).map_err(|err| {
                format!(
                    "Unable to import private key from file '{}': {}",
                    private_key_path.display(),
                    err
                )
            })?;

        let signing_key = SigningKey::new(
            public_key_info.owner().clone(),
            public_key_info.flags(),
            key_pair,
        );

        Ok(signing_key)
    }
}

fn next_owner_hash_to_name(
    next_owner_hash_hex: &str,
    apex: &FamilyName<Name<Bytes>>,
) -> Result<Name<Bytes>, ()> {
    let mut builder = NameBuilder::new_bytes();
    builder
        .append_chars(next_owner_hash_hex.chars())
        .map_err(|_| ())?;
    let next_owner_name = builder.append_origin(apex.owner()).map_err(|_| ())?;
    Ok(next_owner_name)
}

//------------ SigningMode ---------------------------------------------------

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum SigningMode {
    /// Both hash (NSEC/NSEC3) and sign zone records.
    #[default]
    HashAndSign,

    /// Only hash (NSEC/NSEC3) zone records, don't sign them.
    HashOnly,
    // /// Only sign zone records, assume they are already hashed.
    // SignOnly,
}

//------------ FileOrStdout --------------------------------------------------

enum FileOrStdout<T: io::Write, U: fmt::Write> {
    File(T),
    Stdout(Stream<U>),
}

impl<T: io::Write, U: fmt::Write> fmt::Write for FileOrStdout<T, U> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        match self {
            FileOrStdout::File(f) => f.write_all(s.as_bytes()).map_err(|_| fmt::Error),
            FileOrStdout::Stdout(o) => {
                o.write_str(s);
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

//------------ Commented -----------------------------------------------------

trait Commented<T> {
    fn comment<W: fmt::Write>(
        &self,
        writer: &mut W,
        record: &Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>,
        metadata: T,
    ) -> Result<(), fmt::Error>;
}

#[derive(Copy, Clone)]
struct Nsec3CommentState<'a> {
    hashes_ref: Option<&'a HashMap<Name<Bytes>, Name<Bytes>, RandomState>>,
    apex: &'a FamilyName<Name<Bytes>>,
}

impl<'b, O: AsRef<[u8]>> Commented<Nsec3CommentState<'b>> for Nsec3<O> {
    fn comment<'a, W: fmt::Write>(
        &self,
        writer: &mut W,
        record: &'a Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>,
        state: Nsec3CommentState<'b>,
    ) -> Result<(), fmt::Error> {
        if let Some(hashes) = state.hashes_ref {
            // TODO: For ldns-signzone backward compatibilty we output
            // "  ;{... <domain>.}" but I find the spacing ugly and
            // would prefer for dnst to output " ; {... <domain>. }"
            // instead.
            writer.write_str(" ;{ flags: ")?;

            if self.opt_out() {
                writer.write_str("optout")?;
            } else {
                writer.write_str("-")?;
            }

            let next_owner_hash_hex = format!("{}", self.next_owner());
            let next_owner_name = next_owner_hash_to_name(&next_owner_hash_hex, state.apex);

            let from = hashes
                .get(record.owner())
                .map(|n| format!("{}", n.fmt_with_dot()))
                .unwrap_or_default();

            let to = if let Ok(next_owner_name) = next_owner_name {
                hashes
                    .get(&next_owner_name)
                    .map(|n| format!("{}", n.fmt_with_dot()))
                    .unwrap_or_else(|| format!("<unknown hash: {next_owner_hash_hex}>"))
            } else {
                format!("<invalid name: {next_owner_hash_hex}>")
            };

            writer.write_fmt(format_args!(", from: {from}, to: {to}}}"))?;
        }
        Ok(())
    }
}

impl Commented<()> for Dnskey<Bytes> {
    fn comment<W: fmt::Write>(
        &self,
        writer: &mut W,
        record: &Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>,
        _metadata: (),
    ) -> Result<(), fmt::Error> {
        writer.write_fmt(format_args!(" ;{{id = {}", self.key_tag()))?;
        if self.is_secure_entry_point() {
            writer.write_str(" (ksk)")?;
        } else if self.is_zone_key() {
            writer.write_str(" (zsk)")?;
        }
        let owner = record.owner().clone();
        let key = domain::validate::Key::from_dnskey(owner, self.clone()).unwrap();
        let key_size = key.key_size();
        writer.write_fmt(format_args!(", size = {key_size}b}}"))
    }
}

//------------ AnyFamiliesIter -----------------------------------------------

type FamilyIterByValue<'a> =
    std::slice::Iter<'a, Family<'a, Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>>;
type FamilyIterByRef<'a> = RecordsIter<'a, Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>;

/// An iterator over a collection of [`Family`], whether by reference or not.
enum AnyFamiliesIter<'a> {
    VecIter(FamilyIterByValue<'a>),
    FamiliesIter(FamilyIterByRef<'a>),
}

impl<'a> Iterator for AnyFamiliesIter<'a>
where
    Family<'a, Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>: Clone,
{
    type Item = Family<'a, Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            AnyFamiliesIter::VecIter(it) => it.next().cloned(),
            AnyFamiliesIter::FamiliesIter(it) => it.next(),
        }
    }
}

//--- From<std::slice::Iter<'a, Family<'a, N, D>>>

impl<'a> From<std::slice::Iter<'a, Family<'a, Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>>>
    for AnyFamiliesIter<'a>
{
    fn from(
        iter: std::slice::Iter<'a, Family<'a, Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>>,
    ) -> Self {
        Self::VecIter(iter)
    }
}

//--- From<RecordsIter<'a, N, D>>

impl<'a> From<RecordsIter<'a, Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>>
    for AnyFamiliesIter<'a>
{
    fn from(iter: RecordsIter<'a, Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>) -> Self {
        Self::FamiliesIter(iter)
    }
}
