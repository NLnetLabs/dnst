// Output differences compared to the original ldns-signzone:
// ----------------------------------------------------------
// We differ to some example zone content in RFCs and to the output of the
// original LDNS tools regarding the order or case of some resource record
// data values that we output. The output format is defined by code in the
// `domain` crate, it is not defined here. It could in theory be overridden
// here but both formats are correct because the RFCs are not strict in how
// they define the presentation format of these fields, e.g.:
//
//   - DS digest: RFC 4034 5.3 says "The Digest MUST be represented as a
//     sequence of case-insensitive hexadecimal digits".
//   - NSEC3 salt: RFC 5155 3.3 says "The Salt field is represented as a
//     sequence of case-insensitive hexadecimal digits"
//   - NSEC3 next hashed owner: RFC 5155 3.3 says "The Next Hashed Owner Name
//     field is represented as an unpadded sequence of case-insensitive base32
//     digits, without whitespace."
//   - NSEC3 type bit maps: RFC 5155 3.3 says "The Type Bit Maps field is
//     represented as a sequence of RR type mnemonics", so a sequence but
//     nothing said about the order of that sequence. We output it in
//     ascending order by RTYPE code.
//   - ZONEMD hash: RFC 8976 2.3 says "The Digest is represented as a sequence
//     of case-insensitive hexadecimal digits".

use core::clone::Clone;
use core::cmp::Ordering;
use core::fmt::Write;
use core::ops::Add;
use core::str::FromStr;

use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};

use bytes::{BufMut, Bytes};
use clap::builder::ValueParser;

use domain::base::iana::nsec3::Nsec3HashAlgorithm;
use domain::base::iana::zonemd::{ZonemdAlgorithm, ZonemdScheme};
use domain::base::iana::Class;
use domain::base::name::FlattenInto;
use domain::base::zonefile_fmt::{self, Formatter, ZonefileFmt};
use domain::base::{
    CanonicalOrd, Name, NameBuilder, Record, RecordData, Rtype, Serial, ToName, Ttl,
};
use domain::crypto::sign::{FromBytesError, KeyPair, SecretKeyBytes};
use domain::dnssec::common::parse_from_bind;
use domain::dnssec::sign::denial::config::DenialConfig;
use domain::dnssec::sign::denial::nsec::GenerateNsecConfig;
use domain::dnssec::sign::denial::nsec3::mk_hashed_nsec3_owner_name;
use domain::dnssec::sign::denial::nsec3::{GenerateNsec3Config, Nsec3ParamTtlMode};
use domain::dnssec::sign::error::SigningError;
use domain::dnssec::sign::keys::SigningKey;
use domain::dnssec::sign::records::{OwnerRrs, RecordsIter, Rrset, SortedRecords};
use domain::dnssec::sign::signatures::rrsigs::sign_rrset;
use domain::dnssec::sign::traits::{Signable, SignableZoneInPlace};
use domain::dnssec::sign::SigningConfig;
use domain::dnssec::validator::base::DnskeyExt;
use domain::rdata::dnssec::Timestamp;
use domain::rdata::nsec3::Nsec3Salt;
use domain::rdata::{Dnskey, Nsec3, Nsec3param, Rrsig, Soa, ZoneRecordData, Zonemd};
use domain::utils::base64;
use domain::zonefile::inplace::{self, Entry};
use domain::zonetree::types::StoredRecordData;
use domain::zonetree::{StoredName, StoredRecord};
use lexopt::Arg;
use octseq::builder::with_infallible;
use rayon::slice::ParallelSliceMut;
use ring::digest;

use crate::env::{Env, Stream};
use crate::error::{Context, Error};
use crate::{Args, DISPLAY_KIND};

use super::nsec3hash::Nsec3Hash;
use super::{parse_os, parse_os_with, Command, LdnsCommand};

//------------ Constants -----------------------------------------------------

const FOUR_WEEKS: u32 = 2419200;

//------------ SignZone ------------------------------------------------------

#[derive(Clone, Debug, clap::Args, PartialEq)]
#[clap(
    after_help = "Keys must be specified by their base name (usually K<name>+<alg>+<id>), i.e. WITHOUT the .private or .key extension.
If the public part of the key is not present in the zone, the DNSKEY RR will be read from the file called <base name>.key.
A date can be a timestamp (seconds since the epoch), or of the form <YYYYMMdd[hhmmss]>
"
)]
pub struct SignZone {
    // -----------------------------------------------------------------------
    // Original ldns-signzone options in ldns-signzone -h order:
    // -----------------------------------------------------------------------
    /// Use layout in signed zone and print comments on DNSSEC records.
    ///
    /// Using this flag enables -O and -R automatically.
    #[arg(
        help_heading = Some("OUTPUT FORMATTING"),
        short = 'b',
        default_value_t = false
    )]
    extra_comments: bool,

    /// Used keys are not added to the zone.
    #[arg(short = 'd', default_value_t = false)]
    do_not_add_keys_to_zone: bool,

    /// Expiration date [default: 4 weeks from now].
    // Default is not documented in ldns-signzone -h or man ldns-signzone but
    // in code (see ldns/dnssec_sign.c::ldns_create_empty_rrsig()) LDNS uses
    // now + 4 weeks if no expiration timestamp is specified.
    #[arg(
        short = 'e',
        value_name = "date",
        default_value_t = TestableTimestamp::now().into_int().add(FOUR_WEEKS).into(),
        hide_default_value = true,
        value_parser = ValueParser::new(SignZone::parse_timestamp),
    )]
    expiration: Timestamp,

    /// Output zone to file [default: <zonefile>.signed].
    ///
    /// Use '-f -' to output to stdout.
    #[arg(short = 'f', value_name = "file")]
    out_file: Option<PathBuf>,

    /// Inception date [default: now].
    // Default is not documented in ldns-signzone -h or man ldns-signzone but
    // in code (see ldns/dnssec_sign.c::ldns_create_empty_rrsig()) LDNS uses
    // now if no inception timestamp is specified.
    #[arg(
        short = 'i',
        value_name = "date",
        default_value_t = TestableTimestamp::now(),
        hide_default_value = true,
        value_parser = ValueParser::new(SignZone::parse_timestamp),
    )]
    inception: Timestamp,

    /// Origin for the zone (for zonefiles with relative names and no $ORIGIN).
    #[arg(short = 'o', value_name = "domain")]
    origin: Option<StoredName>,

    /// Set SOA serial to the number of seconds since Jan 1st 1970.
    ///
    /// If this would NOT result in the SOA serial increasing it will be
    /// incremented instead.
    #[arg(short = 'u', default_value_t = false)]
    set_soa_serial_to_epoch_time: bool,

    /// Use NSEC3 instead of NSEC.
    #[arg(short = 'n', default_value_t = false, group = "nsec3")]
    use_nsec3: bool,

    /// Sign DNSKEYs with all keys instead of the minimal set.
    #[arg(short = 'A', default_value_t = false)]
    sign_dnskeys_with_all_keys: bool,

    /// Sign with every unique algorithm in the provided keys.
    #[arg(short = 'U', default_value_t = false)]
    sign_with_every_unique_algorithm: bool,

    /// Add a ZONEMD resource record.
    ///
    /// <hash> currently supports "SHA384" (1) or "SHA512" (2).
    /// <scheme> currently only supports "SIMPLE" (1).
    ///
    /// Can occur more than once, but only one per unique scheme and hash
    /// tuple will be added.
    #[arg(
        short = 'z',
        value_name = "[scheme:]hash",
        value_parser = Self::parse_zonemd_tuple,
        action = clap::ArgAction::Append
    )]
    // Clap doesn't support HashSet (without complex workarounds), therefore
    // the uniqueness of the tuples need to be checked at runtime.
    zonemd: Vec<ZonemdTuple>,

    /// Allow ZONEMDs to be added without signing.
    #[arg(short = 'Z', requires = "zonemd")]
    allow_zonemd_without_signing: bool,

    /// Hashing algorithm.
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 'a',
        value_name = "algorithm",
        default_value = "SHA-1",
        value_parser = ValueParser::new(Nsec3Hash::parse_nsec3_alg),
        requires = "nsec3"
    )]
    algorithm: Nsec3HashAlgorithm,

    /// Number of hash iterations.
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 't',
        value_name = "number",
        default_value_t = 0,
        requires = "nsec3"
    )]
    iterations: u16,

    /// Salt.
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 's',
        value_name = "string",
        default_value_t = Nsec3Salt::empty(),
        requires = "nsec3"
    )]
    salt: Nsec3Salt<Bytes>,

    /// Set the opt-out flag on all NSEC3 RRs.
    ///
    /// Cannot be used with -P.
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
    /// Set the opt-out flag on all NSEC3 RRs and skip unsigned delegations.
    ///
    /// Cannot be used with -p.
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 'P',
        default_value_t = false,
        requires = "nsec3",
        conflicts_with = "nsec3_opt_out_flags_only"
    )]
    nsec3_opt_out: bool,

    /// Hash only, don't sign.
    #[arg(short = 'H', default_value_t = false)]
    hash_only: bool,

    /// Preceed the zone output by a list that contains the NSEC3 hashes of the
    /// original ownernames.
    ///
    /// Requires -n.
    #[arg(
        help_heading = Some("OUTPUT FORMATTING"),
        short = 'L',
        default_value_t = false,
        requires = "nsec3"
    )]
    preceed_zone_with_hash_list: bool,

    /// Order NSEC3 RRs by unhashed owner name.
    ///
    /// Enabled automatically by -b.
    #[arg(
        help_heading = Some("OUTPUT FORMATTING"),
        short = 'O',
        default_value_t = false,
        default_value_if("extra_comments", "true", Some("true")),
        requires = "nsec3",
    )]
    order_nsec3_rrs_by_unhashed_owner_name: bool,

    /// Order RRSIG RRs by the record type that they cover.
    ///
    /// Enabled automatically by -b.
    #[arg(
        help_heading = Some("OUTPUT FORMATTING"),
        short = 'R',
        default_value_t = false,
        default_value_if("extra_comments", "true", Some("true")),
    )]
    order_rrsigs_after_the_rtype_they_cover: bool,

    /// Output YYYYMMDDHHmmSS RRSIG timestamps instead of seconds since epoch.
    ///
    /// Cannot be used with -Z or -H.
    #[arg(
        help_heading = Some("OUTPUT FORMATTING"),
        short = 'T',
        default_value_t = false,
        conflicts_with_all = ["allow_zonemd_without_signing", "hash_only"],
    )]
    use_yyyymmddhhmmss_rrsig_format: bool,

    // -----------------------------------------------------------------------
    // Original ldns-signzone positional arguments in position order:
    // -----------------------------------------------------------------------
    /// The zonefile to sign.
    #[arg(value_name = "zonefile")]
    zonefile_path: PathBuf,

    /// The keys to sign the zone with.
    ///
    /// Cannot be used with -Z or -H.
    #[arg(
        value_name = "key",
        conflicts_with_all = ["allow_zonemd_without_signing", "hash_only"],
        required_unless_present_any = ["allow_zonemd_without_signing", "hash_only"]
    )]
    key_paths: Vec<PathBuf>,

    // -----------------------------------------------------------------------
    // Non-command line argument fields:
    // -----------------------------------------------------------------------
    /// Whether or not we were invoked as `ldns-signzone`.
    #[arg(skip)]
    invoked_as_ldns: bool,
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
  -L            Preceed the zone output by a list of NSEC3 owners and hashes.

  keys must be specified by their base name (usually K<name>+<alg>+<id>),
  i.e. WITHOUT the .private extension.
  If the public part of the key is not present in the zone, the DNSKEY RR
  will be read from the file called <base name>.key.
  A date can be a timestamp (seconds since the epoch), or of
  the form <YYYYMMdd[hhmmss]>
"###;

impl LdnsCommand for SignZone {
    const NAME: &'static str = "signzone";
    const HELP: &'static str = LDNS_HELP;
    const COMPATIBLE_VERSION: &'static str = "1.8.4";

    fn parse_ldns<I: IntoIterator<Item = OsString>>(args: I) -> Result<Args, Error> {
        let mut extra_comments = false;
        let mut do_not_add_keys_to_zone = false;
        let mut expiration = TestableTimestamp::now().into_int().add(FOUR_WEEKS).into();
        let mut out_file = Option::<PathBuf>::None;
        let mut inception = TestableTimestamp::now();
        let mut origin = Option::<StoredName>::None;
        let mut set_soa_serial_to_epoch_time = false;
        let mut zonemd = Vec::new();
        let mut allow_zonemd_without_signing = false;
        let mut sign_dnskeys_with_all_keys = false;
        let mut sign_with_every_unique_algorithm = false;
        let mut use_nsec3 = false;
        let mut algorithm = Nsec3HashAlgorithm::SHA1;
        let mut iterations = 1u16;
        let mut salt = Nsec3Salt::<Bytes>::empty();
        let mut nsec3_opt_out_flags_only = false;
        let mut preceed_zone_with_hash_list = false;
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
                    // LDNS treats 0 as unset.
                    let val_as_num = usize::from_str(val.to_str().unwrap_or_default());
                    if val_as_num.is_err() || val_as_num.unwrap() > 0 {
                        expiration = parse_os_with("-e", &val, SignZone::parse_timestamp)?;
                    }
                }
                Arg::Short('f') => {
                    let val = parser.value()?;
                    out_file = Some(parse_os("-f", &val)?);
                }
                Arg::Short('i') => {
                    let val = parser.value()?;
                    // LDNS treats 0 as unset.
                    let val_as_num = usize::from_str(val.to_str().unwrap_or_default());
                    if val_as_num.is_err() || val_as_num.unwrap() > 0 {
                        inception = parse_os_with("-e", &val, SignZone::parse_timestamp)?;
                    }
                }
                Arg::Short('o') => {
                    let val = parser.value()?;
                    origin = Some(parse_os("-o", &val)?);
                }
                Arg::Short('u') => {
                    set_soa_serial_to_epoch_time = true;
                }
                Arg::Short('z') => {
                    let val = parser.value()?;
                    zonemd.push(parse_os_with(
                        "-z",
                        &val,
                        SignZone::parse_zonemd_tuple_ldns,
                    )?);
                }
                Arg::Short('Z') => {
                    allow_zonemd_without_signing = true;
                }
                Arg::Short('A') => {
                    sign_dnskeys_with_all_keys = true;
                }
                Arg::Short('U') => {
                    sign_with_every_unique_algorithm = true;
                }
                Arg::Short('v') => {
                    return Ok(Self::report_version());
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
                    nsec3_opt_out_flags_only = true;
                }
                Arg::Short('L') => {
                    preceed_zone_with_hash_list = true;
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

        // Logically this should also check that zonemd flags are given, but
        // ldns-signzone just copies the unsigned zone (without comments) when
        // using only -Z (without -z).
        if key_paths.is_empty() && !allow_zonemd_without_signing {
            return Err("No keys to sign with. Aborting.".into());
        };

        preceed_zone_with_hash_list &= extra_comments && use_nsec3;

        Ok(Args::from(Command::SignZone(Self {
            extra_comments,
            do_not_add_keys_to_zone,
            expiration,
            out_file,
            inception,
            origin,
            set_soa_serial_to_epoch_time,
            zonemd,
            allow_zonemd_without_signing,
            sign_dnskeys_with_all_keys,
            sign_with_every_unique_algorithm,
            use_nsec3,
            algorithm,
            iterations,
            salt,
            nsec3_opt_out_flags_only,
            nsec3_opt_out: false,
            hash_only: false,
            use_yyyymmddhhmmss_rrsig_format: true,
            preceed_zone_with_hash_list,
            order_rrsigs_after_the_rtype_they_cover: extra_comments,
            order_nsec3_rrs_by_unhashed_owner_name: extra_comments,
            zonefile_path,
            key_paths,
            invoked_as_ldns: true,
        })))
    }
}

impl SignZone {
    fn parse_zonemd_tuple(arg: &str) -> Result<ZonemdTuple, Error> {
        let scheme;
        let hash_alg;

        if let Some((s, h)) = arg.split_once(':') {
            scheme = if let Ok(num) = s.parse() {
                Self::num_to_zonemd_scheme(num)
            } else {
                ZonemdScheme::from_mnemonic(s.as_bytes()).ok_or("unknown ZONEMD scheme mnemonic")
            }?;
            hash_alg = h;
        } else {
            scheme = ZonemdScheme::SIMPLE;
            hash_alg = arg
        };

        let hash_alg = if let Ok(num) = hash_alg.parse() {
            Self::num_to_zonemd_alg(num)
        } else {
            ZonemdAlgorithm::from_mnemonic(hash_alg.as_bytes())
                .ok_or("unknown ZONEMD algorithm mnemonic")
        }?;

        Ok(ZonemdTuple(scheme, hash_alg))
    }

    pub fn num_to_zonemd_alg(num: u8) -> Result<ZonemdAlgorithm, &'static str> {
        let alg = ZonemdAlgorithm::from_int(num);
        match alg.to_mnemonic() {
            Some(_) => Ok(alg),
            None => Err("unknown ZONEMD algorithm number"),
        }
    }

    pub fn num_to_zonemd_scheme(num: u8) -> Result<ZonemdScheme, &'static str> {
        let alg = ZonemdScheme::from_int(num);
        match alg.to_mnemonic() {
            Some(_) => Ok(alg),
            None => Err("unknown ZONEMD scheme number"),
        }
    }

    fn parse_zonemd_tuple_ldns(arg: &str) -> Result<ZonemdTuple, Error> {
        let scheme;
        let hash_alg;

        fn parse_zonemd_scheme_ldns(s: &str) -> Result<ZonemdScheme, Error> {
            match s.to_lowercase().as_str() {
                "simple" | "1" => Ok(ZonemdScheme::SIMPLE),
                _ => Err("unknown ZONEMD scheme name or number".into()),
            }
        }

        fn parse_zonemd_hash_alg_ldns(h: &str) -> Result<ZonemdAlgorithm, Error> {
            match h.to_lowercase().as_str() {
                "sha384" | "1" => Ok(ZonemdAlgorithm::SHA384),
                "sha512" | "2" => Ok(ZonemdAlgorithm::SHA512),
                _ => Err("unknown ZONEMD algorithm name or number".into()),
            }
        }

        if let Some((s, h)) = arg.split_once(':') {
            scheme = parse_zonemd_scheme_ldns(s)?;
            hash_alg = parse_zonemd_hash_alg_ldns(h)?;
        } else {
            scheme = ZonemdScheme::SIMPLE;
            hash_alg = parse_zonemd_hash_alg_ldns(arg)?;
        };

        Ok(ZonemdTuple(scheme, hash_alg))
    }

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
        let signing_mode = if self.hash_only {
            if self.key_paths.is_empty() {
                SigningMode::HashOnly
            } else {
                return Err("Key paths are not expected when using '-H'".into());
            }
        } else if self.allow_zonemd_without_signing {
            SigningMode::None
        } else {
            SigningMode::HashAndSign
        };

        let out_file = if let Some(out_file) = &self.out_file {
            out_file.clone()
        } else {
            let out_file = format!("{}.signed", self.zonefile_path.display());
            PathBuf::from_str(&out_file)
                .map_err(|err| format!("Cannot write to {out_file}: {err}"))?
        };

        // ldns-signzone only shows these warnings if verbosity < 1 but offers
        // no way to configure the verbosity level. I assume the intent was to
        // add support for a -q (--quiet) option or similar but that was never
        // done.
        match self.iterations {
            500.. => Self::write_extreme_iterations_warning(&env),
            100.. if self.invoked_as_ldns => Self::write_large_iterations_warning(&env),
            1.. if !self.invoked_as_ldns => Self::write_non_zero_iterations_warning(&env),
            _ => { /* Good, nothing to warn about */ }
        }

        // Read the zone file.
        let mut records = self.load_zone(&env.in_cwd(&self.zonefile_path))?;

        // Extract the SOA RR from the loaded zone.
        let Some(soa_rr) = records.find_soa() else {
            return Err(format!(
                "Zone file '{}' does not contain a SOA record",
                self.zonefile_path.display()
            )
            .into());
        };
        let ZoneRecordData::Soa(_) = soa_rr.first().data() else {
            return Err(format!(
                "Zone file '{}' contains an invalid SOA record",
                self.zonefile_path.display()
            )
            .into());
        };

        let mut signing_keys: Vec<SigningKey<Bytes, KeyPair>> = vec![];

        let mut zone_signing_keys = Vec::new();

        if signing_mode == SigningMode::HashAndSign {
            let dnskey_rrset = records.find_apex_rtype(soa_rr.owner(), Rtype::DNSKEY);
            let cds_rrset = records.find_apex_rtype(soa_rr.owner(), Rtype::CDS);
            let cdnskey_rrset = records.find_apex_rtype(soa_rr.owner(), Rtype::CDNSKEY);

            // Extract and validate the DNSKEY RRs from the loaded zone.
            let mut found_public_keys = vec![];
            if let Some(dnskey_rrset) = &dnskey_rrset {
                for rr in dnskey_rrset.iter() {
                    if let ZoneRecordData::Dnskey(dnskey) = rr.data() {
                        // Create a public key object from the found DNSKEY RR.
                        let public_key = Record::new(rr.owner(), Class::IN, Ttl::ZERO, dnskey);

                        found_public_keys.push(public_key);
                    }
                }
            }

            // Load the specified private keys, match them against the found
            // public keys, failing that load a DNSKEY RR from the corresponding
            // public key file and validate that its owner matches that of the
            // zone apex. Unlike ldns-signzone we don't use a generated public key
            // if these attempts fail.
            'next_key_path: for key_path in &self.key_paths {
                let key_path = env.in_cwd(key_path).into_owned();
                // Load the private key.
                let private_key_path = Self::mk_private_key_path(&key_path);
                let private_key = Self::load_private_key(&env.in_cwd(&private_key_path))?;

                // Note: Our behaviour differs to that of the original
                // ldns-signzone because we are unable at the time of writing to
                // generate a public key from a private key. As such we cannot
                // compare the key tag of any found DNSKEY RRs to that of the
                // public key generated from the private key. Instead we attempt
                // to construct a key pair from the found public key and each
                // private key which tests that they match.
                for public_key in &found_public_keys {
                    // Attempt to create a key pair from this public key and every
                    // private key that we have.
                    if let Ok(signing_key) = self.mk_signing_key(
                        (*public_key.owner()).clone(),
                        &private_key,
                        (*public_key.data()).clone(),
                    ) {
                        // Match found, keep the created signing key.
                        // TODO: Log here.
                        // TODO: Check the key tag against the key tag in the key file name?
                        // println!(
                        //     "DNSKEY RR with key tag {} matches loaded private key '{}'",
                        //     public_key.key_tag(),
                        //     private_key_path.display()
                        // );
                        signing_keys.push(signing_key);
                        continue 'next_key_path;
                    }
                }

                // No matching public key found, try to load the public key
                // instead.
                let public_key_path = Self::mk_public_key_path(&key_path);
                let public_key = Self::load_public_key(&env.in_cwd(&public_key_path))?;

                // Verify that the owner of the public key matches the apex of the
                // zone.
                if public_key.owner() != soa_rr.owner() {
                    return Err(format!(
                        "Zone apex ({}) does not match the expected apex ({})",
                        soa_rr.owner(),
                        public_key.owner()
                    )
                    .into());
                }

                // Attempt to create a key pair from the loaded private and public
                // keys.
                let signing_key = self
                    .mk_signing_key(
                        public_key.owner().clone(),
                        &private_key,
                        public_key.data().clone(),
                    )
                    .map_err(|err| {
                        format!(
                            "Unable to create key pair from '{}' and '{}': {}",
                            public_key_path.display(),
                            private_key_path.display(),
                            err
                        )
                    })?;

                // Store the created signing key.
                signing_keys.push(signing_key);

                // TODO: Log
                // println!(
                //     "Loaded public key with key tag {} from '{}' for private key '{}'",
                //     public_key.key_tag(),
                //     public_key_path.display(),
                //     private_key_path.display()
                // );
            }

            // First split the key into Key Signing Keys (KSK) that sign the
            // DNSKEY RRset and Zone Signing Keys (ZSK) that sign the zone.
            let mut key_signing_keys = Vec::new();
            for k in &signing_keys {
                if k.is_secure_entry_point() {
                    key_signing_keys.push(k);
                } else {
                    zone_signing_keys.push(k);
                }
            }

            if key_signing_keys.is_empty() {
                // Sign the DNSKEY RRset with the zone signing keys.
                key_signing_keys.append(&mut zone_signing_keys.clone());
            } else if zone_signing_keys.is_empty() {
                // Sign the zone with the key signing keys.
                zone_signing_keys.append(&mut key_signing_keys.clone());
            } else {
                if self.sign_dnskeys_with_all_keys {
                    // Sign DNSKEY RRset with all keys. Add the ZSKs to the
                    // KSKs.
                    key_signing_keys.append(&mut zone_signing_keys.clone());
                }
                if self.sign_with_every_unique_algorithm {
                    // Add ZSKs to KSKs if the ZSKs have an algorithm that is
                    // not currently used by the KSKs.
                    let mut algorithms = HashSet::new();
                    for k in &key_signing_keys {
                        algorithms.insert(k.algorithm());
                    }
                    for k in &zone_signing_keys {
                        if !algorithms.contains(&k.algorithm()) {
                            // ldns-signzone adds just one key per algorithm.
                            algorithms.insert(k.algorithm());

                            key_signing_keys.push(k);
                        }
                    }

                    // Add KSKs to ZSKs if the KSKs have an algorithm that is
                    // not currently used by the ZSKs.
                    let mut algorithms = HashSet::new();
                    for k in &zone_signing_keys {
                        algorithms.insert(k.algorithm());
                    }
                    for k in &key_signing_keys {
                        if !algorithms.contains(&k.algorithm()) {
                            // ldns-signzone adds just one key per algorithm.
                            algorithms.insert(k.algorithm());

                            zone_signing_keys.push(k);
                        }
                    }
                }
            }

            let mut dnskey_extra = Vec::new();
            let mut all_dnskeys = Vec::new();
            let empty_records: [Record<_, _>; 0] = [];
            for r in dnskey_rrset
                .as_ref()
                .map_or(empty_records.iter(), |r| r.iter())
            {
                all_dnskeys.push(r.clone());
            }
            if !self.do_not_add_keys_to_zone {
                let dnskey_ttl = dnskey_rrset.as_ref().map_or(soa_rr.ttl(), |r| r.ttl());
                // Make sure that the DNSKEY RRset contains all keys.
                for k in &signing_keys {
                    let pubkey = k.dnskey();
                    if !dnskey_rrset
                        .as_ref()
                        .map_or(empty_records.iter(), |r| r.iter())
                        .any(|k| {
                            if let ZoneRecordData::Dnskey(dnskey) = k.data() {
                                *dnskey == pubkey
                            } else {
                                false
                            }
                        })
                    {
                        let pubkey: Dnskey<Bytes> = pubkey.convert();
                        let data = ZoneRecordData::Dnskey(pubkey);
                        let record =
                            Record::new(soa_rr.owner().clone(), soa_rr.class(), dnskey_ttl, data);
                        dnskey_extra.push(record.clone());
                        all_dnskeys.push(record);
                    }
                }
            }

            let all_dnskeys = Rrset::new(&all_dnskeys);

            let mut dnskey_rrsigs = Vec::new();
            if let Ok(all_dnskeys) = all_dnskeys {
                for k in &key_signing_keys {
                    let rrsig = sign_rrset(k, &all_dnskeys, self.inception, self.expiration)
                        .expect("should not fail");
                    let data = ZoneRecordData::Rrsig(rrsig.data().clone());
                    let record =
                        Record::new(rrsig.owner().clone(), rrsig.class(), rrsig.ttl(), data);
                    dnskey_rrsigs.push(record);
                }
            }

            let mut cds_cdnskey_rrsigs = Vec::new();
            if let Some(cds_rrset) = &cds_rrset {
                for k in &key_signing_keys {
                    let rrsig = sign_rrset(k, cds_rrset, self.inception, self.expiration)
                        .expect("should not fail");
                    let data = ZoneRecordData::Rrsig(rrsig.data().clone());
                    let record =
                        Record::new(rrsig.owner().clone(), rrsig.class(), rrsig.ttl(), data);
                    cds_cdnskey_rrsigs.push(record);
                }
            }

            if let Some(cdnskey_rrset) = &cdnskey_rrset {
                for k in key_signing_keys {
                    let rrsig = sign_rrset(k, cdnskey_rrset, self.inception, self.expiration)
                        .expect("should not fail");
                    let data = ZoneRecordData::Rrsig(rrsig.data().clone());
                    let record =
                        Record::new(rrsig.owner().clone(), rrsig.class(), rrsig.ttl(), data);
                    cds_cdnskey_rrsigs.push(record);
                }
            }

            for r in dnskey_extra {
                records.insert(r).expect("should not fail");
            }
            for r in dnskey_rrsigs {
                records.insert(r).expect("should not fail");
            }
            for r in cds_cdnskey_rrsigs {
                records.insert(r).expect("should not fail");
            }
        }

        self.go_further(env, records, signing_mode, &zone_signing_keys, out_file)
    }

    #[allow(clippy::too_many_arguments)]
    fn go_further(
        &self,
        env: impl Env,
        mut records: SortedRecords<
            StoredName,
            ZoneRecordData<Bytes, StoredName>,
            MultiThreadedSorter,
        >,
        signing_mode: SigningMode,
        signing_keys: &[&SigningKey<Bytes, KeyPair>],
        out_file: PathBuf,
    ) -> Result<(), Error> {
        let mut writer = if out_file.as_os_str() == "-" {
            FileOrStdout::Stdout(env.stdout())
        } else {
            let file = File::create(env.in_cwd(&out_file))?;
            let file = BufWriter::new(file);
            FileOrStdout::File(file)
        };

        // Make sure, zonemd arguments are unique
        let zonemd: HashSet<ZonemdTuple> = HashSet::from_iter(self.zonemd.clone());

        // Change the SOA serial.
        if self.set_soa_serial_to_epoch_time {
            Self::bump_soa_serial(&env, &mut records)?;
        }

        // Find the apex.
        let (apex, zone_class, ttl, soa_serial) = Self::find_apex(&records).unwrap();

        // The original ldns-signzone filters out (with warnings) NSEC3 RRs,
        // or RRSIG RRs covering NSEC3 RRs, where the hashed owner name
        // doesn't correspond to an unhashed owner name in the zone. To work
        // this out you have to NSEC3 hash every owner name during loading and
        // filter out any NSEC3 hashed owner name that doesn't appear in the
        // built NSEC3 hash set. To generate the NSEC3 hashes we have to know
        // the settings that were used to NSEC3 hash the zone, i.e. we have to
        // find an NSEC3PARAM RR at the apex, or an NSEC3 RR in the zone. But
        // we don't know what the apex is until we find the SOA, and checking
        // DNSKEYs and loading key files is quick so we do that first. Then
        // once we get here we have the ordered zone, we know the apex, and we
        // can find the NSEC3PARAM RR. Then we can generate NSEC3 hashes for
        // owner names.
        //
        // However, WE DON'T DO THIS as it was (a) discovered that
        // ldns-signzone is too simplistic in its approach as it would wrongly
        // conclude that NSEC3 hashes for empty non-terminals lack a matching
        // owner name in the zone because it only determined ENTs _after_
        // ignoring and warning about hashed owner names that don't correspond
        // to an unhashed owner name in the zone, and (b) that it would be
        // better for ldns-signzone to strip out NSEC(3)s on loading anyway as
        // it should only operate on unsigned zone input.

        if !zonemd.is_empty() {
            Self::replace_apex_zonemd_with_placeholder(
                &mut records,
                &apex,
                zone_class,
                soa_serial,
                ttl,
            );
        }

        let mut nsec3_hashes: Option<Nsec3HashMap> = None;

        if self.use_nsec3 && (self.extra_comments || self.preceed_zone_with_hash_list) {
            // Create a collection of NSEC3 hashes that can later be used for
            // debug output.
            let mut hash_provider = Nsec3HashMap::new();
            let mut prev_name = None;
            let mut delegation = None;
            for rrset in records.rrsets() {
                let owner = rrset.owner();

                if let Some(ref prev_name) = prev_name {
                    if *owner == prev_name {
                        // Already done.
                        if rrset.rtype() == Rtype::NS && *owner != apex {
                            delegation = Some(owner.clone());
                        }
                        continue;
                    }
                }
                if let Some(ref delegation_name) = delegation {
                    if owner != delegation_name {
                        if owner.ends_with(&delegation_name) {
                            // Below zone cut, ignore.
                            continue;
                        } else {
                            // Reset delegation.
                            delegation = None;
                        }
                    }
                }
                prev_name = Some(owner.clone());

                if rrset.rtype() == Rtype::NS && *owner != apex {
                    delegation = Some(owner.clone());
                    if self.nsec3_opt_out {
                        // Delegations are ignored for NSEC3. Ignore this
                        // entry but keep looking for other types at the
                        // same owner name.
                        prev_name = None;
                        continue;
                    }
                }

                let hashed_name = mk_hashed_nsec3_owner_name(
                    owner,
                    self.algorithm,
                    self.iterations,
                    &self.salt,
                    &apex,
                )
                .map_err(|err| Error::from(format!("NSEC3 error: {err}")))?;
                let hash_info = Nsec3HashInfo::new(owner.clone(), false);
                hash_provider
                    .hashes_by_unhashed_owner
                    .insert(hashed_name, hash_info);

                if *owner == apex {
                    // No need to consider empty non-terminals.
                    continue;
                }

                // Insert empty non-terminals
                for suffix in owner.iter_suffixes() {
                    if suffix == owner {
                        // Owner is already done.
                        continue;
                    }
                    if suffix == apex {
                        // Apex is not an ENT. No need to consider
                        // smaller suffixes.
                        break;
                    }

                    let hashed_name = mk_hashed_nsec3_owner_name(
                        &suffix,
                        self.algorithm,
                        self.iterations,
                        &self.salt,
                        &apex,
                    )
                    .map_err(|err| Error::from(format!("NSEC3 error: {err}")))?;
                    if hash_provider
                        .hashes_by_unhashed_owner
                        .contains_key(&hashed_name)
                    {
                        // Hash is already there. No need to continue
                        // with smaller suffixes.
                        break;
                    }

                    let hash_info = Nsec3HashInfo::new(suffix.clone(), true);
                    hash_provider
                        .hashes_by_unhashed_owner
                        .insert(hashed_name, hash_info);
                }
            }
            nsec3_hashes = Some(hash_provider);
        }

        let signing_config: SigningConfig<_, _> = match signing_mode {
            SigningMode::HashOnly | SigningMode::HashAndSign => {
                // LDNS doesn't add NSECs to a zone that already has NSECs or
                // NSEC3s. It *does* add NSEC3s if the zone has NSECs. As noted in
                // load_zone() we instead, as LDNS should, strip NSEC(3)s on load
                // and thus always add NSEC(3)s when hashing.
                //
                // Note: Assuming that we want to later be able to support
                // transition between NSEC <-> NSEC3 we will need to be able to
                // sign with more than one hashing configuration at once.
                if self.use_nsec3 {
                    let params =
                        Nsec3param::new(self.algorithm, 0, self.iterations, self.salt.clone());
                    let mut nsec3_config = GenerateNsec3Config::new(params);
                    if self.nsec3_opt_out {
                        nsec3_config = nsec3_config.with_opt_out();
                    } else if self.nsec3_opt_out_flags_only {
                        nsec3_config = nsec3_config
                            .with_opt_out()
                            .without_opt_out_excluding_owner_names_of_unsigned_delegations();
                    }
                    if self.invoked_as_ldns {
                        nsec3_config = nsec3_config
                            .with_ttl_mode(Nsec3ParamTtlMode::fixed(Ttl::from_secs(3600)));
                    }
                    SigningConfig::new(
                        DenialConfig::Nsec3(nsec3_config),
                        self.inception,
                        self.expiration,
                    )
                } else {
                    SigningConfig::new(
                        DenialConfig::Nsec(GenerateNsecConfig::new()),
                        self.inception,
                        self.expiration,
                    )
                }
            }

            SigningMode::None => SigningConfig::new(
                DenialConfig::AlreadyPresent,
                self.inception,
                self.expiration,
            ),
        };

        records
            .sign_zone(&apex, &signing_config, signing_keys)
            .map_err(|err| format!("Signing failed: {err}"))?;

        if !zonemd.is_empty() {
            // Remove the placeholder ZONEMD RR at apex
            let _ = records.remove_first_by_name_class_rtype(&apex, None, Some(Rtype::ZONEMD));

            let zonemd_rrs = Self::create_zonemd_digest_and_records(
                &records, &apex, zone_class, &zonemd, soa_serial, ttl,
            )?;

            // Add ZONEMD RRs to output records
            for zrr in zonemd_rrs.clone() {
                let _ = records.insert(zrr);
            }

            if signing_mode == SigningMode::HashAndSign {
                Self::update_zonemd_rrsig(
                    &apex,
                    &mut records,
                    signing_keys,
                    &zonemd_rrs,
                    self.inception,
                    self.expiration,
                )
                .map_err(|err| format!("ZONEMD re-signing error: {err}"))?;
            }
        }

        // The signed RRs are in DNSSEC canonical order by owner name. For
        // compatibility with ldns-signzone, re-order them to be in canonical
        // order by unhashed owner name and so that hashed names come after
        // equivalent unhashed names.
        //
        // INCOMAPATIBILITY WARNING: Unlike ldns-signzone, we only apply this
        // ordering if `-b` is specified.
        let mut owner_rrs;
        let owner_rrs_iter: AnyOwnerRrsIter =
            if self.order_nsec3_rrs_by_unhashed_owner_name && nsec3_hashes.is_some() {
                owner_rrs = records.owner_rrs().collect::<Vec<_>>();
                let Some(hashes) = nsec3_hashes.as_ref() else {
                    unreachable!();
                };

                owner_rrs.par_sort_unstable_by(|a, b| {
                    let mut hashed_count = 0;
                    let unhashed_a = if let Some(name) = hashes.get(a.owner()).map(|v| v.name()) {
                        hashed_count += 1;
                        name
                    } else {
                        a.owner()
                    };
                    let unhashed_b = if let Some(name) = hashes.get(b.owner()).map(|v| v.name()) {
                        hashed_count += 2;
                        name
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
                owner_rrs.iter().into()
            } else {
                records.owner_rrs().into()
            };

        // Output the resulting zone, with comments if enabled.
        if self.extra_comments {
            writer.write_fmt(format_args!(";; Zone: {}\n;\n", apex.fmt_with_dot()))?;
        }

        if self.preceed_zone_with_hash_list {
            if let Some(hashes) = &nsec3_hashes {
                let mut owner_sorted_hashes = hashes.iter().collect::<Vec<_>>();
                owner_sorted_hashes.par_sort_by(|(_, a), (_, b)| a.name().canonical_cmp(b.name()));
                for (hash, info) in owner_sorted_hashes {
                    writer.write_fmt(format_args!("; H({}) = {hash}\n", info.name()))?;
                }
            }
        }

        if let Some(record) = records.iter().find(|r| r.rtype() == Rtype::SOA) {
            self.writeln_rr(&mut writer, record)?;
            if self.order_rrsigs_after_the_rtype_they_cover {
                for r in records.iter().filter(|r| {
                    if let ZoneRecordData::Rrsig(rrsig) = r.data() {
                        rrsig.type_covered() == Rtype::SOA
                    } else {
                        false
                    }
                }) {
                    self.writeln_rr(&mut writer, r)?;
                }
                if self.extra_comments {
                    writer.write_str(";\n")?;
                }
            }
        }

        let nsec3_cs = Nsec3CommentState {
            hashes: nsec3_hashes.as_ref(),
            apex: &apex,
        };

        for owner_rrs in owner_rrs_iter {
            if self.extra_comments {
                if let Some(hashes) = nsec3_hashes.as_ref() {
                    if let Some(unhashed_owner_name) = hashes.get_if_ent(owner_rrs.owner()) {
                        writer.write_fmt(format_args!(
                            ";; Empty nonterminal: {unhashed_owner_name}\n"
                        ))?;
                    }
                }
            }

            // The SOA is output separately above as the very first RRset so
            // we skip that, and we skip RRSIGs as they are output only after
            // the RRset that they cover.
            if self.order_rrsigs_after_the_rtype_they_cover {
                for rrset in owner_rrs
                    .rrsets()
                    .filter(|rrset| !matches!(rrset.rtype(), Rtype::SOA | Rtype::RRSIG))
                {
                    for rr in rrset.iter() {
                        self.write_rr(&mut writer, rr)?;
                        match rr.data() {
                            ZoneRecordData::Nsec3(nsec3) if self.extra_comments => {
                                nsec3.comment(&mut writer, rr, nsec3_cs)?
                            }
                            ZoneRecordData::Dnskey(dnskey) => {
                                dnskey.comment(&mut writer, rr, ())?
                            }
                            _ => {
                                // Nothing to do. We do not support Bubble Babble
                                // output for DS records.
                                //
                                // See:
                                // https://bohwaz.net/archives/web/Bubble_Babble.html
                            }
                        }
                        writer.write_str("\n")?;
                    }

                    // Now attempt to print the RRSIGs that covers the RTYPE of this RRSET.
                    for covering_rrsigs in owner_rrs
                        .rrsets()
                        .filter(|this_rrset| this_rrset.rtype() == Rtype::RRSIG)
                        .map(|this_rrset| this_rrset.iter().filter(|rr| matches!(rr.data(), ZoneRecordData::Rrsig(rrsig) if rrsig.type_covered() == rrset.rtype())))
                    {
                        for covering_rrsig_rr in covering_rrsigs {
                            self.writeln_rr(&mut writer, covering_rrsig_rr)?;
                        }
                    }
                }
                if self.extra_comments {
                    writer.write_str(";\n")?;
                }
            } else {
                for rrset in owner_rrs
                    .rrsets()
                    .filter(|rrset| rrset.rtype() != Rtype::SOA)
                {
                    for rr in rrset.iter() {
                        // Only output the key tag comment if running as LDNS.
                        // When running as DNST we assume without `-b` that speed
                        // is wanted, not human readable comments.
                        self.write_rr(&mut writer, rr)?;
                        if self.invoked_as_ldns {
                            if let ZoneRecordData::Dnskey(dnskey) = rr.data() {
                                dnskey.comment(&mut writer, rr, ())?
                            }
                        }
                        writer.write_char('\n')?;
                    }
                }
            }
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
        if self.use_yyyymmddhhmmss_rrsig_format {
            if let ZoneRecordData::Rrsig(rrsig) = rr.data() {
                let rr = Record::new(rr.owner(), rr.class(), rr.ttl(), YyyyMmDdHhMMSsRrsig(rrsig));
                return writer.write_fmt(format_args!("{}", rr.display_zonefile(DISPLAY_KIND)));
            }
        }

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
            .map_err(Error::from)
            .context(&format!(
                "loading zone file from path '{}'",
                zonefile_path.display(),
            ))?;
        let zone_file_len = zone_file.metadata()?.len();
        let mut buf = inplace::Zonefile::with_capacity(zone_file_len as usize).writer();
        std::io::copy(&mut zone_file, &mut buf)?;
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

                    // Strip existing RRSIGs, as the original ldns-signzone
                    // does. Also strip NSEC(3)s as the original ldns-signzone
                    // should do instead of its current behaviour of (a)
                    // trying (imperfectly) to warn about hashed owner names
                    // for which a corresponding unhashed owner name is
                    // missing, and (b) hashing only if not already hashed.
                    //
                    // TODO: Create an issue for the original ldns-signzone or
                    // release a fixed version of ldns-signzone that strips
                    // NSEC(3)s.
                    //
                    // TODO: Support partial and re-signing.
                    if !matches!(
                        record.rtype(),
                        Rtype::RRSIG | Rtype::NSEC | Rtype::NSEC3 | Rtype::NSEC3PARAM
                    ) {
                        records.push(record);
                    }
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

    fn find_apex(
        records: &SortedRecords<StoredName, StoredRecordData, MultiThreadedSorter>,
    ) -> Result<(StoredName, Class, Ttl, Serial), Error> {
        let soa = match records.find_soa() {
            Some(soa) => soa,
            None => {
                return Err(Error::from("Invalid zone file: Cannot find SOA record"));
            }
        };

        let (ttl, serial) = match *soa.first().data() {
            ZoneRecordData::Soa(ref soa_data) => {
                // RFC 9077 updated RFC 4034 (NSEC) and RFC 5155 (NSEC3) to
                // say that the "TTL of the NSEC(3) RR that is returned MUST be
                // the lesser of the MINIMUM field of the SOA record and the
                // TTL of the SOA itself".
                (min(soa_data.minimum(), soa.ttl()), soa_data.serial())
            }
            _ => unreachable!(),
        };

        Ok((soa.owner().clone(), soa.class(), ttl, serial))
    }

    fn bump_soa_serial(
        env: &impl Env,
        records: &mut SortedRecords<
            StoredName,
            ZoneRecordData<Bytes, StoredName>,
            MultiThreadedSorter,
        >,
    ) -> Result<(), Error> {
        // SAFETY: Already checked before this point.
        let old_soa_rr = records.find_soa().unwrap();
        let ZoneRecordData::Soa(old_soa) = old_soa_rr.first().data() else {
            unreachable!();
        };

        // Undocumented behaviour in ldns-signzone: it doesn't just set the
        // SOA serial to the current unix timestamp as is documented for '-u'
        // but rather only does that if the resulting value would be larger
        // than the current unix timestamp, otherwise it increments it. I
        // assume it does that to ensure that the SOA serial advances on zone
        // change per expectations defined in RFC 1034, though it is assuming
        // that the SOA serial can be interpreted as a unix timestamp which
        // may not be the intention of the zone owner.

        let now = Serial::from(env.seconds_since_epoch());
        let new_serial = if now > old_soa.serial() {
            now
        } else {
            old_soa.serial().add(1)
        };

        let new_soa = ZoneRecordData::Soa(Soa::new(
            old_soa.mname().clone(),
            old_soa.rname().clone(),
            new_serial,
            old_soa.refresh(),
            old_soa.retry(),
            old_soa.expire(),
            old_soa.minimum(),
        ));

        records.update_data(|rr| rr.rtype() == Rtype::SOA, new_soa);

        Ok(())
    }

    fn load_private_key(key_path: &Path) -> Result<SecretKeyBytes, Error> {
        let private_data = std::fs::read_to_string(key_path)
            .map_err(Error::from)
            .context(&format!(
                "loading private key from file '{}'",
                key_path.display(),
            ))?;

        // Note: Compared to the original ldns-signzone there is a minor
        // regression here because at the time of writing the error returned
        // from parsing indicates broadly the type of parsing failure but does
        // note indicate the line number at which parsing failed.
        let secret_key = SecretKeyBytes::parse_from_bind(&private_data).map_err(|err| {
            format!(
                "Unable to parse BIND formatted private key file '{}': {}",
                key_path.display(),
                err
            )
        })?;

        Ok(secret_key)
    }

    fn load_public_key(key_path: &Path) -> Result<Record<Name<Bytes>, Dnskey<Bytes>>, Error> {
        let public_data = std::fs::read_to_string(key_path)
            .map_err(Error::from)
            .context(&format!(
                "loading public key from file '{}'",
                key_path.display(),
            ))?;

        // Note: Compared to the original ldns-signzone there is a minor
        // regression here because at the time of writing the error returned
        // from parsing indicates broadly the type of parsing failure but does
        // note indicate the line number at which parsing failed.
        let public_key_info = parse_from_bind(&public_data).map_err(|err| {
            format!(
                "Unable to parse BIND formatted public key file '{}': {}",
                key_path.display(),
                err
            )
        })?;

        Ok(public_key_info)
    }

    fn mk_public_key_path(key_path: &Path) -> PathBuf {
        if key_path.extension().and_then(|ext| ext.to_str()) == Some("key") {
            key_path.to_path_buf()
        } else {
            PathBuf::from(format!("{}.key", key_path.display()))
        }
    }

    fn mk_private_key_path(key_path: &Path) -> PathBuf {
        if key_path.extension().and_then(|ext| ext.to_str()) == Some("private") {
            key_path.to_path_buf()
        } else {
            PathBuf::from(format!("{}.private", key_path.display()))
        }
    }

    fn mk_signing_key(
        &self,
        owner: Name<Bytes>,
        private_key: &SecretKeyBytes,
        public_key: Dnskey<Bytes>,
    ) -> Result<SigningKey<Bytes, KeyPair>, FromBytesError> {
        let key_pair = KeyPair::from_bytes(private_key, &public_key)?;
        let signing_key = SigningKey::new(owner, public_key.flags(), key_pair);
        Ok(signing_key)
    }

    fn write_extreme_iterations_warning(env: &impl Env) {
        Self::write_iterations_warning(
            env,
            "NSEC3 iterations larger than 500 may cause validating resolvers to return SERVFAIL!",
        );
    }

    fn write_large_iterations_warning(env: &impl Env) {
        Self::write_iterations_warning(env, "NSEC3 iterations larger than 100 may cause validating resolvers to return insecure responses!");
    }

    fn write_non_zero_iterations_warning(env: &impl Env) {
        Self::write_iterations_warning(env, "NSEC3 iterations larger than 0 increases performance cost while providing only moderate protection!");
    }

    fn write_iterations_warning(env: &impl Env, text: &str) {
        Error::write_warning(&mut env.stderr(), text);
        writeln!(
            env.stderr(),
            "See: https://www.rfc-editor.org/rfc/rfc9276.html"
        );
    }

    /// Create the ZONEMD digest for the SIMPLE scheme.
    /// The records need to be in DNSSEC canonical ordering,
    /// with same owner RRs sorted numerically by RTYPE.
    ///
    /// [RFC 8976] Section 3.3.1. The SIMPLE Scheme
    /// ```text
    /// 3.3.1.  The SIMPLE Scheme
    ///
    ///    For the SIMPLE scheme, the digest is calculated over the zone as a
    ///    whole.  This means that a change to a single RR in the zone requires
    ///    iterating over all RRs in the zone to recalculate the digest.  SIMPLE
    ///    is a good choice for zones that are small and/or stable, but it is
    ///    probably not good for zones that are large and/or dynamic.
    ///
    ///    Calculation of a zone digest requires RRs to be processed in a
    ///    consistent format and ordering.  This specification uses DNSSEC's
    ///    canonical on-the-wire RR format (without name compression) and
    ///    ordering as specified in Sections 6.1, 6.2, and 6.3 of [RFC4034] with
    ///    the additional provision that RRsets having the same owner name MUST
    ///    be numerically ordered, in ascending order, by their numeric RR TYPE.
    ///
    /// 3.3.1.1.  SIMPLE Scheme Inclusion/Exclusion Rules
    ///
    ///    When iterating over records in the zone, the following inclusion/
    ///    exclusion rules apply:
    ///
    ///    *  All records in the zone, including glue records, MUST be included
    ///       unless excluded by a subsequent rule.
    ///
    ///    *  Occluded data ([RFC5936], Section 3.5) MUST be included.
    ///
    ///    *  If there are duplicate RRs with equal owner, class, type, and
    ///       RDATA, only one instance is included ([RFC4034], Section 6.3) and
    ///       the duplicates MUST be omitted.
    ///
    ///    *  The placeholder apex ZONEMD RR(s) MUST NOT be included.
    ///
    ///    *  If the zone is signed, DNSSEC RRs MUST be included, except:
    ///
    ///    *  The RRSIG covering the apex ZONEMD RRset MUST NOT be included
    ///       because the RRSIG will be updated after all digests have been
    ///       calculated.
    ///
    /// 3.3.1.2.  SIMPLE Scheme Digest Calculation
    ///
    ///    A zone digest using the SIMPLE scheme is calculated by concatenating
    ///    all RRs in the zone, in the format and order described in
    ///    Section 3.3.1 subject to the inclusion/exclusion rules described in
    ///    Section 3.3.1.1, and then applying the chosen hash algorithm:
    ///
    ///    digest = hash( RR(1) | RR(2) | RR(3) | ... )
    ///
    ///    where "|" denotes concatenation.
    /// ```
    ///
    /// [RFC 8976]: https://www.rfc-editor.org/rfc/rfc8976.html
    /// [RFC 4034]: https://www.rfc-editor.org/rfc/rfc4034.html
    fn create_zonemd_digest_simple(
        apex: &StoredName,
        records: &SortedRecords<StoredName, StoredRecordData, MultiThreadedSorter>,
        algorithm: ZonemdAlgorithm,
    ) -> Result<digest::Digest, Error> {
        // TODO: optimize by using multiple digest'ers at once, instead of
        // looping over the whole zone per digest algorithm.
        let mut buf: Vec<u8> = Vec::new();

        let mut ctx = match algorithm {
            ZonemdAlgorithm::SHA384 => digest::Context::new(&digest::SHA384),
            ZonemdAlgorithm::SHA512 => digest::Context::new(&digest::SHA512),
            _ => {
                // This should be caught by the argument parsing, but in case...
                return Err("unsupported zonemd hash algorithm".into());
            }
        };

        for owner_rr in records.owner_rrs() {
            if !owner_rr.is_in_zone(apex) {
                continue;
            }

            // From RFC 8976:
            // ```text
            //  *  All records in the zone, including glue records, MUST be included
            //     unless excluded by a subsequent rule.
            //  *  Occluded data ([RFC5936], Section 3.5) MUST be included.
            //  *  If there are duplicate RRs with equal owner, class, type, and
            //     RDATA, only one instance is included ([RFC4034], Section 6.3) and
            //     the duplicates MUST be omitted.
            //  *  The placeholder apex ZONEMD RR(s) MUST NOT be included.
            //  *  If the zone is signed, DNSSEC RRs MUST be included, except:
            //  *  The RRSIG covering the apex ZONEMD RRset MUST NOT be included
            //     because the RRSIG will be updated after all digests have been
            //     calculated.
            // ```
            // The first three rules are currently implemented by the SortedRecords type.
            for record in owner_rr.records() {
                buf.clear();
                if record.rtype() == Rtype::ZONEMD && record.owner() == apex {
                    // Skip placeholder ZONEMD at apex
                    continue;
                } else if record.rtype() == Rtype::RRSIG && record.owner() == apex {
                    // Skip RRSIG for ZONEMD at apex
                    if let ZoneRecordData::Rrsig(rrsig) = record.data() {
                        if rrsig.type_covered() == Rtype::ZONEMD {
                            continue;
                        }
                    };
                }

                with_infallible(|| record.compose_canonical(&mut buf));
                ctx.update(&buf);
            }
        }

        Ok(ctx.finish())
    }

    fn replace_apex_zonemd_with_placeholder(
        records: &mut SortedRecords<
            StoredName,
            ZoneRecordData<Bytes, StoredName>,
            MultiThreadedSorter,
        >,
        apex: &StoredName,
        zone_class: Class,
        soa_serial: Serial,
        ttl: Ttl,
    ) {
        // Remove existing ZONEMD RRs at apex for any class (it's class independent).
        let _ = records.remove_all_by_name_class_rtype(apex, None, Some(Rtype::ZONEMD));

        // Insert a single placeholder ZONEMD at apex for creating the
        // correct NSEC(3) bitmap (the ZONEMD RR will be replaced later).
        let placeholder_zonemd = ZoneRecordData::Zonemd(Zonemd::new(
            soa_serial,
            ZonemdScheme::from_int(0),
            ZonemdAlgorithm::from_int(0),
            Bytes::default(),
        ));
        let _ = records.insert(Record::new(
            apex.clone(),
            zone_class,
            ttl,
            placeholder_zonemd,
        ));
    }

    fn create_zonemd_digest_and_records(
        records: &SortedRecords<StoredName, ZoneRecordData<Bytes, StoredName>, MultiThreadedSorter>,
        apex: &StoredName,
        zone_class: Class,
        zonemd: &HashSet<ZonemdTuple>,
        soa_serial: Serial,
        ttl: Ttl,
    ) -> Result<Vec<Record<StoredName, StoredRecordData>>, Error> {
        let mut zonemd_rrs = Vec::new();

        for z in zonemd {
            // For now, only the SIMPLE scheme for ZONEMD is defined
            if z.0 != ZonemdScheme::SIMPLE {
                return Err("unsupported zonemd scheme (only SIMPLE is supported)".into());
            }
            let digest = Self::create_zonemd_digest_simple(apex, records, z.1)?;

            // Create actual ZONEMD RR
            let tmp_zrr = ZoneRecordData::Zonemd(Zonemd::new(
                soa_serial,
                z.0,
                z.1,
                Bytes::copy_from_slice(digest.as_ref()),
            ));
            zonemd_rrs.push(Record::new(apex.clone(), zone_class, ttl, tmp_zrr));
        }

        Ok(zonemd_rrs)
    }

    fn update_zonemd_rrsig(
        apex: &StoredName,
        records: &mut SortedRecords<StoredName, StoredRecordData, MultiThreadedSorter>,
        keys: &[&SigningKey<Bytes, KeyPair>],
        zonemd_rrs: &[Record<StoredName, StoredRecordData>],
        inception: Timestamp,
        expiration: Timestamp,
    ) -> Result<(), SigningError> {
        if !zonemd_rrs.is_empty() {
            let zonemd_rrset =
                Rrset::new(zonemd_rrs).expect("zonemd_rrs is not empty so new should not fail");
            let mut new_rrsig_recs = zonemd_rrset.sign(apex, keys, inception, expiration)?;
            records.update_data(|rr| {
                matches!(rr.data(), ZoneRecordData::Rrsig(rrsig) if rr.owner() == apex && rrsig.type_covered() == Rtype::ZONEMD)
            }, new_rrsig_recs.pop().unwrap().into_data().into());
        }

        Ok(())
    }
}

fn next_owner_hash_to_name(next_owner_hash_hex: &str, apex: &StoredName) -> Result<StoredName, ()> {
    let mut builder = NameBuilder::new_bytes();
    builder
        .append_chars(next_owner_hash_hex.chars())
        .map_err(|_| ())?;
    let next_owner_name = builder.append_origin(apex).map_err(|_| ())?;
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
    /// Neither hash or sign zone records (e.g. when just using ZONEMD).
    None,
}

//------------ ZonemdTuple ---------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
struct ZonemdTuple(ZonemdScheme, ZonemdAlgorithm);

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

/// Support for RTYPE specific zonefile comment generation.
///
/// Intended to be used to enable behaviour to be matched to that of the LDNS
/// `ldns_rr2buffer_str_fmt()` function.
trait Commented<T> {
    fn comment<W: fmt::Write>(
        &self,
        writer: &mut W,
        record: &Record<StoredName, ZoneRecordData<Bytes, StoredName>>,
        metadata: T,
    ) -> Result<(), fmt::Error>;
}

impl Commented<()> for Dnskey<Bytes> {
    fn comment<W: fmt::Write>(
        &self,
        writer: &mut W,
        _record: &Record<StoredName, ZoneRecordData<Bytes, StoredName>>,
        _metadata: (),
    ) -> Result<(), fmt::Error> {
        writer.write_fmt(format_args!(" ;{{id = {}", self.key_tag()))?;
        if self.is_secure_entry_point() {
            writer.write_str(" (ksk)")?;
        } else if self.is_zone_key() {
            writer.write_str(" (zsk)")?;
        }
        // What do we do if key_size fails. Currently we have to return a
        // fmt::Error. Just return default and hope that we only get keys
        // with algorithms that are supported.
        let key_size = self.key_size().map_err(|_| fmt::Error)?;
        writer.write_fmt(format_args!(", size = {key_size}b}}"))
    }
}

#[derive(Copy, Clone)]
struct Nsec3CommentState<'a> {
    hashes: Option<&'a Nsec3HashMap>,
    apex: &'a StoredName,
}

impl<'b, O: AsRef<[u8]>> Commented<Nsec3CommentState<'b>> for Nsec3<O> {
    fn comment<'a, W: fmt::Write>(
        &self,
        writer: &mut W,
        record: &'a Record<StoredName, ZoneRecordData<Bytes, StoredName>>,
        state: Nsec3CommentState<'b>,
    ) -> Result<(), fmt::Error> {
        // For an existing NSEC3 chain that we didn't generate ourselves but
        // left intact, still output flags info, but not the from/to owner as
        // we didn't generate the hash mappings.
        writer.write_str("  ;{ flags: ")?;

        if self.opt_out() {
            writer.write_str("optout")?;
        } else {
            writer.write_str("-")?;
        }

        if let Some(hashes) = state.hashes {
            let next_owner_hash_hex = format!("{}", self.next_owner());
            let next_owner_name = next_owner_hash_to_name(&next_owner_hash_hex, state.apex);

            let from = hashes
                .get(record.owner())
                .map(|v| v.unhashed_owner_name.fmt_with_dot());

            let to = next_owner_name
                .ok()
                .and_then(|n| hashes.get(&n).map(|v| v.unhashed_owner_name.fmt_with_dot()));

            match (from, to) {
                (None, _) => writer.write_str(", from: <internal error>, to: <internal error>"),
                (Some(from), None) => writer.write_fmt(format_args!(
                    ", from: {from}, to: <unknown hash: {next_owner_hash_hex}>"
                )),
                (Some(from), Some(to)) => {
                    writer.write_fmt(format_args!(", from: {from}, to: {to}"))
                }
            }?;
        }

        writer.write_char('}')
    }
}

//------------ AnyOwnerRrsIter -----------------------------------------------

type OwnerRrsIterByValue<'a> =
    std::slice::Iter<'a, OwnerRrs<'a, StoredName, ZoneRecordData<Bytes, StoredName>>>;
type OwnerRrsIterByRef<'a> = RecordsIter<'a, StoredName, ZoneRecordData<Bytes, StoredName>>;

/// An iterator over a collection of [`OwnerRrs`], whether by reference or not.
enum AnyOwnerRrsIter<'a> {
    VecIter(OwnerRrsIterByValue<'a>),
    OwnerRrsIter(OwnerRrsIterByRef<'a>),
}

impl<'a> Iterator for AnyOwnerRrsIter<'a>
where
    OwnerRrs<'a, StoredName, ZoneRecordData<Bytes, StoredName>>: Clone,
{
    type Item = OwnerRrs<'a, StoredName, ZoneRecordData<Bytes, StoredName>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            AnyOwnerRrsIter::VecIter(it) => it.next().cloned(),
            AnyOwnerRrsIter::OwnerRrsIter(it) => it.next(),
        }
    }
}

//--- From<std::slice::Iter<'a, OwnerRrs<'a, N, D>>>

impl<'a> From<std::slice::Iter<'a, OwnerRrs<'a, StoredName, ZoneRecordData<Bytes, StoredName>>>>
    for AnyOwnerRrsIter<'a>
{
    fn from(
        iter: std::slice::Iter<'a, OwnerRrs<'a, StoredName, ZoneRecordData<Bytes, StoredName>>>,
    ) -> Self {
        Self::VecIter(iter)
    }
}

//--- From<RecordsIter<'a, N, D>>

impl<'a> From<RecordsIter<'a, StoredName, ZoneRecordData<Bytes, StoredName>>>
    for AnyOwnerRrsIter<'a>
{
    fn from(iter: RecordsIter<'a, StoredName, ZoneRecordData<Bytes, StoredName>>) -> Self {
        Self::OwnerRrsIter(iter)
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

//------------ YyyyMmDdHhMMSsRrsig -------------------------------------------

/// A RFC 4034 section 3.2 YYYYMMDDHHmmSS presentable RRSIG wrapper.
///
/// This wrapper type provides an alternate implementation of [`ZonefileFmt`]
/// to the default implemented in `domain` such that RRSIG inception and
/// expiration timestamps are rendered in RFC 4034 3.2 YYYYMMDDHHmmSS format
/// instead of seconds since 1 January 1970 00:00:00 UTC format.
struct YyyyMmDdHhMMSsRrsig<'a, O, N>(&'a Rrsig<O, N>);

impl<O: AsRef<[u8]>, N: ToName> ZonefileFmt for YyyyMmDdHhMMSsRrsig<'_, O, N> {
    fn fmt(&self, p: &mut impl Formatter) -> zonefile_fmt::Result {
        #[allow(non_snake_case)]
        fn to_YYYYMMDDHHmmSS(ts: &Timestamp) -> impl Display {
            jiff::Timestamp::from_second(ts.into_int().into())
                .unwrap()
                .strftime("%Y%m%d%H%M%S")
        }

        // This block of code was copied from the `domain` crate impl of
        // `Zonefilefmt` for domain::rdata::Rrsig. Ideally we wouldn't have to
        // copy it like this but at the time of writing `domain` doesn't
        // provide a way to override the rendering of RRSIG timestamps alone
        // nor provide alternate renderings itself. For more information see
        // https://github.com/NLnetLabs/domain/issues/467.
        p.block(|p| {
            let expiration = to_YYYYMMDDHHmmSS(&self.0.expiration());
            let inception = to_YYYYMMDDHHmmSS(&self.0.inception());
            p.write_show(self.0.type_covered())?;
            p.write_show(self.0.algorithm())?;
            p.write_token(self.0.labels())?;
            p.write_comment("labels")?;
            p.write_show(self.0.original_ttl())?;
            p.write_comment("original ttl")?;
            p.write_token(expiration)?;
            p.write_comment("expiration")?;
            p.write_token(inception)?;
            p.write_comment("inception")?;
            p.write_token(self.0.key_tag())?;
            p.write_comment("key tag")?;
            p.write_token(self.0.signer_name().fmt_with_dot())?;
            p.write_comment("signer name")?;
            p.write_token(base64::encode_display(&self.0.signature()))
        })
    }
}

impl<O, N> RecordData for YyyyMmDdHhMMSsRrsig<'_, O, N> {
    fn rtype(&self) -> Rtype {
        Rtype::RRSIG
    }
}

//-------------- Nsec3HashMap ------------------------------------------------

#[derive(Debug)]
struct Nsec3HashInfo {
    unhashed_owner_name: StoredName,
    is_empty_non_terminal: bool,
}

impl Nsec3HashInfo {
    fn new(unhashed_owner_name: StoredName, is_empty_non_terminal: bool) -> Self {
        Self {
            unhashed_owner_name,
            is_empty_non_terminal,
        }
    }

    fn name(&self) -> &StoredName {
        &self.unhashed_owner_name
    }
}

struct Nsec3HashMap {
    /// A record of hashed owner names to unhashed owner names.
    ///
    /// We also record if the unhashed owner name was an empty non-terminal or
    /// not.
    hashes_by_unhashed_owner: HashMap<StoredName, Nsec3HashInfo>,
}

impl Nsec3HashMap {
    fn new() -> Self {
        Self {
            hashes_by_unhashed_owner: HashMap::new(),
        }
    }

    fn get_if_ent(&self, k: &StoredName) -> Option<&StoredName> {
        self.hashes_by_unhashed_owner
            .get(k)
            .filter(|v| v.is_empty_non_terminal)
            .map(|v| &v.unhashed_owner_name)
    }
}

impl std::ops::Deref for Nsec3HashMap {
    type Target = HashMap<StoredName, Nsec3HashInfo>;

    fn deref(&self) -> &Self::Target {
        &self.hashes_by_unhashed_owner
    }
}

//------------ TestableTimestamp ---------------------------------------------

struct TestableTimestamp;

impl TestableTimestamp {
    fn now() -> Timestamp {
        if cfg!(test) {
            // Don't use Timestamp::now() because that will use the actual
            // SystemTime::now() even in tests which, if there are any
            // unexpected delays as can happen in a CI environment, can cause
            // two nearby calls to Timestamp::now() to return a different
            // number of seconds since the epoch which will thus fail to
            // compare as equal in a test. Ironically the underlying Timestamp
            // implementation supports mocking of time, but the test flag is
            // not set by Cargo for dependencies, only for our own code, so we
            // have to manually construct a predictable Timestamp ourselves.
            Timestamp::from(0)
        } else {
            Timestamp::now()
        }
    }
}

//------------ Tests ---------------------------------------------------------

// TODO: Maybe resolve the Timestamp issue differently? When running the tests
// and the base struct get's constructed at say time "12:30:29" and the command
// parsing for an assertion get's executed at "12:30:30", then the timestamps
// don't match and the tests fails. This creates a flaky test without actual
// errors in the code. Right now it is solved by recreating the expiration and
// inception fields during the assertion. However, this means we need to
// remember adding that for every assertion.

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Write;
    use std::ops::Add;
    use std::path::PathBuf;
    use std::str::FromStr;

    use domain::base::iana::{Nsec3HashAlgorithm, ZonemdAlgorithm, ZonemdScheme};
    use domain::base::Name;
    use domain::rdata::dnssec::Timestamp;
    use domain::rdata::nsec3::Nsec3Salt;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    use crate::commands::signzone::{TestableTimestamp, ZonemdTuple, FOUR_WEEKS};
    use crate::commands::Command;
    use crate::env::fake::FakeCmd;

    use super::SignZone;
    use crate::env::Env;

    #[track_caller]
    fn parse(args: FakeCmd) -> SignZone {
        let res = args.parse().unwrap();
        let Command::SignZone(x) = res.command else {
            panic!("Not a SignZone!");
        };
        x
    }

    #[test]
    fn dnst_parse_failures() {
        let cmd = FakeCmd::new(["dnst", "signzone"]);

        cmd.parse().unwrap_err();
        // Missing keys
        cmd.args(["example.org.zone"]).parse().unwrap_err();
        // Missing ZONEMD arguments
        cmd.args(["-Z", "example.org.zone"]).parse().unwrap_err();

        // Invalid ZONEMD arguments
        cmd.args(["-z", "3", "example.org.zone", "anykey"])
            .parse()
            .unwrap_err();
        cmd.args(["-z", "0:0", "example.org.zone", "anykey"])
            .parse()
            .unwrap_err();

        // Invalid NSEC3 arguments
        cmd.args(["-na", "MD5", "example.org.zone", "anykey"])
            .parse()
            .unwrap_err();
        cmd.args(["-ns", "NOBASE64", "example.org.zone", "anykey"])
            .parse()
            .unwrap_err();
        // Conflicting NSEC3 optout options
        cmd.args(["-nPp", "example.org.zone", "anykey"])
            .parse()
            .unwrap_err();
    }

    #[test]
    fn dnst_parse_successes() {
        let cmd = FakeCmd::new(["dnst", "signzone"]);

        let expiration = TestableTimestamp::now().into_int().add(FOUR_WEEKS).into();
        let inception = TestableTimestamp::now();

        let base = SignZone {
            extra_comments: false,
            do_not_add_keys_to_zone: false,
            expiration,
            out_file: None,
            inception,
            origin: None,
            set_soa_serial_to_epoch_time: false,
            zonemd: Vec::new(),
            allow_zonemd_without_signing: false,
            sign_dnskeys_with_all_keys: false,
            use_nsec3: false,
            sign_with_every_unique_algorithm: false,
            algorithm: Nsec3HashAlgorithm::SHA1,
            iterations: 0,
            salt: Nsec3Salt::empty(),
            nsec3_opt_out_flags_only: false,
            nsec3_opt_out: false,
            hash_only: false,
            use_yyyymmddhhmmss_rrsig_format: false,
            preceed_zone_with_hash_list: false,
            order_rrsigs_after_the_rtype_they_cover: false,
            order_nsec3_rrs_by_unhashed_owner_name: false,
            zonefile_path: PathBuf::from("example.org.zone"),
            key_paths: Vec::from([PathBuf::from("anykey")]),
            invoked_as_ldns: false,
        };

        // Check the defaults
        assert_eq!(parse(cmd.args(["example.org.zone", "anykey"])), base);

        // The switches (TODO: missing -A and -U)
        assert_eq!(
            parse(cmd.args(["-bdunp", "example.org.zone", "anykey"])),
            SignZone {
                extra_comments: true,
                do_not_add_keys_to_zone: true,
                set_soa_serial_to_epoch_time: true,
                use_nsec3: true,
                nsec3_opt_out_flags_only: true,
                order_rrsigs_after_the_rtype_they_cover: true,
                order_nsec3_rrs_by_unhashed_owner_name: true,
                expiration,
                inception,
                ..base.clone()
            }
        );
        assert_eq!(
            parse(cmd.args(["-H", "example.org.zone"])),
            SignZone {
                hash_only: true,
                key_paths: Vec::new(),
                expiration,
                inception,
                ..base.clone()
            }
        );

        // ZONEMD arguments
        assert_eq!(
            parse(cmd.args(["-z", "SIMPLE:SHA512", "example.org.zone", "anykey"])),
            SignZone {
                zonemd: Vec::from([ZonemdTuple(ZonemdScheme::SIMPLE, ZonemdAlgorithm::SHA512)]),
                expiration,
                inception,
                ..base.clone()
            }
        );
        assert_eq!(
            parse(cmd.args(["-z", "simple:sha512", "example.org.zone", "anykey"])),
            SignZone {
                zonemd: Vec::from([ZonemdTuple(ZonemdScheme::SIMPLE, ZonemdAlgorithm::SHA512)]),
                expiration,
                inception,
                ..base.clone()
            }
        );
        assert_eq!(
            parse(cmd.args(["-z", "sha512", "example.org.zone", "anykey"])),
            SignZone {
                zonemd: Vec::from([ZonemdTuple(ZonemdScheme::SIMPLE, ZonemdAlgorithm::SHA512)]),
                expiration,
                inception,
                ..base.clone()
            }
        );

        // NSEC3 arguments
        assert_eq!(
            parse(cmd.args([
                "-n",
                "-s",
                "BABABA",
                "-t",
                "15",
                "example.org.zone",
                "anykey"
            ])),
            SignZone {
                use_nsec3: true,
                salt: Nsec3Salt::from_str("BABABA").unwrap(),
                iterations: 15,
                expiration,
                inception,
                ..base.clone()
            }
        );

        // Timestamps
        assert_eq!(
            parse(cmd.args([
                "-i",
                "20240101020202",
                "-e",
                "20240101050505",
                "example.org.zone",
                "anykey"
            ])),
            SignZone {
                expiration: Timestamp::from_str("20240101050505").unwrap(),
                inception: Timestamp::from_str("20240101020202").unwrap(),
                ..base.clone()
            }
        );

        // Output file
        assert_eq!(
            parse(cmd.args(["-f-", "example.org.zone", "anykey"])),
            SignZone {
                out_file: Some(PathBuf::from("-")),
                expiration,
                inception,
                ..base.clone()
            }
        );
        assert_eq!(
            parse(cmd.args(["-f", "output", "example.org.zone", "anykey"])),
            SignZone {
                out_file: Some(PathBuf::from("output")),
                expiration,
                inception,
                ..base.clone()
            }
        );

        // Origin
        assert_eq!(
            parse(cmd.args(["-o", "origin.test", "example.org.zone", "anykey"])),
            SignZone {
                origin: Some(Name::from_str("origin.test.").unwrap()),
                expiration,
                inception,
                ..base.clone()
            }
        );
    }

    #[test]
    fn ldns_parse_failures() {
        let cmd = FakeCmd::new(["ldns-signzone"]);

        cmd.parse().unwrap_err();
        // Missing keys
        cmd.args(["example.org.zone"]).parse().unwrap_err();

        // Invalid ZONEMD arguments
        cmd.args(["-z", "3", "example.org.zone", "anykey"])
            .parse()
            .unwrap_err();
        cmd.args(["-z", "0:0", "example.org.zone", "anykey"])
            .parse()
            .unwrap_err();

        // Invalid NSEC3 arguments
        cmd.args(["-na", "MD5", "example.org.zone", "anykey"])
            .parse()
            .unwrap_err();
        cmd.args(["-ns", "NOBASE64", "example.org.zone", "anykey"])
            .parse()
            .unwrap_err();
    }

    #[test]
    fn ldns_parse_successes() {
        let cmd = FakeCmd::new(["ldns-signzone"]);

        let expiration = TestableTimestamp::now().into_int().add(FOUR_WEEKS).into();
        let inception = TestableTimestamp::now();

        let base = SignZone {
            extra_comments: false,
            do_not_add_keys_to_zone: false,
            expiration,
            out_file: None,
            inception,
            origin: None,
            set_soa_serial_to_epoch_time: false,
            zonemd: Vec::new(),
            allow_zonemd_without_signing: false,
            sign_dnskeys_with_all_keys: false,
            sign_with_every_unique_algorithm: false,
            use_nsec3: false,
            algorithm: Nsec3HashAlgorithm::SHA1,
            iterations: 1,
            salt: Nsec3Salt::empty(),
            nsec3_opt_out_flags_only: false,
            nsec3_opt_out: false,
            hash_only: false,
            use_yyyymmddhhmmss_rrsig_format: true,
            preceed_zone_with_hash_list: false,
            order_rrsigs_after_the_rtype_they_cover: false,
            order_nsec3_rrs_by_unhashed_owner_name: false,
            zonefile_path: PathBuf::from("example.org.zone"),
            key_paths: Vec::from([PathBuf::from("anykey")]),
            invoked_as_ldns: true,
        };

        // Check the defaults
        assert_eq!(parse(cmd.args(["example.org.zone", "anykey"])), base);

        // The switches (TODO: missing -A and -U)
        assert_eq!(
            parse(cmd.args(["-bdunp", "example.org.zone", "anykey"])),
            SignZone {
                extra_comments: true,
                do_not_add_keys_to_zone: true,
                set_soa_serial_to_epoch_time: true,
                use_nsec3: true,
                nsec3_opt_out_flags_only: true,
                order_rrsigs_after_the_rtype_they_cover: true,
                order_nsec3_rrs_by_unhashed_owner_name: true,
                expiration,
                inception,
                ..base.clone()
            }
        );

        // ZONEMD arguments
        assert_eq!(
            parse(cmd.args(["-Z", "example.org.zone", "anykey"])),
            SignZone {
                allow_zonemd_without_signing: true,
                expiration,
                inception,
                ..base.clone()
            }
        );
        assert_eq!(
            parse(cmd.args(["-z", "SIMPLE:SHA512", "example.org.zone", "anykey"])),
            SignZone {
                zonemd: Vec::from([ZonemdTuple(ZonemdScheme::SIMPLE, ZonemdAlgorithm::SHA512)]),
                expiration,
                inception,
                ..base.clone()
            }
        );
        assert_eq!(
            parse(cmd.args(["-z", "simple:sha512", "example.org.zone", "anykey"])),
            SignZone {
                zonemd: Vec::from([ZonemdTuple(ZonemdScheme::SIMPLE, ZonemdAlgorithm::SHA512)]),
                expiration,
                inception,
                ..base.clone()
            }
        );
        assert_eq!(
            parse(cmd.args(["-z", "sha512", "example.org.zone", "anykey"])),
            SignZone {
                zonemd: Vec::from([ZonemdTuple(ZonemdScheme::SIMPLE, ZonemdAlgorithm::SHA512)]),
                expiration,
                inception,
                ..base.clone()
            }
        );
        assert_eq!(
            parse(cmd.args(["-z", "1", "example.org.zone", "anykey"])),
            SignZone {
                zonemd: Vec::from([ZonemdTuple(ZonemdScheme::SIMPLE, ZonemdAlgorithm::SHA384)]),
                expiration,
                inception,
                ..base.clone()
            }
        );

        // NSEC3 arguments
        assert_eq!(
            parse(cmd.args([
                "-n",
                "-s",
                "BABABA",
                "-t",
                "15",
                "example.org.zone",
                "anykey"
            ])),
            SignZone {
                use_nsec3: true,
                salt: Nsec3Salt::from_str("BABABA").unwrap(),
                iterations: 15,
                expiration,
                inception,
                ..base.clone()
            }
        );

        // Timestamps
        assert_eq!(
            parse(cmd.args([
                "example.org.zone",
                "-i",
                "20240101020202",
                "-e",
                "20240101050505",
                "anykey"
            ])),
            SignZone {
                expiration: Timestamp::from_str("20240101050505").unwrap(),
                inception: Timestamp::from_str("20240101020202").unwrap(),
                ..base.clone()
            }
        );

        // Output file
        assert_eq!(
            parse(cmd.args(["-f-", "example.org.zone", "anykey"])),
            SignZone {
                out_file: Some(PathBuf::from("-")),
                expiration,
                inception,
                ..base.clone()
            }
        );
        assert_eq!(
            parse(cmd.args(["-f", "output", "example.org.zone", "anykey"])),
            SignZone {
                out_file: Some(PathBuf::from("output")),
                expiration,
                inception,
                ..base.clone()
            }
        );

        // Origin
        assert_eq!(
            parse(cmd.args(["-o", "origin.test", "example.org.zone", "anykey"])),
            SignZone {
                origin: Some(Name::from_str("origin.test.").unwrap()),
                expiration,
                inception,
                ..base.clone()
            }
        );

        // Version
        assert!(matches!(
            cmd.args(["-v"]).parse().unwrap().command,
            Command::Report(_)
        ));
    }

    #[test]
    fn do_not_add_keys_to_zone() {
        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc8976-simple");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+31967");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+38353");

        let res1 = FakeCmd::new([
            "dnst",
            "signzone",
            "-oexample",
            "-d",
            "-f",
            "-",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res1.stderr, "");
        assert_eq!(
            res1.stdout,
            "example.\t86400\tIN\tSOA\tns1.example. admin.example. 2018031900 1800 900 604800 86400\n\
            example.\t86400\tIN\tNS\tns1.example.\n\
            example.\t86400\tIN\tNS\tns2.example.\n\
            example.\t86400\tIN\tRRSIG\tNS 8 1 86400 2419200 0 38353 example. Nf1AJOIse+BKTnng70iYOSazSo/PLZA3SAld/oOGqxE4g5ZTmfVa5ikHP8C+jBNaOW/nXNQJVc446pr1cI5kWVbKLbuPWKv33IygLVsOCKz8m8HIgihKxIcd0Wbzvsbgy4963wAo7ypde5mZ8+XDrLDNpcW8HKQMccZX1w63HF8=\n\
            example.\t86400\tIN\tRRSIG\tSOA 8 1 86400 2419200 0 38353 example. GxHcCYArh7wmh/dpx95MVtAkc1soNSzw9OBmkvkG8gQiUwZSt5YJq8ImjRlzMQ+UQ/JfR6VGqpHdq/ScVgqOsXOYicn2430h4h1SebtWwwXnvkzWHCwSxVVInufQIRgZHfhhpNyjBxrSBwh2Y+qxnH2JYcrELQ28t0If7fo+tDM=\n\
            example.\t86400\tIN\tRRSIG\tNSEC 8 1 86400 2419200 0 38353 example. ZooZy2FXylWuoy41yJt0XEFlllQNeuqnkb8of2HryRlDNbRwqARGzJxOUgCxJ6387w01lAiQJ3kMTHzz2U7FVwRh+mrtDUQ3SpIaH4iKNKyRUMAKJrrn2xhBtPg49bR/sHDfcIjRK67ktieYLKZqnPh636QaZFBjAk5ZXoG4g/8=\n\
            example.\t86400\tIN\tNSEC\tns1.example. NS SOA RRSIG NSEC DNSKEY\n\
            ns1.example.\t3600\tIN\tA\t203.0.113.63\n\
            ns1.example.\t3600\tIN\tRRSIG\tA 8 2 3600 2419200 0 38353 example. BXRmu3njAbizxTX49isTcab9HR495sOrTYzq5nU71aEbY89lz8rdMhxLA6NYX0zIYJPHdkI7yf8/aHf2VsAjz+p2NQ7qaODtm5oFpIm2O9JiBqTrqj5P4fK9qN+pJmKsJAXupphXhFKmsQkWJdYCoHq/wXjq1Hp7xICdd30XsUY=\n\
            ns1.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 2419200 0 38353 example. G1ohioxllf2ZTVt4XrgKkCQ0JhxNZn4ABecihoHVVOpUNBlk4aWrdOtWTKt81dwbnXONhttL3sf6mWJJXJFe1yAxZAU3LA1wHlc+V50xjbO2vNW6oSQ9CjTBZW9/aih5aUtG4uTroa8din5eaUn1hL2DTOfG7bKKNfkH5wpU9vs=\n\
            ns1.example.\t86400\tIN\tNSEC\tns2.example. A RRSIG NSEC\n\
            ns2.example.\t3600\tIN\tAAAA\t2001:db8::63\n\
            ns2.example.\t3600\tIN\tRRSIG\tAAAA 8 2 3600 2419200 0 38353 example. X566NNfPtSpPXdOfJT0XaMPcTHSvBKThjaCvodojDW6OLKfZJyvZOjzYcvMMLDcHkRkNak6M534Zn++Hrym3n2hl3FS/A1hGLMZ2MxlQxVwya4Xg9zE3IEmlRGlVFjVFrEK1Me8sfwyg+eM7+8Wq3qOtxyK/xb4eL8lmgB/kfm4=\n\
            ns2.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 2419200 0 38353 example. cM6oDa/FElsY5XuBa7LXwn35w7t2Dckya+9EVr3oxqKWrVCOemFXUCQkFv/DX2NA9IY1ijJkvDN+I2lg7XXhokFc78CpJeL/rr7EbxKQulKEy64u/Skd4ZuedLD6pQw21oIqFTnJ/nj1e3DXoWAEk2rGflexZ6E9NrxJrXYmTrA=\n\
            ns2.example.\t86400\tIN\tNSEC\texample. AAAA RRSIG NSEC\n"
        );
        assert_eq!(res1.exit_code, 0);
    }

    #[test]
    fn zonemd_digest_and_replacing_existing_at_apex() {
        let dir = run_setup();

        let res1 = FakeCmd::new([
            "dnst",
            "signzone",
            "-Z",
            "-z",
            "SIMPLE:SHA384",
            "-f",
            "-",
            "zonemd1_example.org.zone",
        ])
        .cwd(&dir)
        .run();

        assert_eq!(res1.exit_code, 0);
        assert_eq!(
            res1.stdout,
            "example.org.\t240\tIN\tSOA\texample.net. hostmaster.example.net. 1234567890 28800 7200 604800 240\n\
            example.org.\t240\tIN\tA\t128.140.76.106\n\
            example.org.\t240\tIN\tNS\texample.net.\n\
            example.org.\t240\tIN\tZONEMD\t1234567890 1 1 D2D125EE8B4DDAD944FD7EE437908A5D4D5A7DB7C2F948C5A051146FC75D124666033DF7D1BA1653CF490E89F9A454F3\n\
            *.example.org.\t240\tIN\tA\t1.2.3.4\n\
            deleg.example.org.\t240\tIN\tNS\texample.com.\n\
            occluded.deleg.example.org.\t240\tIN\tA\t1.2.3.4\n"
        );
        assert_eq!(res1.stderr, "");

        let res2 = FakeCmd::new([
            "dnst",
            "signzone",
            "-Z",
            "-z",
            "SIMPLE:SHA384",
            "-f",
            "-",
            "zonemd1_example.org.zone",
        ])
        .cwd(&dir)
        .run();

        assert_eq!(res2.exit_code, 0);
        assert_eq!(res2.stdout, res1.stdout);
        assert_eq!(res2.stderr, "");
    }

    #[test]
    fn zonemd_and_sign() {
        let dir = run_setup();

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-z",
            "1:1",
            "-f",
            "-",
            "-e",
            "20241127162422",
            "-i",
            "20241127162422",
            "zonemd1_example.org.zone",
            "ksk1",
        ])
        .cwd(&dir)
        .run();

        assert_eq!(res.exit_code, 0);
        assert_eq!(
            res.stdout,
            "example.org.\t240\tIN\tSOA\texample.net. hostmaster.example.net. 1234567890 28800 7200 604800 240\n\
            example.org.\t240\tIN\tA\t128.140.76.106\n\
            example.org.\t240\tIN\tNS\texample.net.\n\
            example.org.\t240\tIN\tRRSIG\tA 15 2 240 1732724662 1732724662 38873 example.org. dVrR1Ay58L3cDaRIial45keWp/X8roeirciEqJqVZcqWO4AkSaILqDYIpfNRf3i9WvDzio0BLZT5K4r2krmyCA==\n\
            example.org.\t240\tIN\tRRSIG\tNS 15 2 240 1732724662 1732724662 38873 example.org. JJDRuXMuv9yiJAFN+15/7DBbaBHepA20QxLruqrjSJZsgzRcPb1UTyGozlsq9BdCq3oxZm8lea5DcIi2tyGVDQ==\n\
            example.org.\t240\tIN\tRRSIG\tSOA 15 2 240 1732724662 1732724662 38873 example.org. 2Jp7z/VMHlUvZoXApvsolX78ZzH9BmI8jznVHjagpmjOto/tAb1bL7AaTcOG2Ihk+uSSvDmIExaax0dbtL8CAg==\n\
            example.org.\t240\tIN\tRRSIG\tNSEC 15 2 240 1732724662 1732724662 38873 example.org. bL1aldkxI/a0P9Oo3FUJfGspDchBs8B476AnKS4O5g43KZ5Oy+Xvb5UimyzFQ2f5gXL47cdt8EMmuy2iRhUpBg==\n\
            example.org.\t240\tIN\tRRSIG\tDNSKEY 15 2 240 1732724662 1732724662 38873 example.org. UPk13WDbN2MLjSwgV82084DrNUdJFmS9bthBw52X0rfiBMAvrQJJhSYbq72G5j11SFp2DnUyml8stScKJyMlCQ==\n\
            example.org.\t240\tIN\tRRSIG\tZONEMD 15 2 240 1732724662 1732724662 38873 example.org. f2VO/ROXqwgZdQNmTcu3Cc6zYbsFNRwiJsdYcfX1e+mdgIBt8PFsa5OOUy7VJHZnFD4/5Gq6n/6/FkWF/5iNDg==\n\
            example.org.\t240\tIN\tNSEC\t*.example.org. A NS SOA RRSIG NSEC DNSKEY ZONEMD\n\
            example.org.\t240\tIN\tDNSKEY\t257 3 15 6VdB0mk5qwjHWNC5TTOw1uHTzA0m3Xadg7aYVbcRn8Y=\n\
            example.org.\t240\tIN\tZONEMD\t1234567890 1 1 97FCF584F87A42EA94F7C0DE25F3BA581A48D5FC4C5F1DD0FB275B9634EFE68A268606B6AB92A5D95062AB563B58196A\n\
            *.example.org.\t240\tIN\tA\t1.2.3.4\n\
            *.example.org.\t240\tIN\tRRSIG\tA 15 2 240 1732724662 1732724662 38873 example.org. 1eLPyREltQqUClcAuT4SkqdWXL8D4C3K0mnotLv8d1x6kh/ARcac9l99ulLwtxvmJb+61+zv4vFgX35Yqbm1BA==\n\
            *.example.org.\t240\tIN\tRRSIG\tNSEC 15 2 240 1732724662 1732724662 38873 example.org. FgRwrOd36au9ijKnx3AxsyN5Ar4mwt4AALTye3/IqravMHa2pTTP8h0Z2GXgu3YPmP3RXpPTwza5960KwE8YCQ==\n\
            *.example.org.\t240\tIN\tNSEC\tdeleg.example.org. A RRSIG NSEC\n\
            deleg.example.org.\t240\tIN\tNS\texample.com.\n\
            deleg.example.org.\t240\tIN\tRRSIG\tNSEC 15 3 240 1732724662 1732724662 38873 example.org. m/j7UOa1SvFw0rz5pBXVWS62gX328rxveNeD+Gd7husNcvbYhW2rLLYfTCG6LNvUP4fG2rJ45OhY3g3Trx2iBQ==\n\
            deleg.example.org.\t240\tIN\tNSEC\texample.org. NS RRSIG NSEC\n\
            occluded.deleg.example.org.\t240\tIN\tA\t1.2.3.4\n\
            "
        );
        assert_eq!(res.stderr, "");
    }

    #[test]
    fn rfc_8976_zonemd_simple_example_zone() {
        let expected_zone = "example.\t86400\tIN\tSOA\tns1.example. admin.example. 2018031900 1800 900 604800 86400\n\
        example.\t86400\tIN\tNS\tns1.example.\n\
        example.\t86400\tIN\tNS\tns2.example.\n\
        example.\t86400\tIN\tZONEMD\t2018031900 1 1 C68090D90A7AED716BC459F9340E3D7C1370D4D24B7E2FC3A1DDC0B9A87153B9A9713B3C9AE5CC27777F98B8E730044C\n\
        ns1.example.\t3600\tIN\tA\t203.0.113.63\n\
        ns2.example.\t3600\tIN\tAAAA\t2001:db8::63\n\
        ";

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc8976-simple");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-oexample",
            "-f-",
            "-z1:1",
            "-Z",
            &zone_file_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn rfc_8976_zonemd_complex_example_zone() {
        let expected_zone = "example.\t86400\tIN\tSOA\tns1.example. admin.example. 2018031900 1800 900 604800 86400\n\
        example.\t86400\tIN\tNS\tns1.example.\n\
        example.\t86400\tIN\tNS\tns2.example.\n\
        example.\t86400\tIN\tZONEMD\t2018031900 1 1 A3B69BAD980A3504E1CFFCB0FD6397F93848071C93151F552AE2F6B1711D4BD2D8B39808226D7B9DB71E34B72077F8FE\n\
        *.example.\t777\tIN\tPTR\tdont-forget-about-wildcards.example.\n\
        duplicate.example.\t300\tIN\tTXT\t\"I must be digested just once\"\n\
        mail.example.\t3600\tIN\tMX\t10 Mail2.Example.\n\
        mail.example.\t3600\tIN\tMX\t20 MAIL1.example.\n\
        non-apex.example.\t900\tIN\tZONEMD\t2018031900 1 1 616C6C6F776564206275742069676E6F7265642E20616C6C6F776564206275742069676E6F7265642E20616C6C6F7765\n\
        ns1.example.\t3600\tIN\tA\t203.0.113.63\n\
        NS2.example.\t3600\tIN\tAAAA\t2001:db8::63\n\
        sortme.example.\t3600\tIN\tAAAA\t2001:db8::1:65\n\
        sortme.example.\t3600\tIN\tAAAA\t2001:db8::2:64\n\
        sortme.example.\t3600\tIN\tAAAA\t2001:db8::3:62\n\
        sortme.example.\t3600\tIN\tAAAA\t2001:db8::4:63\n\
        sortme.example.\t3600\tIN\tAAAA\t2001:db8::5:61\n\
        sub.example.\t7200\tIN\tNS\tns1.example.\n\
        occluded.sub.example.\t7200\tIN\tTXT\t\"I'm occluded but must be digested\"\n\
        UPPERCASE.example.\t3600\tIN\tTXT\t\"canonicalize uppercase owner names\"\n\
        foo.test.\t555\tIN\tTXT\t\"out-of-zone data must be excluded\"\n\
        ";

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc8976-complex");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-oexample",
            "-f-",
            "-z1:1",
            "-Z",
            &zone_file_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn rfc_8976_zonemd_example_zone_with_multiple_digests() {
        // The ZONEMD records in the input zone at the apex are stripped out
        // and replaced by ones we generate based on the `-z` arguments given.
        let expected_zone = "\
        example.\t86400\tIN\tSOA\tns1.example. admin.example. 2018031900 1800 900 604800 86400\n\
        example.\t86400\tIN\tNS\tns1.example.\n\
        example.\t86400\tIN\tNS\tns2.example.\n\
        example.\t86400\tIN\tZONEMD\t2018031900 1 1 62E6CF51B02E54B9B5F967D547CE43136792901F9F88E637493DAAF401C92C279DD10F0EDB1C56F8080211F8480EE306\n\
        example.\t86400\tIN\tZONEMD\t2018031900 1 2 08CFA1115C7B948C4163A901270395EA226A930CD2CBCF2FA9A5E6EB85F37C8A4E114D884E66F176EAB121CB02DB7D652E0CC4827E7A3204F166B47E5613FD27\n\
        ns1.example.\t3600\tIN\tA\t203.0.113.63\n\
        ns2.example.\t86400\tIN\tTXT\t\"This example has multiple digests\"\n\
        NS2.EXAMPLE.\t3600\tIN\tAAAA\t2001:db8::63\n\
        ";

        let zone_file_path =
            mk_test_data_abs_path_string("test-data/example.rfc8976-multiple-digests");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-oexample",
            "-f-",
            "-z1:1",
            "-z1:2",
            // "-z1:240", // Neither of these are supported by us currently
            // "-z240:1", // Neither of these are supported by us currently
            "-Z",
            &zone_file_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn rfc_8976_zonemd_the_uri_dot_arpa_zone() {
        let expected_zone = r###"uri.arpa.\t3600\tIN\tSOA\tsns.dns.icann.org. noc.dns.icann.org. 2018100702 10800 3600 1209600 3600
uri.arpa.\t3600\tIN\tRRSIG\tSOA 8 2 3600 20210217232440 20210120232440 36153 uri.arpa. qP8f0IqOT3VJn/ysxBCZC+yXdwW+z7wPB1O2SHnQn8B9b5B4F5jzN4UqJDJ6CNQdZYv7TMDO24sGk8OIT3kmzTMcEZZSdxD+y8Q160mI54fHN8XZVwKs1bByNtk6k5bUG7kUi9agbqe1GNkMJJk8acgeZzWPC/LsB90fOEhvYK1QgMBCqFEYHx9JybLCXvAvMbS3T0hizYLY5tDqgDmzuIE9KXR8J9UTsWuu/GmadtBNtG71fPq4rhlypnjMM5Tgo5ygHO1fYS6TmAapF3T6I4zVs9V++y7MNIYaVtFPZfhvuB3LFY6C8RNOB9HyFRldKkeqYFkHH7K6A0pghK7Y5Q==
uri.arpa.\t86400\tIN\tNS\ta.iana-servers.net.
uri.arpa.\t86400\tIN\tNS\tb.iana-servers.net.
uri.arpa.\t86400\tIN\tNS\tc.iana-servers.net.
uri.arpa.\t86400\tIN\tNS\tns2.lacnic.net.
uri.arpa.\t86400\tIN\tNS\tsec3.apnic.net.
uri.arpa.\t86400\tIN\tRRSIG\tNS 8 2 86400 20210217232440 20210120232440 36153 uri.arpa. Sd7Y2mhMmffhjFeX2j5rGAts+bGljJjOgMJVL8ksnW/pZWhzLDUQcugpQNIA4UxoAGBSBqS03LboYyItAIGPrbmHLqg9TmU5l9PFI8WX9CIIwk4Ym3OflXTTpZANlKevQzjmmraRkNjmcBvrZdcgUiATP7jBNECnsC2OyA7iPQUMNN+DhmXjO3ghXRv2Wc74pXoT0uAeSIrdgyieHse2icoePTDx+wzBDkyzw5yYzZMHmSRJBP4yuNR9sLbzoaL1JDBVdZ061YT4zl1YsLQ+htTizSzx6iPxjNJAZ8RAHWWTPAXZVqMSjm3vrzEzEgdOgMrCJVYV/yvmLBoA+Pq8Tw==
uri.arpa.\t600\tIN\tMX\t10 pechora.icann.org.
uri.arpa.\t600\tIN\tRRSIG\tMX 8 2 600 20210217232440 20210120232440 36153 uri.arpa. UfoDlqfS+xHmAoe9uu8suPAS6Hwl0pEGYjyWr7SV6tqszbOrpA4Juk1sygvuVSGjO9nEc5wLitSonY+NbHuWTLtbtj6i3A8xHD71a8IDMfEegrr6ZrTN0HRUJetB4w67p8ieI+Szgh0U7a52XzU0fvjD7cqFRqHIAG6DR5fY68t//ehZG+jcAbU+m26dc7EC+NC7yzklvEehCWknnFAqUEV9JzjOyhUj9GGWXxhgHBBS0QQcNLzUq+FwIq1Mr25tH0bUkjVrkpDDNqTDzRzr8SLfbW+ldgiowVapkt2lpfm+siy3GCuXaddB49WTBcAmKuip5V8WSV0hDKSl7Q2zNA==
uri.arpa.\t3600\tIN\tNSEC\tftp.uri.arpa. NS SOA MX RRSIG NSEC DNSKEY ZONEMD
uri.arpa.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20210217232440 20210120232440 36153 uri.arpa. EUBTH/YN3A4HIVyR2FJ0iIrR53xKE98swa7ViTNUIccjDUst2NedYJG8ei24mUNMID/Y4AXN/Npo/Y92PxTMtVd7w4fQ/lX3wADIvp49N21UPonq2J/IG4Y742+JReTz3zmQmAoMkvqTKys2asOPpkktllCGACv70VJd/Z9Am2kRlfkrss5xfSxLIVIE0lA1XXZQGbll93FLa74+lein60YtyWj5WZydoo4Kr/k0oT/TA7qjuzJ9OXcG+dff9HdYt7IKM5aRVA0tpZwDIZLn+uKZZilRLrUFfXxPLndFdnnXWsHy/Rue1YpaB2Lfg6gAAkU0Ken+D4u62izI8vIoJA==
uri.arpa.\t3600\tIN\tDNSKEY\t256 3 8 AwEAAbdA7hbl8YtfwjDxI1L06os3xkyehpGROhX8nLCwrwx3+veYbAWIdRahKN2SMSHrRtj8k7bRxJC5fhUweA5L8h4CDVGCOJhkOCni/O0xQ44MVT/bHF4WcCtAbThy8vlPj0xR0r0DkqEbuOsK+uJAJfgli5I5Im3VNB8RPBcfu42GR8ObDOLVxuDJ52A+ZGqH8H9VyGfuxtnjSVenkeQNQidwkfI6IWxrk1/H1G+Az/45yFDZGCWzqBX0yml6dplmxX9LMypPubeDQZniR+9hxut0Ig2Wh3c6yB/619A0P5gbtuO7gqrfkoEuZThEUzzqyKGOQV4UF2hU7BLABuyzch0= ;{id = 36153 (zsk), size = 2048b}
uri.arpa.\t3600\tIN\tDNSKEY\t257 3 8 AwEAAahOTGtQI/HNtJgStghtd8Y4H26mPauZw1UFVSq/X5c3ThjRCd2KieTVokcUhZfWIw9AQmLEO4qJTPXreiXDRZTLm8O0M7jDXggzdnAxhstSaUITjBbvnBf1p2erI2BQK6d7mmsywEgJ8Fy5zhQGMwRpNCe8eDsEPHWdfhO++xxxCqeZQgGi++3M+9/R41qXpJUySlmlxUp0cE5OianyxcJEl5gOnVz9UXpcZeaZdyQuEkZVe1BcXgYB3tKPREujHTiwp+tXZHqfE3pqnDpepzR3tFrHoU3/KkreXP/8Xn0Behe8TByic8Gb60tFl5Q5Kb98poPKzTdeKv0PvhRL+VE= ;{id = 22772 (ksk), size = 2048b}
uri.arpa.\t3600\tIN\tDNSKEY\t257 3 8 AwEAAcd4/Jd9UZEHkAtD6IAhkgMqKnhDQR29DRAJBvfymZ2h6hvHRoEk/mLhpmlpdqJ6AWYTGeTu+03Yk4DRyxAbPmWiY3q0+ceezbGEgHzuW53llsu9PFX2zK1yqU6kCJ5V4dNYDwe+G5RoQO0/Qo5IRXzruQIowKZKVdJBi22x6APNul61g22GUk1Et9kO+Wc9g116KBR7eRzmvj/7cprd19sJGDGFCNieyeexIgXstk5u/d+dZ2DXHDn+3hp3QhYQLqbYG7s+9wIzw0Oa1jneujXzI3udkQ6khp1GeIziuI1IWQNNF7/weoHu1LzX/xPCE/aK5eTy1Avu11DTamn163M= ;{id = 42686 (ksk), size = 2048b}
uri.arpa.\t3600\tIN\tRRSIG\tDNSKEY 8 2 3600 20210217232440 20210120232440 22772 uri.arpa. R2ecLjDnuDyoAJ8KMOhfRJzs0bp9TBWAHZ+vmOKnTMhuW6NqIp8tzO0Z3ti5nxVFqDDX7aL9IXVbYjxE2u5TCSQUYx9Qkr84rpNsvHiz0V9qZfe2/CY02Jy0D/TswLSrW5w/Ph2fdH8kAzZZSlyELadAI69qSE6GUXAW5xml9Abikd5ITX9TeK0z3VmSSpjw/nV5Piui7IRCY1ADKIBJJZJliiSB9iTglkzfTEdtsoFncfsqa/giWP3o8CCLyj9fuwg4oxkbRBoQDtZUmvNqKjXP7GfOqtZa0DNtWH7eGWk6ZJsPtVnq436XNqlbidSJjXclZoUlwGEPjf4X75fE1g==
uri.arpa.\t3600\tIN\tRRSIG\tDNSKEY 8 2 3600 20210217232440 20210120232440 42686 uri.arpa. hZ97HPDGO8Cfpiz240wxLKvMMHkhh9tLqrXG2w9OXv/DtbovAnG7RnCRMVOjOgZIqLqgxZo3OY72Ctb1ayL7M9fpuhSypOxkZPl/tNlyH0IafcQu2BYed+N3kbHlf784Sy1YlI19VZgDZk7yrXYkuLkSTXOSOydWjDIAUVGSgj8jmL0/pJn5zVv/kTn693ubo7lxpVQhCYeeWz/m2/QMAYRIb9h7vb//EAcqKZQFv5DQvGPQ9r92jN1+0WO/883O+kgTiSXVk79KcbfiQfPVWy9RhOnFGNHEyrC8ro2lEsEz/pKlr7jaqO9jSY2j+v59G70rJHQqSJZtMNlIpAYpuA==
uri.arpa.\t3600\tIN\tZONEMD\t2018100702 1 1 BC4DFEC4593BDAE8755E04D5C4009685D5861F92681C3BABA54C102E4215938E4531966EEEC385A1EA2BED0D072122FB
uri.arpa.\t3600\tIN\tRRSIG\tZONEMD 8 2 3600 20210217232440 20210120232440 36153 uri.arpa. M5dEgDlUPUbWM6DgdUJDfcEh22R8EYutKR8LLijoC/L56+Obt/P+1ZjPs0b1tn3gf0YR7c+210gupbt3AHN9c4MWR+YrpzsyXNnLIKzeb2P+hldEgbcXS2jIqbBPd6B24RpaNzKMurnBSHz+tLBsxsXOk19olzMWDPRYqVsCTsuQGfqTyH9KlEflQrtoDlCPMr9gVnkcgbBfQyMheOmVmA5cWYyHQPF2oyf938q11SmQrSiAuAtv2sezhHyNVZxCOdjNb+jmKJyFuyImKvsVSz+1/zR82fxzxrsEtVOhZ2oVuqWna2AizIHqoDaoGk0BXR1jE4rW2uvbMzMl4uApmQ==
ftp.uri.arpa.\t604800\tIN\tNAPTR\t0 0 "" "" "!^ftp://([^:/?#]*).*$!\\1!i" .
ftp.uri.arpa.\t604800\tIN\tRRSIG\tNAPTR 8 3 604800 20210217232440 20210120232440 36153 uri.arpa. mPOGEz2vGEfbcqzA8vcFBNeOxNyFVFsOqUBN5foI2hnML1BLgECpU1dkoXAI2HhkdocwA76FinQgFy80/kdbWjNriZ6GBxRIuuy9HIffwSCBIJ7v6OUSyReXEQ9ky8qIIpJSYIxX0BZnMC/ChqmcZnQUeDzar7OKn7LCumGtqObtyBUabP4/Cp7MnpBcaCpsZBzpemjmlmuzkG0hv+b3m8OF1CxcR/Lt6LUK1dfA4/0r3hKdjt/H2Y5hptRUCIyd6OpkQqTy3Y0/CXsJIcDOIohrpiOkwOnS8bdzIc1bVIadkP8e4odoCuUQT5n9XEHECpJYpvMgWSs7kdbG3LLfiw==
ftp.uri.arpa.\t3600\tIN\tNSEC\thttp.uri.arpa. NAPTR RRSIG NSEC
ftp.uri.arpa.\t3600\tIN\tRRSIG\tNSEC 8 3 3600 20210217232440 20210120232440 36153 uri.arpa. cFeGFiIM81B7YFBd9ScDc+rjo12udBgS43mVkSCsw4nlfB7mKW60BuyQjbU2l0UbdcoRxeroXVHwLQfMOIRMKb46h30Hk+/eu4Q6NL5vC0wnwOqrRyYp9THDnL9OIZZX2yrIlGI+cbt3+lGmP/tj6qLwqxIkrOD61EVTLf4NDZS8sUxS32z/Lq6iCngOIUyQDMTMJCtNAD6f4iAJNLuPwBnpMkH7iYUvhLgEOsYE4QAC1AkTwwQWl4zU3QsTDcJ9zliZ7TUroHLBRuhajp5wZjkip6tOwIOmMInsx6KGTTt9Q9guAoVEY+ies1IYdASRjhR/3KnNUiUFMSx4QAM3iQ==
http.uri.arpa.\t604800\tIN\tNAPTR\t0 0 "" "" "!^http://([^:/?#]*).*$!\\1!i" .
http.uri.arpa.\t604800\tIN\tRRSIG\tNAPTR 8 3 604800 20210217232440 20210120232440 36153 uri.arpa. kUVuEOTyoX5oEJcO2E3hj022y++hct2yJq3ZK46bPrJnrk6EBHuCGDxEm7QoMKTsI9UJ5YYkwVAQmjfWnId55PgfgerHS+b4qoXY7ECkc2xmNOuHLLog8ewWCm2yRVAy5p9FoiIvWJsV09J4Q6T7FW6qMWJuiwi63QjJwvSbqCrK/lSjtzp+cg41VIW0H6k54ZSO6uhEYtV1gk2APySygcvtqMXOJRtkd4wX19oT5pppCx/DGTsiq955WLuGwtsUmILwj6LSnd6khuOmS+LvYxOTG/RM7e5duhZV0pBwMPhMWD35n9a6zLIFdx6ZIi0JQ5WQTQprA6DK2ADpTCpNBQ==
http.uri.arpa.\t3600\tIN\tNSEC\tmailto.uri.arpa. NAPTR RRSIG NSEC
http.uri.arpa.\t3600\tIN\tRRSIG\tNSEC 8 3 3600 20210217232440 20210120232440 36153 uri.arpa. f9nFsiTzR1ZkcIx7pIW4uRdF4yV8E8823F5nkKsqf8t4oD7K1A6KcqtPaL/0RqYFYeICCstpy/F0bcINgYXxLv+yXDAl8a48D5jXx/MBvurwB3bbLlkAzke5wHMiEFp2ZC917D1/cm5NXwXQusFS0uPkHQ3cUF7FK0coYd+5v0lFl/sByK/fmiBPNfMKnXzwxelCGpR28PhdDUuva+TB/GxbnH9+Z0GoLzZeQ6q023rEVR6yTJ4C7LUeFMX8R3kYK4NfS8/33nKV3SqK70MEnHpkwJClTYTbWMTHuUnTqj402OG45ApA8nXyg6xXnnnm3SjJ69zm6P0aCQCVdkQhfA==
mailto.uri.arpa.\t604800\tIN\tNAPTR\t0 0 "" "" "!^mailto:(.*)@(.*)$!\\2!i" .
mailto.uri.arpa.\t604800\tIN\tRRSIG\tNAPTR 8 3 604800 20210217232440 20210120232440 36153 uri.arpa. q6qLEPQQtfCdIGUJrZeHMh+4Wd9ANSMKSnUCcacpfmnyq3jjaJn47K5AYrukTP7kI30x20QlX5zyOU/MsdsgzCXgUtBUB47gGmRZwPHO9KB7Ky7D4PEcnisUl1mEeSfs7um+ujtjDwxZzn40JuEslPUL/nuNLkrZrZyhiTr4JWWDoTV2S2LJgGpbCMg5hjTWirr0LGzksxBz0BE7T9mzECEumwpZlOK/riqF2oiYrImFP42tsV/7z5y44ooCkaw3ftW1HK+lFMqooXBZ/H0Hdn/8CGi+n9U6iC49j+GDFurWMQ+Gjp9CcKMootiQ/08DaNQ1UGOz7CPWRhxJmzhlUQ==
mailto.uri.arpa.\t3600\tIN\tNSEC\turn.uri.arpa. NAPTR RRSIG NSEC
mailto.uri.arpa.\t3600\tIN\tRRSIG\tNSEC 8 3 3600 20210217232440 20210120232440 36153 uri.arpa. BR3Qv9BRZPcmLz3yN8JO0Q+xzx82NKks+Qx3NYTA1mFKGgrgzNCJfGFHqderL/D4YVGTsFijS8u9GIY5IvvGTtpoCQ5buh6yvdcMZsvv1gIZv32/ipVPxUBq1mAdZVQN5S/tnkKMnNhRR7oyZb8Plx8NPgdrggb5RUFCBu23barqZwdcphDFDPaKATt0MKrVqhSe3iQWhNXepje/k8AYy3A1oFPcIn2NRN9Ajx5CO6wf3uw1MvTRthAxCv+xA1wq0R6i49ByNkyIDc3YnGnOHJdPNmd1KDMkzbeI7VaeIKW+N40z0Vj1FYsnLh3BYQOkNvhtBFGHjdqxxLnIwWY8yg==
urn.uri.arpa.\t604800\tIN\tNAPTR\t0 0 "" "" "/urn:([^:]+)/\\1/i" .
urn.uri.arpa.\t604800\tIN\tRRSIG\tNAPTR 8 3 604800 20210217232440 20210120232440 36153 uri.arpa. SO2V2fKM2dd8oyXjAaC9M1eMvaUmq0O748ntBYMycajNgeCRIz6VU10QYapMZoLb5Ky/JIQAWDgHYZr2AyJ7v4wzAsoQc8UBCAVLzqf3KwpDENJ0rHmwLRROjIv2j4nFHzBqyJiMP2dTBd3odwhTqXznlaZ4JORAQyG81v10Cw4Chybl1xGo/ig/FiHlVMuWT9hiN4mwPTsLDYRzu4q2o/p6KWgdH2DyZioBfVuFPYzEw4ZhKKxpO/+/31j35LcKncqWwKRsBd1CGtbFO3yGUi+J2+2djPC0CjlKD8ka+IN3l4dkLjgPfgXOu82kXLsqEtrgbIcng+YBOZUMl9U9cg==
urn.uri.arpa.\t3600\tIN\tNSEC\turi.arpa. NAPTR RRSIG NSEC
urn.uri.arpa.\t3600\tIN\tRRSIG\tNSEC 8 3 3600 20210217232440 20210120232440 36153 uri.arpa. V597e3piSVuLUu/sqyZCcKvS9FvB44DTfwrszA0FNmBiIi3LyIaObUN91F5wQshFP8et0GetNN38EpZeuA2JzapgIS7Oby2ZPFijBPXZg+9rRIjeB6UhSkQ7hO94ZrnWsNCcuGtsryT/Fz4HXShwogeks2nSODl5cqclhGnAtdiAnBVve4oMzZMTBJWxOb3wTq9kF7PmWnBDdDAZ0T1x9aJW7XKiJj4fSDvHpeWWQKv5lBbCkIRri3DF5lBeC/0qZC4H7/TTVP2HLI7oTAgRU7c7eE62tidtE0VC0EYV3HLZoOmw8lg7U9ZophqhJy5OjtiV8BGnopP3wZwmpYlLaw==
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/uri.arpa.rfc8976");
        let ksk1_path = mk_test_data_abs_path_string("test-data/Kuri.arpa.+008+42686");
        let ksk2_path = mk_test_data_abs_path_string("test-data/Kuri.arpa.+008+22772");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kuri.arpa.+008+36153");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-ouri.arpa",
            "-T",
            "-R",
            "-f-",
            "-e",
            "20210217232440",
            "-i",
            "20210120232440",
            "-z1:1",
            &zone_file_path,
            &ksk1_path,
            &ksk2_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn rfc_8976_zonemd_the_root_servers_dot_net_zone() {
        let expected_zone = r###"root-servers.net.\t3600000\tIN\tSOA\ta.root-servers.net. nstld.verisign-grs.com. 2018091100 14400 7200 1209600 3600000
root-servers.net.\t3600000\tIN\tNS\ta.root-servers.net.
root-servers.net.\t3600000\tIN\tNS\tb.root-servers.net.
root-servers.net.\t3600000\tIN\tNS\tc.root-servers.net.
root-servers.net.\t3600000\tIN\tNS\td.root-servers.net.
root-servers.net.\t3600000\tIN\tNS\te.root-servers.net.
root-servers.net.\t3600000\tIN\tNS\tf.root-servers.net.
root-servers.net.\t3600000\tIN\tNS\tg.root-servers.net.
root-servers.net.\t3600000\tIN\tNS\th.root-servers.net.
root-servers.net.\t3600000\tIN\tNS\ti.root-servers.net.
root-servers.net.\t3600000\tIN\tNS\tj.root-servers.net.
root-servers.net.\t3600000\tIN\tNS\tk.root-servers.net.
root-servers.net.\t3600000\tIN\tNS\tl.root-servers.net.
root-servers.net.\t3600000\tIN\tNS\tm.root-servers.net.
root-servers.net.\t3600000\tIN\tZONEMD\t2018091100 1 1 F1CA0CCD91BD5573D9F431C00EE0101B2545C97602BE0A978A3B11DBFC1C776D5B3E86AE3D973D6B5349BA7F04340F79
a.root-servers.net.\t3600000\tIN\tA\t198.41.0.4
a.root-servers.net.\t3600000\tIN\tAAAA\t2001:503:ba3e::2:30
b.root-servers.net.\t3600000\tIN\tA\t199.9.14.201
b.root-servers.net.\t3600000\tIN\tMX\t20 mail.isi.edu.
b.root-servers.net.\t3600000\tIN\tAAAA\t2001:500:200::b
c.root-servers.net.\t3600000\tIN\tA\t192.33.4.12
c.root-servers.net.\t3600000\tIN\tAAAA\t2001:500:2::c
d.root-servers.net.\t3600000\tIN\tA\t199.7.91.13
d.root-servers.net.\t3600000\tIN\tAAAA\t2001:500:2d::d
e.root-servers.net.\t3600000\tIN\tA\t192.203.230.10
e.root-servers.net.\t3600000\tIN\tAAAA\t2001:500:a8::e
f.root-servers.net.\t3600000\tIN\tA\t192.5.5.241
f.root-servers.net.\t3600000\tIN\tAAAA\t2001:500:2f::f
g.root-servers.net.\t3600000\tIN\tA\t192.112.36.4
g.root-servers.net.\t3600000\tIN\tAAAA\t2001:500:12::d0d
h.root-servers.net.\t3600000\tIN\tA\t198.97.190.53
h.root-servers.net.\t3600000\tIN\tAAAA\t2001:500:1::53
i.root-servers.net.\t3600000\tIN\tA\t192.36.148.17
i.root-servers.net.\t3600000\tIN\tMX\t10 mx.i.root-servers.org.
i.root-servers.net.\t3600000\tIN\tAAAA\t2001:7fe::53
j.root-servers.net.\t3600000\tIN\tA\t192.58.128.30
j.root-servers.net.\t3600000\tIN\tAAAA\t2001:503:c27::2:30
k.root-servers.net.\t3600000\tIN\tA\t193.0.14.129
k.root-servers.net.\t3600000\tIN\tAAAA\t2001:7fd::1
l.root-servers.net.\t3600000\tIN\tA\t199.7.83.42
l.root-servers.net.\t3600000\tIN\tAAAA\t2001:500:9f::42
m.root-servers.net.\t3600000\tIN\tA\t202.12.27.33
m.root-servers.net.\t3600000\tIN\tAAAA\t2001:dc3::35
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/root-servers.net.rfc8976");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-oroot-servers.net",
            "-f-",
            "-z1:1",
            "-Z",
            &zone_file_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    /// Test NSEC3 optout behaviour with signing
    fn ldns_nsec3_optout() {
        // TODO: maybe make these strings a regex match of some kind for better flexibility with
        // layout changes that don't affect the zonefile semantics?
        let dir = run_setup();

        // (dnst) ldns-signzone -np -f - -e 20241127162422 -i 20241127162422 nsec3_optout1_example.org.zone ksk1 | grep NSEC3
        let ldns_dnst_output_stripped: &str = "\
            example.org.\t3600\tIN\tRRSIG\tNSEC3PARAM 15 2 3600 20241127162422 20241127162422 38873 example.org. 0XdDm1l2Mm8dyhtzbyQb91CmyNONs8lc9d22FUGvpjfqo8T2h0xs04x5MIfP0DjmiVnNqIyPK6sipnDqf6tCDg==\n\
            example.org.\t3600\tIN\tNSEC3PARAM\t1 1 1 -\n\
            93u63bg57ppj6649al2n31l92iedkjd6.example.org.\t240\tIN\tRRSIG\tNSEC3 15 3 240 20241127162422 20241127162422 38873 example.org. z4ceUmbSZiSnluFj8CDJ7B9fukCR2flTWgca4GE2xrw48+fiieH/04xCKhJmDRJUJTVkKtIYpB4p0Q4m60M1Cg==\n\
            93u63bg57ppj6649al2n31l92iedkjd6.example.org.\t240\tIN\tNSEC3\t1 1 1 - K71KU6AICR5JPDJOE9J7CDNLK6D5C3UE A NS SOA RRSIG DNSKEY NSEC3PARAM\n\
            k71ku6aicr5jpdjoe9j7cdnlk6d5c3ue.example.org.\t240\tIN\tRRSIG\tNSEC3 15 3 240 20241127162422 20241127162422 38873 example.org. HUrf7tOm3simXqpZj1oZeKX/P3eWoTTKc3fsyqfuLD6sGssXrBfpv1/LINBR9eEBjJ9rFbQXILgweS6huBL/Ag==\n\
            k71ku6aicr5jpdjoe9j7cdnlk6d5c3ue.example.org.\t240\tIN\tNSEC3\t1 1 1 - OJICMHRI4VP8PO7H2KVEJ99SKLQNJ5P2 NS\n\
            ojicmhri4vp8po7h2kvej99sklqnj5p2.example.org.\t240\tIN\tRRSIG\tNSEC3 15 3 240 20241127162422 20241127162422 38873 example.org. NG/8jk3UHht1ZYNEjUZ4swaEHea1amF4l3jZ893oARi95oxtPVLKoinVbBbfVuoanicOgeZxUPpKWHMBR12XDA==\n\
            ojicmhri4vp8po7h2kvej99sklqnj5p2.example.org.\t240\tIN\tNSEC3\t1 1 1 - 93U63BG57PPJ6649AL2N31L92IEDKJD6 NS DS RRSIG\n\
            ";

        let res = FakeCmd::new([
            "ldns-signzone",
            "-np",
            "-f-",
            "-e",
            "20241127162422",
            "-i",
            "20241127162422",
            "nsec3_optout1_example.org.zone",
            "ksk1",
        ])
        .cwd(&dir)
        .run();

        assert_eq!(res.exit_code, 0);
        assert_eq!(
            filter_lines_containing_all(&res.stdout, &["NSEC3"]),
            ldns_dnst_output_stripped
        );
        assert_eq!(res.stderr, "");
    }

    #[test]
    fn ldns_signzone_disables_minus_b_when_output_is_to_stdout() {
        let expected_output = r###"example.org.\t239\tIN\tSOA\texample.net. hostmaster.example.net. 1234567890 28800 7200 604800 238
example.org.\t239\tIN\tRRSIG\tSOA 8 2 239 20241127162422 20241127162422 51331 example.org. XD5+Exk0KLfvLYA7y+Qs6jhF+JeESFONqZAjkSvznXdjod80W6cv9C77XeHqqod+5glGHlw9bXmVhuJ/5n056BbnDcMWF+AV4taFc/RrDcZb5A0tS6LnRWbpO9puKeLVK10FeAChCygct6/+GNiE12DDLnzKJFuyMuu+nLa2p88=
example.org.\t238\tIN\tRRSIG\tNSEC 8 2 238 20241127162422 20241127162422 51331 example.org. AT4PDLEolpApcrYi7mcTXrqCQ6psXeZNdmFub08m6BJRs2jeW07fM11Amft53FXKgqbT23WILkEM7Raai8E8qPJoSdDCys6zYXW/NCU9Cf/oXIKdD4nxQXXWbnX4GCMN4XJy382dYnxTDssQK6lNIKKi4OvGYIxVUPthaLKJFU0=
example.org.\t239\tIN\tRRSIG\tDNSKEY 8 2 239 20241127162422 20241127162422 51331 example.org. rLwqlu9fYkzAy0jM9crtw5du4rUaDVH9PI4m06lRwjSKhu1VQ1AHjRhlKy1OgUee/5LovXSRGcgNZi4wiTS5ZULTJw7UQTBRXaaNhVACENX/MoVw9SmYuDSTyvQboChmFmYSMch3Q/02VhgN+BT8F7+OdDVgsWqZUEKPVNixk/0=
example.org.\t238\tIN\tNSEC\tsome.example.org. SOA RRSIG NSEC DNSKEY
example.org.\t239\tIN\tDNSKEY\t257 3 8 AwEAAckp/oMmocs+pv4KsCkCciazIl2+SohAZ2/bH2viAMg3tHAPjw5YfPNErUBqMGvN4c23iBCnt9TktT5bVoQdpXyCJ+ZwmWrFxlXvXIqG8rpkwHi1xFoXWVZLrG9XYCqLVMq2cB+FgMIaX504XMGk7WQydtV1LAqLgP3B8JA2Fc1j ;{id = 51331 (ksk), size = 1024b}
some.example.org.\t240\tIN\tA\t1.2.3.4
some.example.org.\t240\tIN\tRRSIG\tA 8 3 240 20241127162422 20241127162422 51331 example.org. xdVbhbaMXEyMySCOKy2yYQgU2URAOnu+jLU5py+4R8R3yVVvdl6yMjzdUD3vyxprHitJ+xLrXU/wHSQvtjSwmxVL53ztu+9wrnrhQm6nqXGLW+iw58LepdLVRlppz2WlV0CJAlLIQPJ8rw4hND3NYLJojnO8OdrgpHL89ajD4II=
some.example.org.\t238\tIN\tRRSIG\tNSEC 8 3 238 20241127162422 20241127162422 51331 example.org. PP4tH4Y6JNymWSJebPd3zjvDrjyZXVBF8QTKxKAmbmtPacbWyIcRuI0L8+8Z1folAN2U5cUZmCaIbt5Ylaj6ab4UAYHiy0BrcF/zbNIeLRSTz4hOteencIooTDvqIqYuI9/xTVXcfJ+gVzzlIh2dJK2GW5O4+B1xR+CINLNJ/j8=
some.example.org.\t238\tIN\tNSEC\texample.org. A RRSIG NSEC
"###.replace("\\t", "\t");

        let zone_file_path =
            mk_test_data_abs_path_string("test-data/example.org.rfc9077-min-is-soa-minimum");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+51331");

        let res = FakeCmd::new([
            "ldns-signzone",
            "-b",
            "-f-",
            "-e",
            "20241127162422",
            "-i",
            "20241127162422",
            &zone_file_path,
            &ksk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.exit_code, 0);
        assert_eq!(&res.stdout, &expected_output);
    }

    #[test]
    fn rfc_4035_nsec_signed_zone_example() {
        // Modified from the version in RFC 4035 replacing the keys used with
        // ones we have the private key for and using a key algorithm that we
        // support (8 instead of 5).
        let expected_signed_zone = r###"example.\t3600\tIN\tSOA\tns1.example. bugs.x.w.example. 1081539377 3600 300 3600000 3600
example.\t3600\tIN\tRRSIG\tSOA 8 1 3600 20040509183619 20040409183619 38353 example. PTJr4PGqaoA7hl8SqD3qyoAqN+oEYuKsBjYaKWgyPxGIb4Z377Ru2kkT9QUsb6ETFCLVMpa315NwMwXhqTiWlak/gTF5OTf/+lTTP0H1sNVv4X3NwRGOzwzfxzgHY0/Rav/FrUjNZCmTA6KMo3i1rrMCG9FzCsnP1TQk9152Uiw=
example.\t3600\tIN\tNS\tns1.example.
example.\t3600\tIN\tNS\tns2.example.
example.\t3600\tIN\tRRSIG\tNS 8 1 3600 20040509183619 20040409183619 38353 example. S1vIMaEeVmm2Z14gVGWcXpAKVCyB2BrsHR4R3R1t7lm/ptS6EE+8sV5pzILv7jW7qXhUtoXAY66r6xclUXI7xtvQQqJrcFz9e0QF9Ogt47XotbyV3pU/adtp543pmzK5gNs21uRPHnyJTmEvVQCPhYGGqTH/p0LhZk8DEFlR+q0=
example.\t3600\tIN\tMX\t1 xx.example.
example.\t3600\tIN\tRRSIG\tMX 8 1 3600 20040509183619 20040409183619 38353 example. CcFb8nMrXhPDRVu5mp3YA2OW8Gpp5926EkcZRGqjVNxO+Xn/xWfhtxIhxhwP8b4oVNYQKq+L8L/jOXSvHe0yMfcBM1sQF0Eg1Qb+S48VtF5ZHwWVxLTHNfEYIsZbTa9TBp3oncmOkobPKIa4KceoaPba5Oq09Bc4HG0x1I8E3Xo=
example.\t3600\tIN\tNSEC\ta.example. NS SOA MX RRSIG NSEC DNSKEY
example.\t3600\tIN\tRRSIG\tNSEC 8 1 3600 20040509183619 20040409183619 38353 example. PPaIiWtu/9cpju9ttaEH+bxGiagc3hXpMsnlP9RHAfy9G9QNXOCYCEp6cIhM9mbYHEAUyo/IBXEbKh7eeLrc/PqdvG1hTOgRnXHzuqdsiVeHHuPOrw3jN5fIJwr9g0vnSoLJ/S0HkZjGt9YfiOQgfhfEXXkJQbwU0g9LQDjPYv4=
example.\t3600\tIN\tDNSKEY\t256 3 8 AwEAAbsD4Tcz8hl2Rldov4CrfYpK3ORIh/giSGDlZaDTZR4gpGxGvMBwu2jzQ3m0iX3PvqPoaybC4tznjlJi8g/qsCRHhOkqWmjtmOYOJXEuUTb+4tPBkiboJM5QchxTfKxkYbJ2AD+VAUX1S6h/0DI0ZCGx1H90QTBE2ymRgHBwUfBt ;{id = 38353 (zsk), size = 1024b}
example.\t3600\tIN\tDNSKEY\t257 3 8 AwEAAaYL5iwWI6UgSQVcDZmH7DrhQU/P6cOfi4wXYDzHypsfZ1D8znPwoAqhj54kTBVqgZDHw8QEnMcS3TWxvHBvncRTIXhCLx0BNK5/6mcTSK2IDbxl0j4vkcQrOxc77tyExuFfuXouuKVtE7rggOJiX6ga5LJW2if6Jxe/Rh8+aJv7 ;{id = 31967 (ksk), size = 1024b}
example.\t3600\tIN\tRRSIG\tDNSKEY 8 1 3600 20040509183619 20040409183619 31967 example. IXPr+2MolSmtlo9ri9prF/PcBhYTL+3n+3MEGJOjdJFDSv00HW3a2ymankSZekNTkVA/AMOOyEnZhF/98ihhfLHmvWYKBfwMiXQX8uSh+YqrcTV6b6/N7JDmCimZ9t3R2T90+VpPb/lERwnHv9KdytiZV7tUWzihPqx3mEFpmME=
example.\t3600\tIN\tRRSIG\tDNSKEY 8 1 3600 20040509183619 20040409183619 38353 example. G2DatUOySjh3hf2KYIOwdwsRRAmiIz+xnP59DbcqjGAPrWLrtK+h2etlBeWDbS1yGFOAf7FYSl/4QjRdkA111frRTc2kINqAkflRAb0g2e5b6JEp1kbUPSG1c07W/0GBQoY9Pl9MvSdLs9ZfzZT9jhIFgla9NzcR19kHIcSIjZ4=
a.example.\t3600\tIN\tNS\tns1.a.example.
a.example.\t3600\tIN\tNS\tns2.a.example.
a.example.\t3600\tIN\tDS\t57855 5 1 B6DCD485719ADCA18E5F3D48A2331627FDD3636B
a.example.\t3600\tIN\tRRSIG\tDS 8 2 3600 20040509183619 20040409183619 38353 example. pT03HgemJqArs5oDzJt01PpSyvFLcIcD4knqE2ZjaOLtsgErjjVqWmywWVRJSsySzMu2AEK2BPWBZsznovpY/bWCDh+c0LW6GpWupoUm4J43ORPmenA3FTL/bjrZMfv7D9CDrSi7/JegTT4VKEz0/GniicPluDVsUNYBIUfPIm0=
a.example.\t3600\tIN\tNSEC\tai.example. NS DS RRSIG NSEC
a.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20040509183619 20040409183619 38353 example. GD9X/mMKRiDTRAKO/QccqekZjSkMjN92foDHRHpYDFtmWuqNDAXq1Se2NedMpgwsPcI6uvBnab7+cHmI24Rv5z90IHpzVzEAx8EgJpgh7cMUUjiJL06t0GU3nhLV1nZvwVQWRVj8n3Y0otQwWjA/bDXt2COF6fnxUZyryyVJswM=
ns1.a.example.\t3600\tIN\tA\t192.0.2.5
ns2.a.example.\t3600\tIN\tA\t192.0.2.6
ai.example.\t3600\tIN\tA\t192.0.2.9
ai.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20040509183619 20040409183619 38353 example. oe2JZhvPBaocVMeCj92hVmESDpobTnWzp/ye5qE+/e0eCO2hRCcltU18f4RtuGQVe9cF9H8HbjDTRyUVmU8HTXQTv9Oi9MRWtU4+po/lYWmvbB+7+mBuUVc+UUtHXwBp++Yak+QYnpARUEs2oPujGYvjIbbTMxtmnUofcHDhBlg=
ai.example.\t3600\tIN\tHINFO\t"KLH-10" "ITS"
ai.example.\t3600\tIN\tRRSIG\tHINFO 8 2 3600 20040509183619 20040409183619 38353 example. ZwShN6dqV7Kfv8Ki0AGN7Qmd6Cd71xfSdCNXRXTRYVSn8/fTFd8QOd92c4u6/IK96HZYhSWgzJ0h9bHQcaAZxOnToq5T6+kvFq6xlSnusEvigx6j6gsuKR1cMoaXxmInCsyy3g9yPfb8jNSVYH3h03GgN1NlPbpVHHT9mZKdkhw=
ai.example.\t3600\tIN\tAAAA\t2001:db8::f00:baa9
ai.example.\t3600\tIN\tRRSIG\tAAAA 8 2 3600 20040509183619 20040409183619 38353 example. IyoKttTAyeZdBbOCO4pobuJYrFATws3G8Pi24+M0w5lFcG9rIdBj2fiE8N8PyDApfMhckA9LVOwmRaK+JZn6Ep6FPzHWHrdzkB6J7X/QKpcjzmRiffa1kn8/Ev87hk4BZO9DPuQNkQBKQGX5bLE3ejAuXayuAieDZh10F0Nt/YI=
ai.example.\t3600\tIN\tNSEC\tb.example. A HINFO AAAA RRSIG NSEC
ai.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20040509183619 20040409183619 38353 example. ue5AJm6A4P/jgzUDrjNTNRcKsbou9gv2LTucGSBZxpZXw6hXpJu3lIY7znIz5CqURXI3YNZ9fLzjYk8ZVCCjdSq/5WcP6aVcWPyqYC1q9hsPAKEbPYu4oVg0tIj1HBPqtEWwgizvCvHNVNF1vUcI29bm/lob9L0P/iDiUh0BDBc=
b.example.\t3600\tIN\tNS\tns1.b.example.
b.example.\t3600\tIN\tNS\tns2.b.example.
b.example.\t3600\tIN\tNSEC\tns1.example. NS RRSIG NSEC
b.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20040509183619 20040409183619 38353 example. lURCI1R6jVuhaKCd5qyOIoM20nqLRitEZ0QK5E/kdbYWJpASz3vOJjAegoCdsfUf4nWHC+nwhBgQcN4SG2mXD3IX6Y6gD0yKsFtWqrs7NF579qEMkHsNuKNG6zrCtf0AOUlC/836gpDmOWkEnptUDbbjroc9i4Jo/qLSHybvO4w=
ns1.b.example.\t3600\tIN\tA\t192.0.2.7
ns2.b.example.\t3600\tIN\tA\t192.0.2.8
ns1.example.\t3600\tIN\tA\t192.0.2.1
ns1.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20040509183619 20040409183619 38353 example. P5BFP/IZBphRLFkzyK93iF7OOu1DQZIDjXk3133A+Zc4foo84Ny+3GID2LoRfMFd8joggO4sxiczdvaWz7awyt8SYF9ckk7ACj0JU1g+6q+v7DLkI9KSeLyMvaLzcy9/k/YAOLbewZ09YKME0PuMIgnPt5XiWN+iPY7AAg0n/jY=
ns1.example.\t3600\tIN\tNSEC\tns2.example. A RRSIG NSEC
ns1.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20040509183619 20040409183619 38353 example. r/1bsbwMppvJEuLiMvYqoVAdZAeO1sbW/vuqThX+0TJ5fsmtBTP2l4jm2JC+8atB4xFwxNCQVwFgNic3OUpu/a9nNcsfIO6kqIBaFF3+hQq3S8xl+sTbWc7ZJHcNvEYm+XPEWRRXtgKwdGTLMAL5IcWJXCYXt5ZjAkJCWKb+6c0=
ns2.example.\t3600\tIN\tA\t192.0.2.2
ns2.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20040509183619 20040409183619 38353 example. I0Vqke2ZFjPdMxjbsaCVF23k6riPx0GjC/TRWUzx30EbOoGhEQd8+WWiHFKyDiebK0fFXfz/DGEAXlyE6kVWq6dV1BdL8fREHj7sJSu9Xa7jNShlxsDBO7OEQuq3ignpDs+q70JQJSr7eV7HNlSuNQf5/CLzyEwQy0ZDr/ZJ8PQ=
ns2.example.\t3600\tIN\tNSEC\t*.w.example. A RRSIG NSEC
ns2.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20040509183619 20040409183619 38353 example. UtAds21EnSeWeEig2ZakQNg6YcV/rNgjVgbVF8BVhuTUiUUe0aH/oDy6/X/qrJqAOQ9qIxiIEV5PlilzYcpn2vdTVi/wvG1lZ12dD7fsfw8iE4E297uUyoeJdwGxln96scvykcoP7YrtRmUNB0U3i9l2/E7WSQru23wSQLGrL3E=
*.w.example.\t3600\tIN\tMX\t1 ai.example.
*.w.example.\t3600\tIN\tRRSIG\tMX 8 2 3600 20040509183619 20040409183619 38353 example. qaprB/xswn0rlCjCEhA72fcClIyjcASSR+73qwRfNzzg/VhZVSKVZFBeFc4Nk381KSqICTPvQ5uY4yHB6Vojrroyp0I8j+zxZrAtLSw/Tb3tZBO4e3Nx8G0QCYNR/NGdjMNdiR1vY9rUzYZbmWaZIeK+nYAX6n8Jl4Tqi7kozMQ=
*.w.example.\t3600\tIN\tNSEC\tx.w.example. MX RRSIG NSEC
*.w.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20040509183619 20040409183619 38353 example. VisjtZ+b5ChGkV4R9DFi3GDqoM6kW7RyU+57fiJ58drpZLL6LlfU+enxa6Ps+hvGO/z+wbtPYV+LCVJUJUHh/T3wB4W8qKv7fV2krcz3+M/HA08u6JmG1q3y6jy0Mla+3BrwYFGQ/0AQxz+NfB26IKm9jLHYYFT1t40JXpRIG6E=
x.w.example.\t3600\tIN\tMX\t1 xx.example.
x.w.example.\t3600\tIN\tRRSIG\tMX 8 3 3600 20040509183619 20040409183619 38353 example. fLyorrCjwFo6vsb4nCSOvKYxZUZKFrsqjvoP5PqElF2yPGAZ8MlNXitLH8eBWKq8ePz2pFhPt3RirgUIZxQ1j+8zf+TfUKwDR1/dGYfnvXi6vWXH9N5ZfexmcaQrSZ99SN3QooTAIaM4eatd0vDV+b29f7F5A9IyIk1rbN5XRco=
x.w.example.\t3600\tIN\tNSEC\tx.y.w.example. MX RRSIG NSEC
x.w.example.\t3600\tIN\tRRSIG\tNSEC 8 3 3600 20040509183619 20040409183619 38353 example. i64PpzFIe+TKz48GIu1RI+qvTvnRZtO03ldYvTv85pa7guwpjD0YgonNWkvMUgWhmmsk4418s6mgJ5OTbKeHih17YkbNmizIEktJfwiSYUIVfQRCslws4tKfOU7xOTN7SH/GoCYB4blgXQJiLfU3PBaJcnIKi1Pw67sXSelPpNA=
x.y.w.example.\t3600\tIN\tMX\t1 xx.example.
x.y.w.example.\t3600\tIN\tRRSIG\tMX 8 4 3600 20040509183619 20040409183619 38353 example. I0OFGGjH/AOv2w0rjRRU+JQo+1lBMlDZkegPPgsK2qo+CDXqxxFdLGdXY2StsL3amrXxMQOShq0Fj2/FvbpuEcIKGyn2BO5xreZyKaqZxA2XsOJ7rEXQU80TXHCo84JPoPkdajhuBXv2xVI6glMRCbJKlhr651K4idlz+jkAB0E=
x.y.w.example.\t3600\tIN\tNSEC\txx.example. MX RRSIG NSEC
x.y.w.example.\t3600\tIN\tRRSIG\tNSEC 8 4 3600 20040509183619 20040409183619 38353 example. Q7G8zrA62rOIU+jcgxNXVoeECX1N78rdg64Al2JQfHenBaCtRlm2oRcCZ0tjDloLJxi72oiSSKatumEDT6feyY2EkPtPFbot+iz0/HISyvfaBxYIUu27ibdVgrppA43vFdgE973/Q/nKN8FI656h2kblrPtjNp+u+UjkxTZhCyY=
xx.example.\t3600\tIN\tA\t192.0.2.10
xx.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20040509183619 20040409183619 38353 example. gJKAa/CfRLSIg1hZ2LX8dtFhODqCUk2CKp/hTZKBZHlCfWda3/SQUgFNUaCHQ8n9CZu9RNuAhRta/Hm0HqWqKcyZoLYHDyf2cuphRCmp+/d657gnlJVFe14IsdWYtKTT5ERexmPVyJgZa5FbodOr40vekxi0RML/eTw/T3ZJaGc=
xx.example.\t3600\tIN\tHINFO\t"KLH-10" "TOPS-20"
xx.example.\t3600\tIN\tRRSIG\tHINFO 8 2 3600 20040509183619 20040409183619 38353 example. emr6/dlkeuOyp8e2zlHfTZGUd/VsWDikllEZnG8TH4kmEKL1ZlPEjaU9PTvAaCJbpg92dUOgMiUjWAMLqXEMwZJXgfMruGhLVroRiCse9SshQb6WL0AzjL9vcwesBR6lqRSHAhYbjGUwbvOeJzSnBzQrIwWlOQtqFe+XuYFatTs=
xx.example.\t3600\tIN\tAAAA\t2001:db8::f00:baaa
xx.example.\t3600\tIN\tRRSIG\tAAAA 8 2 3600 20040509183619 20040409183619 38353 example. Gkfs9xXgn8YFs/10VYNgR0vasQwaTOckPMXZngMGQiWeuuk3aKUdtUlXP5511MOu+4UQINzj+xEb6BBFUZSnWXrZvxiZNDMwfJxzXNG6WqbS4B/Wp9vJWbNHxad2mBPkd8oeAP+XuFslRPJNJW+hHvBmx03nK/gr8pOE4dxur5U=
xx.example.\t3600\tIN\tNSEC\texample. A HINFO AAAA RRSIG NSEC
xx.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20040509183619 20040409183619 38353 example. c6WAeuLoXZnSTZTwK5wHcEMlzjEkDvdP8dY/4jmRj9dq6TL9GuDVfrKtxWSZsZyZUPmu/LugFdewpBUFEokoJLFI9ruPvZ+a+4zD4VuWXiP91bZLcB2oO5lu2PDwQ8er5B7E8pHO0W2c96hPleRRpMMmuHkDMiBPcLdLGdmK7R0=
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc4035");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+31967");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+38353");

        // Use -A to get the second DNSKEY RRSIG as included in RFC 4035 Appendix A.
        // Use -T to output RRSIG timestmaps in YYYYMMDDHHmmSS format to match
        // RFC 4035 Appendix A.
        // Use -R to get similar ordering to that of RFC 4035 Appendix A.
        // Use -e and -i to generate RRSIG timestamps that match RFC 4035 Appendix A.
        // Use RSASHA256 (type 8) signing keys as they produce consistent
        // signatures for the same input, and are supported by us unlike
        // RSASHA1 (type 5) which is used by the RFC 4035 Appendix A signed
        // zone but we do not support.
        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-A",
            "-T",
            "-R",
            "-f-",
            "-e",
            "20040509183619",
            "-i",
            "20040409183619",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stdout, expected_signed_zone);
        assert_eq!(res.stderr, "");
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn rfc_5155_nsec3_signed_zone_example() {
        let expected_signed_zone = r###"; H(example) = 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example
; H(2t7b4g4vsa5smi47k61mv5bv1a22bojr.example) = kohar7mbb8dc2ce8a9qvl8hon4k53uhi.example
; H(a.example) = 35mthgpgcu1qg68fab165klnsnk3dpvl.example
; H(ai.example) = gjeqe526plbf1g8mklp59enfd789njgi.example
; H(ns1.example) = 2t7b4g4vsa5smi47k61mv5bv1a22bojr.example
; H(ns2.example) = q04jkcevqvmu85r014c7dkba38o0ji5r.example
; H(w.example) = k8udemvp1j2f7eg6jebps17vp3n8i58h.example
; H(*.w.example) = r53bq7cc2uvmubfu5ocmm6pers9tk9en.example
; H(x.w.example) = b4um86eghhds6nea196smvmlo4ors995.example
; H(y.w.example) = ji6neoaepv8b5o6k4ev33abha8ht9fgc.example
; H(x.y.w.example) = 2vptu5timamqttgl4luu9kg21e0aor3s.example
; H(xx.example) = t644ebqk9bibcna874givr6joj62mlhv.example
example.\t3600\tIN\tSOA\tns1.example. bugs.x.w.example. 1 3600 300 3600000 3600
example.\t3600\tIN\tRRSIG\tSOA 8 1 3600 20150420235959 20051021000000 38353 example. OQmI2syAvTPgPZCKCV2cIvJyEAWyTatdMUKhg9hBdPovmZzRZ9wWaLtRzwGUuHdzeNzA7MEPOSZ1heIWYiS4JqEfemJSwZtQRLuwhOKznPMQt7UJNN4e7cjM2j0W7D8v92TsjwdB9j47Qjl64Yl0Y26zh25Sw3JRuq2dbGbbl8I=
example.\t3600\tIN\tNS\tns1.example.
example.\t3600\tIN\tNS\tns2.example.
example.\t3600\tIN\tRRSIG\tNS 8 1 3600 20150420235959 20051021000000 38353 example. YEedzYLNAJpDj/1ekisL51HQ3m9Dmcf/kj+1XxMs86P91wWTB07mhv9Jin6ziwPPwSn2erXKsJkFOT6W5XNh1W3WlgvxsQ1mAApppm0OPxmuA/pjMiv6Hr+df+N/6IZ2Wq36EtgUXxFU+QN4WVPzwebjM9rZLtNxN8kQnhSs4E4=
example.\t3600\tIN\tMX\t1 xx.example.
example.\t3600\tIN\tRRSIG\tMX 8 1 3600 20150420235959 20051021000000 38353 example. tEw3cOYajeExrCquvSlxpcjUUKNw7Myy6WjsQvboMtM4W5rs36oLF9bJiG0IuduLz3JnGPnl8o1XgpVpsmrt/xqh2ifesUD1SILxKmljw7IvJ1VDeqsaVJxmlbG0BXhNrGLRwfuiJnvUxGf3Dl8bW1g8aLOEwwm+Gz7091GJcvM=
example.\t3600\tIN\tDNSKEY\t256 3 8 AwEAAbsD4Tcz8hl2Rldov4CrfYpK3ORIh/giSGDlZaDTZR4gpGxGvMBwu2jzQ3m0iX3PvqPoaybC4tznjlJi8g/qsCRHhOkqWmjtmOYOJXEuUTb+4tPBkiboJM5QchxTfKxkYbJ2AD+VAUX1S6h/0DI0ZCGx1H90QTBE2ymRgHBwUfBt ;{id = 38353 (zsk), size = 1024b}
example.\t3600\tIN\tDNSKEY\t257 3 8 AwEAAaYL5iwWI6UgSQVcDZmH7DrhQU/P6cOfi4wXYDzHypsfZ1D8znPwoAqhj54kTBVqgZDHw8QEnMcS3TWxvHBvncRTIXhCLx0BNK5/6mcTSK2IDbxl0j4vkcQrOxc77tyExuFfuXouuKVtE7rggOJiX6ga5LJW2if6Jxe/Rh8+aJv7 ;{id = 31967 (ksk), size = 1024b}
example.\t3600\tIN\tRRSIG\tDNSKEY 8 1 3600 20150420235959 20051021000000 31967 example. neFL5wACumr7fNXVJAjNRz+5xpmkOVtsZfoW0AnOCT9Kmo8RKkArWxIMRoqCjSwL7gqAVkkDCe0hdkktfAjqwqi2cSy2SSytqgX3MBaJlfFsg/d0cTHRK32qDlhDZ4zZ511VmJCgK5rwrHPZIO5g1FTEj+hawpPVWlFqu/rWk6M=
example.\t3600\tIN\tNSEC3PARAM\t1 1 12 AABBCCDD
example.\t3600\tIN\tRRSIG\tNSEC3PARAM 8 1 3600 20150420235959 20051021000000 38353 example. EMeWCqjK1a8AmRIcl31fH2JlIwxozhyRTkuA6N/DPC6lkun6/RONLsA1ksZuY4P3b9fUcVp5/nYxo+AGNwSgr3I8VcnzhEVsDfg68grtYrcUrwhZz7TkiyLNMlMZ+krj9NpqCY1Kht/uJTrUbnG3WefBdtx3sDKa0wFY/kp/cpM=
0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.\t3600\tIN\tNSEC3\t1 1 12 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS SOA MX RRSIG DNSKEY NSEC3PARAM
0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.\t3600\tIN\tRRSIG\tNSEC3 8 2 3600 20150420235959 20051021000000 38353 example. psCexsG2DMIfSm4WgYSGx/DeUGcYvj9pTcCihdM3QO5bKJfXMQ6f0zP+Af+VpYBst+zlRZkZaoNZ04rNdm3asOLGyXlEvXSecwM9VVwpof21LaX2IW/8uue/pvr1UQQUtxqbFt5VoOoLdUVUXyo/4B5BLw1qhv3vDTbaRnKjBXc=
2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.\t3600\tIN\tA\t192.0.2.127
2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20150420235959 20051021000000 38353 example. h7JOg0b+I3ZWI4usKYTCV8Kvik2wIOlJbbgqnQuMq/eADcNucUSKP454p+6HgrTA+11FLirv07d1CL3HcXUiNd0J/85LfII965t9jEKOWq2tWzEXj0LYhoXFqcfLDmYBSNxOXy8/VexRvYlIk1wooQ8aYqdc0VIeQKba66yNAKo=
2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.\t3600\tIN\tNSEC3\t1 1 12 AABBCCDD 2VPTU5TIMAMQTTGL4LUU9KG21E0AOR3S A RRSIG
2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.\t3600\tIN\tRRSIG\tNSEC3 8 2 3600 20150420235959 20051021000000 38353 example. W3ZqyTU5dpvSeNYUtjk5mGDDyLWyoNmJXBNfZmv9Hwpb7FZQ/dZLu9OhS6B8JBDxunRaatpNFQjurkdQNdaLPH3B61824V0mW4JZFWZuTJJMIVZtPDOXNYXeezejYwuIKn1CZXtkobdJOtQUEmiW3OjC0Hz3L/0IUoKTgIbLZB4=
2vptu5timamqttgl4luu9kg21e0aor3s.example.\t3600\tIN\tNSEC3\t1 1 12 AABBCCDD 35MTHGPGCU1QG68FAB165KLNSNK3DPVL MX RRSIG
2vptu5timamqttgl4luu9kg21e0aor3s.example.\t3600\tIN\tRRSIG\tNSEC3 8 2 3600 20150420235959 20051021000000 38353 example. n0psta4fcHe5JvTi3KSA4O0n732l/4qYpwZhso2G8MvCTGTlVrGH/DQTPjS9rhBwkw2AWBN0kAVZ7Ry48jtfub9zC6VjLaF2aNzBScvbRRsewJi3pdNbo69qidOrlBEJUyVRo9cu3XQOA0zjT0mh+iT31oqQMNg3n3d66HnD3bs=
35mthgpgcu1qg68fab165klnsnk3dpvl.example.\t3600\tIN\tNSEC3\t1 1 12 AABBCCDD B4UM86EGHHDS6NEA196SMVMLO4ORS995 NS DS RRSIG
35mthgpgcu1qg68fab165klnsnk3dpvl.example.\t3600\tIN\tRRSIG\tNSEC3 8 2 3600 20150420235959 20051021000000 38353 example. cLVHqZp0jL0MG2ZqcnVUsOHkrGajuOtSJU/W9t7u8JDr0pjhw/yhtY1sCemgHEDVz1E9cyp3WLvcVphApGOMR6tkVOHzsPbVlKHRHogILXWL5Q6BUvXCWYtTsPvRT0eukGy/yFGL+JnCI+uRHuhMqmAmfjvBfIDzvYyy8MjNF5w=
a.example.\t3600\tIN\tNS\tns1.a.example.
a.example.\t3600\tIN\tNS\tns2.a.example.
a.example.\t3600\tIN\tDS\t58470 5 1 3079F1593EBAD6DC121E202A8B766A6A4837206C
a.example.\t3600\tIN\tRRSIG\tDS 8 2 3600 20150420235959 20051021000000 38353 example. hvn/QOHcGuvuZFuBgc2w6Z6GwhIYlzz+Rc1Y0F8ewD9IURCHmU438p++lx8MRY7IlGpa9rO+TIXiGpeA4amgO0wLTNUz9PcCihZuJ7wI8CSM49VB9OyCgORDsW13WTAUkqKgKyldbH3xE4EzNlY59pmWQgt6dGdHNj1aM9WsEco=
ns1.a.example.\t3600\tIN\tA\t192.0.2.5
ns2.a.example.\t3600\tIN\tA\t192.0.2.6
ai.example.\t3600\tIN\tA\t192.0.2.9
ai.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20150420235959 20051021000000 38353 example. Y/ycwCcc4Ocm7Hmn0p7G2LqiQmm3rO9J8up3Q/rz6VhRm9IhAYj9Pae3iaGuaPd3lXwmWvSYx6aLhGvl5q8BPJXH5l220pDH1aszH48c+sYfSSgSkCe3Tjcd2OnWBX3rkbVIs8JYkAdkBct8jOQXzzjqtRIwdE4rbBav4/Azk3s=
ai.example.\t3600\tIN\tHINFO\t"KLH-10" "ITS"
ai.example.\t3600\tIN\tRRSIG\tHINFO 8 2 3600 20150420235959 20051021000000 38353 example. lt9YIge2LzOVGEED+l0oHuVuhebYI3rudx4Knl0WZ4qMk7xcLtzAfK2NT0cV2MYKe9hi31O7ITh4mVZUC3yq9L1lpbZQaeeDRxJHsm1LDtlEh32GCKHXBRNNaQWmFZEuXeGeNec3/itTYMQx/2e7xXmltzVPvvBFqjn8t4pGyFo=
ai.example.\t3600\tIN\tAAAA\t2001:db8::f00:baa9
ai.example.\t3600\tIN\tRRSIG\tAAAA 8 2 3600 20150420235959 20051021000000 38353 example. diBqPpbIyhguumnN3aqQnAKiqOZk0q1fJSANjYZcnGJjAxrTfQ1kkEjG1NAJpINnfIo2lD1dxXwHvW9TJXHRcx6KcLc5v0e+weoLtA+6eNViLQVG7JvL24amuPMHS0oJBE4bkJEMYGvtJmIitb0rNaA4MIf3j0oYWS+dhL4B8A4=
b4um86eghhds6nea196smvmlo4ors995.example.\t3600\tIN\tNSEC3\t1 1 12 AABBCCDD GJEQE526PLBF1G8MKLP59ENFD789NJGI MX RRSIG
b4um86eghhds6nea196smvmlo4ors995.example.\t3600\tIN\tRRSIG\tNSEC3 8 2 3600 20150420235959 20051021000000 38353 example. q2De6iOGJZBGqKlrmdGEXvXHb2Rz0OT1P5Rnfqn+TutSupUYmLKZYlk66QSj/CXW8aLb0mDGdqyRTjm7DuDv0+su2T+w0SoS3M5t1wiDSeE/vl6VFwGuZeCZGb0Re4sfkGpuFv/LD6VmNvhCcy+O+sXrguMrMdJ3lQCvJQjhCqA=
c.example.\t3600\tIN\tNS\tns1.c.example.
c.example.\t3600\tIN\tNS\tns2.c.example.
ns1.c.example.\t3600\tIN\tA\t192.0.2.7
ns2.c.example.\t3600\tIN\tA\t192.0.2.8
gjeqe526plbf1g8mklp59enfd789njgi.example.\t3600\tIN\tNSEC3\t1 1 12 AABBCCDD JI6NEOAEPV8B5O6K4EV33ABHA8HT9FGC A HINFO AAAA RRSIG
gjeqe526plbf1g8mklp59enfd789njgi.example.\t3600\tIN\tRRSIG\tNSEC3 8 2 3600 20150420235959 20051021000000 38353 example. WOV1cBmmwlbTsR4qie8996TsFxWeYh0Q9CKNvHbTRtvNX2BHFa2K8583B+5x/GBOrHdZqFgSHXqkyAkD8y1gAj0cHzCUIvZhlGwHKtOlLk3lZBK0UdQGtWzbqRJBfoEZW9ZLuyWw1R67hxCkysPS2Mq4pHsXQgbQZZt4G7O/XwM=
ji6neoaepv8b5o6k4ev33abha8ht9fgc.example.\t3600\tIN\tNSEC3\t1 1 12 AABBCCDD K8UDEMVP1J2F7EG6JEBPS17VP3N8I58H
ji6neoaepv8b5o6k4ev33abha8ht9fgc.example.\t3600\tIN\tRRSIG\tNSEC3 8 2 3600 20150420235959 20051021000000 38353 example. J0QT2D31aTMBikuGbnGDTazPPx2fHNg3R8T6BPyNW+nX2qtI74BEdgFOsPUL7C3DlXPayWDYHFREXumHQldAb65X2N4EGblZVJ5HiVVxe4mqaGipckyWhvbNXTm3ITvvuCK6G+Q0XUMsQ2INb7wF9Qo1acd1b5cLLi1UNET3NPo=
k8udemvp1j2f7eg6jebps17vp3n8i58h.example.\t3600\tIN\tNSEC3\t1 1 12 AABBCCDD KOHAR7MBB8DC2CE8A9QVL8HON4K53UHI
k8udemvp1j2f7eg6jebps17vp3n8i58h.example.\t3600\tIN\tRRSIG\tNSEC3 8 2 3600 20150420235959 20051021000000 38353 example. s43tb7Gyh2lQ5wSKgxNMrP0HFJtjBuT+lzutMwoivhn4CMmJqYoOiMgtozsOg8OcG6mBZn6WqEC5y05CuHrHOirzGY55+Jp2B/I/RwVgWjWTA5qsjuqohgJjNnJDF1PpC+qVJZjdDU41+q/M63fiMvDBeJ5PAfqqdDLOxX/muGc=
kohar7mbb8dc2ce8a9qvl8hon4k53uhi.example.\t3600\tIN\tNSEC3\t1 1 12 AABBCCDD Q04JKCEVQVMU85R014C7DKBA38O0JI5R A RRSIG
kohar7mbb8dc2ce8a9qvl8hon4k53uhi.example.\t3600\tIN\tRRSIG\tNSEC3 8 2 3600 20150420235959 20051021000000 38353 example. iCIqnxLw7KsQZxj7MNPlEGlbU4SvoroyygNAILtzxgEY0qJflPEsV4lyjsJMNMPMvzlyzs4zAl2StBYF+Y9WDCJf5h1t/W0tB9oddfoLwtAEqukHFW6DIcoHuERjdqTVr3+fvcIJzwGAuT+TYuOucq/2aTwmludE1lhHBgOIjJU=
ns1.example.\t3600\tIN\tA\t192.0.2.1
ns1.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20150420235959 20051021000000 38353 example. i2ljZXbHVRHFrDI00jW8Ln6Pivq0S2cBS9TNBHoiiCvMR4cxE/jijDAqt7U/TqIHyu3lSK3tmLEZhCh9rWEXOzfLuzo6RfcXvg4V7lLXuLMRhvLjTn1+LmWHGaW6xnNkvapU8/bm2Ckriy3+05cTEsbpTJ9swf2Fg6Q2yDnn8ig=
ns2.example.\t3600\tIN\tA\t192.0.2.2
ns2.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20150420235959 20051021000000 38353 example. hnBX5fSoXikZeE903WDLD6o2u+1j+9mo+u5b1YRxlCvR1FPRnhV8byCTEpV8RyQdjN6YL/tCG+wyLDysdHiVkNMEQe8SIRTzJLXFD1OvvdpIe+tNA2yTEemrMEkJIDcQeXy5BqWQwZb+DckvOxwnAIsHgCidUGNVXQrqtC0hwJc=
q04jkcevqvmu85r014c7dkba38o0ji5r.example.\t3600\tIN\tNSEC3\t1 1 12 AABBCCDD R53BQ7CC2UVMUBFU5OCMM6PERS9TK9EN A RRSIG
q04jkcevqvmu85r014c7dkba38o0ji5r.example.\t3600\tIN\tRRSIG\tNSEC3 8 2 3600 20150420235959 20051021000000 38353 example. TolAxcK5GG0pkbK6DawH8immUjUF/HbrVlmD+QPB0te4JcawLHxARbigxoHQnwUNqhoU5CEj2f/ozPjWJ/F+sj3ZsLzC4dcGp4nMOE0cdP9SQ+5fxuq57/Aj26invkthydBMdk+kZSD5IDw2I4llR3Es+P1ZqA+qd4auIpcHsX4=
r53bq7cc2uvmubfu5ocmm6pers9tk9en.example.\t3600\tIN\tNSEC3\t1 1 12 AABBCCDD T644EBQK9BIBCNA874GIVR6JOJ62MLHV MX RRSIG
r53bq7cc2uvmubfu5ocmm6pers9tk9en.example.\t3600\tIN\tRRSIG\tNSEC3 8 2 3600 20150420235959 20051021000000 38353 example. CsWt2WIBFyVeGv5wE13EI3MyGa4lhoZIOBQQWphNLKeH7j5c5xKmaoeleKmsl2D1Ni1+sr8U5IwvWfHmjOqo0mo4zQdv6K/U6AcnwXd0hZ+jCWE0QNAJt4HJXC/7vBCeDcSZ1MJ95X24FxkToQRPFkboCoP/+9glOJAx6X+jnCE=
t644ebqk9bibcna874givr6joj62mlhv.example.\t3600\tIN\tNSEC3\t1 1 12 AABBCCDD 0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM A HINFO AAAA RRSIG
t644ebqk9bibcna874givr6joj62mlhv.example.\t3600\tIN\tRRSIG\tNSEC3 8 2 3600 20150420235959 20051021000000 38353 example. AI+9pSvUUyTVQiLMX0Iz/2yyL9CdFzOYYJkbYH6sJX7/649vikFsMSCTpz3UTBp17ubKtlr1sP5Xiu++RCXu0hL8k9AOBSzy1ZmCS3T24Nj20gzuueN77ov0NsVxAh/tyBJV5LoNG1TG7+AVbepsqVKOMvON4clunFHlbTCYueM=
*.w.example.\t3600\tIN\tMX\t1 ai.example.
*.w.example.\t3600\tIN\tRRSIG\tMX 8 2 3600 20150420235959 20051021000000 38353 example. OzXlQ4NOdqgULXY+nHuXWzomMR9WAha768A/zfm24C4/Ug5OIR0vkjNZ0Is2MoXPCMv2GI2X42BkIY9S60pjlJ26IITW8pzArt+xURsWfonw9/WF/mpa6r1IxXZ3QCWmS7aIrQ/sDw1u6UnsTJIaFZbE94DvyeU+/TZ8mN8tz2k=
x.w.example.\t3600\tIN\tMX\t1 xx.example.
x.w.example.\t3600\tIN\tRRSIG\tMX 8 3 3600 20150420235959 20051021000000 38353 example. nw5Z1G1XkM3R6uJNzohynT9cXnNwCDwORheT4aqmO3EcfJrrp6k5VjtdY5Bqtxo6FlCgybcsinZVdcIV+14374aQrvezjiZmiqECdCDHzO/X4XVaxk6ei5oj+22Pl4P6D3YLt6D+KlXZbdTmfRkgo8ZwQ9JceEYwvTrlPQw3ldQ=
x.y.w.example.\t3600\tIN\tMX\t1 xx.example.
x.y.w.example.\t3600\tIN\tRRSIG\tMX 8 4 3600 20150420235959 20051021000000 38353 example. fJTea7tirPJYIy10rt0PHyV08ZbfuyJ4dyh8B4ycCxiHZkRJgnNjTS4y+/csAKkaIvToub5f/ob53/4ZMg9f6SlTby6ybbwxY4bWoZsISXIjhw3mDdVm2FsJiz4r8hPQjTOLSE6wpZtbxgfwtXa7OiJbzgAuHg9KbgGk2PNPfns=
xx.example.\t3600\tIN\tA\t192.0.2.10
xx.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20150420235959 20051021000000 38353 example. ZPoxxa+U0ZI5Do7mJsq5rGC+bpUNTwRtTZJrr+tREhQn/AWKVwJGJFTitzn5akmusIk3RLGIfZPOLECMu6o+sF924qKA+M66ts98HfQP8b+duBd7kFW5I0hqtq0pcRDJm/tyFRgDRTas0puUzgNt4jud4CGFD0SM0h/MsWnxSnE=
xx.example.\t3600\tIN\tHINFO\t"KLH-10" "TOPS-20"
xx.example.\t3600\tIN\tRRSIG\tHINFO 8 2 3600 20150420235959 20051021000000 38353 example. qp2kpSTjHgc2xFZKH/iaek8ACNFzq7EFsVpiWSoJdyf5V1CIZY7SdxTe0k4W+zyzcGQOzC1u1ehWGmZeyIQYig+fOVZrnBFdJJcbQ9//JQnqcF6O2eGa5jMyLJQ8NceSK9dTMNj45KX1SlCaHwzCareLZip2obzaRyJqjvXtzl4=
xx.example.\t3600\tIN\tAAAA\t2001:db8::f00:baaa
xx.example.\t3600\tIN\tRRSIG\tAAAA 8 2 3600 20150420235959 20051021000000 38353 example. TX5v7Jnw/lo29b3jr0aSbRGUDrk/NJm/3mcdGgSXsIPObhEI82PGPLKpy6vTQDyoXVIMigG0XATN74gav/kF90aBsTRsm6ITKE09sccLR8OIg+lFaVtEjSroZBrBHRocWStD4yssaWrmhS/+g8IC3PTPEPXJDFkj46vK9Z/nlNU=
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc5155");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+31967");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+38353");

        // Use `dnst signzone` mode instead of `ldns-signzone` mode to get
        // more control via specific CLI arguments over the output format to
        // better match that of the example in RFC 4035 Appendix A without
        // also introducing extra comments that `ldns-signzone -b` adds.
        // Specifically the following options are used to make the output a
        // better match to that of RFC 5155 Appendix A:
        //
        //   -T outputs RRSIG timestamps in YYYYMMDDHHmmSS format. -L outputs
        //   NSEC3 hash mappings. -R orders RRSIGs after the records they
        //   sign.
        //
        // We use RSASHA256 (type 8) signing keys instead of RSASHA1 (type 5)
        // used by RFC 5155 Appendix A as we don't support type 5 (as it is
        // NOT RECOMMENDED by RFC 8624) and because RSASHA256 signatures are
        // consistent for the same input unlike ECDSAP256SHA256 for example.
        //
        // Signature validity period (expiration via `-e` and inception via
        // `-i`) and NSEC3 options (extra iterations via `-t12` and salt via
        // `-saabbccdd`) are set to match those in the RFC 5155 Appendix A
        // example.
        //
        // We use -P (note the capital) because without it the standard, ldns
        // based, opt-out behaviour is to include insecure delegations in the
        // NSEC3 chain but the RFC 5155 Appendix A signed zone assumes that
        // insecure delegations (such as c.example which lacks a DS record and
        // is thus an insecure delegation) are omitted from the NSEC3 chain.
        // Both behaviours are valid according to RFC 5155 as it states in
        // section 7.1 on Zone Signing: "Owner names that correspond to
        // unsigned delegations MAY have a corresponding NSEC3 RR", note the
        // "MAY".
        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-T",
            "-L",
            "-R",
            "-f-",
            "-e",
            "20150420235959",
            "-i",
            "20051021000000",
            "-n",
            "-t12",
            "-saabbccdd",
            "-P",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stdout, expected_signed_zone);
        // assert_eq!(res.stderr, ""); // Commented out due to NSEC3 iterations warning.
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn ldns_signzone_nsec_signed_zone_example_with_minus_b() {
        let expected_signed_zone = r###";; Zone: example.org.
;
example.org.\t239\tIN\tSOA\texample.net. hostmaster.example.net. 1234567890 28800 7200 604800 238
example.org.\t239\tIN\tRRSIG\tSOA 8 2 239 1429574399 1129852800 28954 example.org. V1LINcwCh6ulr9LBERp2zTUW4QfvoUKiv8VX5P8S03SZ9hdNk2BDLzNJj5TJj6o4ki708+DNzyqVHdz+EgyGUR9wH/vT9PxgRrKzjhJ35ktkKFLO+r08XxLMfZ7sCQrVYYr+LRpzDbzGqQby2fisMbNY8V4Lq3c7C7INP64peag=
;
example.org.\t238\tIN\tNSEC\tsome.example.org. SOA RRSIG NSEC DNSKEY
example.org.\t238\tIN\tRRSIG\tNSEC 8 2 238 1429574399 1129852800 28954 example.org. enga3YYnD/6JGZuWbiBWFeSGTKfV3wba/5UoYDeY43XPs5nN7BDWpDRTtksP4N8sRTlbmtzxxk7negGinm3XGDm+Pvxl651Q2Gujn6URX+vH+IDxkIYTcooVJTG1tEZqtKB/Nwa0kgmeO28Wf+/9XOT4gyqV2qTY6uOrnu9PE9w=
example.org.\t239\tIN\tDNSKEY\t256 3 8 AwEAAcCIpalbX67WU8Z+gI/oaeD0EjOt41Py++X1HQauTfSB5gwivbGwIsqA+Qf5+/j3gcuSFRbFzyPfAb5x14jy/TU3MWXGfmJsJX/DeTqiMwfTQTTlWgMdqRi7JuQoDx3ueYOQOLTDPVqlyvF5/g7b9FUd4LO8G3aO2FfqRBjNG8px ;{id = 28954 (zsk), size = 1024b}
example.org.\t239\tIN\tDNSKEY\t257 3 8 AwEAAckp/oMmocs+pv4KsCkCciazIl2+SohAZ2/bH2viAMg3tHAPjw5YfPNErUBqMGvN4c23iBCnt9TktT5bVoQdpXyCJ+ZwmWrFxlXvXIqG8rpkwHi1xFoXWVZLrG9XYCqLVMq2cB+FgMIaX504XMGk7WQydtV1LAqLgP3B8JA2Fc1j ;{id = 51331 (ksk), size = 1024b}
example.org.\t239\tIN\tRRSIG\tDNSKEY 8 2 239 1429574399 1129852800 51331 example.org. VBK2AFt1u3O0HIBjJrvQ2mo4aRnQcF5j1ibZ1FVpPoi6qtQ9MeL0B67AZJOcEgX080miM4IR+OujTooU1Npor8TIfx1nKr9Yamxzt1hrZkZz4eIbZ68bXPIBuLuvD/5Br4x0TcrXL+R6/QaRErPnbpB8WIBRohofoqMVFRR0Og0=
;
some.example.org.\t240\tIN\tA\t1.2.3.4
some.example.org.\t240\tIN\tRRSIG\tA 8 3 240 1429574399 1129852800 28954 example.org. HJ+HG8Z6jgSuzeBTbNtgLXO4QXXGNbrqijGfNrSIjqLJi1w8S/ADsiamh9Kua6EtwP653uYWmG34pA2mE8TDq6jjJp4ExCEs0fuYBsw7dkNiG++yh8oSr7jVHkYm3sQuDZC2984c4zIKolJD85dsGZ9Pp5b/YFdzQUj1nrhwIs8=
some.example.org.\t238\tIN\tNSEC\texample.org. A RRSIG NSEC
some.example.org.\t238\tIN\tRRSIG\tNSEC 8 3 238 1429574399 1129852800 28954 example.org. rkKQ2NCHw8tTQhxMDV+BvDThJC+mXUolpmjjVB7H1ziYDUhF18j4MbigGzQI9L6FXFPmwR6HIYexOnend0+2x2mHefnEGcoYVPVyRV6zTD4jFxJTy2l4mumEk8gPbTvN0Tgg4bMkWZWTeOivMmIcAXO+s06ICw2XKSq/LzL4kWc=
;
"###.replace("\\t", "\t");

        let zone_file_path =
            mk_test_data_abs_path_string("test-data/example.org.rfc9077-min-is-soa-minimum");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+51331");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+28954");

        // Signature validity period (expiration via `-e` and inception via
        // `-i`) are specified to make output matching more deterministic.
        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-f-",
            "-e",
            "20150420235959",
            "-i",
            "20051021000000",
            "-b",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_signed_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn dnst_signzone_nsec3_signed_zone_example_with_minus_b() {
        let expected_signed_zone = r###";; Zone: example.org.
;
example.org.\t239\tIN\tSOA\texample.net. hostmaster.example.net. 1234567890 28800 7200 604800 238
example.org.\t239\tIN\tRRSIG\tSOA 8 2 239 1429574399 1129852800 28954 example.org. V1LINcwCh6ulr9LBERp2zTUW4QfvoUKiv8VX5P8S03SZ9hdNk2BDLzNJj5TJj6o4ki708+DNzyqVHdz+EgyGUR9wH/vT9PxgRrKzjhJ35ktkKFLO+r08XxLMfZ7sCQrVYYr+LRpzDbzGqQby2fisMbNY8V4Lq3c7C7INP64peag=
;
example.org.\t239\tIN\tDNSKEY\t256 3 8 AwEAAcCIpalbX67WU8Z+gI/oaeD0EjOt41Py++X1HQauTfSB5gwivbGwIsqA+Qf5+/j3gcuSFRbFzyPfAb5x14jy/TU3MWXGfmJsJX/DeTqiMwfTQTTlWgMdqRi7JuQoDx3ueYOQOLTDPVqlyvF5/g7b9FUd4LO8G3aO2FfqRBjNG8px ;{id = 28954 (zsk), size = 1024b}
example.org.\t239\tIN\tDNSKEY\t257 3 8 AwEAAckp/oMmocs+pv4KsCkCciazIl2+SohAZ2/bH2viAMg3tHAPjw5YfPNErUBqMGvN4c23iBCnt9TktT5bVoQdpXyCJ+ZwmWrFxlXvXIqG8rpkwHi1xFoXWVZLrG9XYCqLVMq2cB+FgMIaX504XMGk7WQydtV1LAqLgP3B8JA2Fc1j ;{id = 51331 (ksk), size = 1024b}
example.org.\t239\tIN\tRRSIG\tDNSKEY 8 2 239 1429574399 1129852800 51331 example.org. VBK2AFt1u3O0HIBjJrvQ2mo4aRnQcF5j1ibZ1FVpPoi6qtQ9MeL0B67AZJOcEgX080miM4IR+OujTooU1Npor8TIfx1nKr9Yamxzt1hrZkZz4eIbZ68bXPIBuLuvD/5Br4x0TcrXL+R6/QaRErPnbpB8WIBRohofoqMVFRR0Og0=
example.org.\t239\tIN\tNSEC3PARAM\t1 0 0 -
example.org.\t239\tIN\tRRSIG\tNSEC3PARAM 8 2 239 1429574399 1129852800 28954 example.org. IHWhCUqMv3MqMfeQgKhqqSBHVBku1KWXR8kqwnYK2WIPh8lip3TQPvvp/30VWZmuzHy6ixgO35rmPLwQEJmUIkjFFhAR+YLdqOlxN0gxIU7t3kwyyjNsKlRZhiNTwb9dDGhaSkkae4zww9ZT9reZVIvDQ6y79hiriLYEB30o2QY=
;
8um1kjcjmofvvmq7cb0op7jt39lg8r9j.example.org.\t238\tIN\tNSEC3\t1 0 0 - VRCJ1RGALBB9EH2II8A43FBEIB1UFQF6 SOA RRSIG DNSKEY NSEC3PARAM  ;{ flags: -, from: example.org., to: some.example.org.}
8um1kjcjmofvvmq7cb0op7jt39lg8r9j.example.org.\t238\tIN\tRRSIG\tNSEC3 8 3 238 1429574399 1129852800 28954 example.org. O4eZ+kgHciA7xfgjHwM2OxREhwQr49bsTujdBFXNxwFmhlaB9kfMd8d+WIYSZLvhcchh5a8cOAsCc0FRmelEAAs3wh0LzWPjmzVsLIU3iM/dgjyYm524jD0HMJDw2OYo8d6RKeF2anCbA/ynno5OmJd8TZ/h1tZ5BTso/mtZckI=
;
some.example.org.\t240\tIN\tA\t1.2.3.4
some.example.org.\t240\tIN\tRRSIG\tA 8 3 240 1429574399 1129852800 28954 example.org. HJ+HG8Z6jgSuzeBTbNtgLXO4QXXGNbrqijGfNrSIjqLJi1w8S/ADsiamh9Kua6EtwP653uYWmG34pA2mE8TDq6jjJp4ExCEs0fuYBsw7dkNiG++yh8oSr7jVHkYm3sQuDZC2984c4zIKolJD85dsGZ9Pp5b/YFdzQUj1nrhwIs8=
;
vrcj1rgalbb9eh2ii8a43fbeib1ufqf6.example.org.\t238\tIN\tNSEC3\t1 0 0 - 8UM1KJCJMOFVVMQ7CB0OP7JT39LG8R9J A RRSIG  ;{ flags: -, from: some.example.org., to: example.org.}
vrcj1rgalbb9eh2ii8a43fbeib1ufqf6.example.org.\t238\tIN\tRRSIG\tNSEC3 8 3 238 1429574399 1129852800 28954 example.org. fpbF8OsVXpUwFzsTRmGmVcEJ5+h/5FrlyqO+goyUapRudSPS7Izxblz+RE3IRu1eYOdYdU62Sz9hnpRK2NCs7NuBacLRGKiudNI5fv/Z0XF3nELjM3TSk7WYfCOFAjgoEGK2OKZrNWUTONsdaFNeJbs/SyzW+77nbWYZ4Al16gQ=
;
"###.replace("\\t", "\t");

        let zone_file_path =
            mk_test_data_abs_path_string("test-data/example.org.rfc9077-min-is-soa-minimum");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+51331");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+28954");

        // Signature validity period (expiration via `-e` and inception via
        // `-i`) are specified to make output matching more deterministic.
        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-f-",
            "-e",
            "20150420235959",
            "-i",
            "20051021000000",
            "-b",
            "-n",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_signed_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn nsec_hash_only() {
        let expected_signed_zone = r###"example.\t3600\tIN\tSOA\tns1.example. bugs.x.w.example. 1 3600 300 3600000 3600
example.\t3600\tIN\tNS\tns1.example.
example.\t3600\tIN\tNS\tns2.example.
example.\t3600\tIN\tMX\t1 xx.example.
example.\t3600\tIN\tNSEC\t2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. NS SOA MX RRSIG NSEC DNSKEY
example.\t3600\tIN\tDNSKEY\t256 3 8 AwEAAbsD4Tcz8hl2Rldov4CrfYpK3ORIh/giSGDlZaDTZR4gpGxGvMBwu2jzQ3m0iX3PvqPoaybC4tznjlJi8g/qsCRHhOkqWmjtmOYOJXEuUTb+4tPBkiboJM5QchxTfKxkYbJ2AD+VAUX1S6h/0DI0ZCGx1H90QTBE2ymRgHBwUfBt
example.\t3600\tIN\tDNSKEY\t257 3 8 AwEAAaYL5iwWI6UgSQVcDZmH7DrhQU/P6cOfi4wXYDzHypsfZ1D8znPwoAqhj54kTBVqgZDHw8QEnMcS3TWxvHBvncRTIXhCLx0BNK5/6mcTSK2IDbxl0j4vkcQrOxc77tyExuFfuXouuKVtE7rggOJiX6ga5LJW2if6Jxe/Rh8+aJv7
2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.\t3600\tIN\tA\t192.0.2.127
2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.\t3600\tIN\tNSEC\ta.example. A RRSIG NSEC
a.example.\t3600\tIN\tNS\tns1.a.example.
a.example.\t3600\tIN\tNS\tns2.a.example.
a.example.\t3600\tIN\tDS\t58470 5 1 3079F1593EBAD6DC121E202A8B766A6A4837206C
a.example.\t3600\tIN\tNSEC\tai.example. NS DS RRSIG NSEC
ns1.a.example.\t3600\tIN\tA\t192.0.2.5
ns2.a.example.\t3600\tIN\tA\t192.0.2.6
ai.example.\t3600\tIN\tA\t192.0.2.9
ai.example.\t3600\tIN\tHINFO\t"KLH-10" "ITS"
ai.example.\t3600\tIN\tAAAA\t2001:db8::f00:baa9
ai.example.\t3600\tIN\tNSEC\tc.example. A HINFO AAAA RRSIG NSEC
c.example.\t3600\tIN\tNS\tns1.c.example.
c.example.\t3600\tIN\tNS\tns2.c.example.
c.example.\t3600\tIN\tNSEC\tns1.example. NS RRSIG NSEC
ns1.c.example.\t3600\tIN\tA\t192.0.2.7
ns2.c.example.\t3600\tIN\tA\t192.0.2.8
ns1.example.\t3600\tIN\tA\t192.0.2.1
ns1.example.\t3600\tIN\tNSEC\tns2.example. A RRSIG NSEC
ns2.example.\t3600\tIN\tA\t192.0.2.2
ns2.example.\t3600\tIN\tNSEC\t*.w.example. A RRSIG NSEC
*.w.example.\t3600\tIN\tMX\t1 ai.example.
*.w.example.\t3600\tIN\tNSEC\tx.w.example. MX RRSIG NSEC
x.w.example.\t3600\tIN\tMX\t1 xx.example.
x.w.example.\t3600\tIN\tNSEC\tx.y.w.example. MX RRSIG NSEC
x.y.w.example.\t3600\tIN\tMX\t1 xx.example.
x.y.w.example.\t3600\tIN\tNSEC\txx.example. MX RRSIG NSEC
xx.example.\t3600\tIN\tA\t192.0.2.10
xx.example.\t3600\tIN\tHINFO\t"KLH-10" "TOPS-20"
xx.example.\t3600\tIN\tAAAA\t2001:db8::f00:baaa
xx.example.\t3600\tIN\tNSEC\texample. A HINFO AAAA RRSIG NSEC
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc5155");

        let res = FakeCmd::new(["dnst", "signzone", "-f-", "-H", &zone_file_path]).run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_signed_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn nsec3_hash_only() {
        let expected_signed_zone = r###"example.\t3600\tIN\tSOA\tns1.example. bugs.x.w.example. 1 3600 300 3600000 3600
example.\t3600\tIN\tNS\tns1.example.
example.\t3600\tIN\tNS\tns2.example.
example.\t3600\tIN\tMX\t1 xx.example.
example.\t3600\tIN\tDNSKEY\t256 3 8 AwEAAbsD4Tcz8hl2Rldov4CrfYpK3ORIh/giSGDlZaDTZR4gpGxGvMBwu2jzQ3m0iX3PvqPoaybC4tznjlJi8g/qsCRHhOkqWmjtmOYOJXEuUTb+4tPBkiboJM5QchxTfKxkYbJ2AD+VAUX1S6h/0DI0ZCGx1H90QTBE2ymRgHBwUfBt
example.\t3600\tIN\tDNSKEY\t257 3 8 AwEAAaYL5iwWI6UgSQVcDZmH7DrhQU/P6cOfi4wXYDzHypsfZ1D8znPwoAqhj54kTBVqgZDHw8QEnMcS3TWxvHBvncRTIXhCLx0BNK5/6mcTSK2IDbxl0j4vkcQrOxc77tyExuFfuXouuKVtE7rggOJiX6ga5LJW2if6Jxe/Rh8+aJv7
example.\t3600\tIN\tNSEC3PARAM\t1 0 0 -
2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.\t3600\tIN\tA\t192.0.2.127
3msev9usmd4br9s97v51r2tdvmr9iqo1.example.\t3600\tIN\tNSEC3\t1 0 0 - 5E35TOOBFJ2A4I0CL6F4F893UD43PA93 NS SOA MX RRSIG DNSKEY NSEC3PARAM
5e35toobfj2a4i0cl6f4f893ud43pa93.example.\t3600\tIN\tNSEC3\t1 0 0 - 6CD522290VMA0NR8LQU1IVTCOFJ94RGA A RRSIG
6cd522290vma0nr8lqu1ivtcofj94rga.example.\t3600\tIN\tNSEC3\t1 0 0 - 9JS115EA61CHTVGNSDGK2LLDV5CEU01U NS DS RRSIG
9js115ea61chtvgnsdgk2lldv5ceu01u.example.\t3600\tIN\tNSEC3\t1 0 0 - A2BBV5G5D8IK754A2A44GDC113SC00DK
a.example.\t3600\tIN\tNS\tns1.a.example.
a.example.\t3600\tIN\tNS\tns2.a.example.
a.example.\t3600\tIN\tDS\t58470 5 1 3079F1593EBAD6DC121E202A8B766A6A4837206C
ns1.a.example.\t3600\tIN\tA\t192.0.2.5
ns2.a.example.\t3600\tIN\tA\t192.0.2.6
a2bbv5g5d8ik754a2a44gdc113sc00dk.example.\t3600\tIN\tNSEC3\t1 0 0 - ATUTAKMS2NNIOD8SIE19KMFB3UQD60KQ MX RRSIG
ai.example.\t3600\tIN\tA\t192.0.2.9
ai.example.\t3600\tIN\tHINFO\t"KLH-10" "ITS"
ai.example.\t3600\tIN\tAAAA\t2001:db8::f00:baa9
atutakms2nniod8sie19kmfb3uqd60kq.example.\t3600\tIN\tNSEC3\t1 0 0 - D8CM5M2D14EE3CI2UDFLRLK00604LNNK NS
c.example.\t3600\tIN\tNS\tns1.c.example.
c.example.\t3600\tIN\tNS\tns2.c.example.
ns1.c.example.\t3600\tIN\tA\t192.0.2.7
ns2.c.example.\t3600\tIN\tA\t192.0.2.8
d8cm5m2d14ee3ci2udflrlk00604lnnk.example.\t3600\tIN\tNSEC3\t1 0 0 - DSQ717D99RRRN3N4O1O20NTK5LDJKNT3 A HINFO AAAA RRSIG
dsq717d99rrrn3n4o1o20ntk5ldjknt3.example.\t3600\tIN\tNSEC3\t1 0 0 - L76MHQG6OA3A5SCU8LULA061NEPF70PH A RRSIG
l76mhqg6oa3a5scu8lula061nepf70ph.example.\t3600\tIN\tNSEC3\t1 0 0 - M1O89LFDO9RRF2F8R8SS42D81D09V48M A HINFO AAAA RRSIG
m1o89lfdo9rrf2f8r8ss42d81d09v48m.example.\t3600\tIN\tNSEC3\t1 0 0 - P9N5PTEVJSJOSKR5U50VC77GP9BDSCK8 A RRSIG
ns1.example.\t3600\tIN\tA\t192.0.2.1
ns2.example.\t3600\tIN\tA\t192.0.2.2
p9n5ptevjsjoskr5u50vc77gp9bdsck8.example.\t3600\tIN\tNSEC3\t1 0 0 - TF4V2JBVF5IQ28BHEOT32E5NSH2DBOF3 MX RRSIG
tf4v2jbvf5iq28bheot32e5nsh2dbof3.example.\t3600\tIN\tNSEC3\t1 0 0 - VDEC5SVARLB837SLN077FFSVBRJ6LV0Q
vdec5svarlb837sln077ffsvbrj6lv0q.example.\t3600\tIN\tNSEC3\t1 0 0 - 3MSEV9USMD4BR9S97V51R2TDVMR9IQO1 MX RRSIG
*.w.example.\t3600\tIN\tMX\t1 ai.example.
x.w.example.\t3600\tIN\tMX\t1 xx.example.
x.y.w.example.\t3600\tIN\tMX\t1 xx.example.
xx.example.\t3600\tIN\tA\t192.0.2.10
xx.example.\t3600\tIN\tHINFO\t"KLH-10" "TOPS-20"
xx.example.\t3600\tIN\tAAAA\t2001:db8::f00:baaa
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc5155");

        let res = FakeCmd::new(["dnst", "signzone", "-f-", "-n", "-H", &zone_file_path]).run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_signed_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn glue_records_should_not_be_nsec_hashed_or_signed() {
        // There should not be NSEC, NSEC3 or RRSIG RRs for A/AAAA RRs at glue
        // owner names.
        let expected_zone = r###"example.org.\t239\tIN\tSOA\texample.net. hostmaster.example.net. 1234567890 28800 7200 604800 238
example.org.\t239\tIN\tRRSIG\tSOA 8 2 239 20040509183619 20040409183619 28954 example.org. rKO4uWby08Xjz35KqY/6BX60e/4pJYKVkrOSVZ+smMWLn1QDN9sAf4JR5lwQs/SdnGuHqcJlMgmTGn3tObfywS4nmz5YYLRIvROhmZ931Ezu+uR5qY2HqqP/+kAjVw0rAeou/N3VKMY2nA5h0YWAEKsxpSWBcsH3JPUg/A447U0=
example.org.\t240\tIN\tA\t128.140.76.106
example.org.\t240\tIN\tRRSIG\tA 8 2 240 20040509183619 20040409183619 28954 example.org. ifMaJ6K8bma4RfwCA+zV3LoGD8H28/MTgVRdNZd/h3bkBLeAHeaLRQYfJ68f359lgMIq7uRtedFdxv+syKlXO4ad4WnNV7yMFWVIVBfltmkzJ6+PHRtk1465xtBe0J7hRLAd+pNIIEHrxUWq8EbB0Kt6I+xcMtKHtZsI6INDYmg=
example.org.\t1000\tIN\tNS\texample.net.
example.org.\t1000\tIN\tRRSIG\tNS 8 2 1000 20040509183619 20040409183619 28954 example.org. c/i5UigkjCw23eL0Mwntsv6jXptDjP7X932TfhsJwgU+PwO7N2axes1uMNffgOM/tZJCo8Gi0OEmrkaxcseOsUUezM3dsTF2QhNDdUJYzIN6UfiW4JEBF5hXnhbiuarBW38Dw+MCXqDf3s4Sgop3qiFmSS+XW7pjKvs+ZK0KFdQ=
example.org.\t238\tIN\tNSEC\tinsecure-deleg.example.org. A NS SOA RRSIG NSEC DNSKEY
example.org.\t238\tIN\tRRSIG\tNSEC 8 2 238 20040509183619 20040409183619 28954 example.org. ScErSL6LmEIrsVpqR0+Jw+TMjx32AsUq1tUK26ecNk//qRhWf9yvPuDSJ9zQc6eO7cFIL3nr6ZmJdEqaOwn+OoGQPORaKXn9q1CzpiT0hyC/SUdaIhWicdxTMgpwmj8u+/3+B2yW3jZdG+nPuJann70FJJZx7BRwMRheU3l7u74=
example.org.\t239\tIN\tDNSKEY\t256 3 8 AwEAAcCIpalbX67WU8Z+gI/oaeD0EjOt41Py++X1HQauTfSB5gwivbGwIsqA+Qf5+/j3gcuSFRbFzyPfAb5x14jy/TU3MWXGfmJsJX/DeTqiMwfTQTTlWgMdqRi7JuQoDx3ueYOQOLTDPVqlyvF5/g7b9FUd4LO8G3aO2FfqRBjNG8px ;{id = 28954 (zsk), size = 1024b}
example.org.\t239\tIN\tDNSKEY\t257 3 8 AwEAAckp/oMmocs+pv4KsCkCciazIl2+SohAZ2/bH2viAMg3tHAPjw5YfPNErUBqMGvN4c23iBCnt9TktT5bVoQdpXyCJ+ZwmWrFxlXvXIqG8rpkwHi1xFoXWVZLrG9XYCqLVMq2cB+FgMIaX504XMGk7WQydtV1LAqLgP3B8JA2Fc1j ;{id = 51331 (ksk), size = 1024b}
example.org.\t239\tIN\tRRSIG\tDNSKEY 8 2 239 20040509183619 20040409183619 51331 example.org. v/TJSG+fm2Cqgo5CMG7G9Oqm4WAYFf4rdyy+nP0HHKwkr26kLPd8EP7Ks2iq/vctR7eaO7KEubOf8GmdLTCmFlxKKtQwW0vP+mLssTmvJmiISCuHFlDEUP332nW3uLn0RCvFlUKzCNNdAhBMpRg9GTYa+WY7IN8kxt9CaewanyY=
insecure-deleg.example.org.\t240\tIN\tA\t1.1.1.1
insecure-deleg.example.org.\t240\tIN\tNS\texample.com.
insecure-deleg.example.org.\t240\tIN\tNS\tinsecure-deleg.example.org.
insecure-deleg.example.org.\t240\tIN\tAAAA\t::1
insecure-deleg.example.org.\t238\tIN\tNSEC\tsecure-deleg.example.org. NS RRSIG NSEC
insecure-deleg.example.org.\t238\tIN\tRRSIG\tNSEC 8 3 238 20040509183619 20040409183619 28954 example.org. Bo85edrZIAdZ3whoSMtaKcSHhXEhg3I4SQcRQtCl/Qf/OZdB8NiU4RDU36ld92IP8INuKYY10fwdmGrFNCRUwbglk6I/VQh098bvn4L2IwsetsIexV03QB9pOAtvLw3ptp5VtCxhSyLWBoe/VbDtdl7x1bTby3PuNX2x6atNXvo=
occluded.insecure-deleg.example.org.\t240\tIN\tA\t1.2.3.4
secure-deleg.example.org.\t240\tIN\tA\t1.1.1.1
secure-deleg.example.org.\t240\tIN\tNS\texample.com.
secure-deleg.example.org.\t240\tIN\tNS\tsecure-deleg.example.org.
secure-deleg.example.org.\t240\tIN\tAAAA\t::1
secure-deleg.example.org.\t240\tIN\tDS\t3120 15 2 0675D8C4A90ECD25492E4C4C6583AFCEF7C3B910B7A39162803058E6E7393A19
secure-deleg.example.org.\t240\tIN\tRRSIG\tDS 8 3 240 20040509183619 20040409183619 28954 example.org. W0uGbOEdJnb5hwKSkMIQ4RJj3lnAUqu0mIxfPr0+irCxjk6yRy1G0IuozMftG8k1hBxHNC2Ak+y/jPF54fXpYTe0ePyxw0sXTBZFJPwH3ZP8q7SPDx0gXlNoF9Rpq/VjSp0de0ru88OmARkqtq+cX5OdKxUrlj9M5DH2/8jltaA=
secure-deleg.example.org.\t238\tIN\tNSEC\texample.org. NS DS RRSIG NSEC
secure-deleg.example.org.\t238\tIN\tRRSIG\tNSEC 8 3 238 20040509183619 20040409183619 28954 example.org. FIGAoKOlz83oqWx8+ymMd22KO1nOOP5N8nb8A9fWL9Fdduw2GlxH79T1Js/SZy4J9fChTIzvgUToYXc8uwQqu0O01Zra+XyhfnHGv52Hl/JxoBQPj3OXXpEcphcm3lmc7zMBS8YtXxSBrpjciyy0MZWerQDcme6/dVzCZxPmF4o=
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.org");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+51331");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+28954");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-T",
            "-R",
            "-f-",
            "-e",
            "20040509183619",
            "-i",
            "20040409183619",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn glue_records_should_not_be_nsec3_hashed_or_signed() {
        // There should not be NSEC, NSEC3 or RRSIG RRs for A/AAAA RRs at glue
        // owner names.
        //
        // This test also showcases how TTLs are determined.
        //   - Existing RRs keep their current TTL.
        //   - RRSIG TTLs match that of the record they cover.
        //   - New RRs such as DNSKEYs are given the SOA RR TTL.
        //   - UNLESS they are NSEC(3) RRs in which case they are given the
        //     minimum of the SOA RR TTL and the SOA MINIMUM.
        //   - The $TTL value, if specified in the input zonefile, is used as
        //     the TTL of loaded RRs that lack a TTL, and will as above
        //     likewise be used by any generated covering RRSIG.
        let expected_zone = r###"example.org.\t239\tIN\tSOA\texample.net. hostmaster.example.net. 1234567890 28800 7200 604800 238
example.org.\t239\tIN\tRRSIG\tSOA 8 2 239 20240101010101 20240101010101 28954 example.org. EYeXeqDlGLECQSXWnwBDQlN7DaNejYhQ2whkBkhhQMl5JGGRqCGuWDK0VwUykTQnMkjqL1rbJaDlBvD6/9kZW+IoxEe7lMGksXCUjl0TGAg/qZvgHRSJ26z8BWfbCDqHlwQeIbqZBeg0W7fJBniGNnbp29hJJUbjaYPVg1RLNW8=
example.org.\t240\tIN\tA\t128.140.76.106
example.org.\t240\tIN\tRRSIG\tA 8 2 240 20240101010101 20240101010101 28954 example.org. Nc33Gu7E46O6+3/VjGySyu4c3X+E7gyrD9xDvfy2T0WY/z4Hgh7ia9adToN5IA6antpJqdaYW3qBrBZ1aEb8c0wfZygkD//PJCRKwZxDNrwCTOc4AK37xk6WH72Acs/0w20zhk8PUuCxCerVAdNpr0FRgIpiOq9nD1RjEtbsd6g=
example.org.\t1000\tIN\tNS\texample.net.
example.org.\t1000\tIN\tRRSIG\tNS 8 2 1000 20240101010101 20240101010101 28954 example.org. I5Aggj1a1IdCp+w50H+0s3jgGfVLYprhaXqJGX+fHX+XQsGg+JF0zxSYNNKDLxdLXsUmqroZSTD6UpOSpwS0QIptdEdSWBhLJgwIaqXpci6zmzwtr+rX4uJ34L/PUO1AZN7E5Q1CVgj+DcspPXoHeg+dl0m+o2sRd6PpdJuB0zo=
example.org.\t239\tIN\tDNSKEY\t256 3 8 AwEAAcCIpalbX67WU8Z+gI/oaeD0EjOt41Py++X1HQauTfSB5gwivbGwIsqA+Qf5+/j3gcuSFRbFzyPfAb5x14jy/TU3MWXGfmJsJX/DeTqiMwfTQTTlWgMdqRi7JuQoDx3ueYOQOLTDPVqlyvF5/g7b9FUd4LO8G3aO2FfqRBjNG8px ;{id = 28954 (zsk), size = 1024b}
example.org.\t239\tIN\tDNSKEY\t257 3 8 AwEAAckp/oMmocs+pv4KsCkCciazIl2+SohAZ2/bH2viAMg3tHAPjw5YfPNErUBqMGvN4c23iBCnt9TktT5bVoQdpXyCJ+ZwmWrFxlXvXIqG8rpkwHi1xFoXWVZLrG9XYCqLVMq2cB+FgMIaX504XMGk7WQydtV1LAqLgP3B8JA2Fc1j ;{id = 51331 (ksk), size = 1024b}
example.org.\t239\tIN\tRRSIG\tDNSKEY 8 2 239 20240101010101 20240101010101 51331 example.org. aWRFnYg77f8mAG0iSaHSBSJPNk5ZeAU3KVeQH6mPPOzP6FKA8Me5LkYi+cPhbaoJxVkYQEWtFo8DKSx4PBG+daB3dQdfRoR7o2gVawMr9r+SDEKnXfO0q92cb7m1oSWw9Xc512LViuPyKH2Yll4tSGZTOLQJzJ1CIhMYkm/M0HQ=
example.org.\t239\tIN\tNSEC3PARAM\t1 0 0 -
example.org.\t239\tIN\tRRSIG\tNSEC3PARAM 8 2 239 20240101010101 20240101010101 28954 example.org. SYie+jTjLhj8VNuq9dQEqDZ2RgMxvdmcPf2u/Ox4YsQYFzFDYReY8+viw2zMhQQmwwDE2UqbX1i4edhyYKymKqOlII14tg0AXMF9JOsus1wdTGARO0EpbEeCXhACrcdbps3WloUrpH54QkKwX1ykRrgXFEPmV4FQUXrboF+S1gs=
8um1kjcjmofvvmq7cb0op7jt39lg8r9j.example.org.\t238\tIN\tNSEC3\t1 0 0 - 91IALF4LB2F492UF8G331EVVRT8HQU5T A NS SOA RRSIG DNSKEY NSEC3PARAM
8um1kjcjmofvvmq7cb0op7jt39lg8r9j.example.org.\t238\tIN\tRRSIG\tNSEC3 8 3 238 20240101010101 20240101010101 28954 example.org. SEShQ9Kg2UaczhX9n/Kes8K3SrEfoTbBKOclJg1PJkeqsusuhWu0A1Gvmj2mAgqCxGBjXjt3Uavf6TxNs4KJn0KhBd2/sOixn/4RhzwSUyMnIYgeojA0k0uKA7PkOqDOiPyU3HtRfSSr7WfKrnmQHf3164nF9JKZmd0cMH22J1I=
91ialf4lb2f492uf8g331evvrt8hqu5t.example.org.\t238\tIN\tNSEC3\t1 0 0 - R35JQEBBC97RPOGPEPDIFHMBSJV6ISND NS DS RRSIG
91ialf4lb2f492uf8g331evvrt8hqu5t.example.org.\t238\tIN\tRRSIG\tNSEC3 8 3 238 20240101010101 20240101010101 28954 example.org. ruZKcW9CqFAdABy+YeA+0KtPpmnCM5X8doXE0lp2mSJz8XIPlDnwzQvEl+5JSjxpeGvrIDITSn8m4wn6HJ0FN2bIhmud/IbxosnhxnMMWIpPi0yHZjWo6aHUhSOUOmGbg8XKGthk4SxvZiYt/IWudthG17ClymKEJleEYT4Yoo8=
insecure-deleg.example.org.\t240\tIN\tA\t1.1.1.1
insecure-deleg.example.org.\t240\tIN\tNS\texample.com.
insecure-deleg.example.org.\t240\tIN\tNS\tinsecure-deleg.example.org.
insecure-deleg.example.org.\t240\tIN\tAAAA\t::1
occluded.insecure-deleg.example.org.\t240\tIN\tA\t1.2.3.4
r35jqebbc97rpogpepdifhmbsjv6isnd.example.org.\t238\tIN\tNSEC3\t1 0 0 - 8UM1KJCJMOFVVMQ7CB0OP7JT39LG8R9J NS
r35jqebbc97rpogpepdifhmbsjv6isnd.example.org.\t238\tIN\tRRSIG\tNSEC3 8 3 238 20240101010101 20240101010101 28954 example.org. T+jM8NIZjYh8LxUbvWT1aBnMRkl+30yG5VHath2QHyM8QdxOgcbrVlYg9usUjbdr/l6W1IJk9d6+cB7ZnCMuUBATSTA6Pj+327omYC5UuqQxpsusPke2SLa6vYDyHuMaRtWRn3PBy1bDyUbBadUtSG0x1kaWS7U/A/x89lRFBm0=
secure-deleg.example.org.\t240\tIN\tA\t1.1.1.1
secure-deleg.example.org.\t240\tIN\tNS\texample.com.
secure-deleg.example.org.\t240\tIN\tNS\tsecure-deleg.example.org.
secure-deleg.example.org.\t240\tIN\tAAAA\t::1
secure-deleg.example.org.\t240\tIN\tDS\t3120 15 2 0675D8C4A90ECD25492E4C4C6583AFCEF7C3B910B7A39162803058E6E7393A19
secure-deleg.example.org.\t240\tIN\tRRSIG\tDS 8 3 240 20240101010101 20240101010101 28954 example.org. FWhpg9GySyXsu//5l2jcnzIEx6e7pBnn1IqIR/oAUvosSKefOo41o7T+F0WUOOkcAa4VB7UvfRFp9fMdqzyRHMFqLeTjopBFg8qfE+lUaOxhOOp+AckGhWl1GLBX/A3nt+EKZJ75rYikEs6CYdX8co3Xn0/S9Z1CwEkzUtKK/fU=
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.org");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+51331");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+28954");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-T",
            "-R",
            "-f-",
            "-e",
            "20240101010101",
            "-i",
            "20240101010101",
            "-n",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn rfc_9077_nsec_ttl_minimum_select_soa_ttl() {
        // https://www.rfc-editor.org/rfc/rfc9077.html#section-3.2
        // 3.2.  Updates to RFC 4035
        //   ...
        //   "The TTL of the NSEC RR that is returned MUST be the lesser of
        //   the MINIMUM field of the SOA record and the TTL of the SOA
        //   itself. This matches the definition of the TTL for negative
        //   responses in [RFC2308]. Because some signers incrementally update
        //   the NSEC chain, a transient inconsistency between the observed
        //   and expected TTL MAY exist."
        let expected_zone = r###"example.org.\t238\tIN\tSOA\texample.net. hostmaster.example.net. 1234567890 28800 7200 604800 239
example.org.\t238\tIN\tRRSIG\tSOA 8 2 238 20240101010101 20240101010101 28954 example.org. C8kaFDeolgI0zDIKRext43cpcJlYPUxxxxK9e9aW75amnLXgaG+IWRqbKmky7bIAaV6FaLPOyj2e85C7iXF+KMhWdfYpIUZdqrWwMcLZawja/7ExzYhKgtetTTdnPEjVdKnzh7a/opreicQbsVl2RLkEvgIQYH19O96fUPU7dzI=
example.org.\t238\tIN\tNSEC\tsome.example.org. SOA RRSIG NSEC DNSKEY
example.org.\t238\tIN\tRRSIG\tNSEC 8 2 238 20240101010101 20240101010101 28954 example.org. svHOYxh5ix5ArcHQX/AdPRpfJN/hBWXw66u2JJpBXYl3Ee/r8o8Sf7aTWHZgjveWQvIuARnxNeIbTYbh9Lhi2HyIlOIK5XPh3Q/ehfHIyqLB9gQRCocPrel6VGVk6yp/4urM2Dc+5DJr19Hq1DfICiYA+zrLdM5xcu77e8bqfXg=
example.org.\t238\tIN\tDNSKEY\t256 3 8 AwEAAcCIpalbX67WU8Z+gI/oaeD0EjOt41Py++X1HQauTfSB5gwivbGwIsqA+Qf5+/j3gcuSFRbFzyPfAb5x14jy/TU3MWXGfmJsJX/DeTqiMwfTQTTlWgMdqRi7JuQoDx3ueYOQOLTDPVqlyvF5/g7b9FUd4LO8G3aO2FfqRBjNG8px ;{id = 28954 (zsk), size = 1024b}
example.org.\t238\tIN\tDNSKEY\t257 3 8 AwEAAckp/oMmocs+pv4KsCkCciazIl2+SohAZ2/bH2viAMg3tHAPjw5YfPNErUBqMGvN4c23iBCnt9TktT5bVoQdpXyCJ+ZwmWrFxlXvXIqG8rpkwHi1xFoXWVZLrG9XYCqLVMq2cB+FgMIaX504XMGk7WQydtV1LAqLgP3B8JA2Fc1j ;{id = 51331 (ksk), size = 1024b}
example.org.\t238\tIN\tRRSIG\tDNSKEY 8 2 238 20240101010101 20240101010101 51331 example.org. Q74Mi168vo15haY1hUwWx1TcFsR0VwxSncMtAvF26OeIuTKVuM6J/m2ZqJ30zJe1jDYmZgLoD+m14VMING+CSrUDGnX/g30W5SGMY3iw6Xk4KnMTaAjEpcWD1bGYWlIch1vlK1Mkf7gJSE0GmLJbwBZ4yt5HkWxy7nrKEssQcrA=
some.example.org.\t240\tIN\tA\t1.2.3.4
some.example.org.\t240\tIN\tRRSIG\tA 8 3 240 20240101010101 20240101010101 28954 example.org. tJysnYa9fLWD0g9dhR24i/uVv9hNi+GdqTgUm6H9UvXgOoJverUQYSFd+Q5b8h94QwlykG0FEQ5BITIkIpwrIoMPs4Y2m4cID3C1bGeLPD3FOFFZhia7z8+6JsppF0VmDBPbozgbpVhWwO8vWxpKdxYynfkfQnwKe7tkzUdjn1U=
some.example.org.\t238\tIN\tNSEC\texample.org. A RRSIG NSEC
some.example.org.\t238\tIN\tRRSIG\tNSEC 8 3 238 20240101010101 20240101010101 28954 example.org. ZS1zp9zED/2nFX6bej6bRuzi0E0fQ97RpmfNSWlCZb9GsxQJa7NP+IX61pQJmLHwbhg6evGblkzHK6YdhzzH4Qy2eRuk8OmwFiyNiwUVswHsTsW5zPpGUMJe41MvYi22oSTUhtyJ2Xo4hfZ+wMfUnKV00GRrWXUQohXbbpOnHAo=
"###.replace("\\t", "\t");

        let zone_file_path =
            mk_test_data_abs_path_string("test-data/example.org.rfc9077-min-is-soa-ttl");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+51331");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+28954");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-T",
            "-R",
            "-f-",
            "-e",
            "20240101010101",
            "-i",
            "20240101010101",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn rfc_9077_nsec_ttl_minimum_select_soa_minimum() {
        // https://www.rfc-editor.org/rfc/rfc9077.html#section-3.2
        // 3.2.  Updates to RFC 4035
        //   ...
        //   "The TTL of the NSEC RR that is returned MUST be the lesser of
        //   the MINIMUM field of the SOA record and the TTL of the SOA
        //   itself. This matches the definition of the TTL for negative
        //   responses in [RFC2308]. Because some signers incrementally update
        //   the NSEC chain, a transient inconsistency between the observed
        //   and expected TTL MAY exist."
        let expected_zone = r###"example.org.\t239\tIN\tSOA\texample.net. hostmaster.example.net. 1234567890 28800 7200 604800 238
example.org.\t239\tIN\tRRSIG\tSOA 8 2 239 20240101010101 20240101010101 28954 example.org. EYeXeqDlGLECQSXWnwBDQlN7DaNejYhQ2whkBkhhQMl5JGGRqCGuWDK0VwUykTQnMkjqL1rbJaDlBvD6/9kZW+IoxEe7lMGksXCUjl0TGAg/qZvgHRSJ26z8BWfbCDqHlwQeIbqZBeg0W7fJBniGNnbp29hJJUbjaYPVg1RLNW8=
example.org.\t238\tIN\tNSEC\tsome.example.org. SOA RRSIG NSEC DNSKEY
example.org.\t238\tIN\tRRSIG\tNSEC 8 2 238 20240101010101 20240101010101 28954 example.org. svHOYxh5ix5ArcHQX/AdPRpfJN/hBWXw66u2JJpBXYl3Ee/r8o8Sf7aTWHZgjveWQvIuARnxNeIbTYbh9Lhi2HyIlOIK5XPh3Q/ehfHIyqLB9gQRCocPrel6VGVk6yp/4urM2Dc+5DJr19Hq1DfICiYA+zrLdM5xcu77e8bqfXg=
example.org.\t239\tIN\tDNSKEY\t256 3 8 AwEAAcCIpalbX67WU8Z+gI/oaeD0EjOt41Py++X1HQauTfSB5gwivbGwIsqA+Qf5+/j3gcuSFRbFzyPfAb5x14jy/TU3MWXGfmJsJX/DeTqiMwfTQTTlWgMdqRi7JuQoDx3ueYOQOLTDPVqlyvF5/g7b9FUd4LO8G3aO2FfqRBjNG8px ;{id = 28954 (zsk), size = 1024b}
example.org.\t239\tIN\tDNSKEY\t257 3 8 AwEAAckp/oMmocs+pv4KsCkCciazIl2+SohAZ2/bH2viAMg3tHAPjw5YfPNErUBqMGvN4c23iBCnt9TktT5bVoQdpXyCJ+ZwmWrFxlXvXIqG8rpkwHi1xFoXWVZLrG9XYCqLVMq2cB+FgMIaX504XMGk7WQydtV1LAqLgP3B8JA2Fc1j ;{id = 51331 (ksk), size = 1024b}
example.org.\t239\tIN\tRRSIG\tDNSKEY 8 2 239 20240101010101 20240101010101 51331 example.org. aWRFnYg77f8mAG0iSaHSBSJPNk5ZeAU3KVeQH6mPPOzP6FKA8Me5LkYi+cPhbaoJxVkYQEWtFo8DKSx4PBG+daB3dQdfRoR7o2gVawMr9r+SDEKnXfO0q92cb7m1oSWw9Xc512LViuPyKH2Yll4tSGZTOLQJzJ1CIhMYkm/M0HQ=
some.example.org.\t240\tIN\tA\t1.2.3.4
some.example.org.\t240\tIN\tRRSIG\tA 8 3 240 20240101010101 20240101010101 28954 example.org. tJysnYa9fLWD0g9dhR24i/uVv9hNi+GdqTgUm6H9UvXgOoJverUQYSFd+Q5b8h94QwlykG0FEQ5BITIkIpwrIoMPs4Y2m4cID3C1bGeLPD3FOFFZhia7z8+6JsppF0VmDBPbozgbpVhWwO8vWxpKdxYynfkfQnwKe7tkzUdjn1U=
some.example.org.\t238\tIN\tNSEC\texample.org. A RRSIG NSEC
some.example.org.\t238\tIN\tRRSIG\tNSEC 8 3 238 20240101010101 20240101010101 28954 example.org. ZS1zp9zED/2nFX6bej6bRuzi0E0fQ97RpmfNSWlCZb9GsxQJa7NP+IX61pQJmLHwbhg6evGblkzHK6YdhzzH4Qy2eRuk8OmwFiyNiwUVswHsTsW5zPpGUMJe41MvYi22oSTUhtyJ2Xo4hfZ+wMfUnKV00GRrWXUQohXbbpOnHAo=
"###.replace("\\t", "\t");

        let zone_file_path =
            mk_test_data_abs_path_string("test-data/example.org.rfc9077-min-is-soa-minimum");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+51331");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+28954");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-T",
            "-R",
            "-f-",
            "-e",
            "20240101010101",
            "-i",
            "20240101010101",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn rfc_9077_nsec3_ttl_minimum_select_soa_ttl() {
        // https://www.rfc-editor.org/rfc/rfc9077.html#section-3.2
        // 3.3.  Updates to RFC 5155
        //   ...
        //   "The TTL value for each NSEC3 RR MUST be the lesser of the
        //   MINIMUM field of the zone SOA RR and the TTL of the zone SOA RR
        //   itself. Because some signers incrementally update the NSEC3
        //   chain, a transient inconsistency between the observed and
        //   expected TTL MAY exist."
        let expected_zone = r###"example.org.\t238\tIN\tSOA\texample.net. hostmaster.example.net. 1234567890 28800 7200 604800 239
example.org.\t238\tIN\tRRSIG\tSOA 8 2 238 20240101010101 20240101010101 28954 example.org. C8kaFDeolgI0zDIKRext43cpcJlYPUxxxxK9e9aW75amnLXgaG+IWRqbKmky7bIAaV6FaLPOyj2e85C7iXF+KMhWdfYpIUZdqrWwMcLZawja/7ExzYhKgtetTTdnPEjVdKnzh7a/opreicQbsVl2RLkEvgIQYH19O96fUPU7dzI=
example.org.\t238\tIN\tDNSKEY\t256 3 8 AwEAAcCIpalbX67WU8Z+gI/oaeD0EjOt41Py++X1HQauTfSB5gwivbGwIsqA+Qf5+/j3gcuSFRbFzyPfAb5x14jy/TU3MWXGfmJsJX/DeTqiMwfTQTTlWgMdqRi7JuQoDx3ueYOQOLTDPVqlyvF5/g7b9FUd4LO8G3aO2FfqRBjNG8px ;{id = 28954 (zsk), size = 1024b}
example.org.\t238\tIN\tDNSKEY\t257 3 8 AwEAAckp/oMmocs+pv4KsCkCciazIl2+SohAZ2/bH2viAMg3tHAPjw5YfPNErUBqMGvN4c23iBCnt9TktT5bVoQdpXyCJ+ZwmWrFxlXvXIqG8rpkwHi1xFoXWVZLrG9XYCqLVMq2cB+FgMIaX504XMGk7WQydtV1LAqLgP3B8JA2Fc1j ;{id = 51331 (ksk), size = 1024b}
example.org.\t238\tIN\tRRSIG\tDNSKEY 8 2 238 20240101010101 20240101010101 51331 example.org. Q74Mi168vo15haY1hUwWx1TcFsR0VwxSncMtAvF26OeIuTKVuM6J/m2ZqJ30zJe1jDYmZgLoD+m14VMING+CSrUDGnX/g30W5SGMY3iw6Xk4KnMTaAjEpcWD1bGYWlIch1vlK1Mkf7gJSE0GmLJbwBZ4yt5HkWxy7nrKEssQcrA=
example.org.\t238\tIN\tNSEC3PARAM\t1 0 0 -
example.org.\t238\tIN\tRRSIG\tNSEC3PARAM 8 2 238 20240101010101 20240101010101 28954 example.org. ulr1pnf3/Um1/2KYz20+AT3aEtTlQPVBzZiDrgi87pEjiXOLm6gg2tfQ/trDGWRg3TYUbGsSrU8k6cPWB/R242gMCiKxJvgLfw9jmF8K6fDCstFLfiNB9GGNu5tyvaowglN3aVPIqsCeHRADPXNRd9QKRDX0pDft8mc/McqTM2Y=
8um1kjcjmofvvmq7cb0op7jt39lg8r9j.example.org.\t238\tIN\tNSEC3\t1 0 0 - VRCJ1RGALBB9EH2II8A43FBEIB1UFQF6 SOA RRSIG DNSKEY NSEC3PARAM
8um1kjcjmofvvmq7cb0op7jt39lg8r9j.example.org.\t238\tIN\tRRSIG\tNSEC3 8 3 238 20240101010101 20240101010101 28954 example.org. UAWDADL4eJ8eva4RDOlMaR+ronXYRWD+m1yrm5O+/h6tOToOLAovl5vra0kVOp5Bo5hxs2+KCtnh62yrG7LnJRFlDkNHfVmP4NekfCl6E7xsLKcB98ry1vu/G+KSqOl6AMq74hRbV0p9xLcYEOzW8Vpj8cEJgB4UIJFYBpFbMI4=
some.example.org.\t240\tIN\tA\t1.2.3.4
some.example.org.\t240\tIN\tRRSIG\tA 8 3 240 20240101010101 20240101010101 28954 example.org. tJysnYa9fLWD0g9dhR24i/uVv9hNi+GdqTgUm6H9UvXgOoJverUQYSFd+Q5b8h94QwlykG0FEQ5BITIkIpwrIoMPs4Y2m4cID3C1bGeLPD3FOFFZhia7z8+6JsppF0VmDBPbozgbpVhWwO8vWxpKdxYynfkfQnwKe7tkzUdjn1U=
vrcj1rgalbb9eh2ii8a43fbeib1ufqf6.example.org.\t238\tIN\tNSEC3\t1 0 0 - 8UM1KJCJMOFVVMQ7CB0OP7JT39LG8R9J A RRSIG
vrcj1rgalbb9eh2ii8a43fbeib1ufqf6.example.org.\t238\tIN\tRRSIG\tNSEC3 8 3 238 20240101010101 20240101010101 28954 example.org. QOql1jm9CY+x/2p9F2eRz+7VwT6aojPqqKqAOHPYfUwYHS9lMWpIdfkxqWVFA9Q7Azo/B8yYw5FvE+A5LL2hpmtPk4hlwpQgOuh8RpNjyTNzryvFfP8xFzMZqDnOP+I6oDn+fDTWBHzjs2IkTPJz3Q5fEcqLPqfZHEyxMUjY3Aw=
"###.replace("\\t", "\t");

        let zone_file_path =
            mk_test_data_abs_path_string("test-data/example.org.rfc9077-min-is-soa-ttl");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+51331");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+28954");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-T",
            "-R",
            "-f-",
            "-e",
            "20240101010101",
            "-i",
            "20240101010101",
            "-n",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn rfc_9077_nsec3_ttl_minimum_select_soa_minimum() {
        // https://www.rfc-editor.org/rfc/rfc9077.html#section-3.2
        // 3.3.  Updates to RFC 5155
        //   ...
        //   "The TTL value for each NSEC3 RR MUST be the lesser of the
        //   MINIMUM field of the zone SOA RR and the TTL of the zone SOA RR
        //   itself. Because some signers incrementally update the NSEC3
        //   chain, a transient inconsistency between the observed and
        //   expected TTL MAY exist."
        let expected_zone = r###"example.org.\t239\tIN\tSOA\texample.net. hostmaster.example.net. 1234567890 28800 7200 604800 238
example.org.\t239\tIN\tRRSIG\tSOA 8 2 239 20240101010101 20240101010101 28954 example.org. EYeXeqDlGLECQSXWnwBDQlN7DaNejYhQ2whkBkhhQMl5JGGRqCGuWDK0VwUykTQnMkjqL1rbJaDlBvD6/9kZW+IoxEe7lMGksXCUjl0TGAg/qZvgHRSJ26z8BWfbCDqHlwQeIbqZBeg0W7fJBniGNnbp29hJJUbjaYPVg1RLNW8=
example.org.\t239\tIN\tDNSKEY\t256 3 8 AwEAAcCIpalbX67WU8Z+gI/oaeD0EjOt41Py++X1HQauTfSB5gwivbGwIsqA+Qf5+/j3gcuSFRbFzyPfAb5x14jy/TU3MWXGfmJsJX/DeTqiMwfTQTTlWgMdqRi7JuQoDx3ueYOQOLTDPVqlyvF5/g7b9FUd4LO8G3aO2FfqRBjNG8px ;{id = 28954 (zsk), size = 1024b}
example.org.\t239\tIN\tDNSKEY\t257 3 8 AwEAAckp/oMmocs+pv4KsCkCciazIl2+SohAZ2/bH2viAMg3tHAPjw5YfPNErUBqMGvN4c23iBCnt9TktT5bVoQdpXyCJ+ZwmWrFxlXvXIqG8rpkwHi1xFoXWVZLrG9XYCqLVMq2cB+FgMIaX504XMGk7WQydtV1LAqLgP3B8JA2Fc1j ;{id = 51331 (ksk), size = 1024b}
example.org.\t239\tIN\tRRSIG\tDNSKEY 8 2 239 20240101010101 20240101010101 51331 example.org. aWRFnYg77f8mAG0iSaHSBSJPNk5ZeAU3KVeQH6mPPOzP6FKA8Me5LkYi+cPhbaoJxVkYQEWtFo8DKSx4PBG+daB3dQdfRoR7o2gVawMr9r+SDEKnXfO0q92cb7m1oSWw9Xc512LViuPyKH2Yll4tSGZTOLQJzJ1CIhMYkm/M0HQ=
example.org.\t239\tIN\tNSEC3PARAM\t1 0 0 -
example.org.\t239\tIN\tRRSIG\tNSEC3PARAM 8 2 239 20240101010101 20240101010101 28954 example.org. SYie+jTjLhj8VNuq9dQEqDZ2RgMxvdmcPf2u/Ox4YsQYFzFDYReY8+viw2zMhQQmwwDE2UqbX1i4edhyYKymKqOlII14tg0AXMF9JOsus1wdTGARO0EpbEeCXhACrcdbps3WloUrpH54QkKwX1ykRrgXFEPmV4FQUXrboF+S1gs=
8um1kjcjmofvvmq7cb0op7jt39lg8r9j.example.org.\t238\tIN\tNSEC3\t1 0 0 - VRCJ1RGALBB9EH2II8A43FBEIB1UFQF6 SOA RRSIG DNSKEY NSEC3PARAM
8um1kjcjmofvvmq7cb0op7jt39lg8r9j.example.org.\t238\tIN\tRRSIG\tNSEC3 8 3 238 20240101010101 20240101010101 28954 example.org. UAWDADL4eJ8eva4RDOlMaR+ronXYRWD+m1yrm5O+/h6tOToOLAovl5vra0kVOp5Bo5hxs2+KCtnh62yrG7LnJRFlDkNHfVmP4NekfCl6E7xsLKcB98ry1vu/G+KSqOl6AMq74hRbV0p9xLcYEOzW8Vpj8cEJgB4UIJFYBpFbMI4=
some.example.org.\t240\tIN\tA\t1.2.3.4
some.example.org.\t240\tIN\tRRSIG\tA 8 3 240 20240101010101 20240101010101 28954 example.org. tJysnYa9fLWD0g9dhR24i/uVv9hNi+GdqTgUm6H9UvXgOoJverUQYSFd+Q5b8h94QwlykG0FEQ5BITIkIpwrIoMPs4Y2m4cID3C1bGeLPD3FOFFZhia7z8+6JsppF0VmDBPbozgbpVhWwO8vWxpKdxYynfkfQnwKe7tkzUdjn1U=
vrcj1rgalbb9eh2ii8a43fbeib1ufqf6.example.org.\t238\tIN\tNSEC3\t1 0 0 - 8UM1KJCJMOFVVMQ7CB0OP7JT39LG8R9J A RRSIG
vrcj1rgalbb9eh2ii8a43fbeib1ufqf6.example.org.\t238\tIN\tRRSIG\tNSEC3 8 3 238 20240101010101 20240101010101 28954 example.org. QOql1jm9CY+x/2p9F2eRz+7VwT6aojPqqKqAOHPYfUwYHS9lMWpIdfkxqWVFA9Q7Azo/B8yYw5FvE+A5LL2hpmtPk4hlwpQgOuh8RpNjyTNzryvFfP8xFzMZqDnOP+I6oDn+fDTWBHzjs2IkTPJz3Q5fEcqLPqfZHEyxMUjY3Aw=
"###.replace("\\t", "\t");

        let zone_file_path =
            mk_test_data_abs_path_string("test-data/example.org.rfc9077-min-is-soa-minimum");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+51331");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+28954");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-T",
            "-R",
            "-f-",
            "-e",
            "20240101010101",
            "-i",
            "20240101010101",
            "-n",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn multiple_algorithms_no_sign_with_every_unique_algorithm() {
        let expected_zone = r###"example.\t86400\tIN\tSOA\tns1.example. admin.example. 2018031900 1800 900 604800 86400
example.\t86400\tIN\tRRSIG\tSOA 15 1 86400 20240101010101 20240101010101 39188 example. ckYQDK2HeLK09CjpO76H0oT5CGjc6WcKYihl0zkS79VYzcj2Cspifcf3V5Sft8QDmGzjtBqqQvGYPsbzZwlYCQ==
example.\t86400\tIN\tNS\tns1.example.
example.\t86400\tIN\tNS\tns2.example.
example.\t86400\tIN\tRRSIG\tNS 15 1 86400 20240101010101 20240101010101 39188 example. A06Y3VSm8/G3YhuxJ3yHNI71iTi9UcyG8zIp7bHuXkhhSFDT4kRQMahlaNRP30HvaJDBJz9vy9hXmmbuc28cCQ==
example.\t86400\tIN\tNSEC\tns1.example. NS SOA RRSIG NSEC DNSKEY
example.\t86400\tIN\tRRSIG\tNSEC 15 1 86400 20240101010101 20240101010101 39188 example. R3mhoKHFOusQOU0l6vn7vvUPGLnkoOeYQ9o2HmcsQ3PxVpJ1+oQc7igxycgQLw9JLSIz8p2vjPXfQBm+7qE+AQ==
example.\t86400\tIN\tDNSKEY\t256 3 15 AnxyASt7Bws/Y883BjIsK+Vcl2rlR7fnGqoVHf+wY5o= ;{id = 39188 (zsk), size = 256b}
example.\t86400\tIN\tDNSKEY\t257 3 8 AwEAAaYL5iwWI6UgSQVcDZmH7DrhQU/P6cOfi4wXYDzHypsfZ1D8znPwoAqhj54kTBVqgZDHw8QEnMcS3TWxvHBvncRTIXhCLx0BNK5/6mcTSK2IDbxl0j4vkcQrOxc77tyExuFfuXouuKVtE7rggOJiX6ga5LJW2if6Jxe/Rh8+aJv7 ;{id = 31967 (ksk), size = 1024b}
example.\t86400\tIN\tRRSIG\tDNSKEY 8 1 86400 20240101010101 20240101010101 31967 example. N0YniZN9ZZqFh6xzB+q63GpRNfC8SGWmCB7GovxoLdM7czL7g7Sd7ADAvLqrwguFa4aPoT/dof8NBphh4a4DpQjfcp6AIRAUMUQxA5ELsNN6vvLK2HM8EIN6d7J8H0uyEcDs2b0X84Zgyl5Peg9L8BRfReORU9eyUgexOmO8TGs=
ns1.example.\t3600\tIN\tA\t203.0.113.63
ns1.example.\t3600\tIN\tRRSIG\tA 15 2 3600 20240101010101 20240101010101 39188 example. LVmEy45TIoFZgoSryXQbZjUCLpwYUerR2nt9EK6WcSgIkeGkj3IDRGqQfQVyrutjohhlxdkDnFBE4dT5nBwnBg==
ns1.example.\t86400\tIN\tNSEC\tns2.example. A RRSIG NSEC
ns1.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 39188 example. GqyC25UtODem9X3uVI5gLQ/OLFBvSwdA/bwnj1jB8qP9NhD03bLDfuKzm8QvSJvkq7ERBcHibpEL+lZUL5HrDw==
ns2.example.\t3600\tIN\tAAAA\t2001:db8::63
ns2.example.\t3600\tIN\tRRSIG\tAAAA 15 2 3600 20240101010101 20240101010101 39188 example. Fikp9s+ht+B9ncP0GsjWce3Oz2wtixNl8RZAZe+95kaHEL2w+hfNSO30ox8dTPOe5Yih0jJTu1bMmvRySbVXCg==
ns2.example.\t86400\tIN\tNSEC\texample. AAAA RRSIG NSEC
ns2.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 39188 example. fTkEc85fTdlicaZ/D6YIbMpaZFFZdbpA98vyPjZfCC2aoXvFjTl/RmigLd0L0hMSYW+jIlSANzzKYO7Oj7iFDA==
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc8976-simple");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+31967");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.+015+39188");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-oexample",
            "-T",
            "-R",
            "-f-",
            "-e",
            "20240101010101",
            "-i",
            "20240101010101",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn multiple_algorithms_with_sign_with_every_unique_algorithm() {
        let expected_zone = r###"example.\t86400\tIN\tSOA\tns1.example. admin.example. 2018031900 1800 900 604800 86400
example.\t86400\tIN\tRRSIG\tSOA 8 1 86400 20240101010101 20240101010101 31967 example. kKRK3zSRGnsHEZqZpCacJHW6U/xWafetom45QQrLCdIZF8wV6b5T8x9X//fbb13X0GNrzsDxXzwDm/Nz9EbS5fOMKe/uh7eIiWpvdUIkApSwWQmNJXr7zHBBqfdk9C7+NraWAj5Dkd7hqHfvFbgBJDN1T3rCMywyxEeO+0RHkUs=
example.\t86400\tIN\tRRSIG\tSOA 15 1 86400 20240101010101 20240101010101 39188 example. ckYQDK2HeLK09CjpO76H0oT5CGjc6WcKYihl0zkS79VYzcj2Cspifcf3V5Sft8QDmGzjtBqqQvGYPsbzZwlYCQ==
example.\t86400\tIN\tNS\tns1.example.
example.\t86400\tIN\tNS\tns2.example.
example.\t86400\tIN\tRRSIG\tNS 8 1 86400 20240101010101 20240101010101 31967 example. ow1ECVYGToR7Wd+RKlHpCjYgc3Vl4VmS4b3oZBhLp+ASMXwG58rPS1q79X0z4Zu/7UvucIk7jTS3RYQsJpd5SYahXVwG9Tg3SPy5sD498kyvaczRcMmrgF+MtKf4BFIcBO2Id0g+6ELxplkID1/mStbNlBP9IDoumWpxgeKHct4=
example.\t86400\tIN\tRRSIG\tNS 15 1 86400 20240101010101 20240101010101 39188 example. A06Y3VSm8/G3YhuxJ3yHNI71iTi9UcyG8zIp7bHuXkhhSFDT4kRQMahlaNRP30HvaJDBJz9vy9hXmmbuc28cCQ==
example.\t86400\tIN\tNSEC\tns1.example. NS SOA RRSIG NSEC DNSKEY
example.\t86400\tIN\tRRSIG\tNSEC 8 1 86400 20240101010101 20240101010101 31967 example. igfv+N3fWG9tlHwJLvbRH9R+CfpoDF+m7exyW5nbcRu6/bX39E8W/REzz11ib7CaFOKXfVn7AZ1aJTOGIF5fYQkgNCZwUX6G3dEuwCAbex0UnZLdw++AcqDiqkfVh95F6+GBLhNDZJh4uklQLEo8yfg1HtJfgrOtPpthMt52Mz4=
example.\t86400\tIN\tRRSIG\tNSEC 15 1 86400 20240101010101 20240101010101 39188 example. R3mhoKHFOusQOU0l6vn7vvUPGLnkoOeYQ9o2HmcsQ3PxVpJ1+oQc7igxycgQLw9JLSIz8p2vjPXfQBm+7qE+AQ==
example.\t86400\tIN\tDNSKEY\t256 3 15 AnxyASt7Bws/Y883BjIsK+Vcl2rlR7fnGqoVHf+wY5o= ;{id = 39188 (zsk), size = 256b}
example.\t86400\tIN\tDNSKEY\t257 3 8 AwEAAaYL5iwWI6UgSQVcDZmH7DrhQU/P6cOfi4wXYDzHypsfZ1D8znPwoAqhj54kTBVqgZDHw8QEnMcS3TWxvHBvncRTIXhCLx0BNK5/6mcTSK2IDbxl0j4vkcQrOxc77tyExuFfuXouuKVtE7rggOJiX6ga5LJW2if6Jxe/Rh8+aJv7 ;{id = 31967 (ksk), size = 1024b}
example.\t86400\tIN\tRRSIG\tDNSKEY 8 1 86400 20240101010101 20240101010101 31967 example. N0YniZN9ZZqFh6xzB+q63GpRNfC8SGWmCB7GovxoLdM7czL7g7Sd7ADAvLqrwguFa4aPoT/dof8NBphh4a4DpQjfcp6AIRAUMUQxA5ELsNN6vvLK2HM8EIN6d7J8H0uyEcDs2b0X84Zgyl5Peg9L8BRfReORU9eyUgexOmO8TGs=
example.\t86400\tIN\tRRSIG\tDNSKEY 15 1 86400 20240101010101 20240101010101 39188 example. a1uf/OWJ2eP2mTDVM6o3CwRjr/0AjHxYDsyw4xoqOr/5iy+W4wSnspydhLH2Fe5V5GQj+J332Nz02qwqzy/LDQ==
ns1.example.\t3600\tIN\tA\t203.0.113.63
ns1.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20240101010101 20240101010101 31967 example. Boa50TSmpAiTVtZlk/v4ZRWuhDMwLmz0U6WUT9DYP7HgVfpa/sCCb9AXevpti18RRAlv4IQwFoQDWnQOCFwrpODW5BM3uXOcMMyb8E0dxw+s5j/oSKqv4YUcgthMoWj08eskkRfsr9dWXXKfZa7Y7lsYmkdzcC2hpSALPQbRNn8=
ns1.example.\t3600\tIN\tRRSIG\tA 15 2 3600 20240101010101 20240101010101 39188 example. LVmEy45TIoFZgoSryXQbZjUCLpwYUerR2nt9EK6WcSgIkeGkj3IDRGqQfQVyrutjohhlxdkDnFBE4dT5nBwnBg==
ns1.example.\t86400\tIN\tNSEC\tns2.example. A RRSIG NSEC
ns1.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 20240101010101 20240101010101 31967 example. PYa57fkqDGJQP42aXs5JrqIzbw5VrYZ6IWqMyLB1UPuSzgq0E6xe7vxoeas0eCppBxDrwYzFqZ5iXHa5C39I1P/WcGWNSelL++3wpiuw1dEOWEQ1Eudg6TD0MQD3sa9V1M2PRONrtvjp+anQgluk+G+JlEfGuLv7nCyxiWvqY74=
ns1.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 39188 example. GqyC25UtODem9X3uVI5gLQ/OLFBvSwdA/bwnj1jB8qP9NhD03bLDfuKzm8QvSJvkq7ERBcHibpEL+lZUL5HrDw==
ns2.example.\t3600\tIN\tAAAA\t2001:db8::63
ns2.example.\t3600\tIN\tRRSIG\tAAAA 8 2 3600 20240101010101 20240101010101 31967 example. AFLqBlmUqxQiZAvKjIzerIvg3pEdpJ9Azj4hp/WyUrxoLKr7CdvIbREHBYE4mgZrs6cTYEZEEZNyyt2pOqJUUMVsrguXb6Y72c+8K1dz6gvd7NGpmJTmx9dqCvXacaX7TRqXHuAVnQ2WRFEBCEc4GS8EyqfatIJjhLv971gvMOg=
ns2.example.\t3600\tIN\tRRSIG\tAAAA 15 2 3600 20240101010101 20240101010101 39188 example. Fikp9s+ht+B9ncP0GsjWce3Oz2wtixNl8RZAZe+95kaHEL2w+hfNSO30ox8dTPOe5Yih0jJTu1bMmvRySbVXCg==
ns2.example.\t86400\tIN\tNSEC\texample. AAAA RRSIG NSEC
ns2.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 20240101010101 20240101010101 31967 example. Rv0gTuaWSlFzvEndvuh22kBNQu0i2cWxNVq9zPFWZNJKyUJWRYYANXnR3hsHmBArdk+1fY4HPxbz9Fgb9PbEGBLkQir6ftt138lWATr8U2Fc3Z1IrJF+J3OdNXMMbDaOtwH+15nE5LZVuplEPnhgTChN0wrufPYcylB1Ok+r7P4=
ns2.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 39188 example. fTkEc85fTdlicaZ/D6YIbMpaZFFZdbpA98vyPjZfCC2aoXvFjTl/RmigLd0L0hMSYW+jIlSANzzKYO7Oj7iFDA==
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc8976-simple");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+31967");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.+015+39188");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-oexample",
            "-T",
            "-R",
            "-U",
            "-f-",
            "-e",
            "20240101010101",
            "-i",
            "20240101010101",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn multiple_algorithms_with_sign_with_all_and_every_unique_algorithm() {
        let expected_zone = r###"example.\t86400\tIN\tSOA\tns1.example. admin.example. 2018031900 1800 900 604800 86400
example.\t86400\tIN\tRRSIG\tSOA 8 1 86400 20240101010101 20240101010101 31967 example. kKRK3zSRGnsHEZqZpCacJHW6U/xWafetom45QQrLCdIZF8wV6b5T8x9X//fbb13X0GNrzsDxXzwDm/Nz9EbS5fOMKe/uh7eIiWpvdUIkApSwWQmNJXr7zHBBqfdk9C7+NraWAj5Dkd7hqHfvFbgBJDN1T3rCMywyxEeO+0RHkUs=
example.\t86400\tIN\tRRSIG\tSOA 15 1 86400 20240101010101 20240101010101 39188 example. ckYQDK2HeLK09CjpO76H0oT5CGjc6WcKYihl0zkS79VYzcj2Cspifcf3V5Sft8QDmGzjtBqqQvGYPsbzZwlYCQ==
example.\t86400\tIN\tNS\tns1.example.
example.\t86400\tIN\tNS\tns2.example.
example.\t86400\tIN\tRRSIG\tNS 8 1 86400 20240101010101 20240101010101 31967 example. ow1ECVYGToR7Wd+RKlHpCjYgc3Vl4VmS4b3oZBhLp+ASMXwG58rPS1q79X0z4Zu/7UvucIk7jTS3RYQsJpd5SYahXVwG9Tg3SPy5sD498kyvaczRcMmrgF+MtKf4BFIcBO2Id0g+6ELxplkID1/mStbNlBP9IDoumWpxgeKHct4=
example.\t86400\tIN\tRRSIG\tNS 15 1 86400 20240101010101 20240101010101 39188 example. A06Y3VSm8/G3YhuxJ3yHNI71iTi9UcyG8zIp7bHuXkhhSFDT4kRQMahlaNRP30HvaJDBJz9vy9hXmmbuc28cCQ==
example.\t86400\tIN\tNSEC\tns1.example. NS SOA RRSIG NSEC DNSKEY
example.\t86400\tIN\tRRSIG\tNSEC 8 1 86400 20240101010101 20240101010101 31967 example. igfv+N3fWG9tlHwJLvbRH9R+CfpoDF+m7exyW5nbcRu6/bX39E8W/REzz11ib7CaFOKXfVn7AZ1aJTOGIF5fYQkgNCZwUX6G3dEuwCAbex0UnZLdw++AcqDiqkfVh95F6+GBLhNDZJh4uklQLEo8yfg1HtJfgrOtPpthMt52Mz4=
example.\t86400\tIN\tRRSIG\tNSEC 15 1 86400 20240101010101 20240101010101 39188 example. R3mhoKHFOusQOU0l6vn7vvUPGLnkoOeYQ9o2HmcsQ3PxVpJ1+oQc7igxycgQLw9JLSIz8p2vjPXfQBm+7qE+AQ==
example.\t86400\tIN\tDNSKEY\t256 3 15 AnxyASt7Bws/Y883BjIsK+Vcl2rlR7fnGqoVHf+wY5o= ;{id = 39188 (zsk), size = 256b}
example.\t86400\tIN\tDNSKEY\t257 3 8 AwEAAaYL5iwWI6UgSQVcDZmH7DrhQU/P6cOfi4wXYDzHypsfZ1D8znPwoAqhj54kTBVqgZDHw8QEnMcS3TWxvHBvncRTIXhCLx0BNK5/6mcTSK2IDbxl0j4vkcQrOxc77tyExuFfuXouuKVtE7rggOJiX6ga5LJW2if6Jxe/Rh8+aJv7 ;{id = 31967 (ksk), size = 1024b}
example.\t86400\tIN\tRRSIG\tDNSKEY 8 1 86400 20240101010101 20240101010101 31967 example. N0YniZN9ZZqFh6xzB+q63GpRNfC8SGWmCB7GovxoLdM7czL7g7Sd7ADAvLqrwguFa4aPoT/dof8NBphh4a4DpQjfcp6AIRAUMUQxA5ELsNN6vvLK2HM8EIN6d7J8H0uyEcDs2b0X84Zgyl5Peg9L8BRfReORU9eyUgexOmO8TGs=
example.\t86400\tIN\tRRSIG\tDNSKEY 15 1 86400 20240101010101 20240101010101 39188 example. a1uf/OWJ2eP2mTDVM6o3CwRjr/0AjHxYDsyw4xoqOr/5iy+W4wSnspydhLH2Fe5V5GQj+J332Nz02qwqzy/LDQ==
ns1.example.\t3600\tIN\tA\t203.0.113.63
ns1.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20240101010101 20240101010101 31967 example. Boa50TSmpAiTVtZlk/v4ZRWuhDMwLmz0U6WUT9DYP7HgVfpa/sCCb9AXevpti18RRAlv4IQwFoQDWnQOCFwrpODW5BM3uXOcMMyb8E0dxw+s5j/oSKqv4YUcgthMoWj08eskkRfsr9dWXXKfZa7Y7lsYmkdzcC2hpSALPQbRNn8=
ns1.example.\t3600\tIN\tRRSIG\tA 15 2 3600 20240101010101 20240101010101 39188 example. LVmEy45TIoFZgoSryXQbZjUCLpwYUerR2nt9EK6WcSgIkeGkj3IDRGqQfQVyrutjohhlxdkDnFBE4dT5nBwnBg==
ns1.example.\t86400\tIN\tNSEC\tns2.example. A RRSIG NSEC
ns1.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 20240101010101 20240101010101 31967 example. PYa57fkqDGJQP42aXs5JrqIzbw5VrYZ6IWqMyLB1UPuSzgq0E6xe7vxoeas0eCppBxDrwYzFqZ5iXHa5C39I1P/WcGWNSelL++3wpiuw1dEOWEQ1Eudg6TD0MQD3sa9V1M2PRONrtvjp+anQgluk+G+JlEfGuLv7nCyxiWvqY74=
ns1.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 39188 example. GqyC25UtODem9X3uVI5gLQ/OLFBvSwdA/bwnj1jB8qP9NhD03bLDfuKzm8QvSJvkq7ERBcHibpEL+lZUL5HrDw==
ns2.example.\t3600\tIN\tAAAA\t2001:db8::63
ns2.example.\t3600\tIN\tRRSIG\tAAAA 8 2 3600 20240101010101 20240101010101 31967 example. AFLqBlmUqxQiZAvKjIzerIvg3pEdpJ9Azj4hp/WyUrxoLKr7CdvIbREHBYE4mgZrs6cTYEZEEZNyyt2pOqJUUMVsrguXb6Y72c+8K1dz6gvd7NGpmJTmx9dqCvXacaX7TRqXHuAVnQ2WRFEBCEc4GS8EyqfatIJjhLv971gvMOg=
ns2.example.\t3600\tIN\tRRSIG\tAAAA 15 2 3600 20240101010101 20240101010101 39188 example. Fikp9s+ht+B9ncP0GsjWce3Oz2wtixNl8RZAZe+95kaHEL2w+hfNSO30ox8dTPOe5Yih0jJTu1bMmvRySbVXCg==
ns2.example.\t86400\tIN\tNSEC\texample. AAAA RRSIG NSEC
ns2.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 20240101010101 20240101010101 31967 example. Rv0gTuaWSlFzvEndvuh22kBNQu0i2cWxNVq9zPFWZNJKyUJWRYYANXnR3hsHmBArdk+1fY4HPxbz9Fgb9PbEGBLkQir6ftt138lWATr8U2Fc3Z1IrJF+J3OdNXMMbDaOtwH+15nE5LZVuplEPnhgTChN0wrufPYcylB1Ok+r7P4=
ns2.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 39188 example. fTkEc85fTdlicaZ/D6YIbMpaZFFZdbpA98vyPjZfCC2aoXvFjTl/RmigLd0L0hMSYW+jIlSANzzKYO7Oj7iFDA==
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc8976-simple");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+31967");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.+015+39188");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-oexample",
            "-T",
            "-R",
            "-A",
            "-U",
            "-f-",
            "-e",
            "20240101010101",
            "-i",
            "20240101010101",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn multiple_algorithms_with_sign_with_every_unique_algorithm_extra_zsk() {
        let expected_zone = r###"example.\t86400\tIN\tSOA\tns1.example. admin.example. 2018031900 1800 900 604800 86400
example.\t86400\tIN\tRRSIG\tSOA 8 1 86400 20240101010101 20240101010101 38353 example. I5rP5chAQ2IeI+Lcu+NPe7N5YMW8CQ4VGPhANiKEiLJAc1qeW0X7LAj2RQprCkxY9lLayp/ldwdH0471J8TP6uEV+bVf5YVDq115zdPOuo0gIc0ZrrJGA6DSbmF0RDQFfEAuHQXeY7u3sg5zEn6ctFbjV/Ye2gpAtZzgMDdz98o=
example.\t86400\tIN\tRRSIG\tSOA 15 1 86400 20240101010101 20240101010101 39188 example. ckYQDK2HeLK09CjpO76H0oT5CGjc6WcKYihl0zkS79VYzcj2Cspifcf3V5Sft8QDmGzjtBqqQvGYPsbzZwlYCQ==
example.\t86400\tIN\tNS\tns1.example.
example.\t86400\tIN\tNS\tns2.example.
example.\t86400\tIN\tRRSIG\tNS 8 1 86400 20240101010101 20240101010101 38353 example. ic/iYPEWbPaeVkBjO1x3Ykqtl7xLWnfGVKyUJ71sJ/u6OipAnHidqjMthJyWEGc3+Zg868OoFEABqJjJeUeyyEyOiYbvwHsjtejXUP8j0L1xET1ktAOJ0mLcQ1qdz7/SnUhxfxQXRfluC2GYhvzvwqy+R5T+VyELChukTGdr/bM=
example.\t86400\tIN\tRRSIG\tNS 15 1 86400 20240101010101 20240101010101 39188 example. A06Y3VSm8/G3YhuxJ3yHNI71iTi9UcyG8zIp7bHuXkhhSFDT4kRQMahlaNRP30HvaJDBJz9vy9hXmmbuc28cCQ==
example.\t86400\tIN\tNSEC\tns1.example. NS SOA RRSIG NSEC DNSKEY
example.\t86400\tIN\tRRSIG\tNSEC 8 1 86400 20240101010101 20240101010101 38353 example. DrIr6ZSjABNVBt7hAvoUIrcGJ5ytdWdP1G0jVqI+y01i+eZunsUjLJBLCGMBB98tz6FLW9HyUbe7o/x9I6jXz4cE7stip8Wxb+/TBcJwTQOYCZ5nfi4NLZ2zqpOdzJ2urRcitqhf8O6itsqwAq29BGnxOk/rlWjL27w3CdvmoJs=
example.\t86400\tIN\tRRSIG\tNSEC 15 1 86400 20240101010101 20240101010101 39188 example. R3mhoKHFOusQOU0l6vn7vvUPGLnkoOeYQ9o2HmcsQ3PxVpJ1+oQc7igxycgQLw9JLSIz8p2vjPXfQBm+7qE+AQ==
example.\t86400\tIN\tDNSKEY\t256 3 8 AwEAAbsD4Tcz8hl2Rldov4CrfYpK3ORIh/giSGDlZaDTZR4gpGxGvMBwu2jzQ3m0iX3PvqPoaybC4tznjlJi8g/qsCRHhOkqWmjtmOYOJXEuUTb+4tPBkiboJM5QchxTfKxkYbJ2AD+VAUX1S6h/0DI0ZCGx1H90QTBE2ymRgHBwUfBt ;{id = 38353 (zsk), size = 1024b}
example.\t86400\tIN\tDNSKEY\t256 3 15 AnxyASt7Bws/Y883BjIsK+Vcl2rlR7fnGqoVHf+wY5o= ;{id = 39188 (zsk), size = 256b}
example.\t86400\tIN\tDNSKEY\t257 3 8 AwEAAaYL5iwWI6UgSQVcDZmH7DrhQU/P6cOfi4wXYDzHypsfZ1D8znPwoAqhj54kTBVqgZDHw8QEnMcS3TWxvHBvncRTIXhCLx0BNK5/6mcTSK2IDbxl0j4vkcQrOxc77tyExuFfuXouuKVtE7rggOJiX6ga5LJW2if6Jxe/Rh8+aJv7 ;{id = 31967 (ksk), size = 1024b}
example.\t86400\tIN\tRRSIG\tDNSKEY 8 1 86400 20240101010101 20240101010101 31967 example. HMrFLtPafFjrc948B8o6Y0Q7PWeG+Dmbp66/MpLkf+04BIzi5+7NROPtLeiR2Ljlj+T0mYGCjH0cYv8/8IoQKJ3U8MmFzxjWx72smJFYsHq7/bDfEMLYQkF3ZC9cZYbeeue3m3OkSNhKhmTwcWun2Eb0zQDVNeCreG88A4YXfo8=
example.\t86400\tIN\tRRSIG\tDNSKEY 15 1 86400 20240101010101 20240101010101 39188 example. fJnk0r7M6bj4SL5CgFet/zfo8+x6qVIdh9yb21DjzbzLGCYCd/ZbGpQU2SQtN/AsNWRhszNMpBsFvAGU58nlDA==
ns1.example.\t3600\tIN\tA\t203.0.113.63
ns1.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20240101010101 20240101010101 38353 example. LUqcCem/enGx/t88s1VgxwfPuGqr1U+PFNBBFhOWU9hbl+vYVhPzw7ycKdHmR8+UUryuHJOgwYfZYIjZFLKBX3901zslR7nX99UJdTutKubOyLyn8eaz3l6gdjYr4fKryj76Z5Bss3/jtA+nGdTz+ubAOnoBw0X3hgYCwHmS6vY=
ns1.example.\t3600\tIN\tRRSIG\tA 15 2 3600 20240101010101 20240101010101 39188 example. LVmEy45TIoFZgoSryXQbZjUCLpwYUerR2nt9EK6WcSgIkeGkj3IDRGqQfQVyrutjohhlxdkDnFBE4dT5nBwnBg==
ns1.example.\t86400\tIN\tNSEC\tns2.example. A RRSIG NSEC
ns1.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 20240101010101 20240101010101 38353 example. K7W6OzGx4I2PT7FJxx2msXo5yLUiwYT7+vvPoBdJN6im4QVbdsJ21uFNYnYgAH+OKhjry6E7ywnkvICy5diCJu5hgpI6qbFguLx3zQ5loUtF3Nz+uole+fep5Hrhf18I6g77Dd2VVh+mVW1vATmuHmWnIMu0Wd1lACzg3Xd6U0E=
ns1.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 39188 example. GqyC25UtODem9X3uVI5gLQ/OLFBvSwdA/bwnj1jB8qP9NhD03bLDfuKzm8QvSJvkq7ERBcHibpEL+lZUL5HrDw==
ns2.example.\t3600\tIN\tAAAA\t2001:db8::63
ns2.example.\t3600\tIN\tRRSIG\tAAAA 8 2 3600 20240101010101 20240101010101 38353 example. cYvHJhwLhHls4ChlB+cGrp4eal0NIGftZsjPNE7mTboz+2rpvLou0ykqa257DKOJL6ximQ4MDUfn6WJF4l//2t7p3iTmcDtXndyPMf9LYAczXV+MDMVDPbBGpDQyKZNr4cHZS/82Xj3K4R6I+GNXNQyFUJ/6ctwBZ3pLfoebIo8=
ns2.example.\t3600\tIN\tRRSIG\tAAAA 15 2 3600 20240101010101 20240101010101 39188 example. Fikp9s+ht+B9ncP0GsjWce3Oz2wtixNl8RZAZe+95kaHEL2w+hfNSO30ox8dTPOe5Yih0jJTu1bMmvRySbVXCg==
ns2.example.\t86400\tIN\tNSEC\texample. AAAA RRSIG NSEC
ns2.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 20240101010101 20240101010101 38353 example. IO3iDg4S1cJXRLubj0ZRKYLUB/ggFkPKQR4zGJ1J6rkFyPYbZNcPqJRiiJW2O6dSgRmmZzw2eA2DJLmOIRh17kj0EmoRJh/iuiLSBrJWJ9PN/sLIS5t/hB17sBf8gxPv4vYk5kJ7RhiVNbY0nOp87CiQlgqV6ZQFqYm8Xam1spM=
ns2.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 39188 example. fTkEc85fTdlicaZ/D6YIbMpaZFFZdbpA98vyPjZfCC2aoXvFjTl/RmigLd0L0hMSYW+jIlSANzzKYO7Oj7iFDA==
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc8976-simple");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+31967");
        let zsk1_path = mk_test_data_abs_path_string("test-data/Kexample.+008+38353");
        let zsk2_path = mk_test_data_abs_path_string("test-data/Kexample.+015+39188");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-oexample",
            "-T",
            "-R",
            "-U",
            "-f-",
            "-e",
            "20240101010101",
            "-i",
            "20240101010101",
            &zone_file_path,
            &ksk_path,
            &zsk1_path,
            &zsk2_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn multiple_algorithms_with_sign_with_all_and_every_unique_algorithm_extra_ksk() {
        let expected_zone = r###"example.\t86400\tIN\tSOA\tns1.example. admin.example. 2018031900 1800 900 604800 86400
example.\t86400\tIN\tRRSIG\tSOA 8 1 86400 20240101010101 20240101010101 38353 example. I5rP5chAQ2IeI+Lcu+NPe7N5YMW8CQ4VGPhANiKEiLJAc1qeW0X7LAj2RQprCkxY9lLayp/ldwdH0471J8TP6uEV+bVf5YVDq115zdPOuo0gIc0ZrrJGA6DSbmF0RDQFfEAuHQXeY7u3sg5zEn6ctFbjV/Ye2gpAtZzgMDdz98o=
example.\t86400\tIN\tRRSIG\tSOA 15 1 86400 20240101010101 20240101010101 53470 example. opsQQglFNDCuoV21f2THEoSQOyKAyeCnT/oBTXvTWT3P7JMWi2vd+7k8mmwfIe/pkbzZkIulggS/mka0S0OGCQ==
example.\t86400\tIN\tNS\tns1.example.
example.\t86400\tIN\tNS\tns2.example.
example.\t86400\tIN\tRRSIG\tNS 8 1 86400 20240101010101 20240101010101 38353 example. ic/iYPEWbPaeVkBjO1x3Ykqtl7xLWnfGVKyUJ71sJ/u6OipAnHidqjMthJyWEGc3+Zg868OoFEABqJjJeUeyyEyOiYbvwHsjtejXUP8j0L1xET1ktAOJ0mLcQ1qdz7/SnUhxfxQXRfluC2GYhvzvwqy+R5T+VyELChukTGdr/bM=
example.\t86400\tIN\tRRSIG\tNS 15 1 86400 20240101010101 20240101010101 53470 example. /D9HDzvXSkSCXuV+JYIpqIwMAjFyTRjN8cuRe1HngCheDcKEPjLPDHP9kZvqXiVkLMGXn4qaLrJf0Zn9OuwICw==
example.\t86400\tIN\tNSEC\tns1.example. NS SOA RRSIG NSEC DNSKEY
example.\t86400\tIN\tRRSIG\tNSEC 8 1 86400 20240101010101 20240101010101 38353 example. DrIr6ZSjABNVBt7hAvoUIrcGJ5ytdWdP1G0jVqI+y01i+eZunsUjLJBLCGMBB98tz6FLW9HyUbe7o/x9I6jXz4cE7stip8Wxb+/TBcJwTQOYCZ5nfi4NLZ2zqpOdzJ2urRcitqhf8O6itsqwAq29BGnxOk/rlWjL27w3CdvmoJs=
example.\t86400\tIN\tRRSIG\tNSEC 15 1 86400 20240101010101 20240101010101 53470 example. Db3scOlMnlBtSQIguqB2AOAtB74dynYxNieX+VBSH2Od1Iu0Tle5At5sBnIh0kI2+lRC7+vSl1IEQsYSSONGBg==
example.\t86400\tIN\tDNSKEY\t256 3 8 AwEAAbsD4Tcz8hl2Rldov4CrfYpK3ORIh/giSGDlZaDTZR4gpGxGvMBwu2jzQ3m0iX3PvqPoaybC4tznjlJi8g/qsCRHhOkqWmjtmOYOJXEuUTb+4tPBkiboJM5QchxTfKxkYbJ2AD+VAUX1S6h/0DI0ZCGx1H90QTBE2ymRgHBwUfBt ;{id = 38353 (zsk), size = 1024b}
example.\t86400\tIN\tDNSKEY\t257 3 8 AwEAAaYL5iwWI6UgSQVcDZmH7DrhQU/P6cOfi4wXYDzHypsfZ1D8znPwoAqhj54kTBVqgZDHw8QEnMcS3TWxvHBvncRTIXhCLx0BNK5/6mcTSK2IDbxl0j4vkcQrOxc77tyExuFfuXouuKVtE7rggOJiX6ga5LJW2if6Jxe/Rh8+aJv7 ;{id = 31967 (ksk), size = 1024b}
example.\t86400\tIN\tDNSKEY\t257 3 15 ABfITiMt1O3QAyTkpGVfkAk3mlV8W18/qqHv1BVW5Hs= ;{id = 53470 (ksk), size = 256b}
example.\t86400\tIN\tRRSIG\tDNSKEY 8 1 86400 20240101010101 20240101010101 31967 example. mQGDo4tEH/SlJSrcJWsmwvg4XG1EFyh64MjYa86dmtpNgMt8Nd6ZF9+o388pwQlaRO6WAipZseXIl17xjoianBpTsDZKo6jSguOC+jDgfCbKDHK61apGUxPSqB/D/4zWMByluRbDLi6j3mqgA0eRmVedgmyCM/sbuehumqgsj9E=
example.\t86400\tIN\tRRSIG\tDNSKEY 8 1 86400 20240101010101 20240101010101 38353 example. BH538M0CNk722Hn35gFXaVbA9aMW9R6cw8krFejFk75dkKNKv9eypvSgTS51hRqDF4l+asQKqqpF90RfWl0TzG43L3wY7jh5wiNuDzuzZTv+/d1itT1OVjLeJGNvnnTuix4e942eUbTb2yFmPWd6aqPVUjgsiZzyZyB+bmoPm/o=
example.\t86400\tIN\tRRSIG\tDNSKEY 15 1 86400 20240101010101 20240101010101 53470 example. DL5gB0YWnJXSZVzgzNWXIbXQ6+7KOmXMEGeehPoARGmu8CiZAc8bdiNMdDX7VfOhrTY5W5yrc4Rr7w+CGS8kAg==
ns1.example.\t3600\tIN\tA\t203.0.113.63
ns1.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20240101010101 20240101010101 38353 example. LUqcCem/enGx/t88s1VgxwfPuGqr1U+PFNBBFhOWU9hbl+vYVhPzw7ycKdHmR8+UUryuHJOgwYfZYIjZFLKBX3901zslR7nX99UJdTutKubOyLyn8eaz3l6gdjYr4fKryj76Z5Bss3/jtA+nGdTz+ubAOnoBw0X3hgYCwHmS6vY=
ns1.example.\t3600\tIN\tRRSIG\tA 15 2 3600 20240101010101 20240101010101 53470 example. zjYPZBcbf6kC2WA0yg4sgbf7D9BSrMxaxRCtspxFBIgOpqYFP0TrI21frP8a0i8QaphYqoOhH+7PfXBaBp1uCA==
ns1.example.\t86400\tIN\tNSEC\tns2.example. A RRSIG NSEC
ns1.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 20240101010101 20240101010101 38353 example. K7W6OzGx4I2PT7FJxx2msXo5yLUiwYT7+vvPoBdJN6im4QVbdsJ21uFNYnYgAH+OKhjry6E7ywnkvICy5diCJu5hgpI6qbFguLx3zQ5loUtF3Nz+uole+fep5Hrhf18I6g77Dd2VVh+mVW1vATmuHmWnIMu0Wd1lACzg3Xd6U0E=
ns1.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 53470 example. 7edVBWAplNvrzR/HiaVMZGg1ARa+ZZC/g/nRqFvp1Ivk9/q/P1Xb3GQkCzwhjF1lK55FIytaaTPrPkejcmeaCw==
ns2.example.\t3600\tIN\tAAAA\t2001:db8::63
ns2.example.\t3600\tIN\tRRSIG\tAAAA 8 2 3600 20240101010101 20240101010101 38353 example. cYvHJhwLhHls4ChlB+cGrp4eal0NIGftZsjPNE7mTboz+2rpvLou0ykqa257DKOJL6ximQ4MDUfn6WJF4l//2t7p3iTmcDtXndyPMf9LYAczXV+MDMVDPbBGpDQyKZNr4cHZS/82Xj3K4R6I+GNXNQyFUJ/6ctwBZ3pLfoebIo8=
ns2.example.\t3600\tIN\tRRSIG\tAAAA 15 2 3600 20240101010101 20240101010101 53470 example. RfD1n/NNKG2aEs2e4rT2Fp8/Eb7o7ZoWDx1iGsPzg+Xcld9TA+1c9e7vY84EJOtY289fI6M2W5wNkkOLegPYCQ==
ns2.example.\t86400\tIN\tNSEC\texample. AAAA RRSIG NSEC
ns2.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 20240101010101 20240101010101 38353 example. IO3iDg4S1cJXRLubj0ZRKYLUB/ggFkPKQR4zGJ1J6rkFyPYbZNcPqJRiiJW2O6dSgRmmZzw2eA2DJLmOIRh17kj0EmoRJh/iuiLSBrJWJ9PN/sLIS5t/hB17sBf8gxPv4vYk5kJ7RhiVNbY0nOp87CiQlgqV6ZQFqYm8Xam1spM=
ns2.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 53470 example. GkAx/E5VUNaxOREPi/LHz+SS7Pf/ZRQ6pgsGFPz8laggOStWMNntd3fle92wm2S1FII9DEoDOJYPo1zHEyYMCA==
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc8976-simple");
        let ksk1_path = mk_test_data_abs_path_string("test-data/Kexample.+008+31967");
        let ksk2_path = mk_test_data_abs_path_string("test-data/Kexample.+015+53470");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+38353");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-oexample",
            "-T",
            "-R",
            "-A",
            "-U",
            "-f-",
            "-e",
            "20240101010101",
            "-i",
            "20240101010101",
            &zone_file_path,
            &ksk1_path,
            &ksk2_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn multiple_algorithms_with_sign_with_all_and_every_unique_algorithm_extra_zsk() {
        let expected_zone = r###"example.\t86400\tIN\tSOA\tns1.example. admin.example. 2018031900 1800 900 604800 86400
example.\t86400\tIN\tRRSIG\tSOA 8 1 86400 20240101010101 20240101010101 38353 example. I5rP5chAQ2IeI+Lcu+NPe7N5YMW8CQ4VGPhANiKEiLJAc1qeW0X7LAj2RQprCkxY9lLayp/ldwdH0471J8TP6uEV+bVf5YVDq115zdPOuo0gIc0ZrrJGA6DSbmF0RDQFfEAuHQXeY7u3sg5zEn6ctFbjV/Ye2gpAtZzgMDdz98o=
example.\t86400\tIN\tRRSIG\tSOA 15 1 86400 20240101010101 20240101010101 39188 example. ckYQDK2HeLK09CjpO76H0oT5CGjc6WcKYihl0zkS79VYzcj2Cspifcf3V5Sft8QDmGzjtBqqQvGYPsbzZwlYCQ==
example.\t86400\tIN\tNS\tns1.example.
example.\t86400\tIN\tNS\tns2.example.
example.\t86400\tIN\tRRSIG\tNS 8 1 86400 20240101010101 20240101010101 38353 example. ic/iYPEWbPaeVkBjO1x3Ykqtl7xLWnfGVKyUJ71sJ/u6OipAnHidqjMthJyWEGc3+Zg868OoFEABqJjJeUeyyEyOiYbvwHsjtejXUP8j0L1xET1ktAOJ0mLcQ1qdz7/SnUhxfxQXRfluC2GYhvzvwqy+R5T+VyELChukTGdr/bM=
example.\t86400\tIN\tRRSIG\tNS 15 1 86400 20240101010101 20240101010101 39188 example. A06Y3VSm8/G3YhuxJ3yHNI71iTi9UcyG8zIp7bHuXkhhSFDT4kRQMahlaNRP30HvaJDBJz9vy9hXmmbuc28cCQ==
example.\t86400\tIN\tNSEC\tns1.example. NS SOA RRSIG NSEC DNSKEY
example.\t86400\tIN\tRRSIG\tNSEC 8 1 86400 20240101010101 20240101010101 38353 example. DrIr6ZSjABNVBt7hAvoUIrcGJ5ytdWdP1G0jVqI+y01i+eZunsUjLJBLCGMBB98tz6FLW9HyUbe7o/x9I6jXz4cE7stip8Wxb+/TBcJwTQOYCZ5nfi4NLZ2zqpOdzJ2urRcitqhf8O6itsqwAq29BGnxOk/rlWjL27w3CdvmoJs=
example.\t86400\tIN\tRRSIG\tNSEC 15 1 86400 20240101010101 20240101010101 39188 example. R3mhoKHFOusQOU0l6vn7vvUPGLnkoOeYQ9o2HmcsQ3PxVpJ1+oQc7igxycgQLw9JLSIz8p2vjPXfQBm+7qE+AQ==
example.\t86400\tIN\tDNSKEY\t256 3 8 AwEAAbsD4Tcz8hl2Rldov4CrfYpK3ORIh/giSGDlZaDTZR4gpGxGvMBwu2jzQ3m0iX3PvqPoaybC4tznjlJi8g/qsCRHhOkqWmjtmOYOJXEuUTb+4tPBkiboJM5QchxTfKxkYbJ2AD+VAUX1S6h/0DI0ZCGx1H90QTBE2ymRgHBwUfBt ;{id = 38353 (zsk), size = 1024b}
example.\t86400\tIN\tDNSKEY\t256 3 15 AnxyASt7Bws/Y883BjIsK+Vcl2rlR7fnGqoVHf+wY5o= ;{id = 39188 (zsk), size = 256b}
example.\t86400\tIN\tDNSKEY\t257 3 8 AwEAAaYL5iwWI6UgSQVcDZmH7DrhQU/P6cOfi4wXYDzHypsfZ1D8znPwoAqhj54kTBVqgZDHw8QEnMcS3TWxvHBvncRTIXhCLx0BNK5/6mcTSK2IDbxl0j4vkcQrOxc77tyExuFfuXouuKVtE7rggOJiX6ga5LJW2if6Jxe/Rh8+aJv7 ;{id = 31967 (ksk), size = 1024b}
example.\t86400\tIN\tRRSIG\tDNSKEY 8 1 86400 20240101010101 20240101010101 31967 example. HMrFLtPafFjrc948B8o6Y0Q7PWeG+Dmbp66/MpLkf+04BIzi5+7NROPtLeiR2Ljlj+T0mYGCjH0cYv8/8IoQKJ3U8MmFzxjWx72smJFYsHq7/bDfEMLYQkF3ZC9cZYbeeue3m3OkSNhKhmTwcWun2Eb0zQDVNeCreG88A4YXfo8=
example.\t86400\tIN\tRRSIG\tDNSKEY 8 1 86400 20240101010101 20240101010101 38353 example. OfXxzb4L2KWzsl3a+r9ORwfox/PfXtrCx7N12FaUS/PVaySO8Nh3oDD0Q8t/3Iiu3RoTLKKpTS8Dvh1P9sqFl8IOhjM/9FVS8C4gEHKsjwn7UWZNYZstRVomjilOWuOZH4gy/ndzxwuwh4tREWVHm/0q6F8VxngQ5A7BiFVxtXc=
example.\t86400\tIN\tRRSIG\tDNSKEY 15 1 86400 20240101010101 20240101010101 39188 example. fJnk0r7M6bj4SL5CgFet/zfo8+x6qVIdh9yb21DjzbzLGCYCd/ZbGpQU2SQtN/AsNWRhszNMpBsFvAGU58nlDA==
ns1.example.\t3600\tIN\tA\t203.0.113.63
ns1.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20240101010101 20240101010101 38353 example. LUqcCem/enGx/t88s1VgxwfPuGqr1U+PFNBBFhOWU9hbl+vYVhPzw7ycKdHmR8+UUryuHJOgwYfZYIjZFLKBX3901zslR7nX99UJdTutKubOyLyn8eaz3l6gdjYr4fKryj76Z5Bss3/jtA+nGdTz+ubAOnoBw0X3hgYCwHmS6vY=
ns1.example.\t3600\tIN\tRRSIG\tA 15 2 3600 20240101010101 20240101010101 39188 example. LVmEy45TIoFZgoSryXQbZjUCLpwYUerR2nt9EK6WcSgIkeGkj3IDRGqQfQVyrutjohhlxdkDnFBE4dT5nBwnBg==
ns1.example.\t86400\tIN\tNSEC\tns2.example. A RRSIG NSEC
ns1.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 20240101010101 20240101010101 38353 example. K7W6OzGx4I2PT7FJxx2msXo5yLUiwYT7+vvPoBdJN6im4QVbdsJ21uFNYnYgAH+OKhjry6E7ywnkvICy5diCJu5hgpI6qbFguLx3zQ5loUtF3Nz+uole+fep5Hrhf18I6g77Dd2VVh+mVW1vATmuHmWnIMu0Wd1lACzg3Xd6U0E=
ns1.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 39188 example. GqyC25UtODem9X3uVI5gLQ/OLFBvSwdA/bwnj1jB8qP9NhD03bLDfuKzm8QvSJvkq7ERBcHibpEL+lZUL5HrDw==
ns2.example.\t3600\tIN\tAAAA\t2001:db8::63
ns2.example.\t3600\tIN\tRRSIG\tAAAA 8 2 3600 20240101010101 20240101010101 38353 example. cYvHJhwLhHls4ChlB+cGrp4eal0NIGftZsjPNE7mTboz+2rpvLou0ykqa257DKOJL6ximQ4MDUfn6WJF4l//2t7p3iTmcDtXndyPMf9LYAczXV+MDMVDPbBGpDQyKZNr4cHZS/82Xj3K4R6I+GNXNQyFUJ/6ctwBZ3pLfoebIo8=
ns2.example.\t3600\tIN\tRRSIG\tAAAA 15 2 3600 20240101010101 20240101010101 39188 example. Fikp9s+ht+B9ncP0GsjWce3Oz2wtixNl8RZAZe+95kaHEL2w+hfNSO30ox8dTPOe5Yih0jJTu1bMmvRySbVXCg==
ns2.example.\t86400\tIN\tNSEC\texample. AAAA RRSIG NSEC
ns2.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 20240101010101 20240101010101 38353 example. IO3iDg4S1cJXRLubj0ZRKYLUB/ggFkPKQR4zGJ1J6rkFyPYbZNcPqJRiiJW2O6dSgRmmZzw2eA2DJLmOIRh17kj0EmoRJh/iuiLSBrJWJ9PN/sLIS5t/hB17sBf8gxPv4vYk5kJ7RhiVNbY0nOp87CiQlgqV6ZQFqYm8Xam1spM=
ns2.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 39188 example. fTkEc85fTdlicaZ/D6YIbMpaZFFZdbpA98vyPjZfCC2aoXvFjTl/RmigLd0L0hMSYW+jIlSANzzKYO7Oj7iFDA==
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc8976-simple");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+31967");
        let zsk1_path = mk_test_data_abs_path_string("test-data/Kexample.+008+38353");
        let zsk2_path = mk_test_data_abs_path_string("test-data/Kexample.+015+39188");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-oexample",
            "-T",
            "-R",
            "-A",
            "-U",
            "-f-",
            "-e",
            "20240101010101",
            "-i",
            "20240101010101",
            &zone_file_path,
            &ksk_path,
            &zsk1_path,
            &zsk2_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn multiple_algorithms_with_sign_with_every_unique_algorithm_extra_zsk_alt() {
        let expected_zone = r###"example.\t86400\tIN\tSOA\tns1.example. admin.example. 2018031900 1800 900 604800 86400
example.\t86400\tIN\tRRSIG\tSOA 8 1 86400 20240101010101 20240101010101 31967 example. kKRK3zSRGnsHEZqZpCacJHW6U/xWafetom45QQrLCdIZF8wV6b5T8x9X//fbb13X0GNrzsDxXzwDm/Nz9EbS5fOMKe/uh7eIiWpvdUIkApSwWQmNJXr7zHBBqfdk9C7+NraWAj5Dkd7hqHfvFbgBJDN1T3rCMywyxEeO+0RHkUs=
example.\t86400\tIN\tRRSIG\tSOA 15 1 86400 20240101010101 20240101010101 39188 example. ckYQDK2HeLK09CjpO76H0oT5CGjc6WcKYihl0zkS79VYzcj2Cspifcf3V5Sft8QDmGzjtBqqQvGYPsbzZwlYCQ==
example.\t86400\tIN\tRRSIG\tSOA 15 1 86400 20240101010101 20240101010101 41613 example. LlJzwGuHm9uSYrcPJR70HoLrGQtxbblWM4QDvikHlM2k+bufsViT7X+BFhWpPRDMu9aY2+sJRoZXOR3vIXxhBg==
example.\t86400\tIN\tNS\tns1.example.
example.\t86400\tIN\tNS\tns2.example.
example.\t86400\tIN\tRRSIG\tNS 8 1 86400 20240101010101 20240101010101 31967 example. ow1ECVYGToR7Wd+RKlHpCjYgc3Vl4VmS4b3oZBhLp+ASMXwG58rPS1q79X0z4Zu/7UvucIk7jTS3RYQsJpd5SYahXVwG9Tg3SPy5sD498kyvaczRcMmrgF+MtKf4BFIcBO2Id0g+6ELxplkID1/mStbNlBP9IDoumWpxgeKHct4=
example.\t86400\tIN\tRRSIG\tNS 15 1 86400 20240101010101 20240101010101 39188 example. A06Y3VSm8/G3YhuxJ3yHNI71iTi9UcyG8zIp7bHuXkhhSFDT4kRQMahlaNRP30HvaJDBJz9vy9hXmmbuc28cCQ==
example.\t86400\tIN\tRRSIG\tNS 15 1 86400 20240101010101 20240101010101 41613 example. Co++V4B69csQqYE9+N1b6eUvkLVuLnd8klKSsvCOWEkUiQl+O+z7SnXqndESGj4iIpVn3j1lhHbYlPVVznLABQ==
example.\t86400\tIN\tNSEC\tns1.example. NS SOA RRSIG NSEC DNSKEY
example.\t86400\tIN\tRRSIG\tNSEC 8 1 86400 20240101010101 20240101010101 31967 example. igfv+N3fWG9tlHwJLvbRH9R+CfpoDF+m7exyW5nbcRu6/bX39E8W/REzz11ib7CaFOKXfVn7AZ1aJTOGIF5fYQkgNCZwUX6G3dEuwCAbex0UnZLdw++AcqDiqkfVh95F6+GBLhNDZJh4uklQLEo8yfg1HtJfgrOtPpthMt52Mz4=
example.\t86400\tIN\tRRSIG\tNSEC 15 1 86400 20240101010101 20240101010101 39188 example. R3mhoKHFOusQOU0l6vn7vvUPGLnkoOeYQ9o2HmcsQ3PxVpJ1+oQc7igxycgQLw9JLSIz8p2vjPXfQBm+7qE+AQ==
example.\t86400\tIN\tRRSIG\tNSEC 15 1 86400 20240101010101 20240101010101 41613 example. ewXIRoDUNicJC7YAFRbgMEvMNHJrMbbvnC7qTcZvXLQtA3I5RS5YgYh+0Qkp1J5DTd6awRxcY93kc5CaG05kBw==
example.\t86400\tIN\tDNSKEY\t256 3 15 AnxyASt7Bws/Y883BjIsK+Vcl2rlR7fnGqoVHf+wY5o= ;{id = 39188 (zsk), size = 256b}
example.\t86400\tIN\tDNSKEY\t256 3 15 vARhxM8vGTdL1DuBk8PIRWFZLcYeDAFgHepUiArciRU= ;{id = 41613 (zsk), size = 256b}
example.\t86400\tIN\tDNSKEY\t257 3 8 AwEAAaYL5iwWI6UgSQVcDZmH7DrhQU/P6cOfi4wXYDzHypsfZ1D8znPwoAqhj54kTBVqgZDHw8QEnMcS3TWxvHBvncRTIXhCLx0BNK5/6mcTSK2IDbxl0j4vkcQrOxc77tyExuFfuXouuKVtE7rggOJiX6ga5LJW2if6Jxe/Rh8+aJv7 ;{id = 31967 (ksk), size = 1024b}
example.\t86400\tIN\tRRSIG\tDNSKEY 8 1 86400 20240101010101 20240101010101 31967 example. ofnWRu+0sSovDkCAMmOwxnkip7wSEA2paR33EvDeDwadKvnQ0aLpgMQbLTunaaISh7o8Y07vEt7Z+oQj0v/OsSDI1SxZveWUfhZdiStIAdG92Cl/q68QyAYMscIxeoXtHGAQnahIOvnSlrgJRTlwPbWhJsLwX6h8bSiK9etIv+A=
example.\t86400\tIN\tRRSIG\tDNSKEY 15 1 86400 20240101010101 20240101010101 39188 example. 6O5etAcDlOiNK9LHx/1ekw03lZBv0fVgIT8QhNPZTOwTcoI/sRsxUNMS8ng0bh1NKyprjesczegCa228qA3AAA==
ns1.example.\t3600\tIN\tA\t203.0.113.63
ns1.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20240101010101 20240101010101 31967 example. Boa50TSmpAiTVtZlk/v4ZRWuhDMwLmz0U6WUT9DYP7HgVfpa/sCCb9AXevpti18RRAlv4IQwFoQDWnQOCFwrpODW5BM3uXOcMMyb8E0dxw+s5j/oSKqv4YUcgthMoWj08eskkRfsr9dWXXKfZa7Y7lsYmkdzcC2hpSALPQbRNn8=
ns1.example.\t3600\tIN\tRRSIG\tA 15 2 3600 20240101010101 20240101010101 39188 example. LVmEy45TIoFZgoSryXQbZjUCLpwYUerR2nt9EK6WcSgIkeGkj3IDRGqQfQVyrutjohhlxdkDnFBE4dT5nBwnBg==
ns1.example.\t3600\tIN\tRRSIG\tA 15 2 3600 20240101010101 20240101010101 41613 example. f70Ls4F6A8HVvgelJpITVVrZle9ZLOhPozzRG/3evVza2XG4j/7Qxy+7R8HiQBTjDxj2zOfwtPs4ifJJTqKoBQ==
ns1.example.\t86400\tIN\tNSEC\tns2.example. A RRSIG NSEC
ns1.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 20240101010101 20240101010101 31967 example. PYa57fkqDGJQP42aXs5JrqIzbw5VrYZ6IWqMyLB1UPuSzgq0E6xe7vxoeas0eCppBxDrwYzFqZ5iXHa5C39I1P/WcGWNSelL++3wpiuw1dEOWEQ1Eudg6TD0MQD3sa9V1M2PRONrtvjp+anQgluk+G+JlEfGuLv7nCyxiWvqY74=
ns1.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 39188 example. GqyC25UtODem9X3uVI5gLQ/OLFBvSwdA/bwnj1jB8qP9NhD03bLDfuKzm8QvSJvkq7ERBcHibpEL+lZUL5HrDw==
ns1.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 41613 example. 5cV6p62KmcESO0Bk8EAfy75P6RHOlFoGxIoT578n2XDkFZeg0IPAgPL5o/WWK5QGhKi9/Rj50WxuRCMlkz37DQ==
ns2.example.\t3600\tIN\tAAAA\t2001:db8::63
ns2.example.\t3600\tIN\tRRSIG\tAAAA 8 2 3600 20240101010101 20240101010101 31967 example. AFLqBlmUqxQiZAvKjIzerIvg3pEdpJ9Azj4hp/WyUrxoLKr7CdvIbREHBYE4mgZrs6cTYEZEEZNyyt2pOqJUUMVsrguXb6Y72c+8K1dz6gvd7NGpmJTmx9dqCvXacaX7TRqXHuAVnQ2WRFEBCEc4GS8EyqfatIJjhLv971gvMOg=
ns2.example.\t3600\tIN\tRRSIG\tAAAA 15 2 3600 20240101010101 20240101010101 39188 example. Fikp9s+ht+B9ncP0GsjWce3Oz2wtixNl8RZAZe+95kaHEL2w+hfNSO30ox8dTPOe5Yih0jJTu1bMmvRySbVXCg==
ns2.example.\t3600\tIN\tRRSIG\tAAAA 15 2 3600 20240101010101 20240101010101 41613 example. 1sjwWYH+L9iDpbLMO3l7182BQyDgPGekm1YGlm9HILCpHatdmJHPkrl6abjDfIr6iOWb2Dry+6ibY7ykFjnvDw==
ns2.example.\t86400\tIN\tNSEC\texample. AAAA RRSIG NSEC
ns2.example.\t86400\tIN\tRRSIG\tNSEC 8 2 86400 20240101010101 20240101010101 31967 example. Rv0gTuaWSlFzvEndvuh22kBNQu0i2cWxNVq9zPFWZNJKyUJWRYYANXnR3hsHmBArdk+1fY4HPxbz9Fgb9PbEGBLkQir6ftt138lWATr8U2Fc3Z1IrJF+J3OdNXMMbDaOtwH+15nE5LZVuplEPnhgTChN0wrufPYcylB1Ok+r7P4=
ns2.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 39188 example. fTkEc85fTdlicaZ/D6YIbMpaZFFZdbpA98vyPjZfCC2aoXvFjTl/RmigLd0L0hMSYW+jIlSANzzKYO7Oj7iFDA==
ns2.example.\t86400\tIN\tRRSIG\tNSEC 15 2 86400 20240101010101 20240101010101 41613 example. 26U9FxV+l7Dfqj+LlWQN9fiG1O5gwbu80iHFH+kKknU2S6fBeXhGTjxwyFjLntTR8IikilpGHGeWlYBMk22XAw==
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.rfc8976-simple");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+31967");
        let zsk1_path = mk_test_data_abs_path_string("test-data/Kexample.+015+39188");
        let zsk2_path = mk_test_data_abs_path_string("test-data/Kexample.+015+41613");

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-oexample",
            "-T",
            "-R",
            "-U",
            "-f-",
            "-e",
            "20240101010101",
            "-i",
            "20240101010101",
            &zone_file_path,
            &ksk_path,
            &zsk1_path,
            &zsk2_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn signed_zone_with_cds_and_cdnskey_example() {
        // Make sure the CDS and CDNSKEY RRsets are signed with the KSKs.
        // RFC 7344 Section 4.1
        // o  Signer: MUST be signed with a key that is represented in both
        //    the current DNSKEY and DS RRsets, [...]
        let expected_signed_zone = r###"example.\t3600\tIN\tSOA\tns1.example. bugs.x.w.example. 1081539377 3600 300 3600000 3600
example.\t3600\tIN\tRRSIG\tSOA 8 1 3600 20240101010101 20240101010101 38353 example. cL7d3D6QdmgXqh3CbD10VgF/xMGtNpWoJnEcljYRIdX3rbC2jIf+GtEuTPGx2IFbynmR/Mu+EWcN208eLNtzZmVuPZ2gnN2mlj3O3UgvB5OnXEl9AQsQ7aJzkdTKwWdX7Y8CE2BeJkETa9IQgHmeuJdc1tQHZewJwnuzeQSsDgQ=
example.\t3600\tIN\tNS\tns1.example.
example.\t3600\tIN\tNS\tns2.example.
example.\t3600\tIN\tRRSIG\tNS 8 1 3600 20240101010101 20240101010101 38353 example. Gz8ertKXzdKE4JM1RfdPit3yLFr9SeADLX2jQd9TILmb6t6AJY613wkiuAqF6MWumrxgbLWrculdY0nywgkbbeCxUqet3KXPtTblBpGQuuvJv1nmveAMr7l2Yga1f4t6soJ1mbP8J3upbZ9gRk7ztPyuG3CDwkVMN4loGwadn+U=
example.\t3600\tIN\tMX\t1 xx.example.
example.\t3600\tIN\tRRSIG\tMX 8 1 3600 20240101010101 20240101010101 38353 example. YFr6UaUKs2ypho6nRWw3rnXFnYrD0gdjPtolOGeq+fsGuEfWv0cMGX5n7/qQHlXmfBGOJf+3u7Mk299lQKxLBiMMqy9cBihx8CB+FwnWerycg4jW5uqGfqgtBUHo8pwABoC/tLgKbQyeAruuRBoLsPAh2G10zyM7sW/ecChAb/w=
example.\t3600\tIN\tNSEC\ta.example. NS SOA MX RRSIG NSEC DNSKEY CDS CDNSKEY
example.\t3600\tIN\tRRSIG\tNSEC 8 1 3600 20240101010101 20240101010101 38353 example. Qiw+vax1xUEfN1BhX1O0KbD/V8t2IUh+ex6d1tfqK5C55r296HuiZ70j76V4VjIFXj5tgz9uU1JIR2/UUghGhpp4mmg6Ct5rOiq6DW6w2WN4fLinCwIPnOZ4GLIl/h3+Au5T6hxjZM6OQIsvlP3k7Y5ICViHIqPa+HsJbPFO9Vg=
example.\t3600\tIN\tDNSKEY\t256 3 8 AwEAAbsD4Tcz8hl2Rldov4CrfYpK3ORIh/giSGDlZaDTZR4gpGxGvMBwu2jzQ3m0iX3PvqPoaybC4tznjlJi8g/qsCRHhOkqWmjtmOYOJXEuUTb+4tPBkiboJM5QchxTfKxkYbJ2AD+VAUX1S6h/0DI0ZCGx1H90QTBE2ymRgHBwUfBt ;{id = 38353 (zsk), size = 1024b}
example.\t3600\tIN\tDNSKEY\t257 3 8 AwEAAaYL5iwWI6UgSQVcDZmH7DrhQU/P6cOfi4wXYDzHypsfZ1D8znPwoAqhj54kTBVqgZDHw8QEnMcS3TWxvHBvncRTIXhCLx0BNK5/6mcTSK2IDbxl0j4vkcQrOxc77tyExuFfuXouuKVtE7rggOJiX6ga5LJW2if6Jxe/Rh8+aJv7 ;{id = 31967 (ksk), size = 1024b}
example.\t3600\tIN\tRRSIG\tDNSKEY 8 1 3600 20240101010101 20240101010101 31967 example. GmunmCEX5pnYq5v4dgdmjEfxvT31do2Aw6msSJGbnwR51ZhtNuqq1p0VAyvS/YW0YaL2PaCxP2LT4ydsvnOHdqW0YKDUlAlCXz8RXQslagslvRMwLXuQwALzE/tFWJJOA5OAAydIzEhVq3SNOwOiucqFpAR8An5FmNxIAzz1F/A=
example.\t3600\tIN\tCDS\t31967 8 2 2B8562A69323CF45D662976637829EC082C6204D0C83C9E1AEDCD655629389AA
example.\t3600\tIN\tRRSIG\tCDS 8 1 3600 20240101010101 20240101010101 31967 example. gLUWk/uFgIeN0Jj7u+Qn1ulyQ1V4YSKUfEZaKVCbmG1u83j9u0HcHAECf21OVf9ihbryGf5mN56By7pLMSZTdRI07ZwIxkFmNeZBrJyt9NlhHvn+drLCxgZT6bw4wN1x37yc9CwWyWY/ufuiXYg7nF2+foOsFCQyMUmZYzm19KE=
example.\t3600\tIN\tCDNSKEY\t257 3 8 AwEAAaYL5iwWI6UgSQVcDZmH7DrhQU/P6cOfi4wXYDzHypsfZ1D8znPwoAqhj54kTBVqgZDHw8QEnMcS3TWxvHBvncRTIXhCLx0BNK5/6mcTSK2IDbxl0j4vkcQrOxc77tyExuFfuXouuKVtE7rggOJiX6ga5LJW2if6Jxe/Rh8+aJv7
example.\t3600\tIN\tRRSIG\tCDNSKEY 8 1 3600 20240101010101 20240101010101 31967 example. Sg+R/AVr2/VsRREKvYCRnplwHMz3AEwAeNWYCZks3mF4UkqQOa3bxszZFPoDQRIU6iP8LjWpqA3SgXDFNPwHhIrh4J/SuGRWYG7QkGpe49aeYpcbyUiD+DvgcruJXp2McxyjxCvkgFMrFL4qtrMTjkn9UBRuOjlpoa5FLqa8q9g=
a.example.\t3600\tIN\tNS\tns1.a.example.
a.example.\t3600\tIN\tNS\tns2.a.example.
a.example.\t3600\tIN\tDS\t57855 5 1 B6DCD485719ADCA18E5F3D48A2331627FDD3636B
a.example.\t3600\tIN\tRRSIG\tDS 8 2 3600 20240101010101 20240101010101 38353 example. LMf+InLS3tvyadrLa0OqvAjWDfwaGeTDyoXfg1ljh//wiJR8IheUfP6hXqTd9UVm0T4SKd+ph6/5oOeVnDRJ9ugd1TlE4c89weAOHwJsJULQdkow1/GYw6v9WRVR75D4g9ogaB7zlLfVXFC9uFlxTGQE+FyOUc4obiJ7o2Swz98=
a.example.\t3600\tIN\tNSEC\tai.example. NS DS RRSIG NSEC
a.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20240101010101 20240101010101 38353 example. fsXgi03vsWU2R3j6jGmTEcyId6AOtIKgVhD0AecNIkwXhn9FOL86hf4orVHbBKpuB1RExql+msJ68EyCyfyM5H8he3sn9BIA/EWaIAg9/c/u+tqLmLE6w7GTm4ZwijExPHfTkYljLLKUWV55hTGD1cqeVT73IljzlHCH9Nt2I+w=
ns1.a.example.\t3600\tIN\tA\t192.0.2.5
ns2.a.example.\t3600\tIN\tA\t192.0.2.6
ai.example.\t3600\tIN\tA\t192.0.2.9
ai.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20240101010101 20240101010101 38353 example. Hnns8AklQUUYKPdc5kmBwEauOSdOZnIRY1w/Lz+O4e7zHyyr1LK7BTmMKsvo+FQ6ORwuqFJ9caI3X7ZG7loduzrfhdrWJ0BN9Zbxi+oGvxnNpK+HP0YoLFKeW4rrJcgRRrQdtzIZTknze+fd73we2Mr0YuZuvbMode+A1pIvQWU=
ai.example.\t3600\tIN\tHINFO\t"KLH-10" "ITS"
ai.example.\t3600\tIN\tRRSIG\tHINFO 8 2 3600 20240101010101 20240101010101 38353 example. PNISCG06jg9+Zc+s+/rrHXyUEKWO/Rh7El6pABCZzq9PK081I31AKn5V0wRgPDm3Z0wF5or0qa6L5FXH/3cwCvPrQS4CkvGdTkW8/O7CUUNEGh1gw+lUNryz8LtkKo5blM7ubi8m4RW8mOm2+J1kwbWtEMyhtfj7cCwXxsaIIsg=
ai.example.\t3600\tIN\tAAAA\t2001:db8::f00:baa9
ai.example.\t3600\tIN\tRRSIG\tAAAA 8 2 3600 20240101010101 20240101010101 38353 example. XD+egYoiwjDOuZFr0FympXEr6uWAhkTGBfNYrLoJAX6Xxk9Aa3JSrEhRXkT7bvEMmsSmFZAy3Ek+VmDT4yvsBw0ZmvyefIQRVBqze1EtNfRCgtRqQL5P+zXHou58XKcdNSKUR0o/lcRqm9Np+FMOEeTbnVjkPbGg/zc/UZk2mDM=
ai.example.\t3600\tIN\tNSEC\tb.example. A HINFO AAAA RRSIG NSEC
ai.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20240101010101 20240101010101 38353 example. dvcv/WQN3JqOouLSLAXvGhV9IGi/Vz0UISdFkV4DKD5/ZwcPVUBi6ykcQAhj9k2medZcCLWM4sy4FWqMmuqSpgUuEV/nkEJk96PW1901g+CD8W67d2SnPhRJnLa8TOJZgPlYKwMEz9eB7mV8KjHSZTa4hYCW26eVhD5GTfLJfMk=
b.example.\t3600\tIN\tNS\tns1.b.example.
b.example.\t3600\tIN\tNS\tns2.b.example.
b.example.\t3600\tIN\tNSEC\tns1.example. NS RRSIG NSEC
b.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20240101010101 20240101010101 38353 example. qRfOaUm6fI1Ae0QMGERwfIGmVasBwshLlPu70GDj/AW0nRXahv5T3PjaDvraQfHFMhvWKlfZLVseEX7A+I6rA+wV/nhQWpD+14jzPc6Bt5T3gmjEq8xSZgl/5MVjLgQQbvi9WAcbNkzBr6oP+bx7qxdrgEG/1UU8amVj7/llKE0=
ns1.b.example.\t3600\tIN\tA\t192.0.2.7
ns2.b.example.\t3600\tIN\tA\t192.0.2.8
ns1.example.\t3600\tIN\tA\t192.0.2.1
ns1.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20240101010101 20240101010101 38353 example. iQF6pCPHm0UPARJeK4bQ3G4E+nk4pAQBnsxDLrZSWvEJEt31NELTrBftyoBBawfzP4V6/n5+8KPQ2LDN4Gws1xZlqrrKPFQOSho83Wfk0Arx9RSet8W1RSj+RabVV3BFkbJkBE5s+bGDDL7gJvdFwHfPT0xSFpSG65qAi+NYtmg=
ns1.example.\t3600\tIN\tNSEC\tns2.example. A RRSIG NSEC
ns1.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20240101010101 20240101010101 38353 example. cr3lvE/56qrQcLg98R/2XLpNF6gJ/VHmVwKJrr+mH22JhtsDicPxggQOOogv+AJ+eXqd4C76NRRYv/PfuAau75gySKNTCMhit+NlAUKxi7aNpNa9uY0sT2j55xm0BjBHgC1oYDtNuRitTIwJDC3LydoG8wEXNWACMfn7dPxz/7w=
ns2.example.\t3600\tIN\tA\t192.0.2.2
ns2.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20240101010101 20240101010101 38353 example. O6jfsXRL0shlZ4gyYLc2HZhNUPvU70+j0+b/tTrohkwJwSnwBd0mP4arQ8qTjOpWmDR2EgYVKRc0sVBKdOjXthjaxTBmA24KifrbcKkMeaZwDAlfpHjgW4uWxFv+EK2LrIqpzLdIKUYOKmlWJgixmg47jeBZCgl76QKPzuXkWBA=
ns2.example.\t3600\tIN\tNSEC\t*.w.example. A RRSIG NSEC
ns2.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20240101010101 20240101010101 38353 example. G1diMrjHA5ESNK6vsuLYgTLCt8OmZBicO8XO0hXmzNwmToiJgGFxiWCCyHCRm/GINBOEEqR0pVXvA88tfmR1370YWD45mdMLeQm0pA+8nOwB3+2q7ow2/Us7S33319kvJcdkksZGBr+yzgh95YyvrJQ6no4BPTZ/t8Vp1IUxs78=
*.w.example.\t3600\tIN\tMX\t1 ai.example.
*.w.example.\t3600\tIN\tRRSIG\tMX 8 2 3600 20240101010101 20240101010101 38353 example. Xxw3GRDGppmG7vtqB+hvqAIlRI8FEFuZomVXaquhYSUHk07/3XI3gpzkn9tZihAZXp9ZOCzJ8Wqz2n1HzPN5od5hh1Jr48aEPqvG/cU2Uh8ChblR+6yX/op8rBSkSnJvh/4MfxmFYBmnWXVQRmcOwVqKhyiWbMsBtK3mKf2FQMo=
*.w.example.\t3600\tIN\tNSEC\tx.w.example. MX RRSIG NSEC
*.w.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20240101010101 20240101010101 38353 example. hR8wuOcdiaOcBqs/MN9mh4SY40yaHa1lOhCDoxwG1KLqkZi3anN3RdBpx2GssT37rQv+YFpftX2wdn4pvxpRLRkQLtwbAphUDnAAa6rCrfqerUo+3Xcc2+xOx5wyHjTQ0ZRzf2H6hG+VEUbDEQ1nsFXoVqAl2RhcB+WC5zbYfvc=
x.w.example.\t3600\tIN\tMX\t1 xx.example.
x.w.example.\t3600\tIN\tRRSIG\tMX 8 3 3600 20240101010101 20240101010101 38353 example. ffs2V0oDavRzclaPILSPmSyj8fk1di264FRpz2hlcFfSpHeRw5VOleM/HZ/O/OOKepjZLyvRlfwOO/xeN6JEK1utOQxDLEoziJRx/II3XehkRtfMMY/MP4yRQ3IOtCChzMbzluiZYoyG6DQ/rNJrb+mtEE5p1XJe4dlcjHjCcJ8=
x.w.example.\t3600\tIN\tNSEC\tx.y.w.example. MX RRSIG NSEC
x.w.example.\t3600\tIN\tRRSIG\tNSEC 8 3 3600 20240101010101 20240101010101 38353 example. sgkt+WxHIbNPUFwSBbRgskm6V/g5I7mpKUB1OE3HhWQPrXwLgfuKGVwRQHoYT5yclSblgQGz498mqu7OBRtr+JKBAx1X8IjFXcRF1kWtYJbj8oyR/wv4JRrvr5MT78WE0wv6Iu8gYKMB/8zzluBwQGBKXr449kT2cuzgtB3/Dr4=
x.y.w.example.\t3600\tIN\tMX\t1 xx.example.
x.y.w.example.\t3600\tIN\tRRSIG\tMX 8 4 3600 20240101010101 20240101010101 38353 example. ul6QjoykQ6Fv82wQtSCr2FKjmO+9xcBbqtCTPG+Pe1as5h0uQ9g1CRVA5hL8tyroNVN2ZnOgC4pS9IwvqSd5uhSAe9GvUZ/yfXfe7dLjgaLnHRckQeiaUCkQns7jd9KwTY+q2AQP4U3Rv4xkuWU1NpzjvuCP0WjKAxkVebxXzYU=
x.y.w.example.\t3600\tIN\tNSEC\txx.example. MX RRSIG NSEC
x.y.w.example.\t3600\tIN\tRRSIG\tNSEC 8 4 3600 20240101010101 20240101010101 38353 example. ioQ/JE7YxVTd+FKHI+cejcrboc6hcIMRuYyPufM+VZ/2k/QN7BRjivwdUdumksaRHBZ4pjy92kNfZs2mwTtWMHGrscGnYNc+np8PS/UVXzf64I/rxsM0Y0xHj47J7mzfW9ckeMhPUYwkGIdEpofXD75qEmLpdNtnFHVm83E8Wvw=
xx.example.\t3600\tIN\tA\t192.0.2.10
xx.example.\t3600\tIN\tRRSIG\tA 8 2 3600 20240101010101 20240101010101 38353 example. Sdi0syLs5N4MQAXj7MAQWMM1ctA61fACVqCnkmJ/fo5DMlql7Jzw0+j0RioWq+hpvGBP3yC4eImwVguU77SL/b1m8IbzxTvqdOyq5g2SbpRhkeGlZMDqluoOYHaVHeO1MFTctKa3TZ0c7tB5e2V4Z7soPA8J0LR5StXxWfay9K0=
xx.example.\t3600\tIN\tHINFO\t"KLH-10" "TOPS-20"
xx.example.\t3600\tIN\tRRSIG\tHINFO 8 2 3600 20240101010101 20240101010101 38353 example. TBscw+fZ/WwLzuQB6hB7qIn1KY/dU4KxTIJNasT8ky5xpMVNps+yofRoMVF0O5vDEAEnEfSjLrLfWk7DGrYJghUAhc8K4m5UQSCwUyYSJiy9n4jaFVqpOaDKCiKWkW+VSWlG+0VWkAY8Hm6JgA2O/GdxxlYqZkEKG/0ZOcV1tnc=
xx.example.\t3600\tIN\tAAAA\t2001:db8::f00:baaa
xx.example.\t3600\tIN\tRRSIG\tAAAA 8 2 3600 20240101010101 20240101010101 38353 example. Eu4tNWn/jzq0lwTx9FCO+B2/Anj64FE1KtxTQ9FDITrTO/w5LkPYCJVOaF3gOUvuY4sQieWcaZPIXDkt/JAvRFrOoDWhwwgWY56Ic/UsSmq8ia6DaF9sUVu1MKKIVWw/0mN6S3rE7HixiVaxjxnZoDHC/xyJtmY1/z87q29wGRw=
xx.example.\t3600\tIN\tNSEC\texample. A HINFO AAAA RRSIG NSEC
xx.example.\t3600\tIN\tRRSIG\tNSEC 8 2 3600 20240101010101 20240101010101 38353 example. PB3pkKf0VHe7GHFbvW6y4lvKxhJx8+p0BGfQqMwGWsC95WUq0244a4bKigraFRR59RCuFjuwUkSKgEs2knxRW4rTjfs6bcbzMr7y1Cwa58tMXU73yg4A881iiC+guiKbu1Gfi9uXTrpuMmi8+hHeaUqPO78N9h/r2QKRnj0lr6s=
"###.replace("\\t", "\t");

        let zone_file_path = mk_test_data_abs_path_string("test-data/example.CDS+CDNSKEY");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+31967");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.+008+38353");

        // Use -T to output RRSIG timestmaps in YYYYMMDDHHmmSS format to match
        // RFC 4035 Appendix A.
        // Use -R to get similar ordering to that of RFC 4035 Appendix A.
        // Use -e and -i to generate RRSIG timestamps that match RFC 4035 Appendix A.
        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-T",
            "-R",
            "-f-",
            "-e",
            "20240101010101",
            "-i",
            "20240101010101",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stdout, expected_signed_zone);
        assert_eq!(res.stderr, "");
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn non_existing_input_file_should_not_create_empty_output_file() {
        let dir = tempfile::TempDir::new().unwrap();

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            dir.path()
                .join("missing_zonefile")
                .to_string_lossy()
                .as_ref(),
            dir.path().join("missing_key").to_string_lossy().as_ref(),
        ])
        .run();

        assert!(!res.stderr.is_empty());
        assert_eq!(res.stdout, "");
        assert_eq!(res.exit_code, 1);

        assert!(!dir.path().join("missing_zonefile.signed").exists());
    }

    #[test]
    fn dnst_signzone_nsec3_signed_zone_example_with_minus_capital_l() {
        let expected_signed_zone = r###"; H(example.org) = 8um1kjcjmofvvmq7cb0op7jt39lg8r9j.example.org
; H(some.example.org) = vrcj1rgalbb9eh2ii8a43fbeib1ufqf6.example.org
example.org.\t239\tIN\tSOA\texample.net. hostmaster.example.net. 1234567890 28800 7200 604800 238
example.org.\t239\tIN\tRRSIG\tSOA 8 2 239 1429574399 1129852800 28954 example.org. V1LINcwCh6ulr9LBERp2zTUW4QfvoUKiv8VX5P8S03SZ9hdNk2BDLzNJj5TJj6o4ki708+DNzyqVHdz+EgyGUR9wH/vT9PxgRrKzjhJ35ktkKFLO+r08XxLMfZ7sCQrVYYr+LRpzDbzGqQby2fisMbNY8V4Lq3c7C7INP64peag=
example.org.\t239\tIN\tRRSIG\tDNSKEY 8 2 239 1429574399 1129852800 51331 example.org. VBK2AFt1u3O0HIBjJrvQ2mo4aRnQcF5j1ibZ1FVpPoi6qtQ9MeL0B67AZJOcEgX080miM4IR+OujTooU1Npor8TIfx1nKr9Yamxzt1hrZkZz4eIbZ68bXPIBuLuvD/5Br4x0TcrXL+R6/QaRErPnbpB8WIBRohofoqMVFRR0Og0=
example.org.\t239\tIN\tRRSIG\tNSEC3PARAM 8 2 239 1429574399 1129852800 28954 example.org. IHWhCUqMv3MqMfeQgKhqqSBHVBku1KWXR8kqwnYK2WIPh8lip3TQPvvp/30VWZmuzHy6ixgO35rmPLwQEJmUIkjFFhAR+YLdqOlxN0gxIU7t3kwyyjNsKlRZhiNTwb9dDGhaSkkae4zww9ZT9reZVIvDQ6y79hiriLYEB30o2QY=
example.org.\t239\tIN\tDNSKEY\t256 3 8 AwEAAcCIpalbX67WU8Z+gI/oaeD0EjOt41Py++X1HQauTfSB5gwivbGwIsqA+Qf5+/j3gcuSFRbFzyPfAb5x14jy/TU3MWXGfmJsJX/DeTqiMwfTQTTlWgMdqRi7JuQoDx3ueYOQOLTDPVqlyvF5/g7b9FUd4LO8G3aO2FfqRBjNG8px
example.org.\t239\tIN\tDNSKEY\t257 3 8 AwEAAckp/oMmocs+pv4KsCkCciazIl2+SohAZ2/bH2viAMg3tHAPjw5YfPNErUBqMGvN4c23iBCnt9TktT5bVoQdpXyCJ+ZwmWrFxlXvXIqG8rpkwHi1xFoXWVZLrG9XYCqLVMq2cB+FgMIaX504XMGk7WQydtV1LAqLgP3B8JA2Fc1j
example.org.\t239\tIN\tNSEC3PARAM\t1 0 0 -
8um1kjcjmofvvmq7cb0op7jt39lg8r9j.example.org.\t238\tIN\tRRSIG\tNSEC3 8 3 238 1429574399 1129852800 28954 example.org. O4eZ+kgHciA7xfgjHwM2OxREhwQr49bsTujdBFXNxwFmhlaB9kfMd8d+WIYSZLvhcchh5a8cOAsCc0FRmelEAAs3wh0LzWPjmzVsLIU3iM/dgjyYm524jD0HMJDw2OYo8d6RKeF2anCbA/ynno5OmJd8TZ/h1tZ5BTso/mtZckI=
8um1kjcjmofvvmq7cb0op7jt39lg8r9j.example.org.\t238\tIN\tNSEC3\t1 0 0 - VRCJ1RGALBB9EH2II8A43FBEIB1UFQF6 SOA RRSIG DNSKEY NSEC3PARAM
some.example.org.\t240\tIN\tA\t1.2.3.4
some.example.org.\t240\tIN\tRRSIG\tA 8 3 240 1429574399 1129852800 28954 example.org. HJ+HG8Z6jgSuzeBTbNtgLXO4QXXGNbrqijGfNrSIjqLJi1w8S/ADsiamh9Kua6EtwP653uYWmG34pA2mE8TDq6jjJp4ExCEs0fuYBsw7dkNiG++yh8oSr7jVHkYm3sQuDZC2984c4zIKolJD85dsGZ9Pp5b/YFdzQUj1nrhwIs8=
vrcj1rgalbb9eh2ii8a43fbeib1ufqf6.example.org.\t238\tIN\tRRSIG\tNSEC3 8 3 238 1429574399 1129852800 28954 example.org. fpbF8OsVXpUwFzsTRmGmVcEJ5+h/5FrlyqO+goyUapRudSPS7Izxblz+RE3IRu1eYOdYdU62Sz9hnpRK2NCs7NuBacLRGKiudNI5fv/Z0XF3nELjM3TSk7WYfCOFAjgoEGK2OKZrNWUTONsdaFNeJbs/SyzW+77nbWYZ4Al16gQ=
vrcj1rgalbb9eh2ii8a43fbeib1ufqf6.example.org.\t238\tIN\tNSEC3\t1 0 0 - 8UM1KJCJMOFVVMQ7CB0OP7JT39LG8R9J A RRSIG
"###.replace("\\t", "\t");

        let zone_file_path =
            mk_test_data_abs_path_string("test-data/example.org.rfc9077-min-is-soa-minimum");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+51331");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+28954");

        // Signature validity period (expiration via `-e` and inception via
        // `-i`) are specified to make output matching more deterministic.
        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-f-",
            "-e",
            "20150420235959",
            "-i",
            "20051021000000",
            "-n",
            "-L",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run();

        assert_eq!(res.stderr, "");
        assert_eq!(res.stdout, expected_signed_zone);
        assert_eq!(res.exit_code, 0);
    }

    #[test]
    fn set_soa_serial_to_epoch_time() {
        let zone_file_path =
            mk_test_data_abs_path_string("test-data/example.org.rfc9077-min-is-soa-ttl");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+51331");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+28954");

        // Simulate that the time now is later than the 1234567890 SOA SERIAL
        // in the zonefile.
        let time_now = 1234567891;
        let expected_soa_line = format!("example.org.\t238\tIN\tSOA\texample.net. hostmaster.example.net. {} 28800 7200 604800 239\n", time_now);

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-f-",
            "-u",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run_with_modified_env(|env| env.set_seconds_since_epoch(time_now));

        assert_eq!(res.stderr, "");
        assert_eq!(res.exit_code, 0);
        assert_eq!(
            filter_lines_containing_all(&res.stdout, &["SOA", "hostmaster"]),
            expected_soa_line,
        );
    }

    #[test]
    fn increment_soa_serial() {
        let zone_file_path =
            mk_test_data_abs_path_string("test-data/example.org.rfc9077-min-is-soa-ttl");
        let ksk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+51331");
        let zsk_path = mk_test_data_abs_path_string("test-data/Kexample.org.+008+28954");

        // Simulate that the time now is earlier than the 1234567890 SOA
        // SERIAL in the zonefile.
        let time_now = 1234567889;
        let expected_soa_line = "example.org.\t238\tIN\tSOA\texample.net. hostmaster.example.net. 1234567891 28800 7200 604800 239\n";

        let res = FakeCmd::new([
            "dnst",
            "signzone",
            "-f-",
            "-u",
            &zone_file_path,
            &ksk_path,
            &zsk_path,
        ])
        .run_with_modified_env(|env| env.set_seconds_since_epoch(time_now));

        assert_eq!(res.stderr, "");
        assert_eq!(res.exit_code, 0);
        assert_eq!(
            filter_lines_containing_all(&res.stdout, &["SOA", "hostmaster"]),
            expected_soa_line,
        );
    }

    // TODO: Add a test for https://rfc-annotations.research.icann.org/rfc6840.html#section-5.1?

    // ------------ Helper functions -----------------------------------------

    fn create_file_with_content(dir: &TempDir, filename: &str, content: &[u8]) {
        let mut file = File::create(dir.path().join(filename)).unwrap();
        file.write_all(content).unwrap();
    }

    fn run_setup() -> TempDir {
        let dir = tempfile::TempDir::new().unwrap();

        create_file_with_content(&dir, "ksk1.key", b"example.org. IN DNSKEY 257 3 15 6VdB0mk5qwjHWNC5TTOw1uHTzA0m3Xadg7aYVbcRn8Y= ;{id = 38873 (ksk), size = 256b}\n");
        create_file_with_content(&dir, "ksk1.ds", b"example.org. IN DS 38873 15 2 e195b1a7d31c878993ad0095d723592a1e5ea55c90b229fc35e4c549ef406f6c\n");
        create_file_with_content(&dir, "ksk1.private", b"Private-key-format: v1.2\nAlgorithm: 15 (ED25519)\nPrivateKey: /e7bFDFF88sdC949PC2YoHX9KJ5eEak3bk/Tub2vIng=\n");

        create_file_with_content(&dir, "zsk1.key", b"example.org. IN DNSKEY 256 3 15 fPzhX3Tq/w3ncwsWYIRsK8rHLNtkVv1O3kXYAMdBQUk= ;{id = 44471 (zsk), size = 256b}");
        create_file_with_content(&dir, "zsk1.private", b"Private-key-format: v1.2\nAlgorithm: 15 (ED25519)\nPrivateKey: mc2xW8JiES5Ub6UPP2xoHT0KyD6Lvi6fnjugjnRzBJU=");

        create_file_with_content(&dir, "zonemd1_example.org.zone", b"\
                example.org.    240     IN      SOA     example.net. hostmaster.example.net. 1234567890 28800 7200 604800 240\n\
                example.org.    240     IN      NS      example.net.\n\
                ; Will be replaced when using ZONEMD option\n\
                example.org.    240     IN      ZONEMD 1234567890 1 1 ABABABABABABABABABABABABABABABABABABABABABABABAB ABABABABABABABABABABABABABABABABABABABABABABABAB\n\
                example.org.    240     IN      ZONEMD 1234567890 1 2 ABABABABABABABABABABABABABABABABABABABABABABABAB ABABABABABABABABABABABABABABABABABABABABABABABAB ABABABABABABABABABABABABABABABAB\n\
                example.org.                240 IN  A  128.140.76.106\n\
                *.example.org.              240 IN  A  1.2.3.4\n\
                deleg.example.org.          240 IN  NS example.com.\n\
                occluded.deleg.example.org. 240 IN  A  1.2.3.4\n\
                ");

        create_file_with_content(&dir, "nsec3_optout1_example.org.zone", b"\
                example.org.                          240 IN SOA example.net. hostmaster.example.net. 1234567890 28800 7200 604800 240\n\
                example.org.                          240 IN NS  example.net.\n\
                example.org.                          240 IN A   128.140.76.106\n\
                insecure-deleg.example.org.           240 IN NS  example.com.\n\
                occluded.insecure-deleg.example.org.  240 IN A   1.2.3.4\n\
                secure-deleg.example.org.             240 IN NS  example.com.\n\
                secure-deleg.example.org.             240 IN DS  3120 15 2 0675d8c4a90ecd25492e4c4c6583afcef7c3b910b7a39162803058e6e7393a19\n\
                ");

        dir
    }

    /// Filter a string slice for lines containing at least one of the provided patterns.
    #[allow(dead_code)]
    fn filter_lines_containing_any(src: &str, patterns: &[&str]) -> String {
        if patterns.is_empty() {
            // For consistency with str::contains() and filter_lines_containing_all()
            String::from(src)
        } else {
            src.split_inclusive('\n')
                .filter(|s| {
                    for p in patterns {
                        if s.contains(p) {
                            return true;
                        }
                    }
                    false
                })
                .collect()
        }
    }

    /// Filter a string slice for lines containing all provided patterns.
    fn filter_lines_containing_all(src: &str, patterns: &[&str]) -> String {
        src.split_inclusive('\n')
            .filter(|s| {
                for p in patterns {
                    if !s.contains(p) {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    fn mk_test_data_abs_path_string(rel_path: &str) -> String {
        std::env::current_dir()
            .unwrap()
            .join(rel_path)
            .to_string_lossy()
            .to_string()
    }
}
