use core::cmp::Ordering;
use core::fmt::Write;
use core::ops::Add;
use core::str::FromStr;

use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::hash::RandomState;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};

use bytes::{BufMut, Bytes, BytesMut};
use clap::builder::ValueParser;
use domain::base::iana::nsec3::Nsec3HashAlg;
use domain::base::iana::zonemd::{ZonemdAlg, ZonemdScheme};
use domain::base::name::FlattenInto;
use domain::base::zonefile_fmt::ZonefileFmt;
use domain::base::{Name, NameBuilder, Record, Rtype, Serial, Ttl};
use domain::rdata::dnssec::Timestamp;
use domain::rdata::nsec3::Nsec3Salt;
use domain::rdata::{Dnskey, Nsec3, Nsec3param, Soa, ZoneRecordData, Zonemd};
use domain::sign::common::{FromBytesError, KeyPair};
use domain::sign::records::{
    Family, FamilyName, Nsec3OptOut, Nsec3Records, RecordsIter, SortedRecords,
};
use domain::sign::{SecretKeyBytes, SigningKey};
use domain::validate::Key;
use domain::zonefile::inplace::{self, Entry};
use domain::zonetree::types::StoredRecordData;
use domain::zonetree::{StoredName, StoredRecord};
use lexopt::Arg;
use octseq::builder::with_infallible;
use ring::digest;

use crate::env::{Env, Stream};
use crate::error::Error;
use crate::Args;

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
    /// Add a ZONEMD resource record
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

    /// Allow ZONEMDs to be added without signing
    #[arg(short = 'Z', requires = "zonemd")]
    allow_zonemd_without_signing: bool,

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
        short = 'P',
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
    // May be omitted if -Z or -H are given
    #[arg(value_name = "key", required_unless_present_any = ["allow_zonemd_without_signing", "hash_only"])]
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
        let mut expiration = Timestamp::now().into_int().add(FOUR_WEEKS).into();
        let mut out_file = Option::<PathBuf>::None;
        let mut inception = Timestamp::now();
        let mut origin = Option::<Name<Bytes>>::None;
        let mut set_soa_serial_to_epoch_time = false;
        let mut zonemd = Vec::new();
        let mut allow_zonemd_without_signing = false;
        let mut use_nsec3 = false;
        let mut algorithm = Nsec3HashAlg::SHA1;
        let mut iterations = 1u16;
        let mut salt = Nsec3Salt::<Bytes>::empty();
        let mut nsec3_opt_out_flags_only = false;
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
                    nsec3_opt_out_flags_only = true;
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
            return Err("Missing key argument".into());
        };

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
            use_nsec3,
            algorithm,
            iterations,
            salt,
            nsec3_opt_out_flags_only,
            nsec3_opt_out: false,
            hash_only: false,
            zonefile_path,
            key_paths,
            no_require_keys_match_apex: false,
            invoked_as_ldns: true,
        })))
    }
}

impl SignZone {
    fn parse_zonemd_tuple(arg: &str) -> Result<ZonemdTuple, Error> {
        let scheme;
        let hash_alg;

        if let Some((s, h)) = arg.split_once(':') {
            scheme = s
                .parse()
                .map_err(|e| format!("Error while parsing zonemd scheme: {e}"))?;
            hash_alg = h
                .parse()
                .map_err(|e| format!("Error while parsing zonemd hash algorithm: {e}"))?;
        } else {
            scheme = ZonemdScheme::SIMPLE;
            hash_alg = arg
                .parse()
                .map_err(|e| format!("Error while parsing zonemd hash algorithm: {e}"))?;
        };

        Ok(ZonemdTuple(scheme, hash_alg))
    }

    fn parse_zonemd_tuple_ldns(arg: &str) -> Result<ZonemdTuple, Error> {
        let scheme;
        let hash_alg;

        fn parse_zonemd_scheme_ldns(s: &str) -> Result<ZonemdScheme, Error> {
            match s {
                "simple" | "1" => Ok(ZonemdScheme::SIMPLE),
                _ => Err("unknown ZONEMD scheme name or number".into()),
            }
        }

        fn parse_zonemd_hash_alg_ldns(h: &str) -> Result<ZonemdAlg, Error> {
            match h {
                "sha384" | "1" => Ok(ZonemdAlg::SHA384),
                "sha512" | "2" => Ok(ZonemdAlg::SHA512),
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
        // Make sure, zonemd arguments are unique
        let zonemd: HashSet<ZonemdTuple> = HashSet::from_iter(self.zonemd.clone());

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
        } else if self.key_paths.is_empty() {
            if self.allow_zonemd_without_signing {
                SigningMode::None
            } else {
                return Err("Missing key argument".into());
            }
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

        let mut writer = if out_file.as_os_str() == "-" {
            FileOrStdout::Stdout(env.stdout())
        } else {
            let file = File::create(env.in_cwd(&out_file))?;
            let file = BufWriter::new(file);
            FileOrStdout::File(file)
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
        let mut records = self.load_zone(&env)?;

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

        // Extract and validate the DNSKEY RRs from the loaded zone.
        let mut found_public_keys = vec![];
        for rr in records.iter() {
            if let ZoneRecordData::Dnskey(dnskey) = rr.data() {
                // Create a public key object from the found DNSKEY RR.
                let public_key =
                    Key::from_dnskey(rr.owner().clone(), dnskey.clone()).map_err(|err| {
                        Error::from(format!(
                            "Zone file '{}' DNSKEY record '{dnskey}' is invalid: {err}",
                            self.zonefile_path.display()
                        ))
                    })?;

                found_public_keys.push(public_key);
            }
        }

        // Load the specified private keys, match them against the found
        // public keys, failing that load a DNSKEY RR from the corresponding
        // public key file and validate that its owner matches that of the
        // zone apex. Unlike ldns-signzone we don't use a generated public key
        // if these attempts fail.
        let mut keys: Vec<SigningKey<Bytes, KeyPair>> = vec![];

        'next_key_path: for key_path in &self.key_paths {
            let key_path = env.in_cwd(key_path).into_owned();
            // Load the private key.
            let private_key_path = Self::mk_private_key_path(&key_path);
            let private_key = Self::load_private_key(&private_key_path)?;

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
                if let Ok(signing_key) = Self::mk_signing_key(&private_key, public_key.clone()) {
                    // Match found, keep the created signing key.
                    // TODO: Log here.
                    // TODO: Check the key tag against the key tag in the key file name?
                    // println!(
                    //     "DNSKEY RR with key tag {} matches loaded private key '{}'",
                    //     public_key.key_tag(),
                    //     private_key_path.display()
                    // );
                    keys.push(signing_key);
                    continue 'next_key_path;
                }
            }

            // No matching public key found, try to load the public key
            // instead.
            let public_key_path = Self::mk_public_key_path(&key_path);
            let public_key = Self::load_public_key(&public_key_path)?;

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

            // Attempt to crate a key pair from the loaded private and public
            // keys.
            let signing_key =
                Self::mk_signing_key(&private_key, public_key.clone()).map_err(|err| {
                    format!(
                        "Unable to create key pair from '{}' and '{}': {}",
                        public_key_path.display(),
                        private_key_path.display(),
                        err
                    )
                })?;

            // Store the created signing key.
            keys.push(signing_key);

            // TODO: Log
            // println!(
            //     "Loaded public key with key tag {} from '{}' for private key '{}'",
            //     public_key.key_tag(),
            //     public_key_path.display(),
            //     private_key_path.display()
            // );

            let public_key = Key::<Bytes>::new(
                public_key.owner().clone(),
                public_key.flags() + 1,
                public_key.raw_public_key().clone(),
            );

            let signing_key =
                Self::mk_signing_key(&private_key, public_key.clone()).map_err(|err| {
                    format!(
                        "Unable to create key pair from '{}' and '{}': {}",
                        public_key_path.display(),
                        private_key_path.display(),
                        err
                    )
                })?;

            // Store the created signing key.
            keys.push(signing_key);
        }

        // Change the SOA serial.
        if self.set_soa_serial_to_epoch_time {
            Self::bump_soa_serial(&mut records)?;
        }

        // Find the apex.
        let (apex, ttl, soa_serial) = Self::find_apex(&records).unwrap();

        if !zonemd.is_empty() {
            Self::replace_apex_zonemd_with_placeholder(&mut records, &apex, soa_serial, ttl);
        }

        // Hash the zone with NSEC or NSEC3, unless only ZONEMD is done.
        let hashes = if matches!(
            signing_mode,
            SigningMode::HashOnly | SigningMode::HashAndSign
        ) {
            if self.use_nsec3 {
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
            }
        } else {
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
                .map_err(|_| "Signing failed")?;
            records.extend(extra_records.into_iter().map(Record::from_record));
        }

        if !zonemd.is_empty() {
            // Remove existing ZONEMD RRs at apex (the placeholder is no longer needed)
            let _ = records.remove_first_by_name_class_rtype(
                apex.owner().clone(),
                None,
                Some(Rtype::ZONEMD),
            );

            let zonemd_rrs =
                Self::create_zonemd_digest_and_records(&records, &apex, &zonemd, soa_serial, ttl)?;

            // Add ZONEMD RRs to output records
            records.extend(zonemd_rrs.clone().into_iter().map(Record::from_record));

            self.update_zonemd_rrsig(&mut records, &apex, &keys, zonemd_rrs);
        }

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
        let family_iter: AnyFamiliesIter = if self.extra_comments && hashes.is_some() {
            families = records.families().collect::<Vec<_>>();
            let Some(hashes) = hashes.as_ref() else {
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

        let nsec3_cs = Nsec3CommentState {
            hashes: hashes.as_ref(),
            apex: &apex,
        };

        for family in family_iter {
            if let Some(hashes) = hashes.as_ref() {
                // If this is family contains an NSEC3 RR and the number of
                // RRs in the RRSET of the unhashed owner name is zero, then
                // the NSEC3 was generated for an empty non-terminal.
                if family.rrsets().any(|rrset| rrset.rtype() == Rtype::NSEC3) {
                    if let Some(unhashed_name) = hashes.get(family.owner()) {
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

            // The SOA is output separately above as the very first RRset so
            // we skip that, and we skip RRSIGs as they are output only after
            // the RRset that they cover.
            for rrset in family
                .rrsets()
                .filter(|rrset| !matches!(rrset.rtype(), Rtype::SOA | Rtype::RRSIG))
            {
                for rr in rrset.iter() {
                    writer.write_fmt(format_args!("{}", rr.display_zonefile(false, true)))?;
                    match rr.data() {
                        ZoneRecordData::Nsec3(nsec3) => nsec3.comment(&mut writer, rr, nsec3_cs)?,
                        ZoneRecordData::Dnskey(dnskey) => dnskey.comment(&mut writer, rr, ())?,
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

                // Now attempt to print the RRSIG that covers the RTYPE of this RRSET.
                if let Some(covering_rrsig_rr) = family
                    .rrsets()
                    .filter(|this_rrset| this_rrset.rtype() == Rtype::RRSIG)
                    .find_map(|this_rrset| this_rrset.iter().find(|rr| matches!(rr.data(), ZoneRecordData::Rrsig(rrsig) if rrsig.type_covered() == rrset.rtype())))
                {
                    writer.write_fmt(format_args!("{}", covering_rrsig_rr.display_zonefile(false, true)))?;
                    writer.write_str("\n")?;
                    if self.extra_comments {
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
    ) -> Result<SortedRecords<StoredName, StoredRecordData>, Error> {
        // Don't use Zonefile::load() as it knows nothing about the size of
        // the original file so uses default allocation which allocates more
        // bytes than are needed. Instead control the allocation size based on
        // our knowledge of the file size.
        let mut zone_file = File::open(env.in_cwd(&self.zonefile_path))?;
        let zone_file_len = zone_file.metadata()?.len();
        let mut buf = inplace::Zonefile::with_capacity(zone_file_len as usize).writer();
        std::io::copy(&mut zone_file, &mut buf)?;
        let mut reader = buf.into_inner();
        let mut records = SortedRecords::new();

        if let Some(origin) = &self.origin {
            reader.set_origin(origin.clone());
        }

        for entry in reader {
            let entry = entry.map_err(|err| format!("Invalid zone file: {err}"))?;
            match entry {
                Entry::Record(record) => {
                    let record: StoredRecord = record.flatten_into();

                    let _ = records.insert(record);
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
    ) -> Result<(FamilyName<Name<Bytes>>, Ttl, Serial), Error> {
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

        Ok((soa.family_name().cloned(), ttl, serial))
    }

    fn bump_soa_serial(
        records: &mut SortedRecords<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>,
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

    fn load_private_key(key_path: &Path) -> Result<SecretKeyBytes, Error> {
        let private_data = std::fs::read_to_string(key_path).map_err(|err| {
            format!(
                "Unable to load private key from file '{}': {}",
                key_path.display(),
                err
            )
        })?;

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

    fn load_public_key(key_path: &Path) -> Result<Key<Bytes>, Error> {
        let public_data = std::fs::read_to_string(key_path).map_err(|err| {
            format!(
                "Unable to load public key from file '{}': {}",
                key_path.display(),
                err
            )
        })?;

        // Note: Compared to the original ldns-signzone there is a minor
        // regression here because at the time of writing the error returned
        // from parsing indicates broadly the type of parsing failure but does
        // note indicate the line number at which parsing failed.
        let public_key_info = Key::parse_from_bind(&public_data).map_err(|err| {
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
        private_key: &SecretKeyBytes,
        public_key: Key<Bytes>,
    ) -> Result<SigningKey<Bytes, KeyPair>, FromBytesError> {
        let key_pair = KeyPair::from_bytes(private_key, public_key.raw_public_key())?;
        let signing_key = SigningKey::new(public_key.owner().clone(), public_key.flags(), key_pair);
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
        apex: &FamilyName<Name<Bytes>>,
        records: &SortedRecords<StoredName, StoredRecordData>,
        algorithm: ZonemdAlg,
    ) -> Result<digest::Digest, Error> {
        // TODO: optimize by using multiple digest'ers at once, instead of
        // looping over the whole zone per digest algorithm.
        let mut buf: Vec<u8> = Vec::new();

        let mut ctx = match algorithm {
            ZonemdAlg::SHA384 => digest::Context::new(&digest::SHA384),
            ZonemdAlg::SHA512 => digest::Context::new(&digest::SHA512),
            _ => {
                // This should be caught by the argument parsing, but in case...
                return Err("unsupported zonemd hash algorithm".into());
            }
        };

        for family in records.families() {
            if !family.is_in_zone(apex) {
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
            for record in family.records() {
                buf.clear();
                if record.rtype() == Rtype::ZONEMD && record.owner() == apex.owner() {
                    // Skip placeholder ZONEMD at apex
                    continue;
                } else if record.rtype() == Rtype::RRSIG && record.owner() == apex.owner() {
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
        records: &mut SortedRecords<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>,
        apex: &FamilyName<Name<Bytes>>,
        soa_serial: Serial,
        ttl: Ttl,
    ) {
        // Remove existing ZONEMD RRs at apex for any class (it's class independent).
        let _ =
            records.remove_all_by_name_class_rtype(apex.owner().clone(), None, Some(Rtype::ZONEMD));

        // Insert placeholder ZONEMD at apex for
        // correct NSEC(3) bitmap (will be replaced later).
        let placeholder_zonemd = ZoneRecordData::Zonemd(Zonemd::new(
            soa_serial,
            ZonemdScheme::from_int(0),
            ZonemdAlg::from_int(0),
            Bytes::default(),
        ));
        let _ = records.insert(Record::new(
            apex.owner().clone(),
            apex.class(),
            ttl,
            placeholder_zonemd,
        ));
    }

    fn create_zonemd_digest_and_records(
        records: &SortedRecords<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>,
        apex: &FamilyName<Name<Bytes>>,
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
            zonemd_rrs.push(Record::new(
                apex.owner().clone(),
                apex.class(),
                ttl,
                tmp_zrr,
            ));
        }

        Ok(zonemd_rrs)
    }

    fn update_zonemd_rrsig(
        &self,
        records: &mut SortedRecords<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>,
        apex: &FamilyName<Name<Bytes>>,
        keys: &Vec<SigningKey<Bytes, KeyPair>>,
        zonemd_rrs: Vec<Record<StoredName, StoredRecordData>>,
    ) {
        // Sign only ZONEMD RRs
        let zonemd_rrs: SortedRecords<StoredName, StoredRecordData> =
            SortedRecords::from(zonemd_rrs);
        // No need to check for keys, as SortedRecords::sign just doesn't do anything without keys.
        let mut zonemd_rrsig = zonemd_rrs
            .sign(
                apex,
                self.expiration,
                self.inception,
                keys.as_slice(),
                false,
            )
            .unwrap();

        // Replace original ZONEMD RRSIG with newly generated one
        if let Some(rrsig) = zonemd_rrsig.pop() {
            if let ZoneRecordData::Rrsig(rrsig) = rrsig.data() {
                records.replace_rrsig_for_apex_zonemd(rrsig.clone(), apex);
            }
        }
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
    /// Neither hash or sign zone records (e.g. when just using ZONEMD).
    None,
}

//------------ ZonemdTuple ---------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
struct ZonemdTuple(ZonemdScheme, ZonemdAlg);

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
        record: &Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>,
        metadata: T,
    ) -> Result<(), fmt::Error>;
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

#[derive(Copy, Clone)]
struct Nsec3CommentState<'a> {
    hashes: Option<&'a HashMap<Name<Bytes>, Name<Bytes>, RandomState>>,
    apex: &'a FamilyName<Name<Bytes>>,
}

impl<'b, O: AsRef<[u8]>> Commented<Nsec3CommentState<'b>> for Nsec3<O> {
    fn comment<'a, W: fmt::Write>(
        &self,
        writer: &mut W,
        record: &'a Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>,
        state: Nsec3CommentState<'b>,
    ) -> Result<(), fmt::Error> {
        if let Some(hashes) = state.hashes {
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

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Write;
    use std::ops::Add;
    use std::path::PathBuf;

    use domain::base::iana::{Nsec3HashAlg, ZonemdAlg, ZonemdScheme};
    use domain::rdata::dnssec::Timestamp;
    use domain::rdata::nsec3::Nsec3Salt;
    use tempfile::TempDir;

    use crate::commands::signzone::{ZonemdTuple, FOUR_WEEKS};
    use crate::commands::Command;
    use crate::env::fake::FakeCmd;

    use super::SignZone;

    #[track_caller]
    fn parse(args: FakeCmd) -> SignZone {
        let res = args.parse();
        let Command::SignZone(x) = res.unwrap().command else {
            panic!("Not a SignZone!");
        };
        x
    }

    #[test]
    fn dnst_parse() {
        let cmd = FakeCmd::new(["dnst", "signzone"]);

        cmd.parse().unwrap_err();
        cmd.args(["example.org.zone"]).parse().unwrap_err();
        cmd.args(["-Z", "example.org.zone"]).parse().unwrap_err();
        cmd.args(["-z", "simple:sha512", "example.org.zone", "key1"])
            .parse()
            .unwrap_err();
        cmd.args(["-z", "sha512", "example.org.zone", "key1"])
            .parse()
            .unwrap_err();
        cmd.args(["-z", "3", "example.org.zone", "key1"])
            .parse()
            .unwrap_err();
        // TODO: other parse failures

        let base = SignZone {
            extra_comments: false,
            do_not_add_keys_to_zone: false,
            expiration: Timestamp::now().into_int().add(FOUR_WEEKS).into(),
            out_file: None,
            inception: Timestamp::now(),
            origin: None,
            set_soa_serial_to_epoch_time: false,
            zonemd: Vec::new(),
            allow_zonemd_without_signing: false,
            use_nsec3: false,
            algorithm: Nsec3HashAlg::SHA1,
            iterations: 0,
            salt: Nsec3Salt::empty(),
            nsec3_opt_out_flags_only: false,
            nsec3_opt_out: false,
            hash_only: false,
            no_require_keys_match_apex: false,
            zonefile_path: PathBuf::from("example.org.zone"),
            key_paths: Vec::from([PathBuf::from("key1")]),
            invoked_as_ldns: false,
        };

        // Check the defaults
        let res = parse(cmd.args(["example.org.zone", "key1"]));
        assert_eq!(res, base);

        let res = parse(cmd.args(["example.org.zone", "-z", "SIMPLE:SHA512", "key1"]));
        assert_eq!(
            res,
            SignZone {
                zonemd: Vec::from([ZonemdTuple(ZonemdScheme::SIMPLE, ZonemdAlg::SHA512)]),
                ..base.clone()
            }
        );

        // TODO: Other arguments
    }

    #[test]
    fn ldns_parse() {
        let cmd = FakeCmd::new(["ldns-signzone"]);

        cmd.parse().unwrap_err();
        cmd.args(["example.org.zone"]).parse().unwrap_err();
        cmd.args(["example.org.zone", "-z", "SIMPLE:SHA512", "key1"])
            .parse()
            .unwrap_err();
        cmd.args(["example.org.zone", "-z", "SHA512", "key1"])
            .parse()
            .unwrap_err();
        cmd.args(["example.org.zone", "-z", "3", "key1"])
            .parse()
            .unwrap_err();
        // TODO: other parse failures

        let base = SignZone {
            extra_comments: false,
            do_not_add_keys_to_zone: false,
            expiration: Timestamp::now().into_int().add(FOUR_WEEKS).into(),
            out_file: None,
            inception: Timestamp::now(),
            origin: None,
            set_soa_serial_to_epoch_time: false,
            zonemd: Vec::new(),
            allow_zonemd_without_signing: false,
            use_nsec3: false,
            algorithm: Nsec3HashAlg::SHA1,
            iterations: 1,
            salt: Nsec3Salt::empty(),
            nsec3_opt_out_flags_only: false,
            nsec3_opt_out: false,
            hash_only: false,
            no_require_keys_match_apex: false,
            zonefile_path: PathBuf::from("example.org.zone"),
            key_paths: Vec::from([PathBuf::from("key1")]),
            invoked_as_ldns: true,
        };

        // Check the defaults
        let res = parse(cmd.args(["example.org.zone", "key1"]));
        assert_eq!(res, base);

        let res = parse(cmd.args(["-Z", "example.org.zone", "key1"]));
        assert_eq!(
            res,
            SignZone {
                allow_zonemd_without_signing: true,
                expiration: Timestamp::now().into_int().add(FOUR_WEEKS).into(),
                inception: Timestamp::now(),
                ..base.clone()
            }
        );

        let res = parse(cmd.args(["-z", "simple:sha512", "example.org.zone", "key1"]));
        assert_eq!(
            res,
            SignZone {
                zonemd: Vec::from([ZonemdTuple(ZonemdScheme::SIMPLE, ZonemdAlg::SHA512)]),
                expiration: Timestamp::now().into_int().add(FOUR_WEEKS).into(),
                inception: Timestamp::now(),
                ..base.clone()
            }
        );

        let res = parse(cmd.args(["example.org.zone", "-z", "sha512", "key1"]));
        assert_eq!(
            res,
            SignZone {
                zonemd: Vec::from([ZonemdTuple(ZonemdScheme::SIMPLE, ZonemdAlg::SHA512)]),
                expiration: Timestamp::now().into_int().add(FOUR_WEEKS).into(),
                inception: Timestamp::now(),
                ..base.clone()
            }
        );

        let res = parse(cmd.args(["example.org.zone", "-z", "1", "key1"]));
        assert_eq!(
            res,
            SignZone {
                zonemd: Vec::from([ZonemdTuple(ZonemdScheme::SIMPLE, ZonemdAlg::SHA384)]),
                expiration: Timestamp::now().into_int().add(FOUR_WEEKS).into(),
                inception: Timestamp::now(),
                ..base.clone()
            }
        );

        // TODO: Other arguments
    }

    fn run_setup() -> TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        let mut file = File::create(dir.path().join("key1.key")).unwrap();
        file
            .write_all(b"example.org. IN DNSKEY 257 3 15 6VdB0mk5qwjHWNC5TTOw1uHTzA0m3Xadg7aYVbcRn8Y= ;{id = 38873 (ksk), size = 256b}")
            .unwrap();

        let mut file = File::create(dir.path().join("key1.ds")).unwrap();
        file
            .write_all(b"example.org. IN DS 38873 15 2 e195b1a7d31c878993ad0095d723592a1e5ea55c90b229fc35e4c549ef406f6c")
            .unwrap();

        let mut file = File::create(dir.path().join("key1.private")).unwrap();
        file
            .write_all(b"Private-key-format: v1.2\nAlgorithm: 15 (ED25519)\nPrivateKey: /e7bFDFF88sdC949PC2YoHX9KJ5eEak3bk/Tub2vIng=\n")
            .unwrap();

        let mut file = File::create(dir.path().join("zonemd1_example.org.zone")).unwrap();
        file
            .write_all("\
                example.org.    240     IN      SOA     example.net. hostmaster.example.net. 1234567890 28800 7200 604800 240\n\
                example.org.    240     IN      NS      example.net.\n\
                ; Will be replaced when using ZONEMD option\n\
                example.org.    240     IN      ZONEMD 1234567890 1 1 ABABABABABABABABABABABABABABABABABABABABABABABAB ABABABABABABABABABABABABABABABABABABABABABABABAB\n\
                example.org.    240     IN      ZONEMD 1234567890 1 2 ABABABABABABABABABABABABABABABABABABABABABABABAB ABABABABABABABABABABABABABABABABABABABABABABABAB ABABABABABABABABABABABABABABABAB\n\
                example.org.                240 IN  A  128.140.76.106\n\
                *.example.org.              240 IN  A  1.2.3.4\n\
                deleg.example.org.          240 IN  NS example.com.\n\
                occluded.deleg.example.org. 240 IN  A  1.2.3.4\n\
                ".as_bytes())
            .unwrap();

        let mut file = File::create(dir.path().join("zonemd2_example.org.zone")).unwrap();
        file
            .write_all("\
                example.org.    240     IN      SOA     example.net. hostmaster.example.net. 1234567890 28800 7200 604800 240\n\
                example.org.    240     IN      NS      example.net.\n\
                example.org.                240 IN  A  128.140.76.106\n\
                *.example.org.              240 IN  A  1.2.3.4\n\
                deleg.example.org.          240 IN  NS example.com.\n\
                occluded.deleg.example.org. 240 IN  A  1.2.3.4\n\
                ".as_bytes())
            .unwrap();

        dir
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
            "example.org.\t240\tIN\tSOA\texample.net.\thostmaster.example.net.\t1234567890\t28800\t7200\t604800\t240\n\
            example.org.\t240\tIN\tA\t128.140.76.106\n\
            example.org.\t240\tIN\tNS\texample.net.\n\
            example.org.\t240\tIN\tZONEMD\t1234567890\t1\t1\tD2D125EE8B4DDAD944FD7EE437908A5D4D5A7DB7C2F948C5A051146FC75D124666033DF7D1BA1653CF490E89F9A454F3\n\
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
            "zonemd2_example.org.zone",
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
            "key1",
        ])
        .cwd(&dir)
        .run();

        dbg!(&res);
        assert_eq!(res.exit_code, 0);
        assert_eq!(
            res.stdout,
            "example.org.\t240\tIN\tSOA\texample.net.\thostmaster.example.net.\t1234567890\t28800\t7200\t604800\t240\n\
            example.org.\t240\tIN\tRRSIG\tSOA\t15\t2\t240\t1732724662\t1732724662\t38874\texample.org.\tubpDtDSKyO1QB8sItZaYgngByZmZ4nC3APfcIhR6LRKcLm2ivNra2QaSnCuMqSNULdPtynqMXtdpd0hAaDCOCQ==\n\
            example.org.\t240\tIN\tA\t128.140.76.106\n\
            example.org.\t240\tIN\tRRSIG\tA\t15\t2\t240\t1732724662\t1732724662\t38874\texample.org.\tbwiPzp/CD3/vGz22da9OVWI34R1CaPqe3LSgm3UyFyQ7zxn8GrlKX5l7OHf15jSyYWgd4qGFER3XgvCj+0ZgCw==\n\
            example.org.\t240\tIN\tNS\texample.net.\n\
            example.org.\t240\tIN\tRRSIG\tNS\t15\t2\t240\t1732724662\t1732724662\t38874\texample.org.\tnhaHOrSvqfnXD9VIg1pIFhRmIdlSTxGAxEY/fWGZPJlA3iw7JGvLl0KpH5nSNPgMKArV6wqnF5sCpaZM3JFDAg==\n\
            example.org.\t240\tIN\tNSEC\t*.example.org.\tA\tNS\tSOA\tRRSIG\tNSEC\tDNSKEY\tZONEMD\n\
            example.org.\t240\tIN\tRRSIG\tNSEC\t15\t2\t240\t1732724662\t1732724662\t38874\texample.org.\tDacktsTAulRMlUAI+C557/PO/LczjKO42B0UahkTYKgb1OCM4vSfCRnBvzp5gGtb/92VvcdHbgExavZmvcvqAA==\n\
            example.org.\t240\tIN\tDNSKEY\t257\t3\t15\t6VdB0mk5qwjHWNC5TTOw1uHTzA0m3Xadg7aYVbcRn8Y= ;{id = 38873 (ksk), size = 256b}\n\
            example.org.\t240\tIN\tDNSKEY\t258\t3\t15\t6VdB0mk5qwjHWNC5TTOw1uHTzA0m3Xadg7aYVbcRn8Y= ;{id = 38874 (zsk), size = 256b}\n\
            example.org.\t240\tIN\tRRSIG\tDNSKEY\t15\t2\t240\t1732724662\t1732724662\t38873\texample.org.\tz8ecItPcgUElneJc/VBAmqxOUloYxC7ff5CwClZGH0/jnOrdC6P3GPRTeHVpBlUnpaMBHTWHdpn6RFXut4I7Ag==\n\
            example.org.\t240\tIN\tZONEMD\t1234567890\t1\t1\tD7309C80EA9F3EC0DF549E796E3E0DA0F99A6C3E36AAD7E039C3AC9E94834DD22D2CF73BB41C918914F315511C76A2A8\n\
            example.org.\t240\tIN\tRRSIG\tZONEMD\t15\t2\t240\t1732724662\t1732724662\t38874\texample.org.\tSjPvYWFvqwX26AxwDGs4YUq56/j9mTCG8zewWNmUv2yvqGL3m+eiGHbmB/GDRDDWEXqt0GGNPP644HaW9JEbAg==\n\
            *.example.org.\t240\tIN\tA\t1.2.3.4\n\
            *.example.org.\t240\tIN\tRRSIG\tA\t15\t2\t240\t1732724662\t1732724662\t38874\texample.org.\tr0y1xlc1QYWQKHLsK6UH5t7ByjcqkGNwOkHz5uJnREurhXqZJyv/ZA32ZsP9SQ+HOcWrSd+kiqCF9j7cNVAJDg==\n\
            *.example.org.\t240\tIN\tNSEC\tdeleg.example.org.\tA\tRRSIG\tNSEC\n\
            *.example.org.\t240\tIN\tRRSIG\tNSEC\t15\t2\t240\t1732724662\t1732724662\t38874\texample.org.\tzS2EXRkVem5j1YBXm0miaPZk3A57Qe6gtwo/vGLtbdTcGdQeDVFGtSSHM3fYj6DRkQmb7smREhNWK9VMtffVAQ==\n\
            deleg.example.org.\t240\tIN\tNS\texample.com.\n\
            deleg.example.org.\t240\tIN\tNSEC\texample.org.\tNS\tRRSIG\tNSEC\n\
            deleg.example.org.\t240\tIN\tRRSIG\tNSEC\t15\t3\t240\t1732724662\t1732724662\t38874\texample.org.\tQkbX4pnJpN07vHu7SudHKVAn//dOScDroe0dJGKWLm3qg5xDr4/c2dpvEuJ6Wpe8HRYvorDmSKSvxgVHX3T/Ag==\n\
            occluded.deleg.example.org.\t240\tIN\tA\t1.2.3.4\n"
            );
        assert_eq!(res.stderr, "");
    }
}
