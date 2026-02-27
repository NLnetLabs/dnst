use super::keyset::KeySetState;
use super::nsec3hash::Nsec3Hash;
use crate::env::{Env, Stream};
use crate::error::{Context, Error};
use crate::DISPLAY_KIND;
use bytes::{BufMut, Bytes, BytesMut};
use clap::builder::ValueParser;
use clap::Subcommand;
use core::clone::Clone;
use core::cmp::Ordering;
use core::fmt::Write;
use core::str::FromStr;
use domain::base::iana::nsec3::Nsec3HashAlgorithm;
use domain::base::iana::zonemd::{ZonemdAlgorithm, ZonemdScheme};
use domain::base::iana::Class;
use domain::base::name::FlattenInto;
use domain::base::zonefile_fmt::{self, Formatter, ZonefileFmt};
use domain::base::{
    CanonicalOrd, Name, NameBuilder, Record, RecordData, Rtype, Serial, ToName, Ttl,
};
use domain::crypto::sign::{KeyPair, SecretKeyBytes};
use domain::dep::octseq::OctetsFrom;
use domain::dnssec::common::{nsec3_hash, parse_from_bind};
use domain::dnssec::sign::denial::config::DenialConfig;
use domain::dnssec::sign::denial::nsec::{generate_nsecs, GenerateNsecConfig};
use domain::dnssec::sign::denial::nsec3::{
    generate_nsec3s, mk_hashed_nsec3_owner_name, GenerateNsec3Config, Nsec3ParamTtlMode,
};
use domain::dnssec::sign::error::SigningError;
use domain::dnssec::sign::keys::keyset::{KeyType, UnixTime};
use domain::dnssec::sign::keys::SigningKey;
use domain::dnssec::sign::records::{DefaultSorter, OwnerRrs, RecordsIter, Rrset, SortedRecords};
use domain::dnssec::sign::signatures::rrsigs::sign_rrset;
use domain::dnssec::sign::traits::{Signable, SignableZoneInPlace};
use domain::dnssec::sign::SigningConfig;
use domain::dnssec::validator::base::DnskeyExt;
use domain::rdata::dnssec::{RtypeBitmap, Timestamp};
use domain::rdata::nsec3::{Nsec3Salt, OwnerHash};
use domain::rdata::{Dnskey, Nsec, Nsec3, Nsec3param, Rrsig, Soa, ZoneRecordData, Zonemd};
use domain::utils::{base32, base64};
use domain::zonefile::inplace::{self, Entry};
use domain::zonetree::types::StoredRecordData;
use domain::zonetree::{StoredName, StoredRecord};
use jiff::tz::TimeZone;
use jiff::Timestamp as JiffTimestamp;
use jiff::Zoned;
use octseq::builder::with_infallible;
use rayon::slice::ParallelSliceMut;
use ring::digest;
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{self, Display};
use std::fs::{metadata, File};
use std::io::Write as IoWrite;
use std::io::{self, /*stdout,*/ BufWriter};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, UNIX_EPOCH};
use tokio::time::Duration;
use tracing::warn;
use url::Url;

//------------ Constants -----------------------------------------------------

const FOUR_WEEKS: u64 = 2419200;
const TWO_WEEKS: u64 = 1209600;
const FIFTEEN_MINUTES: u64 = 15 * 60;

//------------ Signer --------------------------------------------------------

#[derive(Clone, Debug, clap::Args)]
#[clap(
    after_help = "Keys must be specified by their base name (usually K<name>+<alg>+<id>), i.e. WITHOUT the .private or .key extension.
If the public part of the key is not present in the zone, the DNSKEY RR will be read from the file called <base name>.key.
A date can be a timestamp (seconds since the epoch), or of the form <YYYYMMdd[hhmmss]>
"
)]
pub struct Signer {
    /// Signer config
    #[arg(short = 'c')]
    signer_config: PathBuf,

    /// Subcommand
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Clone, Debug, Subcommand)]
enum Commands {
    Create {
        /// State file
        #[arg(short = 's')]
        signer_state: PathBuf,

        /// State file
        #[arg(short = 'k')]
        keyset_state: PathBuf,

        /// Unsigned zone file (input)
        #[arg(short = 'i')]
        zonefile_in: PathBuf,

        /// Signed zone file (output)
        #[arg(short = 'o')]
        zonefile_out: Option<PathBuf>,
    },
    Sign {
        /// Use layout in signed zone and print comments on DNSSEC records
        #[arg(long, action)]
        extra_comments: bool,

        /// Preceed the zone output by a list that contains the NSEC3 hashes
        /// of the original ownernames.
        #[arg(long, action)]
        preceed_zone_with_hash_list: bool,

        /// Order NSEC3 RRs by unhashed owner name.
        #[arg(long, action)]
        order_nsec3_rrs_by_unhashed_owner_name: bool,

        /// Order RRSIG RRs by the record type that they cover.
        #[arg(long, action, default_value_if("extra_comments", "true", Some("true")))]
        order_rrsigs_after_the_rtype_they_cover: bool,

        /// Output YYYYMMDDHHmmSS RRSIG timestamps instead of seconds since
        /// epoch.
        #[arg(long, action)]
        use_yyyymmddhhmmss_rrsig_format: bool,
    },
    Resign,
    Show,
    Cron,

    Set {
        #[command(subcommand)]
        subcommand: SetCommands,
    },
}

#[derive(Clone, Debug, Subcommand)]
enum SetCommands {
    /// Set the amount inception times of signatures are backdated.
    ///
    /// Note that positive values are subtracted from the current time.
    InceptionOffset {
        /// The offset.
        #[arg(value_parser = super::keyset::cmd::parse_duration)]
        duration: Duration,
    },
    /// Set how much time the expiration times of signatures are in the
    /// future.
    Lifetime {
        /// The lifetime.
        #[arg(value_parser = super::keyset::cmd::parse_duration)]
        duration: Duration,
    },
    /// Set how much time the signatures still have to be valid.
    ///
    /// New signatures will be generated before the time until the expiration
    /// time is less than that.
    RemainTime {
        /// The required remaining time.
        #[arg(value_parser = super::keyset::cmd::parse_duration)]
        duration: Duration,
    },
    UseNsec3 {
        #[arg(action = clap::ArgAction::Set)]
        boolean: bool,
    },
    Algorithm {
        #[arg(
	    value_parser = ValueParser::new(Nsec3Hash::parse_nsec3_alg),
	)]
        algorithm: Nsec3HashAlgorithm,
    },
    Iterations {
        iterations: u16,
    },
    Salt {
        salt: Nsec3Salt<Bytes>,
    },
    OptOut {
        #[arg(action = clap::ArgAction::Set)]
        boolean: bool,
    },
    ZoneMD {
        /// Add a ZONEMD resource record.
        ///
        /// <hash> currently supports "SHA384" (1) or "SHA512" (2).
        /// <scheme> currently only supports "SIMPLE" (1).
        ///
        /// Can occur more than once, but only one per unique scheme and hash
        /// tuple will be added.
        #[arg(
	    value_parser = Signer::parse_zonemd_set,
	)]
        // Clap doesn't support HashSet (without complex workarounds), therefore
        // the uniqueness of the tuples need to be checked at runtime.
        zonemd: HashSet<ZonemdTuple>,
    },
    SerialPolicy {
        serial_policy: SerialPolicy,
    },
    NotifyCommand {
        args: Vec<String>,
    },

    /// Set the fake time to use when signing and other time related
    /// operations.
    FakeTime {
        /// The time value as Unix seconds.
        #[arg(value_parser = super::keyset::cmd::parse_opt_unixtime)]
        opt_unixtime: super::keyset::cmd::OptUnixTime,
    },
}

#[derive(Default)]
struct SigningOptions {
    extra_comments: bool,
    preceed_zone_with_hash_list: bool,
    order_nsec3_rrs_by_unhashed_owner_name: bool,
    order_rrsigs_after_the_rtype_they_cover: bool,
    use_yyyymmddhhmmss_rrsig_format: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, clap::ValueEnum)]
enum SerialPolicy {
    /// Keep the original SOA serial from the unsigned zone file. Only
    /// resign when the zone changes. Should be used only for zones that
    /// get frequent updates.
    Keep,

    /// Keep incrementing the SOA serial but track the serial in the unsigned
    /// zone file.
    Increment,

    /// Use the current time in Unix seconds as the SOA serial. Increment
    /// in case the time is less than or equal to the last serial.
    UnixSeconds,

    /// Use the current date plus a two digit counter (YYYYMMDDxx) as the
    /// SOA serial. Increment the last serial if it is still the same day.
    Date,
}

impl Signer {
    fn parse_zonemd_set(arg: &str) -> Result<HashSet<ZonemdTuple>, Error> {
        let mut set = HashSet::new();
        if !arg.is_empty() {
            for a in arg.split(',') {
                let zonemd_tuple = Self::parse_zonemd_tuple(a)?;
                set.insert(zonemd_tuple);
            }
        }
        Ok(set)
    }

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

    fn file_modified(filename: impl AsRef<Path>) -> Result<UnixTime, Error> {
        let md = metadata(&filename).map_err(|e| {
            format!(
                "unable to get metadata for {}: {e}",
                filename.as_ref().display()
            )
        })?;
        let modified = md.modified().map_err(|e| {
            format!(
                "unable to get the modified time for {}: {e}",
                filename.as_ref().display()
            )
        })?;
        modified
            .try_into()
            .map_err(|e| format!("unable to convert from SystemTime: {e}").into())
    }

    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        // Post-process arguments.
        // TODO: Can Clap do this for us?

        if let Commands::Create {
            signer_state: signer_state_file,
            zonefile_in,
            zonefile_out,
            keyset_state,
        } = self.cmd
        {
            let zonefile_out = if let Some(zonefile_out) = zonefile_out {
                zonefile_out.clone()
            } else {
                let zonefile_out = format!("{}.signed", zonefile_in.display());
                PathBuf::from_str(&zonefile_out)
                    .map_err(|err| format!("Cannot write to {zonefile_out}: {err}"))?
            };
            const ONE_DAY: u64 = 86400;
            let sc = SignerConfig {
                signer_state: signer_state_file.clone(),
                zonefile_in,
                zonefile_out,
                keyset_state,
                inception_offset: Duration::from_secs(ONE_DAY),
                signature_lifetime: Duration::from_secs(FOUR_WEEKS),
                remain_time: Duration::from_secs(TWO_WEEKS),
                use_nsec3: false,
                algorithm: Nsec3HashAlgorithm::SHA1,
                iterations: 0,
                salt: Nsec3Salt::empty(),
                opt_out: false,
                zonemd: HashSet::new(),
                serial_policy: SerialPolicy::Keep,
                notify_command: Vec::new(),
                signature_refresh_interval: Duration::from_secs(FIFTEEN_MINUTES),
                key_roll_time: Duration::from_secs(ONE_DAY),
                faketime: None,
            };
            let json = serde_json::to_string_pretty(&sc).expect("should not fail");
            let mut file = File::create(&self.signer_config).map_err(|e| {
                format!(
                    "unable to create file {}: {e}",
                    self.signer_config.display()
                )
            })?;
            write!(file, "{json}").map_err(|e| {
                format!(
                    "unable to write to file {}: {e}",
                    self.signer_config.display()
                )
            })?;

            let signer_state = SignerState {
                config_modified: UNIX_EPOCH.try_into().expect("should not fail"),
                keyset_state_modified: UNIX_EPOCH.try_into().expect("should not fail"),
                zonefile_modified: UNIX_EPOCH.try_into().expect("should not fail"),
                minimum_expiration: UNIX_EPOCH.try_into().expect("should not fail"),
                previous_serial: None,
                apex_remove: HashSet::new(),
                apex_extra: vec![],
                key_tags: HashSet::new(),
                key_roll: None,
                last_signature_refresh: UNIX_EPOCH.try_into().expect("should not fail"),
            };
            let json = serde_json::to_string_pretty(&signer_state).expect("should not fail");
            let mut file = File::create(&signer_state_file).map_err(|e| {
                format!("unable to create file {}: {e}", signer_state_file.display())
            })?;
            write!(file, "{json}").map_err(|e| {
                format!(
                    "unable to write to file {}: {e}",
                    signer_state_file.display()
                )
            })?;

            return Ok(());
        }

        // Record the modified times of the files before reading them. This
        // avoids race conditions.
        let signer_config_modified = Self::file_modified(self.signer_config.clone())?;

        let file = File::open(&self.signer_config)
            .map_err(|e| format!("unable to open file {}: {e}", self.signer_config.display()))?;
        let sc: SignerConfig = serde_json::from_reader(file).map_err::<Error, _>(|e| {
            format!("error loading {:?}: {e}\n", self.signer_config).into()
        })?;

        let file = File::open(&sc.signer_state)
            .map_err(|e| format!("unable to open file {}: {e}", sc.signer_state.display()))?;
        let signer_state: SignerState = serde_json::from_reader(file).map_err::<Error, _>(|e| {
            format!("error loading {:?}: {e}\n", sc.signer_state).into()
        })?;

        let keyset_state_modified = Self::file_modified(sc.keyset_state.clone())?;
        let file = File::open(&sc.keyset_state)
            .map_err(|e| format!("unable to open file {}: {e}", sc.keyset_state.display()))?;
        let kss: KeySetState = serde_json::from_reader(file).map_err::<Error, _>(|e| {
            format!("error loading {:?}: {e}\n", sc.keyset_state).into()
        })?;

        let mut ws = WorkSpace {
            keyset_state: kss,
            keyset_state_modified,
            config: sc,
            config_changed: false,
            state: signer_state,
            state_changed: false,
        };

        let mut res = Ok(());

        match self.cmd {
            Commands::Create { .. } => unreachable!(),
            Commands::Sign {
                extra_comments,
                preceed_zone_with_hash_list,
                order_nsec3_rrs_by_unhashed_owner_name,
                order_rrsigs_after_the_rtype_they_cover,
                use_yyyymmddhhmmss_rrsig_format,
            } => {
                let options = SigningOptions {
                    extra_comments,
                    preceed_zone_with_hash_list,
                    order_nsec3_rrs_by_unhashed_owner_name,
                    order_rrsigs_after_the_rtype_they_cover,
                    use_yyyymmddhhmmss_rrsig_format,
                };

                // Copy modified times to the state file. Do we need to be clever
                // and avoid updating the state file if modified times do not
                // change?
                ws.state.config_modified = signer_config_modified;
                let zonefile_modified = Self::file_modified(ws.config.zonefile_in.clone())?;
                ws.state.zonefile_modified = zonefile_modified;
                ws.state_changed = true;
                res = self.sign_full(&mut ws, env, options)
            }
            Commands::Resign => ws.resign()?,
            Commands::Show => {
                todo!();
            }
            Commands::Cron => {
                ws.sign_incrementally(false)?;
            }
            Commands::Set { subcommand } => ws.set_command(subcommand, &env)?,
        }

        if ws.config_changed {
            let json = serde_json::to_string_pretty(&ws.config).expect("should not fail");
            let mut file = File::create(&self.signer_config)
                .map_err(|e| format!("unable to create {}: {e}", self.signer_config.display()))?;
            write!(file, "{json}")
                .map_err(|e| format!("unable to write to {}: {e}", self.signer_config.display()))?;
        }
        if ws.state_changed {
            let json = serde_json::to_string_pretty(&ws.state).expect("should not fail");
            let mut file = File::create(&ws.config.signer_state).map_err(|e| {
                format!("unable to create {}: {e}", ws.config.signer_state.display())
            })?;
            write!(file, "{json}").map_err(|e| {
                format!(
                    "unable to write to {}: {e}",
                    ws.config.signer_state.display()
                )
            })?;
        }
        res
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_full(
        &self,
        ws: &mut WorkSpace,
        env: impl Env,
        options: SigningOptions,
    ) -> Result<(), Error> {
        // Populate the signer state fields from keyset state.
        ws.handle_keyset_changed();

        // The entire zone is signed, clear key_roll.
        ws.state.key_roll = None;

        // Read the zone file.
        let origin = ws.keyset_state.keyset.name().to_bytes();
        let mut records = self.load_zone(&env.in_cwd(&ws.config.zonefile_in), origin.clone())?;

        for r in &ws.keyset_state.dnskey_rrset {
            let zonefile =
                domain::zonefile::inplace::Zonefile::from((r.to_string() + "\n").as_ref() as &str);
            for entry in zonefile {
                let entry = entry.map_err::<Error, _>(|e| format!("bad entry: {e}\n").into())?;

                // We only care about records in a zonefile
                let Entry::Record(record) = entry else {
                    continue;
                };

                let owner = record.owner().to_name::<Bytes>();
                let data = record.data().clone().try_flatten_into().unwrap();
                let r = Record::new(owner, record.class(), record.ttl(), data);

                records.insert(r).unwrap();
            }
        }
        for r in &ws.keyset_state.cds_rrset {
            let zonefile =
                domain::zonefile::inplace::Zonefile::from((r.to_string() + "\n").as_ref() as &str);
            for entry in zonefile {
                let entry = entry.map_err::<Error, _>(|e| format!("bad entry: {e}\n").into())?;

                // We only care about records in a zonefile
                let Entry::Record(record) = entry else {
                    continue;
                };

                let owner = record.owner().to_name::<Bytes>();
                let data = record.data().clone().try_flatten_into().unwrap();
                let r = Record::new(owner, record.class(), record.ttl(), data);

                records.insert(r).unwrap();
            }
        }

        let mut keys = Vec::new();
        for (k, v) in ws.keyset_state.keyset.keys() {
            let signer = match v.keytype() {
                KeyType::Ksk(_) => false,
                KeyType::Zsk(key_state) => key_state.signer(),
                KeyType::Csk(_, key_state) => key_state.signer(),
                KeyType::Include(_) => false,
            };

            if signer {
                let privref = v.privref().ok_or("missing private key")?;
                let priv_url = Url::parse(privref).expect("valid URL expected");
                let private_data = if priv_url.scheme() == "file" {
                    std::fs::read_to_string(priv_url.path()).map_err::<Error, _>(|e| {
                        format!("unable read from file {}: {e}", priv_url.path()).into()
                    })?
                } else {
                    panic!("unsupported URL scheme in {priv_url}");
                };
                let secret_key = SecretKeyBytes::parse_from_bind(&private_data)
                    .map_err::<Error, _>(|e| {
                        format!("unable to parse private key file {privref}: {e}").into()
                    })?;
                let pub_url = Url::parse(k).expect("valid URL expected");
                let public_data = if pub_url.scheme() == "file" {
                    std::fs::read_to_string(pub_url.path()).map_err::<Error, _>(|e| {
                        format!("unable read from file {}: {e}", pub_url.path()).into()
                    })?
                } else {
                    panic!("unsupported URL scheme in {pub_url}");
                };
                let public_key =
                    parse_from_bind::<Bytes>(&public_data).map_err::<Error, _>(|e| {
                        format!("unable to parse public key file {k}: {e}").into()
                    })?;

                let key_pair = KeyPair::from_bytes(&secret_key, public_key.data())
                    .map_err::<Error, _>(|e| {
                        format!("private key {privref} and public key {k} do not match: {e}").into()
                    })?;
                let signing_key = SigningKey::new(
                    public_key.owner().clone(),
                    public_key.data().flags(),
                    key_pair,
                );
                keys.push(signing_key);
            }
        }

        let signing_keys: Vec<_> = keys.iter().collect();
        let out_file = ws.config.zonefile_out.clone();

        let mut writer = if out_file.as_os_str() == "-" {
            FileOrStdout::Stdout(env.stdout())
        } else {
            let file = File::create(env.in_cwd(&out_file)).map_err(|e| {
                format!(
                    "unable to create file {}: {e}",
                    env.in_cwd(&out_file).display()
                )
            })?;
            let file = BufWriter::new(file);
            FileOrStdout::File(file)
        };

        // Make sure, zonemd arguments are unique
        let zonemd: HashSet<ZonemdTuple> = HashSet::from_iter(ws.config.zonemd.clone());

        // SAFETY: Already checked before this point.
        let zone_soa_rr = records.find_soa().expect("should exist");
        let new_soa = ws.update_soa_serial(zone_soa_rr.first())?;
        records.update_data(|rr| rr.rtype() == Rtype::SOA, new_soa.into_data());

        // Find the apex.
        let (apex, zone_class, ttl, soa_serial) = Self::find_apex(&records).unwrap();

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

        if ws.config.use_nsec3 && (options.extra_comments || options.preceed_zone_with_hash_list) {
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
                        if rrset.rtype() == Rtype::NS {
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
                    if ws.config.opt_out {
                        // Delegations are ignored for NSEC3. Ignore this
                        // entry but keep looking for other types at the
                        // same owner name.
                        prev_name = None;
                        continue;
                    }
                }

                let hashed_name = mk_hashed_nsec3_owner_name(
                    owner,
                    ws.config.algorithm,
                    ws.config.iterations,
                    &ws.config.salt,
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
                        ws.config.algorithm,
                        ws.config.iterations,
                        &ws.config.salt,
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

        let now = ws.faketime_or_now();
        let now_u32 = Into::<Duration>::into(now.clone()).as_secs() as u32;
        let inception = (now_u32 - ws.config.inception_offset.as_secs() as u32).into();
        let expiration = (now_u32 + ws.config.signature_lifetime.as_secs() as u32).into();

        // Set last_signature_refresh to the current time.
        ws.state.last_signature_refresh = now;

        let signing_config = if ws.config.use_nsec3 {
            let params = Nsec3param::new(
                ws.config.algorithm,
                0,
                ws.config.iterations,
                ws.config.salt.clone(),
            );
            let mut nsec3_config = GenerateNsec3Config::new(params);
            if ws.config.opt_out {
                nsec3_config = nsec3_config.with_opt_out();
            }
            SigningConfig::new(DenialConfig::Nsec3(nsec3_config), inception, expiration)
        } else {
            SigningConfig::new(
                DenialConfig::Nsec(GenerateNsecConfig::new()),
                inception,
                expiration,
            )
        };

        records
            .sign_zone(&apex, &signing_config, &signing_keys)
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

            Self::update_zonemd_rrsig(
                &apex,
                &mut records,
                &signing_keys,
                &zonemd_rrs,
                inception,
                expiration,
            )
            .map_err(|err| format!("ZONEMD re-signing error: {err}"))?;
        }

        let now_ts = Timestamp::now();
        // Note that truncating the u64 from as_secs() to u32 is fine because
        // Timestamp is designed for this situation.
        let expire_ts: Timestamp = (Duration::from_secs(now_ts.into_int() as u64)
            .saturating_add(ws.config.signature_lifetime)
            .as_secs() as u32)
            .into();
        let ts = records
            .iter()
            // Get RRSIG rdata. Also include whether the record is at the
            // apex or not.
            .filter_map(|r| {
                let at_apex = r.owner() == &origin;
                if let ZoneRecordData::Rrsig(rrsig) = r.data() {
                    Some((at_apex, rrsig))
                } else {
                    None
                }
            })
            // Ignore any RRSIGs that cover DNSKEY, CDS, or CDNSKEY at the apex.
            .filter(|(a, s)| {
                let rtype = s.type_covered();
                !a || (rtype != Rtype::DNSKEY && rtype != Rtype::CDS && rtype != Rtype::CDNSKEY)
            })
            // Extract the expiration date.
            .map(|(_, s)| s.expiration())
            // Timestamps are only partially ordered. Clamp to now and
            // now+signature_lifetime.
            .map(|t| {
                if t < now_ts {
                    now_ts
                } else if t > expire_ts {
                    expire_ts
                } else {
                    t
                }
            })
            // Assume PartialOrd is fine now.
            .min_by(|t1, t2| t1.partial_cmp(t2).expect("Should not fail"));
        let minimum_expiration = if let Some(ts) = ts {
            ts.into()
        } else {
            UnixTime::now() + ws.config.signature_lifetime
        };
        ws.state.minimum_expiration = minimum_expiration;

        // The signed RRs are in DNSSEC canonical order by owner name. For
        // compatibility with ldns-signzone, re-order them to be in canonical
        // order by unhashed owner name and so that hashed names come after
        // equivalent unhashed names.
        //
        // INCOMAPATIBILITY WARNING: Unlike ldns-signzone, we only apply this
        // ordering if `-b` is specified.
        let mut owner_rrs;
        let owner_rrs_iter: AnyOwnerRrsIter =
            if options.order_nsec3_rrs_by_unhashed_owner_name && nsec3_hashes.is_some() {
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
        if options.extra_comments {
            writer.write_fmt(format_args!(";; Zone: {}\n;\n", apex.fmt_with_dot()))?;
        }

        if options.preceed_zone_with_hash_list {
            if let Some(hashes) = &nsec3_hashes {
                let mut owner_sorted_hashes = hashes.iter().collect::<Vec<_>>();
                owner_sorted_hashes.par_sort_by(|(_, a), (_, b)| a.name().canonical_cmp(b.name()));
                for (hash, info) in owner_sorted_hashes {
                    writer.write_fmt(format_args!("; H({}) = {hash}\n", info.name()))?;
                }
            }
        }

        if let Some(record) = records.iter().find(|r| r.rtype() == Rtype::SOA) {
            self.writeln_rr(&mut writer, record, options.use_yyyymmddhhmmss_rrsig_format)?;
            if options.order_rrsigs_after_the_rtype_they_cover {
                for r in records.iter().filter(|r| {
                    if let ZoneRecordData::Rrsig(rrsig) = r.data() {
                        rrsig.type_covered() == Rtype::SOA
                    } else {
                        false
                    }
                }) {
                    self.writeln_rr(&mut writer, r, options.use_yyyymmddhhmmss_rrsig_format)?;
                }
                if options.extra_comments {
                    writer.write_str(";\n")?;
                }
            }
        }

        let nsec3_cs = Nsec3CommentState {
            hashes: nsec3_hashes.as_ref(),
            apex: &apex,
        };

        for owner_rrs in owner_rrs_iter {
            if options.extra_comments {
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
            if options.order_rrsigs_after_the_rtype_they_cover {
                for rrset in owner_rrs
                    .rrsets()
                    .filter(|rrset| !matches!(rrset.rtype(), Rtype::SOA | Rtype::RRSIG))
                {
                    for rr in rrset.iter() {
                        self.write_rr(&mut writer, rr, options.use_yyyymmddhhmmss_rrsig_format)?;
                        match rr.data() {
                            ZoneRecordData::Nsec3(nsec3) if options.extra_comments => {
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
                            self.writeln_rr(&mut writer, covering_rrsig_rr, options.use_yyyymmddhhmmss_rrsig_format)?;
                        }
                    }
                }
                if options.extra_comments {
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
                        self.write_rr(&mut writer, rr, options.use_yyyymmddhhmmss_rrsig_format)?;
                        writer.write_char('\n')?;
                    }
                }
            }
        }

        writer.flush().map_err(|e| format!("flush failed: {e}"))?;

        ws.run_notify_command()?;

        Ok(())
    }

    fn write_rr<W, N, O: AsRef<[u8]>>(
        &self,
        writer: &mut W,
        rr: &Record<N, ZoneRecordData<O, N>>,
        use_yyyymmddhhmmss_rrsig_format: bool,
    ) -> std::fmt::Result
    where
        N: ToName,
        W: Write,
        ZoneRecordData<O, N>: ZonefileFmt,
    {
        if use_yyyymmddhhmmss_rrsig_format {
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
        use_yyyymmddhhmmss_rrsig_format: bool,
    ) -> std::fmt::Result
    where
        N: ToName,
        W: Write,
        ZoneRecordData<O, N>: ZonefileFmt,
    {
        self.write_rr(writer, rr, use_yyyymmddhhmmss_rrsig_format)?;
        writer.write_char('\n')
    }

    fn load_zone(
        &self,
        zonefile_path: &Path,
        origin: Name<Bytes>,
    ) -> Result<SortedRecords<StoredName, StoredRecordData, MultiThreadedSorter>, Error> {
        // Don't use Zonefile::load() as it knows nothing about the size of
        // the original file so uses default allocation which allocates more
        // bytes than are needed. Instead control the allocation size based on
        // our knowledge of the file size.
        let mut zone_file = File::open(zonefile_path)
            .map_err(|e| format!("open failed: {e}").into())
            .context(&format!(
                "loading zone file from path '{}'",
                zonefile_path.display(),
            ))?;
        let zone_file_len = zone_file
            .metadata()
            .map_err(|e| {
                format!(
                    "unable to get metadata from {}: {e}",
                    zonefile_path.display()
                )
            })?
            .len();
        let mut buf = inplace::Zonefile::with_capacity(zone_file_len as usize).writer();
        std::io::copy(&mut zone_file, &mut buf)
            .map_err(|e| format!("copy to {} failed: {e}", zonefile_path.display()))?;
        let mut reader = buf.into_inner();

        reader.set_origin(origin.clone());

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

    fn write_extreme_iterations_warning(env: &impl Env) {
        Self::write_iterations_warning(
            env,
            "NSEC3 iterations larger than 500 may cause validating resolvers to return SERVFAIL!",
        );
    }

    fn write_non_zero_iterations_warning(env: &impl Env) {
        Self::write_iterations_warning(env, "NSEC3 iterations larger than 0 increases performance cost while providing only moderate protection!");
    }

    fn write_iterations_warning(env: &impl Env, text: &str) {
        warn!("{text}");
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
            let zonemd_rrset = Rrset::new_from_owned(zonemd_rrs)
                .expect("zonemd_rrs is not empty so new should not fail");
            let mut new_rrsig_recs = zonemd_rrset.sign(apex, keys, inception, expiration)?;
            records.update_data(|rr| {
                matches!(rr.data(), ZoneRecordData::Rrsig(rrsig) if rr.owner() == apex && rrsig.type_covered() == Rtype::ZONEMD)
            }, new_rrsig_recs.pop().unwrap().into_data().into());
        }

        Ok(())
    }
}

struct WorkSpace {
    keyset_state: KeySetState,
    keyset_state_modified: UnixTime,
    config: SignerConfig,
    config_changed: bool,
    state: SignerState,
    state_changed: bool,
}

impl WorkSpace {
    fn set_command(&mut self, cmd: SetCommands, env: &impl Env) -> Result<(), Error> {
        match cmd {
            SetCommands::InceptionOffset { duration } => {
                self.config.inception_offset = duration;
            }
            SetCommands::Lifetime { duration } => {
                self.config.signature_lifetime = duration;
            }
            SetCommands::RemainTime { duration } => {
                self.config.remain_time = duration;
            }
            SetCommands::UseNsec3 { boolean } => {
                self.config.use_nsec3 = boolean;
            }
            SetCommands::Algorithm { algorithm } => {
                self.config.algorithm = algorithm;
            }
            SetCommands::Iterations { iterations } => {
                self.config.iterations = iterations;
                match self.config.iterations {
                    500.. => Signer::write_extreme_iterations_warning(&env),
                    1.. => Signer::write_non_zero_iterations_warning(&env),
                    _ => { /* Good, nothing to warn about */ }
                }
            }
            SetCommands::Salt { salt } => {
                self.config.salt = salt;
            }
            SetCommands::OptOut { boolean } => {
                self.config.opt_out = boolean;
            }
            SetCommands::ZoneMD { zonemd } => {
                self.config.zonemd = zonemd;
            }
            SetCommands::SerialPolicy { serial_policy } => {
                self.config.serial_policy = serial_policy;
            }
            SetCommands::NotifyCommand { args } => {
                self.config.notify_command = args;
            }
            SetCommands::FakeTime { opt_unixtime } => self.config.faketime = opt_unixtime,
        }
        self.config_changed = true;
        Ok(())
    }

    fn sign_incrementally(&mut self, load_unsigned: bool) -> Result<(), Error> {
        // Check what work needs to be done. If the keyset state
        // changed then check if the APEX records change or if a
        // CSK or ZSK roll require resigning the zone.
        // If enough time has passed since the last time
        // signatures have been updated, then update signatures
        // and during a key roll, sign with the new key(s).
        // Ignore signer configuration changes, they will get picked up when
        // signatures need to be updated.
        // Resign using the unsigned zonefile when load_unsigned is true.

        let apex_changed = self.handle_keyset_changed();

        let mut refresh_signatures = false;
        let now = self.faketime_or_now();
        if now > self.state.last_signature_refresh.clone() + self.config.signature_refresh_interval
        {
            println!(
                "refresh signatures: {} > {} + {:?}",
                now, self.state.last_signature_refresh, self.config.signature_refresh_interval
            );
            refresh_signatures = true;
        }

        if !load_unsigned && !apex_changed && !refresh_signatures {
            // Nothing to do.
            return Ok(());
        }

        let mut iss = IncrementalSigningState::new(self)?;

        let start = Instant::now();
        load_signed_zone(&mut iss, &self.config.zonefile_out).unwrap();
        println!("loading signed zone took {:?}", start.elapsed());

        self.handle_nsec_nsec3(&mut iss)?;

        if load_unsigned {
            let start = Instant::now();
            load_unsigned_zone(&mut iss, &self.config.zonefile_in).unwrap();
            println!("loading new unsigned zone took {:?}", start.elapsed());
        } else {
            // Re-use the signed data.
            load_signed_only(&mut iss);
        }

        let start = Instant::now();
        self.load_apex_records(&mut iss)?;

        initial_diffs(&mut iss)?;

        if self.config.use_nsec3 {
            incremental_nsec3(&mut iss)?;
        } else {
            incremental_nsec(&mut iss)?;
        }

        self.new_nsec_nsec3_sigs(&mut iss)?;

        if !self.config.zonemd.is_empty() {
            let start = Instant::now();
            self.add_zonemd(&mut iss)?;
            println!("ZONEMD took {:?}", start.elapsed());
        }

        if refresh_signatures {
            self.refresh_some_signatures(&mut iss)?;
            if self.state.key_roll.is_some() {
                self.key_roll_signatures(&mut iss)?;
            }
        }
        println!("incremental signing took {:?}", start.elapsed());

        self.incremental_write_output(&iss)?;

        self.run_notify_command()?;

        Ok(())
    }

    fn refresh_some_signatures(&mut self, iss: &mut IncrementalSigningState) -> Result<(), Error> {
        let effective_lifetime = self.config.signature_lifetime - self.config.remain_time;
        let now = self.faketime_or_now();
        let now_system_time = UNIX_EPOCH + Duration::from(now.clone());
        let min_expire = now_system_time + self.config.remain_time;
        let mut since_last_time: Duration = if now >= self.state.last_signature_refresh {
            <UnixTime as Into<Duration>>::into(now.clone())
                - <UnixTime as Into<Duration>>::into(self.state.last_signature_refresh.clone())
        } else {
            Duration::ZERO
        };

        // Limit to effective_lifetime in case of weird values.
        if since_last_time > effective_lifetime {
            since_last_time = effective_lifetime;
        }

        let total_signatures = iss.rrsigs.len();

        let to_sign = since_last_time.as_secs_f64() * (total_signatures as f64)
            / effective_lifetime.as_secs_f64();
        let to_sign = to_sign.ceil() as usize;

        // Collect expiration times, owner names, and types to figure out what
        // to sign.
        let mut expire_sigs = vec![];
        for ((owner, rtype), r) in &iss.rrsigs {
            let min_expiration = r
                .iter()
                .map(|r| {
                    let ZoneRecordData::Rrsig(rrsig) = r.data() else {
                        panic!("Rrsig expected");
                    };
                    rrsig.expiration().to_system_time(now_system_time)
                })
                .min()
                .expect("minimum should exist");
            let v = (min_expiration, owner, rtype);
            expire_sigs.push(v);
        }

        expire_sigs.sort();

        let mut new_sigs = vec![];
        for (i, (expire, owner, rtype)) in expire_sigs.iter().enumerate() {
            if *expire > min_expire && i >= to_sign {
                break;
            }

            let key = ((*owner).clone(), **rtype);
            if **rtype == Rtype::NSEC {
                let record = iss.nsecs.get(&key.0).expect("NSEC record should exist");
                let records = [record.clone()];
                sign_records(
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            } else if **rtype == Rtype::NSEC3 {
                let record = iss.nsec3s.get(&key.0).expect("NSEC3 record should exist");
                let records = [record.clone()];
                sign_records(
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            } else {
                let records = iss.new_data.get(&key).expect("records should exist");
                sign_records(
                    records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            };
        }

        for (sigs, rtype) in new_sigs {
            let key = (sigs[0].owner().clone(), rtype);
            iss.rrsigs.insert(key, sigs);
        }

        if to_sign != 0 {
            // Only update last_signature_refresh when enough time has passed
            // that at least one record got signed.
            self.state.last_signature_refresh = now;
            self.state_changed = true;
        }
        Ok(())
    }

    fn key_roll_signatures(&mut self, iss: &mut IncrementalSigningState) -> Result<(), Error> {
        let key_roll_time = self.config.key_roll_time;
        let key_roll_start = self.state.key_roll.as_ref().expect("should be there");

        let now = self.faketime_or_now();

        let since_start: Duration = <UnixTime as Into<Duration>>::into(now.clone())
            - <UnixTime as Into<Duration>>::into(key_roll_start.clone());

        if since_start > key_roll_time {
            // Full roll. Make sure all signatures are made using the new keys.
            // Clear key_roll when we are done.

            let mut new_sigs = vec![];
            for ((owner, rtype), r) in &iss.rrsigs {
                let key_tags: HashSet<u16> = r
                    .iter()
                    .map(|r| {
                        let ZoneRecordData::Rrsig(rrsig) = r.data() else {
                            panic!("Rrsig expected");
                        };
                        rrsig.key_tag()
                    })
                    .collect();
                if key_tags == self.state.key_tags {
                    // Nothing to do.
                    continue;
                }

                let key = ((*owner).clone(), *rtype);
                if *rtype == Rtype::NSEC3 {
                    let record = iss.nsec3s.get(&key.0).expect("NSEC3 record should exist");
                    let records = [record.clone()];
                    sign_records(
                        &records,
                        &iss.keys,
                        iss.inception,
                        iss.expiration,
                        &mut new_sigs,
                    )?;
                } else {
                    let records = iss.new_data.get(&key).expect("records should exist");
                    sign_records(
                        records,
                        &iss.keys,
                        iss.inception,
                        iss.expiration,
                        &mut new_sigs,
                    )?;
                };
            }

            for (sigs, rtype) in new_sigs {
                let key = (sigs[0].owner().clone(), rtype);
                iss.rrsigs.insert(key, sigs);
            }
            self.state.key_roll = None;
            self.state_changed = true;
            return Ok(());
        }

        let total_signatures = iss.rrsigs.len();

        let to_sign =
            since_start.as_secs_f64() * (total_signatures as f64) / key_roll_time.as_secs_f64();
        let to_sign = to_sign.ceil() as usize;

        // owner names, types, and key tags to figure out what to sign.
        let mut sigs_key_tags = vec![];
        for ((owner, rtype), r) in &iss.rrsigs {
            let key_tags: Vec<u16> = r
                .iter()
                .map(|r| {
                    let ZoneRecordData::Rrsig(rrsig) = r.data() else {
                        panic!("Rrsig expected");
                    };
                    rrsig.key_tag()
                })
                .collect();
            let v = (owner, rtype, key_tags);
            sigs_key_tags.push(v);
        }

        sigs_key_tags.sort();

        let mut new_sigs = vec![];
        for (i, (owner, rtype, key_tags)) in sigs_key_tags.iter().enumerate() {
            if i >= to_sign {
                break;
            }

            if HashSet::<u16>::from_iter(key_tags.iter().copied()) == self.state.key_tags {
                // Nothing to do.
                continue;
            }

            let key = ((*owner).clone(), **rtype);
            if **rtype == Rtype::NSEC3 {
                let record = iss.nsec3s.get(&key.0).expect("NSEC3 record should exist");
                let records = [record.clone()];
                sign_records(
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            } else {
                let records = iss.new_data.get(&key).expect("records should exist");
                sign_records(
                    records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            };
        }

        for (sigs, rtype) in new_sigs {
            let key = (sigs[0].owner().clone(), rtype);
            iss.rrsigs.insert(key, sigs);
        }
        Ok(())
    }

    fn handle_keyset_changed(&mut self) -> bool {
        if self.keyset_state_modified == self.state.keyset_state_modified {
            // Nothing changed.
            return false;
        }
        self.state.keyset_state_modified = self.keyset_state_modified.clone();
        self.state_changed = true;

        let mut apex_changed = false;

        // Check the APEX RRtypes that need to be removed. We
        // should get that from keyset, but currently we don't.
        // Just have a fixed list.
        let apex_remove: HashSet<Rtype> = [Rtype::DNSKEY, Rtype::CDS, Rtype::CDNSKEY].into();

        if apex_remove != self.state.apex_remove {
            println!(
                "APEX remove RRtypes changed: from {:?} to {apex_remove:?}",
                self.state.apex_remove
            );
            apex_changed = true;
            self.state.apex_remove = apex_remove;
        }

        // Check records that need to be added to the APEX.
        let mut apex_extra = vec![];
        apex_extra.extend_from_slice(&self.keyset_state.dnskey_rrset);
        apex_extra.extend_from_slice(&self.keyset_state.cds_rrset);
        apex_extra.sort();

        if apex_extra != self.state.apex_extra {
            println!(
                "APEX types changed: from {:?} to {apex_extra:?}",
                self.state.apex_extra
            );
            apex_changed = true;
            self.state.apex_extra = apex_extra;
        }

        // Check if a ZSK/CSK roll has started.
        let mut key_tags = HashSet::new();
        for v in self.keyset_state.keyset.keys().values() {
            let signer = match v.keytype() {
                KeyType::Ksk(_) => false,
                KeyType::Zsk(key_state) => key_state.signer(),
                KeyType::Csk(_, key_state) => key_state.signer(),
                KeyType::Include(_) => false,
            };

            if !signer {
                continue;
            }

            key_tags.insert(v.key_tag());
        }

        if key_tags != self.state.key_tags {
            println!(
                "key tags changed: from {:?} to {key_tags:?}",
                self.state.key_tags
            );
            self.state.key_roll = Some(self.faketime_or_now());
            self.state.key_tags = key_tags;
        }
        apex_changed
    }

    fn resign(&mut self) -> Result<(), Error> {
        self.sign_incrementally(true)
    }

    fn faketime_or_now(&self) -> UnixTime {
        self.config.faketime.clone().unwrap_or(UnixTime::now())
    }

    fn handle_nsec_nsec3(&self, iss: &mut IncrementalSigningState) -> Result<(), Error> {
        // Note that we could try to regenerate the NSEC(3). Assume that
        // switching between NSEC, NSEC3, and NSEC3 opt-out (or other NSEC3
        // parameter changes) is rare enough that we can just resign the full
        // zone.
        let key = (iss.origin.clone(), Rtype::NSEC3PARAM);
        let opt_nsec3param = iss.old_data.get(&key);
        if let Some(nsec3param_records) = opt_nsec3param {
            // Zone was signed with NSEC3.
            if !self.config.use_nsec3 {
                // Zone is signed with NSEC3 but we want NSEC.
                let start = Instant::now();
                remove_nsec_nsec3(iss);
                new_nsec_chain(iss)?;
                println!("replacing NSEC3 with NSEC took {:?}", start.elapsed());
                return Ok(());
            }
            let ZoneRecordData::Nsec3param(nsec3param) = nsec3param_records[0].data() else {
                panic!("ZoneRecordData::Nsec3param expected");
            };
            if *nsec3param != iss.nsec3param {
                // Parameters changed, resign.
                let start = Instant::now();
                remove_nsec_nsec3(iss);
                new_nsec3_chain(iss)?;
                println!("updating NSEC3 parameters took {:?}", start.elapsed());
                return Ok(());
            }

            // Nothing has changed. Insert the old NSEC3PARAM records in the
            // new zone data.
            iss.new_data.insert(key, nsec3param_records.to_vec());
        } else {
            // Zone was signed with NSEC, check if that is also the target.
            if self.config.use_nsec3 {
                // Resign the full zone with NSEC3.
                let start = Instant::now();
                remove_nsec_nsec3(iss);
                new_nsec3_chain(iss)?;
                println!("replacing NSEC with NSEC3 took {:?}", start.elapsed());
                return Ok(());
            }
            // Stay with NSEC.
        }
        Ok(())
    }

    fn new_nsec_nsec3_sigs(&self, iss: &mut IncrementalSigningState) -> Result<(), Error> {
        let mut new_sigs = vec![];
        if self.config.use_nsec3 {
            for m in &iss.modified_nsecs {
                let Some(nsec3) = iss.nsec3s.get(m) else {
                    panic!("NSEC3 for {m} should exist");
                };

                let nsec3 = nsec3.clone();
                sign_records(
                    &[nsec3],
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            }
        } else {
            for m in &iss.modified_nsecs {
                let Some(nsec) = iss.nsecs.get(m) else {
                    panic!("NSEC for {m} should exist");
                };

                let nsec = nsec.clone();
                sign_records(
                    &[nsec],
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            }
        }
        for (sig, rtype) in new_sigs {
            let key = (sig[0].owner().clone(), rtype);
            iss.rrsigs.insert(key, sig);
        }
        Ok(())
    }

    fn incremental_write_output(&self, iss: &IncrementalSigningState) -> Result<(), Error> {
        let start = Instant::now();
        let mut writer = {
            let filename = &self.config.zonefile_out;
            let file = File::create(filename)
                .map_err(|e| format!("unable to create file {}: {e}", filename.display()))?;
            BufWriter::new(file)
            // FileOrStdout::File(file)
        };

        for data in iss.new_data.values() {
            for rr in data {
                writer
                    .write_fmt(format_args!("{}\n", rr.display_zonefile(DISPLAY_KIND)))
                    .map_err(|e| format!("unable write signed zone: {e}"))?;
            }
        }
        for rr in iss.nsecs.values() {
            writer
                .write_fmt(format_args!("{}\n", rr.display_zonefile(DISPLAY_KIND)))
                .map_err(|e| format!("unable write signed zone: {e}"))?;
        }
        for rr in iss.nsec3s.values() {
            writer
                .write_fmt(format_args!("{}\n", rr.display_zonefile(DISPLAY_KIND)))
                .map_err(|e| format!("unable write signed zone: {e}"))?;
        }
        for data in iss.rrsigs.values() {
            for rr in data {
                let ZoneRecordData::Rrsig(rrsig) = rr.data() else {
                    panic!("RRSIG expected");
                };
                let rr = Record::new(rr.owner(), rr.class(), rr.ttl(), YyyyMmDdHhMMSsRrsig(rrsig));
                writer
                    .write_fmt(format_args!("{}\n", rr.display_zonefile(DISPLAY_KIND)))
                    .map_err(|e| format!("unable write signed zone: {e}"))?;
            }
        }
        println!("writing output took {:?}", start.elapsed());
        Ok(())
    }

    fn load_apex_records(&mut self, iss: &mut IncrementalSigningState) -> Result<(), Error> {
        // Assume that the APEX records have been copied from KeySetState to
        // SignerState. Now update the APEX in new_data.

        // Delete all types in apex_remove.
        for t in &self.state.apex_remove {
            let key = (iss.origin.clone(), *t);
            iss.new_data.remove(&key);
            iss.rrsigs.remove(&key);
        }

        for r in &self.state.apex_extra {
            let zonefile =
                domain::zonefile::inplace::Zonefile::from((r.to_string() + "\n").as_ref() as &str);
            for entry in zonefile {
                let entry = entry.map_err::<Error, _>(|e| format!("bad entry: {e}\n").into())?;

                // We only care about records in a zonefile
                let Entry::Record(record) = entry else {
                    continue;
                };

                let owner = record.owner().to_name::<Bytes>();
                let data = record.data().clone().try_flatten_into().unwrap();
                let r = Record::new(owner.clone(), record.class(), record.ttl(), data);

                if r.rtype() == Rtype::RRSIG {
                    let ZoneRecordData::Rrsig(rrsig) = r.data() else {
                        panic!("RRSIG expected");
                    };
                    let key = (owner, rrsig.type_covered());
                    let mut records = vec![r];
                    if let Some(v) = iss.rrsigs.get_mut(&key) {
                        v.append(&mut records);
                    } else {
                        iss.rrsigs.insert(key, records);
                    }
                } else {
                    let key = (owner, r.rtype());
                    let mut records = vec![r];
                    if let Some(v) = iss.new_data.get_mut(&key) {
                        v.append(&mut records);
                    } else {
                        iss.new_data.insert(key, records);
                    }
                }
            }
        }

        if !self.config.zonemd.is_empty() {
            let zonemd = Zonemd::new(
                0.into(),
                ZonemdScheme::SIMPLE,
                ZonemdAlgorithm::SHA384,
                Bytes::new(),
            );
            let record = Record::new(
                iss.origin.clone(),
                Class::IN,
                Ttl::ZERO,
                ZoneRecordData::Zonemd(zonemd),
            );
            let records = vec![record];
            let key = (iss.origin.clone(), Rtype::ZONEMD);
            iss.new_data.insert(key, records);
        }

        // Update the SOA serial.
        let key = (iss.origin.clone(), Rtype::SOA);
        let zone_soa_rr = &iss.new_data.get(&key).expect("SOA should exist")[0];
        let new_soa = self.update_soa_serial(zone_soa_rr)?;
        let new_rrset = vec![new_soa];
        iss.new_data.insert(key, new_rrset);

        Ok(())
    }

    fn add_zonemd(&self, iss: &mut IncrementalSigningState) -> Result<(), Error> {
        // Get the SOA record. We need that for the Serial and for the
        // TTL.
        let key = (iss.origin.clone(), Rtype::SOA);
        let soa_records = iss
            .new_data
            .get(&key)
            .expect("SOA record should be present");
        let ZoneRecordData::Soa(soa) = soa_records[0].data() else {
            panic!("SOA record expected");
        };

        let start = Instant::now();

        // Create a Vec with all records to be able to sort them in canonical
        // order. Ignore ZONEMD and RRSIGs of ZONEMD records.
        let mut all = vec![];

        let mut data: Vec<_> = iss
            .new_data
            .iter()
            .filter_map(|((o, t), r)| {
                if *o != iss.origin || *t != Rtype::ZONEMD {
                    Some(r)
                } else {
                    None
                }
            })
            .flatten()
            .collect();
        all.append(&mut data);

        let mut data: Vec<_> = iss.nsecs.values().collect();
        all.append(&mut data);

        let mut data: Vec<_> = iss.nsec3s.values().collect();
        all.append(&mut data);

        let mut data: Vec<_> = iss
            .rrsigs
            .iter()
            .filter_map(|((o, t), r)| {
                if *o != iss.origin || *t != Rtype::ZONEMD {
                    Some(r)
                } else {
                    None
                }
            })
            .flatten()
            .collect();
        all.append(&mut data);

        //all.sort_by(|e1, e2| CanonicalOrd::canonical_cmp(*e1, *e2));
        all.par_sort_by(|e1, e2| CanonicalOrd::canonical_cmp(*e1, *e2));

        println!("ZONEMD prepare and sort took {:?}", start.elapsed());

        let start = Instant::now();

        let mut zonemd_records = vec![];
        for z in &self.config.zonemd {
            if z.0 != ZonemdScheme::SIMPLE {
                return Err("unsupported zonemd scheme (only SIMPLE is supported)".into());
            }
            let mut buf: Vec<u8> = Vec::new();
            let mut ctx = match z.1 {
                ZonemdAlgorithm::SHA384 => digest::Context::new(&digest::SHA384),
                ZonemdAlgorithm::SHA512 => digest::Context::new(&digest::SHA512),
                _ => unreachable!(),
            };
            for r in &all {
                buf.clear();
                with_infallible(|| r.compose_canonical(&mut buf));
                ctx.update(&buf);
            }
            let digest = ctx.finish();
            let zonemd = Zonemd::new(
                soa.serial(),
                z.0,
                z.1,
                Bytes::copy_from_slice(digest.as_ref()),
            );
            let record = Record::new(
                iss.origin.clone(),
                soa_records[0].class(),
                soa_records[0].ttl(),
                ZoneRecordData::Zonemd(zonemd),
            );
            zonemd_records.push(record);
        }

        println!("ZONEMD hash took {:?}", start.elapsed());

        let key = (iss.origin.clone(), Rtype::ZONEMD);
        let mut new_sigs = vec![];
        sign_records(
            &zonemd_records,
            &iss.keys,
            iss.inception,
            iss.expiration,
            &mut new_sigs,
        )?;
        iss.new_data.insert(key.clone(), zonemd_records);
        iss.rrsigs.insert(key, new_sigs[0].0.clone());
        Ok(())
    }

    fn update_soa_serial(&mut self, old_soa: &Zrd) -> Result<Zrd, Error> {
        // Implement SOA serial policies. There are four policies:
        // 1) Keep. Copy the serial from the unsigned zone. Refuse to sign
        //    if the serial did not change.
        // 2) Increment. Copy the serial from the unsigned zone but increment
        //    the serial if the zone needs to be signed an the serial in
        //    the unsigned zone did not change.
        // 3) Unix timestamp. The current time in Unix seconds. Increment if
        //    that does not result in a higher serial.
        // 4) Broken down time (YYYYMMDDnn). The current day plus a serial
        //    number. Implies increment to generate different serial numbers
        //    over a day.

        let ZoneRecordData::Soa(zone_soa) = old_soa.data() else {
            unreachable!();
        };

        // Assume that we will change the state.
        self.state_changed = true;

        match self.config.serial_policy {
            SerialPolicy::Keep => {
                if let Some(previous_serial) = self.state.previous_serial {
                    if zone_soa.serial() <= previous_serial {
                        return Err(
                            "Serial policy is Keep but upstream serial did not increase".into()
                        );
                    }
                }

                self.state.previous_serial = Some(zone_soa.serial());
                Ok(old_soa.clone())
            }
            SerialPolicy::Increment => {
                let mut serial = zone_soa.serial();
                if let Some(previous_serial) = self.state.previous_serial {
                    if serial <= previous_serial {
                        serial = previous_serial.add(1);
                        self.state.previous_serial = Some(serial);

                        let new_soa = ZoneRecordData::Soa(Soa::new(
                            zone_soa.mname().clone(),
                            zone_soa.rname().clone(),
                            serial,
                            zone_soa.refresh(),
                            zone_soa.retry(),
                            zone_soa.expire(),
                            zone_soa.minimum(),
                        ));
                        let record = Record::new(
                            old_soa.owner().clone(),
                            old_soa.class(),
                            old_soa.ttl(),
                            new_soa,
                        );

                        return Ok(record);
                    }
                }

                self.state.previous_serial = Some(serial);
                Ok(old_soa.clone())
            }
            SerialPolicy::UnixSeconds => {
                let mut serial = Serial::now();
                if let Some(previous_serial) = self.state.previous_serial {
                    if serial <= previous_serial {
                        serial = previous_serial.add(1);
                    }
                }

                self.state.previous_serial = Some(serial);

                let new_soa = ZoneRecordData::Soa(Soa::new(
                    zone_soa.mname().clone(),
                    zone_soa.rname().clone(),
                    serial,
                    zone_soa.refresh(),
                    zone_soa.retry(),
                    zone_soa.expire(),
                    zone_soa.minimum(),
                ));

                let record = Record::new(
                    old_soa.owner().clone(),
                    old_soa.class(),
                    old_soa.ttl(),
                    new_soa,
                );

                Ok(record)
            }
            SerialPolicy::Date => {
                let ts = JiffTimestamp::now();
                let zone = Zoned::new(ts, TimeZone::UTC);
                let serial = ((zone.year() as u32 * 100 + zone.month() as u32) * 100
                    + zone.day() as u32)
                    * 100;
                let mut serial: Serial = serial.into();

                if let Some(previous_serial) = self.state.previous_serial {
                    if serial <= previous_serial {
                        serial = previous_serial.add(1);
                    }
                }

                self.state.previous_serial = Some(serial);

                let new_soa = ZoneRecordData::Soa(Soa::new(
                    zone_soa.mname().clone(),
                    zone_soa.rname().clone(),
                    serial,
                    zone_soa.refresh(),
                    zone_soa.retry(),
                    zone_soa.expire(),
                    zone_soa.minimum(),
                ));

                let record = Record::new(
                    old_soa.owner().clone(),
                    old_soa.class(),
                    old_soa.ttl(),
                    new_soa,
                );

                Ok(record)
            }
        }
    }

    fn run_notify_command(&self) -> Result<(), Error> {
        if self.config.notify_command.is_empty() {
            return Ok(()); // Nothing to do.
        }

        let output = Command::new(&self.config.notify_command[0])
            .args(&self.config.notify_command[1..])
            .output()
            .map_err(|e| {
                format!(
                    "unable to create new Command for {}: {e}",
                    self.config.notify_command[0]
                )
            })?;
        if !output.status.success() {
            println!("notify command failed with: {}", output.status);
            io::stdout()
                .write_all(&output.stdout)
                .map_err(|e| format!("unable to write to stdout: {e}"))?;
            io::stderr()
                .write_all(&output.stderr)
                .map_err(|e| format!("unable to write to stderr: {e}"))?;
        }
        Ok(())
    }
}

fn remove_nsec_nsec3(iss: &mut IncrementalSigningState) {
    for k in iss.nsecs.keys() {
        let key = (k.clone(), Rtype::NSEC);
        iss.rrsigs.remove(&key);
    }
    iss.nsecs = BTreeMap::new();

    for k in iss.nsec3s.keys() {
        let key = (k.clone(), Rtype::NSEC3);
        iss.rrsigs.remove(&key);
    }
    iss.nsec3s = BTreeMap::new();
}

fn new_nsec_chain(iss: &mut IncrementalSigningState) -> Result<(), Error> {
    let records = get_unsigned_sorted(iss);
    let records_iter = RecordsIter::new_from_refs(&records);
    let config = GenerateNsecConfig::new();
    let nsec_records = generate_nsecs(&iss.origin, records_iter, &config)
        .map_err(|e| format!("generate_nsec3s failed: {e}"))?;

    // Collect signatures here.
    let mut new_sigs = vec![];

    for r in nsec_records {
        let record = Record::new(
            r.owner().clone(),
            r.class(),
            r.ttl(),
            ZoneRecordData::Nsec(r.data().clone()),
        );
        iss.nsecs.insert(record.owner().clone(), record.clone());
        sign_records(
            &[record],
            &iss.keys,
            iss.inception,
            iss.expiration,
            &mut new_sigs,
        )?;
    }
    for (sig, rtype) in new_sigs {
        let key = (sig[0].owner().clone(), rtype);
        iss.rrsigs.insert(key, sig);
    }
    Ok(())
}

fn new_nsec3_chain(iss: &mut IncrementalSigningState) -> Result<(), Error> {
    let records = get_unsigned_sorted(iss);
    let records_iter = RecordsIter::new_from_refs(&records);
    let config = GenerateNsec3Config::<_, DefaultSorter>::new(iss.nsec3param.clone())
        .with_ttl_mode(Nsec3ParamTtlMode::SoaMinimum);
    let nsec3_records = generate_nsec3s(&iss.origin, records_iter, &config)
        .map_err(|e| format!("generate_nsec3s failed: {e}"))?;

    // Collect signatures here.
    let mut new_sigs = vec![];

    let r = nsec3_records.nsec3param;
    let record = Record::new(
        r.owner().clone(),
        r.class(),
        r.ttl(),
        ZoneRecordData::Nsec3param(r.data().clone()),
    );
    let key = (record.owner().clone(), Rtype::NSEC3PARAM);
    let records = vec![record.clone()];

    // Insert in both old and new data.
    sign_records(
        &[record],
        &iss.keys,
        iss.inception,
        iss.expiration,
        &mut new_sigs,
    )?;
    iss.old_data.insert(key.clone(), records.clone());
    iss.new_data.insert(key, records);

    for r in nsec3_records.nsec3s {
        let record = Record::new(
            r.owner().clone(),
            r.class(),
            r.ttl(),
            ZoneRecordData::Nsec3(r.data().clone()),
        );
        iss.nsec3s.insert(record.owner().clone(), record.clone());
        sign_records(
            &[record],
            &iss.keys,
            iss.inception,
            iss.expiration,
            &mut new_sigs,
        )?;
    }
    for (sig, rtype) in new_sigs {
        let key = (sig[0].owner().clone(), rtype);
        iss.rrsigs.insert(key, sig);
    }
    Ok(())
}

fn get_unsigned_sorted(iss: &IncrementalSigningState) -> Vec<&Zrd> {
    // Create a Vec with all unsigned records to be able to sort them in
    // canonical order.

    let mut data: Vec<_> = iss.old_data.values().flatten().collect();
    data.par_sort_by(|e1, e2| CanonicalOrd::canonical_cmp(*e1, *e2));

    data
}

fn next_owner_hash_to_name(next_owner_hash_hex: &str, apex: &StoredName) -> Result<StoredName, ()> {
    let mut builder = NameBuilder::new_bytes();
    builder
        .append_chars(next_owner_hash_hex.chars())
        .map_err(|_| ())?;
    let next_owner_name = builder.append_origin(apex).map_err(|_| ())?;
    Ok(next_owner_name)
}

#[derive(Deserialize, Serialize)]
struct SignerConfig {
    signer_state: PathBuf,
    keyset_state: PathBuf,
    zonefile_in: PathBuf,
    zonefile_out: PathBuf,

    inception_offset: Duration,
    signature_lifetime: Duration,
    remain_time: Duration,
    use_nsec3: bool,
    algorithm: Nsec3HashAlgorithm,
    iterations: u16,
    salt: Nsec3Salt<Bytes>,
    opt_out: bool,
    zonemd: HashSet<ZonemdTuple>,
    serial_policy: SerialPolicy,
    notify_command: Vec<String>,

    /// Minimum period for updating signatures.
    signature_refresh_interval: Duration,

    /// Maxmimum time to resign all records with new ZSKs or CSKs.
    key_roll_time: Duration,

    /// Fake time to use when signing.
    ///
    /// This is need for integration tests.
    faketime: Option<UnixTime>,
}

#[derive(Deserialize, Serialize)]
struct SignerState {
    config_modified: UnixTime,
    keyset_state_modified: UnixTime,
    zonefile_modified: UnixTime,
    minimum_expiration: UnixTime,
    previous_serial: Option<Serial>,

    /// APEX RRtypes to remove. Should come from keyset, currently hardcoded.
    #[serde(default)]
    apex_remove: HashSet<Rtype>,

    /// extra APEX records, from keyset.
    #[serde(default)]
    apex_extra: Vec<String>,

    /// Current CSK/ZSK key tags.
    #[serde(default)]
    key_tags: HashSet<u16>,

    /// Start time of CSK/KSK key roll.
    #[serde(default)]
    key_roll: Option<UnixTime>,

    /// Last time some signature were refreshed.
    last_signature_refresh: UnixTime,
}

type RtypeSet = HashSet<Rtype>;
type ChangesValue = (RtypeSet, RtypeSet); // add set followed by delete set.

struct IncrementalSigningState {
    origin: Name<Bytes>,
    old_data: HashMap<(Name<Bytes>, Rtype), Vec<Zrd>>,
    new_data: BTreeMap<(Name<Bytes>, Rtype), Vec<Zrd>>,
    nsecs: BTreeMap<Name<Bytes>, Zrd>,
    nsec3s: BTreeMap<Name<Bytes>, Zrd>,
    rrsigs: HashMap<(Name<Bytes>, Rtype), Vec<Zrd>>,

    changes: HashMap<Name<Bytes>, ChangesValue>,
    modified_nsecs: HashSet<Name<Bytes>>,
    keys: Vec<SigningKey<Bytes, KeyPair>>,
    inception: Timestamp,
    expiration: Timestamp,

    // NSEC3 paramters.
    nsec3param: Nsec3param<Bytes>,
}

impl IncrementalSigningState {
    fn new(ws: &WorkSpace) -> Result<Self, Error> {
        let origin = ws.keyset_state.keyset.name();
        let origin = Name::<Bytes>::octets_from(origin.clone());

        let mut keys = Vec::new();
        for (k, v) in ws.keyset_state.keyset.keys() {
            let signer = match v.keytype() {
                KeyType::Ksk(_) => false,
                KeyType::Zsk(key_state) => key_state.signer(),
                KeyType::Csk(_, key_state) => key_state.signer(),
                KeyType::Include(_) => false,
            };

            if signer {
                let privref = v.privref().ok_or("missing private key")?;
                let priv_url = Url::parse(privref).expect("valid URL expected");
                let private_data = if priv_url.scheme() == "file" {
                    std::fs::read_to_string(priv_url.path()).map_err::<Error, _>(|e| {
                        format!("unable read from file {}: {e}", priv_url.path()).into()
                    })?
                } else {
                    panic!("unsupported URL scheme in {priv_url}");
                };
                let secret_key = SecretKeyBytes::parse_from_bind(&private_data)
                    .map_err::<Error, _>(|e| {
                        format!("unable to parse private key file {privref}: {e}").into()
                    })?;
                let pub_url = Url::parse(k).expect("valid URL expected");
                let public_data = if pub_url.scheme() == "file" {
                    std::fs::read_to_string(pub_url.path()).map_err::<Error, _>(|e| {
                        format!("unable read from file {}: {e}", pub_url.path()).into()
                    })?
                } else {
                    panic!("unsupported URL scheme in {pub_url}");
                };
                let public_key =
                    parse_from_bind::<Bytes>(&public_data).map_err::<Error, _>(|e| {
                        format!("unable to parse public key file {k}: {e}").into()
                    })?;

                let key_pair = KeyPair::from_bytes(&secret_key, public_key.data())
                    .map_err::<Error, _>(|e| {
                        format!("private key {privref} and public key {k} do not match: {e}").into()
                    })?;
                let signing_key = SigningKey::new(
                    public_key.owner().clone(),
                    public_key.data().flags(),
                    key_pair,
                );
                keys.push(signing_key);
            }
        }

        let now = ws.faketime_or_now();
        let now_u32 = Into::<Duration>::into(now.clone()).as_secs() as u32;
        let inception = (now_u32 - ws.config.inception_offset.as_secs() as u32).into();
        let expiration = (now_u32 + ws.config.signature_lifetime.as_secs() as u32).into();

        // This is the only way to deal with opt-out. There is no data type
        // for flags or constant for opt-out. Creating an Nsec3param makes it
        // possible to set opt-out.
        let mut nsec3param = Nsec3param::new(
            ws.config.algorithm,
            0,
            ws.config.iterations,
            ws.config.salt.clone(),
        );
        if ws.config.opt_out {
            nsec3param.set_opt_out_flag();
        }
        Ok(Self {
            origin,
            old_data: HashMap::new(),
            new_data: BTreeMap::new(),
            nsecs: BTreeMap::new(),
            nsec3s: BTreeMap::new(),
            rrsigs: HashMap::new(),
            changes: HashMap::new(),
            modified_nsecs: HashSet::new(),
            keys,
            inception,
            expiration,
            nsec3param,
        })
    }
}

type Zrd = Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>;

fn load_signed_zone(iss: &mut IncrementalSigningState, path: &PathBuf) -> Result<(), Error> {
    // Don't use Zonefile::load() as it knows nothing about the size of
    // the original file so uses default allocation which allocates more
    // bytes than are needed. Instead control the allocation size based on
    // our knowledge of the file size.
    let mut zone_file = File::open(path)
        .map_err(|e| format!("open failed: {e}").into())
        .context(&format!("loading zone file from path '{}'", path.display(),))?;
    let zone_file_len = zone_file
        .metadata()
        .map_err(|e| format!("unable to get metadata from {}: {e}", path.display()))?
        .len();
    let mut buf = inplace::Zonefile::with_capacity(zone_file_len as usize).writer();
    std::io::copy(&mut zone_file, &mut buf)
        .map_err(|e| format!("copy to {} failed: {e}", path.display()))?;
    let mut reader = buf.into_inner();

    reader.set_origin(iss.origin.clone());

    // Assume the signed zone is mostly sorted. Collect records for a
    // name/RRtype and store a complete RRset in a hash table.
    let mut records = Vec::<Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>>::new();
    let mut rrsig_records = vec![];
    let mut type_covered = Rtype::RRSIG;

    for entry in reader {
        let entry = entry.map_err(|err| format!("Invalid zone file: {err}"))?;
        match entry {
            Entry::Record(record) => {
                let record: StoredRecord = record.flatten_into();

                match record.data() {
                    ZoneRecordData::Rrsig(rrsig) => {
                        if rrsig_records.is_empty() {
                            type_covered = rrsig.type_covered();
                            rrsig_records.push(record);
                            continue;
                        }
                        if record.owner() == rrsig_records[0].owner()
                            && rrsig.type_covered() == type_covered
                        {
                            rrsig_records.push(record);
                            continue;
                        }

                        let key = (rrsig_records[0].owner().clone(), type_covered);
                        if let Some(v) = iss.rrsigs.get_mut(&key) {
                            v.append(&mut rrsig_records);
                        } else {
                            iss.rrsigs.insert(key, rrsig_records);
                        }
                        type_covered = rrsig.type_covered();
                        rrsig_records = vec![];
                        rrsig_records.push(record);
                    }
                    ZoneRecordData::Nsec(_) => {
                        // Assume (at most) one NSEC record per owner name.
                        // Directly insert into the btree map.
                        iss.nsecs.insert(record.owner().clone(), record);
                    }
                    ZoneRecordData::Nsec3(_) => {
                        // Assume (at most) one NSEC3 record per owner name.
                        // Directly insert into the btree map.
                        iss.nsec3s.insert(record.owner().clone(), record);
                    }
                    _ => {
                        if records.is_empty() {
                            records.push(record);
                            continue;
                        }
                        if record.owner() == records[0].owner()
                            && record.rtype() == records[0].rtype()
                        {
                            records.push(record);
                            continue;
                        }
                        let key = (records[0].owner().clone(), records[0].rtype());
                        if let Some(v) = iss.old_data.get_mut(&key) {
                            v.append(&mut records);
                        } else {
                            iss.old_data.insert(key, records);
                        }
                        records = vec![];
                        records.push(record);
                    }
                }
            }
            Entry::Include { .. } => {
                return Err(Error::from(
                    "Invalid zone file: $INCLUDE directive is not supported",
                ));
            }
        }
    }

    if !records.is_empty() {
        let key = (records[0].owner().clone(), records[0].rtype());
        if let Some(v) = iss.old_data.get_mut(&key) {
            v.append(&mut records);
        } else {
            iss.old_data.insert(key, records);
        }
    }
    if !rrsig_records.is_empty() {
        let key = (rrsig_records[0].owner().clone(), type_covered);
        if let Some(v) = iss.rrsigs.get_mut(&key) {
            v.append(&mut rrsig_records);
        } else {
            iss.rrsigs.insert(key, rrsig_records);
        }
    }
    Ok(())
}

fn load_unsigned_zone(iss: &mut IncrementalSigningState, path: &PathBuf) -> Result<(), Error> {
    // Basically a copy of load_signed_zone execpt that signature and NSEC(3)
    // records are removed. Make sure to delete and update APEX records.

    // Don't use Zonefile::load() as it knows nothing about the size of
    // the original file so uses default allocation which allocates more
    // bytes than are needed. Instead control the allocation size based on
    // our knowledge of the file size.
    let mut zone_file = File::open(path)
        .map_err(|e| format!("open failed: {e}").into())
        .context(&format!("loading zone file from path '{}'", path.display(),))?;
    let zone_file_len = zone_file
        .metadata()
        .map_err(|e| format!("unable to get metadata from {}: {e}", path.display()))?
        .len();
    let mut buf = inplace::Zonefile::with_capacity(zone_file_len as usize).writer();
    std::io::copy(&mut zone_file, &mut buf)
        .map_err(|e| format!("copy to {} failed: {e}", path.display()))?;
    let mut reader = buf.into_inner();

    reader.set_origin(iss.origin.clone());

    // Assume the zone is mostly sorted. Collect records for a
    // name/RRtype and store a complete RRset in a hash table.
    let mut records = Vec::<Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>>::new();

    for entry in reader {
        let entry = entry.map_err(|err| format!("Invalid zone file: {err}"))?;
        match entry {
            Entry::Record(record) => {
                let record: StoredRecord = record.flatten_into();

                match record.data() {
                    ZoneRecordData::Rrsig(_)
                    | ZoneRecordData::Nsec(_)
                    | ZoneRecordData::Nsec3(_)
                    | ZoneRecordData::Nsec3param(_)
                    | ZoneRecordData::Zonemd(_) => (), // Ignore.
                    _ => {
                        if records.is_empty() {
                            records.push(record);
                            continue;
                        }
                        if record.owner() == records[0].owner()
                            && record.rtype() == records[0].rtype()
                        {
                            records.push(record);
                            continue;
                        }
                        let key = (records[0].owner().clone(), records[0].rtype());
                        if let Some(v) = iss.new_data.get_mut(&key) {
                            v.append(&mut records);
                        } else {
                            iss.new_data.insert(key, records);
                        }
                        records = vec![];
                        records.push(record);
                    }
                }
            }
            Entry::Include { .. } => {
                return Err(Error::from(
                    "Invalid zone file: $INCLUDE directive is not supported",
                ));
            }
        }
    }

    if !records.is_empty() {
        let key = (records[0].owner().clone(), records[0].rtype());
        if let Some(v) = iss.new_data.get_mut(&key) {
            v.append(&mut records);
        } else {
            iss.new_data.insert(key, records);
        }
    }
    Ok(())
}

fn load_signed_only(iss: &mut IncrementalSigningState) {
    // Copy old data to new data.

    for (k, v) in &iss.old_data {
        iss.new_data.insert(k.clone(), v.clone());
    }
}

fn initial_diffs(iss: &mut IncrementalSigningState) -> Result<(), Error> {
    let mut new_sigs = vec![];
    for (_, new_rrset) in iss.new_data.iter_mut() {
        let key = (new_rrset[0].owner().clone(), new_rrset[0].rtype());
        if let Some(mut old_rrset) = iss.old_data.remove(&key) {
            let rtype = new_rrset[0].rtype();
            if rtype == Rtype::DNSKEY || rtype == Rtype::CDS || rtype == Rtype::CDNSKEY {
                // These types are signed by the key manager. No need to
                // check for changes.
                continue;
            }
            old_rrset.sort_by(|a, b| a.as_ref().data().canonical_cmp(b.as_ref().data()));
            new_rrset.sort_by(|a, b| a.as_ref().data().canonical_cmp(b.as_ref().data()));

            if *old_rrset != *new_rrset && iss.rrsigs.remove(&key).is_some() {
                sign_records(
                    new_rrset,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            }
        } else if let Some((added, _)) = iss.changes.get_mut(&key.0) {
            added.insert(new_rrset[0].rtype());
        } else {
            let mut added = HashSet::new();
            let removed = HashSet::new();
            added.insert(new_rrset[0].rtype());
            iss.changes.insert(key.0, (added, removed));
        }
    }
    for (sig, rtype) in new_sigs {
        let key = (sig[0].owner().clone(), rtype);
        iss.rrsigs.insert(key, sig);
    }
    for old_rrset in iss.old_data.values() {
        // What is left in old_data is removed.
        let rtype = old_rrset[0].rtype();
        let key = (old_rrset[0].owner().clone(), rtype);

        iss.rrsigs.remove(&key);

        if let Some((_, removed)) = iss.changes.get_mut(&key.0) {
            removed.insert(rtype);
        } else {
            let added = HashSet::new();
            let mut removed = HashSet::new();
            removed.insert(rtype);
            iss.changes.insert(key.0, (added, removed));
        }
    }
    Ok(())
}

fn incremental_nsec(iss: &mut IncrementalSigningState) -> Result<(), Error> {
    // Should changes be sorted or not? If changes is sorted we will
    // process a new delegation before any glue. Which is more efficient.
    // Otherwise if glue comes first, the glue will be signed and inserted
    // in the NSEC chain only to be removed when the delegation is processed.
    // However, we removing a delegation, the situation is reversed. For now
    // assuming that sorting is not necessary.

    let set_nsec_rrsig: HashSet<_> = [Rtype::NSEC, Rtype::RRSIG].into();

    let changes = iss.changes.clone();
    for (key, (add, delete)) in &changes {
        // The intersection between add and delete is empty.
        assert!(add.intersection(delete).next().is_none());

        if let Some(record_nsec) = iss.nsecs.get(key) {
            let record_nsec = record_nsec.clone();
            let ZoneRecordData::Nsec(nsec) = record_nsec.data() else {
                panic!("NSEC record expected");
            };

            // Convert the existing RRtype bitmap into a hash set.
            let mut curr = HashSet::new();
            for rtype in nsec.types() {
                curr.insert(rtype);
            }

            // The intersection between curr and add is empty.
            assert!(curr.intersection(add).next().is_none());

            // delete is completely contained in curr. In other words the
            // difference between delete and curr is empty.
            assert!(delete.difference(&curr).next().is_none());

            if add.contains(&Rtype::NS) {
                // Apex is special, but we can assume the NS RRset will not
                // be added to apex.
                assert!(*key != iss.origin);

                // Remove the signatures for the existing types.
                for rtype in nsec.types().iter() {
                    // When NS is added, we should keep the signatures for
                    // DS and NSEC. The NSEC signature will be updated but
                    // there is no point in removing it first. Do not try to
                    // remove a signature for RRSIG because it does not exist.
                    if rtype == Rtype::DS || rtype == Rtype::NSEC || rtype == Rtype::RRSIG {
                        continue;
                    }
                    let key = (key.clone(), rtype);
                    iss.rrsigs.remove(&key);
                }

                // Restrict curr and add to these types.
                let mask: HashSet<Rtype> = [Rtype::NS, Rtype::DS, Rtype::NSEC, Rtype::RRSIG].into();

                let curr = curr.intersection(&mask).copied().collect();
                let add = add.intersection(&mask).copied().collect();

                // Update the NSEC record.
                nsec_update_bitmap(
                    &record_nsec,
                    nsec,
                    &curr,
                    &add,
                    delete,
                    &set_nsec_rrsig,
                    iss,
                );

                // Mark descendents as occluded after updating the bitmap.
                // The reason is that nsec_update_bitmap uses the current
                // next_name and nsec_set_occluded may change that.
                nsec_set_occluded(key, iss);

                continue;
            }
            if delete.contains(&Rtype::NS) {
                // Apex is special, but we can assume the NS RRset will not
                // be removed from apex.
                assert!(*key != iss.origin);

                // Curr does not include all types at this name. Add the
                // missing types to curr.
                let range_key = (key.clone(), 0.into());
                let range = iss.new_data.range(range_key..);
                for ((r_name, r_type), _) in range {
                    if r_name != key {
                        break;
                    }
                    if add.contains(r_type) {
                        // Skip what we are trying to add.
                        continue;
                    }
                    curr.insert(*r_type);
                }

                let mut new = nsec_update_bitmap(
                    &record_nsec,
                    nsec,
                    &curr,
                    add,
                    delete,
                    &set_nsec_rrsig,
                    iss,
                );

                // Sign the types at this name except for NSEC, and RRSIG.
                new.remove(&Rtype::NSEC);
                new.remove(&Rtype::RRSIG);
                sign_rtype_set(key, &new, iss)?;

                // Names that were previously occluded are no longer.
                nsec_clear_occluded(key, iss)?;
                continue;
            }
            if *key != iss.origin && nsec.types().contains(Rtype::NS) {
                // NS marks a delegation but only when the NS is not
                // at the apex.

                // If the add set contains DS then sign the DS RRset.
                if add.contains(&Rtype::DS) {
                    let ds_set: HashSet<_> = [Rtype::DS].into();
                    sign_rtype_set(key, &ds_set, iss)?;
                }
                nsec_update_bitmap(&record_nsec, nsec, &curr, add, delete, &set_nsec_rrsig, iss);
                continue;
            }

            // The add types need to be signed.
            sign_rtype_set(key, add, iss)?;

            nsec_update_bitmap(&record_nsec, nsec, &curr, add, delete, &set_nsec_rrsig, iss);
        } else {
            if add.is_empty() {
                assert!(!delete.is_empty());
                // No need to do anything.
                continue;
            }
            assert!(delete.is_empty());
            if is_occluded(key, iss) {
                // No need to do anything.
                continue;
            }

            if add.contains(&Rtype::NS) {
                // Create a new NSEC record and sign only DS records (if any).
                let rtypebitmap = nsec_rtypebitmap_from_iterator(add.iter());
                nsec_insert(key, rtypebitmap, iss);
                if add.contains(&Rtype::DS) {
                    let ds_set: HashSet<_> = [Rtype::DS].into();
                    sign_rtype_set(key, &ds_set, iss)?;
                }

                // nsec_set_occluded expects the NSEC for key to exist.
                // So call this after inserting the new NSEC record.
                nsec_set_occluded(key, iss);
                continue;
            }
            // Create a new NSEC record and sign all records.
            let rtypebitmap = nsec_rtypebitmap_from_iterator(add.iter());
            nsec_insert(key, rtypebitmap, iss);
            sign_rtype_set(key, add, iss)?;
        }
    }
    Ok(())
}

fn incremental_nsec3(iss: &mut IncrementalSigningState) -> Result<(), Error> {
    // Should changes be sorted or not? If changes is sorted we will
    // process a new delegation before any glue. Which is more efficient.
    // Otherwise if glue comes first, the glue will be signed and inserted
    // in the NSEC chain only to be removed when the delegation is processed.
    // However, we removing a delegation, the situation is reversed. For now
    // assuming that sorting is not necessary.

    let opt_out_flag = iss.nsec3param.opt_out_flag();

    let changes = iss.changes.clone();
    for (key, (add, delete)) in &changes {
        // The intersection between add and delete is empty.
        assert!(add.intersection(delete).next().is_none());

        let (nsec3_hash_octets, nsec3_name) = nsec3_hash_parts(key, iss);

        if let Some(record_nsec3) = iss.nsec3s.get(&nsec3_name) {
            let record_nsec3 = record_nsec3.clone();
            let ZoneRecordData::Nsec3(nsec3) = record_nsec3.data() else {
                panic!("NSEC3 record expected");
            };

            // Convert the existing RRtype bitmap into a hash set.
            let mut curr = HashSet::new();
            for rtype in nsec3.types() {
                curr.insert(rtype);
            }

            // The intersection between curr and add is empty.
            assert!(curr.intersection(add).next().is_none());

            // delete is completely contained in curr. In other words the
            // difference between delete and curr is empty.
            assert!(delete.difference(&curr).next().is_none());

            if add.contains(&Rtype::NS) {
                // Apex is special, but we can assume the NS RRset will not
                // be added to apex.
                assert!(*key != iss.origin);

                // Remove the signatures for the existing types.
                for rtype in nsec3.types().iter() {
                    // When NS is added, we should keep the signatures for
                    // DS. Do not try to remove a signature for RRSIG because
                    // it does not exist.
                    if rtype == Rtype::DS || rtype == Rtype::RRSIG {
                        continue;
                    }
                    let key = (key.clone(), rtype);
                    iss.rrsigs.remove(&key);
                }

                // Restrict curr and add to these types.
                let mask: HashSet<Rtype> = [Rtype::NS, Rtype::DS, Rtype::RRSIG].into();

                let curr = curr.intersection(&mask).copied().collect();
                let add = add.intersection(&mask).copied().collect();

                // Update the NSEC3 record.
                nsec3_update_bitmap(key, &record_nsec3, nsec3, &curr, &add, delete, iss);

                // Mark descendents as occluded after updating the bitmap.
                // The reason is that nsec3_update_bitmap uses the current
                // next_hash and nsec3_set_occluded may change that.
                nsec3_set_occluded(key, iss);

                continue;
            }
            if delete.contains(&Rtype::NS) {
                // Apex is special, but we can assume the NS RRset will not
                // be removed from apex.
                assert!(*key != iss.origin);

                // Curr does not include all types at this name. Add the
                // missing types to curr.
                let range_key = (key.clone(), 0.into());
                let range = iss.new_data.range(range_key..);
                for ((r_name, r_type), _) in range {
                    if r_name != key {
                        break;
                    }
                    if add.contains(r_type) {
                        // Skip what we are trying to add.
                        continue;
                    }
                    curr.insert(*r_type);
                }

                let mut new =
                    nsec3_update_bitmap(key, &record_nsec3, nsec3, &curr, add, delete, iss);

                // Sign the types at this name except for NSEC, and RRSIG.
                new.remove(&Rtype::RRSIG);
                sign_rtype_set(key, &new, iss)?;

                // Names that were previously occluded are no longer.
                nsec3_clear_occluded(key, iss)?;
                continue;
            }
            if *key != iss.origin && nsec3.types().contains(Rtype::NS) {
                // NS marks a delegation but only when the NS is not
                // at the apex.

                // If the add set contains DS then sign the DS RRset.
                if add.contains(&Rtype::DS) {
                    let ds_set: HashSet<_> = [Rtype::DS].into();
                    sign_rtype_set(key, &ds_set, iss)?;
                }
                nsec3_update_bitmap(key, &record_nsec3, nsec3, &curr, add, delete, iss);
                continue;
            }

            // The add types need to be signed.
            sign_rtype_set(key, add, iss)?;

            nsec3_update_bitmap(key, &record_nsec3, nsec3, &curr, add, delete, iss);
        } else {
            if add.is_empty() {
                assert!(!delete.is_empty());

                // Special magic for out-out. It is possible that an NS
                // record got deleted. With opt-out there will not be an
                // NSEC3 record if there is only a NS record and no DS record.
                if opt_out_flag && delete.contains(&Rtype::NS) {
                    if is_occluded(key, iss) {
                        // No need to do anything.
                        continue;
                    }
                    nsec3_clear_occluded(key, iss)?;
                    continue;
                }

                // No need to do anything.
                continue;
            }
            assert!(delete.is_empty());
            if is_occluded(key, iss) {
                // No need to do anything.
                continue;
            }

            // Just copy add in case we need to change it.
            let mut add = add.clone();
            if opt_out_flag {
                // We have a new record and no NSEC3 record exists. But in the
                // case of opt-out there may already be an NS record.
                // We are not at APEX because APEX always has an NSEC3
                // record.
                let tmpkey = (key.clone(), Rtype::NS);
                if iss.new_data.contains_key(&tmpkey) {
                    // Found an NS record. It is safe to add NS to the add
                    // set.
                    add.insert(Rtype::NS);
                }
            }

            if add.contains(&Rtype::NS) {
                if opt_out_flag {
                    // Check if this is just an NS record. If so, don't
                    // create an NSEC3 record.
                    if !add.iter().any(|r| *r != Rtype::NS) {
                        continue;
                    }
                }
                // Create a new NSEC3 record and sign only DS records (if any).
                // If add contains DS then add RRSIG to add.

                let mut add = add.clone(); // In case we need to add RRSIG.
                if add.contains(&Rtype::DS) {
                    let ds_set: HashSet<_> = [Rtype::DS].into();
                    sign_rtype_set(key, &ds_set, iss)?;
                    add.insert(Rtype::RRSIG);
                }

                let rtypebitmap = nsec3_rtypebitmap_from_iterator(add.iter());

                nsec3_insert_full(key, nsec3_hash_octets, &nsec3_name, rtypebitmap, iss);
                nsec3_set_occluded(key, iss);
                continue;
            }
            // The new name is not a delegation. Add RRSIG to the set of
            // Rtypes.
            let mut add_with_rrsig = add.clone();
            add_with_rrsig.insert(Rtype::RRSIG);

            // Create a new NSEC3 record and sign all records.
            let rtypebitmap = nsec3_rtypebitmap_from_iterator(add_with_rrsig.iter());
            nsec3_insert_full(key, nsec3_hash_octets, &nsec3_name, rtypebitmap, iss);
            sign_rtype_set(key, &add, iss)?;
        }
    }
    Ok(())
}

fn nsec_insert(
    name: &Name<Bytes>,
    rtypebitmap: RtypeBitmap<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    // Try to find the NSEC record that comes before the one we are trying
    // to insert. Assume that the APEX NSEC will always exist can sort
    // before anything else.
    let mut range = iss.nsecs.range::<Name<_>, _>(..name);
    let (previous_name, previous_record) = range
        .next_back()
        .expect("previous NSEC record should exist");
    let previous_name = previous_name.clone();
    let previous_record = previous_record.clone();
    drop(range);
    let ZoneRecordData::Nsec(previous_nsec) = previous_record.data() else {
        panic!("NSEC record expected");
    };
    let next = previous_nsec.next_name();
    let new_nsec = Nsec::new(next.clone(), rtypebitmap);
    let new_record = Record::new(
        name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec(new_nsec),
    );
    iss.nsecs.insert(name.clone(), new_record);
    iss.modified_nsecs.insert(name.clone());
    let previous_nsec = Nsec::new(name.clone(), previous_nsec.types().clone());
    let previous_record = Record::new(
        previous_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec(previous_nsec),
    );
    iss.nsecs.insert(previous_name.clone(), previous_record);
    iss.modified_nsecs.insert(previous_name.clone());
}

fn nsec_remove(name: &Name<Bytes>, next_name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    // Try to find the NSEC record that comes before the one we are trying
    // to remove. Assume that the APEX NSEC will always exist can sort
    // before anything else.
    let mut range = iss.nsecs.range::<Name<_>, _>(..name);
    let (previous_name, previous_record) = range
        .next_back()
        .expect("previous NSEC record should exist");
    let previous_name = previous_name.clone();
    let previous_record = previous_record.clone();
    drop(range);
    let ZoneRecordData::Nsec(previous_nsec) = previous_record.data() else {
        panic!("NSEC record expected");
    };
    let previous_nsec = Nsec::new(next_name.clone(), previous_nsec.types().clone());
    let previous_record = Record::new(
        previous_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec(previous_nsec),
    );
    iss.nsecs.insert(previous_name.clone(), previous_record);
    iss.modified_nsecs.insert(previous_name.clone());
    iss.nsecs.remove(name);
    iss.modified_nsecs.remove(name);
    let key = (name.clone(), Rtype::NSEC);
    iss.rrsigs.remove(&key);
}

// Return the effective result HashSet even when the NSEC record gets deleted.
fn nsec_update_bitmap(
    record: &Zrd,
    nsec: &Nsec<Bytes, Name<Bytes>>,
    curr: &HashSet<Rtype>,
    add: &HashSet<Rtype>,
    delete: &HashSet<Rtype>,
    set_nsec_rrsig: &HashSet<Rtype>,
    iss: &mut IncrementalSigningState,
) -> HashSet<Rtype> {
    // Update curr.
    let curr: HashSet<_> = curr.union(add).copied().collect();
    let curr = curr.difference(delete).copied().collect();

    let owner = record.owner();
    if curr == *set_nsec_rrsig {
        nsec_remove(owner, nsec.next_name(), iss);
        return curr;
    }

    let rtypebitmap = nsec_rtypebitmap_from_iterator(curr.iter());
    let nsec = Nsec::new(nsec.next_name().clone(), rtypebitmap);
    let record = Record::new(
        record.owner().clone(),
        record.class(),
        record.ttl(),
        ZoneRecordData::Nsec(nsec),
    );
    iss.nsecs.insert(owner.clone(), record);

    iss.modified_nsecs.insert(owner.clone());
    curr
}

fn nsec_set_occluded(name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    let Some(nsec_record) = iss.nsecs.get(name) else {
        panic!("NSEC for {name} expected to exist");
    };
    let ZoneRecordData::Nsec(nsec) = nsec_record.data() else {
        panic!("NSEC record expected");
    };
    let nsec = nsec.clone();
    let mut next = nsec.next_name().clone();
    loop {
        if !next.ends_with(name) {
            break;
        }

        // For consistency, make sure next is not equal to name.
        if next == name {
            break;
        }
        let curr = next;
        let Some(nsec_record) = iss.nsecs.get(&curr) else {
            panic!("NSEC for {name} expected to exist");
        };
        let ZoneRecordData::Nsec(nsec) = nsec_record.data() else {
            panic!("NSEC record expected");
        };
        let nsec = nsec.clone();
        next = nsec.next_name().clone();

        nsec_remove(&curr, &next, iss);

        // Remove all signatures.
        for rtype in nsec.types().iter() {
            let key = (curr.clone(), rtype);
            iss.rrsigs.remove(&key);
        }
    }
}

fn nsec_clear_occluded(name: &Name<Bytes>, iss: &mut IncrementalSigningState) -> Result<(), Error> {
    let key = (name.clone(), Rtype::SOA);
    let range = iss.new_data.range(key..);
    let mut opt_curr_name: Option<&Name<Bytes>> = None;
    let mut curr_types: HashSet<Rtype> = HashSet::new();
    let mut work = vec![];

    // Keep track of delegations. Name below a delegation remain occluded.
    let mut delegation: Option<Name<Bytes>> = None;

    for ((key_name, key_rtype), _) in range {
        // There is no easy way to avoid name showing up in the range. Just
        // filter out name.
        if key_name == name {
            continue;
        }

        // Make sure curr_name is below name.
        if !key_name.ends_with(name) {
            break;
        }
        if let Some(d) = &delegation {
            if key_name.ends_with(d) && key_name != d {
                // Skip.
                continue;
            }
        }
        if *key_rtype == Rtype::NS {
            // Set key_name as a delegation.
            delegation = Some(key_name.clone());
        }
        if let Some(curr_name) = opt_curr_name {
            if key_name == curr_name {
                curr_types.insert(*key_rtype);
            } else {
                work.push((curr_name.clone(), curr_types));
                opt_curr_name = Some(key_name);
                curr_types = [*key_rtype].into();
            }
        } else {
            opt_curr_name = Some(key_name);
            curr_types.insert(*key_rtype);
        }
    }
    if let Some(curr_name) = opt_curr_name {
        work.push((curr_name.clone(), curr_types));
    }
    for (curr_name, curr_types) in work {
        let mut curr_types = if curr_types.contains(&Rtype::NS) {
            let has_ds = curr_types.contains(&Rtype::DS);
            let mut curr_types: HashSet<Rtype> = [Rtype::NS].into();
            if has_ds {
                curr_types.insert(Rtype::DS);
            }
            curr_types
        } else {
            curr_types
        };
        let rtypebitmap = nsec_rtypebitmap_from_iterator(curr_types.iter());

        // Make sure NS doesn't get signed.
        curr_types.remove(&Rtype::NS);
        sign_rtype_set(&curr_name, &curr_types, iss)?;
        nsec_insert(&curr_name, rtypebitmap, iss);
    }
    Ok(())
}

fn nsec_rtypebitmap_from_iterator<'a, I>(iter: I) -> RtypeBitmap<Bytes>
where
    I: Iterator<Item = &'a Rtype>,
{
    let mut rtypebitmap = RtypeBitmap::<Bytes>::builder();
    rtypebitmap.add(Rtype::NSEC).expect("should not fail");
    rtypebitmap.add(Rtype::RRSIG).expect("should not fail");
    for rtype in iter {
        rtypebitmap.add(*rtype).expect("should not fail");
    }
    rtypebitmap.finalize()
}

fn nsec3_insert_full(
    name: &Name<Bytes>,
    nsec3_hash: OwnerHash<Bytes>,
    nsec3_name: &Name<Bytes>,
    rtypebitmap: RtypeBitmap<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    nsec3_insert_one(nsec3_hash, nsec3_name, rtypebitmap, iss);

    // Assume that we never insert the APEX. So the parent always exists.
    let name = name.parent().expect("should exist");
    nsec3_insert_ent(&name, iss);
}

fn nsec3_insert_ent(name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    // Check if name has an NSEC3 record. If so, we are done. Otherwise,
    // insert an ENT and continue with the parent.
    let mut name = name.clone();
    loop {
        if !name.ends_with(&iss.origin) {
            // This is weird, we should never be able to get beyond APEX.
            // Just ignore this.
            return;
        }
        if name == iss.origin {
            // APEX exists by definition.
            return;
        }

        let (nsec3_hash_octets, nsec3_name) = nsec3_hash_parts(&name, iss);

        if iss.nsec3s.contains_key(&nsec3_name) {
            // Found something. We are done.
            return;
        }

        let rtypebitmap = RtypeBitmap::<Bytes>::builder();
        let rtypebitmap = rtypebitmap.finalize();
        nsec3_insert_one(nsec3_hash_octets, &nsec3_name, rtypebitmap, iss);

        // Get the parent. We should be below APEX, so the parent has to exist.
        name = name.parent().expect("parent should exist");
    }
}

fn nsec3_insert_one(
    nsec3_hash: OwnerHash<Bytes>,
    nsec3_name: &Name<Bytes>,
    rtypebitmap: RtypeBitmap<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    // Try to find the NSEC3 record that comes before the one we are trying
    // to insert. It is possible that we try to insert before the first NSEC3
    // record. In that case, logically try to insert after the last NSEC3
    // record.
    let mut range = iss.nsec3s.range::<Name<_>, _>(..nsec3_name);
    let (previous_name, previous_record) = if let Some(kv) = range.next_back() {
        kv
    } else {
        let mut range = iss.nsec3s.range::<Name<_>, _>(nsec3_name..);
        range
            .next_back()
            .expect("at least one element should exist")
    };
    let previous_name = previous_name.clone();
    let previous_record = previous_record.clone();
    drop(range);
    let ZoneRecordData::Nsec3(previous_nsec3) = previous_record.data() else {
        panic!("NSEC3 record expected");
    };
    let next = previous_nsec3.next_owner();
    let new_nsec3 = Nsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt().clone(),
        next.clone(),
        rtypebitmap,
    );
    let new_record = Record::new(
        nsec3_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec3(new_nsec3),
    );
    iss.nsec3s.insert(nsec3_name.clone(), new_record);
    iss.modified_nsecs.insert(nsec3_name.clone());
    let previous_nsec3 = Nsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt().clone(),
        nsec3_hash,
        previous_nsec3.types().clone(),
    );
    let previous_record = Record::new(
        previous_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec3(previous_nsec3),
    );
    iss.nsec3s.insert(previous_name.clone(), previous_record);
    iss.modified_nsecs.insert(previous_name.clone());
}

// Return the effective result HashSet even when the NSEC3 record gets deleted.
fn nsec3_update_bitmap(
    name: &Name<Bytes>,
    nsec3_record: &Zrd,
    nsec3: &Nsec3<Bytes>,
    curr: &HashSet<Rtype>,
    add: &HashSet<Rtype>,
    delete: &HashSet<Rtype>,
    iss: &mut IncrementalSigningState,
) -> HashSet<Rtype> {
    // Update curr.
    let curr: HashSet<_> = curr.union(add).copied().collect();
    let mut curr: HashSet<_> = curr.difference(delete).copied().collect();
    let owner = nsec3_record.owner();

    // Check if we need to add or remove RRSIG. Assume that apex has a SOA
    // record.
    if curr.contains(&Rtype::NS) && !curr.contains(&Rtype::SOA) {
        // For an NS not at origin, there is an RRSIG if there is also a
        // DS record.
        if curr.contains(&Rtype::DS) {
            // Yes, add RRSIG.
            curr.insert(Rtype::RRSIG);
        } else {
            // No. Remove RRSIG.
            curr.remove(&Rtype::RRSIG);
        }
    } else {
        // Is there anything apart from RRSIG?
        if curr.iter().any(|r| *r != Rtype::RRSIG) {
            // Yes. Add RRSIG.
            curr.insert(Rtype::RRSIG);
        } else {
            // No. Remove RRSIG.
            curr.remove(&Rtype::RRSIG);
        }
    }

    if curr.is_empty() {
        // The NSEC3 bitmp will be empty, but this may now have become an
        // empty non-terminal. Our only option is to update the NSEC3 record
        // and then call nsec3_remove_et to see if it is empty can can be
        // removed.
        nsec3_update(owner, nsec3_record, nsec3, &curr, iss);
        nsec3_remove_et(name, iss);
        return curr;
    }

    if iss.nsec3param.opt_out_flag() && !curr.iter().any(|r| *r != Rtype::NS) {
        // The new bitmap has nothing except for NS. We would like to delete
        // the NSEC3. However there may still be descendents that need to be
        // removed with nsec3_set_occluded. Update this NSEC3 to be empty and
        // call nsec3_remove_et to remove it if there are no descendents.

        let empty_curr = HashSet::new();
        nsec3_update(owner, nsec3_record, nsec3, &empty_curr, iss);
        nsec3_remove_et(name, iss);
        return curr;
    }

    nsec3_update(owner, nsec3_record, nsec3, &curr, iss);
    curr
}

fn nsec3_update(
    owner: &Name<Bytes>,
    nsec3_record: &Zrd,
    nsec3: &Nsec3<Bytes>,
    rtypes: &HashSet<Rtype>,
    iss: &mut IncrementalSigningState,
) {
    // Just update an NSEC3 record without further logic.
    let rtypebitmap = nsec3_rtypebitmap_from_iterator(rtypes.iter());
    let nsec3 = Nsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt().clone(),
        nsec3.next_owner().clone(),
        rtypebitmap,
    );
    let record = Record::new(
        nsec3_record.owner().clone(),
        nsec3_record.class(),
        nsec3_record.ttl(),
        ZoneRecordData::Nsec3(nsec3),
    );
    iss.nsec3s.insert(owner.clone(), record);

    iss.modified_nsecs.insert(owner.clone());
}

fn nsec3_remove_full(
    name: &Name<Bytes>,
    nsec3_name: &Name<Bytes>,
    nsec3_next: &OwnerHash<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    nsec3_remove_one(nsec3_name, nsec3_next, iss);

    // Assume that we never remove the APEX. So the parent always exists.
    let name = name.parent().expect("should exist");
    nsec3_remove_et(&name, iss);
}

fn nsec3_remove_et(name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    // Check if name is an ET. If so remove it and see if the parent is
    // also an ET.
    //
    // Take a simple approach to check if a name is an ET: first lookup
    // the NSEC3 record for name and check that the bitmap is empty. Then
    // check all descendent names and check that none of them has an
    // NSEC3 record.
    let mut name = name.clone();
    loop {
        if !name.ends_with(&iss.origin) {
            // This is weird, we should never be able to get beyond APEX.
            // Just ignore this.
            return;
        }
        if name == iss.origin {
            // Never remove the NSEC3 record for APEX.
            return;
        }

        let (_, nsec3_name) = nsec3_hash_parts(&name, iss);

        let Some(record_nsec3) = iss.nsec3s.get(&nsec3_name) else {
            // No NSEC3 record, nothing to do.
            return;
        };

        let ZoneRecordData::Nsec3(nsec3) = record_nsec3.data() else {
            panic!("NSEC3 record expected");
        };

        if !nsec3.types().is_empty() {
            // There are types here.
            return;
        }

        // Check the descendents.
        let key = (name.clone(), Rtype::SOA);
        let range = iss.new_data.range(key..);
        let mut opt_curr_name: Option<&Name<Bytes>> = None;

        for ((key_name, _), _) in range {
            // There is no easy way to avoid name showing up in the range. Just
            // filter out name.
            if *key_name == name {
                continue;
            }

            // Make sure curr_name is below name.
            if !key_name.ends_with(&name) {
                break;
            }

            if let Some(curr_name) = opt_curr_name {
                if key_name == curr_name {
                    // Already checked.
                    continue;
                }
            }
            opt_curr_name = Some(key_name);

            let (_, nsec3_name) = nsec3_hash_parts(key_name, iss);

            if iss.nsec3s.contains_key(&nsec3_name) {
                // NSEC3 record is found. Our target is not an ET.
                return;
            };
        }

        // No descendents with NSEC3 records are found. Delete this one.
        let next_owner = nsec3.next_owner().clone();
        nsec3_remove_one(&nsec3_name, &next_owner, iss);

        // We remove the NSEC3 record for the name. Get the parent. We should
        // be below APEX, so the parent has to exist.
        name = name.parent().expect("parent should exist");
    }
}

fn nsec3_remove_one(
    nsec3_name: &Name<Bytes>,
    nsec3_next: &OwnerHash<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    // Try to find the NSEC3 record that comes before the one we are trying
    // to remove.
    let mut range = iss.nsec3s.range::<Name<_>, _>(..nsec3_name);
    let (previous_name, previous_record) = if let Some(kv) = range.next_back() {
        kv
    } else {
        let mut range = iss.nsec3s.range::<Name<_>, _>(nsec3_name..);
        range
            .next_back()
            .expect("at least one element should exist")
    };

    let previous_name = previous_name.clone();
    let previous_record = previous_record.clone();
    drop(range);
    let ZoneRecordData::Nsec3(previous_nsec) = previous_record.data() else {
        panic!("NSEC3 record expected");
    };
    let previous_nsec3 = Nsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt().clone(),
        nsec3_next.clone(),
        previous_nsec.types().clone(),
    );
    let previous_record = Record::new(
        previous_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec3(previous_nsec3),
    );
    iss.nsec3s.insert(previous_name.clone(), previous_record);
    iss.modified_nsecs.insert(previous_name.clone());
    iss.nsec3s.remove(nsec3_name);
    iss.modified_nsecs.remove(nsec3_name);
    let key = (nsec3_name.clone(), Rtype::NSEC3);
    iss.rrsigs.remove(&key);
}

fn nsec3_set_occluded(name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    // Loop over all names below name, if there is an NSEC3 record then
    // delete all signatures and the NSEC3 record.

    let key = (name.clone(), Rtype::SOA);
    let range = iss.new_data.range(key..);
    let mut opt_curr_name: Option<&Name<Bytes>> = None;
    let mut work = vec![];

    for ((key_name, _), _) in range {
        // There is no easy way to avoid name showing up in the range. Just
        // filter out name.
        if key_name == name {
            continue;
        }

        // Make sure curr_name is below name.
        if !key_name.ends_with(name) {
            break;
        }

        if let Some(curr_name) = opt_curr_name {
            if key_name == curr_name {
                // Looked at this name already.
                continue;
            }
        }
        opt_curr_name = Some(key_name);

        let (_, nsec3_name) = nsec3_hash_parts(key_name, iss);

        let Some(record_nsec3) = iss.nsec3s.get(&nsec3_name) else {
            // No NSEC3 record, nothing to do.
            continue;
        };

        let ZoneRecordData::Nsec3(nsec3) = record_nsec3.data() else {
            panic!("NSEC3 record expected");
        };

        work.push((key_name.clone(), nsec3_name));

        // Remove all signatures.
        for rtype in nsec3.types().iter() {
            let key = (key_name.clone(), rtype);
            iss.rrsigs.remove(&key);
        }
    }
    for (key_name, nsec3_name) in work {
        let record_nsec3 = iss.nsec3s.get(&nsec3_name).expect("NSEC3 should exist");

        let ZoneRecordData::Nsec3(nsec3) = record_nsec3.data() else {
            panic!("NSEC3 record expected");
        };

        let nsec3_next = nsec3.next_owner().clone();
        nsec3_remove_full(&key_name, &nsec3_name, &nsec3_next, iss);
    }
}

fn nsec3_clear_occluded(
    name: &Name<Bytes>,
    iss: &mut IncrementalSigningState,
) -> Result<(), Error> {
    let key = (name.clone(), Rtype::SOA);
    let range = iss.new_data.range(key..);
    let mut opt_curr_name: Option<&Name<Bytes>> = None;
    let mut curr_types: HashSet<Rtype> = HashSet::new();
    let mut work = vec![];

    // Keep track of delegations. Name below a delegation remain occluded.
    let mut delegation: Option<Name<Bytes>> = None;

    for ((key_name, key_rtype), _) in range {
        // There is no easy way to avoid name showing up in the range. Just
        // filter out name.
        if key_name == name {
            continue;
        }

        // Make sure curr_name is below name.
        if !key_name.ends_with(name) {
            break;
        }
        if let Some(d) = &delegation {
            if key_name.ends_with(d) && key_name != d {
                // Skip.
                continue;
            }
        }
        if *key_rtype == Rtype::NS {
            // Set key_name as a delegation.
            delegation = Some(key_name.clone());
        }
        if let Some(curr_name) = opt_curr_name {
            if key_name == curr_name {
                curr_types.insert(*key_rtype);
            } else {
                work.push((curr_name.clone(), curr_types));
                opt_curr_name = Some(key_name);
                curr_types = [*key_rtype].into();
            }
        } else {
            opt_curr_name = Some(key_name);
            curr_types.insert(*key_rtype);
        }
    }
    if let Some(curr_name) = opt_curr_name {
        work.push((curr_name.clone(), curr_types));
    }
    for (curr_name, mut curr_types) in work {
        let mut curr_types = if curr_types.contains(&Rtype::NS) {
            let has_ds = curr_types.contains(&Rtype::DS);
            let mut curr_types: HashSet<Rtype> = [Rtype::NS].into();
            if has_ds {
                curr_types.insert(Rtype::DS);
                curr_types.insert(Rtype::RRSIG);
            }
            curr_types
        } else {
            curr_types.insert(Rtype::RRSIG);
            curr_types
        };
        let rtypebitmap = nsec3_rtypebitmap_from_iterator(curr_types.iter());

        // Make sure NS doesn't get signed. And avoid signing RRSIGs.
        curr_types.remove(&Rtype::NS);
        curr_types.remove(&Rtype::RRSIG);
        sign_rtype_set(&curr_name, &curr_types, iss)?;

        let (nsec3_hash_octets, nsec3_name) = nsec3_hash_parts(&curr_name, iss);

        nsec3_insert_full(&curr_name, nsec3_hash_octets, &nsec3_name, rtypebitmap, iss);
    }
    Ok(())
}

fn nsec3_rtypebitmap_from_iterator<'a, I>(iter: I) -> RtypeBitmap<Bytes>
where
    I: Iterator<Item = &'a Rtype>,
{
    let mut rtypebitmap = RtypeBitmap::<Bytes>::builder();
    for rtype in iter {
        rtypebitmap.add(*rtype).expect("should not fail");
    }
    rtypebitmap.finalize()
}

fn nsec3_hash_parts(
    name: &Name<Bytes>,
    iss: &IncrementalSigningState,
) -> (OwnerHash<Bytes>, Name<Bytes>) {
    let nsec3_hash_octets = OwnerHash::<Bytes>::octets_from(
        nsec3_hash::<_, _, BytesMut>(
            name,
            iss.nsec3param.hash_algorithm(),
            iss.nsec3param.iterations(),
            iss.nsec3param.salt(),
        )
        .expect("should not fail"),
    );
    let nsec3_hash_base32 = base32::encode_string_hex(&nsec3_hash_octets).to_ascii_lowercase();
    let mut builder = NameBuilder::<BytesMut>::new();
    builder
        .append_label(nsec3_hash_base32.as_bytes())
        .expect("should not fail");
    let nsec3_name = builder.append_origin(&iss.origin).expect("should not fail");
    (nsec3_hash_octets, nsec3_name)
}

fn is_occluded(name: &Name<Bytes>, iss: &IncrementalSigningState) -> bool {
    // We need to check if the parent of name is a delegation. Stop
    // when we reached origin.
    let Some(mut curr) = name.parent() else {
        // We asked for the parent of the root. That is weird. Just
        // return not occluded.
        return false;
    };
    loop {
        if curr == iss.origin {
            // We reached apex. The name was not occluded.
            return false;
        }
        if !curr.ends_with(&iss.origin) {
            // Something weird is going on. Return not occluded.
            return false;
        }
        if iss.new_data.contains_key(&(curr.clone(), Rtype::NS)) {
            // Name is occluded.
            return true;
        }
        let Some(parent) = curr.parent() else {
            // We asked for the parent of the root. That is weird. Just
            // return not occluded.
            return false;
        };
        curr = parent;
    }
}

fn sign_rtype_set(
    name: &Name<Bytes>,
    set: &HashSet<Rtype>,
    iss: &mut IncrementalSigningState,
) -> Result<(), Error> {
    let mut new_sigs = vec![];
    for rtype in set {
        let key = (name.clone(), *rtype);
        let Some(records) = iss.new_data.get(&key) else {
            panic!("Expected something for {name}/{rtype}");
        };
        sign_records(
            records,
            &iss.keys,
            iss.inception,
            iss.expiration,
            &mut new_sigs,
        )?;
    }
    for (sig, rtype) in new_sigs {
        let key = (sig[0].owner().clone(), rtype);
        iss.rrsigs.insert(key, sig);
    }
    Ok(())
}

fn sign_records(
    records: &[Zrd],
    keys: &[SigningKey<Bytes, KeyPair>],
    inception: Timestamp,
    expiration: Timestamp,
    new_sigs: &mut Vec<(Vec<Zrd>, Rtype)>,
) -> Result<(), Error> {
    let rtype = records[0].rtype();
    if rtype == Rtype::DNSKEY || rtype == Rtype::CDS || rtype == Rtype::CDNSKEY {
        // These records get signed with the KSK(s). Don't touch
        // the signatures.
        return Ok(());
    }

    let rrset = Rrset::new_from_owned(records).map_err(|e| format!("Rrset::new failed: {e}"))?;
    let mut rrsig_records = vec![];
    for key in keys {
        let rrsig = sign_rrset(key, &rrset, inception, expiration)
            .map_err(|e| format!("signing failed: {e}"))?;
        let record = Record::new(
            rrsig.owner().clone(),
            rrsig.class(),
            rrsig.ttl(),
            ZoneRecordData::Rrsig(rrsig.data().clone()),
        );
        rrsig_records.push(record);
    }
    new_sigs.push((rrsig_records, rrset.rtype()));
    Ok(())
}

//------------ ZonemdTuple ---------------------------------------------------

#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq, Hash, Serialize)]
struct ZonemdTuple(ZonemdScheme, ZonemdAlgorithm);

//------------ FileOrStdout --------------------------------------------------

enum FileOrStdout<T: io::Write, U: io::Write> {
    File(T),
    Stdout(Stream<U>),
}

impl<T: io::Write, U: io::Write> FileOrStdout<T, U> {
    fn flush(&mut self) -> Result<(), std::io::Error> {
        match self {
            FileOrStdout::File(f) => f.flush(),
            FileOrStdout::Stdout(s) => (s as &Stream<_>).flush(),
        }
    }
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
