use super::keyset::KeySetState;
use super::nsec3hash::Nsec3Hash;
use crate::env::{Env, Stream};
use crate::error::{Context, Error};
use crate::DISPLAY_KIND;
use bytes::{BufMut, Bytes};
use clap::builder::ValueParser;
use clap::Subcommand;
use core::clone::Clone;
use core::cmp::Ordering;
use core::fmt::Write;
use core::str::FromStr;
use domain::rdata::dnssec::RtypeBitmap;
use domain::rdata::Nsec;
use domain::dep::octseq::OctetsFrom;
use domain::base::iana::nsec3::Nsec3HashAlgorithm;
use domain::base::iana::zonemd::{ZonemdAlgorithm, ZonemdScheme};
use domain::base::iana::Class;
use domain::base::name::FlattenInto;
use domain::base::zonefile_fmt::{self, Formatter, ZonefileFmt};
use domain::base::{
    CanonicalOrd, Name, NameBuilder, Record, RecordData, Rtype, Serial, ToName, Ttl,
};
use domain::crypto::sign::{KeyPair, SecretKeyBytes};
use domain::dnssec::common::parse_from_bind;
use domain::dnssec::sign::denial::config::DenialConfig;
use domain::dnssec::sign::denial::nsec::GenerateNsecConfig;
use domain::dnssec::sign::denial::nsec3::{mk_hashed_nsec3_owner_name, GenerateNsec3Config};
use domain::dnssec::sign::error::SigningError;
use domain::dnssec::sign::keys::keyset::{KeyType, UnixTime};
use domain::dnssec::sign::keys::SigningKey;
use domain::dnssec::sign::records::{OwnerRrs, RecordsIter, Rrset, SortedRecords};
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
use jiff::tz::TimeZone;
use jiff::Timestamp as JiffTimestamp;
use jiff::Zoned;
use octseq::builder::with_infallible;
use rayon::slice::ParallelSliceMut;
use ring::digest;
use serde::{Deserialize, Serialize};
use std::io::stdout;
use std::collections::BTreeMap;
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display};
use std::fs::{metadata, File};
use std::io::Write as IoWrite;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::UNIX_EPOCH;
use tokio::time::Duration;
use tracing::warn;
use url::Url;

//------------ Constants -----------------------------------------------------

const FOUR_WEEKS: u64 = 2419200;
const TWO_WEEKS: u64 = 1209600;

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
        /// Hash only, don't sign.
        #[arg(long, action)]
        hash_only: bool,

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
}

#[derive(Default)]
struct SigningOptions {
    hash_only: bool,
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
                minimal_remaining_validity: Duration::from_secs(TWO_WEEKS),
                use_nsec3: false,
                algorithm: Nsec3HashAlgorithm::SHA1,
                iterations: 0,
                salt: Nsec3Salt::empty(),
                opt_out: false,
                zonemd: HashSet::new(),
                serial_policy: SerialPolicy::Keep,
                notify_command: Vec::new(),
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
        let mut sc: SignerConfig = serde_json::from_reader(file).map_err::<Error, _>(|e| {
            format!("error loading {:?}: {e}\n", self.signer_config).into()
        })?;

        let file = File::open(&sc.signer_state)
            .map_err(|e| format!("unable to open file {}: {e}", sc.signer_state.display()))?;
        let mut signer_state: SignerState =
            serde_json::from_reader(file).map_err::<Error, _>(|e| {
                format!("error loading {:?}: {e}\n", sc.signer_state).into()
            })?;

        let keyset_state_modified = Self::file_modified(sc.keyset_state.clone())?;
        let file = File::open(&sc.keyset_state)
            .map_err(|e| format!("unable to open file {}: {e}", sc.keyset_state.display()))?;
        let kss: KeySetState = serde_json::from_reader(file).map_err::<Error, _>(|e| {
            format!("error loading {:?}: {e}\n", sc.keyset_state).into()
        })?;

        let mut config_changed = false;
        let mut state_changed = false;
        let mut res = Ok(());

        match self.cmd {
            Commands::Create { .. } => unreachable!(),
            Commands::Sign {
                hash_only,
                extra_comments,
                preceed_zone_with_hash_list,
                order_nsec3_rrs_by_unhashed_owner_name,
                order_rrsigs_after_the_rtype_they_cover,
                use_yyyymmddhhmmss_rrsig_format,
            } => {
                let options = SigningOptions {
                    hash_only,
                    extra_comments,
                    preceed_zone_with_hash_list,
                    order_nsec3_rrs_by_unhashed_owner_name,
                    order_rrsigs_after_the_rtype_they_cover,
                    use_yyyymmddhhmmss_rrsig_format,
                };

                // Copy modified times to the state file. Do we need to be clever
                // and avoid updating the state file if modified times do not
                // change?
                signer_state.config_modified = signer_config_modified;
                signer_state.keyset_state_modified = keyset_state_modified;
                let zonefile_modified = Self::file_modified(sc.zonefile_in.clone())?;
                signer_state.zonefile_modified = zonefile_modified;
                state_changed = true;
                res = self.go_further(env, &sc, &mut signer_state, &kss, options)
            }
            Commands::Resign => {
		self.resign(&sc, &kss, env)
	    }
            Commands::Show => {
                todo!();
            }
            Commands::Cron => {
                // Simple automatic signer. Re-sign the zone when needed.
                // The zone needs to be signed when one or more of the three
                // input files has changed (signer config, keyset state or the
                // unsigned zone file.
                // The zone also needs to be signed when the remaining signature
                // lifetime is not long enough anymore.

                let mut need_resign = false;
                if signer_config_modified != signer_state.config_modified {
                    need_resign = true;
                }
                if keyset_state_modified != signer_state.keyset_state_modified {
                    need_resign = true;
                }
                let zonefile_modified = Self::file_modified(sc.zonefile_in.clone())?;
                if zonefile_modified != signer_state.zonefile_modified {
                    need_resign = true;
                }
                let now = UnixTime::now();
                if now + sc.minimal_remaining_validity > signer_state.minimum_expiration {
                    todo!();
                }
                if need_resign {
                    signer_state.config_modified = signer_config_modified;
                    signer_state.keyset_state_modified = keyset_state_modified;
                    let zonefile_modified = Self::file_modified(sc.zonefile_in.clone())?;
                    signer_state.zonefile_modified = zonefile_modified;
                    state_changed = true;
                    res = self.go_further(env, &sc, &mut signer_state, &kss, Default::default())
                }
            }
            Commands::Set { subcommand } => {
                set_command(subcommand, &mut sc, &mut config_changed, &env)?
            }
        }

        if config_changed {
            let json = serde_json::to_string_pretty(&sc).expect("should not fail");
            let mut file = File::create(&self.signer_config)
                .map_err(|e| format!("unable to create {}: {e}", self.signer_config.display()))?;
            write!(file, "{json}")
                .map_err(|e| format!("unable to write to {}: {e}", self.signer_config.display()))?;
        }
        if state_changed {
            let json = serde_json::to_string_pretty(&signer_state).expect("should not fail");
            let mut file = File::create(&sc.signer_state)
                .map_err(|e| format!("unable to create {}: {e}", sc.signer_state.display()))?;
            write!(file, "{json}")
                .map_err(|e| format!("unable to write to {}: {e}", sc.signer_state.display()))?;
        }
        res
    }

    #[allow(clippy::too_many_arguments)]
    fn go_further(
        &self,
        env: impl Env,
        sc: &SignerConfig,
        signer_state: &mut SignerState,
        kss: &KeySetState,
        options: SigningOptions,
    ) -> Result<(), Error> {
        let signing_mode = if options.hash_only {
            SigningMode::HashOnly
        } else {
            SigningMode::HashAndSign
        };

        // Read the zone file.
        let origin = kss.keyset.name().to_bytes();
        let mut records = self.load_zone(&env.in_cwd(&sc.zonefile_in), origin.clone())?;

        for r in &kss.dnskey_rrset {
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
        for r in &kss.cds_rrset {
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
        for (k, v) in kss.keyset.keys() {
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
        let out_file = sc.zonefile_out.clone();

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
        let zonemd: HashSet<ZonemdTuple> = HashSet::from_iter(sc.zonemd.clone());

        // implement SOA serial policies. There are four policies:
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

        // SAFETY: Already checked before this point.
        let zone_soa_rr = records.find_soa().unwrap();
        let ZoneRecordData::Soa(zone_soa) = zone_soa_rr.first().data() else {
            unreachable!();
        };

        match sc.serial_policy {
            SerialPolicy::Keep => {
                if let Some(previous_serial) = signer_state.previous_serial {
                    if zone_soa.serial() <= previous_serial {
                        return Err(
                            "Serial policy is Keep but upstream serial did not increase".into()
                        );
                    }
                }

                signer_state.previous_serial = Some(zone_soa.serial());
            }
            SerialPolicy::Increment => {
                let mut serial = zone_soa.serial();
                if let Some(previous_serial) = signer_state.previous_serial {
                    if serial <= previous_serial {
                        serial = previous_serial.add(1);

                        let new_soa = ZoneRecordData::Soa(Soa::new(
                            zone_soa.mname().clone(),
                            zone_soa.rname().clone(),
                            serial,
                            zone_soa.refresh(),
                            zone_soa.retry(),
                            zone_soa.expire(),
                            zone_soa.minimum(),
                        ));

                        records.update_data(|rr| rr.rtype() == Rtype::SOA, new_soa);
                    }
                }
                signer_state.previous_serial = Some(serial);
            }
            SerialPolicy::UnixSeconds => {
                let mut serial = Serial::now();
                if let Some(previous_serial) = signer_state.previous_serial {
                    if serial <= previous_serial {
                        serial = previous_serial.add(1);
                    }
                }

                let new_soa = ZoneRecordData::Soa(Soa::new(
                    zone_soa.mname().clone(),
                    zone_soa.rname().clone(),
                    serial,
                    zone_soa.refresh(),
                    zone_soa.retry(),
                    zone_soa.expire(),
                    zone_soa.minimum(),
                ));

                records.update_data(|rr| rr.rtype() == Rtype::SOA, new_soa);
                signer_state.previous_serial = Some(serial);
            }
            SerialPolicy::Date => {
                let ts = JiffTimestamp::now();
                let zone = Zoned::new(ts, TimeZone::UTC);
                let serial = ((zone.year() as u32 * 100 + zone.month() as u32) * 100
                    + zone.day() as u32)
                    * 100;
                let mut serial: Serial = serial.into();

                if let Some(previous_serial) = signer_state.previous_serial {
                    if serial <= previous_serial {
                        serial = previous_serial.add(1);
                    }
                }

                let new_soa = ZoneRecordData::Soa(Soa::new(
                    zone_soa.mname().clone(),
                    zone_soa.rname().clone(),
                    serial,
                    zone_soa.refresh(),
                    zone_soa.retry(),
                    zone_soa.expire(),
                    zone_soa.minimum(),
                ));

                records.update_data(|rr| rr.rtype() == Rtype::SOA, new_soa);
                signer_state.previous_serial = Some(serial);
            }
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

        if sc.use_nsec3 && (options.extra_comments || options.preceed_zone_with_hash_list) {
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
                    if sc.opt_out {
                        // Delegations are ignored for NSEC3. Ignore this
                        // entry but keep looking for other types at the
                        // same owner name.
                        prev_name = None;
                        continue;
                    }
                }

                let hashed_name =
                    mk_hashed_nsec3_owner_name(owner, sc.algorithm, sc.iterations, &sc.salt, &apex)
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
                        sc.algorithm,
                        sc.iterations,
                        &sc.salt,
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

        let now = TestableTimestamp::now();
        let inception = (now.into_int() - sc.inception_offset.as_secs() as u32).into();
        let expiration = (now.into_int() + sc.signature_lifetime.as_secs() as u32).into();

        let signing_config: SigningConfig<_, _> = match signing_mode {
            SigningMode::HashOnly | SigningMode::HashAndSign => {
                // LDNS doesn't add NSECs to a zone that already has NSECs or
                // NSEC3s. It *does* add NSEC3 if the zone has NSECs. As noted in
                // load_zone() we instead, as LDNS should, strip NSEC(3)s on load
                // and thus always add NSEC(3)s when hashing.
                //
                // Note: Assuming that we want to later be able to support
                // transition between NSEC <-> NSEC3 we will need to be able to
                // sign with more than one hashing configuration at once.
                if sc.use_nsec3 {
                    let params = Nsec3param::new(sc.algorithm, 0, sc.iterations, sc.salt.clone());
                    let mut nsec3_config = GenerateNsec3Config::new(params);
                    if sc.opt_out {
                        nsec3_config = nsec3_config.with_opt_out();
                    }
                    SigningConfig::new(DenialConfig::Nsec3(nsec3_config), inception, expiration)
                } else {
                    SigningConfig::new(
                        DenialConfig::Nsec(GenerateNsecConfig::new()),
                        inception,
                        expiration,
                    )
                }
            } /*
                          SigningMode::None => {
                              SigningConfig::new(DenialConfig::AlreadyPresent, inception, expiration)
                          }
              */
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

            if signing_mode == SigningMode::HashAndSign {
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
        }

        let now_ts = Timestamp::now();
        // Note that truncating the u64 from as_secs() to u32 is fine because
        // Timestamp is designed for this situation.
        let expire_ts: Timestamp = (Duration::from_secs(now_ts.into_int() as u64)
            .saturating_add(sc.signature_lifetime)
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
            UnixTime::now() + sc.signature_lifetime
        };
        signer_state.minimum_expiration = minimum_expiration;

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

        if !sc.notify_command.is_empty() {
            let output = Command::new(&sc.notify_command[0])
                .args(&sc.notify_command[1..])
                .output()
                .map_err(|e| {
                    format!(
                        "unable to create new Command for {}: {e}",
                        sc.notify_command[0]
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
        }

        Ok(())
    }

    fn resign(&self, sc: &SignerConfig, kss: &KeySetState, _env: impl Env) {
	let origin = kss.keyset.name();
	let origin_bytes = Name::<Bytes>::octets_from(origin.clone());
	let mut iss = IncrementalSigningState::new(origin_bytes);
	load_signed_zone(&mut iss, &sc.zonefile_out).unwrap();

	// Should check if the NSEC(3) mode has changed. Sign the full 
	// zone if that has happened.

	load_unsigned_zone(&mut iss, &sc.zonefile_in).unwrap();

	initial_diffs(&mut iss);

	// Should check whether to do NSEC, NSEC3, or NSEC3 opt-out. Just do
	// NSEC for now.
	incremental_nsec(&mut iss);

	let mut writer = stdout();
	for (_, data) in iss.new_data {
	    for rr in data {
		writer.write_fmt(format_args!("{}\n", rr.display_zonefile(DISPLAY_KIND)));
	    }
	}
	for (_, rr) in iss.nsecs {
	    writer.write_fmt(format_args!("{}\n", rr.display_zonefile(DISPLAY_KIND)));
	}
	for (_, data) in iss.rrsigs {
	    for rr in data {
		let ZoneRecordData::Rrsig(rrsig) = rr.data() else {
		    panic!("RRSIG expected");
		};
		let rr = Record::new(rr.owner(), rr.class(), rr.ttl(), YyyyMmDdHhMMSsRrsig(rrsig));
		writer.write_fmt(format_args!("{}\n", rr.display_zonefile(DISPLAY_KIND)));
	    }
	}
	todo!();
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

fn set_command(
    cmd: SetCommands,
    sc: &mut SignerConfig,
    config_changed: &mut bool,
    env: &impl Env,
) -> Result<(), Error> {
    match cmd {
        SetCommands::UseNsec3 { boolean } => {
            sc.use_nsec3 = boolean;
        }
        SetCommands::Algorithm { algorithm } => {
            sc.algorithm = algorithm;
        }
        SetCommands::Iterations { iterations } => {
            sc.iterations = iterations;
            match sc.iterations {
                500.. => Signer::write_extreme_iterations_warning(&env),
                1.. => Signer::write_non_zero_iterations_warning(&env),
                _ => { /* Good, nothing to warn about */ }
            }
        }
        SetCommands::Salt { salt } => {
            sc.salt = salt;
        }
        SetCommands::OptOut { boolean } => {
            sc.opt_out = boolean;
        }
        SetCommands::ZoneMD { zonemd } => {
            sc.zonemd = zonemd;
        }
        SetCommands::SerialPolicy { serial_policy } => {
            sc.serial_policy = serial_policy;
        }
        SetCommands::NotifyCommand { args } => {
            sc.notify_command = args;
        }
    }
    *config_changed = true;
    Ok(())
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
    minimal_remaining_validity: Duration,
    use_nsec3: bool,
    algorithm: Nsec3HashAlgorithm,
    iterations: u16,
    salt: Nsec3Salt<Bytes>,
    opt_out: bool,
    zonemd: HashSet<ZonemdTuple>,
    serial_policy: SerialPolicy,
    notify_command: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct SignerState {
    config_modified: UnixTime,
    keyset_state_modified: UnixTime,
    zonefile_modified: UnixTime,
    minimum_expiration: UnixTime,
    previous_serial: Option<Serial>,
}

type RtypeSet = HashSet<Rtype>;
type ChangesValue = (RtypeSet, RtypeSet); // add set followed by delete set.

struct IncrementalSigningState {
    origin: Name<Bytes>,
    old_data: HashMap<(Name<Bytes>, Rtype), Vec<ZRD>>,
    new_data: HashMap<(Name<Bytes>, Rtype), Vec<ZRD>>,
    nsecs: BTreeMap<Name<Bytes>, ZRD>,
    rrsigs: HashMap<(Name<Bytes>, Rtype), Vec<ZRD>>,

    changes: HashMap<Name<Bytes>, ChangesValue>,
    modified_nsecs: HashSet<Name<Bytes>>,
}

impl IncrementalSigningState {
    fn new(origin: Name<Bytes>) -> Self {
	Self {
	    origin,
	    old_data: HashMap::new(),
	    new_data: HashMap::new(),
	    nsecs: BTreeMap::new(),
	    rrsigs: HashMap::new(),
	    changes: HashMap::new(),
	    modified_nsecs: HashSet::new(),
       	}
    }
}

type ZRD = Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>;

fn load_signed_zone(iss: &mut IncrementalSigningState, path: &PathBuf, ) -> Result<(), Error> {
    // Don't use Zonefile::load() as it knows nothing about the size of
    // the original file so uses default allocation which allocates more
    // bytes than are needed. Instead control the allocation size based on
    // our knowledge of the file size.
    let mut zone_file = File::open(path)
	.map_err(|e| format!("open failed: {e}").into())
	.context(&format!(
	    "loading zone file from path '{}'",
	    path.display(),
	))?;
    let zone_file_len = zone_file
	.metadata()
	.map_err(|e| {
	    format!(
		"unable to get metadata from {}: {e}",
		path.display()
	    )
	})?
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
			if record.owner() == rrsig_records[0].owner() &&
			    rrsig.type_covered() == type_covered {
			    todo!();
			}

			let key = (rrsig_records[0].owner().clone(), type_covered);
			if let Some(v) = iss.rrsigs.get_mut(&key) {
			    v.append(&mut rrsig_records);
			} else
			{
			    iss.rrsigs.insert(key, rrsig_records);
			}
			type_covered = rrsig.type_covered();
			rrsig_records = vec![];
			rrsig_records.push(record);
		    }
		    ZoneRecordData::Nsec(_) => {
			// Assume (at most) one NSEC record per owner name.
			// Directly insert into the hash map.
			iss.nsecs.insert(record.owner().clone(), record);
		    }
		    ZoneRecordData::Nsec3(_) => todo!(),
		    _ => {
			if records.is_empty() {
			    records.push(record);
			    continue;
			}
			if record.owner() == records[0].owner() &&
			    record.rtype() == records[0].rtype() {
			    records.push(record);
			    continue;
			}
			let key = (records[0].owner().clone(), records[0].rtype());
			if let Some(v) = iss.old_data.get_mut(&key) {
			    v.append(&mut records);
			} else
			{
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
	} else
	{
	    iss.old_data.insert(key, records);
	}
    }
    if !rrsig_records.is_empty() {
	let key = (rrsig_records[0].owner().clone(), type_covered);
	if let Some(v) = iss.rrsigs.get_mut(&key) {
	    v.append(&mut rrsig_records);
	} else
	{
	    iss.rrsigs.insert(key, rrsig_records);
	}
    }
    Ok(())
}

fn load_unsigned_zone(iss: &mut IncrementalSigningState, path: &PathBuf, ) -> Result<(), Error> {
// Basically a copy of load_signed_zone execpt that signature and NSEC(3)
// records are removed. Make sure to delete and update APEX records.

    // Don't use Zonefile::load() as it knows nothing about the size of
    // the original file so uses default allocation which allocates more
    // bytes than are needed. Instead control the allocation size based on
    // our knowledge of the file size.
    let mut zone_file = File::open(path)
	.map_err(|e| format!("open failed: {e}").into())
	.context(&format!(
	    "loading zone file from path '{}'",
	    path.display(),
	))?;
    let zone_file_len = zone_file
	.metadata()
	.map_err(|e| {
	    format!(
		"unable to get metadata from {}: {e}",
		path.display()
	    )
	})?
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
		    ZoneRecordData::Rrsig(_) => (), // Ignore.
		    ZoneRecordData::Nsec(_) => (), // Ignore.
		    ZoneRecordData::Nsec3(_) => todo!(),
		    _ => {
			if records.is_empty() {
			    records.push(record);
			    continue;
			}
			if record.owner() == records[0].owner() &&
			    record.rtype() == records[0].rtype() {
			    records.push(record);
			    continue;
			}
			let key = (records[0].owner().clone(), records[0].rtype());
			if let Some(v) = iss.new_data.get_mut(&key) {
			    v.append(&mut records);
			} else
			{
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
	} else
	{
	    iss.new_data.insert(key, records);
	}
    }
    Ok(())
}

fn initial_diffs( iss: &mut IncrementalSigningState,) {
    for (_, new_rrset) in iss.new_data.iter_mut() {
println!("new rrset: {}/{}", new_rrset[0].owner(), new_rrset[0].rtype());
//dbg!(&new_rrset);
	let key = (new_rrset[0].owner().clone(), new_rrset[0].rtype());
	if let Some(mut old_rrset) = iss.old_data.remove(&key) {
//dbg!(&old_rrset);
	    old_rrset.sort_by(|a, b| {
		a.as_ref().data().canonical_cmp(b.as_ref().data())
	    });
	    new_rrset.sort_by(|a, b| {
		a.as_ref().data().canonical_cmp(b.as_ref().data())
	    });

	    if *old_rrset != *new_rrset {
		if iss.rrsigs.remove(&key).is_some() {
		    println!("modified, should resign {}/{}",
			new_rrset[0].owner(), new_rrset[0].rtype());
		}
	
	    } else {
	    }
	}
	else {
	    if let Some((added, _)) = iss.changes.get_mut(&key.0) {
		added.insert(new_rrset[0].rtype());
	    } else {
		let mut added = HashSet::new();
		let removed = HashSet::new();
		added.insert(new_rrset[0].rtype());
		iss.changes.insert(key.0, (added, removed));
	    }
	}
    }
    for (_, old_rrset) in &iss.old_data {
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
}

fn incremental_nsec( iss: &mut IncrementalSigningState,) {
    // Should changes be sorted or not? If changes is sorted we will 
    // process a new delegation before any glue. Which is more efficient.
    // Otherwise if glue comes first, the glue will be signed and inserted
    // in the NSEC chain only to be removed when the delegation is processed.
    // However, we removing a delegation, the situation is reversed. For now
    // assuming that sorting is not necessary.
    let changes = iss.changes.clone();
    for (key, (add, delete)) in &changes {
	dbg!(key);
	dbg!(add);
	dbg!(delete);
	if let Some(nsec) = iss.nsecs.get(key) {
	    println!("should handle existing name, nsec {nsec:?}");
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
		nsec_set_occluded(key);

		// Create a new NSEC record and sign only DS records (if any).
		let mut rtypebitmap = RtypeBitmap::<Bytes>::builder();
		rtypebitmap.add(Rtype::NSEC).expect("should not fail");
		rtypebitmap.add(Rtype::RRSIG).expect("should not fail");
		for rtype in add {
		    rtypebitmap.add(*rtype).expect("should not fail");
		}
		let rtypebitmap = rtypebitmap.finalize();
		nsec_insert(key, rtypebitmap, iss);
		if add.contains(&Rtype::DS) {
		    let mut ds_set = HashSet::new();
		    ds_set.insert(Rtype::DS);
		    sign_rtype_set(key, &ds_set, iss);
		}
		continue;
	    }
	    // Create a new NSEC record and sign all records.
	    let mut rtypebitmap = RtypeBitmap::<Bytes>::builder();
	    rtypebitmap.add(Rtype::NSEC).expect("should not fail");
	    rtypebitmap.add(Rtype::RRSIG).expect("should not fail");
	    for rtype in add {
		rtypebitmap.add(*rtype).expect("should not fail");
	    }
	    let rtypebitmap = rtypebitmap.finalize();
	    nsec_insert(key, rtypebitmap, iss);
	    sign_rtype_set(key, add, iss);
	}
    }
}

fn nsec_insert(name: &Name<Bytes>, rtypebitmap: RtypeBitmap<Bytes>, iss: &mut IncrementalSigningState) {
    dbg!(&rtypebitmap);
    dbg!(name);

    // Try to find the NSEC record that comes before the one we are trying
    // to insert. Assume that the APEX NSEC will always exist can sort 
    // before anything else.
    let mut range = iss.nsecs.range::<Name<_>, _>(..name);
    let (previous_name, previous_record) = range.next_back().expect("previous NSEC record should exist");
    let previous_name = previous_name.clone();
    let previous_record = previous_record.clone();
    drop(range);
    dbg!(&previous_name);
    dbg!(&previous_record);
    let ZoneRecordData::Nsec(previous_nsec) = previous_record.data() else {
	panic!("NSEC record expected");
    };
    dbg!(previous_nsec);
    let next = previous_nsec.next_name();
    let new_nsec = Nsec::new(next.clone(), rtypebitmap);
    let new_record = Record::new(name.clone(), previous_record.class(),
	previous_record.ttl(), ZoneRecordData::Nsec(new_nsec));
    dbg!(&new_record);
    iss.nsecs.insert(name.clone(), new_record);
    iss.modified_nsecs.insert(name.clone());
    let previous_nsec = Nsec::new(name.clone(), previous_nsec.types().clone());
    let previous_record = Record::new(previous_name.clone(), previous_record.class(),
	previous_record.ttl(), ZoneRecordData::Nsec(previous_nsec));
    iss.nsecs.insert(previous_name.clone(), previous_record);
    iss.modified_nsecs.insert(previous_name.clone());
}

fn nsec_set_occluded(name: &Name<Bytes>) {
    println!("Should implement nsec_set_occluded");
}

fn is_occluded(name: &Name<Bytes>, iss: &IncrementalSigningState) -> bool {
    // We need to check if the parent of name is a delegation. Stop
    // when we reached origin.
    let Some(mut curr) = name.parent() else {
	// We asked for the parent of the root. That is weird. Just
	// return no occluded.
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
	if iss.new_data.get(&(curr.clone(), Rtype::NS)).is_some() {
	    // Name is occluded.
	    return true;
	}
	let Some(parent) = curr.parent() else {
	    // We asked for the parent of the root. That is weird. Just
	    // return no occluded.
	    return false;
	};
	curr = parent;
    }
}

fn sign_rtype_set(name: &Name<Bytes>, set: &HashSet<Rtype>, iss: &mut IncrementalSigningState) {
    for rtype in set {
	let key = (name.clone(), rtype.clone());
	let Some(records) = iss.new_data.get(&key) else {
	    panic!("Expected something for {}/{}", name, rtype);
	};
	println!("Should sign {records:?}");
    }
}

//------------ SigningMode ---------------------------------------------------

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum SigningMode {
    /// Both hash (NSEC/NSEC3) and sign zone records.
    #[default]
    HashAndSign,

    /// Only hash (NSEC/NSEC3) zone records, don't sign them.
    HashOnly,
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
