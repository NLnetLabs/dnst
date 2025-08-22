//! Key management utility.
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use crate::env::Env;
use crate::error::Error;
use crate::util;
use bytes::Bytes;
use clap::Subcommand;
use domain::base::iana::{Class, DigestAlgorithm, OptRcode, SecurityAlgorithm};
use domain::base::name::FlattenInto;
use domain::base::zonefile_fmt::{DisplayKind, ZonefileFmt};
use domain::base::{
    MessageBuilder, Name, ParseRecordData, ParsedName, Record, Rtype, Serial, ToName, Ttl,
};
use domain::crypto::sign::{self, GenerateParams, KeyPair, SecretKeyBytes};
use domain::dnssec::common::{display_as_bind, parse_from_bind};
use domain::dnssec::sign::keys::keyset::{
    self, Action, Key, KeySet, KeyState, KeyType, RollState, RollType, UnixTime,
};
use domain::dnssec::sign::keys::SigningKey;
use domain::dnssec::sign::records::Rrset;
use domain::dnssec::sign::signatures::rrsigs::sign_rrset;
use domain::dnssec::validator::base::DnskeyExt;
use domain::net::client::dgram_stream;
use domain::net::client::protocol::{TcpConnect, UdpConnect};
use domain::net::client::request::{
    ComposeRequest, RequestMessage, RequestMessageMulti, SendRequest, SendRequestMulti,
};
use domain::net::client::stream;
use domain::rdata::dnssec::Timestamp;
use domain::rdata::{AllRecordData, Cdnskey, Cds, Dnskey, Ds, Rrsig, Soa, ZoneRecordData};
use domain::resolv::lookup::lookup_host;
use domain::resolv::StubResolver;
use domain::zonefile::inplace::{Entry, ScannedRecordData, Zonefile};
use futures::future::join_all;
use jiff::{Span, SpanRelativeTo};
use serde::{Deserialize, Serialize};
use std::cmp::max;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::fs::{remove_file, File};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{absolute, Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tracing::{debug, error, warn};
use url::Url;

/// Maximum tries to generate new key with a key tag that does not conclict
/// with the key tags of existing keys.
const MAX_KEY_TAG_TRIES: u8 = 10;

/// Wait this amount before retrying for network errors, DNS errors, etc.
const DEFAULT_WAIT: Duration = Duration::from_secs(10 * 60);

// Types to simplify some HashSet types.
/// Type for a Name that uses a Vec.
type NameVecU8 = Name<Vec<u8>>;
/// Type for a record that uses ZoneRecordData and a Vec.
type RecordZoneRecordData = Record<NameVecU8, ZoneRecordData<Vec<u8>, NameVecU8>>;
/// Type for a DNSKEY record.
type RecordDnskey = Record<NameVecU8, Dnskey<Vec<u8>>>;

// Automatic key rolls
//
// Keyset supports four types of automatic key rolls:
// 1) A KSK roll. Roll one (or more) KSKs to a new KSK.
// 2) A ZSK roll. Roll one (or more) ZSKs to a new ZSK.
// 3) A CSK roll. Roll any KSK, ZSK, or CSK to a single new CSK or roll
//    one (or more CSKs) plus any KSK or ZSK to a new KSK plus a new ZSK.
//    This depends on the value of the use_csk config variable.
// 4) An algorithm roll. Roll any KSK, ZSK, or CSK to a new CSK (if use_csk
//    is true) or to a new KSK and a new ZSK (if use_csk is false) with an
//    algorithm that is different from the one in the old keys.
//
// For each roll type automation can be enable for four different types of
// steps:
// 1) Start. When automation is enabled for this step, keyset checks if keys
//    are expired, no conflicting rolls are currently in progress and no
//    conditions (use of CSK, the need for a algorithm roll) prevents this
//    type of roll.
// 2) Report. In the complete key roll, these are two steps:
//    propagation1_complete and propagation2_complete. When automation is
//    enabled, keyset goes through the list of actions and takes care of
//    the Report actions (ReportDnskeyPropagated, ReportDsPropagated,
//    ReportRrsigPropagated). Keyset checks nameservers for the zone
//    (or the parent zone in the case of ReportDsPropagated) to make sure
//    that new information has propagated to all listed nameservers.
//    The maximum TTL is passed to Keyset::propagation1_complete (or
//    Keyset::propagation2_complete).
// 3) Expire. This corresponds to the steps cache_expired1 and
//    cache_expired2. When enabled, this step wait until time equal to the
//    TTL amount that was reported in propagation1_complete or
//    propagation2_complete to have passed before continuing to the next step.
// 4) Done. When enabled this step takes care of any Wait actions
//    (WaitDnskeyPropagated, WaitDsPropagated, WaitRrsigPropagated). This
//    is very similar to the Report step except no TTL value is reported.
//    After this step, the key roll is considered done though some old date
//    may still exist in caches.
//
//  For each key roll type, automation for each step can be enabled or disabled
//  individually. This give a total of sixteen flags.
//
//  The function auto_start handles the Start step. The other steps are
//  handled by auto_report_expire_done. The current state for automatic report
//  and done handling is kept in a field called 'internal' in the KeySetState
//  structure.
//
//  At every change to the config or the state file, the next time
//  'dnst keyset cron' should be called is computed and stored in the
//  state file. The function cron_next_auto_start provides timestamps for
//  automatic start of key rolls, cron_next_auto_report_expire_done does
//  the same for the report, expire, and done steps.

/// Command line arguments of the keyset utility.
#[derive(Clone, Debug, clap::Args)]
pub struct Keyset {
    /// Keyset config
    #[arg(short = 'c')]
    keyset_conf: PathBuf,

    /// Subcommand
    #[command(subcommand)]
    cmd: Commands,
}

/// Type for an optional Duration. A separate type is needed because CLAP
/// treats Option<T> special.
type OptDuration = Option<Duration>;

/// The subcommands of the keyset utility.
#[derive(Clone, Debug, Subcommand)]
enum Commands {
    /// Create empty state for a DNS zone. This will create both the config
    /// file as well as the state file.
    Create {
        /// Domain name
        #[arg(short = 'n')]
        domain_name: Name<Vec<u8>>,

        /// State file
        #[arg(short = 's')]
        keyset_state: PathBuf,
    },

    /// Init creates keys for an empty state file.
    Init,

    /// The following should be move to ksk, zsk, etc. subcommands.
    StartKskRoll,
    /// XXX
    StartZskRoll,
    /// XXX
    StartCskRoll,
    /// XXX
    StartAlgorithmRoll,
    /// XXX
    KskPropagation1Complete {
        /// XXX
        ttl: u32,
    },
    /// XXX
    KskPropagation2Complete {
        /// XXX
        ttl: u32,
    },
    /// XXX
    ZskPropagation1Complete {
        /// XXX
        ttl: u32,
    },
    /// XXX
    ZskPropagation2Complete {
        /// XXX
        ttl: u32,
    },
    /// XXX
    CskPropagation1Complete {
        /// XXX
        ttl: u32,
    },
    /// XXX
    CskPropagation2Complete {
        /// XXX
        ttl: u32,
    },
    /// XXX
    AlgorithmPropagation1Complete {
        /// XXX
        ttl: u32,
    },
    /// XXX
    AlgorithmPropagation2Complete {
        /// XXX
        ttl: u32,
    },
    /// XXX
    KskCacheExpired1,
    /// XXX
    KskCacheExpired2,
    /// XXX
    ZskCacheExpired1,
    /// XXX
    ZskCacheExpired2,
    /// XXX
    CskCacheExpired1,
    /// XXX
    CskCacheExpired2,
    /// XXX
    AlgorithmCacheExpired1,
    /// XXX
    AlgorithmCacheExpired2,
    /// XXX
    KskRollDone,
    /// XXX
    ZskRollDone,
    /// XXX
    CskRollDone,
    /// XXX
    AlgorithmRollDone,
    /// Report status, such as key rolls that are in progress, expired
    /// keys, when to call the 'cron' subcommand next.
    Status,
    /// Report actions that are associated with the current state of
    /// any key rolls.
    Actions,
    /// List all keys in the current state.
    Keys,

    /// Get various config and state values.
    Get {
        /// The specific get subcommand.
        #[command(subcommand)]
        subcommand: GetCommands,
    },

    /// Set config values.
    Set {
        /// The specific set subcommand.
        #[command(subcommand)]
        subcommand: SetCommands,
    },

    /// Show all config variables.
    Show,

    /// Execute any automatic steps such a refreshing signatures or
    /// automatic steps in key rolls.
    Cron,
}

#[derive(Clone, Debug, Subcommand)]
enum GetCommands {
    /// Get the state of the use_csk config variable.
    UseCsk,
    /// Get the state of the autoremove config variable.
    Autoremove,
    /// Get the state of the algorithm config variable.
    Algorithm,
    /// Get the state of the ds_algorithm config variable.
    DsAlgorithm,
    /// Get the state of the dnskey_lifetime config variable.
    DnskeyLifetime,
    /// Get the state of the cds_lifetime config variable.
    CdsLifetime,
    /// Get the current DNSKEY RRset including signatures.
    Dnskey,
    /// Get the current CDS and CDNSKEY RRsets including signatures.
    Cds,
    /// Get the current DS records that canbe added to the parent zone.
    Ds,
}

#[derive(Clone, Debug, Subcommand)]
enum SetCommands {
    /// Set the use_csk config variable.
    UseCsk {
        /// The value of the config variable.
        #[arg(action = clap::ArgAction::Set)]
        boolean: bool,
    },
    /// Set the autoremove config variable.
    Autoremove {
        /// The value of the config variable.
        #[arg(action = clap::ArgAction::Set)]
        boolean: bool,
    },
    /// Set the algorithm config variable.
    Algorithm {
        /// The number of bits of a new RSA key. At the moment RSA is the
        /// only public key algorithm that needs a bits argument.
        #[arg(short = 'b')]
        bits: Option<usize>,

        /// The algorithm to use for new keys.
        algorithm: String,
    },

    /// Set the config values for automatic KSK rolls.
    AutoKsk {
        /// Whether to automatically start a key roll.
        #[arg(action = clap::ArgAction::Set)]
        start: bool,
        /// Whether to automatically handle report actions.
        #[arg(action = clap::ArgAction::Set)]
        report: bool,
        /// Whether to automatically handle cache expiration actions.
        #[arg(action = clap::ArgAction::Set)]
        expire: bool,
        /// Whether to automatically handle done actions.
        #[arg(action = clap::ArgAction::Set)]
        done: bool,
    },
    /// Set the config values for automatic ZSK rolls.
    AutoZsk {
        /// Whether to automatically start a key roll.
        #[arg(action = clap::ArgAction::Set)]
        start: bool,
        /// Whether to automatically handle report actions.
        #[arg(action = clap::ArgAction::Set)]
        report: bool,
        /// Whether to automatically handle cache expiration actions.
        #[arg(action = clap::ArgAction::Set)]
        expire: bool,
        /// Whether to automatically handle done actions.
        #[arg(action = clap::ArgAction::Set)]
        done: bool,
    },
    /// Set the config values for automatic CSK rolls.
    AutoCsk {
        /// Whether to automatically start a key roll.
        #[arg(action = clap::ArgAction::Set)]
        start: bool,
        /// Whether to automatically handle report actions.
        #[arg(action = clap::ArgAction::Set)]
        report: bool,
        /// Whether to automatically handle cache expiration actions.
        #[arg(action = clap::ArgAction::Set)]
        expire: bool,
        /// Whether to automatically handle done actions.
        #[arg(action = clap::ArgAction::Set)]
        done: bool,
    },
    /// Set the config values for automatic algorithm rolls.
    AutoAlgorithm {
        /// Whether to automatically start a key roll.
        #[arg(action = clap::ArgAction::Set)]
        start: bool,
        /// Whether to automatically handle report actions.
        #[arg(action = clap::ArgAction::Set)]
        report: bool,
        /// Whether to automatically handle cache expiration actions.
        #[arg(action = clap::ArgAction::Set)]
        expire: bool,
        /// Whether to automatically handle done actions.
        #[arg(action = clap::ArgAction::Set)]
        done: bool,
    },
    /// Set the hash algorithm to use for creating DS records.
    DsAlgorithm {
        /// The hash algorithm.
        #[arg(value_parser = DsAlgorithm::new)]
        algorithm: DsAlgorithm,
    },
    /// Set the amount inception times of signatures over the DNSKEY RRset
    /// are backdated.
    ///
    /// Note that positive values are subtract from the current time.
    DnskeyInceptionOffset {
        /// The offset.
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    /// Set how much time the expiration times of signatures over the DNSKEY
    /// RRset are in the future.
    DnskeyLifetime {
        /// The lifetime.
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    /// Set how much time the DNSKEY signatures still have to be valid.
    ///
    /// New signatures will be generated when the time until the expiration
    /// time is less than that.
    DnskeyRemainTime {
        /// The required remaining time.
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    /// Set the amount inception times of signatures over the CDS and
    /// CDNSKEY  RRsets are backdated.
    ///
    /// Note that positive values are subtract from the current time.
    CdsInceptionOffset {
        /// The offset.
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    /// Set how much time the expiration times of signatures over the CDS
    /// and CDNSKEY RRsets are in the future.
    CdsLifetime {
        /// The lifetime.
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    /// Set how much time the CDS/CDNSKEY signatures still have to be valid.
    ///
    /// New signatures will be generated when the time until the expiration
    /// time is less than that.
    CdsRemainTime {
        /// The required remaining time.
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    /// How long a KSK is valid from the time it was first 'published'.
    KskValidity {
        /// The amount of time the key is valid.
        #[arg(value_parser = parse_opt_duration)]
        opt_duration: OptDuration,
    },
    /// How long a ZSK is valid from the time it was first 'published'.
    ZskValidity {
        /// The amount of time the key is valid.
        #[arg(value_parser = parse_opt_duration)]
        opt_duration: OptDuration,
    },
    /// How long a CSK is valid from the time it was first 'published'.
    CskValidity {
        /// The amount of time the key is valid.
        #[arg(value_parser = parse_opt_duration)]
        opt_duration: OptDuration,
    },
}

impl Keyset {
    /// execute the keyset command.
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        let runtime =
            tokio::runtime::Runtime::new().expect("tokio::runtime::Runtime::new should not fail");
        runtime.block_on(self.run(&env))
    }

    /// Run the command as an async function
    pub async fn run(self, env: &impl Env) -> Result<(), Error> {
        if let Commands::Create {
            domain_name,
            keyset_state,
        } = self.cmd
        {
            let state_file = absolute(&keyset_state).map_err::<Error, _>(|e| {
                format!("unable to make {} absolute: {}", keyset_state.display(), e).into()
            })?;
            let keys_dir = make_parent_dir(state_file.clone());

            let ks = KeySet::new(domain_name);
            let kss = KeySetState {
                keyset: ks,
                dnskey_rrset: Vec::new(),
                ds_rrset: Vec::new(),
                cds_rrset: Vec::new(),
                ns_rrset: Vec::new(),
                cron_next: None,
                internal: HashMap::new(),
            };
            const ONE_DAY: u64 = 86400;
            const FOUR_WEEKS: u64 = 2419200;
            let ksc = KeySetConfig {
                state_file: state_file.clone(),
                keys_dir,
                use_csk: false,
                algorithm: KeyParameters::EcdsaP256Sha256,
                ksk_validity: None,
                zsk_validity: None,
                csk_validity: None,
                auto_ksk: { Default::default() },
                auto_zsk: { Default::default() },
                auto_csk: { Default::default() },
                auto_algorithm: { Default::default() },
                dnskey_inception_offset: Duration::from_secs(ONE_DAY),
                dnskey_signature_lifetime: Duration::from_secs(FOUR_WEEKS),
                dnskey_remain_time: Duration::from_secs(FOUR_WEEKS / 2),
                cds_inception_offset: Duration::from_secs(ONE_DAY),
                cds_signature_lifetime: Duration::from_secs(FOUR_WEEKS),
                cds_remain_time: Duration::from_secs(FOUR_WEEKS / 2),
                ds_algorithm: DsAlgorithm::Sha256,
                autoremove: false,
            };
            let json = serde_json::to_string_pretty(&kss).expect("should not fail");
            let mut file = File::create(&state_file).map_err::<Error, _>(|e| {
                format!("unable to create file {}: {e}", state_file.display()).into()
            })?;
            write!(file, "{json}").map_err::<Error, _>(|e| {
                format!("unable to write to file {}: {e}", state_file.display()).into()
            })?;

            let json = serde_json::to_string_pretty(&ksc).expect("should not fail");
            let mut file = File::create(&self.keyset_conf).map_err::<Error, _>(|e| {
                format!("unable to create file {}: {e}", self.keyset_conf.display()).into()
            })?;
            write!(file, "{json}").map_err::<Error, _>(|e| {
                format!(
                    "unable to write to file {}: {e}",
                    self.keyset_conf.display()
                )
                .into()
            })?;
            return Ok(());
        }

        let file = File::open(self.keyset_conf.clone()).map_err::<Error, _>(|e| {
            format!(
                "unable to open config file {}: {e}",
                self.keyset_conf.display()
            )
            .into()
        })?;
        let mut ksc: KeySetConfig = serde_json::from_reader(file).map_err::<Error, _>(|e| {
            format!("error loading {:?}: {e}\n", self.keyset_conf).into()
        })?;
        let file = File::open(ksc.state_file.clone()).map_err::<Error, _>(|e| {
            format!(
                "unable to open state file {}: {e}",
                ksc.state_file.display()
            )
            .into()
        })?;
        let mut kss: KeySetState = serde_json::from_reader(file)
            .map_err::<Error, _>(|e| format!("error loading {:?}: {e}\n", ksc.state_file).into())?;

        let mut config_changed = false;
        let mut state_changed = false;

        match self.cmd {
            Commands::Create { .. } => unreachable!(),
            Commands::Init => {
                // Check for re-init.
                if !kss.keyset.keys().is_empty() {
                    // Avoid re-init.
                    return Err("already initialized\n".into());
                }

                // XXX create common function for new CSK keys.

                // Check for CSK.
                let actions = if ksc.use_csk {
                    // Generate CSK.
                    let (csk_pub_name, csk_priv_name, algorithm, key_tag) = new_keys(
                        kss.keyset.name(),
                        ksc.algorithm.to_generate_params(),
                        true,
                        kss.keyset.keys(),
                        &ksc.keys_dir,
                        env,
                    )?;
                    kss.keyset
                        .add_key_csk(
                            csk_pub_name.to_string(),
                            Some(csk_priv_name.to_string()),
                            algorithm,
                            key_tag,
                            UnixTime::now(),
                            true,
                        )
                        .expect("should not happen");

                    kss.keyset
                        .start_roll(RollType::AlgorithmRoll, &[], &[csk_pub_name.as_str()])
                        .expect("should not happen")
                } else {
                    let (ksk_pub_url, ksk_priv_url, algorithm, key_tag) = new_keys(
                        kss.keyset.name(),
                        ksc.algorithm.to_generate_params(),
                        true,
                        kss.keyset.keys(),
                        &ksc.keys_dir,
                        env,
                    )?;
                    kss.keyset
                        .add_key_ksk(
                            ksk_pub_url.to_string(),
                            Some(ksk_priv_url.to_string()),
                            algorithm,
                            key_tag,
                            UnixTime::now(),
                            true,
                        )
                        .expect("should not happen");
                    let (zsk_pub_url, zsk_priv_url, algorithm, key_tag) = new_keys(
                        kss.keyset.name(),
                        ksc.algorithm.to_generate_params(),
                        false,
                        kss.keyset.keys(),
                        &ksc.keys_dir,
                        env,
                    )?;
                    kss.keyset
                        .add_key_zsk(
                            zsk_pub_url.to_string(),
                            Some(zsk_priv_url.to_string()),
                            algorithm,
                            key_tag,
                            UnixTime::now(),
                            true,
                        )
                        .expect("should not happen");

                    let new = [ksk_pub_url.as_ref(), zsk_pub_url.as_ref()];
                    kss.keyset
                        .start_roll(RollType::AlgorithmRoll, &[], &new)
                        .expect("should not happen")
                };

                handle_actions(&actions, &ksc, &mut kss, env)?;
                kss.internal
                    .insert(RollType::AlgorithmRoll, Default::default());

                print_actions(&actions);
                state_changed = true;
            }
            Commands::StartKskRoll => {
                let actions = start_ksk_roll(&ksc, &mut kss, env)?;

                print_actions(&actions);
                state_changed = true;
            }
            Commands::StartZskRoll => {
                let actions = start_zsk_roll(&ksc, &mut kss, env)?;

                print_actions(&actions);
                state_changed = true;
            }
            Commands::StartCskRoll => {
                let actions = start_csk_roll(&ksc, &mut kss, env)?;

                print_actions(&actions);
                state_changed = true;
            }
            Commands::StartAlgorithmRoll => {
                let actions = start_algorithm_roll(&ksc, &mut kss, env)?;

                print_actions(&actions);
                state_changed = true;
            }
            Commands::KskPropagation1Complete { ttl }
            | Commands::KskPropagation2Complete { ttl }
            | Commands::ZskPropagation1Complete { ttl }
            | Commands::ZskPropagation2Complete { ttl }
            | Commands::CskPropagation1Complete { ttl }
            | Commands::CskPropagation2Complete { ttl }
            | Commands::AlgorithmPropagation1Complete { ttl }
            | Commands::AlgorithmPropagation2Complete { ttl } => {
                let actions = match self.cmd {
                    Commands::KskPropagation1Complete { ttl: _ } => {
                        kss.keyset.propagation1_complete(RollType::KskRoll, ttl)
                    }
                    Commands::KskPropagation2Complete { ttl: _ } => {
                        kss.keyset.propagation2_complete(RollType::KskRoll, ttl)
                    }
                    Commands::ZskPropagation1Complete { ttl: _ } => {
                        kss.keyset.propagation1_complete(RollType::ZskRoll, ttl)
                    }
                    Commands::ZskPropagation2Complete { ttl: _ } => {
                        kss.keyset.propagation2_complete(RollType::ZskRoll, ttl)
                    }
                    Commands::CskPropagation1Complete { ttl: _ } => {
                        kss.keyset.propagation1_complete(RollType::CskRoll, ttl)
                    }
                    Commands::CskPropagation2Complete { ttl: _ } => {
                        kss.keyset.propagation2_complete(RollType::CskRoll, ttl)
                    }
                    Commands::AlgorithmPropagation1Complete { ttl: _ } => kss
                        .keyset
                        .propagation1_complete(RollType::AlgorithmRoll, ttl),
                    Commands::AlgorithmPropagation2Complete { ttl: _ } => kss
                        .keyset
                        .propagation2_complete(RollType::AlgorithmRoll, ttl),
                    _ => unreachable!(),
                };

                let actions = match actions {
                    Ok(actions) => actions,
                    Err(err) => {
                        return Err(format!("Error reporting propagation complete: {err}\n").into());
                    }
                };

                // Handle error

                handle_actions(&actions, &ksc, &mut kss, env)?;

                // Report actions
                print_actions(&actions);
                state_changed = true;
            }
            Commands::KskCacheExpired1
            | Commands::KskCacheExpired2
            | Commands::ZskCacheExpired1
            | Commands::ZskCacheExpired2
            | Commands::CskCacheExpired1
            | Commands::CskCacheExpired2
            | Commands::AlgorithmCacheExpired1
            | Commands::AlgorithmCacheExpired2 => {
                let actions = match self.cmd {
                    Commands::KskCacheExpired1 => kss.keyset.cache_expired1(RollType::KskRoll),
                    Commands::KskCacheExpired2 => kss.keyset.cache_expired2(RollType::KskRoll),
                    Commands::ZskCacheExpired1 => kss.keyset.cache_expired1(RollType::ZskRoll),
                    Commands::ZskCacheExpired2 => kss.keyset.cache_expired2(RollType::ZskRoll),
                    Commands::CskCacheExpired1 => kss.keyset.cache_expired1(RollType::CskRoll),
                    Commands::CskCacheExpired2 => kss.keyset.cache_expired2(RollType::CskRoll),
                    Commands::AlgorithmCacheExpired1 => {
                        kss.keyset.cache_expired1(RollType::AlgorithmRoll)
                    }
                    Commands::AlgorithmCacheExpired2 => {
                        kss.keyset.cache_expired2(RollType::AlgorithmRoll)
                    }
                    _ => unreachable!(),
                };

                let actions = match actions {
                    Ok(actions) => actions,
                    Err(err) => {
                        return Err(format!("Error reporting cache expired: {err}\n").into());
                    }
                };

                // Handle error

                handle_actions(&actions, &ksc, &mut kss, env)?;

                // Report actions
                print_actions(&actions);
                state_changed = true;
            }
            Commands::KskRollDone
            | Commands::ZskRollDone
            | Commands::CskRollDone
            | Commands::AlgorithmRollDone => {
                let r = match self.cmd {
                    Commands::KskRollDone => RollType::KskRoll,
                    Commands::ZskRollDone => RollType::ZskRoll,
                    Commands::CskRollDone => RollType::CskRoll,
                    Commands::AlgorithmRollDone => RollType::AlgorithmRoll,
                    _ => unreachable!(),
                };
                do_done(&mut kss, r, ksc.autoremove)?;
                state_changed = true;
            }
            Commands::Status => {
                for (roll, state) in kss.keyset.rollstates().iter() {
                    println!("{roll:?}: {state:?}");
                }
                if sig_renew(&kss.dnskey_rrset, &ksc.dnskey_remain_time) {
                    println!("DNSKEY RRSIG(s) need to be renewed");
                }
                if sig_renew(&kss.cds_rrset, &ksc.cds_remain_time) {
                    println!("CDS/CDNSKEY RRSIG(s) need to be renewed");
                }

                // Check for expired keys.
                for (pubref, k) in kss.keyset.keys() {
                    let (expired, label) = key_expired(k, &ksc);
                    if expired {
                        println!("{label} {pubref} has expired");
                    }
                }
                if let Some(cron_next) = &kss.cron_next {
                    println!("Next time to run the 'cron' subcommand {cron_next}");
                }
            }
            Commands::Actions => {
                for roll in kss.keyset.rollstates().keys() {
                    let actions = kss.keyset.actions(*roll);
                    println!("{roll:?} actions:");
                    for a in actions {
                        println!("\t{a:?}");
                    }
                }
            }
            Commands::Keys => {
                println!("Keys:");
                let mut keys: Vec<_> = kss.keyset.keys().iter().collect();
                keys.sort_by(|(pubref1, key1), (pubref2, key2)| {
                    (key1.timestamps().creation(), pubref1)
                        .cmp(&(key2.timestamps().creation(), pubref2))
                });
                for (pubref, key) in keys {
                    println!("\t{} {}", pubref, key.privref().unwrap_or_default(),);
                    let (keytype, state, opt_state) = match key.keytype() {
                        KeyType::Ksk(keystate) => ("KSK", keystate, None),
                        KeyType::Zsk(keystate) => ("ZSK", keystate, None),
                        KeyType::Include(keystate) => ("Include", keystate, None),
                        KeyType::Csk(keystate_ksk, keystate_zsk) => {
                            ("CSK", keystate_ksk, Some(keystate_zsk))
                        }
                    };
                    println!(
                        "\t\tType: {keytype}, algorithm: {}, key tag: {}",
                        key.algorithm(),
                        key.key_tag()
                    );
                    if let Some(zskstate) = opt_state {
                        println!("\t\tKSK role state: {state}");
                        println!("\t\tZSK role state: {zskstate}");
                    } else {
                        println!("\t\tState: {state}");
                    }
                    let ts = key.timestamps();
                    println!(
                        "\t\tCreated: {}",
                        ts.creation()
                            .map_or("<empty>".to_string(), |x| x.to_string()),
                    );
                    println!(
                        "\t\tPublished: {}",
                        ts.published()
                            .map_or("<empty>".to_string(), |x| x.to_string())
                    );
                    println!(
                        "\t\tVisible: {}",
                        ts.visible()
                            .map_or("<empty>".to_string(), |x| x.to_string()),
                    );
                    println!(
                        "\t\tDS visible: {}",
                        ts.ds_visible()
                            .map_or("<empty>".to_string(), |x| x.to_string())
                    );
                    println!(
                        "\t\tRRSIG visible: {}",
                        ts.rrsig_visible()
                            .map_or("<empty>".to_string(), |x| x.to_string()),
                    );
                    println!(
                        "\t\tWithdrawn: {}",
                        ts.withdrawn()
                            .map_or("<empty>".to_string(), |x| x.to_string())
                    );
                }
            }
            Commands::Get { subcommand } => get_command(subcommand, &ksc, &kss),
            Commands::Set { subcommand } => set_command(subcommand, &mut ksc, &mut config_changed)?,
            Commands::Show => {
                println!("state-file: {:?}", ksc.state_file);
                println!("use-csk: {}", ksc.use_csk);
                println!("algorithm: {}", ksc.algorithm);
                println!("ksk-validity: {:?}", ksc.ksk_validity);
                println!("zsk-validity: {:?}", ksc.zsk_validity);
                println!("csk-validity: {:?}", ksc.csk_validity);
                println!(
                    "auto-ksk: start {}, report {}, expire {}, done {}",
                    ksc.auto_ksk.start, ksc.auto_ksk.report, ksc.auto_ksk.expire, ksc.auto_ksk.done,
                );
                println!(
                    "auto-zsk: start {}, report {}, expire {}, done {}",
                    ksc.auto_zsk.start, ksc.auto_zsk.report, ksc.auto_zsk.expire, ksc.auto_zsk.done,
                );
                println!(
                    "auto-csk: start {}, report {}, expire {}, done {}",
                    ksc.auto_csk.start, ksc.auto_csk.report, ksc.auto_csk.expire, ksc.auto_csk.done,
                );
                println!(
                    "auto-algorithm: start {}, report {}, expire {}, done {}",
                    ksc.auto_algorithm.start,
                    ksc.auto_algorithm.report,
                    ksc.auto_algorithm.expire,
                    ksc.auto_algorithm.done,
                );
                println!("dnskey-inception-offset: {:?}", ksc.dnskey_inception_offset);
                println!(
                    "dnskey-signature-lifetime: {:?}",
                    ksc.dnskey_signature_lifetime
                );
                println!("dnskey-remain-time: {:?}", ksc.dnskey_remain_time);
                println!("cds-inception-offset: {:?}", ksc.cds_inception_offset);
                println!("cds-signature-lifetime: {:?}", ksc.cds_signature_lifetime);
                println!("cds-remain-time: {:?}", ksc.cds_remain_time);
                println!("ds-algorithm: {:?}", ksc.ds_algorithm);
                println!("autoremove: {:?}", ksc.autoremove);
            }
            Commands::Cron => {
                if sig_renew(&kss.dnskey_rrset, &ksc.dnskey_remain_time) {
                    println!("DNSKEY RRSIG(s) need to be renewed");
                    update_dnskey_rrset(&mut kss, &ksc, env)?;
                    state_changed = true;
                }
                if sig_renew(&kss.cds_rrset, &ksc.cds_remain_time) {
                    println!("CDS/CDNSKEY RRSIGs need to be renewed");
                    create_cds_rrset(&mut kss, &ksc, ksc.ds_algorithm.to_digest_algorithm(), env)?;
                    state_changed = true;
                }

                let need_algorithm_roll = algorithm_roll_needed(&ksc, &kss);

                if ksc.use_csk || need_algorithm_roll {
                    // Start a CSK or algorithm roll if the KSK has expired.
                    // All other rolls are a conflict.
                    auto_start(
                        &ksc.ksk_validity,
                        if need_algorithm_roll {
                            &ksc.auto_algorithm
                        } else {
                            &ksc.auto_csk
                        },
                        &ksc,
                        &mut kss,
                        env,
                        &mut state_changed,
                        |_| true,
                        |keytype| {
                            if let KeyType::Ksk(keystate) = keytype {
                                Some(keystate)
                            } else {
                                None
                            }
                        },
                        if need_algorithm_roll {
                            start_algorithm_roll
                        } else {
                            start_csk_roll
                        },
                    )?;

                    // The same for the ZSK.
                    auto_start(
                        &ksc.zsk_validity,
                        if need_algorithm_roll {
                            &ksc.auto_algorithm
                        } else {
                            &ksc.auto_csk
                        },
                        &ksc,
                        &mut kss,
                        env,
                        &mut state_changed,
                        |_| true,
                        |keytype| {
                            if let KeyType::Zsk(keystate) = keytype {
                                Some(keystate)
                            } else {
                                None
                            }
                        },
                        if need_algorithm_roll {
                            start_algorithm_roll
                        } else {
                            start_csk_roll
                        },
                    )?;
                } else {
                    auto_start(
                        &ksc.ksk_validity,
                        &ksc.auto_ksk,
                        &ksc,
                        &mut kss,
                        env,
                        &mut state_changed,
                        |r| r != RollType::ZskRoll && r != RollType::ZskDoubleSignatureRoll,
                        |keytype| {
                            if let KeyType::Ksk(keystate) = keytype {
                                Some(keystate)
                            } else {
                                None
                            }
                        },
                        start_ksk_roll,
                    )?;

                    auto_start(
                        &ksc.zsk_validity,
                        &ksc.auto_zsk,
                        &ksc,
                        &mut kss,
                        env,
                        &mut state_changed,
                        |r| r != RollType::KskRoll && r != RollType::KskDoubleDsRoll,
                        |keytype| {
                            if let KeyType::Zsk(keystate) = keytype {
                                Some(keystate)
                            } else {
                                None
                            }
                        },
                        start_zsk_roll,
                    )?;
                }

                auto_start(
                    &ksc.csk_validity,
                    if need_algorithm_roll {
                        &ksc.auto_algorithm
                    } else {
                        &ksc.auto_csk
                    },
                    &ksc,
                    &mut kss,
                    env,
                    &mut state_changed,
                    |_| true,
                    |keytype| {
                        if let KeyType::Csk(keystate, _) = keytype {
                            Some(keystate)
                        } else {
                            None
                        }
                    },
                    if need_algorithm_roll {
                        start_algorithm_roll
                    } else {
                        start_csk_roll
                    },
                )?;

                auto_report_expire_done(
                    &ksc.auto_ksk,
                    &[RollType::KskRoll, RollType::KskDoubleDsRoll],
                    &ksc,
                    &mut kss,
                    env,
                    &mut state_changed,
                )
                .await?;
                auto_report_expire_done(
                    &ksc.auto_zsk,
                    &[RollType::ZskRoll, RollType::ZskDoubleSignatureRoll],
                    &ksc,
                    &mut kss,
                    env,
                    &mut state_changed,
                )
                .await?;
                auto_report_expire_done(
                    &ksc.auto_csk,
                    &[RollType::CskRoll],
                    &ksc,
                    &mut kss,
                    env,
                    &mut state_changed,
                )
                .await?;
                auto_report_expire_done(
                    &ksc.auto_algorithm,
                    &[RollType::AlgorithmRoll],
                    &ksc,
                    &mut kss,
                    env,
                    &mut state_changed,
                )
                .await?;
            }
        }

        if !config_changed && !state_changed {
            // No need to update cron_next if nothing has changed.
            return Ok(());
        }

        let mut cron_next = Vec::new();

        cron_next.push(compute_cron_next(
            &kss.dnskey_rrset,
            &ksc.dnskey_remain_time,
        ));

        cron_next.push(compute_cron_next(&kss.cds_rrset, &ksc.cds_remain_time));

        let need_algorithm_roll = algorithm_roll_needed(&ksc, &kss);

        if ksc.use_csk || need_algorithm_roll {
            cron_next_auto_start(
                ksc.ksk_validity,
                if need_algorithm_roll {
                    &ksc.auto_algorithm
                } else {
                    &ksc.auto_csk
                },
                &kss,
                |_| true,
                |keytype| {
                    if let KeyType::Ksk(keystate) = keytype {
                        Some(keystate)
                    } else {
                        None
                    }
                },
                &mut cron_next,
            );
            cron_next_auto_start(
                ksc.zsk_validity,
                if need_algorithm_roll {
                    &ksc.auto_algorithm
                } else {
                    &ksc.auto_csk
                },
                &kss,
                |_| true,
                |keytype| {
                    if let KeyType::Zsk(keystate) = keytype {
                        Some(keystate)
                    } else {
                        None
                    }
                },
                &mut cron_next,
            );
        } else {
            cron_next_auto_start(
                ksc.ksk_validity,
                &ksc.auto_ksk,
                &kss,
                |r| r != RollType::ZskRoll && r != RollType::ZskDoubleSignatureRoll,
                |keytype| {
                    if let KeyType::Ksk(keystate) = keytype {
                        Some(keystate)
                    } else {
                        None
                    }
                },
                &mut cron_next,
            );
            cron_next_auto_start(
                ksc.zsk_validity,
                &ksc.auto_zsk,
                &kss,
                |r| r != RollType::KskRoll && r != RollType::KskDoubleDsRoll,
                |keytype| {
                    if let KeyType::Zsk(keystate) = keytype {
                        Some(keystate)
                    } else {
                        None
                    }
                },
                &mut cron_next,
            );
        }

        cron_next_auto_start(
            ksc.csk_validity,
            if need_algorithm_roll {
                &ksc.auto_algorithm
            } else {
                &ksc.auto_csk
            },
            &kss,
            |_| true,
            |keytype| {
                if let KeyType::Csk(keystate, _) = keytype {
                    Some(keystate)
                } else {
                    None
                }
            },
            &mut cron_next,
        );

        cron_next_auto_report_expire_done(
            &ksc.auto_ksk,
            &[RollType::KskRoll, RollType::KskDoubleDsRoll],
            &kss,
            &mut cron_next,
        )?;
        cron_next_auto_report_expire_done(
            &ksc.auto_zsk,
            &[RollType::ZskRoll, RollType::ZskDoubleSignatureRoll],
            &kss,
            &mut cron_next,
        )?;
        cron_next_auto_report_expire_done(
            &ksc.auto_csk,
            &[RollType::CskRoll],
            &kss,
            &mut cron_next,
        )?;
        cron_next_auto_report_expire_done(
            &ksc.auto_algorithm,
            &[RollType::AlgorithmRoll],
            &kss,
            &mut cron_next,
        )?;

        let cron_next = cron_next.iter().filter_map(|e| e.clone()).min();

        if cron_next != kss.cron_next {
            kss.cron_next = cron_next;
            state_changed = true;
        }
        if config_changed {
            let json = serde_json::to_string_pretty(&ksc).expect("should not fail");
            let mut file = File::create(&self.keyset_conf).map_err::<Error, _>(|e| {
                format!("unable to create file {}: {e}", self.keyset_conf.display()).into()
            })?;
            write!(file, "{json}").map_err::<Error, _>(|e| {
                format!(
                    "unable to write to file {}: {e}",
                    self.keyset_conf.display()
                )
                .into()
            })?;
        }
        if state_changed {
            let json = serde_json::to_string_pretty(&kss).expect("should not fail");
            let mut file = File::create(&ksc.state_file).map_err::<Error, _>(|e| {
                format!("unable to create file {}: {e}", ksc.state_file.display()).into()
            })?;
            write!(file, "{json}").map_err::<Error, _>(|e| {
                format!("unable to write to file {}: {e}", ksc.state_file.display()).into()
            })?;
        }
        Ok(())
    }
}

/// Implement the get subcommand.
fn get_command(cmd: GetCommands, ksc: &KeySetConfig, kss: &KeySetState) {
    match cmd {
        GetCommands::UseCsk => {
            println!("{}", ksc.use_csk);
        }
        GetCommands::Autoremove => {
            println!("{}", ksc.autoremove);
        }
        GetCommands::Algorithm => {
            println!("{}", ksc.algorithm);
        }
        GetCommands::DsAlgorithm => {
            println!("{}", ksc.ds_algorithm);
        }
        GetCommands::DnskeyLifetime => {
            let span = Span::try_from(ksc.dnskey_signature_lifetime).expect("should not fail");
            let signeddur = span
                .to_duration(SpanRelativeTo::days_are_24_hours())
                .expect("should not fail");
            println!("{signeddur:#}");
        }
        GetCommands::CdsLifetime => {
            let span = Span::try_from(ksc.cds_signature_lifetime).expect("should not fail");
            let signeddur = span
                .to_duration(SpanRelativeTo::days_are_24_hours())
                .expect("should not fail");
            println!("{signeddur:#}");
        }
        GetCommands::Dnskey => {
            for r in &kss.dnskey_rrset {
                println!("{r}");
            }
        }
        GetCommands::Cds => {
            for r in &kss.cds_rrset {
                println!("{r}");
            }
        }
        GetCommands::Ds => {
            for r in &kss.ds_rrset {
                println!("{r}");
            }
        }
    }
}

/// Implement the set subcommand.
fn set_command(
    cmd: SetCommands,
    ksc: &mut KeySetConfig,
    config_changed: &mut bool,
) -> Result<(), Error> {
    match cmd {
        SetCommands::UseCsk { boolean } => {
            ksc.use_csk = boolean;
        }
        SetCommands::Autoremove { boolean } => {
            ksc.autoremove = boolean;
        }
        SetCommands::Algorithm { algorithm, bits } => {
            ksc.algorithm = KeyParameters::new(&algorithm, bits)?;
        }
        SetCommands::AutoKsk {
            start,
            report,
            expire,
            done,
        } => {
            ksc.auto_ksk = AutoConfig {
                start,
                report,
                expire,
                done,
            };
            *config_changed = true;
        }
        SetCommands::AutoZsk {
            start,
            report,
            expire,
            done,
        } => {
            ksc.auto_zsk = AutoConfig {
                start,
                report,
                expire,
                done,
            };
            *config_changed = true;
        }
        SetCommands::AutoCsk {
            start,
            report,
            expire,
            done,
        } => {
            ksc.auto_csk = AutoConfig {
                start,
                report,
                expire,
                done,
            };
            *config_changed = true;
        }
        SetCommands::AutoAlgorithm {
            start,
            report,
            expire,
            done,
        } => {
            ksc.auto_algorithm = AutoConfig {
                start,
                report,
                expire,
                done,
            };
            *config_changed = true;
        }
        SetCommands::DsAlgorithm { algorithm } => {
            ksc.ds_algorithm = algorithm;
        }
        SetCommands::DnskeyInceptionOffset { duration } => {
            ksc.dnskey_inception_offset = duration;
        }
        SetCommands::DnskeyLifetime { duration } => {
            ksc.dnskey_signature_lifetime = duration;
        }
        SetCommands::DnskeyRemainTime { duration } => {
            ksc.dnskey_remain_time = duration;
        }
        SetCommands::CdsInceptionOffset { duration } => {
            ksc.cds_inception_offset = duration;
        }
        SetCommands::CdsLifetime { duration } => {
            ksc.cds_signature_lifetime = duration;
        }
        SetCommands::CdsRemainTime { duration } => {
            ksc.cds_remain_time = duration;
        }
        SetCommands::KskValidity { opt_duration } => {
            ksc.ksk_validity = opt_duration;
        }
        SetCommands::ZskValidity { opt_duration } => {
            ksc.zsk_validity = opt_duration;
        }
        SetCommands::CskValidity { opt_duration } => {
            ksc.csk_validity = opt_duration;
        }
    }
    *config_changed = true;
    Ok(())
}

/// Config for the keyset command.
#[derive(Deserialize, Serialize)]
struct KeySetConfig {
    /// Filename of the state file.
    state_file: PathBuf,

    /// Directory where new key file should be created.
    keys_dir: PathBuf,

    /// Whether to use a CSK (if true) or a KSK and a ZSK.
    use_csk: bool,

    /// Algorithm and other parameters for key generation.
    algorithm: KeyParameters,

    /// Validity of KSKs.
    ksk_validity: Option<Duration>,
    /// Validity of ZSKs.
    zsk_validity: Option<Duration>,
    /// Validity of CSKs.
    csk_validity: Option<Duration>,

    /// Configuration variable for automatic KSK rolls.
    auto_ksk: AutoConfig,
    /// Configuration variable for automatic ZSK rolls.
    auto_zsk: AutoConfig,
    /// Configuration variable for automatic CSK rolls.
    auto_csk: AutoConfig,
    /// Configuration variable for automatic algorithm rolls.
    auto_algorithm: AutoConfig,

    /// DNSKEY signature inception offset (positive values are subtracted
    ///from the current time).
    dnskey_inception_offset: Duration,

    /// DNSKEY signature lifetime
    dnskey_signature_lifetime: Duration,

    /// The required remaining signature lifetime.
    dnskey_remain_time: Duration,

    /// CDS/CDNSKEY signature inception offset
    cds_inception_offset: Duration,

    /// CDS/CDNSKEY signature lifetime
    cds_signature_lifetime: Duration,

    /// The required remaining signature lifetime.
    cds_remain_time: Duration,

    /// The DS hash algorithm.
    ds_algorithm: DsAlgorithm,

    /// Automatically remove keys that are no long in use.
    autoremove: bool,
}

#[derive(Default, Deserialize, Serialize)]
struct AutoConfig {
    /// Whether to start a key roll automatically.
    start: bool,
    /// Whether to handle the Report actions automatically.
    report: bool,
    /// Whether to handle the cache expire step automatically.
    expire: bool,
    /// Whether to handle the done step automatically.
    done: bool,
}

/// Persistent state for the keyset command.
#[derive(Deserialize, Serialize)]
struct KeySetState {
    /// Domain KeySet state.
    keyset: KeySet,

    /// DNSKEY RRset plus signatures to include in the signed zone.
    pub dnskey_rrset: Vec<String>,

    /// DS records to add to the parent zone.
    pub ds_rrset: Vec<String>,

    /// CDS and CDNSKEY RRsets plus signatures to include in the signed zone.
    pub cds_rrset: Vec<String>,

    /// Place holder for NS records. Maybe the four _rrset fields should be
    /// combined. Though for extensibility there needs to be a field that
    /// informs the signer which Rtypes need special treatment.
    pub ns_rrset: Vec<String>,

    /// Next time to call the cron subcommand.
    cron_next: Option<UnixTime>,

    /// Internal state for automatic key rolls.
    internal: HashMap<RollType, RollStateReports>,
}

#[derive(Deserialize, Serialize)]
enum KeyParameters {
    /// The RSASHA256 algorithm with the key length in bits.
    RsaSha256(usize),
    /// The RSASHA512 w algorithmith the key length in bits.
    RsaSha512(usize),
    /// The ECDSAP256SHA256 algorithm.
    EcdsaP256Sha256,
    /// The ECDSAP384SHA384 algorithm.
    EcdsaP384Sha384,
    /// The ED25519 algorithm.
    Ed25519,
    /// The ED448 algorithm.
    Ed448,
}

impl KeyParameters {
    /// Generate a new KeyParameter object from the algorithm name and
    /// the key length (when required).
    fn new(algorithm: &str, bits: Option<usize>) -> Result<Self, Error> {
        if algorithm == "RSASHA256" {
            let bits = bits.ok_or::<Error>("bits option expected\n".into())?;
            Ok(KeyParameters::RsaSha256(bits))
        } else if algorithm == "RSASHA512" {
            let bits = bits.ok_or::<Error>("bits option expected\n".into())?;
            Ok(KeyParameters::RsaSha512(bits))
        } else if algorithm == "ECDSAP256SHA256" {
            Ok(KeyParameters::EcdsaP256Sha256)
        } else if algorithm == "ECDSAP384SHA384" {
            Ok(KeyParameters::EcdsaP384Sha384)
        } else if algorithm == "ED25519" {
            Ok(KeyParameters::Ed25519)
        } else if algorithm == "ED448" {
            Ok(KeyParameters::Ed448)
        } else {
            Err(format!("unknown algorithm {algorithm}\n").into())
        }
    }

    /// Return the GenerateParams equivalent of a KeyParameters object.
    fn to_generate_params(&self) -> GenerateParams {
        match self {
            KeyParameters::RsaSha256(size) => GenerateParams::RsaSha256 {
                bits: (*size).try_into().expect("should not fail"),
            },
            KeyParameters::RsaSha512(size) => GenerateParams::RsaSha512 {
                bits: (*size).try_into().expect("should not fail"),
            },
            KeyParameters::EcdsaP256Sha256 => GenerateParams::EcdsaP256Sha256,
            KeyParameters::EcdsaP384Sha384 => GenerateParams::EcdsaP384Sha384,
            KeyParameters::Ed25519 => GenerateParams::Ed25519,
            KeyParameters::Ed448 => GenerateParams::Ed448,
        }
    }
}

impl Display for KeyParameters {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            KeyParameters::RsaSha256(bits) => write!(fmt, "RSASHA256 {bits} bits"),
            KeyParameters::RsaSha512(bits) => write!(fmt, "RSASHA512 {bits} bits"),
            KeyParameters::EcdsaP256Sha256 => write!(fmt, "ECDSAP256SHA256"),
            KeyParameters::EcdsaP384Sha384 => write!(fmt, "ECDSAP384SHA384"),
            KeyParameters::Ed25519 => write!(fmt, "ED25519"),
            KeyParameters::Ed448 => write!(fmt, "ED448"),
        }
    }
}

/// The hash algorithm to use for DS records.
// Do we want Deserialize and Serialize for DigestAlgorithm?
#[derive(Clone, Debug, Deserialize, Serialize)]
enum DsAlgorithm {
    /// Hash the public key using SHA-256.
    Sha256,
    /// Hash the public key using SHA-384.
    Sha384,
}

impl DsAlgorithm {
    /// Create a new DsAlgorithm based on the hash algorithm name.
    fn new(digest: &str) -> Result<Self, Error> {
        if digest == "SHA-256" {
            Ok(DsAlgorithm::Sha256)
        } else if digest == "SHA-384" {
            Ok(DsAlgorithm::Sha384)
        } else {
            Err(format!("unknown digest {digest}\n").into())
        }
    }

    /// Return the equivalent DigestAlgorithm for a DsAlgorithm object.
    fn to_digest_algorithm(&self) -> DigestAlgorithm {
        match self {
            DsAlgorithm::Sha256 => DigestAlgorithm::SHA256,
            DsAlgorithm::Sha384 => DigestAlgorithm::SHA384,
        }
    }
}

impl Display for DsAlgorithm {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            DsAlgorithm::Sha256 => write!(fmt, "SHA-256"),
            DsAlgorithm::Sha384 => write!(fmt, "SHA-384"),
        }
    }
}

/// State needed for automatic key rolls.
#[derive(Default, Deserialize, Serialize)]
struct RollStateReports {
    /// State for the propagation1-complete step.
    propagation1: Mutex<ReportState>,
    /// State for the propagation2-complete step.
    propagation2: Mutex<ReportState>,
    /// State for the done step.
    done: Mutex<ReportState>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct ReportState {
    /// State for DNSKEY propagation checks.
    dnskey: Option<AutoReportActionsResult>,
    /// State for DS propagation checks.
    ds: Option<AutoReportActionsResult>,
    /// State for RRSIG propagation checks.
    rrsig: Option<AutoReportRrsigResult>,
}

fn new_keys(
    name: &Name<Vec<u8>>,
    algorithm: GenerateParams,
    make_ksk: bool,
    keys: &HashMap<String, Key>,
    keys_dir: &Path,
    env: &impl Env,
) -> Result<(Url, Url, SecurityAlgorithm, u16), Error> {
    // Generate the key.
    // TODO: Attempt repeated generation to avoid key tag collisions.
    // TODO: Add a high-level operation in 'domain' to select flags?
    let flags = if make_ksk { 257 } else { 256 };

    let mut retries = MAX_KEY_TAG_TRIES;
    let (secret_key, public_key, key_tag) = loop {
        let (secret_key, public_key) = sign::generate(algorithm.clone(), flags)
            .map_err::<Error, _>(|e| format!("key generation failed: {e}\n").into())?;

        let key_tag = public_key.key_tag();
        if !keys.iter().any(|(_, k)| k.key_tag() == key_tag) {
            break (secret_key, public_key, key_tag);
        }
        if retries <= 1 {
            return Err("unable to generate key with unique key tag".into());
        }
        retries -= 1;
    };

    let algorithm = public_key.algorithm();

    let public_key = Record::new(name.clone(), Class::IN, Ttl::ZERO, public_key);

    let base = format!(
        "K{}+{:03}+{:05}",
        name.fmt_with_dot(),
        algorithm.to_int(),
        key_tag
    );

    let mut secret_key_path = keys_dir.to_path_buf();
    secret_key_path.push(Path::new(&format!("{base}.private")));
    let mut public_key_path = keys_dir.to_path_buf();
    public_key_path.push(Path::new(&format!("{base}.key")));

    let mut secret_key_file = util::create_new_file(&env, &secret_key_path)?;
    let mut public_key_file = util::create_new_file(&env, &public_key_path)?;
    // Prepare the contents to write.
    let secret_key = secret_key.display_as_bind().to_string();
    let public_key = display_as_bind(&public_key).to_string();

    // Write the key files.
    secret_key_file
        .write_all(secret_key.as_bytes())
        .map_err(|err| format!("error while writing private key file '{base}.private': {err}"))?;
    public_key_file
        .write_all(public_key.as_bytes())
        .map_err(|err| format!("error while writing public key file '{base}.key': {err}"))?;

    let secret_key_path = secret_key_path.to_str().ok_or::<Error>(
        format!("path {} needs to be valid UTF-8", secret_key_path.display()).into(),
    )?;
    let secret_key_url = "file://".to_owned() + secret_key_path;
    let public_key_path = public_key_path.to_str().ok_or::<Error>(
        format!("path {} needs to be valid UTF-8", public_key_path.display()).into(),
    )?;
    let public_key_url = "file://".to_owned() + public_key_path;

    let secret_key_url = Url::parse(&secret_key_url)
        .map_err::<Error, _>(|e| format!("unable to parse {secret_key_url} as URL: {e}").into())?;
    let public_key_url = Url::parse(&public_key_url)
        .map_err::<Error, _>(|e| format!("unable to parse {public_key_url} as URL: {e}").into())?;

    Ok((public_key_url, secret_key_url, algorithm, key_tag))
}

/// Update the DNSKEY RRset and signures in the KeySetState.
///
/// Collect all keys where present() returns true and sign the DNSKEY RRset
/// with all KSK and CSK (KSK state) where signer() returns true.
fn update_dnskey_rrset(
    kss: &mut KeySetState,
    ksc: &KeySetConfig,
    env: &impl Env,
) -> Result<(), Error> {
    let mut dnskeys = Vec::new();
    for (k, v) in kss.keyset.keys() {
        let present = match v.keytype() {
            KeyType::Ksk(key_state) => key_state.present(),
            KeyType::Zsk(key_state) => key_state.present(),
            KeyType::Csk(key_state, _) => key_state.present(),
            KeyType::Include(key_state) => key_state.present(),
        };

        let pub_url = Url::parse(k).expect("valid URL expected");

        if present {
            let zonefile = if pub_url.scheme() == "file" {
                let path = pub_url.path();
                let filename = env.in_cwd(&path);
                let mut file = File::open(&filename).map_err::<Error, _>(|e| {
                    format!("unable to open public key file {}: {e}", filename.display()).into()
                })?;
                domain::zonefile::inplace::Zonefile::load(&mut file).map_err::<Error, _>(|e| {
                    format!("unable load zone from file {}: {e}", filename.display()).into()
                })?
            } else {
                panic!("unsupported scheme in {pub_url}");
            };
            for entry in zonefile {
                let entry = entry
                    .map_err::<Error, _>(|e| format!("bad entry in key file {k}: {e}\n").into())?;

                // We only care about records in a zonefile
                let Entry::Record(record) = entry else {
                    continue;
                };

                // Of the records that we see, we only care about DNSKEY records
                let ScannedRecordData::Dnskey(dnskey) = record.data() else {
                    continue;
                };

                let record = Record::new(
                    record
                        .owner()
                        .try_to_name::<Bytes>()
                        .expect("should not fail"),
                    record.class(),
                    record.ttl(),
                    dnskey.clone(),
                );

                dnskeys.push(record);
            }
        }
    }
    let now = Timestamp::now().into_int();
    let inception = (now - ksc.dnskey_inception_offset.as_secs() as u32).into();
    let expiration = (now + ksc.dnskey_signature_lifetime.as_secs() as u32).into();

    let mut sigs = Vec::new();
    for (k, v) in kss.keyset.keys() {
        let dnskey_signer = match v.keytype() {
            KeyType::Ksk(key_state) => key_state.signer(),
            KeyType::Zsk(_) => false,
            KeyType::Csk(key_state, _) => key_state.signer(),
            KeyType::Include(_) => false,
        };

        let rrset = Rrset::new(&dnskeys)
            .map_err::<Error, _>(|e| format!("unable to create Rrset: {e}\n").into())?;

        if dnskey_signer {
            let privref = v.privref().ok_or("missing private key")?;
            let priv_url = Url::parse(privref).expect("valid URL expected");
            let private_data = if priv_url.scheme() == "file" {
                std::fs::read_to_string(priv_url.path()).map_err::<Error, _>(|e| {
                    format!("unable read from file {}: {e}", priv_url.path()).into()
                })?
            } else {
                panic!("unsupported URL scheme in {priv_url}");
            };
            let secret_key =
                SecretKeyBytes::parse_from_bind(&private_data).map_err::<Error, _>(|e| {
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
            let public_key = parse_from_bind(&public_data).map_err::<Error, _>(|e| {
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
            let sig = sign_rrset::<_, _, Bytes, _>(&signing_key, &rrset, inception, expiration)
                .map_err::<Error, _>(|e| {
                format!("error signing DNSKEY RRset with private key {privref}: {e}").into()
            })?;
            sigs.push(sig);
        }
    }

    kss.dnskey_rrset.truncate(0);
    for r in dnskeys {
        kss.dnskey_rrset
            .push(r.display_zonefile(DisplayKind::Simple).to_string());
    }
    for r in sigs {
        kss.dnskey_rrset
            .push(r.display_zonefile(DisplayKind::Simple).to_string());
    }
    println!("Got DNSKEY RRset: {:?}", kss.dnskey_rrset);
    Ok(())
}

/// Create the CDS and CDNSKEY RRsets plus signatures.
///
/// The CDS and CDNSKEY RRsets contain the keys where at_parent() returns
/// true. The RRsets are signed with all keys that sign the DNSKEY RRset.
fn create_cds_rrset(
    kss: &mut KeySetState,
    ksc: &KeySetConfig,
    digest_alg: DigestAlgorithm,
    env: &impl Env,
) -> Result<(), Error> {
    let mut cds_list = Vec::new();
    let mut cdnskey_list = Vec::new();
    for (k, v) in kss.keyset.keys() {
        let at_parent = match v.keytype() {
            KeyType::Ksk(key_state) => key_state.at_parent(),
            KeyType::Zsk(key_state) => key_state.at_parent(),
            KeyType::Csk(key_state, _) => key_state.at_parent(),
            KeyType::Include(key_state) => key_state.at_parent(),
        };

        if at_parent {
            let pub_url = Url::parse(k).expect("valid URL expected");
            let path = pub_url.path();
            let filename = env.in_cwd(&path);
            let mut file = File::open(&filename).map_err::<Error, _>(|e| {
                format!("unable to open public key file {}: {e}", filename.display()).into()
            })?;
            let zonefile = domain::zonefile::inplace::Zonefile::load(&mut file)
                .map_err::<Error, _>(|e| {
                    format!("unable to read zone from file {}: {e}", filename.display()).into()
                })?;
            for entry in zonefile {
                let entry = entry
                    .map_err::<Error, _>(|e| format!("bad entry in key file {k}: {e}\n").into())?;

                // We only care about records in a zonefile
                let Entry::Record(record) = entry else {
                    continue;
                };

                // Of the records that we see, we only care about DNSKEY records
                let ScannedRecordData::Dnskey(dnskey) = record.data() else {
                    continue;
                };

                let cdnskey = Cdnskey::new(
                    dnskey.flags(),
                    dnskey.protocol(),
                    dnskey.algorithm(),
                    dnskey.public_key().clone(),
                )
                .expect("should not fail");
                let cdnskey_record = Record::new(
                    record
                        .owner()
                        .try_to_name::<Bytes>()
                        .expect("should not fail"),
                    record.class(),
                    record.ttl(),
                    cdnskey,
                );

                cdnskey_list.push(cdnskey_record);

                let key_tag = dnskey.key_tag();
                let sec_alg = dnskey.algorithm();

                let digest = dnskey
                    .digest(&record.owner(), digest_alg)
                    .map_err::<Error, _>(|e| {
                        format!("error creating digest for DNSKEY record: {e}").into()
                    })?;

                let cds = Cds::new(key_tag, sec_alg, digest_alg, digest.as_ref().to_vec()).expect(
                    "Infallible because the digest won't be too long since it's a valid digest",
                );

                let cds_record = Record::new(
                    record
                        .owner()
                        .try_to_name::<Bytes>()
                        .expect("should not fail"),
                    record.class(),
                    record.ttl(),
                    cds,
                );

                cds_list.push(cds_record);
            }
        }

        // Need to sign
    }

    let now = Timestamp::now().into_int();
    let inception = (now - ksc.cds_inception_offset.as_secs() as u32).into();
    let expiration = (now + ksc.cds_signature_lifetime.as_secs() as u32).into();

    let mut cds_sigs = Vec::new();
    let mut cdnskey_sigs = Vec::new();
    for (k, v) in kss.keyset.keys() {
        let dnskey_signer = match v.keytype() {
            KeyType::Ksk(key_state) => key_state.signer(),
            KeyType::Zsk(_) => false,
            KeyType::Csk(key_state, _) => key_state.signer(),
            KeyType::Include(_) => false,
        };

        let cds_rrset = Rrset::new(&cds_list)
            .map_err::<Error, _>(|e| format!("unable to create Rrset: {e}\n").into())?;
        let cdnskey_rrset = Rrset::new(&cdnskey_list)
            .map_err::<Error, _>(|e| format!("unable to create Rrset: {e}\n").into())?;

        if dnskey_signer {
            let privref = v.privref().ok_or("missing private key")?;
            let priv_url = Url::parse(privref).expect("valid URL expected");
            let path = priv_url.path();
            let filename = env.in_cwd(&path);
            let private_data = std::fs::read_to_string(&filename).map_err::<Error, _>(|e| {
                format!(
                    "unable to read from private key file {}: {e}",
                    filename.display()
                )
                .into()
            })?;
            let secret_key =
                SecretKeyBytes::parse_from_bind(&private_data).map_err::<Error, _>(|e| {
                    format!(
                        "unable to parse private key file {}: {e}",
                        filename.display()
                    )
                    .into()
                })?;
            let pub_url = Url::parse(k).expect("valid URL expected");
            let path = pub_url.path();
            let filename = env.in_cwd(&path);
            let public_data = std::fs::read_to_string(&filename).map_err::<Error, _>(|e| {
                format!(
                    "unable to read from public key file {}: {e}",
                    filename.display()
                )
                .into()
            })?;
            let public_key = parse_from_bind(&public_data).map_err::<Error, _>(|e| {
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
            let sig = sign_rrset::<_, _, Bytes, _>(&signing_key, &cds_rrset, inception, expiration)
                .map_err::<Error, _>(|e| {
                    format!("error signing CDS RRset with private key {privref}: {e}").into()
                })?;
            cds_sigs.push(sig);
            let sig =
                sign_rrset::<_, _, Bytes, _>(&signing_key, &cdnskey_rrset, inception, expiration)
                    .map_err::<Error, _>(|e| {
                    format!("error signing CDNSKEY RRset with private key {privref}: {e}").into()
                })?;
            cdnskey_sigs.push(sig);
        }
    }

    kss.cds_rrset.truncate(0);
    for r in cdnskey_list {
        kss.cds_rrset
            .push(r.display_zonefile(DisplayKind::Simple).to_string());
    }
    for r in cdnskey_sigs {
        kss.cds_rrset
            .push(r.display_zonefile(DisplayKind::Simple).to_string());
    }
    for r in cds_list {
        kss.cds_rrset
            .push(r.display_zonefile(DisplayKind::Simple).to_string());
    }
    for r in cds_sigs {
        kss.cds_rrset
            .push(r.display_zonefile(DisplayKind::Simple).to_string());
    }

    println!("Got CDS/CDNSKEY RRset: {:?}", kss.cds_rrset);
    Ok(())
}

/// Remove the CDS and CDNSKEY RRsets and signatures.
fn remove_cds_rrset(kss: &mut KeySetState) {
    kss.cds_rrset.truncate(0);
}

/// Update the DS RRset.
///
/// The DS records are generated from all keys where at_parent() returns true.
/// This RRset is not signed.
fn update_ds_rrset(
    kss: &mut KeySetState,
    digest_alg: DigestAlgorithm,
    env: &impl Env,
) -> Result<(), Error> {
    let mut ds_list = Vec::new();
    for (k, v) in kss.keyset.keys() {
        let at_parent = match v.keytype() {
            KeyType::Ksk(key_state) => key_state.at_parent(),
            KeyType::Zsk(key_state) => key_state.at_parent(),
            KeyType::Csk(key_state, _) => key_state.at_parent(),
            KeyType::Include(key_state) => key_state.at_parent(),
        };

        if at_parent {
            let pub_url = Url::parse(k).expect("valid URL expected");
            let path = pub_url.path();
            let filename = env.in_cwd(&path);
            let mut file = File::open(&filename).map_err::<Error, _>(|e| {
                format!("unable to open public key file {}: {e}", filename.display()).into()
            })?;
            let zonefile = domain::zonefile::inplace::Zonefile::load(&mut file)
                .map_err::<Error, _>(|e| {
                    format!("unable to read zone from file {}: {e}", filename.display()).into()
                })?;
            for entry in zonefile {
                let entry = entry
                    .map_err::<Error, _>(|e| format!("bad entry in key file {k}: {e}\n").into())?;

                // We only care about records in a zonefile
                let Entry::Record(record) = entry else {
                    continue;
                };

                // Of the records that we see, we only care about DNSKEY records
                let ScannedRecordData::Dnskey(dnskey) = record.data() else {
                    continue;
                };

                let key_tag = dnskey.key_tag();
                let sec_alg = dnskey.algorithm();

                let digest = dnskey
                    .digest(&record.owner(), digest_alg)
                    .map_err::<Error, _>(|e| {
                        format!("error creating digest for DNSKEY record: {e}").into()
                    })?;

                let ds = Ds::new(key_tag, sec_alg, digest_alg, digest.as_ref().to_vec()).expect(
                    "Infallible because the digest won't be too long since it's a valid digest",
                );

                let ds_record =
                    Record::new(record.owner().clone(), record.class(), record.ttl(), ds);

                ds_list.push(ds_record);
            }
        }
    }

    kss.ds_rrset.truncate(0);
    for r in ds_list {
        kss.ds_rrset
            .push(r.display_zonefile(DisplayKind::Simple).to_string());
    }

    println!("Got DS RRset: {:?}", kss.ds_rrset);
    Ok(())
}

/// Handle the actions that result from key roll steps that always need to
/// be handled independent of automation.
///
/// Those are the actions that update the DNSKEY RRset, DS records and the
/// CDS and CDNSKEY RRsets.
fn handle_actions(
    actions: &[Action],
    ksc: &KeySetConfig,
    kss: &mut KeySetState,
    env: &impl Env,
) -> Result<(), Error> {
    for action in actions {
        match action {
            Action::UpdateDnskeyRrset => update_dnskey_rrset(kss, ksc, env)?,
            Action::CreateCdsRrset => {
                create_cds_rrset(kss, ksc, ksc.ds_algorithm.to_digest_algorithm(), env)?
            }
            Action::RemoveCdsRrset => remove_cds_rrset(kss),
            Action::UpdateDsRrset => {
                update_ds_rrset(kss, ksc.ds_algorithm.to_digest_algorithm(), env)?
            }
            Action::UpdateRrsig => (),
            Action::ReportDnskeyPropagated => (),
            Action::ReportDsPropagated => (),
            Action::ReportRrsigPropagated => (),
            Action::WaitDnskeyPropagated => (),
            Action::WaitDsPropagated => (),
            Action::WaitRrsigPropagated => (),
        }
    }
    Ok(())
}

/// Print a list of actions.
///
/// TODO: make this list user friendly.
fn print_actions(actions: &[Action]) {
    if actions.is_empty() {
        println!("No actions");
    } else {
        print!("Actions:");
        for a in actions {
            print!(" {a:?}");
        }
        println!();
    }
}

/// Parse a duration from a string with suffixes like 'm', 'h', 'w', etc.
fn parse_duration(value: &str) -> Result<Duration, Error> {
    let span: Span = value
        .parse()
        .map_err::<Error, _>(|e| format!("unable to parse {value} as lifetime: {e}\n").into())?;
    let signeddur = span
        .to_duration(SpanRelativeTo::days_are_24_hours())
        .map_err::<Error, _>(|e| format!("unable to convert duration: {e}\n").into())?;
    Duration::try_from(signeddur).map_err(|e| format!("unable to convert duration: {e}\n").into())
}

/// Parse an optional duration from a string but also allow 'off' to signal
/// no duration.
fn parse_opt_duration(value: &str) -> Result<Option<Duration>, Error> {
    if value == "off" {
        return Ok(None);
    }
    let duration = parse_duration(value)?;
    Ok(Some(duration))
}

/// Check whether signatures need to be renewed.
///
/// The input is an RRset plus signatures in zonefile format plus a
/// duration how long the signatures are required to remain valid.
fn sig_renew(rrset: &[String], remain_time: &Duration) -> bool {
    let mut zonefile = Zonefile::new();
    for r in rrset {
        zonefile.extend_from_slice(r.as_ref());
        zonefile.extend_from_slice(b"\n");
    }
    let now = Timestamp::now();
    let renew = now.into_int() as u64 + remain_time.as_secs();
    for e in zonefile {
        let e = e.expect("should not fail");
        match e {
            Entry::Record(r) => {
                if let ZoneRecordData::Rrsig(rrsig) = r.data() {
                    if renew > rrsig.expiration().into_int() as u64 {
                        return true;
                    }
                }
            }
            Entry::Include { .. } => continue, // Just ignore include.
        }
    }
    false
}

/// Return where a key has expired. Return a label for the type of
/// key as well to help user friendly output.
fn key_expired(key: &Key, ksc: &KeySetConfig) -> (bool, &'static str) {
    let Some(timestamp) = key.timestamps().published() else {
        return (false, "");
    };

    // Take published time as basis for computing expiration.
    let (keystate, label, validity) = match key.keytype() {
        KeyType::Ksk(keystate) => (keystate, "KSK", ksc.ksk_validity),
        KeyType::Zsk(keystate) => (keystate, "ZSK", ksc.zsk_validity),
        KeyType::Csk(keystate, _) => (keystate, "CSK", ksc.csk_validity),
        KeyType::Include(_) => return (false, ""), // Does not expire.
    };
    if keystate.stale() {
        // Old key.
        return (false, "");
    }
    let Some(validity) = validity else {
        // No limit on key validity.
        return (false, "");
    };
    (timestamp.elapsed() > validity, label)
}

/// Create a PathBuf for the parent directory of a PathBuf.
fn make_parent_dir(filename: PathBuf) -> PathBuf {
    filename.parent().unwrap_or(Path::new("/")).to_path_buf()
}

/// Compute when the cron subcommand should be called to refresh signatures
/// for an RRset.
fn compute_cron_next(rrset: &[String], remain_time: &Duration) -> Option<UnixTime> {
    let mut zonefile = Zonefile::new();
    for r in rrset {
        zonefile.extend_from_slice(r.as_ref());
        zonefile.extend_from_slice(b"\n");
    }

    let now = SystemTime::now();
    let min_expiration = zonefile
        .map(|r| r.expect("should not fail"))
        .filter_map(|r| match r {
            Entry::Record(r) => Some(r),
            Entry::Include { .. } => None,
        })
        .filter_map(|r| {
            if let ZoneRecordData::Rrsig(rrsig) = r.data() {
                Some(rrsig.expiration())
            } else {
                None
            }
        })
        .map(|t| t.to_system_time(now))
        .min();

    // Map to the Unix epoch in case of failure.
    min_expiration.map(|t| {
        (t - *remain_time)
            .try_into()
            .unwrap_or_else(|_| UNIX_EPOCH.try_into().expect("should not fail"))
    })
}

/// The result of an automatic action check that does not need to report a
/// TTL.
#[derive(Debug)]
enum AutoActionsResult {
    /// The action has completed.
    Ok,
    /// Try again after the UnixTime parameter.
    Wait(UnixTime),
}

/// The result of an automatic action check the does need to report a TTL.
#[derive(Clone, Debug, Deserialize, Serialize)]
enum AutoReportActionsResult {
    /// The action has completed, report at least the Ttl in the parameter.
    Report(Ttl),
    /// Try again after the UnixTime parameter.
    Wait(UnixTime),
}

/// The result of checking for RRSIG propagation.
#[derive(Clone, Debug, Deserialize, Serialize)]
enum AutoReportRrsigResult {
    /// The action has completed, report at least the Ttl in the parameter.
    Report(Ttl),
    /// A DNS request failed (for example due to a network problem). Try again
    /// after the UnixTime parameter.
    Wait(UnixTime),
    /// The zone has updated signatures, wait for this version of the zone to
    /// appear on all name servers.
    WaitSoa {
        /// Try again after this time.
        next: UnixTime,
        /// Wait for this serial or newer.
        serial: Serial,
        /// The ttl to use to compute a new 'next' wait time if the check fails.
        ttl: Ttl,
        /// The ttl to put in the Report variable when the check succeeds.
        report_ttl: Ttl,
    },
    /// Wait for a specific record to get updated signatures.
    WaitRecord {
        /// Try again after this time.
        next: UnixTime,
        /// Name to check.
        name: Name<Vec<u8>>,
        /// Rtype to check.
        rtype: Rtype,
        /// The ttl to use to compute a new 'next' wait time if the check fails.
        ttl: Ttl,
    },
    /// For NSEC3 record, it is not possible to directly check if they got new
    /// signatures. Instead, wait for a new version of the zone and check the
    /// entire zone.
    WaitNextSerial {
        /// Try again after this time.
        next: UnixTime,
        /// Wait until the zone version is new than this serial.
        serial: Serial,
        /// The ttl to use to compute a new 'next' wait time if the check fails.
        ttl: Ttl,
    },
}

/// Handle the actions for the Done state automatically. Actions for this
/// state cannot have report actions, but there can be wait actions.
async fn auto_wait_actions(
    actions: &[Action],
    kss: &KeySetState,
    report_state: &Mutex<ReportState>,
    state_changed: &mut bool,
) -> AutoActionsResult {
    for a in actions {
        match a {
            Action::CreateCdsRrset
            | Action::RemoveCdsRrset
            | Action::UpdateDnskeyRrset
            | Action::UpdateDsRrset
            | Action::UpdateRrsig => (),
            Action::WaitDnskeyPropagated => {
                // Note, an extra scope here to make clippy happy. Otherwise
                // clippy thinks that the lock is used across an await point.
                {
                    let report_state_locked = report_state.lock().expect("lock() should not fail");
                    if let Some(dnskey_status) = &report_state_locked.dnskey {
                        match dnskey_status {
                            AutoReportActionsResult::Wait(next) => {
                                if *next > UnixTime::now() {
                                    return AutoActionsResult::Wait(next.clone());
                                }
                            }
                            AutoReportActionsResult::Report(_) => continue,
                        }
                    }

                    drop(report_state_locked);
                }

                let result = report_dnskey_propagated(kss).await;

                dbg!(&result);

                let mut report_state_locked = report_state.lock().expect("lock() should not fail");
                report_state_locked.dnskey = Some(result.clone());
                drop(report_state_locked);
                *state_changed = true;

                match result {
                    AutoReportActionsResult::Wait(next) => return AutoActionsResult::Wait(next),
                    AutoReportActionsResult::Report(_) => (),
                }
            }
            Action::WaitDsPropagated => {
                // Clippy problem
                {
                    let report_state_locked = report_state.lock().expect("lock() should not fail");
                    if let Some(ds_status) = &report_state_locked.ds {
                        match ds_status {
                            AutoReportActionsResult::Wait(next) => {
                                if *next > UnixTime::now() {
                                    return AutoActionsResult::Wait(next.clone());
                                }
                            }
                            AutoReportActionsResult::Report(_) => continue,
                        }
                    }
                    drop(report_state_locked);
                }

                let result = report_ds_propagated(kss).await.unwrap_or_else(|e| {
                    warn!("Check DS propagation failed: {e}");
                    AutoReportActionsResult::Wait(UnixTime::now() + DEFAULT_WAIT)
                });

                let mut report_state_locked = report_state.lock().expect("lock() should not fail");
                report_state_locked.ds = Some(result.clone());
                drop(report_state_locked);
                *state_changed = true;

                match result {
                    AutoReportActionsResult::Wait(next) => return AutoActionsResult::Wait(next),
                    AutoReportActionsResult::Report(_) => (),
                }
            }
            Action::WaitRrsigPropagated => {
                // Clippy problem
                let opt_rrsig_status = {
                    let report_state_locked = report_state.lock().expect("lock() should not fail");
                    // Make a copy of the state. We need to release the lock
                    // before calling await.
                    let opt_rrsig_status = report_state_locked.rrsig.clone();
                    drop(report_state_locked);
                    opt_rrsig_status
                };

                if let Some(rrsig_status) = opt_rrsig_status {
                    match rrsig_status {
                        AutoReportRrsigResult::Wait(next) => {
                            if next > UnixTime::now() {
                                return AutoActionsResult::Wait(next.clone());
                            }
                        }
                        AutoReportRrsigResult::Report(_) => continue,
                        AutoReportRrsigResult::WaitSoa {
                            next,
                            serial,
                            ttl,
                            report_ttl,
                        } => {
                            if next > UnixTime::now() {
                                return AutoActionsResult::Wait(next.clone());
                            }
                            let res = check_soa(serial, kss).await.unwrap_or_else(|e| {
                                warn!("Check SOA propagation failed: {e}");
                                false
                            });
                            dbg!(format!("got {res} for {serial}"));
                            if res {
                                dbg!("Setting rrsig to Report");
                                let mut report_state_locked =
                                    report_state.lock().expect("lock() should not fail");
                                report_state_locked.rrsig =
                                    Some(AutoReportRrsigResult::Report(report_ttl));
                                drop(report_state_locked);
                                *state_changed = true;
                                continue;
                            } else {
                                let next = UnixTime::now() + ttl.into();
                                dbg!("Setting rrsig to WaitSoa");
                                let mut report_state_locked =
                                    report_state.lock().expect("lock() should not fail");
                                report_state_locked.rrsig = Some(AutoReportRrsigResult::WaitSoa {
                                    next: next.clone(),
                                    serial,
                                    ttl,
                                    report_ttl,
                                });
                                drop(report_state_locked);
                                *state_changed = true;
                                return AutoActionsResult::Wait(next);
                            }
                        }
                        AutoReportRrsigResult::WaitRecord {
                            next,
                            name,
                            rtype,
                            ttl,
                        } => {
                            if next > UnixTime::now() {
                                return AutoActionsResult::Wait(next.clone());
                            }
                            let res = check_record(&name, &rtype, kss).await.unwrap_or_else(|e| {
                                warn!("record check failed: {e}");
                                false
                            });
                            if !res {
                                let next = UnixTime::now() + ttl.into();
                                let mut report_state_locked =
                                    report_state.lock().expect("lock() should not fail");
                                report_state_locked.rrsig =
                                    Some(AutoReportRrsigResult::WaitRecord {
                                        next: next.clone(),
                                        name: name.clone(),
                                        rtype,
                                        ttl,
                                    });
                                drop(report_state_locked);
                                *state_changed = true;
                                return AutoActionsResult::Wait(next);
                            }

                            // This record has the right signatures. Check
                            // the zone.
                        }
                        AutoReportRrsigResult::WaitNextSerial { next, serial, ttl } => {
                            if next > UnixTime::now() {
                                return AutoActionsResult::Wait(next.clone());
                            }
                            let res = check_next_serial(serial, kss).await.unwrap_or_else(|e| {
                                warn!("next serial check failed: {e}");
                                false
                            });
                            if !res {
                                let next = UnixTime::now() + ttl.into();
                                let mut report_state_locked =
                                    report_state.lock().expect("lock() should not fail");
                                report_state_locked.rrsig =
                                    Some(AutoReportRrsigResult::WaitNextSerial {
                                        next: next.clone(),
                                        serial,
                                        ttl,
                                    });
                                drop(report_state_locked);
                                *state_changed = true;
                                return AutoActionsResult::Wait(next);
                            }

                            // A new serial. Check the zone.
                        }
                    }
                }

                let result = report_rrsig_propagated(kss).await.unwrap_or_else(|e| {
                    warn!("Check RRSIG propagation failed: {e}");
                    AutoReportRrsigResult::Wait(UnixTime::now() + DEFAULT_WAIT)
                });

                let mut report_state_locked = report_state.lock().expect("lock() should not fail");
                dbg!("Setting rrsig to WaitSoa");
                report_state_locked.rrsig = Some(result.clone());
                drop(report_state_locked);
                *state_changed = true;

                match result {
                    AutoReportRrsigResult::Wait(next)
                    | AutoReportRrsigResult::WaitRecord { next, .. }
                    | AutoReportRrsigResult::WaitNextSerial { next, .. }
                    | AutoReportRrsigResult::WaitSoa { next, .. } => {
                        return AutoActionsResult::Wait(next)
                    }
                    AutoReportRrsigResult::Report(_) => (),
                }
            }
            // These actions are not compatible with the 'done' state because
            // the 'done' state does not report anything, it can only wait.
            Action::ReportDnskeyPropagated
            | Action::ReportDsPropagated
            | Action::ReportRrsigPropagated => unreachable!(),
        }
    }
    AutoActionsResult::Ok
}

/// Handle automatic report actions.
async fn auto_report_actions(
    actions: &[Action],
    kss: &KeySetState,
    report_state: &Mutex<ReportState>,
    state_changed: &mut bool,
) -> AutoReportActionsResult {
    assert!(!actions.is_empty());
    let mut max_ttl = Ttl::from_secs(0);
    for a in actions {
        match a {
            Action::ReportDnskeyPropagated => {
                // Clippy problem
                {
                    let report_state_locked = report_state.lock().expect("lock() should not fail");
                    if let Some(dnskey_status) = &report_state_locked.dnskey {
                        match dnskey_status {
                            AutoReportActionsResult::Wait(next) => {
                                if *next > UnixTime::now() {
                                    return dnskey_status.clone();
                                }
                            }
                            AutoReportActionsResult::Report(ttl) => {
                                max_ttl = max(max_ttl, *ttl);
                                continue;
                            }
                        }
                    }
                    drop(report_state_locked);
                }

                let result = report_dnskey_propagated(kss).await;

                let mut report_state_locked = report_state.lock().expect("lock() should not fail");
                report_state_locked.dnskey = Some(result.clone());
                drop(report_state_locked);
                *state_changed = true;

                match result {
                    AutoReportActionsResult::Wait(_) => return result,
                    AutoReportActionsResult::Report(ttl) => {
                        max_ttl = max(max_ttl, ttl);
                    }
                }
            }
            Action::ReportDsPropagated => {
                // Clippy problem
                {
                    let report_state_locked = report_state.lock().expect("lock() should not fail");
                    if let Some(ds_status) = &report_state_locked.ds {
                        match ds_status {
                            AutoReportActionsResult::Wait(next) => {
                                if *next > UnixTime::now() {
                                    return ds_status.clone();
                                }
                            }
                            AutoReportActionsResult::Report(ttl) => {
                                max_ttl = max(max_ttl, *ttl);
                                continue;
                            }
                        }
                    }
                    drop(report_state_locked);
                }

                let result = report_ds_propagated(kss).await.unwrap_or_else(|e| {
                    warn!("Check DS propagation failed: {e}");
                    AutoReportActionsResult::Wait(UnixTime::now() + DEFAULT_WAIT)
                });

                let mut report_state_locked = report_state.lock().expect("lock() should not fail");
                report_state_locked.ds = Some(result.clone());
                drop(report_state_locked);
                *state_changed = true;

                match result {
                    AutoReportActionsResult::Wait(_) => return result,
                    AutoReportActionsResult::Report(ttl) => {
                        max_ttl = max(max_ttl, ttl);
                    }
                }
            }
            Action::ReportRrsigPropagated => {
                // Clippy problem
                let opt_rrsig_status = {
                    let report_state_locked = report_state.lock().expect("lock() should not fail");
                    // Make a copy of the state. We need to release the lock
                    // before calling await.
                    let opt_rrsig_status = report_state_locked.rrsig.clone();
                    drop(report_state_locked);
                    opt_rrsig_status
                };

                if let Some(rrsig_status) = opt_rrsig_status {
                    match rrsig_status {
                        AutoReportRrsigResult::Wait(next) => {
                            if next > UnixTime::now() {
                                return AutoReportActionsResult::Wait(next.clone());
                            }
                        }
                        AutoReportRrsigResult::Report(ttl) => {
                            max_ttl = max(max_ttl, ttl);
                            continue;
                        }
                        AutoReportRrsigResult::WaitSoa {
                            next,
                            serial,
                            ttl,
                            report_ttl,
                        } => {
                            if next > UnixTime::now() {
                                return AutoReportActionsResult::Wait(next.clone());
                            }
                            let res = check_soa(serial, kss).await.unwrap_or_else(|e| {
                                warn!("Check SOA propagation failed: {e}");
                                false
                            });
                            dbg!(format!("got {res} for {serial}"));
                            if res {
                                dbg!("Setting rrsig to Report");
                                let mut report_state_locked =
                                    report_state.lock().expect("lock() should not fail");
                                report_state_locked.rrsig =
                                    Some(AutoReportRrsigResult::Report(report_ttl));
                                drop(report_state_locked);
                                *state_changed = true;
                                max_ttl = max(max_ttl, report_ttl);
                                continue;
                            } else {
                                let next = UnixTime::now() + ttl.into();
                                dbg!("Setting rrsig to WaitSoa");
                                let mut report_state_locked =
                                    report_state.lock().expect("lock() should not fail");
                                report_state_locked.rrsig = Some(AutoReportRrsigResult::WaitSoa {
                                    next: next.clone(),
                                    serial,
                                    ttl,
                                    report_ttl,
                                });
                                drop(report_state_locked);
                                *state_changed = true;
                                return AutoReportActionsResult::Wait(next);
                            }
                        }
                        AutoReportRrsigResult::WaitRecord {
                            next,
                            name,
                            rtype,
                            ttl,
                        } => {
                            if next > UnixTime::now() {
                                return AutoReportActionsResult::Wait(next.clone());
                            }
                            let res = check_record(&name, &rtype, kss).await.unwrap_or_else(|e| {
                                warn!("record check failed: {e}");
                                false
                            });
                            if !res {
                                let next = UnixTime::now() + ttl.into();
                                let mut report_state_locked =
                                    report_state.lock().expect("lock() should not fail");
                                report_state_locked.rrsig =
                                    Some(AutoReportRrsigResult::WaitRecord {
                                        next: next.clone(),
                                        name: name.clone(),
                                        rtype,
                                        ttl,
                                    });
                                drop(report_state_locked);
                                *state_changed = true;
                                return AutoReportActionsResult::Wait(next);
                            }

                            // This record has the right signatures. Check
                            // the zone.
                        }
                        AutoReportRrsigResult::WaitNextSerial { next, serial, ttl } => {
                            if next > UnixTime::now() {
                                return AutoReportActionsResult::Wait(next.clone());
                            }
                            let res = check_next_serial(serial, kss).await.unwrap_or_else(|e| {
                                warn!("next serial check failed: {e}");
                                false
                            });
                            if !res {
                                let next = UnixTime::now() + ttl.into();
                                let mut report_state_locked =
                                    report_state.lock().expect("lock() should not fail");
                                report_state_locked.rrsig =
                                    Some(AutoReportRrsigResult::WaitNextSerial {
                                        next: next.clone(),
                                        serial,
                                        ttl,
                                    });
                                drop(report_state_locked);
                                *state_changed = true;
                                return AutoReportActionsResult::Wait(next);
                            }

                            // A new serial. Check the zone.
                        }
                    }
                }

                let result = report_rrsig_propagated(kss).await.unwrap_or_else(|e| {
                    warn!("Check RRSIG propagation failed: {e}");
                    AutoReportRrsigResult::Wait(UnixTime::now() + DEFAULT_WAIT)
                });

                let mut report_state_locked = report_state.lock().expect("lock() should not fail");
                dbg!("Setting rrsig to WaitSoa");
                report_state_locked.rrsig = Some(result.clone());
                drop(report_state_locked);
                *state_changed = true;

                match result {
                    AutoReportRrsigResult::Wait(next)
                    | AutoReportRrsigResult::WaitRecord { next, .. }
                    | AutoReportRrsigResult::WaitNextSerial { next, .. }
                    | AutoReportRrsigResult::WaitSoa { next, .. } => {
                        return AutoReportActionsResult::Wait(next)
                    }
                    AutoReportRrsigResult::Report(ttl) => {
                        max_ttl = max(max_ttl, ttl);
                    }
                }
            }
            Action::UpdateDnskeyRrset
            | Action::CreateCdsRrset
            | Action::RemoveCdsRrset
            | Action::UpdateDsRrset
            | Action::UpdateRrsig => (),

            // These actions should not occur here. Actions in this functions
            // need to be no-ops or report a TTL. Wait actions are not
            // compatible with this.
            Action::WaitDnskeyPropagated
            | Action::WaitDsPropagated
            | Action::WaitRrsigPropagated => unreachable!(),
        }
    }
    AutoReportActionsResult::Report(max_ttl)
}

/// Check whether automatic actions are done or not. If not, return until
/// when to wait to try again.
fn check_auto_actions(actions: &[Action], report_state: &Mutex<ReportState>) -> AutoActionsResult {
    for a in actions {
        match a {
            Action::UpdateDnskeyRrset
            | Action::CreateCdsRrset
            | Action::RemoveCdsRrset
            | Action::UpdateDsRrset
            | Action::UpdateRrsig => (),
            Action::ReportDnskeyPropagated | Action::WaitDnskeyPropagated => {
                let report_state_locked = report_state.lock().expect("lock() should not fail");
                if let Some(dnskey_status) = &report_state_locked.dnskey {
                    match dnskey_status {
                        AutoReportActionsResult::Wait(next) => {
                            return AutoActionsResult::Wait(next.clone())
                        }
                        AutoReportActionsResult::Report(_) => continue,
                    }
                }
                drop(report_state_locked);

                // No status, request cron
                return AutoActionsResult::Wait(UnixTime::now());
            }
            Action::ReportDsPropagated | Action::WaitDsPropagated => {
                let report_state_locked = report_state.lock().expect("lock() should not fail");
                if let Some(ds_status) = &report_state_locked.ds {
                    match ds_status {
                        AutoReportActionsResult::Wait(next) => {
                            return AutoActionsResult::Wait(next.clone())
                        }
                        AutoReportActionsResult::Report(_) => continue,
                    }
                }
                drop(report_state_locked);

                // No status, request cron
                return AutoActionsResult::Wait(UnixTime::now());
            }
            Action::ReportRrsigPropagated | Action::WaitRrsigPropagated => {
                let report_state_locked = report_state.lock().expect("lock() should not fail");
                if let Some(rrsig_status) = &report_state_locked.rrsig {
                    match rrsig_status {
                        AutoReportRrsigResult::Wait(next)
                        | AutoReportRrsigResult::WaitRecord { next, .. }
                        | AutoReportRrsigResult::WaitNextSerial { next, .. }
                        | AutoReportRrsigResult::WaitSoa { next, .. } => {
                            return AutoActionsResult::Wait(next.clone())
                        }
                        AutoReportRrsigResult::Report(_) => continue,
                    }
                }
                drop(report_state_locked);

                // No status, request cron
                return AutoActionsResult::Wait(UnixTime::now());
            }
        }
    }
    AutoActionsResult::Ok
}

/// Execute the done action.
fn do_done(kss: &mut KeySetState, roll_type: RollType, autoremove: bool) -> Result<(), Error> {
    let actions = kss.keyset.roll_done(roll_type);

    let actions = match actions {
        Ok(actions) => actions,
        Err(err) => {
            return Err(format!("Error reporting done: {err}\n").into());
        }
    };

    if !actions.is_empty() {
        return Err("List of actions after reporting done\n".into());
    }

    // Sometimes there is no space for a RemoveCdsRrset action. Just remove
    // it anyhow.
    remove_cds_rrset(kss);

    kss.internal.remove(&roll_type);

    // Remove old keys.
    if autoremove {
        let files: Vec<_> = kss
            .keyset
            .keys()
            .iter()
            .filter(|(_, key)| {
                let state = match key.keytype() {
                    KeyType::Ksk(state) => state,
                    KeyType::Zsk(state) => state,
                    KeyType::Csk(state, _) => state,
                    KeyType::Include(state) => state,
                };
                state.stale()
            })
            .map(|(pubref, key)| (pubref.clone(), key.privref().map(|r| r.to_string())))
            .collect();
        if !files.is_empty() {
            print!("Removing:");
            for f in files {
                let (pubkey, privkey) = &f;
                print!(" {pubkey}");
                kss.keyset.delete_key(pubkey).map_err::<Error, _>(|e| {
                    format!("unable to remove key {pubkey}: {e}\n").into()
                })?;
                remove_file(pubkey).map_err::<Error, _>(|e| {
                    format!("unable to remove file {pubkey}: {e}\n").into()
                })?;
                if let Some(privkey) = privkey {
                    print!(" {privkey}");
                    remove_file(privkey).map_err::<Error, _>(|e| {
                        format!("unable to remove file {privkey}: {e}\n").into()
                    })?;
                }
            }
            println!();
        }
    }
    Ok(())
}

/// Start a KSK roll.
fn start_ksk_roll(
    ksc: &KeySetConfig,
    kss: &mut KeySetState,
    env: &impl Env,
) -> Result<Vec<Action>, Error> {
    let roll_type = RollType::KskRoll;

    assert!(!kss.keyset.keys().is_empty());

    // Check for CSK.
    if ksc.use_csk {
        return Err("wrong key roll, use start-csk-roll\n".into());
    }

    // Refuse if we can find a CSK key.
    if kss.keyset.keys().iter().any(|(_, key)| {
        if let KeyType::Csk(keystate, _) = key.keytype() {
            !keystate.stale()
        } else {
            false
        }
    }) {
        return Err(format!("cannot start {roll_type:?} roll, found CSK\n").into());
    }

    // Find existing KSKs. Do we complain if there is none?
    let old_stored: Vec<_> = kss
        .keyset
        .keys()
        .iter()
        .filter(|(_, key)| {
            if let KeyType::Ksk(keystate) = key.keytype() {
                !keystate.stale()
            } else {
                false
            }
        })
        .map(|(name, _)| name.clone())
        .collect();
    let old: Vec<_> = old_stored.iter().map(|name| name.as_ref()).collect();

    // Create a new KSK
    let (ksk_pub_url, ksk_priv_url, algorithm, key_tag) = new_keys(
        kss.keyset.name(),
        ksc.algorithm.to_generate_params(),
        true,
        kss.keyset.keys(),
        &ksc.keys_dir,
        env,
    )?;
    kss.keyset
        .add_key_ksk(
            ksk_pub_url.to_string(),
            Some(ksk_priv_url.to_string()),
            algorithm,
            key_tag,
            UnixTime::now(),
            true,
        )
        .map_err::<Error, _>(|e| format!("unable to add KSK {ksk_pub_url}: {e}\n").into())?;

    let new = [ksk_pub_url.as_ref()];

    // Start the key roll
    let actions = match kss
        .keyset
        .start_roll(roll_type, &old, &new)
        .map_err::<Error, _>(|e| format!("cannot start {roll_type:?}: {e}\n").into())
    {
        Ok(actions) => actions,
        Err(e) => {
            // Remove the key files we just created.
            if ksk_priv_url.scheme() == "file" {
                remove_file(ksk_priv_url.path()).map_err::<Error, _>(|e| {
                    format!("unable to remove private key file {ksk_priv_url}: {e}\n").into()
                })?;
            } else {
                panic!("unsupported URL scheme in {ksk_priv_url}");
            }

            if ksk_pub_url.scheme() == "file" {
                remove_file(ksk_pub_url.path()).map_err::<Error, _>(|e| {
                    format!("unable to remove public key file {ksk_pub_url}: {e}\n").into()
                })?;
            } else {
                panic!("unsupported URL scheme in {ksk_pub_url}");
            }

            return Err(e);
        }
    };
    handle_actions(&actions, ksc, kss, env)?;
    kss.internal.insert(roll_type, Default::default());
    Ok(actions)
}

/// Start a ZSK roll.
fn start_zsk_roll(
    ksc: &KeySetConfig,
    kss: &mut KeySetState,
    env: &impl Env,
) -> Result<Vec<Action>, Error> {
    let roll_type = RollType::ZskRoll;

    assert!(!kss.keyset.keys().is_empty());

    // Check for CSK.
    if ksc.use_csk {
        return Err("wrong key roll, use start-csk-roll\n".into());
    }

    // Refuse if we can find a CSK key.
    if kss.keyset.keys().iter().any(|(_, key)| {
        if let KeyType::Csk(keystate, _) = key.keytype() {
            !keystate.stale()
        } else {
            false
        }
    }) {
        return Err(format!("cannot start {roll_type:?} roll, found CSK\n").into());
    }

    // Find existing ZSKs. Do we complain if there is none?
    let old_stored: Vec<_> = kss
        .keyset
        .keys()
        .iter()
        .filter(|(_, key)| {
            if let KeyType::Zsk(keystate) = key.keytype() {
                !keystate.stale()
            } else {
                false
            }
        })
        .map(|(name, _)| name.clone())
        .collect();
    let old: Vec<_> = old_stored.iter().map(|name| name.as_ref()).collect();

    // Collect algorithms. Maybe this needs to be in the library.

    // Create a new ZSK
    let (zsk_pub_url, zsk_priv_url, algorithm, key_tag) = new_keys(
        kss.keyset.name(),
        ksc.algorithm.to_generate_params(),
        false,
        kss.keyset.keys(),
        &ksc.keys_dir,
        env,
    )?;
    kss.keyset
        .add_key_zsk(
            zsk_pub_url.to_string(),
            Some(zsk_priv_url.to_string()),
            algorithm,
            key_tag,
            UnixTime::now(),
            true,
        )
        .map_err::<Error, _>(|e| format!("unable to add ZSK {zsk_pub_url}: {e}\n").into())?;

    let new = [zsk_pub_url.as_ref()];

    // Start the key roll
    let actions = match kss
        .keyset
        .start_roll(roll_type, &old, &new)
        .map_err::<Error, _>(|e| format!("cannot start {roll_type:?}: {e}\n").into())
    {
        Ok(actions) => actions,
        Err(e) => {
            // Remove the key files we just created.
            if zsk_priv_url.scheme() == "file" {
                remove_file(zsk_priv_url.path()).map_err::<Error, _>(|e| {
                    format!("unable to remove private key file {zsk_priv_url}: {e}\n").into()
                })?;
            } else {
                panic!("unsupported URL scheme in {zsk_priv_url}");
            }
            if zsk_pub_url.scheme() == "file" {
                remove_file(zsk_pub_url.path()).map_err::<Error, _>(|e| {
                    format!("unable to remove public key file {zsk_pub_url}: {e}\n").into()
                })?;
            } else {
                panic!("unsupported URL scheme in {zsk_pub_url}");
            }
            return Err(e);
        }
    };

    handle_actions(&actions, ksc, kss, env)?;
    kss.internal.insert(roll_type, Default::default());
    Ok(actions)
}

/// Start a CSK roll.
fn start_csk_roll(
    ksc: &KeySetConfig,
    kss: &mut KeySetState,
    env: &impl Env,
) -> Result<Vec<Action>, Error> {
    let roll_type = RollType::CskRoll;

    assert!(!kss.keyset.keys().is_empty());

    // Find existing KSKs, ZSKs and CSKs. Do we complain if there
    // are none?
    let old_stored: Vec<_> = kss
        .keyset
        .keys()
        .iter()
        .filter(|(_, key)| match key.keytype() {
            KeyType::Ksk(keystate) | KeyType::Zsk(keystate) | KeyType::Csk(keystate, _) => {
                // Assume that for a CSK it is sufficient to check
                // one of the key states. Also assume that we
                // can check at_parent for a ZSK.
                !keystate.stale()
            }
            KeyType::Include(_) => false,
        })
        .map(|(name, _)| name.clone())
        .collect();
    let old: Vec<_> = old_stored.iter().map(|name| name.as_ref()).collect();

    // Collect algorithms. Maybe this needs to be in the library.

    let (new_stored, new_urls) = if ksc.use_csk {
        let mut new_urls = Vec::new();

        // Create a new CSK
        let (csk_pub_url, csk_priv_url, algorithm, key_tag) = new_keys(
            kss.keyset.name(),
            ksc.algorithm.to_generate_params(),
            true,
            kss.keyset.keys(),
            &ksc.keys_dir,
            env,
        )?;
        new_urls.push(csk_priv_url.clone());
        new_urls.push(csk_pub_url.clone());
        kss.keyset
            .add_key_csk(
                csk_pub_url.to_string(),
                Some(csk_priv_url.to_string()),
                algorithm,
                key_tag,
                UnixTime::now(),
                true,
            )
            .map_err::<Error, _>(|e| format!("unable to add CSK {csk_pub_url}: {e}\n").into())?;

        let new = vec![csk_pub_url];
        (new, new_urls)
    } else {
        let mut new_urls = Vec::new();

        // Create a new KSK
        let (ksk_pub_url, ksk_priv_url, algorithm, key_tag) = new_keys(
            kss.keyset.name(),
            ksc.algorithm.to_generate_params(),
            true,
            kss.keyset.keys(),
            &ksc.keys_dir,
            env,
        )?;
        new_urls.push(ksk_priv_url.clone());
        new_urls.push(ksk_pub_url.clone());
        kss.keyset
            .add_key_ksk(
                ksk_pub_url.to_string(),
                Some(ksk_priv_url.to_string()),
                algorithm,
                key_tag,
                UnixTime::now(),
                true,
            )
            .map_err::<Error, _>(|e| format!("unable to add KSK {ksk_pub_url}: {e}\n").into())?;

        // Create a new ZSK
        let (zsk_pub_url, zsk_priv_url, algorithm, key_tag) = new_keys(
            kss.keyset.name(),
            ksc.algorithm.to_generate_params(),
            false,
            kss.keyset.keys(),
            &ksc.keys_dir,
            env,
        )?;
        new_urls.push(zsk_priv_url.clone());
        new_urls.push(zsk_pub_url.clone());
        kss.keyset
            .add_key_zsk(
                zsk_pub_url.to_string(),
                Some(zsk_priv_url.to_string()),
                algorithm,
                key_tag,
                UnixTime::now(),
                true,
            )
            .map_err::<Error, _>(|e| format!("unable to add ZSK {zsk_pub_url}: {e}\n").into())?;

        let new = vec![ksk_pub_url, zsk_pub_url];
        (new, new_urls)
    };

    let new: Vec<_> = new_stored.iter().map(|v| v.as_ref()).collect();

    // Start the key roll
    let actions = match kss
        .keyset
        .start_roll(roll_type, &old, &new)
        .map_err::<Error, _>(|e| format!("cannot start {roll_type:?}: {e}\n").into())
    {
        Ok(actions) => actions,
        Err(e) => {
            // Remove the key files we just created.
            for u in new_urls {
                if u.scheme() == "file" {
                    remove_file(u.path()).map_err::<Error, _>(|e| {
                        format!("unable to remove private key file {u}: {e}\n").into()
                    })?;
                } else {
                    panic!("unsupported URL scheme in {u}");
                }
            }
            return Err(e);
        }
    };

    handle_actions(&actions, ksc, kss, env)?;
    kss.internal.insert(roll_type, Default::default());
    Ok(actions)
}

/// Start an algorithm roll.
fn start_algorithm_roll(
    ksc: &KeySetConfig,
    kss: &mut KeySetState,
    env: &impl Env,
) -> Result<Vec<Action>, Error> {
    let roll_type = RollType::AlgorithmRoll;

    assert!(!kss.keyset.keys().is_empty());

    // Find existing KSKs, ZSKs and CSKs. Do we complain if there
    // are none?
    let old_stored: Vec<_> = kss
        .keyset
        .keys()
        .iter()
        .filter(|(_, key)| match key.keytype() {
            KeyType::Ksk(keystate) | KeyType::Zsk(keystate) | KeyType::Csk(keystate, _) => {
                // Assume that for a CSK it is sufficient to check
                // one of the key states. Also assume that we
                // can check at_parent for a ZSK.
                !keystate.stale()
            }
            KeyType::Include(_) => false,
        })
        .map(|(name, _)| name.clone())
        .collect();
    let old: Vec<_> = old_stored.iter().map(|name| name.as_ref()).collect();

    let (new_stored, new_urls) = if ksc.use_csk {
        let mut new_urls = Vec::new();

        // Create a new CSK
        let (csk_pub_url, csk_priv_url, algorithm, key_tag) = new_keys(
            kss.keyset.name(),
            ksc.algorithm.to_generate_params(),
            true,
            kss.keyset.keys(),
            &ksc.keys_dir,
            env,
        )?;
        new_urls.push(csk_priv_url.clone());
        new_urls.push(csk_pub_url.clone());
        kss.keyset
            .add_key_csk(
                csk_pub_url.to_string(),
                Some(csk_priv_url.to_string()),
                algorithm,
                key_tag,
                UnixTime::now(),
                true,
            )
            .map_err::<Error, _>(|e| format!("unable to add CSK {csk_pub_url}: {e}\n").into())?;

        let new = vec![csk_pub_url];
        (new, new_urls)
    } else {
        let mut new_urls = Vec::new();

        // Create a new KSK
        let (ksk_pub_url, ksk_priv_url, algorithm, key_tag) = new_keys(
            kss.keyset.name(),
            ksc.algorithm.to_generate_params(),
            true,
            kss.keyset.keys(),
            &ksc.keys_dir,
            env,
        )?;
        new_urls.push(ksk_priv_url.clone());
        new_urls.push(ksk_pub_url.clone());
        kss.keyset
            .add_key_ksk(
                ksk_pub_url.to_string(),
                Some(ksk_priv_url.to_string()),
                algorithm,
                key_tag,
                UnixTime::now(),
                true,
            )
            .map_err::<Error, _>(|e| format!("unable to add KSK {ksk_pub_url}: {e}\n").into())?;

        // Create a new ZSK
        let (zsk_pub_url, zsk_priv_url, algorithm, key_tag) = new_keys(
            kss.keyset.name(),
            ksc.algorithm.to_generate_params(),
            false,
            kss.keyset.keys(),
            &ksc.keys_dir,
            env,
        )?;
        new_urls.push(zsk_priv_url.clone());
        new_urls.push(zsk_pub_url.clone());
        kss.keyset
            .add_key_zsk(
                zsk_pub_url.to_string(),
                Some(zsk_priv_url.to_string()),
                algorithm,
                key_tag,
                UnixTime::now(),
                true,
            )
            .map_err::<Error, _>(|e| format!("unable to add ZSK {zsk_pub_url}: {e}\n").into())?;

        let new = vec![ksk_pub_url, zsk_pub_url];
        (new, new_urls)
    };

    let new: Vec<_> = new_stored.iter().map(|v| v.as_ref()).collect();

    // Start the key roll
    let actions = match kss
        .keyset
        .start_roll(roll_type, &old, &new)
        .map_err::<Error, _>(|e| format!("cannot start roll: {e}\n").into())
    {
        Ok(actions) => actions,
        Err(e) => {
            // Remove the key files we just created.
            for u in new_urls {
                if u.scheme() == "file" {
                    remove_file(u.path()).map_err::<Error, _>(|e| {
                        format!("unable to private key file {u}: {e}\n").into()
                    })?;
                } else {
                    panic!("unsupported scheme in {u}");
                }
            }
            return Err(e);
        }
    };

    handle_actions(&actions, ksc, kss, env)?;
    kss.internal.insert(roll_type, Default::default());
    Ok(actions)
}

/// Check whether a new DNSKEY RRset has propagated.
///
/// Compile a list of nameservers for the zone and their addresses and
/// query each address for the DNSKEY RRset. The function
/// check_dnskey_for_address does the actual work.
async fn report_dnskey_propagated(kss: &KeySetState) -> AutoReportActionsResult {
    // Convert the DNSKEY RRset plus RRSIGs into a HashSet.
    // Find the address of all name servers of zone
    // Ask each nameserver for the DNSKEY RRset. Check if it matches the
    // one we want.
    // If it doesn't match, wait the TTL of the RRset to try again.
    // On error, wait a default time.
    let mut target_dnskey: HashSet<RecordZoneRecordData> = HashSet::new();
    for dnskey_rr in &kss.dnskey_rrset {
        let mut zonefile = Zonefile::new();
        zonefile.extend_from_slice(dnskey_rr.as_bytes());
        zonefile.extend_from_slice(b"\n");
        if let Ok(Some(Entry::Record(rec))) = zonefile.next_entry() {
            target_dnskey.insert(rec.flatten_into());
        }
    }

    let zone = kss.keyset.name();
    let addresses = match addresses_for_zone(zone).await {
        Ok(a) => a,
        Err(e) => {
            warn!("Getting nameserver addresses for {zone} failed: {e}");
            return AutoReportActionsResult::Wait(UnixTime::now() + DEFAULT_WAIT);
        }
    };
    dbg!(&addresses);

    // addresses_for_zone returns at least one address.
    assert!(!addresses.is_empty());

    let futures: Vec<_> = addresses
        .iter()
        .map(|a| check_dnskey_for_address(zone, a, target_dnskey.clone()))
        .collect();
    let res: Vec<_> = join_all(futures).await;

    // Be paranoid. The variable max_ttl is set to None initially to make
    // sure that we only return a value if something has been assigned
    // during the loop.
    let mut max_ttl = None;
    for r in res {
        let r = match r {
            Ok(r) => r,
            Err(e) => {
                warn!("DNSKEY check failed: {e}");
                return AutoReportActionsResult::Wait(UnixTime::now() + DEFAULT_WAIT);
            }
        };
        match r {
            // It doesn't really matter how long we have to wait.
            AutoReportActionsResult::Wait(_) => return r,
            AutoReportActionsResult::Report(ttl) => {
                max_ttl = Some(max(max_ttl.unwrap_or(Ttl::from_secs(0)), ttl));
            }
        }
    }

    // We can only get here with Some(Ttl) because there is at least one
    // address.
    let max_ttl = max_ttl.expect("cannot be None");
    AutoReportActionsResult::Report(max_ttl)
}

/// Check whether the parent zone has a DS RRset that matches the keys
/// with 'at_parent' equal to true.
///
/// Compile a list of nameservers for the parent zone and their addresses and
/// query each address for the DS RRset. The function
/// check_ds_for_address does the actual work. The CDNSKEY RRset is
/// used as the reference for the DS RRset.
async fn report_ds_propagated(kss: &KeySetState) -> Result<AutoReportActionsResult, Error> {
    // Convert the CDNSKEY RRset into a HashSet.
    // Find the name of the parent zone.
    // Find the address of all name servers of the parent zone.
    // Ask each nameserver for the DS RRset. Check if it matches the
    // one we want.
    // If it doesn't match, wait the TTL of the RRset to try again.
    // On error, wait a default time.

    let mut target_dnskey: HashSet<RecordDnskey> = HashSet::new();
    for cdnskey_rr in &kss.cds_rrset {
        let mut zonefile = Zonefile::new();
        zonefile.extend_from_slice(cdnskey_rr.as_bytes());
        zonefile.extend_from_slice(b"\n");
        if let Ok(Some(Entry::Record(r))) = zonefile.next_entry() {
            if let ZoneRecordData::Cdnskey(cdnskey) = r.data() {
                let dnskey = Dnskey::<Vec<u8>>::new(
                    cdnskey.flags(),
                    cdnskey.protocol(),
                    cdnskey.algorithm(),
                    cdnskey.public_key().to_vec(),
                )
                .expect("should not fail");
                let record = Record::new(r.owner().to_name(), r.class(), r.ttl(), dnskey);
                target_dnskey.insert(record);
            }
        }
    }

    let zone = kss.keyset.name();
    let parent_zone = parent_zone(zone).await?;
    let addresses = addresses_for_zone(&parent_zone).await?;
    dbg!(&addresses);

    // addresses_for_zone returns at least one address.
    assert!(!addresses.is_empty());

    let futures: Vec<_> = addresses
        .iter()
        .map(|a| check_ds_for_address(zone, a, target_dnskey.clone()))
        .collect();
    let res: Vec<_> = join_all(futures).await;
    let mut max_ttl = None;
    for r in res {
        let r = r?;
        match r {
            // It doesn't really matter how long we have to wait.
            AutoReportActionsResult::Wait(_) => return Ok(r),
            AutoReportActionsResult::Report(ttl) => {
                max_ttl = Some(max(max_ttl.unwrap_or(Ttl::from_secs(0)), ttl));
            }
        }
    }

    // We can only get here with Some(Ttl) because there is at least one
    // address.
    let max_ttl = max_ttl.expect("cannot be None");
    Ok(AutoReportActionsResult::Report(max_ttl))
}

/// Report whether all RRSIGs (except for the ones that are copied from
/// keyset state) have been updated.
///
/// The basic process is to send an AXFR query to the primary nameserver and
/// check the zone. If the zone checks out, very that all of the nameservers
/// of the zone have the checked SOA serial or newer. If a (name, rtype) tuple
/// is found with the wrong signatures then keep checking that name, rtype
/// combination until the right signatures are found. Then go back to checking
/// the entire zone. NSEC3 is special because it is not possible to directly
/// query for NSEC3 records. In that case, wait for high SOA serial and check
/// the entire zone again.
async fn report_rrsig_propagated(kss: &KeySetState) -> Result<AutoReportRrsigResult, Error> {
    // This function assume a single signer. Multi-signer is not supported
    // at all, but any kind of active-passive or active-active setup would also
    // need changes. With more than one signer, each signer needs to be
    // checked explicitly. Then for all nameservers it needs to be checked
    // that their SOA versions are at least as high as all of the signers.
    // Check the zone. If the zone checks out, make sure that all nameservers
    // have at least the version of the zone that was checked.

    let result = check_zone(kss).await?;
    let (serial, ttl, report_ttl) = match result {
        // check_zone never returns Report or Wait.
        AutoReportRrsigResult::Report(_) | AutoReportRrsigResult::Wait(_) => unreachable!(),
        AutoReportRrsigResult::WaitSoa {
            serial,
            ttl,
            report_ttl,
            ..
        } => (serial, ttl, report_ttl),
        AutoReportRrsigResult::WaitRecord { .. } | AutoReportRrsigResult::WaitNextSerial { .. } => {
            return Ok(result)
        }
    };

    Ok(
        if check_soa(serial, kss).await.unwrap_or_else(|e| {
            warn!("Check SOA propagation failed: {e}");
            false
        }) {
            AutoReportRrsigResult::Report(report_ttl)
        } else {
            AutoReportRrsigResult::WaitSoa {
                next: UnixTime::now() + ttl.into(),
                serial,
                ttl,
                report_ttl,
            }
        },
    )
}

/// Check whether the zone has signatures from the right keys.
///
/// Collect the ZSK algorithm and key tags into a HashSet
/// Get the primary nameserver from the SOA record (this should become
/// a configuration option for the nameserver and any TSIG key to use).
/// Transfer the zone.
/// Assume the signer is correct.
/// Convert the RRSIGs into a HashMap with (name, type) as key and a HashSet
/// of (algorithm, key tag) as value.
/// Convert the other records into a BtreeMap with name as key and
/// a HashSet of type as the value. Check that each name and type has a
/// corresponding complete RRSIG set.
/// Ignore delegated records
async fn check_zone(kss: &KeySetState) -> Result<AutoReportRrsigResult, Error> {
    let expected_set = get_expected_zsk_key_tags(kss);

    let zone = kss.keyset.name();

    let resolver = StubResolver::new();
    let answer = resolver.query((zone, Rtype::SOA)).await?;
    dbg!(&answer.answer());
    let Some(Ok((mname, mut serial))) = answer
        .answer()?
        .limit_to_in::<Soa<_>>()
        .map(|r| r.map(|r| (r.data().mname().clone(), r.data().serial())))
        .next()
    else {
        let rcode = answer.opt_rcode();
        return if rcode != OptRcode::NOERROR {
            Err(format!("Unable to resolve {zone}/SOA: {rcode}").into())
        } else {
            Err(format!("No result for {zone}/SOA").into())
        };
    };

    let addresses = addresses_for_name(&resolver, mname).await?;

    'addr: for a in &addresses {
        let tcp_conn = match TcpStream::connect((*a, 53_u16)).await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("DNS TCP connection to {a} failed: {e}");
                continue;
            }
        };

        let (tcp, transport) = stream::Connection::<RequestMessage<Vec<u8>>, _>::new(tcp_conn);
        tokio::spawn(transport.run());

        let msg = MessageBuilder::new_vec();
        let mut msg = msg.question();
        msg.push((zone, Rtype::AXFR)).expect("should not fail");
        let req = RequestMessageMulti::new(msg).expect("should not fail");

        // Send a request message.
        let mut request = SendRequestMulti::send_request(&tcp, req.clone());

        let mut treemap = BTreeMap::new();
        let mut sigmap = HashMap::new();

        let mut first_soa = false;
        let mut max_ttl = Ttl::from_secs(0);
        loop {
            // Get the reply
            let reply = match request.get_response().await {
                Ok(reply) => reply,
                Err(e) => {
                    warn!("reading AXFR response from {a} failed: {e}");
                    continue 'addr;
                }
            };
            let Some(reply) = reply else {
                return Err(format!("Unexpected end of AXFR for {zone}").into());
            };
            let rcode = reply.opt_rcode();
            if rcode != OptRcode::NOERROR {
                warn!("AXFR for {zone} from {a} failed: {rcode}");
                continue 'addr;
            }

            let answer = reply.answer()?;
            for r in answer {
                let r = r?;
                if !first_soa {
                    let Some(soa_record) = r.to_record::<Soa<_>>()? else {
                        // Bad start of zone transfer.
                        return Err(format!(
                            "Wrong start of AXFR for {zone}, expected SOA found {}",
                            r.rtype()
                        )
                        .into());
                    };

                    first_soa = true;
                    serial = soa_record.data().serial();
                } else if r.rtype() == Rtype::SOA {
                    // The end.
                    let res = check_rrsigs(treemap, sigmap, zone, expected_set);
                    return match res {
                        CheckRrsigsResult::Done => Ok(AutoReportRrsigResult::WaitSoa {
                            next: UnixTime::now(),
                            serial,
                            ttl: r.ttl(),
                            report_ttl: max_ttl,
                        }),
                        CheckRrsigsResult::WaitRecord { name, rtype } => {
                            Ok(AutoReportRrsigResult::WaitRecord {
                                next: UnixTime::now() + r.ttl().into(),
                                name,
                                rtype,
                                ttl: r.ttl(),
                            })
                        }
                        CheckRrsigsResult::WaitNextSerial => {
                            Ok(AutoReportRrsigResult::WaitNextSerial {
                                next: UnixTime::now() + r.ttl().into(),
                                serial,
                                ttl: r.ttl(),
                            })
                        }
                    };
                }

                let owner = r.owner().to_name();
                if let Some(rrsig_record) = r.to_record::<Rrsig<_, _>>()? {
                    let key = (owner, rrsig_record.data().type_covered());
                    let value = (
                        rrsig_record.data().algorithm(),
                        rrsig_record.data().key_tag(),
                    );
                    let alg_kt_map = sigmap.entry(key).or_insert_with(HashSet::new);
                    alg_kt_map.insert(value);
                    max_ttl = max(max_ttl, r.ttl());
                } else {
                    let key = owner;
                    let rtype_map = treemap.entry(key).or_insert_with(HashSet::new);
                    rtype_map.insert(r.rtype());
                }
            }
        }
    }

    Err(format!("AXFR for {zone} failed for all addresses {addresses:?}").into())
}

/// Return the set of addresses of the nameservers of a zone.
async fn addresses_for_zone(zone: &impl ToName) -> Result<HashSet<IpAddr>, Error> {
    // Paranoid solution:
    // Find nameserver addresses for the parent zone.
    // Iterate over those addresses and try to get a delegation.
    // Record all nameservers and glue addresses returned in the delegations.
    // Add offical address for those nameservers.
    // Iterate over the address and ask for the apex NS RRset. Add those
    // and address offical address for those nameservers.
    // Return the set of addresses.
    //
    // Current method, ask a resolver for the apex NS RRset. Loop over the
    // set and ask for addresses. Return the list of addresses.

    dbg!(zone.to_name::<Vec<u8>>());
    let mut nameservers = Vec::new();
    let resolver = StubResolver::new();
    let answer = resolver.query((zone, Rtype::NS)).await?;
    let rcode = answer.opt_rcode();
    if rcode != OptRcode::NOERROR {
        return Err(format!("{}/NS query failed: {rcode}", zone.to_name::<Vec<u8>>()).into());
    }
    dbg!(&answer.answer());
    for r in answer.answer()?.limit_to_in::<AllRecordData<_, _>>() {
        let r = r?;
        let AllRecordData::Ns(ns) = r.data() else {
            continue;
        };
        if *r.owner() != zone {
            continue;
        }
        nameservers.push(ns.nsdname().clone());
    }
    if nameservers.is_empty() {
        return Err(format!("{} has no NS records", zone.to_name::<Vec<u8>>()).into());
    }
    dbg!(&nameservers);

    let mut futures = Vec::new();
    for n in nameservers {
        futures.push(addresses_for_name(&resolver, n));
    }

    let mut set = HashSet::new();
    for a in join_all(futures).await.into_iter() {
        set.extend(match a {
            Ok(a) => a,
            Err(e) => {
                return Err(e);
            }
        });
    }
    Ok(set)
}

/// Return the IPv4 and IPv6 addresses associated with a name.
async fn addresses_for_name(
    resolver: &StubResolver,
    name: impl ToName,
) -> Result<Vec<IpAddr>, Error> {
    let res = lookup_host(&resolver, &name).await?;
    let res: Vec<_> = res.iter().collect();
    if res.is_empty() {
        return Err(format!("no IP addresses found for {}", name.to_name::<Vec<u8>>()).into());
    }
    Ok(res)
}

/// Check whether a nameserver at a specific address has the right DNSKEY
/// RRset plus signatures.
async fn check_dnskey_for_address(
    zone: &Name<Vec<u8>>,
    address: &IpAddr,
    mut target_dnskey: HashSet<RecordZoneRecordData>,
) -> Result<AutoReportActionsResult, Error> {
    let records = lookup_name_rtype_at_address(zone, Rtype::DNSKEY, address).await?;

    let mut max_ttl = Ttl::from_secs(0);

    for r in records {
        if let AllRecordData::Dnskey(dnskey) = r.data() {
            if r.owner() != zone {
                continue;
            }
            max_ttl = max(max_ttl, r.ttl());
            let target_r = target_dnskey.iter().find(|target_r| {
                if let ZoneRecordData::Dnskey(target_dnskey) = target_r.data() {
                    target_dnskey == dnskey
                } else {
                    false
                }
            });
            if let Some(record) = target_r {
                // Clone record to release target_dnskey.
                let record = record.clone();
                // Found one, remove it from the set.
                target_dnskey.remove(&record);
            } else {
                // The current record is not found in the target set. Wait
                // until the TTL has expired.
                debug!("Check DNSKEY RRset: DNSKEY record not expected");
                return Ok(AutoReportActionsResult::Wait(
                    UnixTime::now() + r.ttl().into_duration(),
                ));
            }
            continue;
        }
        if let AllRecordData::Rrsig(rrsig) = r.data() {
            if r.owner() != zone || rrsig.type_covered() != Rtype::DNSKEY {
                continue;
            }
            max_ttl = max(max_ttl, r.ttl());
            let target_r = target_dnskey.iter().find(|target_r| {
                if let ZoneRecordData::Rrsig(target_rrsig) = target_r.data() {
                    target_rrsig == rrsig
                } else {
                    false
                }
            });
            if let Some(record) = target_r {
                // Clone record to release target_dnskey.
                let record = record.clone();
                // Found one, remove it from the set.
                target_dnskey.remove(&record);
            } else {
                // The current record is not found in the target set. Wait
                // until the TTL has expired.
                debug!("Check DNSKEY RRset: RRSIG record not expected");
                return Ok(AutoReportActionsResult::Wait(
                    UnixTime::now() + r.ttl().into_duration(),
                ));
            }
            continue;
        }
    }
    if let Some(record) = target_dnskey.iter().next() {
        // Not all DNSKEY records were found.
        warn!("Not all required DNSKEY records were found for {zone}");
        Ok(AutoReportActionsResult::Wait(
            UnixTime::now() + record.ttl().into(),
        ))
    } else {
        Ok(AutoReportActionsResult::Report(max_ttl))
    }
}

/// Check whether a nameserver at a specific address has the right DS RRset.
async fn check_ds_for_address(
    zone: &Name<Vec<u8>>,
    address: &IpAddr,
    mut target_dnskey: HashSet<RecordDnskey>,
) -> Result<AutoReportActionsResult, Error> {
    let records = lookup_name_rtype_at_address::<Ds<_>>(zone, Rtype::DS, address).await?;

    let mut max_ttl = Ttl::from_secs(0);

    for r in records {
        if r.owner() != zone {
            continue;
        }
        max_ttl = max(max_ttl, r.ttl());
        let target_r = target_dnskey.iter().find(|target_r| {
            let digest = target_r
                .data()
                .digest(zone, r.data().digest_type())
                .expect("should not fail");
            r.data().algorithm() == target_r.data().algorithm()
                && r.data().digest() == digest.as_ref()
        });
        if let Some(record) = target_r {
            // Clone record to release target_dnskey.
            let record = record.clone();
            // Found one, remove it from the set.
            target_dnskey.remove(&record);
        } else {
            // The current record is not found in the target set. Wait
            // until the TTL has expired.
            debug!("Check DS RRset: DS record not expected");
            return Ok(AutoReportActionsResult::Wait(
                UnixTime::now() + r.ttl().into_duration(),
            ));
        }
        continue;
    }
    let dnskey = target_dnskey.iter().next();
    if let Some(dnskey) = dnskey {
        debug!("Check DS RRset: expected DS record not present");
        let ttl = dnskey.ttl();
        Ok(AutoReportActionsResult::Wait(
            UnixTime::now() + ttl.into_duration(),
        ))
    } else {
        Ok(AutoReportActionsResult::Report(max_ttl))
    }
}

/// Check whether a nameserver at a specific address has the right SOA serial
/// or a newer one.
async fn check_soa_for_address(
    zone: &Name<Vec<u8>>,
    address: &IpAddr,
    serial: Serial,
) -> Result<AutoReportActionsResult, Error> {
    let records = lookup_name_rtype_at_address::<Soa<_>>(zone, Rtype::SOA, address).await?;

    if records.is_empty() {
        return Ok(AutoReportActionsResult::Wait(
            UnixTime::now() + DEFAULT_WAIT,
        ));
    }

    if let Some(ttl) = records
        .iter()
        .filter_map(|r| {
            if r.data().serial() < serial {
                Some(r.ttl())
            } else {
                None
            }
        })
        .next()
    {
        return Ok(AutoReportActionsResult::Wait(UnixTime::now() + ttl.into()));
    }
    // Return a dummy TTL. The caller knows the real TTL to report.
    Ok(AutoReportActionsResult::Report(Ttl::from_secs(0)))
}

/// Lookup a name, rtype pair at an address.
///
/// Extract records of type T from the answer.
async fn lookup_name_rtype_at_address<T>(
    name: &Name<Vec<u8>>,
    rtype: Rtype,
    address: &IpAddr,
) -> Result<Vec<Record<ParsedName<Bytes>, T>>, Error>
where
    for<'a> T: ParseRecordData<'a, Bytes>,
{
    let server_addr = SocketAddr::new(*address, 53);
    let udp_connect = UdpConnect::new(server_addr);
    let tcp_connect = TcpConnect::new(server_addr);
    let (udptcp_conn, transport) = dgram_stream::Connection::new(udp_connect, tcp_connect);
    tokio::spawn(transport.run());

    let mut msg = MessageBuilder::new_vec();
    msg.header_mut().set_rd(true);
    let mut msg = msg.question();
    msg.push((name, rtype)).expect("should not fail");
    let mut req = RequestMessage::new(msg).expect("should not fail");
    req.set_dnssec_ok(true);
    let mut request = udptcp_conn.send_request(req.clone());
    let response = request.get_response().await.map_err::<Error, _>(|e| {
        format!("{name}/{rtype} request to {address} failed: {e}").into()
    })?;

    let mut res = Vec::new();
    for r in response.answer()?.limit_to_in::<T>() {
        let r = r?;
        res.push(r);
    }
    Ok(res)
}

/// Return the name of the parent zone.
async fn parent_zone(name: &Name<Vec<u8>>) -> Result<Name<Vec<u8>>, Error> {
    dbg!("parent_zone");
    dbg!(name);
    let parent = name
        .parent()
        .ok_or_else::<Error, _>(|| format!("unable to get parent of {name}").into())?;

    let resolver = StubResolver::new();
    let answer = resolver.query((&parent, Rtype::SOA)).await?;
    dbg!(&answer.answer());
    let rcode = answer.opt_rcode();
    if rcode != OptRcode::NOERROR {
        return Err(format!("{parent}/SOA query failed: {rcode}").into());
    }
    if let Some(Ok(owner)) = answer
        .answer()?
        .limit_to_in::<Soa<_>>()
        .map(|r| r.map(|r| r.owner().to_name::<Vec<u8>>()))
        .next()
    {
        return Ok(owner);
    }

    // Try the authority section.
    if let Some(Ok(owner)) = answer
        .authority()?
        .limit_to_in::<Soa<_>>()
        .map(|r| r.map(|r| r.owner().to_name::<Vec<u8>>()))
        .next()
    {
        return Ok(owner);
    }

    Err(format!("{parent}/SOA query failed").into())
}

/// This function automatically starts a key roll when the conditions are right.
///
/// First the conficting_roll function is invoked to make sure there are no
/// rolls in progress that would conflict. Then match_keytype is used to
/// select key that could participate in this roll. The published time of
/// each key is compared to the validity parameter to see if the key
/// needs to be replaced. No key roll will happen is validity is equal to
/// None. The start_roll parameter starts the key roll.
#[allow(clippy::too_many_arguments)]
fn auto_start<Env>(
    validity: &Option<Duration>,
    auto: &AutoConfig,
    ksc: &KeySetConfig,
    kss: &mut KeySetState,
    env: Env,
    state_changed: &mut bool,
    conficting_roll: impl Fn(RollType) -> bool,
    match_keytype: impl Fn(KeyType) -> Option<KeyState>,
    start_roll: impl Fn(&KeySetConfig, &mut KeySetState, Env) -> Result<Vec<Action>, Error>,
) -> Result<(), Error> {
    if let Some(validity) = validity {
        if auto.start {
            // If there is no conficting roll, and this
            // flag is set, and the lifetime has expired then
            // start a roll.
            if !kss
                .keyset
                .rollstates()
                .iter()
                .any(|(r, _)| conficting_roll(*r))
            {
                let next = kss
                    .keyset
                    .keys()
                    .iter()
                    .filter_map(|(_, k)| {
                        if let Some(keystate) = match_keytype(k.keytype()) {
                            if !keystate.stale() {
                                k.timestamps()
                                    .published()
                                    .map(|published| published + *validity)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .min();
                if let Some(next) = next {
                    if next < UnixTime::now() {
                        start_roll(ksc, kss, env)?;
                        *state_changed = true;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Handle automation for the report, expire and done steps.
///
/// The auto parameter has the flags that control whether automation is
/// enabled or disabled for a step. The roll_list parameters are the
/// roll types that are covered by the auto parameter.
/// This function calls two function (auto_report_actions and
/// auto_wait_actions) to handle, repectively, the Report and Wait actions.
async fn auto_report_expire_done(
    auto: &AutoConfig,
    roll_list: &[RollType],
    ksc: &KeySetConfig,
    kss: &mut KeySetState,
    env: &impl Env,
    state_changed: &mut bool,
) -> Result<(), Error> {
    if auto.report {
        // If there is currently a roll in one of the
        // propagation states and this flags is set and all
        // actions have comleted report the ttl.
        for r in roll_list {
            if let Some(state) = kss.keyset.rollstates().get(r) {
                let report_state = kss.internal.get(r).expect("should not fail");
                let report_state = match state {
                    RollState::Propagation1 => &report_state.propagation1,
                    RollState::Propagation2 => &report_state.propagation2,
                    _ => continue,
                };
                let actions = kss.keyset.actions(*r);
                match auto_report_actions(&actions, kss, report_state, state_changed).await {
                    AutoReportActionsResult::Wait(_) => continue,
                    AutoReportActionsResult::Report(ttl) => {
                        let actions = match state {
                            RollState::Propagation1 => {
                                kss.keyset.propagation1_complete(*r, ttl.as_secs())
                            }
                            RollState::Propagation2 => {
                                kss.keyset.propagation2_complete(*r, ttl.as_secs())
                            }
                            _ => unreachable!(),
                        };

                        let actions = match actions {
                            Ok(actions) => actions,
                            Err(err) => {
                                return Err(format!(
                                    "Error reporting propagation complete: {err}\n"
                                )
                                .into());
                            }
                        };

                        handle_actions(&actions, ksc, kss, env)?;
                        // Report actions
                        print_actions(&actions);
                        *state_changed = true;
                    }
                }
            }
        }
    }
    if auto.expire {
        // If there is currently a roll in one of the cache
        // expire states and this flag is set, move to the next
        // state
        for r in roll_list {
            if let Some(state) = kss.keyset.rollstates().get(r) {
                let actions = match state {
                    RollState::CacheExpire1(_) => kss.keyset.cache_expired1(*r),
                    RollState::CacheExpire2(_) => kss.keyset.cache_expired2(*r),
                    _ => continue,
                };
                if let Err(keyset::Error::Wait(_)) = actions {
                    // To early.
                    continue;
                }
                let actions = actions.map_err::<Error, _>(|e| {
                    format!("cache_expired[12] failed for state {r:?}: {e}").into()
                })?;
                handle_actions(&actions, ksc, kss, env)?;
                // Report actions
                print_actions(&actions);
                *state_changed = true;
            }
        }
    }
    if auto.done {
        // If there is current a roll in the done state and all
        // actions have completed then call do_done to end the key roll.
        for r in roll_list {
            if let Some(RollState::Done) = kss.keyset.rollstates().get(r) {
                let report_state = &kss.internal.get(r).expect("should not fail").done;
                let actions = kss.keyset.actions(*r);
                match auto_wait_actions(&actions, kss, report_state, state_changed).await {
                    AutoActionsResult::Ok => {
                        do_done(kss, *r, ksc.autoremove)?;
                        *state_changed = true;
                    }
                    AutoActionsResult::Wait(_) => continue,
                }
            }
        }
    }
    Ok(())
}

/// This function computes when the next key roll should happen.
///
/// It has the same logic as auto_start but instead of starting a key roll,
/// it (optionally) adds a timestamp to the cron_next vector. Should this
/// be merged with auto_start?
fn cron_next_auto_start(
    validity: Option<Duration>,
    auto: &AutoConfig,
    kss: &KeySetState,
    conflicting_roll: impl Fn(RollType) -> bool,
    match_keytype: impl Fn(KeyType) -> Option<KeyState>,
    cron_next: &mut Vec<Option<UnixTime>>,
) {
    if let Some(validity) = validity {
        if auto.start {
            // If there is no KSK, CSK, or Algorithm roll, and this
            // flag is set, compute the remaining KSK lifetime

            // The only roll types that are compatible with a KSK roll
            // are the two ZSK rolls.
            if !kss
                .keyset
                .rollstates()
                .iter()
                .any(|(r, _)| conflicting_roll(*r))
            {
                let next = kss
                    .keyset
                    .keys()
                    .iter()
                    .filter_map(|(_, k)| {
                        if let Some(keystate) = match_keytype(k.keytype()) {
                            if !keystate.stale() {
                                k.timestamps().published()
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .map(|published| published + validity)
                    .min();
                cron_next.push(next);
            }
        }
    }
}

/// This function computes when next to try to move to the next state.
///
/// For the Report and Wait actions that involves checking when propagation
/// should be tested again. For the expire step it computes when the
/// keyset object in the domain library accepts the cache_expired1 or
/// cache_expired2 methods.
fn cron_next_auto_report_expire_done(
    auto: &AutoConfig,
    roll_list: &[RollType],
    kss: &KeySetState,
    cron_next: &mut Vec<Option<UnixTime>>,
) -> Result<(), Error> {
    if auto.report {
        // If there is currently a roll in one of the propagation
        // states and this flags is set take when to check again for
        // actions to complete
        for r in roll_list {
            if let Some(state) = kss.keyset.rollstates().get(r) {
                let report_state = kss.internal.get(r).expect("should not fail");
                let report_state = match state {
                    RollState::Propagation1 => &report_state.propagation1,
                    RollState::Propagation2 => &report_state.propagation2,
                    _ => continue,
                };
                let actions = kss.keyset.actions(*r);
                match check_auto_actions(&actions, report_state) {
                    AutoActionsResult::Ok => {
                        // All actions are ready. Request cron.
                        cron_next.push(Some(UnixTime::now()));
                    }
                    AutoActionsResult::Wait(next) => cron_next.push(Some(next)),
                }
            }
        }
    }

    if auto.expire {
        // If there is currently a roll in one of the cache expire
        // states and this flag is set, use the remaining time until caches
        // are expired. Try to issue the cache_expire[12] method on a
        // clone of keyset.
        let mut keyset = kss.keyset.clone();
        for r in roll_list {
            if let Some(state) = keyset.rollstates().get(r) {
                let actions = match state {
                    RollState::CacheExpire1(_) => keyset.cache_expired1(*r),
                    RollState::CacheExpire2(_) => keyset.cache_expired2(*r),
                    _ => continue,
                };
                if let Err(keyset::Error::Wait(remain)) = actions {
                    cron_next.push(Some(UnixTime::now() + remain));
                    continue;
                }
                let _ = actions.map_err::<Error, _>(|e| {
                    format!("cache_expired[12] failed for state {r:?}: {e}").into()
                })?;

                // Time to call cron. Report the current time.
                cron_next.push(Some(UnixTime::now()));
            }
        }
    }

    if auto.done {
        // If there is current a roll in the done state and all
        // and this flag is set, take when the check again for actions to
        // complete
        for r in roll_list {
            if let Some(RollState::Done) = kss.keyset.rollstates().get(r) {
                let report_state = kss.internal.get(r).expect("should not fail");
                match check_auto_actions(&kss.keyset.actions(*r), &report_state.done) {
                    AutoActionsResult::Ok => {
                        // All actions are ready. Request cron.
                        cron_next.push(Some(UnixTime::now()));
                    }
                    AutoActionsResult::Wait(next) => {
                        cron_next.push(Some(next));
                    }
                }
            }
        }
    }

    Ok(())
}

/// The result of checking whether all RRSIG records are present.
#[derive(PartialEq)]
enum CheckRrsigsResult {
    /// The required RRSIGs are present.
    Done,
    /// Wait for a specific name, rtype combination to get updated signatures.
    WaitRecord {
        /// The name to check.
        name: Name<Vec<u8>>,
        /// And the Rtype.
        rtype: Rtype,
    },
    /// Wait for the next version of the zone.
    WaitNextSerial,
}

/// Type for the key of the signature HashMap.
type SigmapKey = (Name<Vec<u8>>, Rtype);
/// Type for the value of the signature HashMap.
type SigmapValue = HashSet<(SecurityAlgorithm, u16)>;

/// Check if all authoritive records have the right signatures.
///
/// A zone is not authoritative for names below a delegation. At a delegation,
/// a zone is authoritative for DS and NSEC records.
fn check_rrsigs(
    treemap: BTreeMap<Name<Vec<u8>>, HashSet<Rtype>>,
    sigmap: HashMap<SigmapKey, SigmapValue>,
    zone: &Name<Vec<u8>>,
    expected_set: HashSet<(SecurityAlgorithm, u16)>,
) -> CheckRrsigsResult {
    let mut delegation = None;
    let mut result = CheckRrsigsResult::Done;
    for (key, rtype_map) in treemap {
        if let Some(name) = &delegation {
            if key.ends_with(name) {
                // Ignore anything below a delegation.
                continue;
            }
            delegation = None;
        }
        if rtype_map.contains(&Rtype::NS) && key != zone {
            delegation = Some(key.clone());
        }
        for rtype in rtype_map {
            if delegation.is_some() {
                // NS is not signed. A and AAAA are glue.
                if rtype == Rtype::NS || rtype == Rtype::A || rtype == Rtype::AAAA {
                    continue;
                } else if rtype == Rtype::DS || rtype == Rtype::NSEC {
                    // DS records are signed. Just keep going.
                } else {
                    error!("Weird type {rtype} in delegation {}", &key);
                    continue;
                }
            }
            if (rtype == Rtype::DNSKEY || rtype == Rtype::CDS || rtype == Rtype::CDNSKEY)
                && key == zone
            {
                // These rtypes are signed with the KSKs
                continue;
            }
            let set = if let Some(set) = sigmap.get(&(key.clone(), rtype)) {
                set.clone()
            } else {
                warn!("RRSIG not found for {key}/{rtype}");
                HashSet::new()
            };
            if set != expected_set {
                // NSEC3 records are special because we cannot directly query
                // for them. For 'normal' record, return WaitRecord.
                // For NSEC3 we need to wait for a new version of the zone,
                // so we return WaitNextSerial. However, WaitRecord is more
                // efficient. Therefore, if the mismatch is at an NSEC3 then
                // remember this by setting result to WaitNextSerial but
                // keep checking.
                if rtype != Rtype::NSEC3 {
                    warn!(
                        "RRSIG mismatch for {key}/{rtype}: found {:?} expected {:?}",
                        set, expected_set
                    );
                    let name = key.to_name::<Vec<u8>>();
                    return CheckRrsigsResult::WaitRecord { name, rtype };
                }
                if result == CheckRrsigsResult::Done {
                    warn!(
                        "RRSIG mismatch for {key}/{rtype}: found {:?} expected {:?}",
                        set, expected_set
                    );
                }
                result = CheckRrsigsResult::WaitNextSerial;
            }
        }
    }

    // All authoritative records have signatures with the right algorithms and
    // key tags. Or an NSEC3 failure was found.
    result
}

/// Check if a name, Rtype pair has the right signatures.
async fn check_record(
    name: &Name<Vec<u8>>,
    rtype: &Rtype,
    kss: &KeySetState,
) -> Result<bool, Error> {
    let expected = get_expected_zsk_key_tags(kss);
    let addresses = get_primary_addresses(kss.keyset.name()).await?;
    for address in &addresses {
        let server_addr = SocketAddr::new(*address, 53);
        let udp_connect = UdpConnect::new(server_addr);
        let tcp_connect = TcpConnect::new(server_addr);
        let (udptcp_conn, transport) = dgram_stream::Connection::new(udp_connect, tcp_connect);
        tokio::spawn(transport.run());

        let mut msg = MessageBuilder::new_vec();
        msg.header_mut().set_rd(true);
        let mut msg = msg.question();
        msg.push((name, *rtype)).expect("should not fail");
        let mut req = RequestMessage::new(msg).expect("should not fail");
        req.set_dnssec_ok(true);
        let mut request = udptcp_conn.send_request(req.clone());
        let response = match request.get_response().await {
            Ok(r) => r,
            Err(e) => {
                warn!("{name}/{rtype} request to {server_addr} failed: {e}");
                continue;
            }
        };

        let mut alg_tag_set = HashSet::new();

        for r in response.answer()?.limit_to_in::<Rrsig<_, _>>() {
            let r = r?;
            if r.data().type_covered() != *rtype {
                continue;
            }
            alg_tag_set.insert((r.data().algorithm(), r.data().key_tag()));
        }
        return Ok(alg_tag_set == expected);
    }
    Err(format!("lookup of {name}/{rtype} failed for all addresses {addresses:?}").into())
}

/// Check if the zone has move to the next serial.
async fn check_next_serial(serial: Serial, kss: &KeySetState) -> Result<bool, Error> {
    let zone = kss.keyset.name();
    let addresses = get_primary_addresses(zone).await?;
    for address in &addresses {
        let server_addr = SocketAddr::new(*address, 53);
        let udp_connect = UdpConnect::new(server_addr);
        let tcp_connect = TcpConnect::new(server_addr);
        let (udptcp_conn, transport) = dgram_stream::Connection::new(udp_connect, tcp_connect);
        tokio::spawn(transport.run());

        let mut msg = MessageBuilder::new_vec();
        msg.header_mut().set_rd(true);
        let mut msg = msg.question();
        msg.push((zone, Rtype::SOA)).expect("should not fail");
        let req = RequestMessage::new(msg).expect("should not fail");
        let mut request = udptcp_conn.send_request(req.clone());
        let response = match request.get_response().await {
            Ok(r) => r,
            Err(e) => {
                warn!("{zone}/SOA request to {server_addr} failed: {e}");
                continue;
            }
        };

        if let Some(r) = response.answer()?.limit_to_in::<Soa<_>>().next() {
            let r = r?;
            return Ok(r.data().serial() > serial);
        }
        warn!("No SOA record in reply to SOA query for zone {zone}");
        return Ok(false);
    }
    Err(format!("lookup of {zone}/SOA failed for all addresses {addresses:?}").into())
}

/// Check if all addresses of all nameservers of the zone to see if they
/// have at least the SOA serial passed as parameter.
async fn check_soa(serial: Serial, kss: &KeySetState) -> Result<bool, Error> {
    // Find the address of all name servers of zone
    // Ask each nameserver for the SOA record.
    // Check that it's version is at least the version we checked.
    // If it doesn't match, wait the TTL of the SOA record to try again.
    // On error, wait a default time.

    let zone = kss.keyset.name();

    let addresses = addresses_for_zone(zone).await?;
    let futures: Vec<_> = addresses
        .iter()
        .map(|a| check_soa_for_address(zone, a, serial))
        .collect();
    let res: Vec<_> = join_all(futures).await;

    for r in res {
        let r = r?;
        match r {
            // It doesn't really matter how long we have to wait.
            AutoReportActionsResult::Wait(_) => return Ok(false),
            AutoReportActionsResult::Report(_) => (),
        }
    }

    Ok(true)
}

/// Get the expected key tags.
///
/// Instead of validating signatures against the keys that sign the zone,
/// the signatures are of only checked for key tags.
fn get_expected_zsk_key_tags(kss: &KeySetState) -> HashSet<(SecurityAlgorithm, u16)> {
    kss.keyset
        .keys()
        .iter()
        .filter_map(|(_, k)| match k.keytype() {
            KeyType::Ksk(_) | KeyType::Include(_) => None,
            KeyType::Zsk(keystate) => Some((keystate, k.algorithm(), k.key_tag())),
            KeyType::Csk(_, keystate) => Some((keystate, k.algorithm(), k.key_tag())),
        })
        .filter_map(|(ks, a, kt)| if ks.signer() { Some((a, kt)) } else { None })
        .collect()
}

/// Get the addresses of the primary nameserver of a zone.
async fn get_primary_addresses(zone: &Name<Vec<u8>>) -> Result<Vec<IpAddr>, Error> {
    let resolver = StubResolver::new();
    let answer = resolver.query((zone, Rtype::SOA)).await?;
    dbg!(&answer.answer());
    let Some(Ok(mname)) = answer
        .answer()?
        .limit_to_in::<Soa<_>>()
        .map(|r| r.map(|r| r.data().mname().clone()))
        .next()
    else {
        let rcode = answer.opt_rcode();
        return if rcode != OptRcode::NOERROR {
            Err(format!("Unable to resolve {zone}/SOA: {rcode}").into())
        } else {
            Err(format!("No result for {zone}/SOA").into())
        };
    };

    addresses_for_name(&resolver, mname).await
}

/// Check if an algorithm roll is needed.
///
/// An algorithm roll is needed if the algorithm listed in config is
/// different from the set of algorithms in the collection of active keys.
fn algorithm_roll_needed(ksc: &KeySetConfig, kss: &KeySetState) -> bool {
    // Collect the algorithms in all active keys. Check if the algorithm
    // for new keys is the same.
    let curr_algs: HashSet<_> = kss
        .keyset
        .keys()
        .iter()
        .filter_map(|(_, k)| {
            if let Some(keystate) = match k.keytype() {
                KeyType::Ksk(keystate) => Some(keystate),
                KeyType::Zsk(keystate) => Some(keystate),
                KeyType::Csk(keystate, _) => Some(keystate),
                KeyType::Include(_) => None,
            } {
                if !keystate.stale() {
                    Some(k.algorithm())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();
    let new_algs = HashSet::from([ksc.algorithm.to_generate_params().algorithm()]);
    curr_algs != new_algs
}

/*
Test for RRSIG check
- records before the zone
- records after the zone
- DNSKEY/CDS/CDNSKEY
  - at apex
  - not at apex
- delegations
  - with DS/NSEC
  - with A/AAAA at the delegations
  - other records at the delegations
  - below delegation
- bad sig NSEC3
- bad sig not NSEC3
*/
