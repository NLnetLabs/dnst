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
#[cfg(feature = "kmip")]
use domain::crypto::sign::SignRaw;
use domain::crypto::sign::{GenerateParams, KeyPair, SecretKeyBytes};
use domain::dep::octseq::{FromBuilder, OctetsFrom};
use domain::dnssec::common::{display_as_bind, parse_from_bind};
use domain::dnssec::sign::keys::keyset::{
    self, Action, Available, Key, KeySet, KeyState, KeyType, RollState, RollType, UnixTime,
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
#[cfg(feature = "kmip")]
use domain::utils::base32::encode_string_hex;
use domain::zonefile::inplace::{Entry, Zonefile};
#[cfg(feature = "kmip")]
use domain_kmip as kmip;
#[cfg(feature = "kmip")]
use domain_kmip::dep::kmip::client::pool::SyncConnPool;
#[cfg(feature = "kmip")]
use domain_kmip::KeyUrl;
use fs2::FileExt;
use futures::future::join_all;
use jiff::{Span, SpanRelativeTo};
use same_file::Handle;
use serde::{Deserialize, Serialize};
use std::cmp::max;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::From;
use std::ffi::OsStr;
use std::fmt::{Debug, Display, Formatter};
use std::fs::{create_dir_all, remove_file, rename, File};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{absolute, Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};
use tokio::net::TcpStream;
#[cfg(feature = "kmip")]
use tracing::{debug, error, warn};
#[cfg(not(feature = "kmip"))]
use tracing::{debug, error, warn};
use url::Url;

#[cfg(feature = "kmip")]
use super::kmip::{format_key_label, kmip_command, KmipCommands, KmipState};

/// Maximum tries to generate new key with a key tag that does not conclict
/// with the key tags of existing keys.
const MAX_KEY_TAG_TRIES: u8 = 10;

/// Number of times to try locking a file.
const MAX_FILE_LOCK_TRIES: u8 = 10;

/// Wait this amount before retrying for network errors, DNS errors, etc.
const DEFAULT_WAIT: Duration = Duration::from_secs(10 * 60);

/// The default TTL for creating a new config file.
const DEFAULT_TTL: Ttl = Ttl::from_secs(3600);

/// The default delay in automatically removing a key pair after it has become
/// stale.
const DEFAULT_AUTOREMOVE_DELAY: Duration = Duration::from_secs(7 * 24 * 3600);

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

/// Type for an optional UnixTime. A separate type is needed because CLAP
/// treats Option<T> special.
type OptUnixTime = Option<UnixTime>;

/// The subcommands of the keyset utility.
#[allow(clippy::large_enum_variant)]
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

    /// Command for KSK rolls.
    Ksk {
        /// The specific key roll subcommand.
        #[command(subcommand)]
        subcommand: RollCommands,
    },
    /// Command for ZSK rolls.
    Zsk {
        /// The specific key roll subcommand.
        #[command(subcommand)]
        subcommand: RollCommands,
    },
    /// Command for CSK rolls.
    Csk {
        /// The specific key roll subcommand.
        #[command(subcommand)]
        subcommand: RollCommands,
    },
    /// Command for algorithm rolls.
    Algorithm {
        /// The specific key roll subcommand.
        #[command(subcommand)]
        subcommand: RollCommands,
    },

    /// Command for importing existing keys.
    Import {
        /// The specific import subcommand.
        #[command(subcommand)]
        subcommand: ImportCommands,
    },

    /// Remove a key from the key set.
    RemoveKey {
        /// Force a key to be removed even if the key is not stale.
        #[arg(long)]
        force: bool,

        /// Continue when removing the underlying keys fails.
        #[arg(long = "continue")]
        continue_flag: bool,

        /// The key to remove.
        key: String,
    },

    /// Report status, such as key rolls that are in progress, expired
    /// keys, when to call the 'cron' subcommand next.
    Status {
        /// Make status verbose.
        #[arg(short = 'v', long)]
        verbose: bool,
    },
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

    /// Kmip command.
    #[cfg(feature = "kmip")]
    Kmip {
        /// Kmip subcommands.
        #[command(subcommand)]
        subcommand: KmipCommands,
    },
}

/// The fields that can be reported with a get command.
#[derive(Clone, Debug, Subcommand)]
enum GetCommands {
    /// Get the state of the use_csk config variable.
    UseCsk,
    /// Get the state of the autoremove config variable.
    Autoremove,
    /// Get the autoremove delay config variable.
    AutoremoveDelay,
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

/// The fields that can be changed with a set command.
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
    /// Set the autoremove delay config variable.
    AutoremoveDelay {
        /// The delay.
        #[arg(value_parser = parse_duration)]
        delay: Duration,
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

    /// Set the TTL to be used DNSKEY/CDS/CDNSKEY records.
    DefaultTtl {
        /// TTL value to set.
        ttl: u32,
    },

    /// Set the command to run when the DS records at the parent need updating.
    UpdateDsCommand {
        /// Command and arguments.
        args: Vec<String>,
    },

    /// Set the fake time to use when signing and other time related
    /// operations.
    FakeTime {
        /// The time value as Unix seconds.
        #[arg(value_parser = parse_opt_unixtime)]
        opt_unixtime: OptUnixTime,
    },
}

/// The various subcommands of a key roll command.
#[derive(Clone, Debug, Subcommand)]
enum RollCommands {
    /// Start a key roll.
    StartRoll,
    /// Report that the first propagation step has completed.
    Propagation1Complete {
        /// The TTL that is required to be reported by the Report actions.
        ttl: u32,
    },
    /// Cached information from before Propagation1Complete should have
    /// expired by now.
    CacheExpired1,
    /// Report that the second propagation step has completed.
    Propagation2Complete {
        /// The TTL that is required to be reported by the Report actions.
        ttl: u32,
    },
    /// Cached information from before Propagation2Complete should have
    /// expired by now.
    CacheExpired2,
    /// Report that the final changes have propagated and the the roll is done.
    RollDone,
}

/// The top-level import command.
#[derive(Clone, Debug, Subcommand)]
enum ImportCommands {
    /// Import a public key.
    PublicKey {
        /// The file name of the public key.
        path: PathBuf,
    },

    /// Command for KSK imports.
    Ksk {
        /// The specific key import subcommand.
        #[command(subcommand)]
        subcommand: ImportKeyCommands,
    },
    /// Command for ZSK imports.
    Zsk {
        /// The specific key import subcommand.
        #[command(subcommand)]
        subcommand: ImportKeyCommands,
    },
    /// Command for CSK imports.
    Csk {
        /// The specific key import subcommand.
        #[command(subcommand)]
        subcommand: ImportKeyCommands,
    },
}

/// Where to import from, either a file or an HSM access using KMIP.
#[derive(Clone, Debug, Subcommand)]
enum ImportKeyCommands {
    /// Import public/private key pair from file.
    File {
        /// Take ownership of the imported keys.
        ///
        /// When the key is removed from the key set, the underlying keys
        /// are also removed. The default is decoupled when the underlying
        /// keys are not removed.
        #[arg(long)]
        coupled: bool,

        /// Explicitly pass the name of the file that holds the private key.
        ///
        /// Otherwise the name is derived from the name of the file that holds
        /// the public key.
        #[arg(long)]
        private_key: Option<PathBuf>,

        /// Pathname of the public key.
        path: PathBuf,
    },
    #[cfg(feature = "kmip")]
    /// Import a KMIP public/private key pair.
    Kmip {
        /// Take ownership of the imported keys.
        ///
        /// When the key is removed from the key set, the underlying keys
        /// are also removed. The default is decoupled when the underlying
        /// keys are not removed.
        #[arg(long)]
        coupled: bool,

        /// The identifier of the KMIP server.
        server: String,

        /// The KMIP identifier of the public key.
        public_id: String,

        /// The KMIP identifier of the private key.
        private_id: String,

        /// The key's DNSSEC security algorithm.
        algorithm: SecurityAlgorithm,

        /// Value to put in the DNSKEY flags field.
        flags: u16,
    },
}

/// Which type of key a command applies to.
#[derive(Debug)]
enum KeyVariant {
    /// Apply command to KSKs.
    Ksk,
    /// Apply command to ZSKs.
    Zsk,
    /// Apply command to CSKs.
    Csk,
}

/// Which high-level key roll a command applies to.
// We cannot use RollType because that name is already in use.
enum RollVariant {
    /// Apply the subcommand to a KSK roll.
    Ksk,
    /// Apply the subcommand to a ZSK roll.
    Zsk,
    /// Apply the subcommand to a CSK roll.
    Csk,
    /// Apply the subcommand to an algorithm roll.
    Algorithm,
}

impl RollVariant {
    /// Return the right RollType for a RollVariant.
    fn roll_variant_to_roll(self) -> RollType {
        // For key types, such as KSK and ZSK, that can have different rolls,
        // we should find out which variant is used.
        match self {
            RollVariant::Ksk => RollType::KskRoll,
            RollVariant::Zsk => RollType::ZskRoll,
            RollVariant::Csk => RollType::CskRoll,
            RollVariant::Algorithm => RollType::AlgorithmRoll,
        }
    }
}

/// Combines most of the state that is needed for the keyset subcommand.
struct WorkSpace {
    /// The keyset config variables.
    config: KeySetConfig,

    /// The keyset state.
    state: KeySetState,

    /// Whether the keyset config was changed.
    config_changed: bool,
    /// Whether the keyset state was changed.
    state_changed: bool,
    /// Whether the command to update DS records has to be executed.
    run_update_ds_command: bool,

    /// Store the locked config file to avoid accidental unlocking.
    _locked_config_file: Option<File>,

    #[cfg(feature = "kmip")]
    /// The current set of KMIP server pools.
    pools: HashMap<String, SyncConnPool>,
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
            let config_file_dir = make_parent_dir(self.keyset_conf.clone());

            let state_file = absolute(&keyset_state).map_err(|e| {
                format!("unable to make {} absolute: {}", keyset_state.display(), e)
            })?;
            let state_file_dir = make_parent_dir(state_file.clone());
            let keys_dir = state_file_dir.clone();

            let ks = KeySet::new(domain_name);
            let kss = KeySetState {
                keyset: ks,
                dnskey_rrset: Vec::new(),
                ds_rrset: Vec::new(),
                cds_rrset: Vec::new(),
                ns_rrset: Vec::new(),
                cron_next: None,
                internal: HashMap::new(),

                #[cfg(feature = "kmip")]
                kmip: Default::default(),
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
                default_ttl: DEFAULT_TTL,
                autoremove: false,
                autoremove_delay: DEFAULT_AUTOREMOVE_DELAY,
                update_ds_command: Vec::new(),
                faketime: None,
            };

            // Create the parent directies.
            create_dir_all(&state_file_dir).map_err(|e| {
                format!(
                    "unable to create directory '{}': {e}",
                    state_file_dir.display()
                )
            })?;
            create_dir_all(&config_file_dir).map_err(|e| {
                format!(
                    "unable to create directory '{}': {e}",
                    config_file_dir.display()
                )
            })?;

            let ws = WorkSpace {
                config: ksc,
                state: kss,
                config_changed: false,
                state_changed: false,
                run_update_ds_command: false,
                _locked_config_file: None,
                #[cfg(feature = "kmip")]
                pools: HashMap::new(),
            };

            ws.write_state()?;
            ws.write_config(&self.keyset_conf)?;

            return Ok(());
        }

        let config_file = file_with_write_lock(&self.keyset_conf)?;

        let ksc: KeySetConfig = serde_json::from_reader(&config_file)
            .map_err(|e| format!("error loading {:?}: {e}\n", self.keyset_conf))?;
        let file = File::open(ksc.state_file.clone()).map_err(|e| {
            format!(
                "unable to open state file {}: {e}",
                ksc.state_file.display()
            )
        })?;
        let kss: KeySetState = serde_json::from_reader(file)
            .map_err(|e| format!("error loading {:?}: {e}\n", ksc.state_file))?;

        let mut ws = WorkSpace {
            config: ksc,
            state: kss,
            config_changed: false,
            state_changed: false,
            run_update_ds_command: false,
            _locked_config_file: Some(config_file),
            #[cfg(feature = "kmip")]
            pools: HashMap::new(),
        };

        let now = ws.faketime_or_now();
        match self.cmd {
            Commands::Create { .. } => unreachable!(),
            Commands::Init => {
                // Assume that dnskey_rrset is a reliable way to tell if
                // we are initialized or not.
                // Check for re-init.
                if !ws.state.dnskey_rrset.is_empty() {
                    // Avoid re-init.
                    return Err("already initialized\n".into());
                }

                // Check if we have any imported keys. Include doesn't count.
                // if we do, make we sure we have a CSK or a KSK plus a ZSK.
                // If we have only of a KSK or only a ZSK then fail. Otherwise
                // Create the dnskey_rrset and the ds_rrset.
                let mut ksk_present = false;
                let mut zsk_present = false;
                let mut csk_present = false;
                for k in ws.state.keyset.keys().values() {
                    match k.keytype() {
                        KeyType::Ksk(_) => ksk_present = true,
                        KeyType::Zsk(_) => zsk_present = true,
                        KeyType::Csk(_, _) => csk_present = true,
                        KeyType::Include(_) => (),
                    }
                }
                if (ksk_present && zsk_present) || csk_present {
                    // Start with imported keys.
                    ws.update_dnskey_rrset(env, true)?;
                    ws.update_ds_rrset(env, true)?;
                } else if ksk_present || zsk_present {
                    // Incomplete keys
                    return Err("Cannot start with only a KSK or ZSK.".into());
                } else {
                    // No imported keys (except possibly for Include), start
                    // an algorithm roll.

                    let (new_stored, _) = ws.new_csk_or_ksk_zsk(env)?;

                    let new: Vec<_> = new_stored.iter().map(|v| v.as_ref()).collect();
                    let actions = ws
                        .state
                        .keyset
                        .start_roll(RollType::AlgorithmRoll, &[], &new)
                        .expect("should not happen");

                    ws.handle_actions(&actions, env, true)?;
                    ws.state
                        .internal
                        .insert(RollType::AlgorithmRoll, Default::default());

                    print_actions(&actions);
                }
                ws.state_changed = true;
            }
            Commands::Ksk { subcommand } => ws.roll_command(subcommand, RollVariant::Ksk, env)?,
            Commands::Zsk { subcommand } => ws.roll_command(subcommand, RollVariant::Zsk, env)?,
            Commands::Csk { subcommand } => ws.roll_command(subcommand, RollVariant::Csk, env)?,
            Commands::Algorithm { subcommand } => {
                ws.roll_command(subcommand, RollVariant::Algorithm, env)?
            }

            Commands::Import { subcommand } => ws.import_command(subcommand, env)?,

            Commands::RemoveKey {
                key,
                force,
                continue_flag,
            } => {
                ws.remove_key_command(key, force, continue_flag)?;
                if force {
                    // If the key was in use then the DNSKEY RRset may be
                    // affected. Avoid introducing a DNSKEY RRset when there
                    // was none.
                    if !ws.state.dnskey_rrset.is_empty() {
                        ws.update_dnskey_rrset(env, true)?;
                    }

                    // What about CDS/CDNSKEY/DS?
                }
                ws.state_changed = true;
            }

            Commands::Status { verbose } => {
                // This clone is needed because public_key_from_url needs a
                // mutable reference to kss. Rewrite the kmip code to avoid
                // that.
                let rollstates = ws.state.keyset.rollstates().clone();
                for (roll, state) in rollstates.iter() {
                    println!("{roll:?}: {state:?}");

                    if verbose {
                        let mut keyset = ws.state.keyset.clone();
                        let res = match state {
                            RollState::CacheExpire1(_) => Some(keyset.cache_expired1(*roll)),
                            RollState::CacheExpire2(_) => Some(keyset.cache_expired2(*roll)),
                            _ => None,
                        };
                        if let Some(res) = res {
                            if let Err(keyset::Error::Wait(remain)) = res {
                                println!(
                                    "Wait until {} to let caches expire",
                                    now.clone() + remain
                                );
                            } else if let Err(e) = res {
                                return Err(format!(
                                    "cache_expired[12] failed for state {roll:?}: {e}"
                                )
                                .into());
                            } else {
                                println!("Caches have expired, continue with the next step");
                            }
                        }

                        for action in ws.state.keyset.actions(*roll) {
                            match action {
                                Action::UpdateDnskeyRrset
                                | Action::CreateCdsRrset
                                | Action::RemoveCdsRrset
                                | Action::UpdateDsRrset
                                | Action::UpdateRrsig => (),
                                Action::ReportDnskeyPropagated | Action::WaitDnskeyPropagated => {
                                    println!("Check that the following RRset has propagated to all name servers:");
                                    for r in &ws.state.dnskey_rrset {
                                        println!("{r}");
                                    }
                                    println!();
                                }
                                Action::ReportDsPropagated | Action::WaitDsPropagated => {
                                    println!("Check that all nameservers of the parent zone have the following RRset (or equivalent):");
                                    for r in &ws.state.ds_rrset {
                                        println!("{r}");
                                    }
                                    println!();
                                }
                                Action::ReportRrsigPropagated | Action::WaitRrsigPropagated => {
                                    println!("Check that all authoritative records in the zone have been signed with the following key(s) and that all nameservers of the zone serve that version or later:");
                                    // This clone is needed because
                                    // public_key_from_url needs a mutable
                                    // reference to kss. Rewrite the kmip
                                    // code to avoid that.
                                    let keys = ws.state.keyset.keys().clone();
                                    for (pubref, k) in keys {
                                        let status = match k.keytype() {
                                            KeyType::Zsk(status) => status,
                                            KeyType::Csk(_, zsk_status) => zsk_status,
                                            KeyType::Ksk(_) | KeyType::Include(_) => continue,
                                        };
                                        if status.signer() {
                                            let url = Url::parse(&pubref).map_err(|e| {
                                                format!("unable to parse {pubref} as URL: {e}")
                                            })?;
                                            let public_key =
                                                ws.public_key_from_url::<Vec<u8>>(&url, env)?;
                                            println!(
                                                "{public_key} ; key tag {}",
                                                public_key.data().key_tag()
                                            );
                                        }
                                    }
                                    println!();
                                }
                            }
                        }

                        let keyset_cmd = format!("dnst keyset -c {}", self.keyset_conf.display());

                        let (roll_subcommand, auto) = match roll {
                            RollType::KskRoll => ("ksk", &ws.config.auto_ksk),
                            RollType::KskDoubleDsRoll => ("ksk", &ws.config.auto_ksk),
                            RollType::ZskRoll => ("zsk", &ws.config.auto_zsk),
                            RollType::ZskDoubleSignatureRoll => ("zsk", &ws.config.auto_zsk),
                            RollType::CskRoll => ("csk", &ws.config.auto_csk),
                            RollType::AlgorithmRoll => ("algorithm", &ws.config.auto_algorithm),
                        };
                        let (state_subcommand, auto) = match state {
                            RollState::Propagation1 => ("propagation1-complete <ttl>", auto.report),
                            RollState::CacheExpire1(_) => ("cache-expired1", auto.expire),
                            RollState::Propagation2 => ("propagation2-complete <ttl>", auto.report),
                            RollState::CacheExpire2(_) => ("cache-expired2", auto.expire),
                            RollState::Done => ("roll-done", auto.done),
                        };
                        println!("For the next step run:");
                        println!("\t{keyset_cmd} {roll_subcommand} {state_subcommand}");
                        println!(
                            "\tautomation is {} for this step.",
                            if auto { "enabled" } else { "disabled" }
                        );
                        println!();
                    }
                }

                let mut first = true;
                for (r, s) in ws.state.keyset.rollstates() {
                    let auto_state = ws.state.internal.get(r).expect("should exist");
                    match s {
                        // Nothing to report.
                        RollState::CacheExpire1(_) | RollState::CacheExpire2(_) => (),

                        RollState::Propagation1 => {
                            let auto_state =
                                auto_state.propagation1.lock().expect("should not fail");
                            if auto_state.dnskey.is_none()
                                && auto_state.ds.is_none()
                                && auto_state.rrsig.is_none()
                            {
                                continue;
                            }
                            if first {
                                first = false;
                                println!("Automatic key roll state:");
                            }
                            show_automatic_roll_state(*r, s, &auto_state, true);
                        }
                        RollState::Propagation2 => {
                            let auto_state =
                                auto_state.propagation2.lock().expect("should not fail");
                            if auto_state.dnskey.is_none()
                                && auto_state.ds.is_none()
                                && auto_state.rrsig.is_none()
                            {
                                continue;
                            }
                            if first {
                                first = false;
                                println!("Automatic key roll state:");
                            }
                            show_automatic_roll_state(*r, s, &auto_state, true);
                        }
                        RollState::Done => {
                            let auto_state = auto_state.done.lock().expect("should not fail");
                            if auto_state.dnskey.is_none()
                                && auto_state.ds.is_none()
                                && auto_state.rrsig.is_none()
                            {
                                continue;
                            }
                            if first {
                                first = false;
                                println!("Automatic key roll state:");
                            }
                            show_automatic_roll_state(*r, s, &auto_state, false);
                        }
                    }
                }
                if !first {
                    println!();
                }

                if sig_renew(
                    &ws.state.dnskey_rrset,
                    &ws.config.dnskey_remain_time,
                    now.clone(),
                ) {
                    println!("DNSKEY RRSIG(s) need to be renewed");
                }
                if sig_renew(&ws.state.cds_rrset, &ws.config.cds_remain_time, now.clone()) {
                    println!("CDS/CDNSKEY RRSIG(s) need to be renewed");
                }

                // Check for expired keys.
                if verbose {
                    for (pubref, k) in ws.state.keyset.keys() {
                        let (keystate, validity) = match k.keytype() {
                            KeyType::Ksk(keystate) => (keystate, Some(ws.config.ksk_validity)),
                            KeyType::Zsk(keystate) => (keystate, Some(ws.config.zsk_validity)),
                            KeyType::Csk(ksk_keystate, _) => {
                                (ksk_keystate, Some(ws.config.csk_validity))
                            }
                            KeyType::Include(keystate) => (keystate, None),
                        };
                        if keystate.stale() {
                            println!("key {pubref} is stale");
                            if ws.config.autoremove {
                                println!(
                                    "this key will be removed automatically after {}",
                                    k.timestamps()
                                        .withdrawn()
                                        .expect("should be set when stale")
                                        + ws.config.autoremove_delay
                                );
                            } else {
                                println!("remove manually (autoremove is false)");
                            }
                            continue;
                        }

                        if let Some(opt_validity) = validity {
                            if let Some(validity) = opt_validity {
                                let Some(timestamp) = k.timestamps().published() else {
                                    println!("key {pubref} is not yet published.");
                                    continue;
                                };
                                if timestamp.elapsed() > validity {
                                    println!("key {pubref} has expired.");
                                } else {
                                    println!("key {pubref} expires at {}", timestamp + validity);
                                }
                            } else {
                                println!("key {pubref} does not expire. No validity period is configured for the key type");
                            }
                        } else {
                            println!("key {pubref} does not expire. No validity is defined for this key type.");
                        }
                    }
                    println!();
                } else {
                    for (pubref, k) in ws.state.keyset.keys() {
                        let (expired, label) = key_expired(k, &ws.config);
                        if expired {
                            println!("{label} {pubref} has expired");
                        }
                    }
                }
                if let Some(cron_next) = &ws.state.cron_next {
                    println!("Next time to run the 'cron' subcommand {cron_next}");
                }
            }
            Commands::Actions => {
                for roll in ws.state.keyset.rollstates().keys() {
                    let actions = ws.state.keyset.actions(*roll);
                    println!("{roll:?} actions:");
                    print_actions(&actions);
                }
            }
            Commands::Keys => {
                println!("Keys:");
                let mut keys: Vec<_> = ws.state.keyset.keys().iter().collect();
                keys.sort_by(|(pubref1, key1), (pubref2, key2)| {
                    (key1.timestamps().creation(), pubref1)
                        .cmp(&(key2.timestamps().creation(), pubref2))
                });
                for (pubref, key) in keys {
                    println!("\t{} {}", pubref, key.privref().unwrap_or_default(),);
                    println!("\t\tDecoupled: {}", key.decoupled(),);
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
            Commands::Get { subcommand } => ws.get_command(subcommand),
            Commands::Set { subcommand } => ws.set_command(subcommand)?,
            Commands::Show => {
                println!("state-file: {:?}", ws.config.state_file);
                println!("use-csk: {}", ws.config.use_csk);
                println!("algorithm: {}", ws.config.algorithm);
                println!("ksk-validity: {:?}", ws.config.ksk_validity);
                println!("zsk-validity: {:?}", ws.config.zsk_validity);
                println!("csk-validity: {:?}", ws.config.csk_validity);
                println!(
                    "auto-ksk: start {}, report {}, expire {}, done {}",
                    ws.config.auto_ksk.start,
                    ws.config.auto_ksk.report,
                    ws.config.auto_ksk.expire,
                    ws.config.auto_ksk.done,
                );
                println!(
                    "auto-zsk: start {}, report {}, expire {}, done {}",
                    ws.config.auto_zsk.start,
                    ws.config.auto_zsk.report,
                    ws.config.auto_zsk.expire,
                    ws.config.auto_zsk.done,
                );
                println!(
                    "auto-csk: start {}, report {}, expire {}, done {}",
                    ws.config.auto_csk.start,
                    ws.config.auto_csk.report,
                    ws.config.auto_csk.expire,
                    ws.config.auto_csk.done,
                );
                println!(
                    "auto-algorithm: start {}, report {}, expire {}, done {}",
                    ws.config.auto_algorithm.start,
                    ws.config.auto_algorithm.report,
                    ws.config.auto_algorithm.expire,
                    ws.config.auto_algorithm.done,
                );
                println!(
                    "dnskey-inception-offset: {:?}",
                    ws.config.dnskey_inception_offset
                );
                println!(
                    "dnskey-signature-lifetime: {:?}",
                    ws.config.dnskey_signature_lifetime
                );
                println!("dnskey-remain-time: {:?}", ws.config.dnskey_remain_time);
                println!("cds-inception-offset: {:?}", ws.config.cds_inception_offset);
                println!(
                    "cds-signature-lifetime: {:?}",
                    ws.config.cds_signature_lifetime
                );
                println!("cds-remain-time: {:?}", ws.config.cds_remain_time);
                println!("ds-algorithm: {:?}", ws.config.ds_algorithm);
                println!("default-ttl: {:?}", ws.config.default_ttl);
                println!("autoremove: {:?}", ws.config.autoremove);
                println!("autoremove-delay: {:?}", ws.config.autoremove_delay);
                println!("update_ds_command: {:?}", ws.config.update_ds_command);
                // Only print faketime when it exists.
                if let Some(faketime) = &ws.config.faketime {
                    println!(
                        "fake-time: {}",
                        <UnixTime as Into<Duration>>::into(faketime.clone()).as_secs()
                    );
                }
            }
            Commands::Cron => {
                if sig_renew(
                    &ws.state.dnskey_rrset,
                    &ws.config.dnskey_remain_time,
                    now.clone(),
                ) {
                    println!("DNSKEY RRSIG(s) need to be renewed");
                    ws.update_dnskey_rrset(env, false)?;
                    ws.state_changed = true;
                }
                if sig_renew(&ws.state.cds_rrset, &ws.config.cds_remain_time, now.clone()) {
                    println!("CDS/CDNSKEY RRSIGs need to be renewed");
                    ws.create_cds_rrset(env, false)?;
                    ws.state_changed = true;
                }

                let need_algorithm_roll = ws.algorithm_roll_needed();

                if ws.config.use_csk || need_algorithm_roll {
                    // Start a CSK or algorithm roll if the KSK has expired.
                    // All other rolls are a conflict.
                    ws.auto_start(
                        ws.config.ksk_validity,
                        if need_algorithm_roll {
                            ws.config.auto_algorithm.clone()
                        } else {
                            ws.config.auto_csk.clone()
                        },
                        env,
                        |_| true,
                        |keytype| {
                            if let KeyType::Ksk(keystate) = keytype {
                                Some(keystate)
                            } else {
                                None
                            }
                        },
                        if need_algorithm_roll {
                            WorkSpace::start_algorithm_roll
                        } else {
                            WorkSpace::start_csk_roll
                        },
                    )?;

                    // The same for the ZSK.
                    ws.auto_start(
                        ws.config.zsk_validity,
                        if need_algorithm_roll {
                            ws.config.auto_algorithm.clone()
                        } else {
                            ws.config.auto_csk.clone()
                        },
                        env,
                        |_| true,
                        |keytype| {
                            if let KeyType::Zsk(keystate) = keytype {
                                Some(keystate)
                            } else {
                                None
                            }
                        },
                        if need_algorithm_roll {
                            WorkSpace::start_algorithm_roll
                        } else {
                            WorkSpace::start_csk_roll
                        },
                    )?;
                } else {
                    ws.auto_start(
                        ws.config.ksk_validity,
                        ws.config.auto_ksk.clone(),
                        env,
                        |r| r != RollType::ZskRoll && r != RollType::ZskDoubleSignatureRoll,
                        |keytype| {
                            if let KeyType::Ksk(keystate) = keytype {
                                Some(keystate)
                            } else {
                                None
                            }
                        },
                        WorkSpace::start_ksk_roll,
                    )?;

                    ws.auto_start(
                        ws.config.zsk_validity,
                        ws.config.auto_zsk.clone(),
                        env,
                        |r| r != RollType::KskRoll && r != RollType::KskDoubleDsRoll,
                        |keytype| {
                            if let KeyType::Zsk(keystate) = keytype {
                                Some(keystate)
                            } else {
                                None
                            }
                        },
                        WorkSpace::start_zsk_roll,
                    )?;
                }

                ws.auto_start(
                    ws.config.csk_validity,
                    if need_algorithm_roll {
                        ws.config.auto_algorithm.clone()
                    } else {
                        ws.config.auto_csk.clone()
                    },
                    env,
                    |_| true,
                    |keytype| {
                        if let KeyType::Csk(keystate, _) = keytype {
                            Some(keystate)
                        } else {
                            None
                        }
                    },
                    if need_algorithm_roll {
                        WorkSpace::start_algorithm_roll
                    } else {
                        WorkSpace::start_csk_roll
                    },
                )?;

                ws.auto_report_expire_done(
                    ws.config.auto_ksk.clone(),
                    &[RollType::KskRoll, RollType::KskDoubleDsRoll],
                    env,
                )
                .await?;
                ws.auto_report_expire_done(
                    ws.config.auto_zsk.clone(),
                    &[RollType::ZskRoll, RollType::ZskDoubleSignatureRoll],
                    env,
                )
                .await?;
                ws.auto_report_expire_done(ws.config.auto_csk.clone(), &[RollType::CskRoll], env)
                    .await?;
                ws.auto_report_expire_done(
                    ws.config.auto_algorithm.clone(),
                    &[RollType::AlgorithmRoll],
                    env,
                )
                .await?;

                let autoremove = ws.config.autoremove;
                let autoremove_delay = ws.config.autoremove_delay;
                let now = UnixTime::now();
                if autoremove {
                    let key_urls: Vec<_> = ws
                        .state
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
                                && key
                                    .timestamps()
                                    .withdrawn()
                                    .expect("should be present if stale")
                                    + autoremove_delay
                                    <= now
                        })
                        .map(|(pubref, key)| (pubref.clone(), key.privref().map(|r| r.to_string())))
                        .collect();
                    if !key_urls.is_empty() {
                        for u in key_urls {
                            let (pubref, privref) = &u;
                            ws.state
                                .keyset
                                .delete_key(pubref)
                                .map_err(|e| format!("unable to remove key {pubref}: {e}\n"))?;
                            if let Some(privref) = privref {
                                let priv_url = Url::parse(privref).map_err(|e| {
                                    format!("unable to parse {privref} as URL: {e}")
                                })?;
                                ws.remove_key(priv_url)?;
                            }
                            let pub_url = Url::parse(pubref)
                                .map_err(|e| format!("unable to parse {pubref} as URL: {e}"))?;
                            ws.remove_key(pub_url)?;
                        }
                        ws.state_changed = true;
                    }
                }
            }

            #[cfg(feature = "kmip")]
            Commands::Kmip { subcommand } => {
                ws.state_changed = kmip_command(env, subcommand, &mut ws.state)?;
            }
        }

        if !ws.config_changed && !ws.state_changed {
            // No need to update cron_next if nothing has changed.
            return Ok(());
        }

        let mut cron_next = Vec::new();

        cron_next.push(compute_cron_next(
            &ws.state.dnskey_rrset,
            &ws.config.dnskey_remain_time,
            now.clone(),
        ));

        cron_next.push(compute_cron_next(
            &ws.state.cds_rrset,
            &ws.config.cds_remain_time,
            now,
        ));

        let need_algorithm_roll = ws.algorithm_roll_needed();

        if ws.config.use_csk || need_algorithm_roll {
            cron_next_auto_start(
                ws.config.ksk_validity,
                if need_algorithm_roll {
                    &ws.config.auto_algorithm
                } else {
                    &ws.config.auto_csk
                },
                &ws.state,
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
                ws.config.zsk_validity,
                if need_algorithm_roll {
                    &ws.config.auto_algorithm
                } else {
                    &ws.config.auto_csk
                },
                &ws.state,
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
                ws.config.ksk_validity,
                &ws.config.auto_ksk,
                &ws.state,
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
                ws.config.zsk_validity,
                &ws.config.auto_zsk,
                &ws.state,
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
            ws.config.csk_validity,
            if need_algorithm_roll {
                &ws.config.auto_algorithm
            } else {
                &ws.config.auto_csk
            },
            &ws.state,
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

        ws.cron_next_auto_report_expire_done(
            &ws.config.auto_ksk,
            &[RollType::KskRoll, RollType::KskDoubleDsRoll],
            &ws.state,
            &mut cron_next,
        )?;
        ws.cron_next_auto_report_expire_done(
            &ws.config.auto_zsk,
            &[RollType::ZskRoll, RollType::ZskDoubleSignatureRoll],
            &ws.state,
            &mut cron_next,
        )?;
        ws.cron_next_auto_report_expire_done(
            &ws.config.auto_csk,
            &[RollType::CskRoll],
            &ws.state,
            &mut cron_next,
        )?;
        ws.cron_next_auto_report_expire_done(
            &ws.config.auto_algorithm,
            &[RollType::AlgorithmRoll],
            &ws.state,
            &mut cron_next,
        )?;

        if ws.config.autoremove {
            let mut next_list: Vec<_> = ws
                .state
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
                .map(|(_, key)| {
                    Some(
                        key.timestamps()
                            .withdrawn()
                            .expect("should be set when stale")
                            + ws.config.autoremove_delay,
                    )
                })
                .collect();
            cron_next.append(&mut next_list);
        }

        let cron_next = cron_next.iter().filter_map(|e| e.clone()).min();

        if cron_next != ws.state.cron_next {
            ws.state.cron_next = cron_next;
            ws.state_changed = true;
        }
        if ws.config_changed {
            ws.write_config(&self.keyset_conf)?;
        }
        if ws.state_changed {
            ws.write_state()?;
        }

        // Now check if we need to run the update_ds_command. Make sure that
        // all locks are released before running the command. The command
        // may want to call back into keyset to retreive the DS
        // (or CDS/CDNSKEY) records.
        if ws.run_update_ds_command && !ws.config.update_ds_command.is_empty() {
            let output = Command::new(&ws.config.update_ds_command[0])
                .args(&ws.config.update_ds_command[1..])
                .output()
                .map_err(|e| {
                    format!(
                        "creating for command for {} failed: {e}",
                        ws.config.update_ds_command[0]
                    )
                })?;
            if !output.status.success() {
                println!("update command failed with: {}", output.status);
                io::stdout()
                    .write_all(&output.stdout)
                    .map_err(|e| format!("writing to stdout failed: {e}"))?;
                io::stderr()
                    .write_all(&output.stderr)
                    .map_err(|e| format!("writing to stderr failed: {e}"))?;
            }
        }

        Ok(())
    }
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

    /// The TTL to use when creating DNSKEY/CDS/CDNSKEY records.
    default_ttl: Ttl,

    /// Automatically remove keys that are no long in use.
    autoremove: bool,

    /// Delay after a key pair has become stale when it can be removed
    /// automatically.
    #[serde(default = "default_autoremove_delay")]
    autoremove_delay: Duration,

    /// Command to run when the DS records at the parent need updating.
    update_ds_command: Vec<String>,

    /// Fake time to use when signing.
    ///
    /// This is need for integration tests.
    faketime: Option<UnixTime>,
}

/// Configuration for key roll automation.
#[derive(Clone, Default, Deserialize, Serialize)]
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
pub struct KeySetState {
    /// Domain KeySet state.
    pub keyset: KeySet,

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

    /// KMIP related configuration.
    #[cfg(feature = "kmip")]
    #[serde(default)]
    pub kmip: KmipState,

    /// Internal state for automatic key rolls.
    internal: HashMap<RollType, RollStateReports>,
}

/// Parameters for creating a new key.
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

/// State for the report progration checks.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ReportState {
    /// State for DNSKEY propagation checks.
    dnskey: Option<AutoReportActionsResult>,
    /// State for DS propagation checks.
    ds: Option<AutoReportActionsResult>,
    /// State for RRSIG propagation checks.
    rrsig: Option<AutoReportRrsigResult>,
}

// Put functions here that take WorkSpace as a parameter.
impl WorkSpace {
    /// Implement the get subcommand.
    fn get_command(&self, cmd: GetCommands) {
        match cmd {
            GetCommands::UseCsk => {
                println!("{}", self.config.use_csk);
            }
            GetCommands::Autoremove => {
                println!("{}", self.config.autoremove);
            }
            GetCommands::AutoremoveDelay => {
                let span = Span::try_from(self.config.autoremove_delay).expect("should not fail");
                let dur = span
                    .to_duration(SpanRelativeTo::days_are_24_hours())
                    .expect("should not fail");
                println!("{dur:#}");
            }
            GetCommands::Algorithm => {
                println!("{}", self.config.algorithm);
            }
            GetCommands::DsAlgorithm => {
                println!("{}", self.config.ds_algorithm);
            }
            GetCommands::DnskeyLifetime => {
                let span =
                    Span::try_from(self.config.dnskey_signature_lifetime).expect("should not fail");
                let signeddur = span
                    .to_duration(SpanRelativeTo::days_are_24_hours())
                    .expect("should not fail");
                println!("{signeddur:#}");
            }
            GetCommands::CdsLifetime => {
                let span =
                    Span::try_from(self.config.cds_signature_lifetime).expect("should not fail");
                let signeddur = span
                    .to_duration(SpanRelativeTo::days_are_24_hours())
                    .expect("should not fail");
                println!("{signeddur:#}");
            }
            GetCommands::Dnskey => {
                for r in &self.state.dnskey_rrset {
                    println!("{r}");
                }
            }
            GetCommands::Cds => {
                for r in &self.state.cds_rrset {
                    println!("{r}");
                }
            }
            GetCommands::Ds => {
                for r in &self.state.ds_rrset {
                    println!("{r}");
                }
            }
        }
    }

    /// Implement the set subcommand.
    fn set_command(&mut self, cmd: SetCommands) -> Result<(), Error> {
        match cmd {
            SetCommands::UseCsk { boolean } => {
                self.config.use_csk = boolean;
            }
            SetCommands::Autoremove { boolean } => {
                self.config.autoremove = boolean;
            }
            SetCommands::AutoremoveDelay { delay } => {
                self.config.autoremove_delay = delay;
            }
            SetCommands::Algorithm { algorithm, bits } => {
                self.config.algorithm = KeyParameters::new(&algorithm, bits)?;
            }
            SetCommands::AutoKsk {
                start,
                report,
                expire,
                done,
            } => {
                self.config.auto_ksk = AutoConfig {
                    start,
                    report,
                    expire,
                    done,
                };
                self.config_changed = true;
            }
            SetCommands::AutoZsk {
                start,
                report,
                expire,
                done,
            } => {
                self.config.auto_zsk = AutoConfig {
                    start,
                    report,
                    expire,
                    done,
                };
                self.config_changed = true;
            }
            SetCommands::AutoCsk {
                start,
                report,
                expire,
                done,
            } => {
                self.config.auto_csk = AutoConfig {
                    start,
                    report,
                    expire,
                    done,
                };
                self.config_changed = true;
            }
            SetCommands::AutoAlgorithm {
                start,
                report,
                expire,
                done,
            } => {
                self.config.auto_algorithm = AutoConfig {
                    start,
                    report,
                    expire,
                    done,
                };
                self.config_changed = true;
            }
            SetCommands::DsAlgorithm { algorithm } => {
                self.config.ds_algorithm = algorithm;
            }
            SetCommands::DnskeyInceptionOffset { duration } => {
                self.config.dnskey_inception_offset = duration;
            }
            SetCommands::DnskeyLifetime { duration } => {
                self.config.dnskey_signature_lifetime = duration;
            }
            SetCommands::DnskeyRemainTime { duration } => {
                self.config.dnskey_remain_time = duration;
            }
            SetCommands::CdsInceptionOffset { duration } => {
                self.config.cds_inception_offset = duration;
            }
            SetCommands::CdsLifetime { duration } => {
                self.config.cds_signature_lifetime = duration;
            }
            SetCommands::CdsRemainTime { duration } => {
                self.config.cds_remain_time = duration;
            }
            SetCommands::KskValidity { opt_duration } => {
                self.config.ksk_validity = opt_duration;
            }
            SetCommands::ZskValidity { opt_duration } => {
                self.config.zsk_validity = opt_duration;
            }
            SetCommands::CskValidity { opt_duration } => {
                self.config.csk_validity = opt_duration;
            }
            SetCommands::DefaultTtl { ttl } => {
                self.config.default_ttl = Ttl::from_secs(ttl);
            }
            SetCommands::UpdateDsCommand { args } => {
                self.config.update_ds_command = args;
            }
            SetCommands::FakeTime { opt_unixtime } => self.config.faketime = opt_unixtime,
        }
        self.config_changed = true;
        Ok(())
    }

    /// Execute the key roll subcommands.
    fn roll_command(
        &mut self,
        cmd: RollCommands,
        roll_variant: RollVariant,
        env: &impl Env,
    ) -> Result<(), Error> {
        let actions = match cmd {
            RollCommands::StartRoll => {
                let actions = match roll_variant {
                    RollVariant::Ksk => self.start_ksk_roll(env, true)?,
                    RollVariant::Zsk => self.start_zsk_roll(env, true)?,
                    RollVariant::Csk => self.start_csk_roll(env, true)?,
                    RollVariant::Algorithm => self.start_algorithm_roll(env, true)?,
                };

                print_actions(&actions);
                self.state_changed = true;
                return Ok(());
            }
            RollCommands::Propagation1Complete { ttl } => {
                let roll = roll_variant.roll_variant_to_roll();
                self.state.keyset.propagation1_complete(roll, ttl)
            }
            RollCommands::CacheExpired1 => {
                let roll = roll_variant.roll_variant_to_roll();
                self.state.keyset.cache_expired1(roll)
            }
            RollCommands::Propagation2Complete { ttl } => {
                let roll = roll_variant.roll_variant_to_roll();
                self.state.keyset.propagation2_complete(roll, ttl)
            }
            RollCommands::CacheExpired2 => {
                let roll = roll_variant.roll_variant_to_roll();
                self.state.keyset.cache_expired2(roll)
            }
            RollCommands::RollDone => {
                let roll = roll_variant.roll_variant_to_roll();
                self.do_done(roll)?;
                self.state_changed = true;
                return Ok(());
            }
        };

        let actions = match actions {
            Ok(actions) => actions,
            Err(err) => {
                return Err(format!("Error reporting propagation complete: {err}\n").into());
            }
        };

        self.handle_actions(&actions, env, true)?;

        // Report actions
        print_actions(&actions);
        self.state_changed = true;
        Ok(())
    }

    /// Implementation of the Import subcommands.
    fn import_command(&mut self, subcommand: ImportCommands, env: &impl Env) -> Result<(), Error> {
        let now = self.faketime_or_now();
        match subcommand {
            ImportCommands::PublicKey { path } => {
                let public_data = std::fs::read_to_string(&path)
                    .map_err(|e| format!("unable read from file {}: {e}", path.display()))?;

                let public_key = parse_from_bind::<Vec<u8>>(&public_data).map_err(|e| {
                    format!("unable to parse public key file {}: {e}", path.display())
                })?;

                let path = absolute(&path)
                    .map_err(|e| format!("unable to make {} absolute: {}", path.display(), e))?;
                let public_key_url = "file://".to_owned() + &path.display().to_string();
                self.state
                    .keyset
                    .add_public_key(
                        public_key_url.clone(),
                        public_key.data().algorithm(),
                        public_key.data().key_tag(),
                        now.clone(),
                        true,
                    )
                    .map_err(|e| format!("unable to add public key {public_key_url}: {e}\n"))?;
                self.state
                    .keyset
                    .set_present(&public_key_url, true)
                    .expect("should not happen");

                // What about visible. We should visible when DNSKEY RRset has
                // propagated. But we are not doing a key roll now. Just set it
                // unconditionally.
                self.state
                    .keyset
                    .set_visible(&public_key_url, now)
                    .expect("should not happen");
            }
            ImportCommands::Ksk { subcommand } => {
                self.import_key_command(subcommand, KeyVariant::Ksk)?;
            }
            ImportCommands::Zsk { subcommand } => {
                self.import_key_command(subcommand, KeyVariant::Zsk)?;
            }
            ImportCommands::Csk { subcommand } => {
                self.import_key_command(subcommand, KeyVariant::Csk)?;
            }
        }
        self.state_changed = true;

        // Update the DNSKEY RRset if is is not empty. We don't want to create
        // an incomplete DNSKEY RRset.
        if !self.state.dnskey_rrset.is_empty() {
            self.update_dnskey_rrset(env, true)?;
        }
        Ok(())
    }

    /// Implement import subcommand for a specific key type.
    fn import_key_command(
        &mut self,
        subcommand: ImportKeyCommands,
        key_variant: KeyVariant,
    ) -> Result<(), Error> {
        let now = self.faketime_or_now();
        let (public_key_url, private_key_url, algorithm, key_tag, coupled) = match subcommand {
            ImportKeyCommands::File {
                path,
                coupled,
                private_key,
            } => {
                let private_path = match private_key {
                    Some(private_key) => private_key,
                    None => {
                        if path.extension() != Some(OsStr::new("key")) {
                            return Err(format!("public key {} should end in .key, use --private-key to specify a private key separately", path.display()).into());
                        }
                        path.with_extension("private")
                    }
                };
                let private_data = std::fs::read_to_string(&private_path).map_err(|e| {
                    format!("unable read from file {}: {e}", private_path.display())
                })?;
                let secret_key = SecretKeyBytes::parse_from_bind(&private_data).map_err(|e| {
                    format!(
                        "unable to parse private key file {}: {e}",
                        private_path.display()
                    )
                })?;
                let public_data = std::fs::read_to_string(&path)
                    .map_err(|e| format!("unable read from file {}: {e}", path.display()))?;
                let public_key = parse_from_bind::<Vec<u8>>(&public_data).map_err(|e| {
                    format!("unable to parse public key file {}: {e}", path.display())
                })?;

                // Check the consistency of the public and private key pair.
                let _key_pair =
                    KeyPair::from_bytes(&secret_key, public_key.data()).map_err(|e| {
                        format!(
                            "private key {} and public key {} do not match: {e}",
                            private_path.display(),
                            path.display()
                        )
                    })?;

                if public_key.owner() != self.state.keyset.name() {
                    return Err(format!(
                        "public key {} has wrong owner name {}, expected {}",
                        path.display(),
                        public_key.owner(),
                        self.state.keyset.name()
                    )
                    .into());
                }

                let path = absolute(&path)
                    .map_err(|e| format!("unable to make {} absolute: {}", path.display(), e))?;
                let private_path = absolute(&private_path).map_err(|e| {
                    format!("unable to make {} absolute: {}", private_path.display(), e)
                })?;
                let public_key_url = "file://".to_owned() + &path.display().to_string();
                let private_key_url = "file://".to_owned() + &private_path.display().to_string();

                (
                    public_key_url,
                    private_key_url,
                    public_key.data().algorithm(),
                    public_key.data().key_tag(),
                    coupled,
                )
            }
            #[cfg(feature = "kmip")]
            ImportKeyCommands::Kmip {
                server,
                public_id,
                private_id,
                algorithm,
                flags,
                coupled,
            } => {
                let pool = self.state.kmip.get_pool(&mut self.pools, &server)?;
                let keypair = kmip::sign::KeyPair::from_metadata(
                    algorithm,
                    flags,
                    &private_id,
                    &public_id,
                    pool,
                )
                .map_err(|e| {
                    format!("error constructing key pair on KMIP server '{server}': {e}")
                })?;
                let public_key_url = keypair.public_key_url();
                let private_key_url = keypair.private_key_url();
                (
                    public_key_url.to_string(),
                    private_key_url.to_string(),
                    keypair.algorithm(),
                    keypair.dnskey().key_tag(),
                    coupled,
                )
            }
        };
        let mut set_at_parent = false;
        let mut set_rrsig_visible = false;
        match key_variant {
            KeyVariant::Ksk => {
                self.state
                    .keyset
                    .add_key_ksk(
                        public_key_url.clone(),
                        Some(private_key_url.clone()),
                        algorithm,
                        key_tag,
                        now.clone(),
                        Available::Available,
                    )
                    .map_err(|e| {
                        format!("unable to add KSK {public_key_url}/{private_key_url}: {e}\n")
                    })?;
                set_at_parent = true;
            }
            KeyVariant::Zsk => {
                self.state
                    .keyset
                    .add_key_zsk(
                        public_key_url.clone(),
                        Some(private_key_url.clone()),
                        algorithm,
                        key_tag,
                        now.clone(),
                        Available::Available,
                    )
                    .map_err(|e| format!("unable to add ZSK {public_key_url}: {e}\n"))?;
                set_rrsig_visible = true;
            }
            KeyVariant::Csk => {
                self.state
                    .keyset
                    .add_key_csk(
                        public_key_url.clone(),
                        Some(private_key_url.clone()),
                        algorithm,
                        key_tag,
                        now.clone(),
                        Available::Available,
                    )
                    .map_err(|e| format!("unable to add CSK {public_key_url}: {e}\n"))?;
                set_at_parent = true;
                set_rrsig_visible = true;
            }
        }

        self.state
            .keyset
            .set_present(&public_key_url, true)
            .expect("should not happen");

        // What about visible? We should visible when the DNSKEY
        // RRset has propagated. But we are not doing a key roll
        // now. Just set it unconditionally.
        self.state
            .keyset
            .set_visible(&public_key_url, now.clone())
            .expect("should not happen");

        self.state
            .keyset
            .set_signer(&public_key_url, true)
            .expect("should not happen");

        self.state
            .keyset
            .set_decoupled(&public_key_url, !coupled)
            .expect("should not happen");

        if set_at_parent {
            self.state
                .keyset
                .set_at_parent(&public_key_url, true)
                .expect("should not happen");

            // What about ds_visible? We should ds_visible when the DS
            // RRset has propagated. But we are not doing a key roll
            // now. Just set it unconditionally.
            self.state
                .keyset
                .set_ds_visible(&public_key_url, now.clone())
                .expect("should not happen");
        }
        if set_rrsig_visible {
            // We should set rrsig_visible when the zone's RRSIG records
            // have propagated. But we are not doing a key roll
            // now. Just set it unconditionally.
            self.state
                .keyset
                .set_rrsig_visible(&public_key_url, now)
                .expect("should not happen");
        }
        Ok(())
    }

    /// Implement the remove-key subcommand.
    fn remove_key_command(
        &mut self,
        key: String,
        force: bool,
        continue_flag: bool,
    ) -> Result<(), Error> {
        // The strategy depends on whether the key is decoupled or not.
        // If the key is decoupled, then just remove the key from the keyset
        // and leave underlying keys where they are.
        // If the key is not decoupled, then we also need to remove the
        // underlying keys. In that case, first check if the key is stale or
        // if force is set.
        // Then remove the private key (if any). If that fails abort unless
        // continue is set. Then remove the public key. If that fails and the
        // private key is remove then just log an error. Finally remove the key
        // from the keyset.
        // If force is true, then mark the key stale before removing.
        let Some(k) = self.state.keyset.keys().get(&key) else {
            return Err(format!("key {key} not found").into());
        };
        let k = k.clone();
        if k.decoupled() {
            if force {
                self.state.keyset.set_stale(&key).expect("should not fail");
            }
            self.state
                .keyset
                .delete_key(&key)
                .map_err(|e| format!("unable to remove key {key}: {e}").into())
        } else {
            let stale = match k.keytype() {
                KeyType::Ksk(keystate) | KeyType::Zsk(keystate) | KeyType::Include(keystate) => {
                    keystate.stale()
                }
                KeyType::Csk(ksk_keystate, zsk_keystate) => {
                    ksk_keystate.stale() && zsk_keystate.stale()
                }
            };
            if !stale && !force {
                return Err(format!(
                    "unable to remove key {key}. Key is not stale. Use --force to override"
                )
                .into());
            }

            // If there is a private key then try to remove that one first. We
            // don't want lingering private key when something else fails.
            if let Some(privref) = k.privref() {
                let private_key_url = Url::parse(privref)
                    .map_err(|e| format!("unable to parse {privref} as Url: {e}"))?;
                let res = self.remove_key(private_key_url);
                if !continue_flag {
                    res?;
                } else if let Err(e) = res {
                    error!("unable to remove key {privref}: {e}");
                }
            }

            // Move on to the public key.
            let public_key_url =
                Url::parse(&key).map_err(|e| format!("unable to parse {key} as Url: {e}"))?;
            let res = self.remove_key(public_key_url);
            if k.privref().is_some() || continue_flag {
                // Ignore errors removing a public key if we previously removed
                // (or tried to remove) a private key. Or if we are told to
                // continue.
                if let Err(e) = res {
                    error!("unable to remove key {key}: {e}");
                }
            } else {
                res?;
            }
            if force {
                self.state.keyset.set_stale(&key).expect("should not fail");
            }
            self.state
                .keyset
                .delete_key(&key)
                .map_err(|e| format!("unable to remove key {key}: {e}").into())
        }
    }

    /// Take a URL, get the public key and return a Record<_, Dnskey<_>>.
    fn public_key_from_url<Octs>(
        &mut self,
        pub_url: &Url,
        env: &impl Env,
    ) -> Result<Record<Name<Octs>, Dnskey<Octs>>, Error>
    where
        Octs: FromBuilder + OctetsFrom<Vec<u8>>,
        <Octs as OctetsFrom<Vec<u8>>>::Error: Display,
    {
        match pub_url.scheme() {
            "file" => {
                let path = pub_url.path();
                let filename = env.in_cwd(&path);

                let public_data = std::fs::read_to_string(&filename)
                    .map_err(|e| format!("unable read from file {}: {e}", filename.display()))?;
                let mut public_key = parse_from_bind::<Vec<u8>>(&public_data).map_err(|e| {
                    format!(
                        "unable to parse public key file {}: {e}",
                        filename.display()
                    )
                })?;

                public_key.set_ttl(self.config.default_ttl);
                let public_key = Record::try_octets_from(public_key)
                    .map_err(|e| format!("try_octets_from failed: {e}"))?;
                Ok(public_key)
            }

            #[cfg(feature = "kmip")]
            "kmip" => {
                let kmip_key_url = KeyUrl::try_from(pub_url.clone())?;
                let flags = kmip_key_url.flags();
                let kmip_conn_pool = self
                    .state
                    .kmip
                    .get_pool(&mut self.pools, kmip_key_url.server_id())?;
                let key = kmip::PublicKey::for_key_url(kmip_key_url, kmip_conn_pool)
                    .map_err(|err| format!("Failed to fetch public key for KMIP key URL: {err}"))?;
                let owner: Name<Octs> = self
                    .state
                    .keyset
                    .name()
                    .clone()
                    .try_flatten_into()
                    .map_err(|e| format!(".try_flatten_into failed: {e}"))?;
                let record = Record::new(
                    owner,
                    Class::IN,
                    self.config.default_ttl,
                    Dnskey::try_octets_from(key.dnskey(flags))
                        .map_err(|e| format!("try_octets_from failed: {e}"))?,
                );
                Ok(record)
            }

            _ => {
                panic!("unsupported scheme in {pub_url}");
            }
        }
    }

    /// Create a new public/private key pair and return the URLs of the
    /// keys.
    fn new_keys(
        &mut self,
        make_ksk: bool,
        env: &impl Env,
    ) -> Result<(Url, Url, SecurityAlgorithm, u16), Error> {
        let algorithm = self.config.algorithm.to_generate_params();
        let name = self.state.keyset.name();
        let keys = self.state.keyset.keys();
        let keys_dir = &self.config.keys_dir;
        #[cfg(feature = "kmip")]
        let kmip = &mut self.state.kmip;

        // Generate the key.
        // TODO: Add a high-level operation in 'domain' to select flags?
        let flags = if make_ksk { 257 } else { 256 };
        let mut retries = MAX_KEY_TAG_TRIES;

        // If a default KMIP server is configured, use that to generate keys
        #[cfg(feature = "kmip")]
        if let Some(kmip_conn_pool) = kmip.get_default_pool(&mut self.pools)? {
            let (key_pair, dnskey) = loop {
                // TODO: Fortanix DSM rejects attempts to create keys by names
                // that are already taken. Should we be able to detect that case
                // specifically and try again with a different name? Should we add
                // a random element to each name? Should we keep track of used
                // names and detect a collision ourselves when choosing a name?
                // Is there some natural differentiator that can be used to name
                // keys uniquely other than zone name?
                //
                // Elements to include in a key name:
                //   - Application, e.g. Nameshed or NS.
                //   - Namespace, e.g. prod or test or dev.
                //   - Key type, e.g. KSK or ZSK.
                //   - Zone name, e.g. example.com, but also a.b.c.d.f.com
                //   - Uniqifier, e.g. to differentiate pre-generated keys for
                //     the same zone.
                //
                // Max 32 characters seem to be wise as that is the lowest limit
                // used amongst PKCS#11 HSM providers for a which a limit is
                // known.
                //
                // Use an overridable naming template? E.g. support placeholders
                // such as <key type>, <uniqifier> and <zone name>, with a default
                // of:
                //
                //   <zone name>-<uniqifier>-<key type>
                //
                // Where <uniqifier> is 2 bytes long and <key type> is 3 bytes
                // long, leaving 32 - '-' - 2 - '-' - 3 = 32 - 7 = 25 bytes for
                // <zone name>, which can be abbreviated if too long by replacing
                // the middle with '...' and <uniqifier> is a 0 padded positive
                // integer in the range 00..99 giving 100 keys to roll the zone
                // up to twice a week without needing to use 00 again.
                //
                // When overridden a user could include fixed namespace and
                // application values, e.g.:
                //
                //   NS-PROD-<zone name>-<uniqifier>-<key type>
                //
                // Resulting in key names like:
                //
                //   NS-PROD-example.com-001-ksk
                //   NS-DEV-some.lo...in-name-013-zsk
                //   (shrunk from NS-DEV-some.long-domain-name-013-zsk)
                //   01234567890123456789012345678901
                //
                // However, regarding <uniqifier>, it may be that pre-generation
                // should be accomplished differently, by generating the keys
                // outside of dnst keyset and importing them. But it may still
                // be useful to consider what to do if a key fails to generate,
                // should we retry with an integer value at the end of the zone
                // name (within the 32 byte limit - aside: should that limit also
                // be configurable?), can we even tell that failure was due to a
                // name collision?
                //
                // Alternate proposals are to use <prefix>-<zone name>-<key
                // type> or even a random number then re-labeled post-generation
                // to include the key tag (which requires the generated key to
                // determine). The initial random number is to avoid conflcits if
                // re-labeling fails.
                //
                // And for <uniqifier> to be a hexified 16-bit random number that
                // we can scan existing keys for to avoid conflict with a key that
                // we might have generated before.
                //
                // And for name truncation to keep the last label (TLD) then remove
                // next nearest labels until the name fits the limit, and add an
                // extra '.' in to make it clear it was truncated, else keep the
                // first n characters.
                //
                // And to make the max limit be configurable for HSMs that support
                // longer than 32 bytes. We could also make the entire label a user
                // overridable format/template string.
                //
                // For now we will do:
                //
                //   1. Configurable label length limit defaulting to 32 bytes.
                //   2. Initial hexified random 32-byte label.
                //   3. Relabel to: <prefix>-<(partial) zone name>-<key tag>-<key type>.

                // Generate initial hexified random byte label.

                let server_id = kmip_conn_pool.server_id();
                let key_label_cfg = &mut kmip.servers.get_mut(server_id).unwrap().key_label_config;

                let mut rnadom_bytes = vec![0; key_label_cfg.max_label_bytes as usize];
                rand::fill(&mut rnadom_bytes[..]);
                let public_key_random_label = encode_string_hex(&rnadom_bytes);

                let mut random_bytes = vec![0; key_label_cfg.max_label_bytes as usize];
                rand::fill(&mut random_bytes[..]);
                let private_key_random_label = encode_string_hex(&random_bytes);

                let key_pair = kmip::sign::generate(
                    public_key_random_label,
                    private_key_random_label,
                    algorithm.clone(),
                    flags,
                    kmip_conn_pool.clone(),
                )
                .map_err(|e| format!("KMIP key generation failed: {e}\n"))?;

                let dnskey = key_pair.dnskey();

                if !keys.iter().any(|(_, k)| k.key_tag() == dnskey.key_tag()) {
                    if key_label_cfg.supports_relabeling {
                        // Re-label the key now that we know the key tag.
                        let key_type = match make_ksk {
                            true => "ksk",
                            false => "zsk",
                        };

                        let prefix = &key_label_cfg.prefix;
                        let key_tag = dnskey.key_tag().to_string();
                        let zone_name = name.to_string();
                        let max_label_bytes = key_label_cfg.max_label_bytes as usize;

                        let public_key_label = format_key_label(
                            prefix,
                            &zone_name,
                            &key_tag,
                            key_type,
                            "-pub",
                            max_label_bytes,
                        );

                        if let Err(err) = &public_key_label {
                            warn!("Failed to generate label for public key, key will have a hex label: {err}");
                        }

                        let private_key_label = format_key_label(
                            prefix,
                            &zone_name,
                            &key_tag,
                            key_type,
                            "-pri",
                            max_label_bytes,
                        );

                        if let Err(err) = &private_key_label {
                            warn!("Failed to generate label for private key, key will have a hex label: {err}");
                        }

                        if let (Ok(public_key_label), Ok(private_key_label)) =
                            (public_key_label, private_key_label)
                        {
                            let conn = kmip_conn_pool.get()?;
                            // If key generation succeeded then the most likely reason
                            // for the rename operation to fail is lack of support for
                            // key relabeling.
                            match conn.rename_key(key_pair.public_key_id(), public_key_label) {
                                Ok(_res) => {
                                    // TODO: Inspect the response attributes to see if
                                    // the Modify Attribute operation actually changed
                                    // the attribute as requested?

                                    // If re-labelling the public key succeeded but
                                    // re-labelling the private key fails, that is
                                    // unexpected. Why would it succeed for one and
                                    // fail for the other?
                                    conn.rename_key(key_pair.private_key_id(), private_key_label)
				.map_err(|e| format!("KMIP key generation failed: failed to re-label private key with id {}: {e}", key_pair.private_key_id()))?;
                                }
                                Err(err) => {
                                    // Assume that key re-labeling is not supported
                                    // and disable future re-labeling attempts for
                                    // this server.
                                    warn!("KMIP post key generation re-labeling with server '{server_id}' failed, re-labeling will be disabled for this server: {err}");
                                    key_label_cfg.supports_relabeling = false;
                                }
                            }
                        }
                    }

                    break (key_pair, dnskey);
                }

                if retries <= 1 {
                    return Err("unable to generate key with unique key tag".into());
                }
                retries -= 1;
            };

            return Ok((
                key_pair.public_key_url(),
                key_pair.private_key_url(),
                key_pair.algorithm(),
                dnskey.key_tag(),
            ));
        }

        // Otherwise use Ring/OpenSSL based key generation.
        let (secret_key, public_key, key_tag) = loop {
            let (secret_key, public_key) =
                domain::crypto::sign::generate(&algorithm.clone(), flags)
                    .map_err(|e| format!("key generation failed: {e}\n"))?;

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
            .map_err(|err| {
                format!("error while writing private key file '{base}.private': {err}")
            })?;
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
            .map_err(|e| format!("unable to parse {secret_key_url} as URL: {e}"))?;
        let public_key_url = Url::parse(&public_key_url)
            .map_err(|e| format!("unable to parse {public_key_url} as URL: {e}"))?;
        Ok((public_key_url, secret_key_url, algorithm, key_tag))
    }

    /// Create a new CSK key or KSK and ZSK keys if use_csk is false.
    fn new_csk_or_ksk_zsk(&mut self, env: &impl Env) -> Result<(Vec<Url>, Vec<Url>), Error> {
        let now = self.faketime_or_now();
        let (new_stored, new_urls) = if self.config.use_csk {
            let mut new_urls = Vec::new();

            // Create a new CSK
            let (csk_pub_url, csk_priv_url, algorithm, key_tag) = self.new_keys(true, env)?;
            new_urls.push(csk_priv_url.clone());
            new_urls.push(csk_pub_url.clone());
            self.state
                .keyset
                .add_key_csk(
                    csk_pub_url.to_string(),
                    Some(csk_priv_url.to_string()),
                    algorithm,
                    key_tag,
                    now,
                    Available::Available,
                )
                .map_err(|e| format!("unable to add CSK {csk_pub_url}: {e}\n"))?;

            let new = vec![csk_pub_url];
            (new, new_urls)
        } else {
            let mut new_urls = Vec::new();

            // Create a new KSK
            let (ksk_pub_url, ksk_priv_url, algorithm, key_tag) = self.new_keys(true, env)?;
            new_urls.push(ksk_priv_url.clone());
            new_urls.push(ksk_pub_url.clone());
            self.state
                .keyset
                .add_key_ksk(
                    ksk_pub_url.to_string(),
                    Some(ksk_priv_url.to_string()),
                    algorithm,
                    key_tag,
                    now.clone(),
                    Available::Available,
                )
                .map_err(|e| format!("unable to add KSK {ksk_pub_url}: {e}\n"))?;

            // Create a new ZSK
            let (zsk_pub_url, zsk_priv_url, algorithm, key_tag) = self.new_keys(false, env)?;
            new_urls.push(zsk_priv_url.clone());
            new_urls.push(zsk_pub_url.clone());
            self.state
                .keyset
                .add_key_zsk(
                    zsk_pub_url.to_string(),
                    Some(zsk_priv_url.to_string()),
                    algorithm,
                    key_tag,
                    now,
                    Available::Available,
                )
                .map_err(|e| format!("unable to add ZSK {zsk_pub_url}: {e}\n"))?;

            let new = vec![ksk_pub_url, zsk_pub_url];
            (new, new_urls)
        };
        Ok((new_stored, new_urls))
    }

    /// Remove a key from the filesystem or the HSM.
    fn remove_key(&mut self, url: Url) -> Result<(), Error> {
        match url.scheme() {
            "file" => {
                remove_file(url.path())
                    .map_err(|e| format!("unable to remove key file {}: {e}\n", url.path()))?;
            }

            #[cfg(feature = "kmip")]
            "kmip" => {
                let key_url = KeyUrl::try_from(url)?;
                let conn = self
                    .state
                    .kmip
                    .get_pool(&mut self.pools, key_url.server_id())?
                    .get()?;
                conn.destroy_key(key_url.key_id())
                    .map_err(|e| format!("unable to remove key {key_url}: {e}"))?;
            }

            _ => {
                panic!("Unsupported URL scheme while removing key {url}");
            }
        }

        Ok(())
    }

    /// Update the DNSKEY RRset and signures in the KeySetState.
    ///
    /// Collect all keys where present() returns true and sign the DNSKEY RRset
    /// with all KSK and CSK (KSK state) where signer() returns true.
    fn update_dnskey_rrset(&mut self, env: &impl Env, verbose: bool) -> Result<(), Error> {
        let now = self.faketime_or_now();
        let mut dnskeys = Vec::new();
        // Clone needed because of public_key_from_url takes &mut KeySetState.
        let keys = self.state.keyset.keys().clone();
        for (k, v) in &keys {
            let present = match v.keytype() {
                KeyType::Ksk(key_state) => key_state.present(),
                KeyType::Zsk(key_state) => key_state.present(),
                KeyType::Csk(key_state, _) => key_state.present(),
                KeyType::Include(key_state) => key_state.present(),
            };

            if present {
                let pub_url = Url::parse(k).expect("valid URL expected");
                let public_key = self.public_key_from_url::<Vec<u8>>(&pub_url, env)?;
                dnskeys.push(public_key);
            }
        }
        let now_u32 = Into::<Duration>::into(now).as_secs() as u32;
        let inception = (now_u32 - self.config.dnskey_inception_offset.as_secs() as u32).into();
        let expiration = (now_u32 + self.config.dnskey_signature_lifetime.as_secs() as u32).into();

        let mut sigs = Vec::new();
        for (k, v) in &keys {
            if dnskeys.is_empty() {
                // Don't try to sign an empty set.
                break;
            }
            let dnskey_signer = match v.keytype() {
                KeyType::Ksk(key_state) => key_state.signer(),
                KeyType::Zsk(_) => false,
                KeyType::Csk(key_state, _) => key_state.signer(),
                KeyType::Include(_) => false,
            };

            let rrset = Rrset::new_from_owned(&dnskeys)
                .map_err(|e| format!("unable to create Rrset: {e}\n"))?;

            if dnskey_signer {
                let privref = v.privref().ok_or("missing private key")?;
                let priv_url = Url::parse(privref).expect("valid URL expected");
                let pub_url = Url::parse(k).expect("valid URL expected");
                match (priv_url.scheme(), pub_url.scheme()) {
                    ("file", "file") => {
                        let private_data =
                            std::fs::read_to_string(priv_url.path()).map_err(|e| {
                                format!("unable read from file {}: {e}", priv_url.path())
                            })?;
                        let secret_key =
                            SecretKeyBytes::parse_from_bind(&private_data).map_err(|e| {
                                format!("unable to parse private key file {privref}: {e}")
                            })?;

                        let public_key = self.public_key_from_url(&pub_url, env)?;

                        let key_pair = KeyPair::from_bytes(&secret_key, public_key.data())
                            .map_err(|e| {
                                format!(
                                    "private key {privref} and public key {k} do not match: {e}"
                                )
                            })?;
                        let signing_key = SigningKey::new(
                            public_key.owner().clone(),
                            public_key.data().flags(),
                            key_pair,
                        );
                        let sig = sign_rrset(&signing_key, &rrset, inception, expiration).map_err(
                            |e| {
                                format!(
                                    "error signing DNSKEY RRset with private key {privref}: {e}"
                                )
                            },
                        )?;
                        sigs.push(sig);
                    }

                    #[cfg(feature = "kmip")]
                    ("kmip", "kmip") => {
                        let owner = self.state.keyset.name().clone().flatten_into();
                        let priv_key_url = KeyUrl::try_from(priv_url)?;
                        let pub_key_url = KeyUrl::try_from(pub_url)?;
                        let flags = priv_key_url.flags();
                        let kmip_conn_pool = self
                            .state
                            .kmip
                            .get_pool(&mut self.pools, priv_key_url.server_id())?;
                        let key_pair = kmip::sign::KeyPair::from_urls(
                            priv_key_url,
                            pub_key_url,
                            kmip_conn_pool,
                        )
                        .map_err(|err| format!("Failed to retrieve KMIP key by URL: {err}"))?;
                        //let key_pair = KeyPair::Kmip(key_pair);
                        let signing_key = SigningKey::new(owner, flags, key_pair);

                        // TODO: Should there be a key not found error we can detect here so that we can retry if
                        // we believe that the key is simply not registered fully yet in the HSM?
                        let sig = sign_rrset(&signing_key, &rrset, inception, expiration).map_err(
                            |e| {
                                format!(
                                    "error signing DNSKEY RRset with private key {privref}: {e}"
                                )
                            },
                        )?;
                        sigs.push(sig);
                    }

                    (priv_scheme, pub_scheme) => {
                        panic!("unsupported URL scheme combination: {priv_scheme} & {pub_scheme}");
                    }
                };
            }
        }

        self.state.dnskey_rrset.truncate(0);
        for r in dnskeys {
            self.state
                .dnskey_rrset
                .push(r.display_zonefile(DisplayKind::Simple).to_string());
        }
        for r in sigs {
            self.state
                .dnskey_rrset
                .push(r.display_zonefile(DisplayKind::Simple).to_string());
        }
        if verbose {
            println!("Got DNSKEY RRset:");
            for r in &self.state.dnskey_rrset {
                println!("\t{r}");
            }
        }
        Ok(())
    }

    /// Create the CDS and CDNSKEY RRsets plus signatures.
    ///
    /// The CDS and CDNSKEY RRsets contain the keys where at_parent() returns
    /// true. The RRsets are signed with all keys that sign the DNSKEY RRset.
    fn create_cds_rrset(&mut self, env: &impl Env, verbose: bool) -> Result<(), Error> {
        let now = self.faketime_or_now();
        let digest_alg = self.config.ds_algorithm.to_digest_algorithm();
        let mut cds_list = Vec::new();
        let mut cdnskey_list = Vec::new();
        // clone needed due to public_key_from_url taking &mut KeySetState.
        let keys = self.state.keyset.keys().clone();
        for (k, v) in &keys {
            let at_parent = match v.keytype() {
                KeyType::Ksk(key_state) => key_state.at_parent(),
                KeyType::Zsk(key_state) => key_state.at_parent(),
                KeyType::Csk(key_state, _) => key_state.at_parent(),
                KeyType::Include(key_state) => key_state.at_parent(),
            };

            if at_parent {
                let pub_url = Url::parse(k).expect("valid URL expected");
                let public_key = self.public_key_from_url(&pub_url, env)?;
                create_cds_rrset_helper(digest_alg, &mut cds_list, &mut cdnskey_list, public_key)?;
            }

            // Need to sign
        }

        let now_u32 = Into::<Duration>::into(now).as_secs() as u32;
        let inception = (now_u32 - self.config.cds_inception_offset.as_secs() as u32).into();
        let expiration = (now_u32 + self.config.cds_signature_lifetime.as_secs() as u32).into();

        let mut cds_sigs = Vec::new();
        let mut cdnskey_sigs = Vec::new();
        for (k, v) in &keys {
            if cds_list.is_empty() {
                // Don't try to sign an empty set. Assume cdnskey_list is empty
                // as well.
                break;
            }
            let dnskey_signer = match v.keytype() {
                KeyType::Ksk(key_state) => key_state.signer(),
                KeyType::Zsk(_) => false,
                KeyType::Csk(key_state, _) => key_state.signer(),
                KeyType::Include(_) => false,
            };

            let cds_rrset = Rrset::new_from_owned(&cds_list)
                .map_err(|e| format!("unable to create Rrset: {e}\n"))?;
            let cdnskey_rrset = Rrset::new_from_owned(&cdnskey_list)
                .map_err(|e| format!("unable to create Rrset: {e}\n"))?;

            if dnskey_signer {
                let privref = v.privref().ok_or("missing private key")?;
                let priv_url = Url::parse(privref).expect("valid URL expected");
                let pub_url = Url::parse(k).expect("valid URL expected");
                match (priv_url.scheme(), pub_url.scheme()) {
                    ("file", "file") => {
                        let path = priv_url.path();
                        let filename = env.in_cwd(&path);
                        let private_data = std::fs::read_to_string(&filename).map_err(|e| {
                            format!(
                                "unable to read from private key file {}: {e}",
                                filename.display()
                            )
                        })?;
                        let secret_key =
                            SecretKeyBytes::parse_from_bind(&private_data).map_err(|e| {
                                format!(
                                    "unable to parse private key file {}: {e}",
                                    filename.display()
                                )
                            })?;
                        let public_key = self.public_key_from_url(&pub_url, env)?;

                        let key_pair = KeyPair::from_bytes(&secret_key, public_key.data())
                            .map_err(|e| {
                                format!(
                                    "private key {privref} and public key {k} do not match: {e}"
                                )
                            })?;
                        let signing_key = SigningKey::new(
                            public_key.owner().clone(),
                            public_key.data().flags(),
                            key_pair,
                        );
                        let sig = sign_rrset(&signing_key, &cds_rrset, inception, expiration)
                            .map_err(|e| {
                                format!("error signing CDS RRset with private key {privref}: {e}")
                            })?;
                        cds_sigs.push(sig);
                        let sig = sign_rrset::<_, _, Bytes, _>(
                            &signing_key,
                            &cdnskey_rrset,
                            inception,
                            expiration,
                        )
                        .map_err(|e| {
                            format!("error signing CDNSKEY RRset with private key {privref}: {e}")
                        })?;
                        cdnskey_sigs.push(sig);
                    }

                    #[cfg(feature = "kmip")]
                    ("kmip", "kmip") => {
                        let owner = self.state.keyset.name().clone().flatten_into();
                        let priv_key_url = KeyUrl::try_from(priv_url)?;
                        let pub_key_url = KeyUrl::try_from(pub_url)?;
                        let flags = priv_key_url.flags();
                        let kmip_conn_pool = self
                            .state
                            .kmip
                            .get_pool(&mut self.pools, priv_key_url.server_id())?;
                        let key_pair = kmip::sign::KeyPair::from_urls(
                            priv_key_url,
                            pub_key_url,
                            kmip_conn_pool,
                        )
                        .map_err(|err| format!("Failed to retrieve KMIP key by URL: {err}"))?;
                        let signing_key = SigningKey::new(owner, flags, key_pair);
                        let sig = sign_rrset(&signing_key, &cds_rrset, inception, expiration)
                            .map_err(|e| {
                                format!("error signing CDS RRset with private key {privref}: {e}")
                            })?;
                        cds_sigs.push(sig);
                        let sig = sign_rrset::<_, _, Bytes, _>(
                            &signing_key,
                            &cdnskey_rrset,
                            inception,
                            expiration,
                        )
                        .map_err(|e| {
                            format!("error signing CDNSKEY RRset with private key {privref}: {e}")
                        })?;
                        cdnskey_sigs.push(sig);
                    }

                    (priv_scheme, pub_scheme) => {
                        panic!("unsupported URL scheme combination: {priv_scheme} & {pub_scheme}");
                    }
                };
            }
        }

        self.state.cds_rrset.truncate(0);
        for r in cdnskey_list {
            self.state
                .cds_rrset
                .push(r.display_zonefile(DisplayKind::Simple).to_string());
        }
        for r in cdnskey_sigs {
            self.state
                .cds_rrset
                .push(r.display_zonefile(DisplayKind::Simple).to_string());
        }
        for r in cds_list {
            self.state
                .cds_rrset
                .push(r.display_zonefile(DisplayKind::Simple).to_string());
        }
        for r in cds_sigs {
            self.state
                .cds_rrset
                .push(r.display_zonefile(DisplayKind::Simple).to_string());
        }

        if verbose {
            println!("Got CDS/CDNSKEY RRset:");
            for r in &self.state.cds_rrset {
                println!("\t{r}");
            }
        }
        Ok(())
    }

    /// Update the DS RRset.
    ///
    /// The DS records are generated from all keys where at_parent() returns true.
    /// This RRset is not signed.
    fn update_ds_rrset(&mut self, env: &impl Env, verbose: bool) -> Result<(), Error> {
        let digest_alg = self.config.ds_algorithm.to_digest_algorithm();

        #[allow(clippy::type_complexity)]
        let mut ds_list: Vec<Record<Name<Vec<u8>>, Ds<Vec<u8>>>> = Vec::new();
        // clone needed due to public_key_from_url taking &mut KeySetState.
        let keys = self.state.keyset.keys().clone();
        for (k, v) in &keys {
            let at_parent = match v.keytype() {
                KeyType::Ksk(key_state) => key_state.at_parent(),
                KeyType::Zsk(key_state) => key_state.at_parent(),
                KeyType::Csk(key_state, _) => key_state.at_parent(),
                KeyType::Include(key_state) => key_state.at_parent(),
            };

            if at_parent {
                let pub_url = Url::parse(k).expect("valid URL expected");
                let public_key = self.public_key_from_url::<Vec<u8>>(&pub_url, env)?;
                let digest = public_key
                    .data()
                    .digest(&public_key.owner(), digest_alg)
                    .map_err(|e| format!("error creating digest for DNSKEY record: {e}"))?;

                let ds = Ds::new(
                    public_key.data().key_tag(),
                    public_key.data().algorithm(),
                    digest_alg,
                    digest.as_ref().to_vec(),
                )
                .expect(
                    "Infallible because the digest won't be too long since it's a valid digest",
                );

                let ds_record = Record::new(
                    public_key.owner().clone().flatten_into(),
                    public_key.class(),
                    self.config.default_ttl,
                    ds,
                );

                ds_list.push(ds_record);
            }
        }

        self.state.ds_rrset.truncate(0);
        for r in ds_list {
            self.state
                .ds_rrset
                .push(r.display_zonefile(DisplayKind::Simple).to_string());
        }

        if verbose {
            println!("Got DS RRset:");
            for r in &self.state.ds_rrset {
                println!("\t{r}");
            }
        }
        Ok(())
    }

    /// Handle the actions that result from key roll steps that always need to
    /// be handled independent of automation.
    ///
    /// Those are the actions that update the DNSKEY RRset, DS records and the
    /// CDS and CDNSKEY RRsets.
    fn handle_actions(
        &mut self,
        actions: &[Action],
        env: &impl Env,
        verbose: bool,
    ) -> Result<(), Error> {
        for action in actions {
            match action {
                Action::UpdateDnskeyRrset => self.update_dnskey_rrset(env, verbose)?,
                Action::CreateCdsRrset => self.create_cds_rrset(env, verbose)?,
                Action::RemoveCdsRrset => remove_cds_rrset(&mut self.state),
                Action::UpdateDsRrset => {
                    self.run_update_ds_command = true;
                    self.update_ds_rrset(env, verbose)?
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

    /// Execute the done action.
    fn do_done(&mut self, roll_type: RollType) -> Result<(), Error> {
        let actions = self.state.keyset.roll_done(roll_type);

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
        remove_cds_rrset(&mut self.state);

        self.state.internal.remove(&roll_type);

        Ok(())
    }

    /// Start a KSK roll.
    fn start_ksk_roll(&mut self, env: &impl Env, verbose: bool) -> Result<Vec<Action>, Error> {
        let now = self.faketime_or_now();

        let roll_type = RollType::KskRoll;

        assert!(!self.state.keyset.keys().is_empty());

        // Check for CSK.
        if self.config.use_csk {
            return Err("wrong key roll, use start-csk-roll\n".into());
        }

        // Refuse if we can find a CSK key.
        if self.state.keyset.keys().iter().any(|(_, key)| {
            if let KeyType::Csk(keystate, _) = key.keytype() {
                !keystate.stale()
            } else {
                false
            }
        }) {
            return Err(format!("cannot start {roll_type:?} roll, found CSK\n").into());
        }

        // Find existing KSKs. Do we complain if there is none?
        let old_stored: Vec<_> = self
            .state
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
        let (ksk_pub_url, ksk_priv_url, algorithm, key_tag) = self.new_keys(true, env)?;
        self.state
            .keyset
            .add_key_ksk(
                ksk_pub_url.to_string(),
                Some(ksk_priv_url.to_string()),
                algorithm,
                key_tag,
                now,
                Available::Available,
            )
            .map_err(|e| format!("unable to add KSK {ksk_pub_url}: {e}\n"))?;

        let new = [ksk_pub_url.as_ref()];

        // Start the key roll
        let actions = match self
            .state
            .keyset
            .start_roll(roll_type, &old, &new)
            .map_err(|e| format!("cannot start {roll_type:?}: {e}\n"))
        {
            Ok(actions) => actions,
            Err(e) => {
                // Remove the keys we just created.
                self.remove_key(ksk_priv_url)?;
                self.remove_key(ksk_pub_url)?;
                return Err(e.into());
            }
        };
        self.handle_actions(&actions, env, verbose)?;
        self.state.internal.insert(roll_type, Default::default());
        Ok(actions)
    }

    /// Start a ZSK roll.
    fn start_zsk_roll(&mut self, env: &impl Env, verbose: bool) -> Result<Vec<Action>, Error> {
        let now = self.faketime_or_now();

        let roll_type = RollType::ZskRoll;

        assert!(!self.state.keyset.keys().is_empty());

        // Check for CSK.
        if self.config.use_csk {
            return Err("wrong key roll, use start-csk-roll\n".into());
        }

        // Refuse if we can find a CSK key.
        if self.state.keyset.keys().iter().any(|(_, key)| {
            if let KeyType::Csk(keystate, _) = key.keytype() {
                !keystate.stale()
            } else {
                false
            }
        }) {
            return Err(format!("cannot start {roll_type:?} roll, found CSK\n").into());
        }

        // Find existing ZSKs. Do we complain if there is none?
        let old_stored: Vec<_> = self
            .state
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
        let (zsk_pub_url, zsk_priv_url, algorithm, key_tag) = self.new_keys(false, env)?;
        self.state
            .keyset
            .add_key_zsk(
                zsk_pub_url.to_string(),
                Some(zsk_priv_url.to_string()),
                algorithm,
                key_tag,
                now,
                Available::Available,
            )
            .map_err(|e| format!("unable to add ZSK {zsk_pub_url}: {e}\n"))?;

        let new = [zsk_pub_url.as_ref()];

        // Start the key roll
        let actions = match self
            .state
            .keyset
            .start_roll(roll_type, &old, &new)
            .map_err(|e| format!("cannot start {roll_type:?}: {e}\n"))
        {
            Ok(actions) => actions,
            Err(e) => {
                // Remove the keys we just created.
                self.remove_key(zsk_priv_url)?;
                self.remove_key(zsk_pub_url)?;
                return Err(e.into());
            }
        };

        self.handle_actions(&actions, env, verbose)?;
        self.state.internal.insert(roll_type, Default::default());
        Ok(actions)
    }

    /// Start a CSK roll.
    fn start_csk_roll(&mut self, env: &impl Env, verbose: bool) -> Result<Vec<Action>, Error> {
        let roll_type = RollType::CskRoll;

        assert!(!self.state.keyset.keys().is_empty());

        // Find existing KSKs, ZSKs and CSKs. Do we complain if there
        // are none?
        let old_stored: Vec<_> = self
            .state
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

        let (new_stored, new_urls) = self.new_csk_or_ksk_zsk(env)?;

        let new: Vec<_> = new_stored.iter().map(|v| v.as_ref()).collect();

        // Start the key roll
        let actions = match self
            .state
            .keyset
            .start_roll(roll_type, &old, &new)
            .map_err(|e| format!("cannot start {roll_type:?}: {e}\n"))
        {
            Ok(actions) => actions,
            Err(e) => {
                // Remove the key files we just created.
                for u in new_urls {
                    self.remove_key(u)?;
                }
                return Err(e.into());
            }
        };

        self.handle_actions(&actions, env, verbose)?;
        self.state.internal.insert(roll_type, Default::default());
        Ok(actions)
    }

    /// Start an algorithm roll.
    fn start_algorithm_roll(
        &mut self,
        env: &impl Env,
        verbose: bool,
    ) -> Result<Vec<Action>, Error> {
        let roll_type = RollType::AlgorithmRoll;

        assert!(!self.state.keyset.keys().is_empty());

        // Find existing KSKs, ZSKs and CSKs. Do we complain if there
        // are none?
        let old_stored: Vec<_> = self
            .state
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

        let (new_stored, new_urls) = self.new_csk_or_ksk_zsk(env)?;
        let new: Vec<_> = new_stored.iter().map(|v| v.as_ref()).collect();

        // Start the key roll
        let actions = match self
            .state
            .keyset
            .start_roll(roll_type, &old, &new)
            .map_err(|e| format!("cannot start roll: {e}\n"))
        {
            Ok(actions) => actions,
            Err(e) => {
                // Remove the key files we just created.
                for u in new_urls {
                    self.remove_key(u)?;
                }
                return Err(e.into());
            }
        };

        self.handle_actions(&actions, env, verbose)?;
        self.state.internal.insert(roll_type, Default::default());
        Ok(actions)
    }

    /// This function automatically starts a key roll when the conditions are right.
    ///
    /// First the conficting_roll function is invoked to make sure there are no
    /// rolls in progress that would conflict. Then match_keytype is used to
    /// select key that could participate in this roll. The published time of
    /// each key is compared to the validity parameter to see if the key
    /// needs to be replaced. No key roll will happen is validity is equal to
    /// None. The start_roll parameter starts the key roll.
    fn auto_start<Env>(
        &mut self,
        validity: Option<Duration>,
        auto: AutoConfig,
        env: Env,
        conficting_roll: impl Fn(RollType) -> bool,
        match_keytype: impl Fn(KeyType) -> Option<KeyState>,
        start_roll: impl Fn(&mut WorkSpace, Env, bool) -> Result<Vec<Action>, Error>,
    ) -> Result<(), Error> {
        let now = self.faketime_or_now();
        if let Some(validity) = validity {
            if auto.start {
                // If there is no conficting roll, and this
                // flag is set, and the lifetime has expired then
                // start a roll.
                if !self
                    .state
                    .keyset
                    .rollstates()
                    .iter()
                    .any(|(r, _)| conficting_roll(*r))
                {
                    let next = self
                        .state
                        .keyset
                        .keys()
                        .values()
                        .filter_map(|k| {
                            if let Some(keystate) = match_keytype(k.keytype()) {
                                if !keystate.stale() {
                                    k.timestamps()
                                        .published()
                                        .map(|published| published + validity)
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .min();
                    if let Some(next) = next {
                        if next < now {
                            start_roll(self, env, false)?;
                            self.state_changed = true;
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
        &mut self,
        auto: AutoConfig,
        roll_list: &[RollType],
        env: &impl Env,
    ) -> Result<(), Error> {
        let now = self.faketime_or_now();
        if auto.report {
            // If there is currently a roll in one of the
            // propagation states and this flags is set and all
            // actions have comleted report the ttl.
            for r in roll_list {
                let map = self.state.keyset.rollstates().clone();
                if let Some(state) = map.get(r) {
                    let report_state = &self.state.internal.get(r).expect("should not fail");
                    let report_state = match state {
                        RollState::Propagation1 => &report_state.propagation1,
                        RollState::Propagation2 => &report_state.propagation2,
                        _ => continue,
                    };
                    let actions = self.state.keyset.actions(*r);
                    match auto_report_actions(
                        &actions,
                        &self.state,
                        report_state,
                        &mut self.state_changed,
                        now.clone(),
                    )
                    .await
                    {
                        AutoReportActionsResult::Wait(_) => continue,
                        AutoReportActionsResult::Report(ttl) => {
                            let actions = match state {
                                RollState::Propagation1 => {
                                    self.state.keyset.propagation1_complete(*r, ttl.as_secs())
                                }
                                RollState::Propagation2 => {
                                    self.state.keyset.propagation2_complete(*r, ttl.as_secs())
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

                            self.handle_actions(&actions, env, false)?;
                            self.state_changed = true;
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
                if let Some(state) = self.state.keyset.rollstates().get(r) {
                    let actions = match state {
                        RollState::CacheExpire1(_) => self.state.keyset.cache_expired1(*r),
                        RollState::CacheExpire2(_) => self.state.keyset.cache_expired2(*r),
                        _ => continue,
                    };
                    if let Err(keyset::Error::Wait(_)) = actions {
                        // To early.
                        continue;
                    }
                    let actions = actions
                        .map_err(|e| format!("cache_expired[12] failed for state {r:?}: {e}"))?;
                    self.handle_actions(&actions, env, false)?;
                    // Report actions
                    self.state_changed = true;
                }
            }
        }
        if auto.done {
            // If there is current a roll in the done state and all
            // actions have completed then call do_done to end the key roll.
            for r in roll_list {
                if let Some(RollState::Done) = self.state.keyset.rollstates().get(r) {
                    let report_state = &self.state.internal.get(r).expect("should not fail").done;
                    let actions = self.state.keyset.actions(*r);
                    match auto_wait_actions(
                        &actions,
                        &self.state,
                        report_state,
                        &mut self.state_changed,
                        now.clone(),
                    )
                    .await
                    {
                        AutoActionsResult::Ok => {
                            self.do_done(*r)?;
                            self.state_changed = true;
                        }
                        AutoActionsResult::Wait(_) => continue,
                    }
                }
            }
        }
        Ok(())
    }

    /// Check if an algorithm roll is needed.
    ///
    /// An algorithm roll is needed if the algorithm listed in config is
    /// different from the set of algorithms in the collection of active keys.
    fn algorithm_roll_needed(&self) -> bool {
        // Collect the algorithms in all active keys. Check if the algorithm
        // for new keys is the same.
        let curr_algs: HashSet<_> = self
            .state
            .keyset
            .keys()
            .values()
            .filter_map(|k| {
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
        let new_algs = HashSet::from([self.config.algorithm.to_generate_params().algorithm()]);
        curr_algs != new_algs
    }

    /// Helper function that either returns the configured fake time or the
    /// current time.
    fn faketime_or_now(&self) -> UnixTime {
        self.config.faketime.clone().unwrap_or(UnixTime::now())
    }

    /// Check whether automatic actions are done or not. If not, return until
    /// when to wait to try again.
    fn check_auto_actions(
        &self,
        actions: &[Action],
        report_state: &Mutex<ReportState>,
    ) -> AutoActionsResult {
        let now = self.faketime_or_now();
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
                    return AutoActionsResult::Wait(now);
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
                    return AutoActionsResult::Wait(now);
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
                    return AutoActionsResult::Wait(now);
                }
            }
        }
        AutoActionsResult::Ok
    }

    /// This function computes when next to try to move to the next state.
    ///
    /// For the Report and Wait actions that involves checking when propagation
    /// should be tested again. For the expire step it computes when the
    /// keyset object in the domain library accepts the cache_expired1 or
    /// cache_expired2 methods.
    fn cron_next_auto_report_expire_done(
        &self,
        auto: &AutoConfig,
        roll_list: &[RollType],
        kss: &KeySetState,
        cron_next: &mut Vec<Option<UnixTime>>,
    ) -> Result<(), Error> {
        let now = self.faketime_or_now();
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
                    match self.check_auto_actions(&actions, report_state) {
                        AutoActionsResult::Ok => {
                            // All actions are ready. Request cron.
                            cron_next.push(Some(now.clone()));
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
                        cron_next.push(Some(now.clone() + remain));
                        continue;
                    }
                    let _ = actions
                        .map_err(|e| format!("cache_expired[12] failed for state {r:?}: {e}"))?;

                    // Time to call cron. Report the current time.
                    cron_next.push(Some(now.clone()));
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
                    match self.check_auto_actions(&kss.keyset.actions(*r), &report_state.done) {
                        AutoActionsResult::Ok => {
                            // All actions are ready. Request cron.
                            cron_next.push(Some(now.clone()));
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

    /// Write config to a file.
    fn write_config(&self, keyset_conf: &PathBuf) -> Result<(), Error> {
        let json = serde_json::to_string_pretty(&self.config).expect("should not fail");
        Self::write_to_new_and_rename(&json, keyset_conf)
    }

    /// Write state to a file.
    fn write_state(&self) -> Result<(), Error> {
        let json = serde_json::to_string_pretty(&self.state).expect("should not fail");
        Self::write_to_new_and_rename(&json, &self.config.state_file)
    }

    /// First write to a new filename and then rename to make sure that
    /// changes are atomic.
    fn write_to_new_and_rename(json: &str, filename: &PathBuf) -> Result<(), Error> {
        let mut filename_new = filename.clone();
        // It would be nice to use add_extension here, but it is only in
        // Rust 1.91.0 and above. Use strings instead.
        // if !state_file_new.add_extension("new") {
        //	return Err(format!("unable to add extension 'new' to {}",
        //		ws.config.state_file.display()).into());
        // }
        filename_new.as_mut_os_string().push(".new");
        let mut file = File::create(&filename_new)
            .map_err(|e| format!("unable to create file {}: {e}", filename_new.display()))?;
        write!(file, "{json}")
            .map_err(|e| format!("unable to write to file {}: {e}", filename_new.display()))?;
        rename(&filename_new, filename).map_err(|e| {
            format!(
                "unable to rename {} to {}: {e}",
                filename_new.display(),
                filename.display()
            )
        })?;

        Ok(())
    }
}

/// Handle automatic report actions.
// Note that we cannot pass an &mut WorkSpace because report_state borrows
// the WorkSpace object as well.
async fn auto_report_actions(
    actions: &[Action],
    kss: &KeySetState,
    report_state: &Mutex<ReportState>,
    state_changed: &mut bool,
    now: UnixTime,
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
                                if *next > now {
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

                let result = report_dnskey_propagated(kss, now.clone()).await;

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
                                if *next > now {
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

                let result = report_ds_propagated(kss, now.clone())
                    .await
                    .unwrap_or_else(|e| {
                        warn!("Check DS propagation failed: {e}");
                        AutoReportActionsResult::Wait(now.clone() + DEFAULT_WAIT)
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
                            if next > now {
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
                            if next > now {
                                return AutoReportActionsResult::Wait(next.clone());
                            }
                            let res =
                                check_soa(serial, kss, now.clone())
                                    .await
                                    .unwrap_or_else(|e| {
                                        warn!("Check SOA propagation failed: {e}");
                                        false
                                    });
                            if res {
                                let mut report_state_locked =
                                    report_state.lock().expect("lock() should not fail");
                                report_state_locked.rrsig =
                                    Some(AutoReportRrsigResult::Report(report_ttl));
                                drop(report_state_locked);
                                *state_changed = true;
                                max_ttl = max(max_ttl, report_ttl);
                                continue;
                            } else {
                                let next = now + ttl.into();
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
                            if next > now {
                                return AutoReportActionsResult::Wait(next.clone());
                            }
                            let res = check_record(&name, &rtype, kss).await.unwrap_or_else(|e| {
                                warn!("record check failed: {e}");
                                false
                            });
                            if !res {
                                let next = now + ttl.into();
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
                            if next > now {
                                return AutoReportActionsResult::Wait(next.clone());
                            }
                            let res = check_next_serial(serial, kss).await.unwrap_or_else(|e| {
                                warn!("next serial check failed: {e}");
                                false
                            });
                            if !res {
                                let next = now + ttl.into();
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

                let result = report_rrsig_propagated(kss, now.clone())
                    .await
                    .unwrap_or_else(|e| {
                        warn!("Check RRSIG propagation failed: {e}");
                        AutoReportRrsigResult::Wait(now.clone() + DEFAULT_WAIT)
                    });

                let mut report_state_locked = report_state.lock().expect("lock() should not fail");
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
/// Create CDS and CDNSKEY RRsets.
fn create_cds_rrset_helper(
    digest_alg: DigestAlgorithm,
    cds_list: &mut Vec<Record<Name<Bytes>, Cds<Vec<u8>>>>,
    cdnskey_list: &mut Vec<Record<Name<Bytes>, Cdnskey<Vec<u8>>>>,
    record: Record<Name<Vec<u8>>, Dnskey<Vec<u8>>>,
) -> Result<(), Error> {
    let owner: Name<Bytes> = record.owner().to_name();
    let dnskey = record.data();
    let cdnskey = Cdnskey::new(
        dnskey.flags(),
        dnskey.protocol(),
        dnskey.algorithm(),
        dnskey.public_key().clone(),
    )
    .expect("should not fail");
    let cdnskey_record = Record::new(owner.clone(), record.class(), record.ttl(), cdnskey);
    cdnskey_list.push(cdnskey_record);
    let key_tag = dnskey.key_tag();
    let sec_alg = dnskey.algorithm();
    let digest = dnskey
        .digest(&record.owner(), digest_alg)
        .map_err(|e| format!("error creating digest for DNSKEY record: {e}"))?;
    let cds = Cds::new(key_tag, sec_alg, digest_alg, digest.as_ref().to_vec())
        .expect("Infallible because the digest won't be too long since it's a valid digest");
    let cds_record = Record::new(owner, record.class(), record.ttl(), cds);
    cds_list.push(cds_record);
    Ok(())
}

/// Remove the CDS and CDNSKEY RRsets and signatures.
fn remove_cds_rrset(kss: &mut KeySetState) {
    kss.cds_rrset.truncate(0);
}

/// Print a list of actions.
///
/// TODO: make this list user friendly.
fn print_actions(actions: &[Action]) {
    if actions.is_empty() {
        println!("No actions");
    } else {
        println!("Actions:");
        let mut report_count = 0;
        for a in actions {
            println!("\t{a:?}:");
            match a {
                Action::CreateCdsRrset => {
                    println!("\t\tsign the zone with the CDS and CDNSKEY RRsets")
                }
                Action::RemoveCdsRrset => {
                    println!("\t\tsign the zone with empty CDS and CDNSKEY RRsets")
                }
                Action::UpdateDnskeyRrset => {
                    println!("\t\tsign the zone with the new DNSKEY RRset from the state file")
                }
                Action::UpdateDsRrset => {
                    println!("\t\tupdate the DS RRset at the parent to match the CDNSKEY RRset")
                }
                Action::UpdateRrsig => println!("\t\tsign the zone with the new zone signing keys"),
                Action::ReportDnskeyPropagated => {
                    println!("\t\tverify that the new DNSKEY RRset has propagated to all");
                    println!("\t\tnameservers and report (at least) the TTL of the DNSKEY RRset");
                    report_count += 1;
                }
                Action::ReportDsPropagated => {
                    println!("\t\tverify that all nameservers of the parent zone have a new");
                    println!("\t\tDS RRset that matches the keys in the CNDSKEY RRset and");
                    println!("\t\treport (at least) the TTL of the DNSKEY RRset");
                    report_count += 1;
                }
                Action::ReportRrsigPropagated => {
                    println!("\t\tverify that the new RRSIG records have propagated to all");
                    println!("\t\tnameservers and report (at least) the maximum TTL among");
                    println!("\t\tthe RRSIG records");
                    report_count += 1;
                }
                Action::WaitDnskeyPropagated => {
                    println!("\t\tverify that the new DNSKEY RRset has propagated to all");
                    println!("\t\tnameservers");
                }
                Action::WaitDsPropagated => {
                    println!("\t\tverify that all nameservers of the parent zone have a new");
                    println!("\t\tDS RRset that matches the keys in the CNDSKEY RRset");
                }
                Action::WaitRrsigPropagated => {
                    println!("\t\tverify that the new RRSIG records have propagated to all");
                    println!("\t\tnameservers");
                }
            }
            println!();
        }
        if report_count > 1 {
            println!("\tNote: with multiple Report actions, report the maximum of the TTLs.");
        }
    }
}

/// Parse a duration from a string with suffixes like 'm', 'h', 'w', etc.
pub fn parse_duration(value: &str) -> Result<Duration, Error> {
    let span: Span = value
        .parse()
        .map_err(|e| format!("unable to parse {value} as lifetime: {e}\n"))?;
    let signeddur = span
        .to_duration(SpanRelativeTo::days_are_24_hours())
        .map_err(|e| format!("unable to convert duration: {e}\n"))?;
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

/// Parse a UnixTime from string.
///
/// Those accepts both both a seconds value and a broken down time value
/// without punctuation.
fn parse_unixtime(value: &str) -> Result<UnixTime, Error> {
    let timestamp = Timestamp::from_str(value)
        .map_err(|e| format!("unable to parse Unix time {value}: {e}"))?;
    Ok(UnixTime::from(timestamp))
}

/// Parse an optional UnixTime from a string but also allow 'off' to signal
/// no UnixTime.
fn parse_opt_unixtime(value: &str) -> Result<Option<UnixTime>, Error> {
    if value == "off" {
        return Ok(None);
    }
    let unixtime = parse_unixtime(value)?;
    Ok(Some(unixtime))
}

/// Check whether signatures need to be renewed.
///
/// The input is an RRset plus signatures in zonefile format plus a
/// duration how long the signatures are required to remain valid.
fn sig_renew(rrset: &[String], remain_time: &Duration, now: UnixTime) -> bool {
    let mut zonefile = Zonefile::new();
    for r in rrset {
        zonefile.extend_from_slice(r.as_ref());
        zonefile.extend_from_slice(b"\n");
    }
    let now_u64 = Into::<Duration>::into(now).as_secs();
    let renew = now_u64 + remain_time.as_secs();
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
fn compute_cron_next(rrset: &[String], remain_time: &Duration, now: UnixTime) -> Option<UnixTime> {
    let mut zonefile = Zonefile::new();
    for r in rrset {
        zonefile.extend_from_slice(r.as_ref());
        zonefile.extend_from_slice(b"\n");
    }

    let now_system_time = UNIX_EPOCH + Duration::from(now.clone());
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
        .map(|t| t.to_system_time(now_system_time))
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
// Note that we cannot pass an &mut WorkSpace because report_state also
// borrows the WorkSpace object.
async fn auto_wait_actions(
    actions: &[Action],
    state: &KeySetState,
    report_state: &Mutex<ReportState>,
    state_changed: &mut bool,
    now: UnixTime,
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
                                if *next > now {
                                    return AutoActionsResult::Wait(next.clone());
                                }
                            }
                            AutoReportActionsResult::Report(_) => continue,
                        }
                    }

                    drop(report_state_locked);
                }

                let result = report_dnskey_propagated(state, now.clone()).await;

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
                                if *next > now {
                                    return AutoActionsResult::Wait(next.clone());
                                }
                            }
                            AutoReportActionsResult::Report(_) => continue,
                        }
                    }
                    drop(report_state_locked);
                }

                let result = report_ds_propagated(state, now.clone())
                    .await
                    .unwrap_or_else(|e| {
                        warn!("Check DS propagation failed: {e}");
                        AutoReportActionsResult::Wait(now.clone() + DEFAULT_WAIT)
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
                            if next > now {
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
                            if next > now {
                                return AutoActionsResult::Wait(next.clone());
                            }
                            let res =
                                check_soa(serial, state, now.clone())
                                    .await
                                    .unwrap_or_else(|e| {
                                        warn!("Check SOA propagation failed: {e}");
                                        false
                                    });
                            if res {
                                let mut report_state_locked =
                                    report_state.lock().expect("lock() should not fail");
                                report_state_locked.rrsig =
                                    Some(AutoReportRrsigResult::Report(report_ttl));
                                drop(report_state_locked);
                                *state_changed = true;
                                continue;
                            } else {
                                let next = now + ttl.into();
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
                            if next > now {
                                return AutoActionsResult::Wait(next.clone());
                            }
                            let res =
                                check_record(&name, &rtype, state)
                                    .await
                                    .unwrap_or_else(|e| {
                                        warn!("record check failed: {e}");
                                        false
                                    });
                            if !res {
                                let next = now + ttl.into();
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
                            if next > now {
                                return AutoActionsResult::Wait(next.clone());
                            }
                            let res = check_next_serial(serial, state).await.unwrap_or_else(|e| {
                                warn!("next serial check failed: {e}");
                                false
                            });
                            if !res {
                                let next = now + ttl.into();
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

                let result = report_rrsig_propagated(state, now.clone())
                    .await
                    .unwrap_or_else(|e| {
                        warn!("Check RRSIG propagation failed: {e}");
                        AutoReportRrsigResult::Wait(now.clone() + DEFAULT_WAIT)
                    });

                let mut report_state_locked = report_state.lock().expect("lock() should not fail");
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

/// Check whether a new DNSKEY RRset has propagated.
///
/// Compile a list of nameservers for the zone and their addresses and
/// query each address for the DNSKEY RRset. The function
/// check_dnskey_for_address does the actual work.
async fn report_dnskey_propagated(kss: &KeySetState, now: UnixTime) -> AutoReportActionsResult {
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
            return AutoReportActionsResult::Wait(now + DEFAULT_WAIT);
        }
    };

    // addresses_for_zone returns at least one address.
    assert!(!addresses.is_empty());

    let futures: Vec<_> = addresses
        .iter()
        .map(|a| check_dnskey_for_address(zone, a, target_dnskey.clone(), now.clone()))
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
                return AutoReportActionsResult::Wait(now + DEFAULT_WAIT);
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
async fn report_ds_propagated(
    kss: &KeySetState,
    now: UnixTime,
) -> Result<AutoReportActionsResult, Error> {
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

    // addresses_for_zone returns at least one address.
    assert!(!addresses.is_empty());

    let futures: Vec<_> = addresses
        .iter()
        .map(|a| check_ds_for_address(zone, a, target_dnskey.clone(), now.clone()))
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
async fn report_rrsig_propagated(
    kss: &KeySetState,
    now: UnixTime,
) -> Result<AutoReportRrsigResult, Error> {
    // This function assume a single signer. Multi-signer is not supported
    // at all, but any kind of active-passive or active-active setup would also
    // need changes. With more than one signer, each signer needs to be
    // checked explicitly. Then for all nameservers it needs to be checked
    // that their SOA versions are at least as high as all of the signers.
    // Check the zone. If the zone checks out, make sure that all nameservers
    // have at least the version of the zone that was checked.

    let result = check_zone(kss, now.clone()).await?;
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
        if check_soa(serial, kss, now.clone())
            .await
            .unwrap_or_else(|e| {
                warn!("Check SOA propagation failed: {e}");
                false
            })
        {
            AutoReportRrsigResult::Report(report_ttl)
        } else {
            AutoReportRrsigResult::WaitSoa {
                next: now + ttl.into(),
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
async fn check_zone(kss: &KeySetState, now: UnixTime) -> Result<AutoReportRrsigResult, Error> {
    let expected_set = get_expected_zsk_key_tags(kss);

    let zone = kss.keyset.name();

    let resolver = StubResolver::new();
    let answer = resolver
        .query((zone, Rtype::SOA))
        .await
        .map_err(|e| format!("lookup of {zone}/SOA failed: {e}"))?;
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
                            next: now,
                            serial,
                            ttl: r.ttl(),
                            report_ttl: max_ttl,
                        }),
                        CheckRrsigsResult::WaitRecord { name, rtype } => {
                            Ok(AutoReportRrsigResult::WaitRecord {
                                next: now + r.ttl().into(),
                                name,
                                rtype,
                                ttl: r.ttl(),
                            })
                        }
                        CheckRrsigsResult::WaitNextSerial => {
                            Ok(AutoReportRrsigResult::WaitNextSerial {
                                next: now + r.ttl().into(),
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

    let mut nameservers = Vec::new();
    let resolver = StubResolver::new();
    let answer = resolver
        .query((zone, Rtype::NS))
        .await
        .map_err(|e| format!("lookup of {}/NS failed: {e}", zone.to_name::<Vec<u8>>()))?;
    let rcode = answer.opt_rcode();
    if rcode != OptRcode::NOERROR {
        return Err(format!("{}/NS query failed: {rcode}", zone.to_name::<Vec<u8>>()).into());
    }
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
    let res = lookup_host(&resolver, &name).await.map_err(|e| {
        format!(
            "lookup of addresses for {} failed: {e}",
            name.to_name::<Vec<u8>>()
        )
    })?;
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
    now: UnixTime,
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
                return Ok(AutoReportActionsResult::Wait(now + r.ttl().into_duration()));
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
                return Ok(AutoReportActionsResult::Wait(now + r.ttl().into_duration()));
            }
            continue;
        }
    }
    if let Some(record) = target_dnskey.iter().next() {
        // Not all DNSKEY records were found.
        warn!("Not all required DNSKEY records were found for {zone}");
        Ok(AutoReportActionsResult::Wait(now + record.ttl().into()))
    } else {
        Ok(AutoReportActionsResult::Report(max_ttl))
    }
}

/// Check whether a nameserver at a specific address has the right DS RRset.
async fn check_ds_for_address(
    zone: &Name<Vec<u8>>,
    address: &IpAddr,
    mut target_dnskey: HashSet<RecordDnskey>,
    now: UnixTime,
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
            return Ok(AutoReportActionsResult::Wait(now + r.ttl().into_duration()));
        }
        continue;
    }
    let dnskey = target_dnskey.iter().next();
    if let Some(dnskey) = dnskey {
        debug!("Check DS RRset: expected DS record not present");
        let ttl = dnskey.ttl();
        Ok(AutoReportActionsResult::Wait(now + ttl.into_duration()))
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
    now: UnixTime,
) -> Result<AutoReportActionsResult, Error> {
    let records = lookup_name_rtype_at_address::<Soa<_>>(zone, Rtype::SOA, address).await?;

    if records.is_empty() {
        return Ok(AutoReportActionsResult::Wait(now + DEFAULT_WAIT));
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
        return Ok(AutoReportActionsResult::Wait(now + ttl.into()));
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
    let response = request
        .get_response()
        .await
        .map_err(|e| format!("{name}/{rtype} request to {address} failed: {e}"))?;

    let mut res = Vec::new();
    for r in response.answer()?.limit_to_in::<T>() {
        let r = r?;
        res.push(r);
    }
    Ok(res)
}

/// Return the name of the parent zone.
async fn parent_zone(name: &Name<Vec<u8>>) -> Result<Name<Vec<u8>>, Error> {
    let parent = name
        .parent()
        .ok_or_else::<Error, _>(|| format!("unable to get parent of {name}").into())?;

    let resolver = StubResolver::new();
    let answer = resolver
        .query((&parent, Rtype::SOA))
        .await
        .map_err(|e| format!("lookup of {parent}/SOA failed: {e}"))?;
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
                    .values()
                    .filter_map(|k| {
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
                // for them. For 'normal' records, return WaitRecord.
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
async fn check_soa(serial: Serial, kss: &KeySetState, now: UnixTime) -> Result<bool, Error> {
    // Find the address of all name servers of zone
    // Ask each nameserver for the SOA record.
    // Check that it's version is at least the version we checked.
    // If it doesn't match, wait the TTL of the SOA record to try again.
    // On error, wait a default time.

    let zone = kss.keyset.name();

    let addresses = addresses_for_zone(zone).await?;
    let futures: Vec<_> = addresses
        .iter()
        .map(|a| check_soa_for_address(zone, a, serial, now.clone()))
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
        .values()
        .filter_map(|k| match k.keytype() {
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
    let answer = resolver
        .query((zone, Rtype::SOA))
        .await
        .map_err(|e| format!("lookup of {zone}/SOA failed: {e}"))?;
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

/// Show the automatic roll state for one state in a roll.
fn show_automatic_roll_state(
    roll: RollType,
    state: &RollState,
    auto_state: &ReportState,
    report: bool,
) {
    println!("Roll {roll:?}, state {state:?}:");
    if let Some(status) = &auto_state.dnskey {
        match status {
            AutoReportActionsResult::Wait(retry) => {
                println!("\tWait until the new DNSKEY RRset has propagated to all nameservers.");
                println!("\tTry again after {retry}");
            }
            AutoReportActionsResult::Report(ttl) => {
                println!("\tThe new DNSKEY RRset has propagated to all nameservers.");
                if report {
                    println!("\tReport (at least) TTL {}", ttl.as_secs());
                }
            }
        }
    }
    if let Some(status) = &auto_state.ds {
        match status {
            AutoReportActionsResult::Wait(retry) => {
                println!("\tWait until the new DS RRset has propagated to all nameservers");
                println!("\tof the parent zone. Try again after {retry}");
            }
            AutoReportActionsResult::Report(ttl) => {
                println!("\tThe new DS RRset has propagated to all nameservers.");
                if report {
                    println!("\tReport (at least) TTL {}", ttl.as_secs());
                }
            }
        }
    }
    if let Some(status) = &auto_state.rrsig {
        match status {
            AutoReportRrsigResult::Wait(next) => {
                println!("\tSomething went wrong transferring the zone to be verified.");
                println!("\tTry again after {next}");
            }
            AutoReportRrsigResult::WaitRecord {
                name, rtype, next, ..
            } => {
                println!("\tWait until {name}/{rtype} is signed with the right keys.");
                println!("\tTry again after {next}");
            }
            AutoReportRrsigResult::WaitNextSerial { serial, next, .. } => {
                println!("\tWait for a zone with serial higher than {serial}");
                println!("\tTry again after {next}");
            }
            AutoReportRrsigResult::WaitSoa { serial, next, .. } => {
                println!("\tWait until the zone with at least serial {serial} has propagated");
                println!("\tto all nameservers. Try again after {next}");
            }
            AutoReportRrsigResult::Report(ttl) => {
                println!("\tThe new RRSIG records have propagated to all nameservers.");
                if report {
                    println!("\tReport (at least) TTL {}", ttl.as_secs());
                }
            }
        }
    }
}

/// Open filename, get an exclusive lock and return the open file.
///
/// Assume changes are saved by creating a new file and renaming. After
/// locking the file, the function has to check if the locked file is the
/// same as the current file under that name.
fn file_with_write_lock(filename: &PathBuf) -> Result<File, Error> {
    // The config file is updated by writing to a new file and then renaming.
    // We might have locked the old file. Check. Try a number of times and
    // then give up. Lock contention is expected to be low.
    for _try in 0..MAX_FILE_LOCK_TRIES {
        let file = File::open(filename)
            .map_err(|e| format!("unable to open file {}: {e}", filename.display()))?;

        file.lock_exclusive()
            .map_err(|e| format!("unable to lock {}: {e}", filename.display()))?;

        let file_clone = file
            .try_clone()
            .map_err(|e| format!("unable to clone locked file {}: {e}", filename.display()))?;
        let locked_file_handle = Handle::from_file(file_clone).map_err(|e| {
            format!(
                "Unable to get handle from locked file {}: {e}",
                filename.display()
            )
        })?;
        let current_file_handle = Handle::from_path(filename)
            .map_err(|e| format!("Unable to get handle from file {}: {e}", filename.display()))?;

        if locked_file_handle != current_file_handle {
            continue;
        }
        return Ok(file);
    }
    Err(format!(
        "unable to lock {} after {MAX_FILE_LOCK_TRIES} tries",
        filename.display()
    )
    .into())
}

/// Helper function for serde.
///
/// Return the default autoremove delay.
fn default_autoremove_delay() -> Duration {
    DEFAULT_AUTOREMOVE_DELAY
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
