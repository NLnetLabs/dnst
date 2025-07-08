use crate::env::Env;
use crate::error::Error;
use crate::util;
use bytes::Bytes;
use clap::Subcommand;
use domain::base::iana::Class;
use domain::base::iana::{DigestAlgorithm, SecurityAlgorithm};
use domain::base::zonefile_fmt::{DisplayKind, ZonefileFmt};
use domain::base::{Name, Record, ToName, Ttl};
use domain::crypto::sign;
use domain::crypto::sign::{GenerateParams, KeyPair, SecretKeyBytes};
use domain::dnssec::common::{display_as_bind, parse_from_bind};
use domain::dnssec::sign::keys::keyset::{Action, Key, KeySet, KeyType, RollType, UnixTime};
use domain::dnssec::sign::keys::SigningKey;
use domain::dnssec::sign::records::Rrset;
use domain::dnssec::sign::signatures::rrsigs::sign_rrset;
use domain::dnssec::validator::base::DnskeyExt;
use domain::rdata::dnssec::Timestamp;
use domain::rdata::{Cdnskey, Cds, Ds, ZoneRecordData};
use domain::zonefile::inplace::Zonefile;
use domain::zonefile::inplace::{Entry, ScannedRecordData};
use jiff::{Span, SpanRelativeTo};
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::{remove_file, File};
use std::io::Write;
use std::path::{absolute, Path, PathBuf};
use std::time::Duration;
use std::time::SystemTime;
use url::Url;

const MAX_KEY_TAG_TRIES: u8 = 10;

#[derive(Clone, Debug, clap::Args)]
pub struct Keyset {
    /// Keyset config
    #[arg(short = 'c')]
    keyset_conf: PathBuf,

    /// Subcommand
    #[command(subcommand)]
    cmd: Commands,
}

type OptDuration = Option<Duration>;

#[derive(Clone, Debug, Subcommand)]
enum Commands {
    Create {
        /// Domain name
        #[arg(short = 'n')]
        domain_name: Name<Vec<u8>>,

        /// State file
        #[arg(short = 's')]
        keyset_state: PathBuf,
    },

    Init,
    StartKskRoll,
    StartZskRoll,
    StartCskRoll,
    StartAlgorithmRoll,
    KskPropagation1Complete {
        ttl: u32,
    },
    KskPropagation2Complete {
        ttl: u32,
    },
    ZskPropagation1Complete {
        ttl: u32,
    },
    ZskPropagation2Complete {
        ttl: u32,
    },
    CskPropagation1Complete {
        ttl: u32,
    },
    CskPropagation2Complete {
        ttl: u32,
    },
    AlgorithmPropagation1Complete {
        ttl: u32,
    },
    AlgorithmPropagation2Complete {
        ttl: u32,
    },
    KskCacheExpired1,
    KskCacheExpired2,
    ZskCacheExpired1,
    ZskCacheExpired2,
    CskCacheExpired1,
    CskCacheExpired2,
    AlgorithmCacheExpired1,
    AlgorithmCacheExpired2,
    KskRollDone,
    ZskRollDone,
    CskRollDone,
    AlgorithmRollDone,
    Status,
    Actions,
    Keys,
    GetUseCsk,
    SetUseCsk {
        boolean: bool,
    },
    GetAutoremove,
    SetAutoremove {
        boolean: bool,
    },
    GetKskAlgorithm,
    SetKskAlgorithm {
        #[arg(short = 'b')]
        bits: Option<usize>,

        // XXX Enum
        value: String,
    },
    GetZskAlgorithm,
    SetZskAlgorithm {
        #[arg(short = 'b')]
        bits: Option<usize>,

        // XXX Enum
        value: String,
    },
    GetCskAlgorithm,
    SetCskAlgorithm {
        #[arg(short = 'b')]
        bits: Option<usize>,

        // XXX Enum
        value: String,
    },
    GetDsAlgorithm,
    SetDsAlgorithm {
        #[arg(value_parser = DsAlgorithm::new)]
        algorithm: DsAlgorithm,
    },
    SetDnskeyInceptionOffset {
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    GetDnskeyLifetime,
    SetDnskeyLifetime {
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    SetDnskeyRemainTime {
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    SetCdsInceptionOffset {
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    GetCdsLifetime,
    SetCdsLifetime {
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    SetCdsRemainTime {
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    SetKskValidity {
        #[arg(value_parser = parse_opt_duration)]
        opt_duration: OptDuration,
    },
    SetZskValidity {
        #[arg(value_parser = parse_opt_duration)]
        opt_duration: OptDuration,
    },
    SetCskValidity {
        #[arg(value_parser = parse_opt_duration)]
        opt_duration: OptDuration,
    },
    Show,
    GetDnskey,
    GetCds,
    GetDs,
    Cron,
}

impl Keyset {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
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
            };
            const ONE_DAY: u64 = 86400;
            const FOUR_WEEKS: u64 = 2419200;
            let ksc = KeySetConfig {
                state_file: state_file.clone(),
                keys_dir,
                use_csk: false,
                ksk_generate_params: KeyParameters::RsaSha256(2048),
                zsk_generate_params: KeyParameters::RsaSha256(2048),
                csk_generate_params: KeyParameters::RsaSha256(2048),
                ksk_validity: None,
                zsk_validity: None,
                csk_validity: None,
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
            Commands::Create {
                domain_name: _,
                keyset_state: _,
            } => unreachable!(),
            Commands::Init => {
                // Check for re-init.
                if !kss.keyset.keys().is_empty() {
                    // Avoid re-init.
                    return Err("already initialized\n".into());
                }

                // Check for CSK.
                let actions = if ksc.use_csk {
                    // Generate CSK.
                    let (csk_pub_name, csk_priv_name, algorithm, key_tag) = new_keys(
                        kss.keyset.name(),
                        ksc.csk_generate_params.to_generate_params(),
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
                        ksc.ksk_generate_params.to_generate_params(),
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
                        ksc.zsk_generate_params.to_generate_params(),
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

                print_actions(&actions);
                state_changed = true;
            }
            Commands::StartKskRoll => {
                if kss.keyset.keys().is_empty() {
                    // Avoid KSK roll without init.
                    return Err("not yet initialized\n".into());
                }

                // Check for CSK.
                if ksc.use_csk {
                    return Err("wrong key roll, use start-csk-roll\n".into());
                }

                // Refuse if we can find a CSK key.
                if kss
                    .keyset
                    .keys()
                    .iter()
                    .any(|(_, key)| matches!(key.keytype(), KeyType::Csk(_, _)))
                {
                    return Err("cannot start key roll, found CSK\n".into());
                }

                // Find existing KSKs. Do we complain if there is none?
                let old_stored: Vec<_> = kss
                    .keyset
                    .keys()
                    .iter()
                    .filter(|(_, key)| {
                        if let KeyType::Ksk(keystate) = key.keytype() {
                            !keystate.old()
                                || keystate.signer()
                                || keystate.present()
                                || keystate.at_parent()
                        } else {
                            false
                        }
                    })
                    .map(|(name, _)| name.clone())
                    .collect();
                let old: Vec<_> = old_stored.iter().map(|name| name.as_ref()).collect();

                // Collect algorithms. Maybe this needs to be in the library.

                // Create a new KSK
                let (ksk_pub_url, ksk_priv_url, algorithm, key_tag) = new_keys(
                    kss.keyset.name(),
                    ksc.ksk_generate_params.to_generate_params(),
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
                    .map_err::<Error, _>(|e| {
                        format!("unable to add KSK {ksk_pub_url}: {e}\n").into()
                    })?;

                let new = [ksk_pub_url.as_ref()];

                // Start the key roll
                let actions = match kss
                    .keyset
                    .start_roll(RollType::KskRoll, &old, &new)
                    .map_err::<Error, _>(|e| format!("cannot start roll: {e}\n").into())
                {
                    Ok(actions) => actions,
                    Err(e) => {
                        // Remove the key files we just created.
                        if ksk_priv_url.scheme() == "file" {
                            remove_file(ksk_priv_url.path()).map_err::<Error, _>(|e| {
                                format!("unable to remove private key file {ksk_priv_url}: {e}\n")
                                    .into()
                            })?;
                        } else {
                            panic!("unsupported URL scheme in {ksk_priv_url}");
                        }

                        if ksk_pub_url.scheme() == "file" {
                            remove_file(ksk_pub_url.path()).map_err::<Error, _>(|e| {
                                format!("unable to remove public key file {ksk_pub_url}: {e}\n")
                                    .into()
                            })?;
                        } else {
                            panic!("unsupported URL scheme in {ksk_pub_url}");
                        }

                        return Err(e);
                    }
                };
                handle_actions(&actions, &ksc, &mut kss, env)?;

                print_actions(&actions);
                state_changed = true;
            }
            Commands::StartZskRoll => {
                if kss.keyset.keys().is_empty() {
                    // Avoid ZSK roll without init.
                    return Err("not yet initialized\n".into());
                }

                // Check for CSK.
                if ksc.use_csk {
                    return Err("wrong key roll, use start-csk-roll\n".into());
                }

                // Refuse if we can find a CSK key.
                if kss
                    .keyset
                    .keys()
                    .iter()
                    .any(|(_, key)| matches!(key.keytype(), KeyType::Csk(_, _)))
                {
                    return Err("cannot start key roll, found CSK\n".into());
                }

                // Find existing ZSKs. Do we complain if there is none?
                let old_stored: Vec<_> = kss
                    .keyset
                    .keys()
                    .iter()
                    .filter(|(_, key)| {
                        if let KeyType::Zsk(keystate) = key.keytype() {
                            !keystate.old() || keystate.signer() || keystate.present()
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
                    ksc.zsk_generate_params.to_generate_params(),
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
                    .map_err::<Error, _>(|e| {
                        format!("unable to add ZSK {zsk_pub_url}: {e}\n").into()
                    })?;

                let new = [zsk_pub_url.as_ref()];

                // Start the key roll
                let actions = match kss
                    .keyset
                    .start_roll(RollType::ZskRoll, &old, &new)
                    .map_err::<Error, _>(|e| format!("cannot start roll: {e}\n").into())
                {
                    Ok(actions) => actions,
                    Err(e) => {
                        // Remove the key files we just created.
                        if zsk_priv_url.scheme() == "file" {
                            remove_file(zsk_priv_url.path()).map_err::<Error, _>(|e| {
                                format!("unable to remove private key file {zsk_priv_url}: {e}\n")
                                    .into()
                            })?;
                        } else {
                            panic!("unsupported URL scheme in {zsk_priv_url}");
                        }
                        if zsk_pub_url.scheme() == "file" {
                            remove_file(zsk_pub_url.path()).map_err::<Error, _>(|e| {
                                format!("unable to remove public key file {zsk_pub_url}: {e}\n")
                                    .into()
                            })?;
                        } else {
                            panic!("unsupported URL scheme in {zsk_pub_url}");
                        }
                        return Err(e);
                    }
                };
                handle_actions(&actions, &ksc, &mut kss, env)?;

                print_actions(&actions);
                state_changed = true;
            }
            Commands::StartCskRoll => {
                // Find existing KSKs, ZSKs and CSKs. Do we complain if there
                // are none?
                let old_stored: Vec<_> = kss
                    .keyset
                    .keys()
                    .iter()
                    .filter(|(_, key)| match key.keytype() {
                        KeyType::Ksk(keystate)
                        | KeyType::Zsk(keystate)
                        | KeyType::Csk(keystate, _) => {
                            // Assume that for a CSK it is sufficient to check
                            // one of the key states. Also assume that we
                            // can check at_parent for a ZSK.
                            !keystate.old()
                                || keystate.signer()
                                || keystate.present()
                                || keystate.at_parent()
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
                        ksc.csk_generate_params.to_generate_params(),
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
                        .map_err::<Error, _>(|e| {
                            format!("unable to add CSK {csk_pub_url}: {e}\n").into()
                        })?;

                    let new = vec![csk_pub_url];
                    (new, new_urls)
                } else {
                    let mut new_urls = Vec::new();

                    // Create a new KSK
                    let (ksk_pub_url, ksk_priv_url, algorithm, key_tag) = new_keys(
                        kss.keyset.name(),
                        ksc.ksk_generate_params.to_generate_params(),
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
                        .map_err::<Error, _>(|e| {
                            format!("unable to add KSK {ksk_pub_url}: {e}\n").into()
                        })?;

                    // Create a new ZSK
                    let (zsk_pub_url, zsk_priv_url, algorithm, key_tag) = new_keys(
                        kss.keyset.name(),
                        ksc.zsk_generate_params.to_generate_params(),
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
                        .map_err::<Error, _>(|e| {
                            format!("unable to add ZSK {zsk_pub_url}: {e}\n").into()
                        })?;

                    let new = vec![ksk_pub_url, zsk_pub_url];
                    (new, new_urls)
                };

                let new: Vec<_> = new_stored.iter().map(|v| v.as_ref()).collect();

                // Start the key roll
                let actions = match kss
                    .keyset
                    .start_roll(RollType::CskRoll, &old, &new)
                    .map_err::<Error, _>(|e| format!("cannot start roll: {e}\n").into())
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

                handle_actions(&actions, &ksc, &mut kss, env)?;

                print_actions(&actions);
                state_changed = true;
            }
            Commands::StartAlgorithmRoll => {
                // Find existing KSKs, ZSKs and CSKs. Do we complain if there
                // are none?
                let old_stored: Vec<_> = kss
                    .keyset
                    .keys()
                    .iter()
                    .filter(|(_, key)| match key.keytype() {
                        KeyType::Ksk(keystate)
                        | KeyType::Zsk(keystate)
                        | KeyType::Csk(keystate, _) => {
                            // Assume that for a CSK it is sufficient to check
                            // one of the key states. Also assume that we
                            // can check at_parent for a ZSK.
                            !keystate.old()
                                || keystate.signer()
                                || keystate.present()
                                || keystate.at_parent()
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
                        ksc.csk_generate_params.to_generate_params(),
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
                        .map_err::<Error, _>(|e| {
                            format!("unable to add CSK {csk_pub_url}: {e}\n").into()
                        })?;

                    let new = vec![csk_pub_url];
                    (new, new_urls)
                } else {
                    let mut new_urls = Vec::new();

                    // Create a new KSK
                    let (ksk_pub_url, ksk_priv_url, algorithm, key_tag) = new_keys(
                        kss.keyset.name(),
                        ksc.ksk_generate_params.to_generate_params(),
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
                        .map_err::<Error, _>(|e| {
                            format!("unable to add KSK {ksk_pub_url}: {e}\n").into()
                        })?;

                    // Create a new ZSK
                    let (zsk_pub_url, zsk_priv_url, algorithm, key_tag) = new_keys(
                        kss.keyset.name(),
                        ksc.zsk_generate_params.to_generate_params(),
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
                        .map_err::<Error, _>(|e| {
                            format!("unable to add ZSK {zsk_pub_url}: {e}\n").into()
                        })?;

                    let new = vec![ksk_pub_url, zsk_pub_url];
                    (new, new_urls)
                };

                let new: Vec<_> = new_stored.iter().map(|v| v.as_ref()).collect();

                // Start the key roll
                let actions = match kss
                    .keyset
                    .start_roll(RollType::AlgorithmRoll, &old, &new)
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

                handle_actions(&actions, &ksc, &mut kss, env)?;

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
                let actions = match self.cmd {
                    Commands::KskRollDone => kss.keyset.roll_done(RollType::KskRoll),
                    Commands::ZskRollDone => kss.keyset.roll_done(RollType::ZskRoll),
                    Commands::CskRollDone => kss.keyset.roll_done(RollType::CskRoll),
                    Commands::AlgorithmRollDone => kss.keyset.roll_done(RollType::AlgorithmRoll),
                    _ => unreachable!(),
                };

                let actions = match actions {
                    Ok(actions) => actions,
                    Err(err) => {
                        return Err(format!("Error reporting done: {err}\n").into());
                    }
                };

                if !actions.is_empty() {
                    return Err("List of actions after reporting done\n".into());
                }

                // Remove old keys.
                if ksc.autoremove {
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
                            state.old() && !state.signer() && !state.present() && !state.at_parent()
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
            }
            Commands::Actions => {
                for roll in kss.keyset.rollstates().keys() {
                    let actions = kss.keyset.actions(roll.clone());
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
            Commands::GetUseCsk => {
                println!("{}", ksc.use_csk);
            }
            Commands::SetUseCsk { boolean } => {
                ksc.use_csk = boolean;
                config_changed = true;
            }
            Commands::GetAutoremove => {
                println!("{}", ksc.autoremove);
            }
            Commands::SetAutoremove { boolean } => {
                ksc.autoremove = boolean;
                config_changed = true;
            }
            Commands::GetKskAlgorithm => {
                println!("{}", ksc.ksk_generate_params);
            }
            Commands::SetKskAlgorithm { bits, value } => {
                ksc.ksk_generate_params = KeyParameters::new(&value, bits)?;
                config_changed = true;
            }
            Commands::GetZskAlgorithm => {
                println!("{}", ksc.zsk_generate_params);
            }
            Commands::SetZskAlgorithm { bits, value } => {
                ksc.zsk_generate_params = KeyParameters::new(&value, bits)?;
                config_changed = true;
            }
            Commands::GetCskAlgorithm => {
                println!("{}", ksc.csk_generate_params);
            }
            Commands::SetCskAlgorithm { bits, value } => {
                ksc.csk_generate_params = KeyParameters::new(&value, bits)?;
                config_changed = true;
            }
            Commands::GetDsAlgorithm => {
                println!("{}", ksc.ds_algorithm);
            }
            Commands::SetDsAlgorithm { algorithm } => {
                ksc.ds_algorithm = algorithm;
                config_changed = true;
            }
            Commands::SetDnskeyInceptionOffset { duration } => {
                ksc.dnskey_inception_offset = duration;
                config_changed = true;
            }
            Commands::GetDnskeyLifetime => {
                let span = Span::try_from(ksc.dnskey_signature_lifetime).expect("should not fail");
                let signeddur = span
                    .to_duration(SpanRelativeTo::days_are_24_hours())
                    .expect("should not fail");
                println!("{signeddur:#}");
            }
            Commands::SetDnskeyLifetime { duration } => {
                ksc.dnskey_signature_lifetime = duration;
                config_changed = true;
            }
            Commands::SetDnskeyRemainTime { duration } => {
                ksc.dnskey_remain_time = duration;
                config_changed = true;
            }
            Commands::SetCdsInceptionOffset { duration } => {
                ksc.cds_inception_offset = duration;
                config_changed = true;
            }
            Commands::GetCdsLifetime => {
                let span = Span::try_from(ksc.cds_signature_lifetime).expect("should not fail");
                let signeddur = span
                    .to_duration(SpanRelativeTo::days_are_24_hours())
                    .expect("should not fail");
                println!("{signeddur:#}");
            }
            Commands::SetCdsLifetime { duration } => {
                ksc.cds_signature_lifetime = duration;
                config_changed = true;
            }
            Commands::SetCdsRemainTime { duration } => {
                ksc.cds_remain_time = duration;
                config_changed = true;
            }
            Commands::SetKskValidity { opt_duration } => {
                ksc.ksk_validity = opt_duration;
                config_changed = true;
            }
            Commands::SetZskValidity { opt_duration } => {
                ksc.zsk_validity = opt_duration;
                config_changed = true;
            }
            Commands::SetCskValidity { opt_duration } => {
                ksc.csk_validity = opt_duration;
                config_changed = true;
            }
            Commands::Show => {
                println!("state-file: {:?}", ksc.state_file);
                println!("use-csk: {}", ksc.use_csk);
                println!("ksk-algorithm: {}", ksc.ksk_generate_params);
                println!("zsk-algorithm: {}", ksc.zsk_generate_params);
                println!("csk-algorithm: {}", ksc.csk_generate_params);
                println!("ksk-validity: {:?}", ksc.ksk_validity);
                println!("zsk-validity: {:?}", ksc.zsk_validity);
                println!("csk-validity: {:?}", ksc.csk_validity);
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
            Commands::GetDnskey => {
                for r in &kss.dnskey_rrset {
                    println!("{r}");
                }
            }
            Commands::GetCds => {
                for r in &kss.cds_rrset {
                    println!("{r}");
                }
            }
            Commands::GetDs => {
                for r in &kss.ds_rrset {
                    println!("{r}");
                }
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
            }
        }

        let cron_next_dnskey = compute_cron_next(&kss.dnskey_rrset, &ksc.dnskey_remain_time);
        let cron_next_cds = compute_cron_next(&kss.cds_rrset, &ksc.cds_remain_time);
        let cron_next = if let Some(cron_next_dnskey) = cron_next_dnskey {
            if let Some(cron_next_cds) = cron_next_cds {
                Some(min(cron_next_dnskey, cron_next_cds))
            } else {
                Some(cron_next_dnskey)
            }
        } else {
            cron_next_cds
        };
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

/// Config for the keyset command.
#[derive(Deserialize, Serialize)]
struct KeySetConfig {
    state_file: PathBuf,
    keys_dir: PathBuf,

    use_csk: bool,

    /// Algorithm and other parameters for key generation.
    ksk_generate_params: KeyParameters,
    zsk_generate_params: KeyParameters,
    csk_generate_params: KeyParameters,

    ksk_validity: Option<Duration>,
    zsk_validity: Option<Duration>,
    csk_validity: Option<Duration>,
    // ksk validity
    // auto-ksk

    // DNSKEY inception offset
    dnskey_inception_offset: Duration,

    // DNSKEY sig lifetime
    dnskey_signature_lifetime: Duration,

    // DNSKEY resign
    dnskey_remain_time: Duration,

    // CDS/CDNSKEY inception offset
    cds_inception_offset: Duration,

    // CDS/CDNSKEY sig lifetime
    cds_signature_lifetime: Duration,

    // CDS/CDNSKEY resign
    cds_remain_time: Duration,

    // DS hash algorithm
    ds_algorithm: DsAlgorithm,

    /// Automatically remove keys that are no long in use.
    autoremove: bool,
}

/// Persistent state for the keyset command.
#[derive(Deserialize, Serialize)]
struct KeySetState {
    /// Domain KeySet state.
    keyset: KeySet,

    pub dnskey_rrset: Vec<String>,
    pub ds_rrset: Vec<String>,
    pub cds_rrset: Vec<String>,
    pub ns_rrset: Vec<String>,

    cron_next: Option<UnixTime>,
}

#[derive(Deserialize, Serialize)]
enum KeyParameters {
    RsaSha256(usize),
    RsaSha512(usize),
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
    Ed448,
}

impl KeyParameters {
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

// Do we want Deserialize and Serialize for DigestAlgorithm?
#[derive(Clone, Debug, Deserialize, Serialize)]
enum DsAlgorithm {
    Sha256,
    Sha384,
}

impl DsAlgorithm {
    fn new(digest: &str) -> Result<Self, Error> {
        if digest == "SHA-256" {
            Ok(DsAlgorithm::Sha256)
        } else if digest == "SHA-384" {
            Ok(DsAlgorithm::Sha384)
        } else {
            Err(format!("unknown digest {digest}\n").into())
        }
    }

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

fn remove_cds_rrset(kss: &mut KeySetState) {
    kss.cds_rrset.truncate(0);
}

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

fn parse_duration(value: &str) -> Result<Duration, Error> {
    let span: Span = value
        .parse()
        .map_err::<Error, _>(|e| format!("unable to parse {value} as lifetime: {e}\n").into())?;
    let signeddur = span
        .to_duration(SpanRelativeTo::days_are_24_hours())
        .map_err::<Error, _>(|e| format!("unable to convert duration: {e}\n").into())?;
    Duration::try_from(signeddur).map_err(|e| format!("unable to convert duration: {e}\n").into())
}

fn parse_opt_duration(value: &str) -> Result<Option<Duration>, Error> {
    if value == "off" {
        return Ok(None);
    }
    let duration = parse_duration(value)?;
    Ok(Some(duration))
}

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
    if keystate.old() && !keystate.present() && !keystate.signer() && !keystate.at_parent() {
        // Old key.
        return (false, "");
    }
    let Some(validity) = validity else {
        // No limit on key validity.
        return (false, "");
    };
    (timestamp.elapsed() > validity, label)
}

fn make_parent_dir(filename: PathBuf) -> PathBuf {
    filename.parent().unwrap_or(Path::new("/")).to_path_buf()
}

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

    min_expiration.map(|t| (t - *remain_time).try_into().unwrap())
}
