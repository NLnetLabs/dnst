use std::cmp::min;
use std::collections::HashMap;
use std::convert::From;
use std::fmt::{Debug, Display, Formatter};
use std::fs::{remove_file, File};
use std::io::Write;
use std::path::{absolute, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use bytes::Bytes;
use domain::base::iana::Class;
use domain::base::iana::{DigestAlgorithm, SecurityAlgorithm};
use domain::base::name::FlattenInto;
use domain::base::zonefile_fmt::{DisplayKind, ZonefileFmt};
use domain::base::{Name, Record, ToName, Ttl};
use domain::crypto::kmip::{self, ClientCertificate, ConnectionSettings};
use domain::crypto::kmip_pool::{ConnectionManager, KmipConnPool};
use domain::crypto::sign::{GenerateParams, KeyPair, SecretKeyBytes, SignRaw};
use domain::dnssec::common::{display_as_bind, parse_from_bind};
use domain::dnssec::sign::keys::keyset::{Action, Key, KeySet, KeyType, RollType, UnixTime};
use domain::dnssec::sign::keys::SigningKey;
use domain::dnssec::sign::records::Rrset;
use domain::dnssec::sign::signatures::rrsigs::sign_rrset;
use domain::dnssec::validator::base::DnskeyExt;
use domain::rdata::dnssec::Timestamp;
use domain::rdata::{Cdnskey, Cds, Dnskey, Ds, ZoneRecordData};
use domain::zonefile::inplace::Zonefile;
use domain::zonefile::inplace::{Entry, ScannedRecordData};
use jiff::{Span, SpanRelativeTo};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::env::Env;
use crate::error::Error;
use crate::util;

const MAX_KEY_TAG_TRIES: u8 = 10;

#[derive(Clone, Debug, clap::Args)]
pub struct Keyset {
    /// Keyset config
    #[arg(short = 'c')]
    keyset_conf: PathBuf,

    /// Domain name (only for create)
    #[arg(short = 'n')]
    domain_name: Option<Name<Vec<u8>>>,

    /// State file (only for create)
    #[arg(short = 's')]
    keyset_state: Option<PathBuf>,

    #[arg(short = 't')]
    ttl: Option<u32>,

    #[arg(short = 'b')]
    bits: Option<usize>,

    /// Subcommand
    #[arg()]
    cmd: String,

    values: Vec<String>,
}

impl Keyset {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(self.run(&env))
    }

    fn value_or(&mut self) -> Result<String, Error> {
        match self.values.len() {
            1 => Ok(self.values.pop().unwrap()),
            _ => Err("argument expected\n".into()),
        }
    }

    fn parse_duration_from_opt(&mut self) -> Result<Duration, Error> {
        let arg = self.value_or()?;
        let span: Span = arg
            .parse()
            .map_err::<Error, _>(|e| format!("unable to parse {arg} as lifetime: {e}\n").into())?;
        let signeddur = span
            .to_duration(SpanRelativeTo::days_are_24_hours())
            .map_err::<Error, _>(|e| format!("unable to convert duration: {e}\n").into())?;
        Duration::try_from(signeddur)
            .map_err(|e| format!("unable to convert duration: {e}\n").into())
    }

    fn parse_opt_duration_from_opt(&mut self) -> Result<Option<Duration>, Error> {
        if let Some(value) = self.values.get(0) {
            if value == "off" {
                return Ok(None);
            }
        }
        let duration = self.parse_duration_from_opt()?;
        Ok(Some(duration))
    }

    /// Run the command as an async function
    pub async fn run(mut self, env: &impl Env) -> Result<(), Error> {
        if self.cmd == "create" {
            let domainname = self
                .domain_name
                .ok_or::<Error>("domain name option expected\n".into())?;

            let state_file = self
                .keyset_state
                .ok_or::<Error>("state file option expected\n".into())?;
            let state_file = absolute(&state_file).map_err::<Error, _>(|e| {
                format!("unable to make {} absolute: {}", state_file.display(), e).into()
            })?;
            let keys_dir = make_parent_dir(state_file.clone());

            let ks = KeySet::new(domainname);
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
                kmip_servers: HashMap::new(),
                default_kmip_server: None,
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

        let kmip_server_id = ksc.default_kmip_server.clone();
        let kmip_conn_settings = kmip_server_id
            .as_ref()
            .and_then(|id| ksc.kmip_servers.get(id))
            .map(|conn_settings| Arc::new(ConnectionSettings::from(conn_settings.clone())));
        let kmip_conn_pool = if let Some(conn_settings) = kmip_conn_settings.as_ref() {
            Some(kmip_create_conn_pool(conn_settings.clone())?)
        } else {
            None
        };

        if self.cmd == "init" {
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
                    &kmip_server_id,
                    &kmip_conn_pool,
                )?;
                kss.keyset
                    .add_key_csk(
                        csk_pub_name.to_string(),
                        Some(csk_priv_name.to_string()),
                        algorithm,
                        key_tag,
                        UnixTime::now(),
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
                    &kmip_server_id,
                    &kmip_conn_pool,
                )?;
                kss.keyset
                    .add_key_ksk(
                        ksk_pub_url.to_string(),
                        Some(ksk_priv_url.to_string()),
                        algorithm,
                        key_tag,
                        UnixTime::now(),
                    )
                    .expect("should not happen");
                let (zsk_pub_url, zsk_priv_url, algorithm, key_tag) = new_keys(
                    kss.keyset.name(),
                    ksc.zsk_generate_params.to_generate_params(),
                    false,
                    kss.keyset.keys(),
                    &ksc.keys_dir,
                    env,
                    &kmip_server_id,
                    &kmip_conn_pool,
                )?;
                kss.keyset
                    .add_key_zsk(
                        zsk_pub_url.to_string(),
                        Some(zsk_priv_url.to_string()),
                        algorithm,
                        key_tag,
                        UnixTime::now(),
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
        } else if self.cmd == "start-ksk-roll" {
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
                &kmip_server_id,
                &kmip_conn_pool,
            )?;
            kss.keyset
                .add_key_ksk(
                    ksk_pub_url.to_string(),
                    Some(ksk_priv_url.to_string()),
                    algorithm,
                    key_tag,
                    UnixTime::now(),
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
                            format!("unable to remove public key file {ksk_pub_url}: {e}\n").into()
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
        } else if self.cmd == "start-zsk-roll" {
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
                &kmip_server_id,
                &kmip_conn_pool,
            )?;
            kss.keyset
                .add_key_zsk(
                    zsk_pub_url.to_string(),
                    Some(zsk_priv_url.to_string()),
                    algorithm,
                    key_tag,
                    UnixTime::now(),
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
                            format!("unable to remove public key file {zsk_pub_url}: {e}\n").into()
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
        } else if self.cmd == "start-csk-roll" {
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
                    &kmip_server_id,
                    &kmip_conn_pool,
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
                    &kmip_server_id,
                    &kmip_conn_pool,
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
                    &kmip_server_id,
                    &kmip_conn_pool,
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
        } else if self.cmd == "start-algorithm-roll" {
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
                    &kmip_server_id,
                    &kmip_conn_pool,
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
                    &kmip_server_id,
                    &kmip_conn_pool,
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
                    &kmip_server_id,
                    &kmip_conn_pool,
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
        } else if self.cmd == "ksk-propagation1-complete"
            || self.cmd == "ksk-propagation2-complete"
            || self.cmd == "zsk-propagation1-complete"
            || self.cmd == "zsk-propagation2-complete"
            || self.cmd == "csk-propagation1-complete"
            || self.cmd == "csk-propagation2-complete"
            || self.cmd == "algorithm-propagation1-complete"
            || self.cmd == "algorithm-propagation2-complete"
        {
            let Some(ttl) = self.ttl else {
                return Err("ttl option is required\n".into());
            };
            let actions = if self.cmd == "ksk-propagation1-complete" {
                kss.keyset.propagation1_complete(RollType::KskRoll, ttl)
            } else if self.cmd == "ksk-propagation2-complete" {
                kss.keyset.propagation2_complete(RollType::KskRoll, ttl)
            } else if self.cmd == "zsk-propagation1-complete" {
                kss.keyset.propagation1_complete(RollType::ZskRoll, ttl)
            } else if self.cmd == "zsk-propagation2-complete" {
                kss.keyset.propagation2_complete(RollType::ZskRoll, ttl)
            } else if self.cmd == "csk-propagation1-complete" {
                kss.keyset.propagation1_complete(RollType::CskRoll, ttl)
            } else if self.cmd == "csk-propagation2-complete" {
                kss.keyset.propagation2_complete(RollType::CskRoll, ttl)
            } else if self.cmd == "algorithm-propagation1-complete" {
                kss.keyset
                    .propagation1_complete(RollType::AlgorithmRoll, ttl)
            } else if self.cmd == "algorithm-propagation2-complete" {
                kss.keyset
                    .propagation2_complete(RollType::AlgorithmRoll, ttl)
            } else {
                unreachable!();
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
        } else if self.cmd == "ksk-cache-expired1"
            || self.cmd == "ksk-cache-expired2"
            || self.cmd == "zsk-cache-expired1"
            || self.cmd == "zsk-cache-expired2"
            || self.cmd == "csk-cache-expired1"
            || self.cmd == "csk-cache-expired2"
            || self.cmd == "algorithm-cache-expired1"
            || self.cmd == "algorithm-cache-expired2"
        {
            let actions = if self.cmd == "ksk-cache-expired1" {
                kss.keyset.cache_expired1(RollType::KskRoll)
            } else if self.cmd == "ksk-cache-expired2" {
                kss.keyset.cache_expired2(RollType::KskRoll)
            } else if self.cmd == "zsk-cache-expired1" {
                kss.keyset.cache_expired1(RollType::ZskRoll)
            } else if self.cmd == "zsk-cache-expired2" {
                kss.keyset.cache_expired2(RollType::ZskRoll)
            } else if self.cmd == "csk-cache-expired1" {
                kss.keyset.cache_expired1(RollType::CskRoll)
            } else if self.cmd == "csk-cache-expired2" {
                kss.keyset.cache_expired2(RollType::CskRoll)
            } else if self.cmd == "algorithm-cache-expired1" {
                kss.keyset.cache_expired1(RollType::AlgorithmRoll)
            } else if self.cmd == "algorithm-cache-expired2" {
                kss.keyset.cache_expired2(RollType::AlgorithmRoll)
            } else {
                unreachable!();
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
        } else if self.cmd == "ksk-roll-done"
            || self.cmd == "zsk-roll-done"
            || self.cmd == "csk-roll-done"
            || self.cmd == "algorithm-roll-done"
        {
            let actions = if self.cmd == "ksk-roll-done" {
                kss.keyset.roll_done(RollType::KskRoll)
            } else if self.cmd == "zsk-roll-done" {
                kss.keyset.roll_done(RollType::ZskRoll)
            } else if self.cmd == "csk-roll-done" {
                kss.keyset.roll_done(RollType::CskRoll)
            } else if self.cmd == "algorithm-roll-done" {
                kss.keyset.roll_done(RollType::AlgorithmRoll)
            } else {
                unreachable!();
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
        } else if self.cmd == "status" {
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
        } else if self.cmd == "actions" {
            for roll in kss.keyset.rollstates().keys() {
                let actions = kss.keyset.actions(roll.clone());
                println!("{roll:?} actions:");
                for a in actions {
                    println!("\t{a:?}");
                }
            }
        } else if self.cmd == "keys" {
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
        } else if self.cmd == "get-use-csk" {
            println!("{}", ksc.use_csk);
        } else if self.cmd == "set-use-csk" {
            let arg = self.value_or()?;
            ksc.use_csk = arg
                .parse()
                .map_err::<Error, _>(|_| format!("unable to parse as boolean: {arg}\n").into())?;
            config_changed = true;
        } else if self.cmd == "get-autoremove" {
            println!("{}", ksc.autoremove);
        } else if self.cmd == "set-autoremove" {
            let arg = self.value_or()?;
            ksc.autoremove = arg
                .parse()
                .map_err::<Error, _>(|_| format!("unable to parse as boolean: {arg}\n").into())?;
            config_changed = true;
        } else if self.cmd == "get-ksk-algorithm" {
            println!("{}", ksc.ksk_generate_params);
        } else if self.cmd == "set-ksk-algorithm" {
            let arg = self.value_or()?;
            ksc.ksk_generate_params = KeyParameters::new(&arg, self.bits)?;
            config_changed = true;
        } else if self.cmd == "get-zsk-algorithm" {
            println!("{}", ksc.zsk_generate_params);
        } else if self.cmd == "set-zsk-algorithm" {
            let arg = self.value_or()?;
            ksc.zsk_generate_params = KeyParameters::new(&arg, self.bits)?;
            config_changed = true;
        } else if self.cmd == "get-csk-algorithm" {
            println!("{}", ksc.csk_generate_params);
        } else if self.cmd == "set-csk-algorithm" {
            let arg = self.value_or()?;
            ksc.csk_generate_params = KeyParameters::new(&arg, self.bits)?;
            config_changed = true;
        } else if self.cmd == "get-ds-algorithm" {
            println!("{}", ksc.ds_algorithm);
        } else if self.cmd == "set-ds-algorithm" {
            let arg = self.value_or()?;
            ksc.ds_algorithm = DsAlgorithm::new(&arg)?;
            config_changed = true;
        } else if self.cmd == "set-dnskey-inception-offset" {
            ksc.dnskey_inception_offset = self.parse_duration_from_opt()?;
            config_changed = true;
        } else if self.cmd == "get-dnskey-lifetime" {
            let span = Span::try_from(ksc.dnskey_signature_lifetime).expect("should not fail");
            let signeddur = span
                .to_duration(SpanRelativeTo::days_are_24_hours())
                .expect("should not fail");
            println!("{signeddur:#}");
        } else if self.cmd == "set-dnskey-lifetime" {
            ksc.dnskey_signature_lifetime = self.parse_duration_from_opt()?;
            config_changed = true;
        } else if self.cmd == "set-dnskey-remain-time" {
            ksc.dnskey_remain_time = self.parse_duration_from_opt()?;
            config_changed = true;
        } else if self.cmd == "set-cds-inception-offset" {
            ksc.cds_inception_offset = self.parse_duration_from_opt()?;
            config_changed = true;
        } else if self.cmd == "get-cds-lifetime" {
            let span = Span::try_from(ksc.cds_signature_lifetime).expect("should not fail");
            let signeddur = span
                .to_duration(SpanRelativeTo::days_are_24_hours())
                .expect("should not fail");
            println!("{signeddur:#}");
        } else if self.cmd == "set-cds-lifetime" {
            ksc.cds_signature_lifetime = self.parse_duration_from_opt()?;
            config_changed = true;
        } else if self.cmd == "set-cds-remain-time" {
            ksc.cds_remain_time = self.parse_duration_from_opt()?;
            config_changed = true;
        } else if self.cmd == "set-ksk-validity" {
            ksc.ksk_validity = self.parse_opt_duration_from_opt()?;
            config_changed = true;
        } else if self.cmd == "set-zsk-validity" {
            ksc.zsk_validity = self.parse_opt_duration_from_opt()?;
            config_changed = true;
        } else if self.cmd == "set-csk-validity" {
            ksc.csk_validity = self.parse_opt_duration_from_opt()?;
            config_changed = true;
        } else if self.cmd == "show" {
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
        } else if self.cmd == "get-dnskey" {
            for r in &kss.dnskey_rrset {
                println!("{r}");
            }
        } else if self.cmd == "get-cds" {
            for r in &kss.cds_rrset {
                println!("{r}");
            }
        } else if self.cmd == "get-ds" {
            for r in &kss.ds_rrset {
                println!("{r}");
            }
        } else if self.cmd.starts_with("kmip-") {
            config_changed = self.handle_kmip_command(&mut ksc)?;
        } else if self.cmd == "cron" {
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
        } else {
            return Err(format!("unknown subcommand {}\n", self.cmd).into());
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

    fn handle_kmip_command(&mut self, ksc: &mut KeySetConfig) -> Result<bool, Error> {
        let mut config_changed = false;

        match self.cmd.as_str() {
            "kmip-add-server" => {
                if self.values.len() != 2 {
                    return Err(
                        "Usage: kmip-add-server <id> [user[:pass]@]ip_or_fqdn[:port]".into(),
                    );
                };

                let id = self.values[0].clone();
                let settings = parse_kmip_server(&self.values[1])?;
                ksc.kmip_servers.insert(id.clone(), settings);
                if ksc.kmip_servers.len() == 1 {
                    ksc.default_kmip_server = Some(id);
                }
                config_changed = true;
            }

            "kmip-remove-server" => {
                let id = self.value_or()?;
                let _ = get_kmip_server_conn_settings(&id, ksc)?;
                if ksc.default_kmip_server.as_ref() == Some(&id) {
                    return Err(format!(
                        "KMIP server index {id} cannot be removed as it is the current default"
                    )
                    .into());
                }
                let _ = ksc.kmip_servers.remove(&id);
                config_changed = true;
            }

            "kmip-set-server-insecure" => {
                if self.values.len() != 2 {
                    return Err("Usage: kmip-set-server-insecure <server id> <true|false>".into());
                };
                let conn_settings = get_kmip_server_conn_settings(&self.values[0], ksc)?;
                let insecure = match self.values[1].as_str() {
                    "true" => true,
                    "false" => false,
                    _ => {
                        return Err(
                            "Usage: kmip-set-server-insecure <server index> <true|false>".into(),
                        )
                    }
                };
                conn_settings.server_insecure = insecure;
                config_changed = true;
            }

            "kmip-set-client-cert" => {
                if self.values.len() != 3 {
                    return Err(
                        "Usage: kmip-set-client-cert <server index> <cert path> <key path>".into(),
                    );
                };
                let conn_settings = get_kmip_server_conn_settings(&self.values[0], ksc)?;
                conn_settings.client_cert_path =
                    Some(PathBuf::from_str(self.values[1].as_str()).unwrap());
                conn_settings.client_key_path =
                    Some(PathBuf::from_str(self.values[2].as_str()).unwrap());
                config_changed = true;
            }

            "kmip-set-default-server" => {
                let id = self.value_or()?;
                let _ = get_kmip_server_conn_settings(&id, ksc)?;
                ksc.default_kmip_server = Some(id);
                config_changed = true;
            }

            "kmip-unset-default-server" => {
                ksc.default_kmip_server = None;
                config_changed = true;
            }

            "kmip-get-default-server" => match &ksc.default_kmip_server {
                Some(id) => println!("Default KMIP server name: {id}"),
                None => println!("No default KMIP server set, keys will NOT be crated using KMIP"),
            },

            "kmip-get-server" => {
                let id = self.value_or()?;
                dbg!(get_kmip_server_conn_settings(&id, ksc)?);
            }

            "kmip-get-servers" => {
                dbg!(&ksc.kmip_servers);
            }

            cmd => return Err(format!("unknown subcommand {cmd}").into()),
        }

        Ok(config_changed)
    }
}

// Returns true if the config has been changed.
fn get_kmip_server_conn_settings<'a>(
    id: &str,
    ksc: &'a mut KeySetConfig,
) -> Result<&'a mut KmipServerConnectionSettings, Error> {
    if ksc.kmip_servers.is_empty() {
        return Err(format!("No KMIP servers are configured.").into());
    }

    Ok(ksc
        .kmip_servers
        .get_mut(id)
        .ok_or_else(|| format!("KMIP server id '{id}' is not known"))?)
}

fn parse_kmip_server(input: &str) -> Result<KmipServerConnectionSettings, Error> {
    // input should be of the form: [user[:pass]@]ip_or_fqdn[:port]
    let (addr, port, user, pass) = match input.split_once('@') {
        Some((user_pass, rest)) => {
            let (user, pass) = parse_user_pass(user_pass)?;
            let (addr, port) = parse_addr_port(rest)?;
            (addr, port, Some(user), pass)
        }
        None => {
            let (addr, port) = parse_addr_port(input)?;
            (addr, port, None, None)
        }
    };

    let mut settings = KmipServerConnectionSettings::default();
    settings.server_addr = addr;
    settings.server_port = port;
    settings.server_username = user;
    settings.server_password = pass;

    Ok(settings)
}

fn parse_user_pass(input: &str) -> Result<(String, Option<String>), Error> {
    // input should be of the form: user[:pass]
    match input.split_once(':') {
        Some((user, pass)) => Ok((user.to_string(), Some(pass.to_string()))),
        None => Ok((input.to_string(), None)),
    }
}

fn parse_addr_port(input: &str) -> Result<(String, u16), Error> {
    // input should be of the form: ip_or_fqdn[:port]
    match input.split_once(':') {
        Some((ip_or_fqdn, port)) => Ok((
            ip_or_fqdn.to_string(),
            port.parse::<u16>()
                .map_err(|err| format!("{port} is not a valid port number: {err}"))?,
        )),
        None => Ok((input.to_string(), 5696)),
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

    /// KMIP servers to use, keyed by user chosen HSM id.
    kmip_servers: HashMap<String, KmipServerConnectionSettings>,

    /// Which KMIP server should new keys be created in, if any?
    #[serde(skip_serializing_if = "Option::is_none", default)]
    default_kmip_server: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KmipServerConnectionSettings {
    /// Path to the client certificate file in PEM format
    #[serde(skip_serializing_if = "Option::is_none", default)]
    client_cert_path: Option<PathBuf>,

    /// Path to the client certificate key file in PEM format
    #[serde(skip_serializing_if = "Option::is_none", default)]
    client_key_path: Option<PathBuf>,

    /// Path to the client certificate and key file in PKCS#12 format
    #[serde(skip_serializing_if = "Option::is_none", default)]
    client_pkcs12_path: Option<PathBuf>,

    /// Disable secure checks (e.g. verification of the server certificate)
    #[serde(default)]
    server_insecure: bool,

    /// Path to the server certificate file in PEM format
    #[serde(skip_serializing_if = "Option::is_none", default)]
    server_cert_path: Option<PathBuf>,

    /// Path to the server CA certificate file in PEM format
    #[serde(skip_serializing_if = "Option::is_none", default)]
    ca_cert_path: Option<PathBuf>,

    /// IP address, hostname or FQDN of the KMIP server
    server_addr: String,

    /// The TCP port number on which the KMIP server listens
    server_port: u16,

    /// The user name to authenticate with the KMIP server
    #[serde(skip_serializing_if = "Option::is_none", default)]
    server_username: Option<String>,

    /// The password to authenticate with the KMIP server
    #[serde(skip_serializing_if = "Option::is_none", default)]
    server_password: Option<String>,
}

impl Default for KmipServerConnectionSettings {
    fn default() -> Self {
        Self {
            server_addr: "localhost".into(),
            server_port: 5696,
            server_insecure: false,
            client_cert_path: None,
            client_key_path: None,
            client_pkcs12_path: None,
            server_cert_path: None,
            ca_cert_path: None,
            server_username: None,
            server_password: None,
        }
    }
}

impl From<KmipServerConnectionSettings> for ConnectionSettings {
    fn from(cfg: KmipServerConnectionSettings) -> Self {
        let client_cert = load_client_cert(&cfg).unwrap();
        let server_cert = if let Some(p) = cfg.server_cert_path {
            Some(load_binary_file(&p).unwrap())
        } else {
            None
        };
        let ca_cert = if let Some(p) = cfg.ca_cert_path {
            Some(load_binary_file(&p).unwrap())
        } else {
            None
        };
        ConnectionSettings {
            host: cfg.server_addr,
            port: cfg.server_port,
            username: cfg.server_username,
            password: cfg.server_password,
            insecure: cfg.server_insecure,
            client_cert,
            server_cert,
            ca_cert,
            connect_timeout: None,    // TODO
            read_timeout: None,       // TODO
            write_timeout: None,      // TODO
            max_response_bytes: None, // TODO
        }
    }
}

fn load_client_cert(
    opt: &KmipServerConnectionSettings,
) -> Result<Option<ClientCertificate>, Error> {
    let client_cert = {
        match (
            &opt.client_cert_path,
            &opt.client_key_path,
            &opt.client_pkcs12_path,
        ) {
            (None, None, None) => None,
            (None, None, Some(path)) => Some(ClientCertificate::CombinedPkcs12 {
                cert_bytes: load_binary_file(path)?,
            }),
            (Some(path), None, None) => Some(ClientCertificate::SeparatePem {
                cert_bytes: load_binary_file(path)?,
                key_bytes: None,
            }),
            (None, Some(_), None) => {
                return Err(
                    "Client certificate key path requires a client certificate path".into(),
                );
            }
            (_, Some(_), Some(_)) | (Some(_), _, Some(_)) => {
                return Err("Use either but not both of: client certificate and key PEM file paths, or a PCKS#12 certficate file path".into());
            }
            (Some(cert_path), Some(key_path), None) => Some(ClientCertificate::SeparatePem {
                cert_bytes: load_binary_file(cert_path)?,
                key_bytes: Some(load_binary_file(key_path)?),
            }),
        }
    };
    Ok(client_cert)
}

pub fn load_binary_file(path: &Path) -> Result<Vec<u8>, Error> {
    use std::{fs::File, io::Read};

    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;

    Ok(bytes)
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
#[derive(Debug, Deserialize, Serialize)]
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
    kmip_server_id: &Option<String>,
    kmip_conn_pool: &Option<KmipConnPool>,
) -> Result<(Url, Url, SecurityAlgorithm, u16), Error> {
    // Generate the key.
    // TODO: Attempt repeated generation to avoid key tag collisions.
    // TODO: Add a high-level operation in 'domain' to select flags?
    let flags = if make_ksk { 257 } else { 256 };
    let mut retries = MAX_KEY_TAG_TRIES;

    if let (Some(kmip_server_id), Some(kmip_conn_pool)) = (kmip_server_id, kmip_conn_pool) {
        let (key_pair, dnskey) = loop {
            // TODO: Fortanix DSM rejects attempts to create keys by names
            // that are already taken. Should we be able to detect that case
            // specifically and try again with a different name? Should we add
            // a random element to each name? Should we keep track of used
            // names and detect a collision ourselves when choosing a name?
            // Is their some natural differentiator that can be used to name
            // keys uniquely other than zone name?
            let suffix = match make_ksk {
                true => "_ksk",
                false => "_zsk",
            };
            let key_pair = kmip::sign::generate(
                format!("{}{suffix}", name.fmt_with_dot()),
                algorithm.clone(),
                flags,
                kmip_conn_pool.clone(),
            )
            .map_err::<Error, _>(|e| format!("KMIP key generation failed: {e}\n").into())?;

            let dnskey = key_pair.dnskey().map_err(|err| {
                Error::new(&format!(
                    "Unable to determine DNSKEY for newly generated signing key: {err}"
                ))
            })?;

            if !keys.iter().any(|(_, k)| k.key_tag() == dnskey.key_tag()) {
                break (key_pair, dnskey);
            }
            if retries <= 1 {
                return Err("unable to generate key with unique key tag".into());
            }
            retries -= 1;
        };

        // Define the KMIP URI to have the form:
        // TODO: Do we need to encode identity information about the HSM in the URI too?
        // TODO: Move KMIP URL construction into domain?
        // We have to store the algorithm because the DNSSEC algorithm (e.g. 5
        // and 7) don't necessarily correspond to the cryptographic algorithm
        // of the key known to the HSM.
        //   kmip://<hsm_id>/keys/<key_id>?algorithm=<algorithm>&flags=<flags>
        let algorithm = dnskey.algorithm();
        let public_key_url = format!(
            "kmip://{kmip_server_id}/keys/{}?algorithm={algorithm}&flags={flags}",
            key_pair.public_key_id()
        );
        let secret_key_url = format!(
            "kmip://{kmip_server_id}/keys/{}?algorithm={algorithm}&flags={flags}",
            key_pair.private_key_id()
        );

        let public_key_url = Url::parse(&public_key_url).map_err::<Error, _>(|e| {
            format!("unable to parse {public_key_url} as URL: {e}").into()
        })?;
        let secret_key_url = Url::parse(&secret_key_url).map_err::<Error, _>(|e| {
            format!("unable to parse {secret_key_url} as URL: {e}").into()
        })?;

        Ok((
            public_key_url,
            secret_key_url,
            key_pair.algorithm(),
            dnskey.key_tag(),
        ))
    } else {
        let (secret_key, public_key, key_tag) = loop {
            let (secret_key, public_key) = domain::crypto::sign::generate(algorithm.clone(), flags)
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

        let secret_key_url = Url::parse(&secret_key_url).map_err::<Error, _>(|e| {
            format!("unable to parse {secret_key_url} as URL: {e}").into()
        })?;
        let public_key_url = Url::parse(&public_key_url).map_err::<Error, _>(|e| {
            format!("unable to parse {public_key_url} as URL: {e}").into()
        })?;
        Ok((public_key_url, secret_key_url, algorithm, key_tag))
    }
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
            if pub_url.scheme() == "file" {
                dbg!("before open");
                let path = pub_url.path();
                let filename = env.in_cwd(&path);
                let mut file = File::open(&filename).map_err::<Error, _>(|e| {
                    format!(
                        "update_dnskey_rrset: unable to open public key file {}: {e}",
                        filename.display()
                    )
                    .into()
                })?;
                let zonefile = domain::zonefile::inplace::Zonefile::load(&mut file)
                    .map_err::<Error, _>(|e| {
                        format!("unable load zone from file {}: {e}", filename.display()).into()
                    })?;
                dbg!("after open");
                for entry in zonefile {
                    let entry = entry.map_err::<Error, _>(|e| {
                        format!("bad entry in key file {k}: {e}\n").into()
                    })?;

                    // We only care about records in a zonefile
                    let Entry::Record(record) = entry else {
                        continue;
                    };

                    // Of the records that we see, we only care about DNSKEY records
                    let ScannedRecordData::Dnskey(dnskey) = record.data() else {
                        continue;
                    };

                    // TODO: Limit class to IN?
                    // TODO: TTL should be determined elsewhere, not taken from the file.
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
            } else if pub_url.scheme() == "kmip" {
                let (public_key_id, algorithm, flags, conn_settings) =
                    parse_kmip_key_url(ksc, &pub_url)?;
                let kmip_conn_pool = kmip_create_conn_pool(conn_settings.into())?;
                let dnskey = kmip_get_dnskey(public_key_id, algorithm, flags, kmip_conn_pool)?;
                let owner = kss.keyset.name().clone().flatten_into();
                let record = Record::new(owner, Class::IN, Ttl::from_days(1), dnskey.convert());
                dnskeys.push(record);
            } else {
                panic!("unsupported scheme in {pub_url}");
            };
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
            let pub_url = Url::parse(k).expect("valid URL expected");
            let signing_key = match (priv_url.scheme(), pub_url.scheme()) {
                ("file", "file") => {
                    let private_data = std::fs::read_to_string(priv_url.path())
                        .map_err::<Error, _>(|e| {
                            format!("unable read from file {}: {e}", priv_url.path()).into()
                        })?;
                    let secret_key = SecretKeyBytes::parse_from_bind(&private_data)
                        .map_err::<Error, _>(|e| {
                            format!("unable to parse private key file {privref}: {e}").into()
                        })?;
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
                            format!("private key {privref} and public key {k} do not match: {e}")
                                .into()
                        })?;
                    SigningKey::new(
                        public_key.owner().clone(),
                        public_key.data().flags(),
                        key_pair,
                    )
                }

                ("kmip", "kmip") => {
                    let owner = kss.keyset.name().clone().flatten_into();
                    kmip_signing_key_from_urls(ksc, owner, priv_url, pub_url)?
                }

                (priv_scheme, pub_scheme) => {
                    panic!("unsupported URL scheme combination: {priv_scheme} & {pub_scheme}");
                }
            };

            // TODO: Should there be a key not found error we can detect here so that we can retry if
            // we believe that the key is simply not registered fully yet in the HSM?
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

fn kmip_signing_key_from_urls(
    ksc: &KeySetConfig,
    owner: Name<Bytes>,
    priv_url: Url,
    pub_url: Url,
) -> Result<SigningKey<Bytes, KeyPair>, Error> {
    let (private_key_id, algorithm1, flags1, conn_settings1) = parse_kmip_key_url(ksc, &priv_url)?;
    let (public_key_id, algorithm2, flags2, conn_settings2) = parse_kmip_key_url(ksc, &pub_url)?;

    assert_eq!(algorithm1, algorithm2);
    assert_eq!(flags1, flags2);
    assert_eq!(conn_settings1, conn_settings2);

    let kmip_conn_pool = kmip_create_conn_pool(conn_settings1.into())?;

    let key_pair = KeyPair::Kmip(
        kmip::sign::KeyPair::new(
            algorithm1,
            flags1,
            &private_key_id,
            &public_key_id,
            kmip_conn_pool,
        )
        .map_err(|err| format!("{err}"))?,
    );

    Ok(SigningKey::new(owner, flags1, key_pair))
}

fn kmip_create_conn_pool(conn_settings: Arc<ConnectionSettings>) -> Result<KmipConnPool, Error> {
    let kmip_conn_pool = ConnectionManager::create_connection_pool(
        conn_settings,
        1,
        Some(Duration::from_secs(60)),
        Some(Duration::from_secs(60)),
    )
    .map_err(|err| format!("Failed to create KMIP connection pool: {err}"))?;
    Ok(kmip_conn_pool)
}

fn kmip_get_dnskey(
    public_key_id: String,
    algorithm: SecurityAlgorithm,
    flags: u16,
    kmip_conn_pool: KmipConnPool,
) -> Result<Dnskey<Vec<u8>>, Error> {
    let public_key = kmip::PublicKey::new(public_key_id, algorithm, kmip_conn_pool);
    let mut retries = 3;
    let dnskey = loop {
        match public_key.dnskey(flags) {
            Ok(dnskey) => break dnskey,
            Err(err) if retries == 0 => {
                Err(format!(
                    "Error while trying to determine KMIP dnskey: {err}"
                ))?;
                tokio::task::spawn_blocking(|| {
                    std::thread::sleep(Duration::from_secs(3));
                });
            }
            Err(_) => retries -= 1,
        }
    };
    Ok(dnskey)
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
            match pub_url.scheme() {
                "file" => {
                    let path = pub_url.path();
                    let filename = env.in_cwd(&path);
                    let mut file = File::open(&filename).map_err::<Error, _>(|e| {
                        format!(
                            "create_cds_rrset: unable to open public key file {}: {e}",
                            filename.display()
                        )
                        .into()
                    })?;
                    let zonefile = domain::zonefile::inplace::Zonefile::load(&mut file)
                        .map_err::<Error, _>(|e| {
                            format!("unable to read zone from file {}: {e}", filename.display())
                                .into()
                        })?;
                    for entry in zonefile {
                        let entry = entry.map_err::<Error, _>(|e| {
                            format!("bad entry in key file {k}: {e}\n").into()
                        })?;

                        // We only care about records in a zonefile
                        let Entry::Record(record) = entry else {
                            continue;
                        };

                        create_cds_rrset_helper(
                            digest_alg,
                            &mut cds_list,
                            &mut cdnskey_list,
                            record.flatten_into(),
                        )?;
                    }
                }

                "kmip" => {
                    let (public_key_id, algorithm, flags, conn_settings) =
                        parse_kmip_key_url(ksc, &pub_url)?;
                    let kmip_conn_pool = kmip_create_conn_pool(conn_settings.into())?;
                    let dnskey = kmip_get_dnskey(public_key_id, algorithm, flags, kmip_conn_pool)?;
                    let dnskey = ZoneRecordData::Dnskey(dnskey.convert());
                    let owner = kss.keyset.name().clone().flatten_into();
                    let record = Record::new(owner, Class::IN, Ttl::from_days(1), dnskey);
                    create_cds_rrset_helper(digest_alg, &mut cds_list, &mut cdnskey_list, record)?;
                }

                _ => panic!("unsupported scheme in {pub_url}"),
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
            let pub_url = Url::parse(k).expect("valid URL expected");
            let signing_key = match (priv_url.scheme(), pub_url.scheme()) {
                ("file", "file") => {
                    let path = priv_url.path();
                    let filename = env.in_cwd(&path);
                    let private_data =
                        std::fs::read_to_string(&filename).map_err::<Error, _>(|e| {
                            format!(
                                "unable to read from private key file {}: {e}",
                                filename.display()
                            )
                            .into()
                        })?;
                    let secret_key = SecretKeyBytes::parse_from_bind(&private_data)
                        .map_err::<Error, _>(|e| {
                            format!(
                                "unable to parse private key file {}: {e}",
                                filename.display()
                            )
                            .into()
                        })?;
                    let path = pub_url.path();
                    let filename = env.in_cwd(&path);
                    let public_data =
                        std::fs::read_to_string(&filename).map_err::<Error, _>(|e| {
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
                            format!("private key {privref} and public key {k} do not match: {e}")
                                .into()
                        })?;
                    SigningKey::new(
                        public_key.owner().clone(),
                        public_key.data().flags(),
                        key_pair,
                    )
                }

                ("kmip", "kmip") => {
                    let owner = kss.keyset.name().clone().flatten_into();
                    kmip_signing_key_from_urls(ksc, owner, priv_url, pub_url)?
                }

                (priv_scheme, pub_scheme) => {
                    panic!("unsupported URL scheme combination: {priv_scheme} & {pub_scheme}");
                }
            };
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

fn parse_kmip_key_url(
    ksc: &KeySetConfig,
    kmip_key_url: &Url,
) -> Result<(String, SecurityAlgorithm, u16, ConnectionSettings), Error> {
    let id = kmip_key_url.host_str().unwrap().to_string();

    // Lookup KMIP server connection details
    let Some(srv) = ksc.kmip_servers.get(&id) else {
        return Err(format!("No KMIP server configured with id {id}").into());
    };

    let mut conn_settings = ConnectionSettings::from(srv.clone());

    // TODO: Move username and password to the key config, and out of the
    // URLs.
    if let Some(username) = &srv.server_username {
        conn_settings.username = Some(username.clone());
    }
    if let Some(password) = &srv.server_password {
        conn_settings.password = Some(password.clone());
    }

    let url_path = kmip_key_url.path().to_string();
    let (keys, key_id) = url_path.strip_prefix('/').unwrap().split_once('/').unwrap();
    assert_eq!(keys, "keys");
    let key_id = key_id.to_string();
    let mut flags = None;
    let mut algorithm = None;
    for (k, v) in kmip_key_url.query_pairs() {
        match &*k {
            "flags" => flags = Some(v.parse::<u16>().unwrap()),
            "algorithm" => algorithm = Some(SecurityAlgorithm::from_str(&*v).unwrap()),
            _ => { /* ignore unknown URL query parameter */ }
        }
    }
    let flags = flags.unwrap();
    let algorithm = algorithm.unwrap();
    Ok((key_id, algorithm, flags, conn_settings))
}

fn create_cds_rrset_helper(
    digest_alg: DigestAlgorithm,
    cds_list: &mut Vec<Record<Name<Bytes>, Cds<Vec<u8>>>>,
    cdnskey_list: &mut Vec<Record<Name<Bytes>, Cdnskey<Vec<u8>>>>,
    record: Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>,
) -> Result<(), Error> {
    let owner = record.owner().clone();
    let ZoneRecordData::Dnskey(dnskey) = record.data() else {
        return Ok(());
    };
    let dnskey: Dnskey<Vec<u8>> = dnskey.clone().convert();
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
        .map_err::<Error, _>(|e| format!("error creating digest for DNSKEY record: {e}").into())?;
    let cds = Cds::new(key_tag, sec_alg, digest_alg, digest.as_ref().to_vec())
        .expect("Infallible because the digest won't be too long since it's a valid digest");
    let cds_record = Record::new(owner, record.class(), record.ttl(), cds);
    cds_list.push(cds_record);
    Ok(())
}

fn remove_cds_rrset(kss: &mut KeySetState) {
    kss.cds_rrset.truncate(0);
}

fn update_ds_rrset(
    ksc: &KeySetConfig,
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
            match pub_url.scheme() {
                "file" => {
                    let path = pub_url.path();
                    let filename = env.in_cwd(&path);
                    let mut file = File::open(&filename).map_err::<Error, _>(|e| {
                        format!(
                            "update_ds_rrset: unable to open public key file {}: {e}",
                            filename.display()
                        )
                        .into()
                    })?;
                    let zonefile = domain::zonefile::inplace::Zonefile::load(&mut file)
                        .map_err::<Error, _>(|e| {
                            format!("unable to read zone from file {}: {e}", filename.display())
                                .into()
                        })?;
                    for entry in zonefile {
                        let entry = entry.map_err::<Error, _>(|e| {
                            format!("bad entry in key file {k}: {e}\n").into()
                        })?;

                        // We only care about records in a zonefile
                        let Entry::Record(record) = entry else {
                            continue;
                        };

                        // Of the records that we see, we only care about DNSKEY records
                        let ScannedRecordData::Dnskey(dnskey) = record.data() else {
                            continue;
                        };

                        let digest = dnskey
                            .digest(&record.owner(), digest_alg)
                            .map_err::<Error, _>(|e| {
                                format!("error creating digest for DNSKEY record: {e}").into()
                            })?;

                        let ds = Ds::new(dnskey.key_tag(), dnskey.algorithm(), digest_alg, digest.as_ref().to_vec()).expect(
                            "Infallible because the digest won't be too long since it's a valid digest",
                        );

                        let ds_record = Record::new(
                            record.owner().clone().flatten_into(),
                            record.class(),
                            record.ttl(),
                            ds,
                        );

                        ds_list.push(ds_record);
                    }
                }

                "kmip" => {
                    let (public_key_id, algorithm, flags, conn_settings) =
                        parse_kmip_key_url(ksc, &pub_url)?;
                    let kmip_conn_pool = kmip_create_conn_pool(conn_settings.into())?;
                    let dnskey = kmip_get_dnskey(public_key_id, algorithm, flags, kmip_conn_pool)?;
                    let owner: Name<Bytes> = kss.keyset.name().clone().flatten_into();
                    let record =
                        Record::new(owner.clone(), Class::IN, Ttl::from_days(1), dnskey.clone());

                    let digest = dnskey
                        .digest(&record.owner(), digest_alg)
                        .map_err::<Error, _>(|e| {
                            format!("error creating digest for DNSKEY record: {e}").into()
                        })?;

                    let ds = Ds::new(
                        dnskey.key_tag(),
                        dnskey.algorithm(),
                        digest_alg,
                        digest.as_ref().to_vec(),
                    )
                    .expect(
                        "Infallible because the digest won't be too long since it's a valid digest",
                    );

                    let ds_record = Record::new(owner, record.class(), record.ttl(), ds);

                    ds_list.push(ds_record);
                }

                _ => panic!("unsupported scheme in {pub_url}"),
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
                update_ds_rrset(ksc, kss, ksc.ds_algorithm.to_digest_algorithm(), env)?
            }
            Action::UpdateRrsig => (),
            Action::ReportDnskeyPropagated => (),
            Action::ReportDsPropagated => (),
            Action::ReportRrsigPropagated => (),
            Action::WaitDnskeyPropagated => (),
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

fn sig_renew(dnskey_rrset: &[String], remain_time: &Duration) -> bool {
    let mut zonefile = Zonefile::new();
    for r in dnskey_rrset {
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
