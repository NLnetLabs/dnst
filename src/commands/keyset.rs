use crate::env::Env;
use crate::error::Error;
use crate::util;
use bytes::Bytes;
use domain::base::iana::Class;
use domain::base::iana::DigestAlgorithm;
use domain::base::zonefile_fmt::DisplayKind;
use domain::base::zonefile_fmt::ZonefileFmt;
use domain::base::Name;
use domain::base::Record;
use domain::base::ToName;
use domain::base::Ttl;
use domain::crypto::sign;
use domain::crypto::sign::GenerateParams;
use domain::crypto::sign::KeyPair;
use domain::crypto::sign::SecretKeyBytes;
use domain::dnssec::common::display_as_bind;
use domain::dnssec::common::parse_from_bind;
use domain::dnssec::sign::keys::keyset::Action;
use domain::dnssec::sign::keys::keyset::Key;
use domain::dnssec::sign::keys::keyset::KeySet;
use domain::dnssec::sign::keys::keyset::KeyType;
use domain::dnssec::sign::keys::keyset::RollType;
use domain::dnssec::sign::keys::keyset::UnixTime;
use domain::dnssec::sign::keys::SigningKey;
use domain::dnssec::sign::records::Rrset;
use domain::dnssec::sign::signatures::rrsigs::sign_rrset;
use domain::dnssec::validator::base::DnskeyExt;
use domain::rdata::dnssec::Timestamp;
use domain::rdata::Cdnskey;
use domain::rdata::Cds;
use domain::rdata::Ds;
use domain::rdata::ZoneRecordData;
use domain::zonefile::inplace::Zonefile;
use domain::zonefile::inplace::{Entry, ScannedRecordData};
use jiff::Span;
use jiff::SpanRelativeTo;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fmt::Formatter;
use std::fs::remove_file;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

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

    value: Option<String>,
}

impl Keyset {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(self.run(&env))
    }

    /// Run the command as an async function
    pub async fn run(self, env: &impl Env) -> Result<(), Error> {
        if self.cmd == "create" {
            let domainname = self
                .domain_name
                .ok_or::<Error>("domain name option expected\n".into())?;
            let state_file = self
                .keyset_state
                .ok_or::<Error>("state file option expected\n".into())?;
            let ks = KeySet::new(domainname);
            let kss = KeySetState {
                keyset: ks,
                dnskey_rrset: Vec::new(),
                ds_rrset: Vec::new(),
                cds_rrset: Vec::new(),
                ns_rrset: Vec::new(),
            };
            const ONE_DAY: u64 = 86400;
            const FOUR_WEEKS: u64 = 2419200;
            let ksc = KeySetConfig {
                state_file: state_file.clone(),
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
            let mut file = File::create(state_file)?;
            write!(file, "{json}")?;

            let json = serde_json::to_string_pretty(&ksc).expect("should not fail");
            let mut file = File::create(self.keyset_conf)?;
            write!(file, "{json}")?;
            return Ok(());
        }

        let file = File::open(self.keyset_conf.clone())?;
        let mut ksc: KeySetConfig = serde_json::from_reader(file).map_err::<Error, _>(|e| {
            format!("error loading {:?}: {e}\n", self.keyset_conf).into()
        })?;
        let file = File::open(ksc.state_file.clone())?;
        let mut kss: KeySetState = serde_json::from_reader(file)
            .map_err::<Error, _>(|e| format!("error loading {:?}: {e}\n", ksc.state_file).into())?;

        let mut config_changed = false;
        let mut state_changed = false;

        if self.cmd == "init" {
            // Check for re-init.
            if !kss.keyset.keys().is_empty() {
                // Avoid re-init.
                return Err("already initialized\n".into());
            }

            // Check for CSK.
            let actions = if ksc.use_csk {
                // Generate CSK.
                let (csk_pub_name, csk_priv_name) = new_keys(
                    kss.keyset.name(),
                    ksc.csk_generate_params.to_generate_params(),
                    true,
                    env,
                )?;
                kss.keyset
                    .add_key_csk(csk_pub_name.clone(), Some(csk_priv_name), UnixTime::now())
                    .expect("should not happen");

                kss.keyset
                    .start_roll(RollType::CskRoll, &[], &[&csk_pub_name])
                    .expect("should not happen")
            } else {
                let (ksk_pub_name, ksk_priv_name) = new_keys(
                    kss.keyset.name(),
                    ksc.ksk_generate_params.to_generate_params(),
                    true,
                    env,
                )?;
                kss.keyset
                    .add_key_ksk(ksk_pub_name.clone(), Some(ksk_priv_name), UnixTime::now())
                    .expect("should not happen");
                let (zsk_pub_name, zsk_priv_name) = new_keys(
                    kss.keyset.name(),
                    ksc.zsk_generate_params.to_generate_params(),
                    false,
                    env,
                )?;
                kss.keyset
                    .add_key_zsk(zsk_pub_name.clone(), Some(zsk_priv_name), UnixTime::now())
                    .expect("should not happen");

                let new = [ksk_pub_name.as_ref(), zsk_pub_name.as_ref()];
                kss.keyset
                    .start_roll(RollType::CskRoll, &[], &new)
                    .expect("should not happen")
            };

            handle_actions(&actions, &ksc, &mut kss, env)?;

            print_actions(&actions);
            state_changed = true;
        } else if self.cmd == "start-ksk-roll" {
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
                .filter(|(_, key)| matches!(key.keytype(), KeyType::Ksk(_)))
                .map(|(name, _)| name.clone())
                .collect();
            let old: Vec<_> = old_stored.iter().map(|name| name.as_ref()).collect();

            // Collect algorithms. Maybe this needs to be in the library.

            // Create a new KSK
            let (ksk_pub_name, ksk_priv_name) = new_keys(
                kss.keyset.name(),
                ksc.ksk_generate_params.to_generate_params(),
                true,
                env,
            )?;
            kss.keyset
                .add_key_ksk(
                    ksk_pub_name.clone(),
                    Some(ksk_priv_name.clone()),
                    UnixTime::now(),
                )
                .map_err::<Error, _>(|e| {
                    format!("unable to add KSK {ksk_pub_name}: {e}\n").into()
                })?;

            let new = [ksk_pub_name.as_ref()];

            // Start the key roll
            let actions = match kss
                .keyset
                .start_roll(RollType::KskRoll, &old, &new)
                .map_err::<Error, _>(|e| format!("cannot start roll: {e}\n").into())
            {
                Ok(actions) => actions,
                Err(e) => {
                    // Remove the key files we just created.
                    remove_file(ksk_priv_name.clone()).map_err::<Error, _>(|e| {
                        format!("unable to remove private key file {ksk_priv_name}: {e}\n").into()
                    })?;
                    remove_file(ksk_pub_name.clone()).map_err::<Error, _>(|e| {
                        format!("unable to remove public key file {ksk_pub_name}: {e}\n").into()
                    })?;
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
                    KeyType::Ksk(_) => true,
                    KeyType::Zsk(_) => true,
                    KeyType::Csk(_, _) => true,
                    KeyType::Include(_) => false,
                })
                .map(|(name, _)| name.clone())
                .collect();
            let old: Vec<_> = old_stored.iter().map(|name| name.as_ref()).collect();

            // Collect algorithms. Maybe this needs to be in the library.

            let (new_stored, new_files) = if ksc.use_csk {
                let mut new_files = Vec::new();

                // Create a new CSK
                let (csk_pub_name, csk_priv_name) = new_keys(
                    kss.keyset.name(),
                    ksc.csk_generate_params.to_generate_params(),
                    true,
                    env,
                )?;
                new_files.push(csk_priv_name.clone());
                new_files.push(csk_pub_name.clone());
                kss.keyset
                    .add_key_csk(
                        csk_pub_name.clone(),
                        Some(csk_priv_name.clone()),
                        UnixTime::now(),
                    )
                    .map_err::<Error, _>(|e| {
                        format!("unable to add CSK {csk_pub_name}: {e}\n").into()
                    })?;

                let new = vec![csk_pub_name];
                (new, new_files)
            } else {
                let mut new_files = Vec::new();

                // Create a new KSK
                let (ksk_pub_name, ksk_priv_name) = new_keys(
                    kss.keyset.name(),
                    ksc.ksk_generate_params.to_generate_params(),
                    true,
                    env,
                )?;
                new_files.push(ksk_priv_name.clone());
                new_files.push(ksk_pub_name.clone());
                kss.keyset
                    .add_key_ksk(
                        ksk_pub_name.clone(),
                        Some(ksk_priv_name.clone()),
                        UnixTime::now(),
                    )
                    .map_err::<Error, _>(|e| {
                        format!("unable to add KSK {ksk_pub_name}: {e}\n").into()
                    })?;

                // Create a new ZSK
                let (zsk_pub_name, zsk_priv_name) = new_keys(
                    kss.keyset.name(),
                    ksc.zsk_generate_params.to_generate_params(),
                    false,
                    env,
                )?;
                new_files.push(zsk_priv_name.clone());
                new_files.push(zsk_pub_name.clone());
                kss.keyset
                    .add_key_zsk(
                        zsk_pub_name.clone(),
                        Some(zsk_priv_name.clone()),
                        UnixTime::now(),
                    )
                    .map_err::<Error, _>(|e| {
                        format!("unable to add ZSK {zsk_pub_name}: {e}\n").into()
                    })?;

                let new = vec![ksk_pub_name, zsk_pub_name];
                (new, new_files)
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
                    for f in new_files {
                        remove_file(&f).map_err::<Error, _>(|e| {
                            format!("unable to private key file {f}: {e}\n").into()
                        })?;
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
        {
            let actions = if self.cmd == "ksk-roll-done" {
                kss.keyset.roll_done(RollType::KskRoll)
            } else if self.cmd == "zsk-roll-done" {
                kss.keyset.roll_done(RollType::ZskRoll)
            } else if self.cmd == "csk-roll-done" {
                kss.keyset.roll_done(RollType::CskRoll)
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
                println!("\t\tType: {keytype}");
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
            let arg = self.value.ok_or::<Error>("argument expected\n".into())?;
            ksc.use_csk = arg
                .parse()
                .map_err::<Error, _>(|_| format!("unable to parse as boolean: {arg}\n").into())?;
            config_changed = true;
        } else if self.cmd == "get-autoremove" {
            println!("{}", ksc.autoremove);
        } else if self.cmd == "set-autoremove" {
            let arg = self.value.ok_or::<Error>("argument expected\n".into())?;
            ksc.autoremove = arg
                .parse()
                .map_err::<Error, _>(|_| format!("unable to parse as boolean: {arg}\n").into())?;
            config_changed = true;
        } else if self.cmd == "get-ksk-algorithm" {
            println!("{}", ksc.ksk_generate_params);
        } else if self.cmd == "set-ksk-algorithm" {
            let arg = self.value.ok_or::<Error>("argument expected\n".into())?;
            ksc.ksk_generate_params = KeyParameters::new(&arg, self.bits)?;
            config_changed = true;
        } else if self.cmd == "get-zsk-algorithm" {
            println!("{}", ksc.zsk_generate_params);
        } else if self.cmd == "set-zsk-algorithm" {
            let arg = self.value.ok_or::<Error>("argument expected\n".into())?;
            ksc.zsk_generate_params = KeyParameters::new(&arg, self.bits)?;
            config_changed = true;
        } else if self.cmd == "get-csk-algorithm" {
            println!("{}", ksc.csk_generate_params);
        } else if self.cmd == "set-csk-algorithm" {
            let arg = self.value.ok_or::<Error>("argument expected\n".into())?;
            ksc.csk_generate_params = KeyParameters::new(&arg, self.bits)?;
            config_changed = true;
        } else if self.cmd == "get-ds-algorithm" {
            println!("{}", ksc.ds_algorithm);
        } else if self.cmd == "set-ds-algorithm" {
            let arg = self.value.ok_or::<Error>("argument expected\n".into())?;
            ksc.ds_algorithm = DsAlgorithm::new(&arg)?;
            config_changed = true;
        } else if self.cmd == "set-dnskey-inception-offset" {
            ksc.dnskey_inception_offset = parse_duration_from_opt(&self.value)?;
            config_changed = true;
        } else if self.cmd == "get-dnskey-lifetime" {
            let span = Span::try_from(ksc.dnskey_signature_lifetime).expect("should not fail");
            let signeddur = span
                .to_jiff_duration(SpanRelativeTo::days_are_24_hours())
                .expect("should not fail");
            println!("{signeddur:#}");
        } else if self.cmd == "set-dnskey-lifetime" {
            ksc.dnskey_signature_lifetime = parse_duration_from_opt(&self.value)?;
            config_changed = true;
        } else if self.cmd == "set-dnskey-remain-time" {
            ksc.dnskey_remain_time = parse_duration_from_opt(&self.value)?;
            config_changed = true;
        } else if self.cmd == "set-cds-inception-offset" {
            ksc.cds_inception_offset = parse_duration_from_opt(&self.value)?;
            config_changed = true;
        } else if self.cmd == "get-cds-lifetime" {
            let span = Span::try_from(ksc.cds_signature_lifetime).expect("should not fail");
            let signeddur = span
                .to_jiff_duration(SpanRelativeTo::days_are_24_hours())
                .expect("should not fail");
            println!("{signeddur:#}");
        } else if self.cmd == "set-cds-lifetime" {
            ksc.cds_signature_lifetime = parse_duration_from_opt(&self.value)?;
            config_changed = true;
        } else if self.cmd == "set-cds-remain-time" {
            ksc.cds_remain_time = parse_duration_from_opt(&self.value)?;
            config_changed = true;
        } else if self.cmd == "set-ksk-validity" {
            ksc.ksk_validity = parse_opt_duration_from_opt(&self.value)?;
            config_changed = true;
        } else if self.cmd == "set-zsk-validity" {
            ksc.zsk_validity = parse_opt_duration_from_opt(&self.value)?;
            config_changed = true;
        } else if self.cmd == "set-csk-validity" {
            ksc.csk_validity = parse_opt_duration_from_opt(&self.value)?;
            config_changed = true;
        } else if self.cmd == "show" {
            println!("state-file: {:?}", ksc.state_file);
            println!("use-csk: {}", ksc.use_csk);
            println!("ksk-generate-params: {}", ksc.ksk_generate_params);
            println!("zsk-generate-params: {}", ksc.zsk_generate_params);
            println!("csk-generate-params: {}", ksc.csk_generate_params);
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
        if config_changed {
            let json = serde_json::to_string_pretty(&ksc).expect("should not fail");
            let mut file = File::create(self.keyset_conf)?;
            write!(file, "{json}")?;
        }
        if state_changed {
            let json = serde_json::to_string_pretty(&kss).expect("should not fail");
            let mut file = File::create(ksc.state_file)?;
            write!(file, "{json}")?;
        }
        Ok(())
    }
}

/// Config for the keyset command.
#[derive(Deserialize, Serialize)]
struct KeySetConfig {
    state_file: PathBuf,

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

    dnskey_rrset: Vec<String>,
    ds_rrset: Vec<String>,
    cds_rrset: Vec<String>,
    ns_rrset: Vec<String>,
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
    env: &impl Env,
) -> Result<(String, String), Error> {
    // Generate the key.
    // TODO: Attempt repeated generation to avoid key tag collisions.
    // TODO: Add a high-level operation in 'domain' to select flags?
    let flags = if make_ksk { 257 } else { 256 };
    let (secret_key, public_key) = sign::generate(algorithm, flags)
        .map_err::<Error, _>(|e| format!("key generation failed: {e}\n").into())?;
    let public_key = Record::new(name.clone(), Class::IN, Ttl::ZERO, public_key);

    let base = format!(
        "K{}+{:03}+{:05}",
        name.fmt_with_dot(),
        public_key.data().algorithm().to_int(),
        public_key.data().key_tag()
    );

    let secret_key_path = format!("{base}.private");
    let public_key_path = format!("{base}.key");

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

    Ok((public_key_path, secret_key_path))
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

        if present {
            let mut file = File::open(env.in_cwd(&k))?;
            let zonefile = domain::zonefile::inplace::Zonefile::load(&mut file)?;
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
            let private_data = std::fs::read_to_string(privref)?;
            let secret_key =
                SecretKeyBytes::parse_from_bind(&private_data).map_err::<Error, _>(|e| {
                    format!("unable to parse private key file {privref}: {e}").into()
                })?;
            let public_data = std::fs::read_to_string(k)?;
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
            let mut file = File::open(env.in_cwd(&k))?;
            let zonefile = domain::zonefile::inplace::Zonefile::load(&mut file)?;
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
            let private_data = std::fs::read_to_string(privref)?;
            let secret_key =
                SecretKeyBytes::parse_from_bind(&private_data).map_err::<Error, _>(|e| {
                    format!("unable to parse private key file {privref}: {e}").into()
                })?;
            let public_data = std::fs::read_to_string(k)?;
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
            let mut file = File::open(env.in_cwd(&k))?;
            let zonefile = domain::zonefile::inplace::Zonefile::load(&mut file)?;
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

fn parse_duration_from_opt(value: &Option<String>) -> Result<Duration, Error> {
    let arg = value
        .as_ref()
        .ok_or::<Error>("argument expected\n".into())?;
    let span: Span = arg
        .parse()
        .map_err::<Error, _>(|e| format!("unable to parse {arg} as lifetime: {e}\n").into())?;
    let signeddur = span
        .to_jiff_duration(SpanRelativeTo::days_are_24_hours())
        .map_err::<Error, _>(|e| format!("unable to convert duration: {e}\n").into())?;
    Duration::try_from(signeddur).map_err(|e| format!("unable to convert duration: {e}\n").into())
}

fn parse_opt_duration_from_opt(value: &Option<String>) -> Result<Option<Duration>, Error> {
    if let Some(value) = value {
        if value == "off" {
            return Ok(None);
        }
    }
    let duration = parse_duration_from_opt(value)?;
    Ok(Some(duration))
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
