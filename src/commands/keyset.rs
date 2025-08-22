use std::cmp::min;
use std::collections::HashMap;
use std::convert::From;
use std::fmt::{Debug, Display, Formatter};
use std::fs::{remove_file, File, OpenOptions};
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write};
use std::ops::Not;
use std::path::{absolute, Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;

use bytes::Bytes;
use clap::Subcommand;
use domain::base::iana::Class;
use domain::base::iana::{DigestAlgorithm, SecurityAlgorithm};
use domain::base::name::{FlattenInto, ToLabelIter};
use domain::base::zonefile_fmt::{DisplayKind, ZonefileFmt};
use domain::base::{Name, NameBuilder, Record, ToName, Ttl};
use domain::crypto::kmip::{self, ClientCertificate, ConnectionSettings, KeyUrl};
use domain::crypto::sign::{GenerateParams, KeyPair, SecretKeyBytes, SignRaw};
use domain::dep::kmip::client::pool::{ConnectionManager, KmipConnError, SyncConnPool};
use domain::dnssec::common::{display_as_bind, parse_from_bind};
use domain::dnssec::sign::keys::keyset::{Action, Key, KeySet, KeyType, RollType, UnixTime};
use domain::dnssec::sign::keys::SigningKey;
use domain::dnssec::sign::records::Rrset;
use domain::dnssec::sign::signatures::rrsigs::sign_rrset;
use domain::dnssec::validator::base::DnskeyExt;
use domain::rdata::dnssec::Timestamp;
use domain::rdata::{Cdnskey, Cds, Dnskey, Ds, ZoneRecordData};
use domain::utils::base32::encode_string_hex;
use domain::zonefile::inplace::Zonefile;
use domain::zonefile::inplace::{Entry, ScannedRecordData};
use jiff::{Span, SpanRelativeTo};
use serde::{Deserialize, Serialize};
use tracing::warn;
use url::Url;

use crate::env::Env;
use crate::error::Error;
use crate::util;

const MAX_KEY_TAG_TRIES: u8 = 10;

/// The default TCP port on which to connect to a KMIP server as defined by
/// IANA.
const DEF_KMIP_PORT: u16 = 5696;

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

#[allow(clippy::large_enum_variant)]
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

    Get {
        #[command(subcommand)]
        subcommand: GetCommands,
    },

    Set {
        #[command(subcommand)]
        subcommand: SetCommands,
    },

    Show,
    Cron,
    Kmip {
        #[command(subcommand)]
        subcommand: KmipCommands,
    },
}

#[derive(Clone, Debug, Subcommand)]
enum GetCommands {
    UseCsk,
    Autoremove,
    KskAlgorithm,
    ZskAlgorithm,
    CskAlgorithm,
    DsAlgorithm,
    DnskeyLifetime,
    CdsLifetime,
    Dnskey,
    Cds,
    Ds,
}

#[derive(Clone, Debug, Subcommand)]
enum SetCommands {
    UseCsk {
        #[arg(action = clap::ArgAction::Set)]
        boolean: bool,
    },
    Autoremove {
        #[arg(action = clap::ArgAction::Set)]
        boolean: bool,
    },
    KskAlgorithm {
        #[arg(short = 'b')]
        bits: Option<usize>,

        algorithm: String,
    },
    ZskAlgorithm {
        #[arg(short = 'b')]
        bits: Option<usize>,

        algorithm: String,
    },
    CskAlgorithm {
        #[arg(short = 'b')]
        bits: Option<usize>,

        algorithm: String,
    },
    DsAlgorithm {
        #[arg(value_parser = DsAlgorithm::new)]
        algorithm: DsAlgorithm,
    },
    DnskeyInceptionOffset {
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    DnskeyLifetime {
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    DnskeyRemainTime {
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    CdsInceptionOffset {
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    CdsLifetime {
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    CdsRemainTime {
        #[arg(value_parser = parse_duration)]
        duration: Duration,
    },
    KskValidity {
        #[arg(value_parser = parse_opt_duration)]
        opt_duration: OptDuration,
    },
    ZskValidity {
        #[arg(value_parser = parse_opt_duration)]
        opt_duration: OptDuration,
    },
    CskValidity {
        #[arg(value_parser = parse_opt_duration)]
        opt_duration: OptDuration,
    },
}

/// Commands for configuring the use of KMIP compatible HSMs for key
/// generation and signing instead of or in addition to using and Ring/OpenSSL
/// based key generation and signing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Subcommand)]
enum KmipCommands {
    /// Disable use of KMIP for generating new keys.
    ///
    /// Existing KMIP keys will still work as normal, but any new keys will
    /// be generated using Ring/OpenSSL whether or not KMIP servers are
    /// configured.
    ///
    /// To re-enable KMIP use: kmip set-default-server.
    Disable,

    /// Add a KMIP server to use for key generation & signing.
    ///
    /// If this is the first KMIP server to be configured it will be used to
    /// generate new keys instead of using Ring/OpenSSL based key generation.
    ///
    /// If this is NOT the first KMIP server to be configured, the new server
    /// will NOT be used to generate keys unless configured to do so by
    /// using: kmip set-default-server.
    AddServer {
        /// An identifier to refer to the KMIP server by.
        ///
        /// This identifier is used in KMIP key URLs. The identifier serves
        /// several purposes:
        ///
        /// 1. To make it easy at a glance to recognize which KMIP server a
        ///    given key was created on, by allowing operators to assign a
        ///    meaningful name to the server instead of whatever identity
        ///    strings the server associates with itself or by using hostnames
        ///    or IP addresses as identifiers.
        ///
        /// 2. To refer to additional configuration elsewhere to avoid
        ///    including sensitive and/or verbose KMIP server credential or
        ///    TLS client certificate/key authentication data in the URL,
        ///    and which would be repeated in every key created on the same
        ///    server.
        ///
        /// 3. To allow the actual location of the server and/or its access
        ///    credentials to be rotated without affecting the key URLs, e.g.
        ///    if a server is assigned a new IP address or if access
        ///    credentials change.
        ///
        /// The downside of this is that consumers of the key URL must also
        /// possess the additional configuration settings and be able to fetch
        /// them based on the same server identifier.
        server_id: String,

        /// The hostname or IP address of the KMIP server.
        ip_host_or_fqdn: String,

        /// TCP port to connect to the KMIP server on.
        #[arg(help_heading = "Server", long = "port", default_value_t = DEF_KMIP_PORT)]
        port: u16,

        /// Optional path to a JSON file to read/write username/password credentials from/to.
        ///
        /// The format of the file (at the time of writing) is like so:
        ///     {
        ///         "server_id": {
        ///             "username": "xxxx",
        ///             "password": "yyyy",
        ///         }
        ///         [, "another_server_id": { ... }]
        ///     }
        #[arg(help_heading = "Client Credentials", long = "credential-store")]
        credentials_store_path: Option<PathBuf>,

        /// Optional username to authenticate to the KMIP server as.
        #[arg(
            help_heading = "Client Credentials",
            long = "username",
            requires = "credentials_store_path"
        )]
        username: Option<String>,

        /// Optional password to authenticate to the KMIP server with.
        #[arg(
            help_heading = "Client Credentials",
            long = "password",
            requires = "username"
        )]
        password: Option<String>,

        /// Optional path to a TLS certificate to authenticate to the KMIP
        /// server with.
        #[arg(
            help_heading = "Client Certificate Authentication",
            long = "client-cert",
            requires = "client_key_path"
        )]
        client_cert_path: Option<PathBuf>,

        /// Optional path to a private key for client certificate
        /// authentication.
        ///
        /// The private key is needed to be able to prove to the KMIP server
        /// that you are the owner of the provided TLS client certificate.
        #[arg(
            help_heading = "Client Certificate Authentication",
            long = "client-key",
            requires = "client_cert_path"
        )]
        client_key_path: Option<PathBuf>,

        /// Whether or not to accept the KMIP server TLS certificate without
        /// verifying it.
        ///
        /// Set to false if using a self-signed TLS certificate, e.g. in a
        /// test environment.
        #[arg(help_heading = "Server Certificate Verification", long = "insecure", default_value_t = false, action = clap::ArgAction::SetTrue)]
        insecure: bool,

        /// Optional path to a TLS PEM certificate for the server.
        #[arg(help_heading = "Server Certificate Verification", long = "server-cert")]
        server_cert_path: Option<PathBuf>,

        /// Optional path to a TLS PEM certificate for a Certificate Authority.
        #[arg(help_heading = "Server Certificate Verification", long = "ca-cert")]
        ca_cert_path: Option<PathBuf>,

        /// TCP connect timeout.
        #[arg(help_heading = "Client Limits", long = "connect-timeout", value_parser = parse_duration, default_value = "10s")]
        connect_timeout: Duration,

        /// TCP response read timeout.
        #[arg(help_heading = "Client Limits", long = "read-timeout", value_parser = parse_duration, default_value = "10s")]
        read_timeout: Duration,

        /// TCP request write timeout.
        #[arg(help_heading = "Client Limits", long = "write-timeout", value_parser = parse_duration, default_value = "10s")]
        write_timeout: Duration,

        /// Maximum KMIP response size to accept (in bytes).
        #[arg(
            help_heading = "Client Limits",
            long = "max-response-bytes",
            default_value_t = 8192
        )]
        max_response_bytes: u32,

        /// Optional user supplied key label prefix.
        ///
        /// Can be used to denote the s/w that created the key, and/or to
        /// indicate which installation/environment it belongs to, e.g. dev,
        /// test, prod, etc.
        #[arg(help_heading = "Key Labels", long = "key-label-prefix")]
        key_label_prefix: Option<String>,

        /// Maximum label length (in bytes) permitted by the HSM.
        #[arg(
            help_heading = "Key Labels",
            long = "key-label-max-bytes",
            default_value_t = 32
        )]
        key_label_max_bytes: u8,
    },

    /// Modify an existing KMIP server configuration.
    ModifyServer {
        /// The identifier of the KMIP server.
        server_id: String,

        /// Modify the hostname or IP address of the KMIP server.
        #[arg(help_heading = "Server", long = "address")]
        ip_host_or_fqdn: Option<String>,

        /// Modify the TCP port to connect to the KMIP server on.
        #[arg(help_heading = "Server", long = "port")]
        port: Option<u16>,

        /// Disable use of username / password authentication.
        ///
        /// Note: This will remove any credentials from the credential-store
        /// for this server id.
        #[arg(help_heading = "Client Credentials", long = "no-credentials", action = clap::ArgAction::SetTrue)]
        no_credentials: bool,

        /// Modify the path to a JSON file to read/write username/password
        /// credentials from/to.
        #[arg(help_heading = "Client Credentials", long = "credential-store")]
        credentials_store_path: Option<PathBuf>,

        /// Modifyt the username to authenticate to the KMIP server as.
        #[arg(help_heading = "Client Credentials", long = "username")]
        username: Option<String>,

        /// Modify the password to authenticate to the KMIP server with.
        #[arg(help_heading = "Client Credentials", long = "password")]
        password: Option<String>,

        /// Disable use of TLS client certificate authentication.
        #[arg(help_heading = "Client Certificate Authentication", long = "no-client-auth", action = clap::ArgAction::SetTrue)]
        no_client_auth: bool,

        /// Modify the path to the TLS certificate to authenticate to the KMIP
        /// server with.
        #[arg(
            help_heading = "Client Certificate Authentication",
            long = "client-cert"
        )]
        client_cert_path: Option<PathBuf>,

        /// Modify the path to the private key for client certificate
        /// authentication.
        #[arg(
            help_heading = "Client Certificate Authentication",
            long = "client-key"
        )]
        client_key_path: Option<PathBuf>,

        /// Modify whether or not to accept the KMIP server TLS certificate
        /// without verifying it.
        #[arg(help_heading = "Server Certificate Verification", long = "insecure")]
        insecure: Option<bool>,

        /// Modify the path to a TLS PEM certificate for the server.
        #[arg(help_heading = "Server Certificate Verification", long = "server-cert")]
        server_cert_path: Option<PathBuf>,

        /// Optional path to a TLS PEM certificate for a Certificate Authority.
        #[arg(help_heading = "Server Certificate Verification", long = "ca-cert")]
        ca_cert_path: Option<PathBuf>,

        /// Modify the TCP connect timeout.
        #[arg(help_heading = "Client Limits", long = "connect-timeout", value_parser = parse_duration)]
        connect_timeout: Option<Duration>,

        /// Modify the TCP response read timeout.
        #[arg(help_heading = "Client Limits", long = "read-timeout", value_parser = parse_duration)]
        read_timeout: Option<Duration>,

        /// Modify the TCP request write timeout.
        #[arg(help_heading = "Client Limits", long = "write-timeout", value_parser = parse_duration)]
        write_timeout: Option<Duration>,

        /// Modify the maximum KMIP response size to accept (in bytes).
        #[arg(help_heading = "Client Limits", long = "max-response-bytes")]
        max_response_bytes: Option<u32>,

        /// Optional user supplied key label prefix.
        ///
        /// Can be used to denote the s/w that created the key, and/or to
        /// indicate which installation/environment it belongs to, e.g. dev,
        /// test, prod, etc.
        #[arg(help_heading = "Key Labels", long = "key-label-prefix")]
        key_label_prefix: Option<String>,

        /// Maximum label length (in bytes) permitted by the HSM.
        #[arg(help_heading = "Key Labels", long = "key-label-max-bytes")]
        key_label_max_bytes: Option<u8>,
    },

    /// Remove an existing non-default KMIP server.
    ///
    /// To remove the default KMIP server use `kmip disable` first.
    RemoveServer {
        /// The identifier of the KMIP server to remove.
        server_id: String,
    },

    /// Set the default KMIP server to use for key generation.
    SetDefaultServer {
        /// The identifier of the KMIP server to use as the default.
        server_id: String,
    },

    /// Get the details of an existing KMIP server.
    GetServer {
        /// The identifier of the KMIP server to get.
        server_id: String,
    },

    /// List all configured KMIP servers.
    ListServers,
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
                kmip: Default::default(),
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
            Commands::Create { .. } => unreachable!(),
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
                        &mut kss.kmip,
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
                        &mut kss.kmip,
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
                        &mut kss.kmip,
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
                    &mut kss.kmip,
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
                        remove_key(&mut kss.kmip, ksk_priv_url)?;
                        remove_key(&mut kss.kmip, ksk_pub_url)?;
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
                    &mut kss.kmip,
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
                        remove_key(&mut kss.kmip, zsk_priv_url)?;
                        remove_key(&mut kss.kmip, zsk_pub_url)?;
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
                        &mut kss.kmip,
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
                        &mut kss.kmip,
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
                        &mut kss.kmip,
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
                            remove_key(&mut kss.kmip, u)?;
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
                        &mut kss.kmip,
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
                        &mut kss.kmip,
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
                        &mut kss.kmip,
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
                            remove_key(&mut kss.kmip, u)?;
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
                    let key_urls: Vec<_> = kss
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
                    if !key_urls.is_empty() {
                        print!("Removing:");
                        for u in key_urls {
                            let (pubref, privkey) = &u;
                            print!(" {pubref}");
                            kss.keyset.delete_key(pubref).map_err::<Error, _>(|e| {
                                format!("unable to remove key {pubref}: {e}\n").into()
                            })?;

                            if let Some(privkey) = privkey {
                                let priv_url = Url::parse(privkey).map_err::<Error, _>(|e| {
                                    format!("unable to parse {privkey} as URL: {e}").into()
                                })?;
                                remove_key(&mut kss.kmip, priv_url)?;
                            }

                            let pub_url = Url::parse(pubref).map_err::<Error, _>(|e| {
                                format!("unable to parse {pubref} as URL: {e}").into()
                            })?;
                            remove_key(&mut kss.kmip, pub_url)?;
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
            Commands::Get { subcommand } => get_command(subcommand, &ksc, &kss),
            Commands::Set { subcommand } => set_command(subcommand, &mut ksc, &mut config_changed)?,
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
            Commands::Kmip { subcommand } => {
                state_changed = kmip_command(env, subcommand, &mut kss)?;
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

fn remove_key(kmip: &mut KmipState, url: Url) -> Result<(), Error> {
    match url.scheme() {
        "file" => {
            remove_file(url.path()).map_err::<Error, _>(|e| {
                format!("unable to remove key file {}: {e}\n", url.path()).into()
            })?;
        }

        "kmip" => {
            let key_url = KeyUrl::try_from(url)?;
            let conn = kmip.get_pool(key_url.server_id())?.get()?;
            conn.destroy_key(key_url.key_id())
                .map_err(|e| format!("unable to remove key {key_url}: {e}"))?;
        }

        _ => {
            panic!("Unsupported URL scheme while removing key {url}");
        }
    }

    Ok(())
}

fn get_command(cmd: GetCommands, ksc: &KeySetConfig, kss: &KeySetState) {
    match cmd {
        GetCommands::UseCsk => {
            println!("{}", ksc.use_csk);
        }
        GetCommands::Autoremove => {
            println!("{}", ksc.autoremove);
        }
        GetCommands::KskAlgorithm => {
            println!("{}", ksc.ksk_generate_params);
        }
        GetCommands::ZskAlgorithm => {
            println!("{}", ksc.zsk_generate_params);
        }
        GetCommands::CskAlgorithm => {
            println!("{}", ksc.csk_generate_params);
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
        SetCommands::KskAlgorithm { algorithm, bits } => {
            ksc.ksk_generate_params = KeyParameters::new(&algorithm, bits)?;
        }
        SetCommands::ZskAlgorithm { algorithm, bits } => {
            ksc.zsk_generate_params = KeyParameters::new(&algorithm, bits)?;
        }
        SetCommands::CskAlgorithm { algorithm, bits } => {
            ksc.csk_generate_params = KeyParameters::new(&algorithm, bits)?;
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

fn kmip_command(env: &impl Env, cmd: KmipCommands, kss: &mut KeySetState) -> Result<bool, Error> {
    match cmd {
        KmipCommands::Disable => {
            kss.kmip.default_server_id = None;
        }

        KmipCommands::AddServer {
            server_id,
            ip_host_or_fqdn,
            port,
            credentials_store_path,
            username,
            password,
            client_cert_path,
            client_key_path,
            insecure,
            server_cert_path,
            ca_cert_path,
            connect_timeout,
            read_timeout,
            write_timeout,
            max_response_bytes,
            key_label_prefix,
            key_label_max_bytes,
        } => {
            // Handle only the valid cases. Let Clap reject the invalid cases
            // with a helpful error message, e.g. password without username is
            // not allowed.
            let credentials = match (credentials_store_path, username, password) {
                (Some(credentials_store_path), Some(username), password) => {
                    Some(KmipClientCredentialArgs {
                        credentials_store_path,
                        credentials: Some(KmipClientCredentials { username, password }),
                    })
                }
                (Some(credentials_store_path), _, _) => Some(KmipClientCredentialArgs {
                    credentials_store_path,
                    credentials: None,
                }),
                _ => None,
            };

            let client_auth = match (client_cert_path, client_key_path) {
                (Some(cert_path), Some(private_key_path)) => {
                    Some(KmipClientTlsCertificateAuthConfig {
                        cert_path,
                        private_key_path,
                    })
                }
                _ => None,
            };

            let server_auth = KmipServerTlsCertificateVerificationConfig {
                verify_certificate: insecure.not(),
                server_cert_path,
                ca_cert_path,
            };

            let limits = KmipClientLimits {
                connect_timeout,
                read_timeout,
                write_timeout,
                max_response_bytes,
            };

            let key_label_cfg = KeyLabelConfig {
                max_label_bytes: key_label_max_bytes,
                supports_relabeling: true,
                prefix: key_label_prefix.unwrap_or_default(),
            };

            add_kmip_server(
                &mut kss.kmip,
                server_id,
                ip_host_or_fqdn,
                port,
                credentials,
                client_auth,
                server_auth,
                limits,
                key_label_cfg,
            )?;
        }

        KmipCommands::ModifyServer {
            server_id,
            ip_host_or_fqdn,
            port,
            no_credentials,
            credentials_store_path,
            username,
            password,
            no_client_auth,
            client_cert_path,
            client_key_path,
            insecure,
            server_cert_path,
            ca_cert_path,
            connect_timeout,
            read_timeout,
            write_timeout,
            max_response_bytes,
            key_label_prefix,
            key_label_max_bytes,
        } => {
            let mut crl_credentials_store_path = ChangeRemoveLeave::Leave;
            let mut crl_username = ChangeRemoveLeave::Leave;
            let mut crl_password = ChangeRemoveLeave::Leave;
            let mut crl_client_cert_path = ChangeRemoveLeave::Leave;
            let mut crl_client_key_path = ChangeRemoveLeave::Leave;
            let mut crl_server_cert_path = ChangeRemoveLeave::Leave;
            let mut crl_ca_cert_path = ChangeRemoveLeave::Leave;

            if no_credentials {
                crl_credentials_store_path = ChangeRemoveLeave::Remove;
                crl_username = ChangeRemoveLeave::Remove;
                crl_password = ChangeRemoveLeave::Remove;
            } else {
                if let Some(v) = credentials_store_path {
                    crl_credentials_store_path = ChangeRemoveLeave::Change(v);
                }
                if let Some(v) = username {
                    crl_username = ChangeRemoveLeave::Change(v);
                }
                if let Some(v) = password {
                    crl_password = ChangeRemoveLeave::Change(v);
                }
            }

            if no_client_auth {
                crl_client_cert_path = ChangeRemoveLeave::Remove;
                crl_client_key_path = ChangeRemoveLeave::Remove;
            } else {
                if let Some(v) = client_cert_path {
                    crl_client_cert_path = ChangeRemoveLeave::Change(v);
                }
                if let Some(v) = client_key_path {
                    crl_client_key_path = ChangeRemoveLeave::Change(v);
                }
            }

            if let Some(v) = server_cert_path {
                crl_server_cert_path = ChangeRemoveLeave::Change(v);
            }
            if let Some(v) = ca_cert_path {
                crl_ca_cert_path = ChangeRemoveLeave::Change(v);
            }

            modify_kmip_server(
                &mut kss.kmip,
                &server_id,
                ip_host_or_fqdn,
                port,
                crl_credentials_store_path,
                crl_username,
                crl_password,
                crl_client_cert_path,
                crl_client_key_path,
                insecure,
                crl_server_cert_path,
                crl_ca_cert_path,
                connect_timeout,
                read_timeout,
                write_timeout,
                max_response_bytes,
                key_label_prefix,
                key_label_max_bytes,
            )
            .map_err(|err| {
                Error::new(&format!(
                    "unable to modify configuration for KMIP server '{server_id}': {err}"
                ))
            })?;
        }

        KmipCommands::RemoveServer { server_id } => {
            remove_kmip_server(kss, server_id)?;
        }

        KmipCommands::SetDefaultServer { server_id } => {
            if !kss.kmip.servers.contains_key(&server_id) {
                return Err(format!("KMIP server id '{server_id}' is not known").into());
            }
            kss.kmip.default_server_id = Some(server_id);
        }

        KmipCommands::GetServer { server_id } => {
            let Some(server) = kss.kmip.servers.get(&server_id) else {
                return Err(format!("KMIP server id '{server_id}' is not known").into());
            };

            write!(env.stdout(), "{server}");

            return Ok(false);
        }

        KmipCommands::ListServers => {
            write!(env.stdout(), "{}", &kss.kmip);
            return Ok(false);
        }
    }

    Ok(true)
}

/// Remove a KMIP server and its credentials.
///
/// Removes the specified KMIP server from the configuration, and any
/// associated referenced credentials.
///
/// Returns an error if:
///   - The KMIP server is the current default.
///   - The KMIP server is in use by any known keys.
///   - A referenced credentials file could not be updated to remove
///     credentials for the server being removed.
fn remove_kmip_server(kss: &mut KeySetState, server_id: String) -> Result<(), Error> {
    if kss.kmip.default_server_id.as_ref() == Some(&server_id) {
        return Err(format!(
            "KMIP server '{server_id}' cannot be removed as it is the current default. Use kmip disable first."
        )
        .into());
    }

    if kss.keyset.keys().iter().any(|(key_url_str, _)| {
        if let Ok(url) = Url::parse(key_url_str) {
            if let Ok(key_url) = KeyUrl::try_from(url) {
                if key_url.server_id() == server_id {
                    return true;
                }
            }
        }
        false
    }) {
        return Err(format!(
            "KMIP server '{server_id}' cannot be removed as there are still keys using it."
        )
        .into());
    }

    let removed = kss.kmip.servers.remove(&server_id);

    if let Some(credentials_path) = removed.and_then(|s| s.client_credentials_path) {
        let _ = remove_kmip_client_credentials(&server_id, &credentials_path)?;
    }

    Ok(())
}

fn remove_kmip_client_credentials(
    server_id: &str,
    credentials_path: &Path,
) -> Result<KmipClientCredentials, Error> {
    let mut credentials_file =
        KmipClientCredentialsFile::new(credentials_path, KmipServerCredentialsFileMode::ReadWrite)?;

    let removed_creds = credentials_file.remove(server_id).ok_or(Error::new(&format!("unable to remove credentials for KMIP server '{server_id}' from credentials file {}: server id does not exist in the file", credentials_path.display())))?;

    credentials_file.save()?;

    if credentials_file.is_empty() {
        drop(credentials_file);
        std::fs::remove_file(credentials_path).map_err(|e| {
            Error::new(&format!(
                "unable to remove empty credentials file {} for KMIP server '{server_id}': {e}",
                credentials_path.display(),
            ))
        })?;
    }

    Ok(removed_creds)
}

/// Adds a KMIP server to the configured set.
///
/// Sensitive credentials must be referenced from separate files, we do not
/// allow them to be stored directly in the main configuration.
///
/// To make it easier for users to store username/password credentials we
/// support writing them to the JSON file for the user using credentials
/// specified on the command line. We also support reading from a pre-existing
/// JSON credentials file, assuming a user was able to create one by hand.
///
/// The format of the file (at the time of writing) is like so:
///
/// {
///     "server_id": {
///         "username": "xxxx",
///         "password": "yyyy",
///     }
/// }
///
/// Note: We do not (yet?) support protection against accidental leakage of
/// secrets in memory (e.g. via the secrecy crate) because the secrecy crate
/// SecretBox type cannot be cloned, thus would have to be both read from disk
/// for every request, and doing so would need to be supported all the way/
/// down to the KMIP message wire serialization in the kmip-protocol crate,
/// plus the crate explicitly warns against creating a Serde Serialize impl
/// for SecretBox'd data and so requires you to manually impl that yourself.
#[allow(clippy::too_many_arguments)]
fn add_kmip_server(
    kmip: &mut KmipState,
    server_id: String,
    ip_host_or_fqdn: String,
    port: u16,
    credentials: Option<KmipClientCredentialArgs>,
    client_cert_auth: Option<KmipClientTlsCertificateAuthConfig>,
    server_cert_verification: KmipServerTlsCertificateVerificationConfig,
    client_limits: KmipClientLimits,
    key_label_config: KeyLabelConfig,
) -> Result<(), Error> {
    if kmip.servers.contains_key(&server_id) {
        return Err(Error::new(&format!(
            "unable to add KMIP server '{server_id}': server already exists!"
        )));
    }

    let client_credentials_path = match credentials {
        // No credentials supplied.
        // Use unauthenticated access to the KMIP server.
        None => None,

        Some(KmipClientCredentialArgs {
            credentials_store_path,
            credentials,
        }) => {
            let mut credentials_file = KmipClientCredentialsFile::new(
                &credentials_store_path,
                KmipServerCredentialsFileMode::CreateReadWrite,
            )?;

            if let Some(credentials) = credentials {
                if credentials_file
                    .insert(server_id.clone(), credentials)
                    .is_some()
                {
                    // Don't accidental change existing credentials.
                    return Err(Error::new(&format!("unable to add KMIP credentials to file {}: server '{server_id}' already exists.", credentials_store_path.display())));
                }
                credentials_file.save()?;
            } else {
                // Only credentials path supplied.
                // Check that it contains credentials for the specified server.
                if !credentials_file.contains(&server_id) {
                    return Err(Error::new(&format!("unable to add KMIP server '{server_id}': credentials for server not found in {}", credentials_store_path.display())));
                }
            }

            Some(credentials_store_path)
        }
    };

    let settings = KmipServerConnectionConfig {
        server_addr: ip_host_or_fqdn,
        server_port: port,
        server_cert_verification,
        client_credentials_path,
        client_cert_auth,
        client_limits,
        key_label_config,
    };

    kmip.servers.insert(server_id.clone(), settings);

    if kmip.servers.len() == 1 {
        kmip.default_server_id = Some(server_id);
    }

    Ok(())
}

/// Should a setting be changed, removed or left as-is?
enum ChangeRemoveLeave<T> {
    Change(T),
    Remove,
    Leave,
}

#[allow(clippy::too_many_arguments)]
fn modify_kmip_server(
    kmip: &mut KmipState,
    server_id: &str,
    ip_host_or_fqdn: Option<String>,
    port: Option<u16>,
    credentials_store_path: ChangeRemoveLeave<PathBuf>,
    username: ChangeRemoveLeave<String>,
    password: ChangeRemoveLeave<String>,
    client_cert_path: ChangeRemoveLeave<PathBuf>,
    client_key_path: ChangeRemoveLeave<PathBuf>,
    server_insecure: Option<bool>,
    server_cert_path: ChangeRemoveLeave<PathBuf>,
    ca_cert_path: ChangeRemoveLeave<PathBuf>,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    max_response_bytes: Option<u32>,
    key_label_prefix: Option<String>,
    key_label_max_bytes: Option<u8>,
) -> Result<(), Error> {
    let Some(mut cfg) = kmip.servers.remove(server_id) else {
        return Err("server does not exist!".into());
    };

    cfg.server_addr = ip_host_or_fqdn.unwrap_or(cfg.server_addr);
    cfg.server_port = port.unwrap_or(cfg.server_port);

    // Handle changed credentials.
    cfg.client_credentials_path = match (credentials_store_path, username, password) {
        (ChangeRemoveLeave::Leave, ChangeRemoveLeave::Leave, ChangeRemoveLeave::Leave) => {
            // Nothing to do.
            cfg.client_credentials_path
        }

        (ChangeRemoveLeave::Remove, ChangeRemoveLeave::Change(_), _)
        | (ChangeRemoveLeave::Remove, _, ChangeRemoveLeave::Change(_))
        | (ChangeRemoveLeave::Leave, ChangeRemoveLeave::Remove, ChangeRemoveLeave::Change(_)) => {
            return Err("cannot remove credentials and change credentials at the same time".into());
        }

        (ChangeRemoveLeave::Change(_), ChangeRemoveLeave::Remove, _) => {
            return Err("cannot move credentials and remove credentials at the same time".into());
        }

        (ChangeRemoveLeave::Remove, _, _) => {
            // Remove any existing stored credentials.
            if let Some(path) = &cfg.client_credentials_path {
                let _ = remove_kmip_client_credentials(server_id, path)?;
            }
            None
        }

        (ChangeRemoveLeave::Change(new_path), username, password) => {
            // Change the file used to store credentials. If the credentials
            // are not being changed, move them from the old file to the
            // new file. Otherwise remove them from the old file and the new
            // credentials to the new file.

            // Remove the old credentials file.
            let creds = if let Some(p) = cfg.client_credentials_path {
                let mut creds = remove_kmip_client_credentials(server_id, &p)?;
                // Adjust credentials if needed.
                match username {
                    ChangeRemoveLeave::Change(v) => creds.username = v,
                    ChangeRemoveLeave::Remove => unreachable!(), // Handled above
                    ChangeRemoveLeave::Leave => { /* Nothing to do */ }
                }
                match password {
                    ChangeRemoveLeave::Change(v) => creds.password = Some(v),
                    ChangeRemoveLeave::Remove => creds.password = None,
                    ChangeRemoveLeave::Leave => { /* Nothing to do */ }
                }
                creds
            } else {
                let username = match username {
                    ChangeRemoveLeave::Change(v) => v,
                    ChangeRemoveLeave::Remove => unreachable!(), // Handled above
                    ChangeRemoveLeave::Leave => {
                        return Err("cannot use existing username as none was found".into())
                    }
                };
                let password = match password {
                    ChangeRemoveLeave::Change(v) => Some(v),
                    ChangeRemoveLeave::Remove => None,
                    ChangeRemoveLeave::Leave => None,
                };
                KmipClientCredentials { username, password }
            };

            // Open the new credentials file.
            let mut new_creds_file = KmipClientCredentialsFile::new(
                &new_path,
                KmipServerCredentialsFileMode::CreateReadWrite,
            )?;

            // Insert credentials and save them.
            let _ = new_creds_file.insert(server_id.to_string(), creds);
            new_creds_file.save()?;
            Some(new_path)
        }

        (ChangeRemoveLeave::Leave, _, _) if cfg.client_credentials_path.is_none() => {
            return Err("cannot change client credentials that don't exist".into());
        }

        (ChangeRemoveLeave::Leave, username, password) => {
            // Open the new credentials file.
            let mut creds_file = KmipClientCredentialsFile::new(
                cfg.client_credentials_path.as_ref().unwrap(), // SAFETY: Checked for is_none() above
                KmipServerCredentialsFileMode::ReadWrite,
            )?;

            let creds = if let Some(mut creds) = creds_file.remove(server_id) {
                // Adjust credentials if needed.
                match username {
                    ChangeRemoveLeave::Change(v) => creds.username = v,
                    ChangeRemoveLeave::Remove => unreachable!(), // Handled above
                    ChangeRemoveLeave::Leave => { /* Nothing to do */ }
                }
                match password {
                    ChangeRemoveLeave::Change(v) => creds.password = Some(v),
                    ChangeRemoveLeave::Remove => creds.password = None,
                    ChangeRemoveLeave::Leave => { /* Nothing to do */ }
                }
                creds
            } else {
                // Create new credentials.
                let ChangeRemoveLeave::Change(username) = username else {
                    return Err(
                        "cannot change credentials that do not exist if no username is supplied"
                            .into(),
                    );
                };
                let password = match password {
                    ChangeRemoveLeave::Change(v) => Some(v),
                    ChangeRemoveLeave::Remove => None,
                    ChangeRemoveLeave::Leave => None,
                };
                KmipClientCredentials { username, password }
            };

            // (re-)insert the credentials and save them.
            let _ = creds_file.insert(server_id.to_string(), creds);
            creds_file.save()?;
            cfg.client_credentials_path
        }
    };

    // Handle changed client certificate authentication.
    cfg.client_cert_auth = match (client_cert_path, client_key_path) {
        (ChangeRemoveLeave::Leave, ChangeRemoveLeave::Leave) => {
            // Use the current values.
            cfg.client_cert_auth
        }

        (ChangeRemoveLeave::Remove, ChangeRemoveLeave::Remove) => {
            // Forget the current values.
            None
        }

        (ChangeRemoveLeave::Remove, _) | (_, ChangeRemoveLeave::Remove) => {
            return Err("cannot remove only one of the client certificate or client key.".into());
        }

        (cert_path, key_path) => {
            // Adjust the settings as needed.
            let cert_path = match cert_path {
                ChangeRemoveLeave::Change(v) => v,
                ChangeRemoveLeave::Remove => unreachable!(), // Handled above
                ChangeRemoveLeave::Leave => cfg.client_cert_auth.as_ref().map(|v| v.cert_path.clone()).ok_or::<Error>("cannot configure client certicate authentication without a client certificate path".into())?,
            };
            let private_key_path = match key_path {
                ChangeRemoveLeave::Change(v) => v,
                ChangeRemoveLeave::Remove => unreachable!(), // Handled above,
                ChangeRemoveLeave::Leave => cfg
                    .client_cert_auth
                    .as_ref()
                    .map(|v| v.private_key_path.clone())
                    .ok_or::<Error>(
                    "cannot configure client certificate authentication with a private key path"
                        .into(),
                )?,
            };

            Some(KmipClientTlsCertificateAuthConfig {
                cert_path,
                private_key_path,
            })
        }
    };

    // Handle changed server certificate verification.
    if let Some(v) = server_insecure {
        cfg.server_cert_verification.verify_certificate = v.not();
    }
    match server_cert_path {
        ChangeRemoveLeave::Change(v) => cfg.server_cert_verification.server_cert_path = Some(v),
        ChangeRemoveLeave::Remove => cfg.server_cert_verification.server_cert_path = None,
        ChangeRemoveLeave::Leave => { /* Nothing to do */ }
    }
    match ca_cert_path {
        ChangeRemoveLeave::Change(v) => cfg.server_cert_verification.ca_cert_path = Some(v),
        ChangeRemoveLeave::Remove => cfg.server_cert_verification.ca_cert_path = None,
        ChangeRemoveLeave::Leave => { /* Nothing to do */ }
    }

    if let Some(v) = connect_timeout {
        cfg.client_limits.connect_timeout = v;
    }
    if let Some(v) = read_timeout {
        cfg.client_limits.read_timeout = v;
    }
    if let Some(v) = write_timeout {
        cfg.client_limits.write_timeout = v;
    }
    if let Some(v) = max_response_bytes {
        cfg.client_limits.max_response_bytes = v;
    }

    if let Some(v) = key_label_prefix {
        cfg.key_label_config.prefix = v;
    }
    if let Some(v) = key_label_max_bytes {
        cfg.key_label_config.max_label_bytes = v;
    }

    kmip.servers.insert(server_id.to_string(), cfg);

    if kmip.servers.len() == 1 {
        kmip.default_server_id = Some(server_id.to_string());
    }

    Ok(())
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

    /// KMIP related configuration.
    kmip: KmipState,
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
    kmip: &mut KmipState,
) -> Result<(Url, Url, SecurityAlgorithm, u16), Error> {
    // Generate the key.
    // TODO: Attempt repeated generation to avoid key tag collisions.
    // TODO: Add a high-level operation in 'domain' to select flags?
    let flags = if make_ksk { 257 } else { 256 };
    let mut retries = MAX_KEY_TAG_TRIES;

    // If a default KMIP server is configured, use that to generate keys.
    if let Some(kmip_conn_pool) = kmip.get_default_pool()? {
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
            .map_err::<Error, _>(|e| format!("KMIP key generation failed: {e}\n").into())?;

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
                            .map_err::<Error, _>(|e| format!("KMIP key generation failed: failed to re-label private key with id {}: {e}", key_pair.private_key_id()).into())?;
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

        Ok((
            key_pair.public_key_url(),
            key_pair.private_key_url(),
            key_pair.algorithm(),
            dnskey.key_tag(),
        ))
    } else {
        // Otherwise use Ring/OpenSSL based key generation.
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

fn format_key_label(
    prefix: &str,
    zone_name: &str,
    key_tag: &str,
    key_type: &str,
    suffix: &str,
    max_label_bytes: usize,
) -> Result<String, Error> {
    let mut public_key_label = format!("{prefix}{zone_name}-{key_tag}-{key_type}{suffix}");
    if public_key_label.len() > max_label_bytes {
        let diff = public_key_label.len() - max_label_bytes;
        let max_zone_name_len = zone_name.len().saturating_sub(diff);
        if max_zone_name_len < 8 {
            return Err(format!("Insufficient space to include a useful (partial) zone name in generated KMIP key label: {max_zone_name_len} < 8").into());
        }
        // If the name is a valid DNS name, truncate it by
        // keeping the right most label (the TLD) but removing
        // labels one by one prior to that until the name is
        // short enough.
        let zone_name = truncate_zone_name(zone_name.to_string(), max_zone_name_len);
        public_key_label = format!("{prefix}{zone_name}-{key_tag}-{key_type}{suffix}");
    }
    Ok(public_key_label)
}

fn truncate_zone_name(mut zone_name: String, max_zone_name_len: usize) -> String {
    if zone_name.len() <= max_zone_name_len {
        return zone_name;
    }
    if max_zone_name_len > 0 {
        if let Ok(dns_name) = Name::<Vec<u8>>::from_str(&zone_name) {
            // We can only shorten names that have at least
            // three labels.
            let num_labels = dns_name.iter_labels().count();
            if num_labels >= 3 {
                let mut end_name = NameBuilder::new_vec();

                // Append prior labels until the current
                // length + '.' + the final label + '.' would
                // be too long.
                let mut labels = dns_name.iter_labels().rev();

                // Keep the root and TLD labels.
                end_name
                    .append_label(labels.next().unwrap().as_slice())
                    .unwrap();
                end_name
                    .append_label(labels.next().unwrap().as_slice())
                    .unwrap();

                // Append labels from the left as long as they fit.
                let mut labels = dns_name.iter_labels();
                let mut start_name = NameBuilder::new_vec();
                for _ in 0..num_labels - 2 {
                    let label = labels.next().unwrap();
                    // Minus one to allow space for the '..' that will be used
                    // instead of '.' to signify that label based truncation
                    // occurred.
                    if start_name.len() + label.len() + end_name.len() < (max_zone_name_len - 1) {
                        start_name.append_label(label.as_slice()).unwrap();
                    }
                }

                if !start_name.is_empty() {
                    // Build final name
                    let mut zone_name = start_name.finish().to_string();
                    zone_name.push_str("..");
                    zone_name.push_str(&end_name.into_name().unwrap().to_string());
                    zone_name.push('.');

                    if zone_name.len() <= max_zone_name_len {
                        return zone_name;
                    }
                }
            }
        }
    }

    zone_name.truncate(max_zone_name_len);
    zone_name
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
                let kmip_key_url = KeyUrl::try_from(pub_url)?;
                let flags = kmip_key_url.flags();
                let kmip_conn_pool = kss.kmip.get_pool(kmip_key_url.server_id())?;
                let key = kmip::PublicKey::for_key_url(kmip_key_url, kmip_conn_pool)
                    .map_err(|err| format!("Failed to fetch public key for KMIP key URL: {err}"))?;
                let owner = kss.keyset.name().clone().flatten_into();
                // TODO: Where does this TTL come from?
                let record = Record::new(
                    owner,
                    Class::IN,
                    Ttl::from_days(1),
                    key.dnskey(flags).convert(),
                );
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
                    let priv_key_url = KeyUrl::try_from(priv_url)?;
                    let pub_key_url = KeyUrl::try_from(pub_url)?;
                    let flags = priv_key_url.flags();
                    let kmip_conn_pool = kss.kmip.get_pool(priv_key_url.server_id())?;
                    let key_pair =
                        kmip::sign::KeyPair::from_urls(priv_key_url, pub_key_url, kmip_conn_pool)
                            .map_err(|err| format!("Failed to retrieve KMIP key by URL: {err}"))?;
                    let key_pair = KeyPair::Kmip(key_pair);
                    SigningKey::new(owner, flags, key_pair)
                }

                (priv_scheme, pub_scheme) => {
                    panic!("unsupported URL scheme combination: {priv_scheme} & {pub_scheme}");
                }
            };

            // TODO: Should there be a key not found error we can detect here so that we can retry if
            // we believe that the key is simply not registered fully yet in the HSM?
            let sig = sign_rrset(&signing_key, &rrset, inception, expiration).map_err::<Error, _>(
                |e| format!("error signing DNSKEY RRset with private key {privref}: {e}").into(),
            )?;
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
            match pub_url.scheme() {
                "file" => {
                    let path = pub_url.path();
                    let filename = env.in_cwd(&path);
                    let mut file = File::open(&filename).map_err::<Error, _>(|e| {
                        format!("unable to open public key file {}: {e}", filename.display()).into()
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
                    let key_url = KeyUrl::try_from(pub_url)?;
                    let flags = key_url.flags();
                    let conn_pool = kss.kmip.get_pool(key_url.server_id())?;
                    let public_key = kmip::PublicKey::for_key_url(key_url, conn_pool)
                        .map_err(|err| format!("Failed to look up KMIP public key: {err}"))?;
                    let dnskey = public_key.dnskey(flags);
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
                    let priv_key_url = KeyUrl::try_from(priv_url)?;
                    let pub_key_url = KeyUrl::try_from(pub_url)?;
                    let flags = priv_key_url.flags();
                    let kmip_conn_pool = kss.kmip.get_pool(priv_key_url.server_id())?;
                    let key_pair =
                        kmip::sign::KeyPair::from_urls(priv_key_url, pub_key_url, kmip_conn_pool)
                            .map_err(|err| format!("Failed to retrieve KMIP key by URL: {err}"))?;
                    let key_pair = KeyPair::Kmip(key_pair);
                    SigningKey::new(owner, flags, key_pair)
                }

                (priv_scheme, pub_scheme) => {
                    panic!("unsupported URL scheme combination: {priv_scheme} & {pub_scheme}");
                }
            };
            let sig = sign_rrset(&signing_key, &cds_rrset, inception, expiration)
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
                    let key_url = KeyUrl::try_from(pub_url)?;
                    let flags = key_url.flags();
                    let conn_pool = kss.kmip.get_pool(key_url.server_id())?;
                    let public_key = kmip::PublicKey::for_key_url(key_url, conn_pool)
                        .map_err(|err| format!("Failed to look up KMIP public key: {err}"))?;
                    let dnskey = public_key.dnskey(flags);
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

//============ KMIP support ==================================================
//
// KMIP (OASIS Key Management Interoperability Protocol) is a specification
// for communicating with HSMs (Hardware Security Modules) that implement
// secure cryptographic key generation and signing of data using generated
// keys.
//
// The functions and types below extend `dnst keyset` to support KMIP based
// cryptographic keys as well as the default Ring/OpenSSL based keys.

//------------ KmipClientCredentialArgs --------------------------------------

struct KmipClientCredentialArgs {
    credentials_store_path: PathBuf,
    credentials: Option<KmipClientCredentials>,
}

//------------ KmipClientCredentials -----------------------------------------

/// Credentials for connecting to a KMIP server.
///
/// Intended to be read from a JSON file stored separately to the main
/// configuration so that separate security policy can be applied to sensitive
/// credentials.
#[derive(Debug, Deserialize, Serialize)]
pub struct KmipClientCredentials {
    /// KMIP username credential.
    ///
    /// Mandatory if the KMIP "Credential Type" is "Username and Password".
    ///
    /// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613458
    username: String,

    /// KMIP password credential.
    ///
    /// Optional when KMIP "Credential Type" is "Username and Password".
    ///
    /// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613458
    #[serde(skip_serializing_if = "Option::is_none", default)]
    password: Option<String>,
}

//------------ KmipClientCredentialSet ---------------------------------------

/// A set of KMIP server credentials.
#[derive(Debug, Default, Deserialize, Serialize)]
struct KmipClientCredentialsSet(HashMap<String, KmipClientCredentials>);

//------------ KmipClientCredentialsFileMode ---------------------------------

#[derive(Debug)]
enum KmipServerCredentialsFileMode {
    /// Open an existing credentials file for reading. Saving will fail.
    ReadOnly,

    /// Open an existing credentials file for reading and writing.
    ReadWrite,

    /// Open or create the credentials file for reading and writing.
    CreateReadWrite,
}

//--- impl Display

impl std::fmt::Display for KmipServerCredentialsFileMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            KmipServerCredentialsFileMode::ReadOnly => write!(f, "read-only"),
            KmipServerCredentialsFileMode::ReadWrite => write!(f, "read-write"),
            KmipServerCredentialsFileMode::CreateReadWrite => write!(f, "create-read-write"),
        }
    }
}

//------------ KmipServerCredentialsFile -------------------------------------

/// A KMIP server credential set file.
#[derive(Debug)]
struct KmipClientCredentialsFile {
    /// The file from which the credentials were loaded, and will be saved
    /// back to.
    file: File,

    /// The path from which the file was loaded. Used for generating error
    /// messages.
    path: PathBuf,

    /// The actual set of loaded credentials.
    credentials: KmipClientCredentialsSet,

    /// The read/write/create mode.
    #[allow(dead_code)]
    mode: KmipServerCredentialsFileMode,
}

impl KmipClientCredentialsFile {
    /// Load credentials from disk.
    ///
    /// Optionally:
    ///   - Create the file if missing.
    ///   - Keep the file open for writing back changes. See ['Self::save()`].
    pub fn new(path: &Path, mode: KmipServerCredentialsFileMode) -> Result<Self, Error> {
        let read;
        let write;
        let create;

        match mode {
            KmipServerCredentialsFileMode::ReadOnly => {
                read = true;
                write = false;
                create = false;
            }
            KmipServerCredentialsFileMode::ReadWrite => {
                read = true;
                write = true;
                create = false;
            }
            KmipServerCredentialsFileMode::CreateReadWrite => {
                read = true;
                write = true;
                create = true;
            }
        }

        let file = OpenOptions::new()
            .read(read)
            .write(write)
            .create(create)
            .truncate(false)
            .open(path)
            .map_err::<Error, _>(|e| {
                format!(
                    "unable to open KMIP credentials file {} in {mode} mode: {e}",
                    path.display()
                )
                .into()
            })?;

        // Determine the length of the file as JSON parsing fails if the file
        // is completely empty.
        let len = file.metadata().map(|m| m.len()).map_err::<Error, _>(|e| {
            format!(
                "unable to query metadata of KMIP credentials file {}: {e}",
                path.display()
            )
            .into()
        })?;

        // Buffer reading as apparently JSON based file reading is extremely
        // slow without buffering, even for small files.
        let mut reader = BufReader::new(&file);

        // Load or create the credential set.
        let credentials: KmipClientCredentialsSet = if len > 0 {
            serde_json::from_reader(&mut reader).map_err::<Error, _>(|e| {
                format!(
                    "error loading KMIP credentials file {:?}: {e}\n",
                    path.display()
                )
                .into()
            })?
        } else {
            KmipClientCredentialsSet::default()
        };

        // Save the path for use in generating error messages.
        let path = path.to_path_buf();

        Ok(KmipClientCredentialsFile {
            file,
            path,
            credentials,
            mode,
        })
    }

    /// Write the credential set back to the file it was loaded from.
    pub fn save(&mut self) -> Result<(), Error> {
        // Ensure that writing happens at the start of the file.
        self.file.seek(SeekFrom::Start(0))?;

        // Use a buffered writer as writing JSON to a file directly is
        // apparently very slow, even for small files.
        //
        // Enclose the use of the BufWriter in a block so that it is
        // definitely no longer using the file when we next act on it.
        {
            let mut writer = BufWriter::new(&self.file);
            serde_json::to_writer_pretty(&mut writer, &self.credentials).map_err::<Error, _>(
                |e| {
                    format!(
                        "error writing KMIP credentials file {}: {e}",
                        self.path.display()
                    )
                    .into()
                },
            )?;

            // Ensure that the BufWriter is flushed as advised by the
            // BufWriter docs.
            writer.flush()?;
        }

        // Truncate the file to the length of data we just wrote..
        let pos = self.file.stream_position()?;
        self.file.set_len(pos)?;

        // Ensure that any write buffers are flushed.
        self.file.flush()?;

        Ok(())
    }

    /// Does this credential set include credentials for the specified KMIP
    /// server.
    pub fn contains(&self, server_id: &str) -> bool {
        self.credentials.0.contains_key(server_id)
    }

    #[allow(dead_code)]
    fn get(&self, server_id: &str) -> Option<&KmipClientCredentials> {
        self.credentials.0.get(server_id)
    }

    /// Add credentials for the specified KMIP server, replacing any that
    /// previously existed for the same server.-
    ///
    /// Returns any previous configuration if found.
    pub fn insert(
        &mut self,
        server_id: String,
        credentials: KmipClientCredentials,
    ) -> Option<KmipClientCredentials> {
        self.credentials.0.insert(server_id, credentials)
    }

    /// Remove any existing configuration for the specified KMIP server.
    ///
    /// Returns any previous configuration if found.
    pub fn remove(&mut self, server_id: &str) -> Option<KmipClientCredentials> {
        self.credentials.0.remove(server_id)
    }

    pub fn is_empty(&self) -> bool {
        self.credentials.0.is_empty()
    }
}

//------------ KmipClientTlsCertificateAuthConfig ----------------------------

/// Configuration for KMIP TLS client certificate based authentication.
///
/// Both certificate and key file must be present and must be in PEM format.
// Note: We only support PEM format, not PKCS#12, because the underlying
// kmip-protocol TLS "drivers" for rustls and OpenSSL both don't actually
// support PKCS#12 even though taking it as config input.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KmipClientTlsCertificateAuthConfig {
    /// Path to the PEM format client certificate file.
    pub cert_path: PathBuf,

    /// Path to the PEM format client private key file.
    pub private_key_path: PathBuf,
}

//------------ KmipServerTlsCertificateVerificationConfig --------------------

/// Configuratin for KMIP TLS certificate verification.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KmipServerTlsCertificateVerificationConfig {
    /// Whether or not to enable server certificate verification.
    #[serde(default)]
    pub verify_certificate: bool,

    /// Path to the server certificate file in PEM format.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub server_cert_path: Option<PathBuf>,

    /// Path to the server CA certificate file in PEM format.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ca_cert_path: Option<PathBuf>,
}

//--- impl Default

impl Default for KmipServerTlsCertificateVerificationConfig {
    fn default() -> Self {
        Self {
            verify_certificate: true,
            server_cert_path: None,
            ca_cert_path: None,
        }
    }
}

//------------ KmipClientLimits ----------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KmipClientLimits {
    /// TCP connect timeout
    pub connect_timeout: Duration,

    /// TCP read timeout
    pub read_timeout: Duration,

    /// TCP write timeout
    pub write_timeout: Duration,

    /// Maximum number of HSM response bytes to accept
    pub max_response_bytes: u32,
}

impl std::fmt::Display for KmipClientLimits {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Connect Timeout:               {} seconds",
            self.connect_timeout.as_secs()
        )?;
        writeln!(
            f,
            "Read Timeout:                  {} seconds",
            self.read_timeout.as_secs()
        )?;
        writeln!(
            f,
            "Write Timeout:                 {} seconds",
            self.write_timeout.as_secs()
        )?;
        writeln!(
            f,
            "Max Response Size:             {} bytes",
            self.max_response_bytes
        )
    }
}

//------------ KeyLabelConfig ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyLabelConfig {
    /// Maximum label length.
    pub max_label_bytes: u8,

    /// Supports re-labeling.
    ///
    /// Defaults to true, will be changed to false if relabeling fails to
    /// avoid further attempts to relabel.
    pub supports_relabeling: bool,

    /// Optional user supplied key label prefix.
    ///
    /// E.g. to denote the s/w that created the key, and/or to indicate which
    /// installation/environment it belongs to, e.g. dev, test, prod, etc.
    pub prefix: String,
}

impl std::fmt::Display for KeyLabelConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Prefix:                        {}", self.prefix)?;
        writeln!(f, "Max Bytes:                     {}", self.max_label_bytes,)?;
        writeln!(
            f,
            "Supports Re-Labeling:          {}",
            self.supports_relabeling
        )?;
        Ok(())
    }
}

//------------ KmipServerConnectionConfig ------------------------------------

/// Settings for connecting to a KMIP HSM server.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KmipServerConnectionConfig {
    /// IP address, hostname or FQDN of the KMIP server.
    pub server_addr: String,

    /// The TCP port number on which the KMIP server listens.
    pub server_port: u16,

    /// KMIP server TLS certificate verification configuration.
    pub server_cert_verification: KmipServerTlsCertificateVerificationConfig,

    /// The credentials to authenticate with the KMIP server.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub client_credentials_path: Option<PathBuf>,

    /// KMIP client TLS certificate authentication configuration.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub client_cert_auth: Option<KmipClientTlsCertificateAuthConfig>,

    /// Limits to be applied by the KMIP client
    pub client_limits: KmipClientLimits,

    /// Key labeling configuration.
    pub key_label_config: KeyLabelConfig,
}

//--- impl Display

/// Displays in multi-line tabulated format like so:
///
/// ```text
/// Address:                           127.0.0.1:5696
/// Server Certificate Verification:   Disabled
/// Server Certificate:                None
/// Certificate Authority Certificate: None
/// Client Credentials:                /tmp/x.creds
/// Client Certificate Authentication: Disabled
/// Client Limits:
///     Connect Timeout:               10 seconds
///     Read Timeout:                  10 seconds
///     Write Timeout:                 10 seconds
///     Max Response Size:             8192 bytes
/// ```
impl std::fmt::Display for KmipServerConnectionConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write;

        fn opt_path_to_string(p: &Option<PathBuf>) -> String {
            match p {
                Some(p) => p.display().to_string(),
                None => "None".to_string(),
            }
        }

        writeln!(
            f,
            "Address:                           {}:{}",
            self.server_addr, self.server_port
        )?;
        let enabled = match self.server_cert_verification.verify_certificate {
            true => "Enabled",
            false => "Disabled",
        };
        writeln!(f, "Server Certificate Verification:   {enabled}")?;
        writeln!(
            f,
            "Server Certificate:                {}",
            opt_path_to_string(&self.server_cert_verification.server_cert_path)
        )?;
        writeln!(
            f,
            "Certificate Authority Certificate: {}",
            opt_path_to_string(&self.server_cert_verification.ca_cert_path)
        )?;
        writeln!(
            f,
            "Client Credentials:                {}",
            opt_path_to_string(&self.client_credentials_path)
        )?;
        match &self.client_cert_auth {
            Some(cfg) => {
                writeln!(f, "Client Certificate Authentication: Enabled")?;
                writeln!(
                    f,
                    "    Client Certificate:            {}",
                    cfg.cert_path.display()
                )?;
                writeln!(
                    f,
                    "    Private Key:                   {}",
                    cfg.private_key_path.display()
                )?;
            }
            None => {
                writeln!(f, "Client Certificate Authentication: Disabled")?;
            }
        }

        {
            writeln!(f, "Client Limits:")?;
            let mut indented = indenter::indented(f);
            write!(indented, "{}", self.client_limits)?;
        }

        {
            writeln!(f, "Key Label Config:")?;
            let mut indented = indenter::indented(f);
            write!(indented, "{}", self.key_label_config)?;
        }

        Ok(())
    }
}

impl KmipServerConnectionConfig {
    /// Load KMIP connection configuration data into memory.
    ///
    /// Load and parse the various credential data that can optionally
    /// be associated with KMIP connection settings from the separate
    /// files on disk where they are stored, and return a populated
    /// `ConnectionSettings` object containing the resulting data.
    ///
    /// TODO: Currently lacks support for configuring timeouts and other
    /// limits that the KMIP client can enforce. By default there are no such
    /// limits.
    pub fn load(&self, server_id: &str) -> Result<ConnectionSettings, Error> {
        let client_cert = self.load_client_cert()?;
        let server_cert = self.load_server_cert()?;
        let ca_cert = self.load_ca_cert()?;
        let (username, password) = self.load_credentials(server_id)?;
        Ok(ConnectionSettings {
            host: self.server_addr.clone(),
            port: self.server_port,
            username,
            password,
            insecure: self.server_cert_verification.verify_certificate.not(),
            client_cert,
            server_cert,
            ca_cert,
            connect_timeout: None,    // TODO
            read_timeout: None,       // TODO
            write_timeout: None,      // TODO
            max_response_bytes: None, // TODO
        })
    }

    /// Load and parse PEM TLS client certificate and key files.
    ///
    /// TLS client certificate and key files can be used to authenticate
    /// against KMIP servers that are configured to require such
    /// authentication.
    fn load_client_cert(&self) -> Result<Option<ClientCertificate>, Error> {
        match &self.client_cert_auth {
            Some(cfg) => Ok(Some(ClientCertificate::SeparatePem {
                cert_bytes: Self::load_binary_file(&cfg.cert_path)?,
                key_bytes: Self::load_binary_file(&cfg.private_key_path)?,
            })),
            None => Ok(None),
        }
    }

    /// Load and parse a PEM format TLS server certificate.
    ///
    /// The certificate contains a public key which can be used to verify the
    /// identity of the remote KMIP server.
    fn load_server_cert(&self) -> Result<Option<Vec<u8>>, Error> {
        Ok(match &self.server_cert_verification.server_cert_path {
            Some(p) => Some(Self::load_binary_file(p)?),
            None => None,
        })
    }

    /// Load and parse a PEM format TLS certificate authority certificate.
    ///
    /// The certificate can be used to verify the issuing authority of the
    /// TLS server certificate, thereby verifying not just that the server is
    /// the owner of the certificate but that the certificate was issued by a
    /// trusted party.
    fn load_ca_cert(&self) -> Result<Option<Vec<u8>>, Error> {
        Ok(match &self.server_cert_verification.ca_cert_path {
            Some(p) => Some(Self::load_binary_file(p)?),
            None => None,
        })
    }

    /// Load credentials from disk for authenticating with a KMIP server.
    ///
    /// Currently supports only one credential type:
    ///   - Username and optional password.
    ///
    /// In the case of Nameshed-HSM-Relay the username is the PKCS#11 slot
    /// label and the password is the PKCS#11 user PIN.
    fn load_credentials(&self, server_id: &str) -> Result<(Option<String>, Option<String>), Error> {
        if let Some(p) = &self.client_credentials_path {
            let mut file =
                KmipClientCredentialsFile::new(p, KmipServerCredentialsFileMode::ReadOnly)?;
            if let Some(creds) = file.remove(server_id) {
                return Ok((Some(creds.username), creds.password));
            }
        }
        Ok((None, None))
    }

    /// Load an arbitrary file as unparsed bytes into memory.
    ///
    /// TODO: Lmiit how many bytes we will read?
    fn load_binary_file(path: &Path) -> Result<Vec<u8>, Error> {
        use std::{fs::File, io::Read};

        let mut bytes = Vec::new();
        File::open(path)?.read_to_end(&mut bytes)?;

        Ok(bytes)
    }
}

//--- Conversions

impl From<KmipConnError> for Error {
    fn from(err: KmipConnError) -> Self {
        Error::new(&format!("KMIP connection error: {err}"))
    }
}

//------------ KmipState -----------------------------------------------------

/// KMIP related state.
///
/// Part of [`KeySetState`].
#[derive(Default, Deserialize, Serialize)]
struct KmipState {
    /// KMIP servers to use, keyed by user chosen HSM id.
    servers: HashMap<String, KmipServerConnectionConfig>,

    /// Which KMIP server should new keys be created in, if any?
    #[serde(skip_serializing_if = "Option::is_none", default)]
    default_server_id: Option<String>,

    /// The current set of KMIP server pools.
    #[serde(skip)]
    pools: HashMap<String, SyncConnPool>,
}

impl KmipState {
    /// Get the default KMIP server pool, if any.
    ///
    /// Requires KeySetConfig::default_kmip_server to be set. The pool will be
    /// created if needed.
    ///
    /// Returns Ok(None) if no default KMIP server is set.
    pub fn get_default_pool(&mut self) -> Result<Option<SyncConnPool>, Error> {
        if self.default_server_id.is_some() {
            let id = self.default_server_id.clone().unwrap();
            return self.get_pool(&id).map(Some);
        }
        Ok(None)
    }

    /// Get the server pool for a specific KMIP server ID.
    ///
    /// Requires the server ID to exist in KeySetConfig::kmip_servers.
    /// The pool will be created if needed.
    ///
    /// Returns Ok(pool) or Err if the server ID is not known or the pool
    /// cannot be created.
    pub fn get_pool(&mut self, id: &str) -> Result<SyncConnPool, Error> {
        match self.pools.get(id) {
            Some(pool) => Ok(pool.clone()),
            None => {
                let Some(srv_conn_settings) = self.servers.get(id) else {
                    return Err(format!("No KMIP server config exists for server '{id}").into());
                };
                let conn_settings = srv_conn_settings.load(id).map_err(|err| {
                    format!("Unable to prepare KMIP connection settings for server '{id}': {err}")
                })?;
                // TODO: Should the timeouts used here be configurable and/or set to some
                // other value?
                let pool = ConnectionManager::create_connection_pool(
                    id.to_string(),
                    conn_settings.into(),
                    1,
                    Some(Duration::from_secs(60)),
                    Some(Duration::from_secs(60)),
                )
                .map_err(|err| format!("Failed to create KMIP connection pool: {err}"))?;

                self.pools.insert(id.to_string(), pool.clone());
                Ok(pool)
            }
        }
    }
}

//--- impl Display

/// Displays in muti-line tabulated format like so:
///
/// ```text
/// Servers:
///     ID: my_server_x [DEFAULT]
///         Address:                           127.0.0.1:5696
///         Server Certificate Verification:   Disabled
///         Server Certificate:                None
///         Certificate Authority Certificate: None
///         Client Certificate Authentication: Disabled
///     ID: my_server
///         Address:                           127.0.0.1:5696
///         Server Certificate Verification:   Disabled
///         Server Certificate:                None
///         Certificate Authority Certificate: None
///         Client Certificate Authentication: Enabled
///             Client Certificate:            /blah
///             Private Key:                   /tmp/tmp
/// ```
impl std::fmt::Display for KmipState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Servers:")?;
        for (server_id, cfg) in &self.servers {
            let default = match Some(server_id) == self.default_server_id.as_ref() {
                true => " [DEFAULT]",
                false => "",
            };
            use std::fmt::Write;
            let mut indented = indenter::indented(f);
            writeln!(indented, "ID: {server_id}{default}")?;

            let mut twice_indented = indenter::indented(&mut indented);
            write!(twice_indented, "{cfg}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_zone_name() {
        // Name already shorter than the truncation length
        assert_eq!(&truncate_zone_name("".to_string(), 5), "");
        assert_eq!(&truncate_zone_name("nl.".to_string(), 5), "nl.");

        // Names longer than the truncation length but the labels under the
        // TLD are too long to allow shortening by dropping of labels, instead
        // shortening is done by brute truncation.
        assert_eq!(&truncate_zone_name("nlnetlabs.nl.".to_string(), 5), "nlnet");
        assert_eq!(
            &truncate_zone_name("a.b.c.d.nlnetlabs.nl.".to_string(), 5),
            "a.b.c"
        );

        // Names longer than the truncation length and has labels under the
        // TLD that are short enough to permit truncation by dropping of labels
        // in the middle. A double dot (..) indicates that truncation occurred.
        assert_eq!(
            &truncate_zone_name("a.b.c.d.nlnetlabs.nl.".to_string(), 10),
            "a.b.c..nl."
        );
        assert_eq!(
            &truncate_zone_name("a.b.c.d.nlnetlabs.nl.".to_string(), 12),
            "a.b.c.d..nl."
        );
        assert_eq!(
            &truncate_zone_name("a.b.c.d.nlnetlabs.nl.".to_string(), 19),
            "a.b.c.d..nl."
        );
        assert_eq!(
            &truncate_zone_name("a.b.c.d.nlnetlabs.nl.".to_string(), 20),
            "a.b.c.d..nl."
        );

        // Name is equal to the truncation length so no truncation needed.
        assert_eq!(
            &truncate_zone_name("a.b.c.d.nlnetlabs.nl.".to_string(), 21),
            "a.b.c.d.nlnetlabs.nl."
        );
    }

    #[test]
    fn test_format_key_label() {
        assert_eq!(
            format_key_label("", "a.b.c.d.nlnetlabs.nl.", "12345", "ksk", "", 20).unwrap(),
            "a.b.c..nl.-12345-ksk"
        );
        assert_eq!(
            format_key_label("", "a.b.c.d.nlnetlabs.nl.", "12345", "ksk", "", 31).unwrap(),
            "a.b.c.d.nlnetlabs.nl.-12345-ksk"
        );
        assert_eq!(
            format_key_label(
                "prefix-",
                "a.b.c.d.nlnetlabs.nl.",
                "12345",
                "ksk",
                "-suffix",
                45
            )
            .unwrap(),
            "prefix-a.b.c.d.nlnetlabs.nl.-12345-ksk-suffix"
        );

        // Max len too short to hold the generated label.
        assert!(format_key_label("", "a.b.c.d.nlnetlabs.nl.", "12345", "ksk", "", 10).is_err());
    }
}
