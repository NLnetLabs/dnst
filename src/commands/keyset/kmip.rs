//! KMIP support for the keyset subcommand.
//!
//! KMIP (OASIS Key Management Interoperability Protocol) is a specification
//! for communicating with HSMs (Hardware Security Modules) that implement
//! secure cryptographic key generation and signing of data using generated
//! keys.
//!
//! The functions and types in this module are used to extend `dnst keyset` to
//! support KMIP based cryptographic keys as well as the default Ring/OpenSSL
//! based keys.

// Note: Currently this is only used by `dnst keyset` but one can imagine it
// also being used by `dnst keygen`, `dnst key2ds` and `dnst signzone`. It may
// make sense to move the pure KMIP content from here to say src/kmip.rs and
// only keep the `dnst keyset` specific KMIP content in this module. One would
// also then need a way to configure which KMIP server the other subcommands
// should use and might want to also at that point consider a `dnst`-wide
// config mechanism for KMIP servers, e.g. `dnst kmip` or `dnst cfg kmip` or
// something.

use std::{
    collections::HashMap,
    fmt::Formatter,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Seek, SeekFrom, Write},
    ops::Not,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use clap::Subcommand;
use domain::{
    base::{name::ToLabelIter, Name, NameBuilder},
    crypto::kmip::{ClientCertificate, ConnectionSettings, KeyUrl},
    dep::kmip::client::pool::{ConnectionManager, KmipConnError, SyncConnPool},
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    commands::keyset::{parse_duration, KeySetState},
    env::Env,
    error::Error,
};

/// The default TCP port on which to connect to a KMIP server as defined by
/// IANA.
// TODO: Move this to the `kmip-protocol` crate?
pub const DEF_KMIP_PORT: u16 = 5696;

//------------ KmipCommands --------------------------------------------------

/// Commands for configuring the use of KMIP compatible HSMs for key
/// generation and signing instead of or in addition to using and Ring/OpenSSL
/// based key generation and signing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Subcommand)]
pub enum KmipCommands {
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
    /// If this is the first KMIP server to be configured it will be set
    /// as the default KMIP server which will be used to generate new keys
    /// instead of using Ring/OpenSSL based key generation.
    ///
    /// If this is NOT the first KMIP server to be configured, the default
    /// KMIP server will be left as-is, either unset or set to an existing
    /// KMIP server.
    ///
    /// Use 'kmip set-default-server' to change the default KMIP server.
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

        /// Add the server but don't make it the default.
        #[arg(help_heading = "Server", long = "pending", default_value_t = false, action = clap::ArgAction::SetTrue)]
        pending: bool,

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
        // Note: This should be low otherwise the CLI user experience when
        // running a command that interacts with a KMIP server, like `dnst
        // init`, is that the command hangs if the KMIP server is not running
        // or not reachable, until the timeout expires, and one would expect
        // that under normal circumstances establishing a TCP connection to
        // the KMIP server should be quite quick.
        // Note: Does this also include time for TLS setup?
        #[arg(help_heading = "Client Limits", long = "connect-timeout", value_parser = parse_duration, default_value = "3s")]
        connect_timeout: Duration,

        /// TCP response read timeout.
        // Note: This should be high otherwise for HSMs that are slow to
        // respond, like the YubiHSM, we time out the connection while waiting
        // for the response when generating keys.
        #[arg(help_heading = "Client Limits", long = "read-timeout", value_parser = parse_duration, default_value = "30s")]
        read_timeout: Duration,

        /// TCP request write timeout.
        #[arg(help_heading = "Client Limits", long = "write-timeout", value_parser = parse_duration, default_value = "3s")]
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

//------------ kmip_command() ------------------------------------------------

/// Process a `dnst keyset kmip` command.
pub fn kmip_command(
    env: &impl Env,
    cmd: KmipCommands,
    kss: &mut KeySetState,
) -> Result<bool, Error> {
    match cmd {
        KmipCommands::Disable => {
            kss.kmip.default_server_id = None;
        }

        KmipCommands::AddServer {
            server_id,
            ip_host_or_fqdn,
            port,
            pending,
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
                    Some(KmipClientCredentialsConfig {
                        credentials_store_path,
                        credentials: Some(KmipClientCredentials { username, password }),
                    })
                }
                (Some(credentials_store_path), _, _) => Some(KmipClientCredentialsConfig {
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
                pending,
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

//------------- remove_kmip_server() -----------------------------------------

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

/// Remove credentials from a file, removing the file entirely if then empty.
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

//------------ add_kmip_server() ---------------------------------------------

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
    pending: bool,
    credentials: Option<KmipClientCredentialsConfig>,
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

        Some(KmipClientCredentialsConfig {
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

    if !pending && kmip.servers.len() == 1 {
        kmip.default_server_id = Some(server_id);
    }

    Ok(())
}

//------------ ChangeRemoveLeave ---------------------------------------------

/// Should a setting be changed, removed or left as-is?
enum ChangeRemoveLeave<T> {
    /// The setting should be changed to the given value.
    Change(T),

    /// The setting should be removed as if it were never set by the user.
    Remove,

    /// The setting should be left unchanged at its current value.
    Leave,
}

//------------ modify_kmip_server() ------------------------------------------

/// Modify the settings of a currently configured KMIP server.
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

//------------ KmipClientCredentialsConfig -----------------------------------

/// Optional disk file based credentials for connecting to a KMIP server.
pub struct KmipClientCredentialsConfig {
    pub credentials_store_path: PathBuf,
    pub credentials: Option<KmipClientCredentials>,
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
    pub username: String,

    /// KMIP password credential.
    ///
    /// Optional when KMIP "Credential Type" is "Username and Password".
    ///
    /// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613458
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub password: Option<String>,
}

//------------ KmipClientCredentialSet ---------------------------------------

/// A set of KMIP server credentials.
#[derive(Debug, Default, Deserialize, Serialize)]
struct KmipClientCredentialsSet(HashMap<String, KmipClientCredentials>);

//------------ KmipClientCredentialsFileMode ---------------------------------

/// The access mode to use when accessing a credentials file.
#[derive(Debug)]
pub enum KmipServerCredentialsFileMode {
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
pub struct KmipClientCredentialsFile {
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
            .map_err(|e| {
                format!(
                    "unable to open KMIP credentials file {} in {mode} mode: {e}",
                    path.display()
                )
            })?;

        // Determine the length of the file as JSON parsing fails if the file
        // is completely empty.
        let len = file.metadata().map(|m| m.len()).map_err(|e| {
            format!(
                "unable to query metadata of KMIP credentials file {}: {e}",
                path.display()
            )
        })?;

        // Buffer reading as apparently JSON based file reading is extremely
        // slow without buffering, even for small files.
        let mut reader = BufReader::new(&file);

        // Load or create the credential set.
        let credentials: KmipClientCredentialsSet = if len > 0 {
            serde_json::from_reader(&mut reader).map_err(|e| {
                format!(
                    "error loading KMIP credentials file {:?}: {e}\n",
                    path.display()
                )
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
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| format!("seek to start failed: {e}"))?;

        // Use a buffered writer as writing JSON to a file directly is
        // apparently very slow, even for small files.
        //
        // Enclose the use of the BufWriter in a block so that it is
        // definitely no longer using the file when we next act on it.
        {
            let mut writer = BufWriter::new(&self.file);
            serde_json::to_writer_pretty(&mut writer, &self.credentials).map_err(|e| {
                format!(
                    "error writing KMIP credentials file {}: {e}",
                    self.path.display()
                )
            })?;

            // Ensure that the BufWriter is flushed as advised by the
            // BufWriter docs.
            writer.flush().map_err(|e| format!("flush failed: {e}"))?;
        }

        // Truncate the file to the length of data we just wrote..
        let pos = self
            .file
            .stream_position()
            .map_err(|e| format!("unable to get stream position: {e}"))?;
        self.file
            .set_len(pos)
            .map_err(|e| format!("unable to set file length: {e}"))?;

        // Ensure that any write buffers are flushed.
        self.file
            .flush()
            .map_err(|e| format!("flush failed: {e}"))?;

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

/// Configuration for KMIP TLS certificate verification.
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

/// Limits to be imposed on the KMIP client when commmunicating with a KMIP
/// server.
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

/// Whether and how to relabel KMIP keys with human readable labels.
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
            connect_timeout: Some(self.client_limits.connect_timeout),
            read_timeout: Some(self.client_limits.read_timeout),
            write_timeout: Some(self.client_limits.write_timeout),
            max_response_bytes: Some(self.client_limits.max_response_bytes),
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
        File::open(path)
            .map_err(|e| format!("unable to open {}: {e}", path.display()))?
            .read_to_end(&mut bytes)
            .map_err(|e| format!("reading from {} failed: {e}", path.display()))?;

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
pub struct KmipState {
    /// KMIP servers to use, keyed by user chosen HSM id.
    pub servers: HashMap<String, KmipServerConnectionConfig>,

    /// Which KMIP server should new keys be created in, if any?
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub default_server_id: Option<String>,

    /// The current set of KMIP server pools.
    #[serde(skip)]
    pub pools: HashMap<String, SyncConnPool>,
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
                    return Err(format!("No KMIP server config exists for server '{id}'").into());
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

/// Construct from parts a KMIP key label.
pub fn format_key_label(
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

/// Trnucate a zone name to a maximum length.
///
/// First attempt to truncate by removing labels under the TLD label, falling
/// back to truncating to N bytes from the start if needed.
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
