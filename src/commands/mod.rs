//! The command of _dnst_.
pub mod help;
pub mod key2ds;
pub mod keygen;
pub mod notify;
pub mod nsec3hash;
pub mod update;

use clap::crate_version;
use std::ffi::{OsStr, OsString};
use std::str::FromStr;

use crate::env::Env;
use crate::Args;

use super::error::Error;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Generate a new key pair for a given domain name
    ///
    /// The following files will be created:
    ///
    /// - K<name>+<alg>+<tag>.key: The public key file
    ///
    ///   This is a DNSKEY resource record in zone file format.
    ///
    /// - K<name>+<alg>+<tag>.private: The private key file
    ///
    ///   This is a text file in the conventional BIND format which
    ///   contains fields describing the private key data.
    ///
    /// - K<name>+<alg>+<tag>.ds: The public key digest file
    ///
    ///   This is a DS resource record in zone file format.
    ///   It is only created for key signing keys.
    ///
    /// <name> is the fully-qualified owner name for the key (with a trailing dot).
    /// <alg> is the algorithm number of the key, zero-padded to 3 digits.
    /// <tag> is the 16-bit tag of the key, zero-padded to 5 digits.
    ///
    /// Upon completion, 'K<name>+<alg>+<tag>' will be printed.
    #[allow(rustdoc::invalid_html_tags)]
    #[command(name = "keygen", verbatim_doc_comment)]
    Keygen(self::keygen::Keygen),

    /// Print the NSEC3 hash of a given domain name
    #[command(name = "nsec3-hash")]
    Nsec3Hash(self::nsec3hash::Nsec3Hash),

    /// Send a NOTIFY packet to DNS servers
    ///
    /// This tells them that an updated zone is available at the primaries. It can perform TSIG
    /// signatures and it can add a SOA serial number of the updated zone. If a server already has
    /// that serial number it will disregard the message.
    #[command(name = "notify")]
    Notify(self::notify::Notify),

    /// Generate a DS RR from the DNSKEYS in keyfile
    ///
    /// The following file will be created for each key:
    /// `K<name>+<alg>+<id>.ds`. The base name `K<name>+<alg>+<id>`
    /// will be printed to stdout.
    #[command(name = "key2ds")]
    Key2ds(key2ds::Key2ds),

    /// Send an UPDATE packet
    #[command(name = "update")]
    Update(self::update::Update),

    /// Show the manual pages
    Help(self::help::Help),

    /// Report a string to stdout
    ///
    /// This is used for printing version information and some other
    /// information.
    #[command(skip)]
    Report(String),
}

impl Command {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        match self {
            Self::Keygen(keygen) => keygen.execute(env),
            Self::Nsec3Hash(nsec3hash) => nsec3hash.execute(env),
            Self::Key2ds(key2ds) => key2ds.execute(env),
            Self::Notify(notify) => notify.execute(env),
            Self::Update(update) => update.execute(env),
            Self::Help(help) => help.execute(),
            Self::Report(s) => {
                writeln!(env.stdout(), "{s}");
                Ok(())
            }
        }
    }
}

/// A command that can be invoked in an LDNS compatibility mode
///
/// These commands do their own argument parsing, because clap cannot always
/// (easily) parse arguments in the same way that the ldns tools do.
///
/// The [`LdnsCommand::parse_ldns`] function should parse arguments and
/// return an error in case of a parsing failure. The help string provided
/// as [`LdnsCommand::HELP`] is automatically appended to returned errors.
pub trait LdnsCommand {
    const NAME: &'static str;
    const HELP: &'static str;
    const COMPATIBLE_VERSION: &'static str;

    fn parse_ldns<I: IntoIterator<Item = OsString>>(args: I) -> Result<Args, Error>;

    fn parse_ldns_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<Args, Error> {
        match Self::parse_ldns(args) {
            Ok(c) => Ok(c),
            Err(e) => Err(format!("{e}\n\n{}", Self::HELP).into()),
        }
    }

    fn report_help() -> Args {
        Args::from(Command::Report(Self::HELP.into()))
    }

    fn report_version() -> Args {
        let s = format!(
            "ldns-{} provided by dnst v{} (compatible with ldns v{})",
            Self::NAME,
            crate_version!(),
            Self::COMPATIBLE_VERSION,
        );
        Args::from(Command::Report(s))
    }
}

/// Utility function to parse an [`OsStr`] with a custom function
fn parse_os_with<T, E>(opt: &str, val: &OsStr, f: impl Fn(&str) -> Result<T, E>) -> Result<T, Error>
where
    E: std::fmt::Display,
{
    let Some(s) = val.to_str() else {
        return Err(format!("Invalid value for {opt}: {val:?} is not valid unicode",).into());
    };

    f(s).map_err(|e| format!("Invalid value {val:?} for {opt}: {e}").into())
}

/// Utility function to parse an [`OsStr`] into a value via [`FromStr`]
fn parse_os<T: FromStr>(opt: &str, val: &OsStr) -> Result<T, Error>
where
    T::Err: std::fmt::Display,
{
    parse_os_with(opt, val, T::from_str)
}
