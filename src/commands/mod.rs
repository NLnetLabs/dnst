//! The command of _dnst_.

pub mod help;
pub mod nsec3hash;

use std::ffi::OsStr;
use std::str::FromStr;

use nsec3hash::Nsec3Hash;

use crate::Args;

use super::error::Error;

#[derive(Clone, Debug, clap::Subcommand)]
pub enum Command {
    /// Print the NSEC3 hash of a given domain name
    #[command(name = "nsec3-hash")]
    Nsec3Hash(self::nsec3hash::Nsec3Hash),

    /// Show the manual pages
    Help(self::help::Help),
}

impl Command {
    pub fn execute(self) -> Result<(), Error> {
        match self {
            Self::Nsec3Hash(nsec3hash) => nsec3hash.execute(),
            Self::Help(help) => help.execute(),
        }
    }
}

/// A command that can be invoked in an LDNS compatibility mode
///
/// These commands do their own argument parsing, because clap cannot always
/// (easily) parse arguments in the same way that the ldns tools do.
///
/// The `LdnsCommand::parse_ldns` function should parse arguments obtained
/// with [`std::env::args`] or [`std::env::args_os`] and return an error in
/// case of invalid arguments. The help string provided as
/// [`LdnsCommand::HELP`] is automatically appended to returned errors.
pub trait LdnsCommand: Into<Command> {
    const HELP: &'static str;

    fn parse_ldns() -> Result<Self, Error>;

    fn parse_ldns_args() -> Result<Args, Error> {
        match Self::parse_ldns() {
            Ok(c) => Ok(Args::from(c.into())),
            Err(e) => Err(format!("{e}\n\n{}", Self::HELP).into()),
        }
    }

    /// Utility function to parse an [`OsStr`] with a custom function
    fn parse_os_with<T, E>(
        opt: &str,
        val: &OsStr,
        f: impl Fn(&str) -> Result<T, E>,
    ) -> Result<T, Error>
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
        Self::parse_os_with(opt, val, T::from_str)
    }
}

impl From<Nsec3Hash> for Command {
    fn from(val: Nsec3Hash) -> Self {
        Command::Nsec3Hash(val)
    }
}
