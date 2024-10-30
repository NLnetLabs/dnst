//! The command of _dnst_.

pub mod help;
pub mod key2ds;
pub mod nsec3hash;

use super::error::Error;

#[derive(Clone, Debug, clap::Subcommand)]
pub enum Command {
    /// Print the NSEC3 hash of a given domain name
    #[command(name = "nsec3-hash")]
    Nsec3Hash(self::nsec3hash::Nsec3Hash),

    /// Generate a DS RR from the DNSKEYS in keyfile
    ///
    /// The following file will be created for each key:
    /// `K<name>+<alg>+<id>.ds`.The base name `K<name>+<alg>+<id>`
    /// will be printed to stdout.
    #[command(name = "key2ds")]
    Key2ds(key2ds::Key2ds),

    /// Show the manual pages
    Help(self::help::Help),
}

impl Command {
    pub fn execute(self) -> Result<(), Error> {
        match self {
            Self::Nsec3Hash(nsec3hash) => nsec3hash.execute(),
            Self::Key2ds(key2ds) => key2ds.execute(),
            Self::Help(help) => help.execute(),
        }
    }
}
