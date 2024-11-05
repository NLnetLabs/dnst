//! The command of _dnst_.

pub mod help;
pub mod nsec3hash;
pub mod signzone;

use super::error::Error;

#[derive(Clone, Debug, clap::Subcommand)]
pub enum Command {
    /// Prints the NSEC3 hash of a given domain name
    #[command(name = "nsec3-hash")]
    Nsec3Hash(self::nsec3hash::Nsec3Hash),

    /// Signs the zone with the given key(s)
    #[command(name = "signzone")]
    SignZone(self::signzone::SignZone),

    /// Show the manual pages
    Help(self::help::Help),
}

impl Command {
    pub fn execute(self) -> Result<(), Error> {
        match self {
            Self::Nsec3Hash(nsec3hash) => nsec3hash.execute(),
            Self::SignZone(signzone) => signzone.execute(),
            Self::Help(help) => help.execute(),
        }
    }
}
