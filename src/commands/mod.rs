//! The command of _dnst_.

pub mod help;
pub mod nsec3hash;
pub mod notify;

use super::error::Error;

#[derive(Clone, Debug, clap::Subcommand)]
pub enum Command {
    /// Print the NSEC3 hash of a given domain name
    #[command(name = "nsec3-hash")]
    Nsec3Hash(self::nsec3hash::Nsec3Hash),

    /// Sends a NOTIFY message to DNS servers
    #[command(name = "notify")]
    Notify(self::notify::Notify),

    /// Show the manual pages
    Help(self::help::Help),
}

impl Command {
    pub fn execute(self) -> Result<(), Error> {
        match self {
            Self::Nsec3Hash(nsec3hash) => nsec3hash.execute(),
            Self::Notify(notify) => notify.execute(),
            Self::Help(help) => help.execute(),
        }
    }
}
