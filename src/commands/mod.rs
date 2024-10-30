//! The command of _dnst_.

pub mod help;
pub mod notify;
pub mod nsec3hash;

use super::error::Error;

#[derive(Clone, Debug, clap::Subcommand)]
pub enum Command {
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
