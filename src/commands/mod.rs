//! The command of _dnst_.

pub mod help;
pub mod nsec3hash;
pub mod update;

use super::error::Error;

#[derive(Clone, Debug, clap::Subcommand)]
pub enum Command {
    /// Print the NSEC3 hash of a given domain name
    #[command(name = "nsec3-hash")]
    Nsec3Hash(self::nsec3hash::Nsec3Hash),

    /// Send a dynamic update packet to update an IP (or delete all existing IPs) for a domain name
    #[command(name = "update", override_usage = self::update::UPDATE_USAGE)]
    Update(self::update::Update),

    /// Show the manual pages
    Help(self::help::Help),
}

impl Command {
    pub fn execute(self) -> Result<(), Error> {
        match self {
            Self::Nsec3Hash(nsec3hash) => nsec3hash.execute(),
            Self::Help(help) => help.execute(),
            Self::Update(update) => update.execute(),
        }
    }
}
