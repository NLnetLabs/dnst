//! The command of _dnst_.

pub mod help;
pub mod nsec3hash;
pub mod update;

use update::Update;

use super::error::Error;

#[derive(Clone, Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Print the NSEC3 hash of a given domain name
    #[command(name = "nsec3-hash")]
    Nsec3Hash(self::nsec3hash::Nsec3Hash),

    /// Send an UPDATE packet
    #[command(name = "update")]
    Update(self::update::Update),

    /// Show the manual pages
    Help(self::help::Help),
}

impl Command {
    pub fn execute(self) -> Result<(), Error> {
        match self {
            Self::Nsec3Hash(nsec3hash) => nsec3hash.execute(),
            Self::Update(update) => update.execute(),
            Self::Help(help) => help.execute(),
        }
    }

    pub fn parse_ldns_args(name: &str, args: &[String]) -> Result<Option<Self>, Error> {
        Ok(Some(match name {
            "ldns-update" => Self::Update(Update::parse_ldns_args(args)?),
            _ => return Ok(None),
        }))
    }
}
