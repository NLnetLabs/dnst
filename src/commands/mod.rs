//! The command of _dnst_.
pub mod help;
pub mod nsec3hash;

use std::io::Write;

use super::error::Error;

#[derive(Clone, Debug, clap::Subcommand)]
pub enum Command {
    /// Prints the NSEC3 hash of a given domain name
    #[command(name = "nsec3-hash")]
    Nsec3Hash(self::nsec3hash::Nsec3Hash),

    /// Show the manual pages
    Help(self::help::Help),
}

impl Command {
    pub fn execute<W: Write>(self, writer: &mut W) -> Result<(), Error> {
        match self {
            Self::Nsec3Hash(nsec3hash) => nsec3hash.execute(writer),
            Self::Help(help) => help.execute(),
        }
    }
}
