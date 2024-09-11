//! The command of _dnst_.

pub mod help;
pub mod nsec3hash;
pub mod keygen;

use super::error::Error;

#[derive(Clone, Debug, clap::Subcommand)]
pub enum Command {
    /// Print the NSEC3 hash of a given domain name
    #[command(name = "nsec3-hash")]
    Nsec3Hash(self::nsec3hash::Nsec3Hash),

    /// Generate a new key pair for a domain, creating the following files:
    ///   K<name>+<alg>+<id>.key        Public key in RR format
    ///   K<name>+<alg>+<id>.private    Private key in key format
    ///   K<name>+<alg>+<id>.ds         DS in RR format (only for DNSSEC KSKs)
    /// The base name (K<name>+<alg>+<id>) will be printed to stdout
    #[command(version, verbatim_doc_comment)]
    KeyGen(self::keygen::KeyGen),

    /// Show the manual pages
    Help(self::help::Help),
}

impl Command {
    pub fn execute(self) -> Result<(), Error> {
        match self {
            Self::Nsec3Hash(nsec3hash) => nsec3hash.execute(),
            Self::KeyGen(keygen) => keygen.execute(),
            Self::Help(help) => help.execute(),
        }
    }
}
