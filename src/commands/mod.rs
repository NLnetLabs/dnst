//! The command of _dnst_.

pub mod help;
pub mod keygen;
pub mod nsec3hash;

use super::error::Error;

#[derive(Clone, Debug, clap::Subcommand)]
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
    #[command(name = "keygen", verbatim_doc_comment)]
    Keygen(self::keygen::Keygen),

    /// Print the NSEC3 hash of a given domain name
    #[command(name = "nsec3-hash")]
    Nsec3Hash(self::nsec3hash::Nsec3Hash),

    /// Show the manual pages
    Help(self::help::Help),
}

impl Command {
    pub fn execute(self) -> Result<(), Error> {
        match self {
            Self::Keygen(keygen) => keygen.execute(),
            Self::Nsec3Hash(nsec3hash) => nsec3hash.execute(),
            Self::Help(help) => help.execute(),
        }
    }
}
