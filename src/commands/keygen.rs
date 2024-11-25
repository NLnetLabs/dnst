use std::ffi::OsString;
use std::fs::File;
use std::io::Write;

use clap::{builder::ValueParser, Args, ValueEnum};
use domain::base::iana::{DigestAlg, SecAlg};
use domain::base::name::Name;
use domain::base::zonefile_fmt::ZonefileFmt;
use domain::sign::{common, GenerateParams};
use domain::validate::Key;
use lexopt::Arg;

use crate::env::Env;
use crate::error::{Context, Error};
use crate::parse::parse_name;

use super::{parse_os, parse_os_with, Command, LdnsCommand};

#[derive(Clone, Debug, Args)]
pub struct Keygen {
    /// The signature algorithm to generate for
    ///
    /// Possible values:
    /// - RSASHA256[:<bits>]: An RSA SHA-256 key (algorithm 8) of the given size (default 2048)
    /// - ECDSAP256SHA256:    An ECDSA P-256 SHA-256 key (algorithm 13)
    /// - ECDSAP384SHA384:    An ECDSA P-384 SHA-384 key (algorithm 14)
    /// - ED25519:            An Ed25519 key (algorithm 15)
    /// - ED448:              An Ed448 key (algorithm 16)
    #[arg(
        short = 'a',
        long = "algorithm",
        value_name = "ALGORITHM",
        value_parser = ValueParser::new(Keygen::parse_algorithm),
        verbatim_doc_comment,
    )]
    algorithm: GenerateParams,

    /// Generate a key signing key instead of a zone signing key
    #[arg(short = 'k')]
    make_ksk: bool,

    /// Whether to create symlinks.
    #[arg(short, long, value_enum, num_args = 0..=1, require_equals = true, default_missing_value = "yes", default_value = "no")]
    symlink: SymlinkArg,

    /// The domain name to generate a key for
    #[arg(value_name = "domain name", value_parser = ValueParser::new(parse_name))]
    name: Name<Vec<u8>>,
}

/// Symlinking behaviour.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum SymlinkArg {
    /// Don't create symlinks.
    No,

    /// Create symlinks, but don't overwrite existing ones.
    Yes,

    /// Create symlinks, overwriting existing ones.
    Force,
}

impl SymlinkArg {
    /// Whether symlinks should be created.
    pub fn create(&self) -> bool {
        matches!(self, Self::Yes | Self::Force)
    }

    /// Whether symlinks should be forced.
    pub fn force(&self) -> bool {
        matches!(self, Self::Force)
    }
}

const LDNS_HELP: &str = "\
ldns-keygen -a <algorithm> [-b bits] [-r /dev/random] [-s] [-f] [-v] domain
  generate a new key pair for domain
  -a <alg>	use the specified algorithm (-a list to show a list)
  -k		set the flags to 257; key signing key
  -b <bits>	specify the keylength (only used for RSA keys)
  -r <random>	randomness device (unused)
  -s		create additional symlinks with constant names
  -f		force override of existing symlinks
  -v		show the version and exit
  The following files will be created:
    K<name>+<alg>+<id>.key	Public key in RR format
    K<name>+<alg>+<id>.private	Private key in key format
    K<name>+<alg>+<id>.ds	DS in RR format (only for DNSSEC KSK keys)
  The base name (K<name>+<alg>+<id>) will be printed to stdout
";

impl LdnsCommand for Keygen {
    const HELP: &'static str = LDNS_HELP;

    fn parse_ldns<I: IntoIterator<Item = OsString>>(args: I) -> Result<Self, Error> {
        let mut algorithm = None;
        let mut make_ksk = false;
        let mut bits = 2048;
        let mut create_symlinks = false;
        let mut force_symlinks = false;
        let mut name = None;

        let mut parser = lexopt::Parser::from_args(args);

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Short('a') => {
                    if algorithm.is_some() {
                        return Err("cannot specify algorithm (-a) more than once".into());
                    }

                    algorithm = parse_os_with("algorithm (-a)", &parser.value()?, |s| {
                        Ok(match s {
                            "list" => {
                                // TODO: Mock stdout and process exit?
                                println!("Possible algorithms:");
                                println!("  - RSASHA256 (8)");
                                println!("  - ECDSAP256SHA256 (13)");
                                println!("  - ECDSAP384SHA384 (14)");
                                println!("  - ED25519 (15)");
                                println!("  - ED448 (16)");
                                std::process::exit(0);
                            }

                            "RSASHA256" | "8" => Some(SecAlg::RSASHA256),
                            "ECDSAP256SHA256" | "13" => Some(SecAlg::ECDSAP256SHA256),
                            "ECDSAP384SHA384" | "14" => Some(SecAlg::ECDSAP384SHA384),
                            "ED25519" | "15" => Some(SecAlg::ED25519),
                            "ED448" | "16" => Some(SecAlg::ED448),

                            _ => {
                                return Err(format!("Invalid value {s:?} for algorithm (-a)"));
                            }
                        })
                    })?;
                }

                Arg::Short('k') => {
                    // NOTE: '-k' can be repeated, to no effect.
                    make_ksk = true;
                }

                Arg::Short('b') => {
                    // NOTE: '-b' can be repeated; the last instance wins.
                    bits = parse_os("bits (-b)", &parser.value()?)?;
                }

                Arg::Short('r') => {
                    // NOTE: '-r' can be repeated; we don't use it, so the order doesn't matter.
                    let _ = parser.value()?;
                }

                Arg::Short('s') => {
                    // NOTE: '-s' can be repeated, to no effect.
                    create_symlinks = true;
                }

                Arg::Short('f') => {
                    // NOTE: '-f' can be repeated, to no effect.
                    force_symlinks = true;
                }

                // TODO: '-v' version argument?
                Arg::Value(value) => {
                    if name.is_some() {
                        return Err("cannot specify multiple domain names".into());
                    }

                    name = Some(parse_os("domain name", &value)?);
                }

                Arg::Short(x) => return Err(format!("Invalid short option: -{x}").into()),
                Arg::Long(x) => {
                    return Err(format!("Long options are not supported, but `--{x}` given").into())
                }
            }
        }

        let algorithm = match algorithm {
            Some(SecAlg::RSASHA256) => GenerateParams::RsaSha256 { bits },
            Some(SecAlg::ECDSAP256SHA256) => GenerateParams::EcdsaP256Sha256,
            Some(SecAlg::ECDSAP384SHA384) => GenerateParams::EcdsaP384Sha384,
            Some(SecAlg::ED25519) => GenerateParams::Ed25519,
            Some(SecAlg::ED448) => GenerateParams::Ed448,
            Some(_) => unreachable!(),
            None => {
                return Err("Missing algorithm (-a) option".into());
            }
        };

        let symlink = match (create_symlinks, force_symlinks) {
            (true, true) => SymlinkArg::Force,
            (true, false) => SymlinkArg::Yes,
            // If only '-f' is specified, no symlinking is done.
            (false, _) => SymlinkArg::No,
        };

        let Some(name) = name else {
            return Err("Missing domain name argument".into());
        };

        Ok(Self {
            algorithm,
            make_ksk,
            symlink,
            name,
        })
    }
}

impl From<Keygen> for Command {
    fn from(value: Keygen) -> Self {
        Self::Keygen(value)
    }
}

impl Keygen {
    fn parse_algorithm(value: &str) -> Result<GenerateParams, clap::Error> {
        match value {
            "RSASHA256" => return Ok(GenerateParams::RsaSha256 { bits: 2048 }),
            "ECDSAP256SHA256" => return Ok(GenerateParams::EcdsaP256Sha256),
            "ECDSAP384SHA384" => return Ok(GenerateParams::EcdsaP384Sha384),
            "ED25519" => return Ok(GenerateParams::Ed25519),
            "ED448" => return Ok(GenerateParams::Ed448),
            _ => {}
        }

        // TODO: Remove attrs when more RSA algorithms are added.
        #[allow(clippy::collapsible_match)]
        if let Some((name, params)) = value.split_once(':') {
            #[allow(clippy::single_match)]
            match name {
                "RSASHA256" => {
                    let bits: u32 = params.parse().map_err(|err| {
                        clap::Error::raw(
                            clap::error::ErrorKind::InvalidValue,
                            format!("invalid RSA key size '{params}': {err}"),
                        )
                    })?;
                    return Ok(GenerateParams::RsaSha256 { bits });
                }
                _ => {}
            }
        }

        Err(clap::Error::raw(
            clap::error::ErrorKind::InvalidValue,
            format!("unrecognized algorithm '{value}'"),
        ))
    }

    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        let mut stdout = env.stdout();

        let params = self.algorithm;

        // The digest algorithm is selected based on the key algorithm.
        let digest_alg = match params.algorithm() {
            SecAlg::RSASHA256 => DigestAlg::SHA256,
            SecAlg::ECDSAP256SHA256 => DigestAlg::SHA256,
            SecAlg::ECDSAP384SHA384 => DigestAlg::SHA384,
            SecAlg::ED25519 => DigestAlg::SHA256,
            SecAlg::ED448 => DigestAlg::SHA256,
            _ => unreachable!(),
        };

        // Generate the key.
        // TODO: Attempt repeated generation to avoid key tag collisions.
        let (secret_key, public_key) = common::generate(params)
            .map_err(|err| format!("an implementation error occurred: {err}").into())
            .context("generating a cryptographic keypair")?;
        // TODO: Add a high-level operation in 'domain' to select flags?
        let flags = if self.make_ksk { 257 } else { 256 };
        let public_key = Key::new(self.name.clone(), flags, public_key);
        let digest = self.make_ksk.then(|| {
            public_key
                .digest(digest_alg)
                .expect("only supported digest algorithms are used")
        });

        // Open the appropriate files to write the key.
        let base = format!(
            "K{}+{:03}+{:05}",
            self.name.fmt_with_dot(),
            public_key.algorithm().to_int(),
            public_key.key_tag()
        );
        // TODO: Adjust for how 'Env' mocks the current directory.
        let mut secret_key_file = File::create_new(format!("{base}.private"))
            .map_err(|err| format!("cannot create '{base}.private': {err}"))?;
        let mut public_key_file = File::create_new(format!("{base}.key"))
            .map_err(|err| format!("public key file '{base}.key' already existed: {err}"))?;
        let mut digest_file = self
            .make_ksk
            .then(|| File::create_new(format!("{base}.ds")))
            .transpose()
            .map_err(|err| format!("digest file '{base}.ds' already existed: {err}"))?;

        #[cfg(unix)]
        if self.symlink.create() {
            if let Ok(metadata) = std::fs::symlink_metadata(".private") {
                if self.symlink.force() {
                    if metadata.is_symlink() {
                        std::fs::remove_file(".private")
                            .map_err(|err| format!("could not remove symlink '.private': {err}"))?;
                    } else {
                        return Err("'.private' already exists but is not a symlink".into());
                    }
                } else {
                    return Err("'.private' already exists".into());
                }
            }

            if let Ok(metadata) = std::fs::symlink_metadata(".key") {
                if self.symlink.force() {
                    if metadata.is_symlink() {
                        std::fs::remove_file(".key")
                            .map_err(|err| format!("could not remove symlink '.key': {err}"))?;
                    } else {
                        return Err("'.key' already exists but is not a symlink".into());
                    }
                } else {
                    return Err("'.key' already exists".into());
                }
            }

            if digest_file.is_some() {
                if let Ok(metadata) = std::fs::symlink_metadata(".ds") {
                    if self.symlink.force() {
                        if metadata.is_symlink() {
                            std::fs::remove_file(".ds")
                                .map_err(|err| format!("could not remove symlink '.ds': {err}"))?;
                        } else {
                            return Err("'.ds' already exists but is not a symlink".into());
                        }
                    } else {
                        return Err("'.ds' already exists".into());
                    }
                }
            }
        }

        #[cfg(not(unix))]
        if self.symlink.create() {
            return Err("Symlinks can only be created on Unix platforms".into());
        }

        // Prepare the contents to write.
        let secret_key = secret_key.display_as_bind().to_string();
        let public_key = public_key.display_as_bind().to_string();
        let digest = digest.map(|digest| {
            format!(
                "{} IN DS {}\n",
                self.name.fmt_with_dot(),
                digest.display_zonefile(false)
            )
        });

        // Write the key files.
        secret_key_file
            .write_all(secret_key.as_bytes())
            .map_err(|err| {
                format!("error while writing private key file '{base}.private': {err}")
            })?;
        public_key_file
            .write_all(public_key.as_bytes())
            .map_err(|err| format!("error while writing public key file '{base}.key': {err}"))?;
        if let Some(digest_file) = digest_file.as_mut() {
            digest_file
                .write_all(digest.unwrap().as_bytes())
                .map_err(|err| format!("error while writing digest file '{base}.ds': {err}"))?;
        }

        secret_key_file.sync_all().map_err(|err| {
            format!("error while writing private key file '{base}.private': {err}")
        })?;
        public_key_file
            .sync_all()
            .map_err(|err| format!("error while writing public key file '{base}.key': {err}"))?;
        if let Some(digest_file) = digest_file.as_mut() {
            digest_file
                .sync_all()
                .map_err(|err| format!("error while writing digest file '{base}.ds': {err}"))?;
        }

        #[cfg(target_family = "unix")]
        if self.symlink.create() {
            use std::os::unix::fs;

            fs::symlink(format!("{base}.key"), ".key")
                .map_err(|err| format!("could not create symlink '.key': {err}"))?;
            fs::symlink(format!("{base}.private"), ".private")
                .map_err(|err| format!("could not create symlink '.private': {err}"))?;
            if digest_file.is_some() {
                fs::symlink(format!("{base}.ds"), ".ds")
                    .map_err(|err| format!("could not create symlink '.ds': {err}"))?;
            }
        }

        // Let the user know what the base name of the files is.
        writeln!(stdout, "{}", base);

        Ok(())
    }
}
