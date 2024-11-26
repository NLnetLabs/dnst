use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

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

#[derive(Clone, Debug, PartialEq, Eq, Args)]
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

        let base = format!(
            "K{}+{:03}+{:05}",
            self.name.fmt_with_dot(),
            public_key.algorithm().to_int(),
            public_key.key_tag()
        );

        let secret_key_path = format!("{base}.private");
        let public_key_path = format!("{base}.key");
        let digest_file_path = self.make_ksk.then(|| format!("{base}.ds"));

        let mut secret_key_file = env.fs_create_new(&secret_key_path)?;
        let mut public_key_file = env.fs_create_new(&public_key_path)?;
        let mut digest_file = digest_file_path
            .as_ref()
            .map(|digest_file_path| env.fs_create_new(digest_file_path))
            .transpose()?;

        Self::symlink(&secret_key_path, ".private", self.symlink, &env)?;
        Self::symlink(&public_key_path, ".key", self.symlink, &env)?;
        if let Some(digest_file_path) = &digest_file_path {
            Self::symlink(&digest_file_path, ".ds", self.symlink, &env)?;
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

        // Let the user know what the base name of the files is.
        writeln!(stdout, "{}", base);

        Ok(())
    }

    /// Create a symlink to the given location.
    fn symlink(
        target: impl AsRef<Path>,
        link: impl AsRef<Path>,
        how: SymlinkArg,
        env: &impl Env,
    ) -> Result<(), Error> {
        #[cfg(unix)]
        match how {
            SymlinkArg::No => Ok(()),
            SymlinkArg::Yes => env.fs_symlink(target, link),
            SymlinkArg::Force => env.fs_symlink_force(target, link),
        }

        #[cfg(not(unix))]
        if how.create() {
            Err("Symlinks can only be created on Unix platforms".into())
        }
    }
}

#[cfg(test)]
mod test {
    use domain::sign::GenerateParams;
    use regex::Regex;

    use crate::commands::Command;
    use crate::env::fake::FakeCmd;

    use super::{Keygen, SymlinkArg};

    #[track_caller]
    fn parse(args: FakeCmd) -> Keygen {
        let res = args.parse();
        let Command::Keygen(x) = res.unwrap().command else {
            panic!("Not a Keygen!");
        };
        x
    }

    #[test]
    fn dnst_parse() {
        let cmd = FakeCmd::new(["dnst", "keygen"]);

        // Algorithm and domain name are needed.
        let _ = cmd.parse().unwrap_err();

        // Multiple domain names cannot be provided.
        let _ = cmd
            .args(["foo.example.org", "bar.example.org"])
            .parse()
            .unwrap_err();

        let base = Keygen {
            algorithm: GenerateParams::Ed25519,
            make_ksk: false,
            symlink: SymlinkArg::No,
            name: "example.org".parse().unwrap(),
        };

        // The simplest invocation.
        assert_eq!(parse(cmd.args(["-a", "ED25519", "example.org"])), base);

        // Test 'algorithm':
        // - RSA-SHA256 uses 2048 bits by default.
        assert_eq!(
            parse(cmd.args(["-a", "RSASHA256", "example.org"])),
            Keygen {
                algorithm: GenerateParams::RsaSha256 { bits: 2048 },
                ..base.clone()
            }
        );
        // - RSA-SHA256 accepts other key sizes.
        assert_eq!(
            parse(cmd.args(["-a", "RSASHA256:1024", "example.org"])),
            Keygen {
                algorithm: GenerateParams::RsaSha256 { bits: 1024 },
                ..base.clone()
            }
        );

        // Test 'make_ksk':
        assert_eq!(
            parse(cmd.args(["-a", "ED25519", "-k", "example.org"])),
            Keygen {
                make_ksk: true,
                ..base.clone()
            }
        );

        // Test 'symlink':
        // - Symlinks can be disabled.
        for symlink in ["-s=no", "--symlink=no"] {
            assert_eq!(
                parse(cmd.args(["-a", "ED25519", symlink, "example.org"])),
                Keygen {
                    symlink: SymlinkArg::No,
                    ..base.clone()
                }
            );
        }
        // - Symlinks can be enabled.
        for symlink in ["-s", "-s=yes", "--symlink", "--symlink=yes"] {
            assert_eq!(
                parse(cmd.args(["-a", "ED25519", symlink, "example.org"])),
                Keygen {
                    symlink: SymlinkArg::Yes,
                    ..base.clone()
                }
            );
        }
        // - Symlinks can be enabled with overwriting.
        for symlink in ["-s=force", "--symlink=force"] {
            assert_eq!(
                parse(cmd.args(["-a", "ED25519", symlink, "example.org"])),
                Keygen {
                    symlink: SymlinkArg::Force,
                    ..base.clone()
                }
            );
        }

        // Test 'name':
        // - Domain names can have a trailing dot.
        assert_eq!(parse(cmd.args(["-a", "ED25519", "example.org."])), base);
    }

    #[test]
    fn ldns_parse() {
        let cmd = FakeCmd::new(["ldns-keygen"]);

        // Algorithm and domain name are needed.
        let _ = cmd.parse().unwrap_err();

        // Multiple domain names cannot be provided.
        let _ = cmd
            .args(["foo.example.org", "bar.example.org"])
            .parse()
            .unwrap_err();

        let base = Keygen {
            algorithm: GenerateParams::Ed25519,
            make_ksk: false,
            symlink: SymlinkArg::No,
            name: "example.org".parse().unwrap(),
        };

        // The simplest invocation.
        assert_eq!(parse(cmd.args(["-a", "ED25519", "example.org"])), base);

        // Test 'algorithm':
        // - RSA-SHA256 uses 2048 bits by default.
        assert_eq!(
            parse(cmd.args(["-a", "RSASHA256", "example.org"])),
            Keygen {
                algorithm: GenerateParams::RsaSha256 { bits: 2048 },
                ..base.clone()
            }
        );
        // - RSA-SHA256 accepts other key sizes.
        assert_eq!(
            parse(cmd.args(["-a", "RSASHA256", "-b", "1024", "example.org"])),
            Keygen {
                algorithm: GenerateParams::RsaSha256 { bits: 1024 },
                ..base.clone()
            }
        );

        // Test 'make_ksk':
        assert_eq!(
            parse(cmd.args(["-a", "ED25519", "-k", "example.org"])),
            Keygen {
                make_ksk: true,
                ..base.clone()
            }
        );

        // Test 'symlink':
        // - Symlinks can be enabled.
        assert_eq!(
            parse(cmd.args(["-a", "ED25519", "-s", "example.org"])),
            Keygen {
                symlink: SymlinkArg::Yes,
                ..base.clone()
            }
        );
        // - Symlinks can be enabled with overwriting.
        assert_eq!(
            parse(cmd.args(["-a", "ED25519", "-s", "-f", "example.org"])),
            Keygen {
                symlink: SymlinkArg::Force,
                ..base.clone()
            }
        );
        // - '-f' without '-s' does not enable symlinks.
        assert_eq!(
            parse(cmd.args(["-a", "ED25519", "-f", "example.org"])),
            Keygen {
                symlink: SymlinkArg::No,
                ..base.clone()
            }
        );

        // Test 'name':
        // - Domain names can have a trailing dot.
        assert_eq!(parse(cmd.args(["-a", "ED25519", "example.org."])), base);
    }

    #[test]
    fn simple() {
        let dir = tempfile::TempDir::new().unwrap();
        let res = FakeCmd::new(["dnst", "keygen", "-a", "ED25519", "example.org"])
            .cwd(&dir)
            .run();

        let name_regex = Regex::new(r"^Kexample\.org\.\+015\+[0-9]{5}$").unwrap();
        let public_key_regex =
            Regex::new(r"^example.org. IN DNSKEY 256 3 15 [A-Za-z0-9/+=]+").unwrap();
        let secret_key_regex = Regex::new(
            r"^Private-key-format: v1\.2\nAlgorithm: 15 \(ED25519\)\nPrivateKey: [A-Za-z0-9/+=]+\n$",
        )
        .unwrap();

        assert_eq!(res.exit_code, 0, "{res:?}");
        assert_eq!(res.stderr, "");

        let name = res.stdout.trim();
        assert!(name_regex.is_match(name));

        let public_key = std::fs::read_to_string(dir.path().join(format!("{name}.key"))).unwrap();
        assert!(public_key_regex.is_match(&public_key));

        // The digest file must not be created.
        assert!(!dir.path().join("{name}.ds").try_exists().unwrap());

        let secret_key =
            std::fs::read_to_string(dir.path().join(format!("{name}.private"))).unwrap();
        assert!(secret_key_regex.is_match(&secret_key));
    }

    #[test]
    fn simple_ksk() {
        let dir = tempfile::TempDir::new().unwrap();
        let res = FakeCmd::new(["dnst", "keygen", "-k", "-a", "ED25519", "example.org"])
            .cwd(&dir)
            .run();

        let name_regex = Regex::new(r"^Kexample\.org\.\+015\+[0-9]{5}$").unwrap();
        let public_key_regex =
            Regex::new(r"^example.org. IN DNSKEY 257 3 15 [A-Za-z0-9/+=]+").unwrap();
        let digest_key_regex =
            Regex::new(r"^example.org. IN DS [0-9]+ 15 2 [0-9a-fA-F]+\n$").unwrap();

        assert_eq!(res.exit_code, 0, "{res:?}");
        assert_eq!(res.stderr, "");

        let name = res.stdout.trim();
        assert!(name_regex.is_match(name));

        let public_key = std::fs::read_to_string(dir.path().join(format!("{name}.key"))).unwrap();
        assert!(public_key_regex.is_match(&public_key));

        let digest_key = std::fs::read_to_string(dir.path().join(format!("{name}.ds"))).unwrap();
        assert!(digest_key_regex.is_match(&digest_key));

        assert!(dir
            .path()
            .join(format!("{name}.private"))
            .try_exists()
            .unwrap());
    }
}
