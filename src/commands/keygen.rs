use core::fmt;
use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

use clap::builder::ValueParser;
use clap::ValueEnum;
use domain::base::iana::{DigestAlgorithm, SecurityAlgorithm};
use domain::base::name::Name;
use domain::base::zonefile_fmt::{DisplayKind, ZonefileFmt};
use domain::crypto::sign::GenerateParams;
use domain::dnssec::validator::base::DnskeyExt;
use domain::rdata::Ds;
use lexopt::Arg;

use crate::env::Env;
use crate::error::{Context, Error};
use crate::parse::parse_name;
use crate::{util, Args, DISPLAY_KIND};

use super::{parse_os, parse_os_with, Command, LdnsCommand};

#[cfg(not(any(feature = "openssl", feature = "ring")))]
compile_error!("Either the 'openssl' or the 'ring' feature (or both) must be enabled");

#[derive(Clone, Debug, PartialEq, Eq, clap::Args)]
pub struct Keygen {
    /// The signature algorithm to generate for
    ///
    /// Possible values:
    /// - RSASHA256:          An RSA SHA-256 key (algorithm 8)
    /// - ECDSAP256SHA256:    An ECDSA P-256 SHA-256 key (algorithm 13)
    /// - ECDSAP384SHA384:    An ECDSA P-384 SHA-384 key (algorithm 14)
    /// - ED25519:            An Ed25519 key (algorithm 15)
    #[cfg_attr(
        feature = "openssl",
        doc = " - ED448:              An Ed448 key (algorithm 16)"
    )]
    ///
    /// Tip: Using the algorithm number instead of the name is also supported.
    #[allow(rustdoc::invalid_html_tags)]
    #[arg(
        short = 'a',
        long = "algorithm",
        value_name = "algorithm",
        value_parser = ValueParser::new(Keygen::parse_algorithm),
        verbatim_doc_comment,
    )]
    algorithm: SecurityAlgorithm,

    /// The length of the key (for RSA keys only)
    #[arg(
        short = 'b',
        long = "bits",
        value_name = "bits",
        default_value = "2048"
    )]
    bits: u32,

    /// Generate a key signing key instead of a zone signing key
    #[arg(short = 'k')]
    make_ksk: bool,

    /// Whether to create symlinks.
    //
    // We want to allow '-s' / '--symlink' to mean 'Symlink::Yes' for convenience.
    // Clap supports this through 'default_missing_value', but it also requires
    // 'num_args' and 'require_equals' to be explicitly set.
    //
    // In the end, this can be used as:
    // - '-s=no' / '--symlink=no':       Symlink::No (also the default)
    // - '-s' / '--symlink':             Symlink::Yes (convenient form)
    // - '-s=yes' / '--symlink=yes':     Symlink::Yes
    // - '-s=force' / '--symlink=force': Symlink::Force
    #[arg(
        short = 's',
        long = "symlink",
        value_enum,
        value_name = "how",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "yes",
        default_value = "no",
    )]
    symlink: SymlinkArg,

    /// The domain name to generate a key for
    #[arg(value_name = "domain", value_parser = ValueParser::new(parse_name))]
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

fn ldns_algs_help() -> String {
    struct Printer;

    impl fmt::Display for Printer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Supported algorithms:")?;
            f.write_str("\n- RSASHA256 (8)")?;
            f.write_str("\n- ECDSAP256SHA256 (13)")?;
            f.write_str("\n- ECDSAP384SHA384 (14)")?;
            f.write_str("\n- ED25519 (15)")?;
            #[cfg(feature = "openssl")]
            f.write_str("\n- ED448 (16)")?;
            Ok(())
        }
    }

    format!("{Printer}")
}

impl LdnsCommand for Keygen {
    const NAME: &'static str = "keygen";
    const HELP: &'static str = LDNS_HELP;
    const COMPATIBLE_VERSION: &'static str = "1.8.4";

    fn parse_ldns<I: IntoIterator<Item = OsString>>(args: I) -> Result<Args, Error> {
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

                    let value = parser.value()?;

                    if value == "list" {
                        return Ok(Args::from(Command::Report(ldns_algs_help())));
                    }

                    algorithm = parse_os_with("algorithm (-a)", &value, |s| {
                        Ok(match s {
                            "RSASHA256" | "8" => Some(SecurityAlgorithm::RSASHA256),
                            "ECDSAP256SHA256" | "13" => Some(SecurityAlgorithm::ECDSAP256SHA256),
                            "ECDSAP384SHA384" | "14" => Some(SecurityAlgorithm::ECDSAP384SHA384),
                            "ED25519" | "15" => Some(SecurityAlgorithm::ED25519),
                            "ED448" | "16" => Some(SecurityAlgorithm::ED448),

                            _ => {
                                return Err("unknown algorithm mnemonic or number");
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
                    // We don't support '-r', people could rely on it for deterministic output.
                    return Err("a custom source of randomness (-r) is not supported".into());
                }

                Arg::Short('s') => {
                    // NOTE: '-s' can be repeated, to no effect.
                    create_symlinks = true;
                }

                Arg::Short('f') => {
                    // NOTE: '-f' can be repeated, to no effect.
                    force_symlinks = true;
                }

                Arg::Short('v') => {
                    return Ok(Self::report_version());
                }

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

        let algorithm = algorithm.ok_or("Missing algorithm (-a) option")?;

        let symlink = match (create_symlinks, force_symlinks) {
            (true, true) => SymlinkArg::Force,
            (true, false) => SymlinkArg::Yes,
            // If only '-f' is specified, no symlinking is done.
            (false, _) => SymlinkArg::No,
        };

        let Some(name) = name else {
            return Err("Missing domain name argument".into());
        };

        Ok(Command::Keygen(Self {
            algorithm,
            bits,
            make_ksk,
            symlink,
            name,
        })
        .into())
    }
}

impl From<Keygen> for Command {
    fn from(value: Keygen) -> Self {
        Self::Keygen(value)
    }
}

impl Keygen {
    fn parse_algorithm(value: &str) -> Result<SecurityAlgorithm, clap::Error> {
        match value {
            "RSASHA256" | "8" => return Ok(SecurityAlgorithm::RSASHA256),
            "ECDSAP256SHA256" | "13" => return Ok(SecurityAlgorithm::ECDSAP256SHA256),
            "ECDSAP384SHA384" | "14" => return Ok(SecurityAlgorithm::ECDSAP384SHA384),
            "ED25519" | "15" => return Ok(SecurityAlgorithm::ED25519),
            "ED448" | "16" => return Ok(SecurityAlgorithm::ED448),
            _ => {}
        }

        Err(clap::Error::raw(
            clap::error::ErrorKind::InvalidValue,
            format!("unrecognized algorithm '{value}'"),
        ))
    }

    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        let mut stdout = env.stdout();

        let params = match self.algorithm {
            SecurityAlgorithm::RSASHA256 => GenerateParams::RsaSha256 { bits: self.bits },
            SecurityAlgorithm::ECDSAP256SHA256 => GenerateParams::EcdsaP256Sha256,
            SecurityAlgorithm::ECDSAP384SHA384 => GenerateParams::EcdsaP384Sha384,
            SecurityAlgorithm::ED25519 => GenerateParams::Ed25519,
            SecurityAlgorithm::ED448 => GenerateParams::Ed448,
            _ => unreachable!()
        };

        // The digest algorithm is selected based on the key algorithm.
        let digest_alg = match params.algorithm() {
            SecurityAlgorithm::RSASHA256 => DigestAlgorithm::SHA256,
            SecurityAlgorithm::ECDSAP256SHA256 => DigestAlgorithm::SHA256,
            SecurityAlgorithm::ECDSAP384SHA384 => DigestAlgorithm::SHA384,
            SecurityAlgorithm::ED25519 => DigestAlgorithm::SHA256,
            SecurityAlgorithm::ED448 => DigestAlgorithm::SHA256,
            _ => unreachable!(),
        };

        // Generate the key.
        // TODO: Attempt repeated generation to avoid key tag collisions.
        // TODO: Add a high-level operation in 'domain' to select flags?
        let flags = if self.make_ksk { 257 } else { 256 };
        let (secret_key, public_key) = domain::crypto::sign::generate(params, flags)
            .map_err(|err| format!("an implementation error occurred: {err}").into())
            .context("generating a cryptographic keypair")?;
        let digest = self.make_ksk.then(|| {
            public_key
                .digest(&self.name, digest_alg)
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

        let mut secret_key_file = util::create_new_file(&env, &secret_key_path)?;
        let mut public_key_file = util::create_new_file(&env, &public_key_path)?;
        let mut digest_file = digest_file_path
            .as_ref()
            .map(|digest_file_path| util::create_new_file(&env, digest_file_path))
            .transpose()?;

        Self::symlink(&secret_key_path, ".private", self.symlink, &env)?;
        Self::symlink(&public_key_path, ".key", self.symlink, &env)?;
        if let Some(digest_file_path) = &digest_file_path {
            Self::symlink(digest_file_path, ".ds", self.symlink, &env)?;
        }

        // Prepare the contents to write.
        let key_tag = public_key.key_tag();
        let algorithm = public_key.algorithm();
        let secret_key = secret_key.display_as_bind().to_string();
        let public_key = format!(
            "{} IN DNSKEY {}\n",
            self.name.fmt_with_dot(),
            public_key.display_zonefile(DisplayKind::Simple)
        );
        let digest = digest.map(|digest| {
            format!(
                "{} IN DS {}\n",
                self.name.fmt_with_dot(),
                Ds::new(key_tag, algorithm, digest_alg, digest)
                    .expect("we generated the digest, so don't expect it to be too long")
                    .display_zonefile(DISPLAY_KIND)
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
        writeln!(stdout, "{base}");

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
            SymlinkArg::Yes => util::symlink(env, target, link),
            SymlinkArg::Force => util::symlink_force(env, target, link),
        }

        #[cfg(not(unix))]
        if how.create() {
            let _ = (target, link, env);
            Err("Symlinks can only be created on Unix platforms".into())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use domain::base::iana::SecurityAlgorithm;
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
            algorithm: SecurityAlgorithm::ED25519,
            bits: 2048,
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
                algorithm: SecurityAlgorithm::RSASHA256,
                ..base.clone()
            }
        );
        // - RSA-SHA256 accepts other key sizes.
        assert_eq!(
            parse(cmd.args(["-a", "RSASHA256", "-b", "1024", "example.org"])),
            Keygen {
                algorithm: SecurityAlgorithm::RSASHA256,
                bits: 1024,
                ..base.clone()
            }
        );
        // - Specifying the algorithm by number
        assert_eq!(
            parse(cmd.args(["-a", "8", "example.org"])),
            Keygen {
                algorithm: SecurityAlgorithm::RSASHA256,
                ..base.clone()
            }
        );
        // - Specifying the algorithm by number incl. keysize
        assert_eq!(
            parse(cmd.args(["-a", "8", "-b", "1024", "example.org"])),
            Keygen {
                algorithm: SecurityAlgorithm::RSASHA256,
                bits: 1024,
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
            algorithm: SecurityAlgorithm::ED25519,
            bits: 2048,
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
                algorithm: SecurityAlgorithm::RSASHA256,
                ..base.clone()
            }
        );
        // - RSA-SHA256 accepts other key sizes.
        assert_eq!(
            parse(cmd.args(["-a", "RSASHA256", "-b", "1024", "example.org"])),
            Keygen {
                algorithm: SecurityAlgorithm::RSASHA256,
                bits: 1024,
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
            Regex::new(r"^example.org. IN DNSKEY 256 3 15 [A-Za-z0-9/+=]+\n$").unwrap();
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
            Regex::new(r"^example.org. IN DNSKEY 257 3 15 [A-Za-z0-9/+=]+\n$").unwrap();
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
