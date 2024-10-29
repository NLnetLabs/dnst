use std::fs::File;
use std::io::Write;

use clap::{builder::ValueParser, Args, ValueEnum};
use domain::base::iana::Class;
use domain::base::name::Name;
use domain::sign::{common, GenerateParams};
use domain::validate::Key;

use crate::error::Error;
use crate::parse::parse_name;

#[derive(Clone, Debug, Args)]
pub struct Keygen {
    /// The signature algorithm to generate for
    #[arg(short = 'a', value_name = "ALGORITHM", value_enum)]
    algorithm: AlgorithmArg,

    /// Generate a key signing key instead of a zone signing key
    #[arg(short = 'k')]
    make_ksk: bool,

    /// The length of the key (for RSA keys only)
    #[arg(short = 'b', value_name = "BITS", default_value_t = 2048)]
    bits: u32,

    /// The randomness source to use for generation
    #[arg(short = 'r', value_name = "DEVICE", default_value_t = String::from("/dev/urandom"))]
    random: String,

    /// Create symlinks '.key' and '.private' to the generated keys
    #[arg(short = 's')]
    create_symlinks: bool,

    /// Overwrite existing symlinks (for use with '-s')
    #[arg(short = 'f')]
    force_symlinks: bool,

    /// The domain name to generate a key for
    #[arg(value_name = "domain name", value_parser = ValueParser::new(parse_name))]
    name: Name<Vec<u8>>,
}

impl Keygen {
    pub fn execute(self) -> Result<(), Error> {
        // Determine the appropriate key generation parameters.
        let params = match self.algorithm {
            AlgorithmArg::List => {
                // Print the algorithm list and exit.
                println!("Possible algorithms:");
                println!("  - RSASHA256 (8)");
                println!("  - ECDSAP256SHA256 (13)");
                println!("  - ECDSAP384SHA384 (14)");
                println!("  - ED25519 (15)");
                println!("  - ED448 (16)");
                return Ok(());
            }

            AlgorithmArg::RsaSha256 => GenerateParams::RsaSha256 { bits: self.bits },
            AlgorithmArg::EcdsaP256Sha256 => GenerateParams::EcdsaP256Sha256,
            AlgorithmArg::EcdsaP384Sha384 => GenerateParams::EcdsaP384Sha384,
            AlgorithmArg::Ed25519 => GenerateParams::Ed25519,
            AlgorithmArg::Ed448 => GenerateParams::Ed448,
        };

        // Generate the key.
        // TODO: Attempt repeated generation to avoid key tag collisions.
        let (secret_key, public_key) = common::generate(params)
            .map_err(|err| format!("an implementation error occurred: {err}"))?;
        let flags = if self.make_ksk { 257 } else { 256 };
        let public_key = Key::new(self.name, flags, public_key);

        // Open the appropriate files to write the key.
        let base = format!(
            "K{}+{:03}+{:05}",
            public_key.owner().fmt_with_dot(),
            public_key.algorithm().to_int(),
            public_key.key_tag()
        );
        let mut secret_key_file = File::create_new(format!("{base}.private"))
            .map_err(|err| format!("private key file '{base}.private' already existed: {err}"))?;
        let mut public_key_file = File::create_new(format!("{base}.key"))
            .map_err(|err| format!("public key file '{base}.key' already existed: {err}"))?;

        // Prepare the contents to write.
        // TODO: Add 'display_as_bind()' to these types.
        let secret_key = {
            let mut buf = String::new();
            secret_key.format_as_bind(&mut buf).unwrap();
            buf
        };
        let public_key = {
            let mut buf = String::new();
            public_key.format_as_bind(Class::IN, &mut buf).unwrap();
            buf
        };

        // Write the key files.
        secret_key_file
            .write_all(secret_key.as_bytes())
            .map_err(|err| {
                format!("error while writing private key file '{base}.private': {err}")
            })?;
        public_key_file
            .write_all(public_key.as_bytes())
            .map_err(|err| format!("error while writing public key file '{base}.key': {err}"))?;

        secret_key_file.sync_all().map_err(|err| {
            format!("error while writing private key file '{base}.private': {err}")
        })?;
        public_key_file
            .sync_all()
            .map_err(|err| format!("error while writing public key file '{base}.key': {err}"))?;

        // Let the user know what the base name of the files is.
        println!("{}", base);

        Ok(())
    }
}

/// An algorithm argument.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum AlgorithmArg {
    /// List all algorithms.
    List,

    /// RSA with SHA-256.
    #[value(name = "RSASHA256", alias("8"))]
    RsaSha256,

    /// ECDSA P-256 with SHA-256.
    #[value(name = "ECDSAP256SHA256", alias("13"))]
    EcdsaP256Sha256,

    /// ECDSA P-384 with SHA-384.
    #[value(name = "ECDSAP384SHA384", alias("14"))]
    EcdsaP384Sha384,

    /// ED25519.
    #[value(name = "ED25519", alias("15"))]
    Ed25519,

    /// ED448.
    #[value(name = "ED448", alias("16"))]
    Ed448,
}
