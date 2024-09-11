use crate::error::Error;
use crate::utils::private_key_file_parser::{gen_private_key_file_text, parse_private_key_file};
use clap::builder::ValueParser;
use domain::base::iana::SecAlg;
use domain::base::name::Name;
use domain::rdata::Dnskey;
use domain::tsig::Algorithm as TsigAlgorithm;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;

// Problems:
// - Can't add --list argument while defining algorithm and name as Option with
//   attribute required_unless_present("list"), and still get --help stating
//   that either --list or --algorithm AND name are required...
//   It will show as optional domain name and optional options, and only when
//   parsing tell that it's missing things
//
//   Usage: dnst key-gen [OPTIONS] --algorithm <NAME> <DOMAIN>
//   vs.
//   Usage: dnst key-gen [OPTIONS] [DOMAIN]
//   vs.
//   Usage: dnst key-gen [OPTIONS] [--list|--algorithm <NAME> <DOMAIN>]

// Implementing -v version for this subcommand seems pretty difficult
#[derive(Clone, Debug, clap::Args)]
pub struct KeyGen {
    /// The algorithm to use (or 'list' to show them all)
    #[arg(
        long,
        short = 'a',
        value_name = "NAME",
        value_parser = ValueParser::new(KeyGen::parse_alg),
        // required = true,
        // required_unless_present("list")
    )]
    algorithm: AlgorithmType,

    /// Specify the key length (the default depends on the algorithm in use)
    #[arg(long, short = 'b', value_name = "NUMBER")]
    bits: Option<u16>,

    /// Set key signing key (KSK) flag
    #[arg(long, short = 'k')]
    ksk: bool,

    /// Specify a random device to seed the random generator with
    // (by default the syscall getrandom is used)
    #[arg(long, short = 'r', value_name = "PATH", /* default_value = "/dev/random" */)]
    random: Option<PathBuf>,

    /// Create additional symlinks with constant names
    #[arg(long, short = 's')]
    symlinks: bool,

    /// Force override existing symlinks
    #[arg(long, short = 'f')]
    force: bool,

    // /// List available algorithms
    // #[arg(long, short = 'l')]
    // list: bool,
    /// The domain name to hash
    #[arg(value_name = "DOMAIN", value_parser = ValueParser::new(KeyGen::parse_name), /* required_unless_present("list") */)]
    name: Name<octseq::Array<255>>,
}

#[derive(Clone, Debug, PartialEq)]
enum AlgorithmType {
    SecAlg(SecAlg),
    TsigAlg(TsigAlgorithm),
    List,
}

impl KeyGen {
    fn parse_name(arg: &str) -> Result<Name<octseq::Array<255>>, Error> {
        Name::from_str(&arg.to_lowercase()).map_err(|e| Error::from(e.to_string()))
    }

    fn parse_alg(arg: &str) -> Result<AlgorithmType, Error> {
        if arg == "list" {
            return Ok(AlgorithmType::List);
        }

        if let Some(alg) = SecAlg::from_mnemonic(arg.as_bytes()) {
            if Self::supported_sec_alg(alg) {
                Ok(AlgorithmType::SecAlg(alg))
            } else {
                Err(Error::from("algorithm not supported"))
            }
        } else if let Ok(alg) = TsigAlgorithm::from_str(arg) {
            Ok(AlgorithmType::TsigAlg(alg))
        } else {
            Err(Error::from("unknown algorithm name"))
        }
    }

    fn supported_sec_alg(alg: SecAlg) -> bool {
        match alg {
            SecAlg::RSAMD5
            | SecAlg::DH
            | SecAlg::DSA
            | SecAlg::RSASHA1
            | SecAlg::DSA_NSEC3_SHA1
            | SecAlg::RSASHA1_NSEC3_SHA1
            | SecAlg::RSASHA256
            | SecAlg::RSASHA512
            | SecAlg::ECC_GOST
            | SecAlg::ECDSAP256SHA256
            | SecAlg::ECDSAP384SHA384
            | SecAlg::ED25519
            | SecAlg::ED448 => true,
            _ => false,
        }
    }
}

// cant implement SecureRandom because it's sealed
#[derive(Debug)]
enum RandomSource {
    SystemRandom(SystemRandom),
    // TODO: somehow define max bytes/key/random-data length
    Bytes([u8; 512]),
}

impl KeyGen {
    pub fn execute(self) -> Result<(), Error> {
        if self.algorithm == AlgorithmType::List {
            list_algorithms();
            return Ok(());
        }

        // let content = std::fs::read_to_string(self.random.as_ref().expect("doit"))?;
        // let lines: Vec<&str> = content.lines().collect::<Vec<_>>();
        // let key = parse_private_key_file(lines.iter())?;
        // // println!("parse result: {:?}", parse_private_key_file(&lines));
        // print!("{}", gen_private_key_file_text(key)?);
        // return Ok(());

        let bits = match self.bits {
            Some(bits) => {
                valid_key_length(bits, &self.algorithm)?;
                bits
            }
            None => match self.algorithm {
                AlgorithmType::SecAlg(alg) => default_key_length_sec(alg),
                AlgorithmType::TsigAlg(alg) => default_key_length_tsig(alg),
                AlgorithmType::List => {
                    panic!("this shouldn't happen, we didn't check algorithm listing properly")
                }
            },
        };

        // XXX: ignoring --random source for now because getting a &dyn SecureRandom from [u8; N]
        // seems impossible

        // let rand_src = match self.random {
        //     Some(ref file) => {
        //         let mut f = File::open(file)?;
        //         let mut x = RandomSource::Bytes([0; 512]);
        //         let _ = match x {
        //             RandomSource::Bytes(ref mut y) => f.read_exact(y),
        //             _ => unreachable!(),
        //         };
        //         x
        //     }
        //     None => RandomSource::SystemRandom(SystemRandom::new()),
        // };

        let dnskey = match self.algorithm {
            AlgorithmType::SecAlg(sec) => Self::generate_sec_key(sec, bits),
            AlgorithmType::TsigAlg(_) => todo!(), // create_tsig(self, todo!());
            AlgorithmType::List => {
                list_algorithms();
                return Ok(());
            }
        };

        println!("{}", dnskey?);

        // TODO: create structures (name, key, rr)
        // TODO: write files and stdout

        Ok(())
    }

    fn generate_sec_key(alg: SecAlg, bits: u16) -> Result<Dnskey<Vec<u8>>, Error> {
        // domain::sign::ring::Key doesn't expose a new or From to use
        // domain::sign::ring::RingKey is private

        let rng = SystemRandom::new();
        match alg {
            SecAlg::ECC_GOST => Err(Error::from("ECC_GOST is currently not supported")),
            SecAlg::RSAMD5
            | SecAlg::RSASHA1
            | SecAlg::RSASHA1_NSEC3_SHA1
            | SecAlg::RSASHA256
            | SecAlg::RSASHA512 => todo!(),
            SecAlg::DH => todo!(),
            SecAlg::DSA | SecAlg::DSA_NSEC3_SHA1 => todo!(),
            SecAlg::ECDSAP256SHA256 | SecAlg::ECDSAP384SHA384 => gen_ecdsa(&rng),
            SecAlg::ED25519 | SecAlg::ED448 => todo!(),
            _ => Err(Error::from("algorithm not supported")),
        }
    }
}

fn gen_ecdsa(rng: &dyn SecureRandom) -> Result<Dnskey<Vec<u8>>, Error> {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng).unwrap();
    // println!("ring: {:?}", pkcs8.as_ref());
    let keypair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), rng).unwrap();
    let public_key = keypair.public_key().as_ref()[1..].into();
    Ok(Dnskey::new(0, 3, SecAlg::ECDSAP256SHA256, public_key).expect("long key"))
    // key: RingKey::Ecdsa(keypair),
}

fn create_tsig(arg: KeyGen, rng: &dyn SecureRandom) -> () {
    // RR type KEY is not supported by domain::tsig, so moving away from tsig::Key
    let key_len = TsigAlgorithm::Sha1.native_len();
    let mut bytes = Vec::new();
    bytes.resize(key_len, 0);
    rng.fill(&mut bytes).expect("not yet");
    let key = domain::tsig::Key::new(TsigAlgorithm::Sha512, &bytes, arg.name, None, None);
    // Ok((key, bytes))
}

fn valid_key_length(bits: u16, algorithm: &AlgorithmType) -> Result<(), Error> {
    match algorithm {
        AlgorithmType::SecAlg(alg) => match *alg {
            SecAlg::RSAMD5
            | SecAlg::RSASHA1
            | SecAlg::RSASHA1_NSEC3_SHA1
            | SecAlg::RSASHA256
            | SecAlg::RSASHA512 => {
                if bits < 512 || bits > 4096 {
                    Err(Error::from(
                        "The key size for RSA must be from 512 to 4096 bits.",
                    ))
                } else {
                    Ok(())
                }
            }
            SecAlg::DSA | SecAlg::DSA_NSEC3_SHA1 => {
                if bits < 512 || bits > 1024 {
                    Err(Error::from(
                        "The key size for DSA must be from 512 to 1024 bits.",
                    ))
                } else {
                    Ok(())
                }
            }
            /* These algorithms don't use variable key sizes */
            SecAlg::ECDSAP256SHA256
            | SecAlg::ECDSAP384SHA384
            | SecAlg::ECC_GOST
            | SecAlg::ED25519
            | SecAlg::ED448
            | SecAlg::DH => {
                eprintln!("ignoring bit length for algorithm {}", alg);
                Ok(())
            }
            _ => panic!("we didn't validate the used algorithms correctly"),
        },
        AlgorithmType::TsigAlg(alg) => match alg {
            TsigAlgorithm::Sha1 => {
                if bits < 1 || bits > 160 {
                    Err(Error::from(
                        "The key size for hmac-sha1 must be from 1 to 160 bits.",
                    ))
                } else {
                    Ok(())
                }
            }
            TsigAlgorithm::Sha256 => {
                if bits < 1 || bits > 256 {
                    Err(Error::from(
                        "The key size for hmac-sha256 must be from 1 to 256 bits.",
                    ))
                } else {
                    Ok(())
                }
            }
            TsigAlgorithm::Sha384 => {
                if bits < 1 || bits > 384 {
                    Err(Error::from(
                        "The key size for hmac-sha384 must be from 1 to 384 bits.",
                    ))
                } else {
                    Ok(())
                }
            }
            TsigAlgorithm::Sha512 => {
                if bits < 1 || bits > 512 {
                    Err(Error::from(
                        "The key size for hmac-sha512 must be from 1 to 512 bits.",
                    ))
                } else {
                    Ok(())
                }
            }
        },
        _ => panic!("this shouldn't happen either, we didn't check the used algorithms correctly"),
    }
}

fn default_key_length_sec(alg: SecAlg) -> u16 {
    match alg {
        SecAlg::RSAMD5 => 2048,
        SecAlg::DH => 2048,
        SecAlg::DSA => 2048,
        SecAlg::RSASHA1 => 2048,
        SecAlg::DSA_NSEC3_SHA1 => 2048,
        SecAlg::RSASHA1_NSEC3_SHA1 => 2048,
        SecAlg::RSASHA256 => 2048,
        SecAlg::RSASHA512 => 2048,
        SecAlg::ECC_GOST => 2048,
        SecAlg::ECDSAP256SHA256 => 2048,
        SecAlg::ECDSAP384SHA384 => 2048,
        SecAlg::ED25519 => 2048,
        SecAlg::ED448 => 2048,
        _ => panic!("we didn't validate the used algorithms correctly"),
    }
}

fn default_key_length_tsig(alg: TsigAlgorithm) -> u16 {
    match alg {
        TsigAlgorithm::Sha1
        | TsigAlgorithm::Sha256
        | TsigAlgorithm::Sha384
        | TsigAlgorithm::Sha512 => 512,
    }
}

fn list_algorithms() {
    // I seel no easy way to list all variants, so just doing it by hand
    let sec_algs = vec![
        SecAlg::RSAMD5,
        SecAlg::DH,
        SecAlg::DSA,
        SecAlg::RSASHA1,
        SecAlg::DSA_NSEC3_SHA1,
        SecAlg::RSASHA1_NSEC3_SHA1,
        SecAlg::RSASHA256,
        SecAlg::RSASHA512,
        SecAlg::ECC_GOST,
        SecAlg::ECDSAP256SHA256,
        SecAlg::ECDSAP384SHA384,
        SecAlg::ED25519,
        SecAlg::ED448,
    ];
    let tsig_algs = vec![
        TsigAlgorithm::Sha1,
        TsigAlgorithm::Sha256,
        TsigAlgorithm::Sha384,
        TsigAlgorithm::Sha512,
        // TODO: decide over completeness of backwards compatibility: ldns additionally
        // supports hmac-md5 and hmac-sha224, which are not provided by ring and therefore
        // domain
    ];

    for i in sec_algs.iter() {
        println!("{}", i);
    }

    for i in tsig_algs.iter() {
        println!("{}", i);
    }
}
