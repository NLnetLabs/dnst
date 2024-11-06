use core::ops::{Add, Sub};

use std::cmp::min;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use bytes::{Bytes, BytesMut};
use clap::builder::ValueParser;

use domain::base::iana::nsec3::Nsec3HashAlg;
use domain::base::name::FlattenInto;
use domain::base::{Name, NameBuilder, Record, Ttl};
use domain::rdata::dnssec::Timestamp;
use domain::rdata::nsec3::Nsec3Salt;
use domain::rdata::{Nsec3param, ZoneRecordData};
use domain::sign::common::KeyPair;
use domain::sign::records::{FamilyName, Nsec3OptOut, Nsec3Records, SortedRecords};
use domain::sign::{SecretKeyBytes, SigningKey};
use domain::validate::Key;
use domain::zonefile::inplace::{self, Entry};
use domain::zonetree::types::StoredRecordData;
use domain::zonetree::{StoredName, StoredRecord};

use crate::error::Error;

use super::nsec3hash::Nsec3Hash;

#[derive(Clone, Debug, clap::Args)]
pub struct SignZone {
    /// Use NSEC3 instead of NSEC
    #[arg(short = 'n', default_value_t = false, group = "nsec3")]
    use_nsec3: bool,

    /// Hashing algorithm
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 'a',
        value_name = "algorithm",
        default_value = "SHA-1",
        value_parser = ValueParser::new(Nsec3Hash::parse_nsec_alg),
        requires = "nsec3"
    )]
    algorithm: Nsec3HashAlg,

    /// Number of hash iterations
    // TODO: make the default for dnst-signzone be 0 (to match best practice)
    // while leaving the default for ldns-signzone be 1 (to match ldns), or
    // maybe even change the default for both to 0.
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 't',
        value_name = "number",
        default_value_t = 1,
        requires = "nsec3"
    )]
    iterations: u16,

    /// Salt
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 's',
        value_name = "string",
        default_value_t = Nsec3Salt::empty(),
        requires = "nsec3"
    )]
    salt: Nsec3Salt<Bytes>,

    /// Set the opt-out flag on all NSEC3 RRs
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 'p',
        default_value_t = false,
        requires = "nsec3",
        conflicts_with = "nsec3_opt_out"
    )]
    nsec3_opt_out_flags_only: bool,

    /// Set the opt-out flag on all NSEC3 RRs and skip unsigned delegations
    #[arg(
        help_heading = Some("NSEC3 (when using '-n')"),
        short = 'A', // Matches BIND dnssec-signzone
        default_value_t = false,
        requires = "nsec3",
        conflicts_with = "nsec3_opt_out_flags_only"
    )]
    nsec3_opt_out: bool,

    /// Hash only, don't sign
    #[arg(short = 'H', default_value_t = false)]
    hash_only: bool,

    /// Use layout in signed zone and print comments on DNSSEC records
    #[arg(short = 'b', default_value_t = false)]
    diagnostic_comments: bool,

    /// Origin for the zone (for zonefiles with relative names and no $ORIGIN)
    #[arg(short = 'o')]
    origin: Option<Name<Bytes>>,

    /// The zonefile to sign
    #[arg(value_name = "zonefile")]
    zonefile_path: PathBuf,

    /// The keys to sign the zone with
    ///
    /// keys must be specified by their base name (usually
    /// K<name>+<alg>+<id>), i.e. WITHOUT the .private extension.
    #[arg(value_name = "key")]
    key_paths: Vec<PathBuf>,
}

impl SignZone {
    pub fn execute(self) -> Result<(), Error> {
        // Post-process arguments.
        // TODO: Can Clap do this for us?
        let opt_out = if self.nsec3_opt_out {
            Nsec3OptOut::OptOut
        } else if self.nsec3_opt_out_flags_only {
            Nsec3OptOut::OptOutFlagsOnly
        } else {
            Nsec3OptOut::NoOptOut
        };

        let signing_mode = if self.hash_only {
            SigningMode::HashOnly
        } else {
            SigningMode::HashAndSign
        };

        // Import the specified keys.
        let mut keys = vec![];
        for key_path in &self.key_paths {
            keys.push(load_key_pair(key_path)?);
        }

        // Read the zone file.
        let mut records = self.load_zone()?;

        // Find the apex.
        let (apex, ttl) = Self::find_apex(&records).unwrap();

        // Hash the zone with NSEC or NSEC3.
        let hashes = if self.use_nsec3 {
            let params = Nsec3param::new(self.algorithm, 0, self.iterations, self.salt.clone());
            let Nsec3Records {
                recs,
                param,
                hashes,
            } = records
                .nsec3s::<_, BytesMut>(&apex, ttl, params, opt_out, self.diagnostic_comments)
                .unwrap();
            records.extend(recs.into_iter().map(Record::from_record));
            records.insert(Record::from_record(param)).unwrap();
            hashes
        } else {
            let nsecs = records.nsecs::<Bytes>(&apex, ttl);
            records.extend(nsecs.into_iter().map(Record::from_record));
            None
        };

        // Sign the zone unless disabled.
        if signing_mode == SigningMode::HashAndSign {
            let inception: Timestamp = Timestamp::now().into_int().sub(10).into();
            let expiration = inception.into_int().add(2592000).into(); // XXX 30 days
            let extra_records = records
                .sign(&apex, expiration, inception, keys.as_slice())
                .unwrap();
            records.extend(extra_records.into_iter().map(Record::from_record));
        }

        // Output the resulting zone, with comments if enabled.
        if let Some(hashes) = hashes {
            records
                .write_with_comments(&mut std::io::stdout().lock(), |r, writer| {
                    if let ZoneRecordData::Nsec3(nsec3) = r.data() {
                        writer.write(b" ;{ flags: ")?;

                        if nsec3.opt_out() {
                            writer.write(b"optout")?;
                        } else {
                            writer.write(b"-")?;
                        }

                        let next_owner_hash_hex = format!("{}", nsec3.next_owner());
                        let next_owner_name = next_owner_hash_to_name(&next_owner_hash_hex, &apex);

                        let from = hashes
                            .get(r.owner())
                            .map(|n| format!("{}", n.fmt_with_dot()))
                            .unwrap_or_default();

                        let to = if let Ok(next_owner_name) = next_owner_name {
                            hashes
                                .get(&next_owner_name)
                                .map(|n| format!("{}", n.fmt_with_dot()))
                                .unwrap_or_else(|| format!("<unknown hash: {next_owner_hash_hex}"))
                        } else {
                            format!("<invalid name: {next_owner_hash_hex}")
                        };

                        write!(writer, ", from: {from}, to: {to}}}")
                    } else {
                        Ok(())
                    }
                })
                .unwrap();
        } else {
            records.write(&mut std::io::stdout().lock()).unwrap();
        }

        Ok(())
    }

    fn load_zone(&self) -> Result<SortedRecords<StoredName, StoredRecordData>, Error> {
        let mut zone_file = File::open(&self.zonefile_path)?;
        let mut reader = inplace::Zonefile::load(&mut zone_file).unwrap();
        if let Some(origin) = &self.origin {
            reader.set_origin(origin.clone());
        }
        let mut records = SortedRecords::new();
        for entry in reader {
            let entry = entry.map_err(|err| format!("Invalid zone file: {err}"))?;
            match entry {
                Entry::Record(record) => {
                    let record: StoredRecord = record.flatten_into();
                    records.insert(record).map_err(|record| {
                        format!("Invalid zone file: Duplicate record detected: {record:?}")
                    })?;
                }
                Entry::Include { .. } => {
                    return Err(Error::from(
                        "Invalid zone file: $INCLUDE directive is not supported",
                    ));
                }
            }
        }
        Ok(records)
    }

    fn find_apex(
        records: &SortedRecords<StoredName, StoredRecordData>,
    ) -> Result<(FamilyName<Name<Bytes>>, Ttl), Error> {
        let soa = match records.find_soa() {
            Some(soa) => soa,
            None => {
                return Err(Error::from("Invalid zone file: Cannot find SOA record"));
            }
        };

        let ttl = match *soa.first().data() {
            ZoneRecordData::Soa(ref soa_data) => {
                // RFC 9077 updated RFC 4034 (NSEC) and RFC 5155 (NSSE3) to
                // say that the "TTL of the NSEC(3) RR that is returned MUST be
                // the lesser of the MINIMUM field of the SOA record and the
                // TTL of the SOA itself".
                min(soa_data.minimum(), soa.ttl())
            }
            _ => unreachable!(),
        };

        Ok((soa.family_name().cloned(), ttl))
    }
}

fn next_owner_hash_to_name(
    next_owner_hash_hex: &String,
    apex: &FamilyName<Name<Bytes>>,
) -> Result<Name<Bytes>, ()> {
    let mut builder = NameBuilder::new_bytes();
    builder
        .append_chars(next_owner_hash_hex.chars())
        .map_err(|_| ())?;
    let next_owner_name = builder.append_origin(apex.owner()).map_err(|_| ())?;
    Ok(next_owner_name)
}

/// Given a BIND style key pair path prefix load the keys from disk.
///
/// Expects a path that is the common prefix in BIND style of a pair of '.key'
/// (public) and '.private' key files, i.e. given
/// /path/to/K<zone_name>.+<algorithm>+<key tag> load and parse the following
/// files:
///
///   - /path/to/K<zone_name>.+<algorithm>+<key tag>.key
///   - /path/to/K<zone_name>.+<algorithm>+<key tag>.private
///
/// However, this function is not strict about the format of the prefix, it
/// will attempt to load files with suffixes '.key' and '.private' irrespective
/// of the format of the rest of the path.
fn load_key_pair(key_path: &Path) -> Result<SigningKey<Bytes, KeyPair>, Error> {
    let key_path_str = key_path.to_string_lossy();
    let public_key_path = PathBuf::from(format!("{key_path_str}.key"));
    let private_key_path = PathBuf::from(format!("{key_path_str}.private"));

    let private_data = std::fs::read_to_string(&private_key_path).map_err(|err| {
        format!(
            "Unable to load private key from file '{}': {}",
            private_key_path.display(),
            err
        )
    })?;

    let public_data = std::fs::read_to_string(&public_key_path).map_err(|err| {
        format!(
            "Unable to load public key from file '{}': {}",
            public_key_path.display(),
            err
        )
    })?;

    let secret_key = SecretKeyBytes::parse_from_bind(&private_data).map_err(|err| {
        format!(
            "Unable to parse BIND formatted private key file '{}': {}",
            private_key_path.display(),
            err
        )
    })?;

    let public_key_info = Key::parse_from_bind(&public_data).map_err(|err| {
        format!(
            "Unable to parse BIND formatted public key file '{}': {}",
            public_key_path.display(),
            err
        )
    })?;

    let key_pair =
        KeyPair::from_bytes(&secret_key, public_key_info.raw_public_key()).map_err(|err| {
            format!(
                "Unable to import private key from file '{}': {}",
                private_key_path.display(),
                err
            )
        })?;

    let signing_key = SigningKey::new(
        public_key_info.owner().clone(),
        public_key_info.flags(),
        key_pair,
    );

    Ok(signing_key)
}

//------------ SigningMode ---------------------------------------------------

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum SigningMode {
    /// Both hash (NSEC/NSEC3) and sign zone records.
    #[default]
    HashAndSign,

    /// Only hash (NSEC/NSEC3) zone records, don't sign them.
    HashOnly,
    // /// Only sign zone records, assume they are already hashed.
    // SignOnly,
}
