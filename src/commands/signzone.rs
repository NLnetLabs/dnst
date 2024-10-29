use core::ops::{Add, Sub};

use std::cmp::min;
use std::path::PathBuf;

use bytes::{Bytes, BytesMut};
use clap::builder::ValueParser;
use std::fs::File;

use domain::base::iana::nsec3::Nsec3HashAlg;
use domain::base::name::FlattenInto;
use domain::base::{Name, Record, Ttl};
use domain::rdata::dnssec::Timestamp;
use domain::rdata::nsec3::Nsec3Salt;
use domain::rdata::{Nsec3param, ZoneRecordData};
use domain::sign::records::{FamilyName, Nsec3Records, SortedRecords};
use domain::zonefile::inplace;
use domain::zonetree::types::StoredRecordData;
use domain::zonetree::{StoredName, StoredRecord};

use crate::error::Error;

use super::nsec3hash::Nsec3Hash;

#[derive(Clone, Debug, clap::Args)]
pub struct SignZone {
    /// use NSEC3 instead of NSEC.
    #[arg(short = 'n', default_value_t = false, group = "nsec3")]
    use_nsec3: bool,

    /// NSEC3 hashing algorithm
    #[arg(
        short = 'a',
        value_name = "algorithm",
        default_value_t = Nsec3HashAlg::SHA1,
        value_parser = ValueParser::new(Nsec3Hash::parse_nsec_alg),
        requires = "nsec3"
    )]
    algorithm: Nsec3HashAlg,

    /// NSEC3 number of hash iterations
    #[arg(
        short = 't',
        value_name = "number",
        default_value_t = 1,
        requires = "nsec3"
    )]
    iterations: u16,

    /// NSEC3 salt
    #[arg(short = 's', value_name = "string", default_value_t = Nsec3Salt::empty(), requires = "nsec3")]
    salt: Nsec3Salt<Bytes>,

    /// NSEC3 set the opt-out flag on all nsec3 rrs
    #[arg(short = 'p', default_value_t = false, requires = "nsec3")]
    nsec3_opt_out: bool,

    /// zonefile
    #[arg(value_name = "zonefile")]
    zonefile_path: PathBuf,

    /// key
    ///
    /// keys must be specified by their base name (usually
    /// K<name>+<alg>+<id>), i.e. WITHOUT the .private extension.
    #[arg(value_name = "key")]
    key_paths: Vec<PathBuf>,
}

impl SignZone {
    pub fn execute(self) -> Result<(), Error> {
        let mut records = self.load_zone()?;

        //---

        // Import the specified key.
        let mut keys = vec![];
        for key_path in self.key_paths {
            let old_ext = key_path.extension().unwrap().to_str().unwrap();
            let new_ext = format!("{}.private", old_ext);
            let private_key_path = key_path.with_extension(new_ext).display().to_string();
            let private_data = std::fs::read_to_string(&private_key_path).map_err(|err| {
                Error::from(format!(
                    "Unable to load private key from file '{}': {}",
                    private_key_path, err
                ))
            })?;

            let old_ext = key_path.extension().unwrap().to_str().unwrap();
            let new_ext = format!("{}.key", old_ext);
            let public_key_path = key_path.with_extension(new_ext).display().to_string();
            let public_data = std::fs::read_to_string(&public_key_path).map_err(|err| {
                Error::from(format!(
                    "Unable to load public key from file '{}': {}",
                    private_key_path, err
                ))
            })?;

            let generic_key =
                domain::sign::KeyBytes::parse_from_bind(&private_data).map_err(|err| {
                    Error::from(format!(
                        "Unable to parse BIND formatted private key file '{}': {}",
                        private_key_path, err
                    ))
                })?;

            let public_key: domain::validate::Key<Bytes> =
                domain::validate::Key::parse_from_bind(&public_data).map_err(|err| {
                    Error::from(format!(
                        "Unable to parse BIND formatted public key file '{}': {}",
                        private_key_path, err
                    ))
                })?;

            let key_pair = domain::sign::openssl::KeyPair::from_bytes(
                &generic_key,
                public_key.raw_public_key(),
            )
            .map_err(|err| {
                Error::from(format!(
                    "Unable to import private key from file '{}': {}",
                    private_key_path, err
                ))
            })?;

            let signing_key = domain::sign::SigningKey::new(
                public_key.owner().to_owned(),
                public_key.flags(),
                key_pair,
            );

            keys.push(signing_key);
        }

        //---

        let (apex, ttl) = Self::find_apex(&records).unwrap();

        if self.use_nsec3 {
            let params = Nsec3param::new(self.algorithm, 0, self.iterations, self.salt.clone());
            let Nsec3Records {
                nsec3_recs,
                nsec3param_rec,
            } = records
                .nsec3s::<_, BytesMut>(&apex, ttl, params, self.nsec3_opt_out)
                .unwrap();
            records.extend(nsec3_recs.into_iter().map(Record::from_record));
            records.insert(Record::from_record(nsec3param_rec)).unwrap();
        } else {
            let nsecs = records.nsecs::<Bytes>(&apex, ttl);
            records.extend(nsecs.into_iter().map(Record::from_record));
        }

        let inception: Timestamp = Timestamp::now().into_int().sub(10).into();
        let expiration = inception.into_int().add(2592000).into(); // XXX 30 days
        let extra_records = records
            .sign(&apex, expiration, inception, keys.as_slice())
            .unwrap();
        records.extend(extra_records.into_iter().map(Record::from_record));
        records.write(&mut std::io::stdout().lock()).unwrap();

        Ok(())
    }

    fn load_zone(&self) -> Result<SortedRecords<StoredName, StoredRecordData>, Error> {
        let mut zone_file = File::open(self.zonefile_path.as_path())?;
        let reader = inplace::Zonefile::load(&mut zone_file).unwrap();
        let mut records = SortedRecords::new();
        for entry in reader {
            let entry = entry.unwrap();
            let inplace::Entry::Record(record) = entry else {
                unimplemented!();
            };
            let record: StoredRecord = record.flatten_into();
            records.insert(record).unwrap();
        }
        Ok(records)
    }

    fn find_apex(
        records: &SortedRecords<StoredName, StoredRecordData>,
    ) -> Result<(FamilyName<Name<Bytes>>, Ttl), std::io::Error> {
        let soa = match records.find_soa() {
            Some(soa) => soa,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "cannot find SOA record",
                ))
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
