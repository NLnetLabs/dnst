use core::ops::{Add, Sub};

use std::path::PathBuf;

use bytes::{Bytes, BytesMut};
use clap::builder::ValueParser;
use ring::rand::SystemRandom;
use std::fs::File;

use domain::base::iana::nsec3::Nsec3HashAlg;
use domain::base::iana::{Class, SecAlg};
use domain::base::name::FlattenInto;
use domain::base::{Name, Record, ToName, Ttl};
use domain::rdata::dnssec::Timestamp;
use domain::rdata::nsec3::Nsec3Salt;
use domain::rdata::{Nsec3param, ZoneRecordData};
use domain::sign::records::{FamilyName, SortedRecords};
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
    key_path: PathBuf,
}

impl SignZone {
    pub fn execute(self) -> Result<(), Error> {
        let mut records = self.load_zone()?;

        //---

        // Import the specified key.
        let data = std::fs::read_to_string(self.key_path).unwrap();
        let generic_key = domain::sign::generic::SecretKey::<Vec<u8>>::from_dns(&data).unwrap(); // What does "from_dns()" mean here?

        // Neither openssl::SecretKey nor generic::SecretKey impl SigningKey
        // and I can't impl it myself because both the trait and the types are in domain.

        // Note: domain key management code doesn't follow formatting guidelines.

        // No is algorithm support fn on the openssl or ring support in domain...

        // Unclear from docs how to generate or import keys.
        // let openssl_key = domain::sign::openssl::generate(SecAlg::ECDSAP256SHA256).unwrap();

        let rng = SystemRandom::new();

        let key_pair = match generic_key.algorithm() {
            SecAlg::ED25519 => {
                let ring_key = domain::sign::ring::SecretKey::import(generic_key, &rng).unwrap(); // Why do I have to do the generic key step myself?
                let key_pair = domain::sign::ring::KeyPair::<Vec<u8>>::new(ring_key).unwrap();
                domain::sign::generic::KeyPair::Ring(key_pair)
            }

            SecAlg::ECDSAP256SHA256 => {
                let openssl_key = domain::sign::openssl::SecretKey::import(generic_key).unwrap(); // Why do I have to do the generic key step myself?
                let key_pair = domain::sign::openssl::KeyPair::<Vec<u8>>::new(openssl_key).unwrap();
                domain::sign::generic::KeyPair::Openssl(key_pair)
            }

            _ => unimplemented!(),
        };

        //---

        let (apex, ttl) = Self::find_apex(&records).unwrap();

        if self.use_nsec3 {
            let nsecs = records.nsec3s::<_, BytesMut>(
                &apex,
                ttl,
                self.algorithm,
                0,
                self.iterations,
                self.salt.clone(),
            );
            records.extend(nsecs.into_iter().map(Record::from_record));
            let nsec3param_data = Nsec3param::new(self.algorithm, 0, self.iterations, self.salt);
            let nsec3param_rec =
                Record::new(apex.owner().to_name(), Class::IN, ttl, nsec3param_data);
            records.insert(Record::from_record(nsec3param_rec)).unwrap();
        } else {
            let nsecs = records.nsecs::<Bytes>(&apex, ttl);
            records.extend(nsecs.into_iter().map(Record::from_record));
        }

        let record = apex.dnskey(ttl, &key_pair).unwrap();
        records.insert(Record::from_record(record)).unwrap();
        let inception: Timestamp = Timestamp::now().into_int().sub(10).into();
        let expiration = inception.into_int().add(2592000).into(); // XXX 30 days
        let rrsigs = records
            .sign(&apex, expiration, inception, &key_pair)
            .unwrap();
        records.extend(rrsigs.into_iter().map(Record::from_record));
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
            ZoneRecordData::Soa(ref soa) => soa.minimum(),
            _ => unreachable!(),
        };
        Ok((soa.family_name().cloned(), ttl))
    }
}
