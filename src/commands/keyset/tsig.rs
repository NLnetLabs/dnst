//! RFC 8945 TSIG support for dnst keyset.
//!
//! This module enables dnst keyset to load TSIG key metadata and secret
//! material from a persisted key store.
//!
//! At the time of writing dnst keyset itself is only able to read from a key
//! store that was persisted by the initial beta version of [Cascade] and as
//! such the persistence format is compatible with and based on that of
//! [Cascade].
//!
//! Support for actually signing with TSIG keys is provided by the [domain]
//! crate and so this module also provides conversions from our types to those
//! of the domain crate.
//!
//! [RFC 8945]: https://www.rfc-editor.org/rfc/rfc8945.html
//! [Cascade]: https://nlnetlabs.nl/cascade
//! [domain]: https://nlnetlabs.nl/domain
use std::collections::HashMap;

use domain::base::Name;
use serde::{Deserialize, Serialize};

//------------ AlgSpec -------------------------------------------------------

/// A Cascade (de)serialization compatible TSIG algorithm specification.
///
/// A subset of the [IANA TSIG algorithm name registry].
///
/// [IANA TSIG algorithm name registry]: https://www.iana.org/assignments/tsig-algorithm-names/tsig-algorithm-names.xhtml
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum AlgSpec {
    /// hmac-sha1.
    #[serde(rename = "hmac-sha1")]
    HmacSha1,

    /// hmac-sha256.
    #[serde(rename = "hmac-sha256")]
    HmacSha256,

    /// hmac-sha384,
    #[serde(rename = "hmac-sha384")]
    HmacSha384,

    /// hmac-sha512.
    #[serde(rename = "hmac-sha512")]
    HmacSha512,
}

//--- impl From<AlgSpec>

/// Support conversion from domain TSIG algorithm identifiers to our
/// equivalent.
impl From<AlgSpec> for domain::tsig::Algorithm {
    fn from(alg: AlgSpec) -> Self {
        match alg {
            AlgSpec::HmacSha1 => domain::tsig::Algorithm::Sha1,
            AlgSpec::HmacSha256 => domain::tsig::Algorithm::Sha256,
            AlgSpec::HmacSha384 => domain::tsig::Algorithm::Sha384,
            AlgSpec::HmacSha512 => domain::tsig::Algorithm::Sha512,
        }
    }
}

//------------ KeySpec ------------------------------------------------------

/// A Casdade (de)serialization compatible TSIG key specification.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct KeySpec {
    /// The key algorithm.
    pub alg: AlgSpec,

    /// The private key material.
    #[serde(with = "tsig_base64")]
    pub data: Box<[u8]>,
}

/// Support for deserializing from base64 to Box<[u8]i> and vice versa.
mod tsig_base64 {
    use domain::utils::base64;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize from a byte slice to a base64 encoded string.
    pub fn serialize<S>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        base64::encode_string(data).serialize(serializer)
    }

    /// Deserialize from a base64 encoded string to a boxed byte array.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Box<[u8]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let data = base64::decode::<Vec<u8>>(&s).map_err(serde::de::Error::custom)?;
        Ok(data.into())
    }
}

//------------ TsigKeyName ---------------------------------------------------

/// A Cascade (de)serialization compatible TSIG key name.
pub type TsigKeyName = Name<octseq::Array<255>>;

//------------ TsigKeyStoreVersion -------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum TsigKeyStoreVersion {
    V1,
}

//------------ TsigKeyStore --------------------------------------------------

/// A Cascade (de)serialization compatible TSIG key store.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TsigKeyStore {
    /// The data format version of the store file.
    pub version: TsigKeyStoreVersion,

    /// A mapping of TSIG key names to key details.
    pub map: HashMap<TsigKeyName, KeySpec>,
}

impl TsigKeyStore {
    /// Create an empty TSIG key store.
    pub fn new() -> Self {
        Self {
            version: TsigKeyStoreVersion::V1,
            map: HashMap::new(),
        }
    }

    /// Get the TSIG key corresponding to the given key name, if any.
    ///
    /// Returns Some(key) if the key was found, None otherwise.
    pub fn get(&self, name: &TsigKeyName) -> Option<domain::tsig::Key> {
        if let Some(key) = self.map.get(name) {
            domain::tsig::Key::new(key.alg.into(), &key.data, name.to_owned(), None, None)
                .map(Option::Some)
                .unwrap_or_else(|_err| {
                    unreachable!("domain::tsig::Key::new() can only fail with non-None arguments")
                })
        } else {
            None
        }
    }
}

//--- impl Default

impl Default for TsigKeyStore {
    fn default() -> Self {
        Self::new()
    }
}
