use std::collections::HashMap;

use domain::base::Name;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AlgSpec {
    /// SHA-1.
    HmacSha1,

    /// SHA-256.
    HmacSha256,

    /// SHA-384,
    HmacSha384,

    /// SHA-512.
    HmacSha512,
}

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

/// A TSIG key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct KeySpec {
    /// The key algorithm.
    pub alg: AlgSpec,

    /// The private key material.
    #[serde(with = "tsig_base64")]
    pub data: Box<[u8]>,
}

mod tsig_base64 {
    use domain::utils::base64;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        base64::encode_string(data).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Box<[u8]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let data = base64::decode::<Vec<u8>>(&s).map_err(serde::de::Error::custom)?;
        Ok(data.into())
    }
}

pub type TsigKeyName = Name<octseq::Array<255>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TsigKeyStore {
    /// The data format version of the store file.
    pub version: String,

    /// A mapping of names to TSIG key details.
    pub map: HashMap<TsigKeyName, KeySpec>,
}

impl TsigKeyStore {
    pub fn new() -> Self {
        Self {
            version: "v1".to_string(),
            map: HashMap::new(),
        }
    }

    pub fn get(&self, name: &TsigKeyName) -> Result<Option<domain::tsig::Key>, String> {
        if let Some(key) = self.map.get(name) {
            domain::tsig::Key::new(key.alg.into(), &key.data, name.to_owned(), None, None)
                .map(Option::Some)
                .map_err(|err| err.to_string())
        } else {
            Ok(None)
        }
    }
}

impl Default for TsigKeyStore {
    fn default() -> Self {
        Self::new()
    }
}
