use std::collections::HashMap;

use domain::base::Name;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AlgSpec {
    /// SHA-1.
    Sha1,

    /// SHA-256.
    Sha256,

    /// SHA-384,
    Sha384,

    /// SHA-512.
    Sha512,
}

impl From<AlgSpec> for domain::tsig::Algorithm {
    fn from(alg: AlgSpec) -> Self {
        match alg {
            AlgSpec::Sha1 => domain::tsig::Algorithm::Sha1,
            AlgSpec::Sha256 => domain::tsig::Algorithm::Sha256,
            AlgSpec::Sha384 => domain::tsig::Algorithm::Sha384,
            AlgSpec::Sha512 => domain::tsig::Algorithm::Sha512,
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
    pub data: Box<[u8]>,
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
