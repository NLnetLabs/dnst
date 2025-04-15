use core::str::FromStr;

use domain::base::Name;
use domain::tsig::{Algorithm, KeyName};
use domain::utils::base64;

use crate::error::Error;

pub fn parse_name(arg: &str) -> Result<Name<Vec<u8>>, Error> {
    Name::from_str(&arg.to_lowercase()).map_err(|e| Error::from(e.to_string()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TSigInfo {
    pub name: KeyName,
    pub key: Vec<u8>,
    pub algorithm: Algorithm,
}

impl FromStr for TSigInfo {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: better error messages
        let Some((mut name, rest)) = s.split_once(':') else {
            return Err("should contain at least one `:`".into());
        };

        let mut key;
        let mut algorithm;
        if let Some((k, a)) = rest.split_once(':') {
            key = k;
            algorithm = a;
        } else {
            key = rest;
            // This is different from the default algorithm that ldns-notify uses, which is MD5,
            // but we don't support that. So we use the default that is also used by dig when MD5
            // is disabled.
            algorithm = "hmac-sha256";
        };

        // With dig TSIG keys are also specified with -y,
        // but our format is: <name:key[:algo]>
        //      and dig's is: [hmac:]name:key
        //
        // When we detect an unknown TSIG algorithm in algo,
        // but a known algorithm in name, we can assume dig
        // order was used.
        //
        // We can correct this by checking whether the name contains a valid
        // algorithm while the algorithm doesn't.
        if Algorithm::from_str(algorithm).is_err() && Algorithm::from_str(name).is_ok() {
            (name, key, algorithm) = (key, algorithm, name);
        }

        let algorithm = Algorithm::from_str(algorithm)
            .map_err(|_| format!("Unsupported TSIG algorithm: {algorithm}"))?;

        let key = base64::decode(key).map_err(|e| format!("TSIG key is invalid base64: {e}"))?;

        let name = KeyName::from_str(name).map_err(|e| format!("TSIG name is invalid: {e}"))?;

        Ok(TSigInfo {
            name,
            key,
            algorithm,
        })
    }
}
