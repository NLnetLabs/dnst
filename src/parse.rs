use core::str::FromStr;

use domain::base::Name;

use crate::error::Error;

pub fn parse_name(arg: &str) -> Result<Name<Vec<u8>>, Error> {
    Name::from_str(&arg.to_lowercase()).map_err(|e| Error::from(e.to_string()))
}
