pub mod args;
pub mod commands;
pub mod error;

use std::{ffi::OsString, path::Path};

use clap::Parser;

use args::Args;
use commands::{nsec3hash::Nsec3Hash, LdnsCommand};
use error::Error;

pub fn parse_args<I: IntoIterator<Item = OsString>, T: Fn() -> I>(
    args_provider: T,
) -> Result<Args, Error> {
    try_ldns_compatibility(args_provider()).or_else(|_| {
        Args::try_parse_from(args_provider()).map_err(|err| Error::new(err.to_string().as_str()))
    })
}

pub fn try_ldns_compatibility<I: IntoIterator<Item = OsString>>(args: I) -> Result<Args, Error> {
    let mut args_iter = args.into_iter();
    let binary_path = args_iter
        .next()
        .ok_or::<Error>("Missing binary name".into())?;

    let binary_name = Path::new(&binary_path)
        .file_name()
        .ok_or::<Error>("Missing binary file name".into())?
        .to_str()
        .ok_or("Binary file name is not valid Unicode")?;

    match binary_name {
        "ldns-nsec3-hash" => Nsec3Hash::parse_ldns_args(args_iter),
        _ => Err("Unrecognised LDNS command".into()),
    }
}
