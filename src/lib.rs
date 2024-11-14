pub mod args;
pub mod commands;
pub mod error;

use std::{ffi::OsString, path::Path};

use clap::Parser;

use args::Args;
use clap::error::ErrorKind;
use commands::Command;
use commands::{nsec3hash::Nsec3Hash, LdnsCommand};
use error::Error;

pub fn parse_args<I: IntoIterator<Item = OsString>, T: Fn() -> I>(
    args_provider: T,
) -> Result<Args, Error> {
    try_ldns_compatibility(args_provider()).unwrap_or_else(|| {
        match Args::try_parse_from(args_provider()) {
            Err(err) if err.kind() == ErrorKind::DisplayVersion => Ok(Args::from(
                Command::Version(crate::commands::version::Version),
            )),

            Err(err) => Err(Error::new(err.to_string().as_str())),

            Ok(args) => Ok(args),
        }
    })
}

pub fn try_ldns_compatibility<I: IntoIterator<Item = OsString>>(
    args: I,
) -> Option<Result<Args, Error>> {
    let mut args_iter = args.into_iter();
    let binary_path = args_iter.next()?;
    let binary_name = Path::new(&binary_path).file_name()?;

    match binary_name.to_string_lossy().to_string().as_str() {
        "ldns-nsec3-hash" => Some(Nsec3Hash::parse_ldns_args(args_iter)),
        _ => None,
    }
}
