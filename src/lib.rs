use std::{ffi::OsString, path::Path};

use commands::{keygen::Keygen, nsec3hash::Nsec3Hash, LdnsCommand};

pub use self::args::Args;

pub mod args;
pub mod commands;
pub mod error;
pub mod parse;

pub fn try_ldns_compatibility<I: IntoIterator<Item = OsString>>(args: I) -> Option<Args> {
    let mut args_iter = args.into_iter();
    let binary_path = args_iter.next()?;

    let binary_name = Path::new(&binary_path).file_name()?.to_str()?;

    let res = match binary_name {
        "ldns-nsec3-hash" => Nsec3Hash::parse_ldns_args(args_iter),
        "ldns-keygen" => Keygen::parse_ldns_args(args_iter),
        _ => return None,
    };

    match res {
        Ok(args) => Some(args),
        Err(err) => {
            err.pretty_print();
            std::process::exit(1)
        }
    }
}
