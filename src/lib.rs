use std::ffi::OsString;
use std::path::Path;

use clap::Parser;
use commands::{nsec3hash::Nsec3Hash, LdnsCommand};
use env::Env;

pub use self::args::Args;

pub mod args;
pub mod commands;
pub mod env;
pub mod error;

pub fn try_ldns_compatibility<I: IntoIterator<Item = OsString>>(args: I) -> Option<Args> {
    let mut args_iter = args.into_iter();
    let binary_path = args_iter.next()?;

    let binary_name = Path::new(&binary_path).file_name()?.to_str()?;

    let res = match binary_name {
        "ldns-nsec3-hash" => Nsec3Hash::parse_ldns_args(args_iter),
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

pub fn run(env: impl Env) -> u8 {
    let env_args = env.args_os();
    let args = try_ldns_compatibility(env_args).unwrap_or_else(|| Args::parse_from(env.args_os()));
    match args.execute(env) {
        Ok(()) => 0,
        Err(err) => {
            err.pretty_print();
            1
        }
    }
}
