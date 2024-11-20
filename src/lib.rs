use std::ffi::OsString;
use std::path::Path;

use clap::Parser;
use commands::LdnsCommand;
use commands::key2ds::Key2ds;
use commands::nsec3hash::Nsec3Hash;
use commands::signzone::SignZone;
use env::Env;
use error::Error;

pub use self::args::Args;

pub mod args;
pub mod commands;
pub mod env;
pub mod error;

pub fn try_ldns_compatibility<I: IntoIterator<Item = OsString>>(
    args: I,
) -> Result<Option<Args>, Error> {
    let mut args_iter = args.into_iter();
    let binary_path = args_iter.next().ok_or("Missing binary name")?;

    let binary_name = Path::new(&binary_path)
        .file_name()
        .ok_or("Missing binary file name")?
        .to_str()
        .ok_or("Binary file name is not valid unicode")?;

    let res = match binary_name {
        "ldns-key2ds" => Key2ds::parse_ldns_args(args_iter),
        "ldns-nsec3-hash" => Nsec3Hash::parse_ldns_args(args_iter),
        "ldns-signzone" => SignZone::parse_ldns_args(args_iter),
        _ => return Ok(None),
    };

    res.map(Some)
}

fn parse_args(env: impl Env) -> Result<Args, Error> {
    if let Some(args) = try_ldns_compatibility(env.args_os())? {
        return Ok(args);
    }
    let args = Args::try_parse_from(env.args_os())?;
    Ok(args)
}

pub fn run(env: impl Env) -> u8 {
    let res = parse_args(&env).and_then(|args| args.execute(&env));
    match res {
        Ok(()) => 0,
        Err(err) => {
            err.pretty_print(&env);
            err.exit_code()
        }
    }
}
