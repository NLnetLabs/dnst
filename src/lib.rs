use std::ffi::OsString;
use std::path::Path;

use clap::Parser;
use commands::{key2ds::Key2ds, notify::Notify, nsec3hash::Nsec3Hash, LdnsCommand};
use env::Env;
use error::Exit;

pub use self::args::Args;

pub mod args;
pub mod commands;
pub mod env;
pub mod error;

pub fn try_ldns_compatibility<I: IntoIterator<Item = OsString>>(
    env: impl Env,
    args: I,
) -> Result<Option<Args>, Exit> {
    let mut args_iter = args.into_iter();
    let binary_path = args_iter.next().ok_or("Missing binary name")?;

    let binary_name = Path::new(&binary_path)
        .file_name()
        .ok_or("Missing binary file name")?
        .to_str()
        .ok_or("Binary file name is not valid unicode")?;

    let res = match binary_name {
        "ldns-key2ds" => Key2ds::parse_ldns_args(env, args_iter),
        "ldns-nsec3-hash" => Nsec3Hash::parse_ldns_args(env, args_iter),
        "ldns-notify" => Notify::parse_ldns_args(env, args_iter),
        _ => return Ok(None),
    };

    res.map(Some)
}

fn parse_args(env: impl Env) -> Result<Args, Exit> {
    if let Some(args) = try_ldns_compatibility(&env, env.args_os())? {
        return Ok(args);
    }
    let args = Args::try_parse_from(env.args_os())?;
    Ok(args)
}

pub fn run(env: impl Env) -> u8 {
    let res = parse_args(&env).and_then(|args| Ok(args.execute(&env)?));
    match res {
        Ok(()) | Err(Exit::Success) => 0,
        Err(Exit::Error(err)) => {
            err.pretty_print(&env);
            err.exit_code()
        }
    }
}
