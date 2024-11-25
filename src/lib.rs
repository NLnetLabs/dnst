use std::ffi::OsString;
use std::path::Path;

use clap::Parser;
use commands::key2ds::Key2ds;
use commands::nsec3hash::Nsec3Hash;
use commands::signzone::SignZone;
use commands::LdnsCommand;
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

    let binary_name = extract_binary_name(Path::new(&binary_path))?;

    // We only branch on the binary name for the ldns utilities. The rest we
    // just handle as regular dnst.
    let Some(binary_name) = binary_name.strip_prefix("ldns-") else {
        return Ok(None);
    };

    let res = match binary_name {
        "key2ds" => Key2ds::parse_ldns_args(args_iter),
        "nsec3-hash" => Nsec3Hash::parse_ldns_args(args_iter),
        "signzone" => SignZone::parse_ldns_args(args_iter),
        _ => return Err(format!("Unrecognized ldns command 'ldns-{binary_name}'").into()),
    };

    Ok(Some(res?))
}

/// Get the binary name from a [`Path`].
///
/// The binary name is the file name without any extensions. It is similar
/// to the unstable `Path::file_stem`.
///
/// ```rust
/// use dnst::extract_binary_name;
/// use std::path::Path;
///
/// let bin = extract_binary_name(Path::new("foo/ldns-xxx")).unwrap();
/// assert_eq!(bin, "ldns-xxx");
///
/// let bin = extract_binary_name(Path::new("foo/ldns-xxx.real")).unwrap();
/// assert_eq!(bin, "ldns-xxx");
///
/// let bin = extract_binary_name(Path::new("./ldns-xxx.exe")).unwrap();
/// assert_eq!(bin, "ldns-xxx");
///
/// let bin = extract_binary_name(Path::new("ldns-xxx")).unwrap();
/// assert_eq!(bin, "ldns-xxx");
/// ```
pub fn extract_binary_name(path: &Path) -> Result<&str, Error> {
    let filename = path
        .file_name()
        .ok_or("Missing binary file name")?
        .to_str()
        .ok_or("Binary file name is not valid unicode")?;

    match filename.split_once('.') {
        Some((binary, _)) => Ok(binary),
        None => Ok(filename),
    }
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
