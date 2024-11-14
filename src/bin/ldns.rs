//! This binary is intended for testing the `ldns-*` commands
//!
//! The `ldns` command is passed as the first argument, so that it can be
//! executed without symlinking. This binary should not be included in any
//! packaged version of `dnst` as it is meant for internal testing only.

use std::process::ExitCode;

use dnst::error::Error;
use dnst::try_ldns_compatibility;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            err.pretty_print();
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Error> {
    let mut args = std::env::args_os();
    args.next().unwrap();
    try_ldns_compatibility(args)
        .ok_or("Unrecognised ldns command")??
        .execute(&mut std::io::stdout())
}
