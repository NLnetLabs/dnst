//! This binary is intended for testing the `ldns-*` commands
//!
//! The `ldns` command is passed as the first argument, so that it can be
//! executed without symlinking. This binary should not be included in any
//! packaged version of `dnst` as it is meant for internal testing only.

use std::process::ExitCode;

use dnst::try_ldns_compatibility;

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    args.next().unwrap();
    let args = try_ldns_compatibility(args).expect("ldns commmand is not recognized");

    match args.execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            err.pretty_print();
            ExitCode::FAILURE
        }
    }
}
