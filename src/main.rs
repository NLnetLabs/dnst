use std::path::Path;
use std::process::ExitCode;

use clap::Parser;
use dnst::commands::{nsec3hash::Nsec3Hash, LdnsCommand};

fn main() -> ExitCode {
    // If none of the ldns-* tools matched, then we continue with clap
    // argument parsing.
    let args = try_ldns_compatibility().unwrap_or_else(dnst::Args::parse);

    match args.execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            err.pretty_print();
            ExitCode::FAILURE
        }
    }
}

fn try_ldns_compatibility() -> Option<dnst::Args> {
    let binary_path = std::env::args_os().next()?;

    let binary_name = Path::new(&binary_path).file_name()?.to_str()?;

    let res = match binary_name {
        "ldns-nsec3-hash" => Nsec3Hash::parse_ldns_args(),
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
