use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    // If none of the ldns-* tools matched, then we continue with clap
    // argument parsing.
    let env_args = std::env::args_os();
    let args = dnst::try_ldns_compatibility(env_args).unwrap_or_else(dnst::Args::parse);

    match args.execute(&mut std::io::stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            err.pretty_print();
            ExitCode::FAILURE
        }
    }
}
