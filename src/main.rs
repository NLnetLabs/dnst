use std::process::ExitCode;

use dnst::error::Error;
use dnst::parse_args;

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
    // If none of the ldns-* tools matched, then we continue with clap
    // argument parsing.
    parse_args(std::env::args_os)?.execute(&mut std::io::stdout())
}
