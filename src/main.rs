use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    match dnst::Args::parse().execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            err.pretty_print();
            ExitCode::FAILURE
        }
    }
}
