use std::process::ExitCode;

fn main() -> ExitCode {
    let env = dnst::env::RealEnv;
    dnst::run(env).into()
}

fn run() -> Result<(), Error> {
    // If none of the ldns-* tools matched, then we continue with clap
    // argument parsing.
    parse_args(std::env::args_os)?.execute(&mut std::io::stdout())
}
