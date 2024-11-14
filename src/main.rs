use std::process::ExitCode;

fn main() -> ExitCode {
    let env = dnst::env::real::RealEnv;
    ExitCode::from(dnst::run(env))
}
