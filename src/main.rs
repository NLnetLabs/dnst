use std::process::ExitCode;

fn main() -> ExitCode {
    let env = dnst::env::RealEnv;
    ExitCode::from(dnst::run(env))
}
