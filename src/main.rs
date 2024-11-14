use std::process::ExitCode;

fn main() -> ExitCode {
    let env = dnst::env::real::RealEnv;
    dnst::run(env).into()
}
