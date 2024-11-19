use std::process::ExitCode;

fn main() -> ExitCode {
    let env = dnst::env::RealEnv;
    dnst::run(env).into()
}
