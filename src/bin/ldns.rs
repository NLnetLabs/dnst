//! This binary is intended for testing the `ldns-*` commands
//!
//! The `ldns` command is passed as the first argument, so that it can be
//! executed without symlinking. This binary should not be included in any
//! packaged version of `dnst` as it is meant for internal testing only.

use std::process::ExitCode;

use dnst::env::Env;
use dnst::log::LogFormatter;
use dnst::try_ldns_compatibility;
use tracing::level_filters::LevelFilter;

fn main() -> ExitCode {
    let env = dnst::env::RealEnv;
    run(env)
}

fn run(env: impl Env) -> ExitCode {
    let mut args = env.args_os();
    let argv0 = args.next().unwrap();
    let stderr = env.stderr();
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_ansi(stderr.is_terminal())
        .with_writer(stderr)
        .with_max_level(LevelFilter::WARN)
        .event_format(LogFormatter {
            program: argv0.to_string_lossy().to_string(),
        });

    let args =
        try_ldns_compatibility(args).map(|args| args.expect("ldns commmand lacks ldns- prefix"));
    tracing::subscriber::with_default(subscriber.finish(), || {
        match args.and_then(|args| args.execute(&env)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                err.pretty_print(env);
                ExitCode::FAILURE
            }
        }
    })
}
