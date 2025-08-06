use crate::env::Env;

use super::commands::Command;
use super::error::Error;

use clap::Parser;

#[derive(Clone, Debug, Parser)]
#[command(version, disable_help_subcommand = true)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,

    /// Verbosity. 0-5 or level name ("off" to "trace")
    #[arg(
        short = 'v',
        long = "verbosity",
        value_name = "level",
        default_value_t = tracing_subscriber::filter::LevelFilter::from_level(tracing::Level::WARN),
    )]
    pub verbosity: tracing_subscriber::filter::LevelFilter,
}

impl Args {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        self.command.execute(env)
    }
}

impl From<Command> for Args {
    fn from(value: Command) -> Self {
        Args {
            command: value,
            verbosity: tracing_subscriber::filter::LevelFilter::from_level(tracing::Level::WARN),
        }
    }
}
