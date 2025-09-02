use crate::env::Env;

use super::commands::Command;
use super::error::Error;

use clap::Parser;
use tracing::level_filters::LevelFilter;

#[derive(Clone, Debug, Parser)]
#[command(version, disable_help_subcommand = true)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,

    /// Verbosity: 0-5 or a level name ("off", "error", "warn", "info", "debug" or "trace")
    #[arg(
        short = 'v',
        long = "verbosity",
        value_name = "level",
        default_value_t = LevelFilter::from_level(tracing::Level::WARN),
    )]
    pub verbosity: LevelFilter,
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
            verbosity: LevelFilter::from_level(tracing::Level::WARN),
        }
    }
}
