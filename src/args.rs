use crate::env::Env;

use super::commands::Command;
use super::error::Error;

use clap::Parser;

#[derive(Clone, Debug, Parser)]
#[command(version, disable_help_subcommand = true)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

impl Args {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        self.command.execute(env)
    }
}

impl From<Command> for Args {
    fn from(value: Command) -> Self {
        Args { command: value }
    }
}
