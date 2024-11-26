use crate::env::Env;

use super::commands::Command;
use super::error::Error;

#[derive(Clone, Debug, clap::Parser)]
#[command(version, disable_help_subcommand = true)]
pub struct Args {
    /// The command that was invoked.
    #[command(subcommand)]
    pub command: Command,

    /// Whether the command was invoked as an LDNS alias or not.
    #[clap(skip = false)]
    is_ldns: bool,
}

impl Args {
    pub fn new(command: Command, is_ldns: bool) -> Self {
        Self { command, is_ldns }
    }

    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        self.command.execute(env, self.is_ldns)
    }
}
