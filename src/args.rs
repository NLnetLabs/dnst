use super::commands::Command;
use super::error::Error;

#[derive(Clone, Debug, clap::Parser)]
#[command(version, disable_help_subcommand = true)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

impl Args {
    pub fn execute(self) -> Result<(), Error> {
        self.command.execute()
    }
}

impl From<Command> for Args {
    fn from(value: Command) -> Self {
        Args { command: value }
    }
}
