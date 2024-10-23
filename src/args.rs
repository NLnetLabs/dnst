use std::path::Path;

use super::commands::Command;
use super::error::Error;

use clap::Parser;

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

    pub fn parse_args() -> Self {
        let mut args = std::env::args();
        let path = args.next().unwrap_or_default();

        let name = Path::new(&path)
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();

        let args: Vec<_> = args.collect();
        match Self::parse_ldns_args(name, &args) {
            Ok(Some(args)) => args,
            Ok(None) => Self::parse(),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }

    pub fn parse_ldns_args(name: &str, args: &[String]) -> Result<Option<Self>, Error> {
        let command = Command::parse_ldns_args(name, args)?;
        Ok(command.map(|command| Self { command }))
    }
}
