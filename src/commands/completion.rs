use std::path::Path;

use crate::env::Env;
use crate::error::Error;
use crate::{extract_binary_name, Args};

#[derive(Clone, Debug, clap::Args)]
pub struct Completion {
    #[arg(value_name = "SHELL")]
    shell: clap_complete::Shell,
}

impl Completion {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        let binary_path = env.args_os().next().ok_or("Missing binary name")?;
        let binary_name = extract_binary_name(Path::new(&binary_path))?;

        clap_complete::generate(
            self.shell,
            &mut <Args as clap::CommandFactory>::command(),
            binary_name,
            &mut &env.stdout(),
        );

        Ok(())
    }
}
