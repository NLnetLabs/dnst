use std::io::Write;

use crate::error::Error;

#[derive(Clone, Debug, clap::Args)]
pub struct Version;

impl Version {
    pub fn execute<W: Write>(self, writer: &mut W) -> Result<(), Error> {
        writeln!(writer, clap::crate_version!()).map_err(Into::into)
    }
}
