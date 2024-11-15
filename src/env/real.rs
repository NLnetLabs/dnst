use std::ffi::OsString;
use std::fmt;
use std::io;

use super::Env;

/// Use real I/O
pub struct RealEnv;

impl Env for RealEnv {
    fn args_os(&self) -> impl Iterator<Item = OsString> {
        std::env::args_os()
    }

    fn stdout(&self) -> impl fmt::Write {
        FmtWriter(io::stdout())
    }

    fn stderr(&self) -> impl fmt::Write {
        FmtWriter(io::stderr())
    }
}

struct FmtWriter<T: io::Write>(T);

impl<T: io::Write> fmt::Write for FmtWriter<T> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        write!(self.0, "{s}").map_err(|_| fmt::Error)
    }
}
