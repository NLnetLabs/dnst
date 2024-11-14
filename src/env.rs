use std::ffi::OsString;
use std::fmt;
use std::io;

pub trait Env {
    // /// Make a network connection
    // fn make_connection(&self);

    // /// Make a new [`StubResolver`]
    // fn make_stub_resolver(&self);

    fn args_os(&self) -> impl Iterator<Item = OsString>;

    /// Get a reference to stdout
    fn stdout(&self) -> impl fmt::Write;

    /// Get a reference to stderr
    fn stderr(&self) -> impl fmt::Write;

    // Not needed yet
    // /// Get a reference to stdin
    // fn stdin(&self) -> impl io::Read;
}

impl<E: Env> Env for &mut E {
    // fn make_connection(&self) {
    //     todo!()
    // }

    // fn make_stub_resolver(&self) {
    //     todo!()
    // }

    fn args_os(&self) -> impl Iterator<Item = OsString> {
        (**self).args_os()
    }

    fn stdout(&self) -> impl fmt::Write {
        (**self).stdout()
    }

    fn stderr(&self) -> impl fmt::Write {
        (**self).stderr()
    }
}

/// Use real I/O
pub struct RealEnv;

impl Env for RealEnv {
    // fn make_connection(&self) {
    //     todo!()
    // }

    // fn make_stub_resolver(&self) {
    //     todo!()
    // }

    fn args_os(&self) -> impl Iterator<Item = OsString> {
        std::env::args_os()
    }

    fn stdout(&self) -> impl fmt::Write {
        FmtWriter(io::stdout().lock())
    }

    fn stderr(&self) -> impl fmt::Write {
        FmtWriter(io::stderr().lock())
    }
}

struct FmtWriter<T: io::Write>(T);

impl<T: io::Write> fmt::Write for FmtWriter<T> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        write!(self.0, "{s}").map_err(|_| fmt::Error)
    }
}
