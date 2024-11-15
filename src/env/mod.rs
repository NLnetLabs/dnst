use std::ffi::OsString;
use std::fmt;

mod real;

#[cfg(test)]
pub mod fake;

pub use real::RealEnv;

pub trait Env {
    // /// Make a network connection
    // fn make_connection(&self);

    // /// Make a new [`StubResolver`]
    // fn make_stub_resolver(&self);

    /// Get an iterator over the command line arguments passed to the program
    ///
    /// Equivalent to [`std::env::args_os`]
    fn args_os(&self) -> impl Iterator<Item = OsString>;

    /// Get a reference to stdout
    ///
    /// Equivalent to [`std::io::stdout`]
    fn stdout(&self) -> impl fmt::Write;

    /// Get a reference to stderr
    ///
    /// Equivalent to [`std::io::stderr`]
    fn stderr(&self) -> impl fmt::Write;

    // /// Get a reference to stdin
    // fn stdin(&self) -> impl io::Read;
}

impl<E: Env> Env for &E {
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
