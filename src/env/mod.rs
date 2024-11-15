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
    fn stdout(&self) -> Stream<impl fmt::Write>;

    /// Get a reference to stderr
    ///
    /// Equivalent to [`std::io::stderr`]
    fn stderr(&self) -> Stream<impl fmt::Write>;

    // /// Get a reference to stdin
    // fn stdin(&self) -> impl io::Read;
}

/// A type with an infallible `write_fmt` method for use with [`write!`] macros
///
/// This ensures that we don't have to `use` either [`std::fmt::Write`] or
/// [`std::io::Write`]. Additionally, this `write_fmt` does not return a
/// result. This means that we can use the [`write!`] and [`writeln`] macros
/// without handling errors.
pub struct Stream<T: fmt::Write>(T);

impl<T: fmt::Write> Stream<T> {
    pub fn write_fmt(&mut self, args: fmt::Arguments<'_>) {
        self.0.write_fmt(args).unwrap();
    }
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

    fn stdout(&self) -> Stream<impl fmt::Write> {
        (**self).stdout()
    }

    fn stderr(&self) -> Stream<impl fmt::Write> {
        (**self).stderr()
    }
}
