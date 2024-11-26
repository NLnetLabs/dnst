use std::borrow::Cow;
use std::ffi::OsString;
use std::fmt;
use std::path::Path;

mod real;

#[cfg(test)]
pub mod fake;

pub use real::RealEnv;

pub trait Env {
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

    fn in_cwd<'a>(&self, path: &'a impl AsRef<Path>) -> Cow<'a, Path>;
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
        // This unwrap is not _really_ safe, but we are using this as stdout.
        // The `println` macro also ignores errors and `push_str` of the
        // fake stream also does not return an error. If this fails, it means
        // we can't write to stdout anymore so a graceful exit will be very
        // hard anyway.
        self.0.write_fmt(args).unwrap();
    }

    pub fn write_str(&mut self, s: &str) {
        // Same as with write_fmt...
        self.0.write_str(s).unwrap();
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

    fn in_cwd<'a>(&self, path: &'a impl AsRef<Path>) -> Cow<'a, Path> {
        (**self).in_cwd(path)
    }
}
