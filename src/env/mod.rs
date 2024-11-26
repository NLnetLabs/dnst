use std::borrow::Cow;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::path::Path;

mod real;

#[cfg(test)]
pub mod fake;

pub use real::RealEnv;

use crate::error::Result;

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

    /// Make relative paths absolute.
    fn in_cwd<'a>(&self, path: &'a impl AsRef<Path>) -> Cow<'a, Path>;

    /// Create and open a file.
    fn fs_create_new(&self, path: impl AsRef<Path>) -> Result<File> {
        let path = path.as_ref();
        let abs_path = self.in_cwd(&path);
        File::create_new(abs_path)
            .map_err(|err| format!("cannot create '{}': {err}", path.display()).into())
    }

    /// Rename a path.
    fn fs_rename(&self, old: impl AsRef<Path>, new: impl AsRef<Path>) -> Result<()> {
        let (old, new) = (old.as_ref(), new.as_ref());
        let abs_old = self.in_cwd(&old);
        let abs_new = self.in_cwd(&new);
        std::fs::rename(abs_old, abs_new).map_err(|err| {
            format!(
                "could not move '{}' to '{}': {err}",
                old.display(),
                new.display()
            )
            .into()
        })
    }

    /// Create a symlink.
    #[cfg(unix)]
    fn fs_symlink(&self, target: impl AsRef<Path>, link: impl AsRef<Path>) -> Result<()> {
        let (target, link) = (target.as_ref(), link.as_ref());
        let target_path = self.in_cwd(&target);
        let link_path = self.in_cwd(&link);
        std::os::unix::fs::symlink(target_path, link_path).map_err(|err| {
            format!(
                "could not create symlink '{}' to '{}': {err}",
                link.display(),
                target.display(),
            )
            .into()
        })
    }

    /// Create a symlink, overwriting if it already exists.
    #[cfg(unix)]
    fn fs_symlink_force(&self, target: impl AsRef<Path>, link: impl AsRef<Path>) -> Result<()> {
        use crate::error::in_context;

        let (target, link) = (target.as_ref(), link.as_ref());
        let mut temp = link.to_path_buf();
        temp.as_mut_os_string().push(".new");

        in_context(
            || {
                format!(
                    "creating symlink '{}' to '{}'",
                    link.display(),
                    target.display()
                )
            },
            || {
                self.fs_symlink(target, &temp)?;
                self.fs_rename(&temp, link)?;
                Ok(())
            },
        )
    }
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
