use std::borrow::Cow;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::path::Path;
use std::sync::Mutex;
use std::{fmt, io};

use domain::net::client::protocol::{AsyncConnect, AsyncDgramRecv, AsyncDgramSend};
use domain::resolv::{stub::conf::ResolvConf, StubResolver};
use tracing_subscriber::fmt::MakeWriter;

#[cfg(test)]
pub mod fake;

mod real;
pub use real::RealEnv;

pub trait Env {
    /// Get an iterator over the command line arguments passed to the program
    ///
    /// Equivalent to [`std::env::args_os`]
    fn args_os(&self) -> impl Iterator<Item = OsString>;

    /// Get a reference to stdout
    ///
    /// Equivalent to [`std::io::stdout`]
    fn stdout(&self) -> Stream<impl io::Write>;

    /// Get a reference to stderr
    ///
    /// Equivalent to [`std::io::stderr`]
    fn stderr(&self) -> Stream<impl io::Write + Send + Sync + 'static>;

    // /// Get a reference to stdin
    // fn stdin(&self) -> impl io::Read;

    /// Make relative paths absolute.
    fn in_cwd<'a>(&self, path: &'a impl AsRef<Path>) -> Cow<'a, Path>;

    /// Get the number of seconds since the UNIX epoch.
    fn seconds_since_epoch(&self) -> u32;

    /// Set the number of seconds since the UNIX epoch.
    ///
    /// Only for use by FakeEnv, should not do anything in RealEnv.
    fn set_seconds_since_epoch(&mut self, seconds: u32);

    fn dgram(
        &self,
        socket: SocketAddr,
    ) -> impl AsyncConnect<Connection: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static>
           + Clone
           + Send
           + Sync
           + 'static;

    #[allow(async_fn_in_trait)]
    async fn stub_resolver(&self) -> StubResolver {
        self.stub_resolver_from_conf(ResolvConf::default()).await
    }

    #[allow(async_fn_in_trait)]
    async fn stub_resolver_from_conf(&self, config: ResolvConf) -> StubResolver;
}

/// A type with an infallible `write_fmt` method for use with [`write!`] macros
///
/// This ensures that we don't have to `use` either [`std::fmt::Write`] or
/// [`std::io::Write`]. Additionally, this `write_fmt` does not return a
/// result. This means that we can use the [`write!`] and [`writeln`] macros
/// without handling errors.
pub struct Stream<T: io::Write> {
    writer: Mutex<T>,
    is_terminal: bool,
}

impl<'writer, T: io::Write + 'writer> MakeWriter<'writer> for Stream<T> {
    type Writer = &'writer Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self
    }
}

impl<T: io::Write> io::Write for &Stream<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.lock().unwrap().deref_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.lock().unwrap().deref_mut().flush()
    }
}

impl<T: io::Write> Stream<T> {
    pub fn write_fmt(&mut self, args: fmt::Arguments<'_>) {
        // This unwrap is not _really_ safe, but we are using this as stdout.
        // The `println` macro also ignores errors and `push_str` of the
        // fake stream also does not return an error. If this fails, it means
        // we can't write to stdout anymore so a graceful exit will be very
        // hard anyway.
        self.writer
            .lock()
            .unwrap()
            .deref_mut()
            .write_fmt(args)
            .unwrap();
    }

    pub fn is_terminal(&self) -> bool {
        self.is_terminal
    }
}

impl<E: Env> Env for &E {
    fn args_os(&self) -> impl Iterator<Item = OsString> {
        (**self).args_os()
    }

    fn stdout(&self) -> Stream<impl io::Write> {
        (**self).stdout()
    }

    fn stderr(&self) -> Stream<impl io::Write + Send + Sync + 'static> {
        (**self).stderr()
    }

    fn in_cwd<'a>(&self, path: &'a impl AsRef<Path>) -> Cow<'a, Path> {
        (**self).in_cwd(path)
    }

    fn seconds_since_epoch(&self) -> u32 {
        (**self).seconds_since_epoch()
    }

    fn set_seconds_since_epoch(&mut self, _seconds: u32) {
        unreachable!()
    }

    fn dgram(
        &self,
        socket: SocketAddr,
    ) -> impl AsyncConnect<Connection: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static>
           + Clone
           + Send
           + Sync
           + 'static {
        (**self).dgram(socket)
    }

    async fn stub_resolver_from_conf(&self, config: ResolvConf) -> StubResolver {
        (**self).stub_resolver_from_conf(config).await
    }
}

impl<E: Env> Env for &mut E {
    fn args_os(&self) -> impl Iterator<Item = OsString> {
        (**self).args_os()
    }

    fn stdout(&self) -> Stream<impl io::Write> {
        (**self).stdout()
    }

    fn stderr(&self) -> Stream<impl io::Write + Send + Sync + 'static> {
        (**self).stderr()
    }

    fn in_cwd<'a>(&self, path: &'a impl AsRef<Path>) -> Cow<'a, Path> {
        (**self).in_cwd(path)
    }

    fn seconds_since_epoch(&self) -> u32 {
        (**self).seconds_since_epoch()
    }

    fn set_seconds_since_epoch(&mut self, seconds: u32) {
        (**self).set_seconds_since_epoch(seconds);
    }

    fn dgram(
        &self,
        socket: SocketAddr,
    ) -> impl AsyncConnect<Connection: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static>
           + Clone
           + Send
           + Sync
           + 'static {
        (**self).dgram(socket)
    }

    async fn stub_resolver_from_conf(&self, config: ResolvConf) -> StubResolver {
        (**self).stub_resolver_from_conf(config).await
    }
}
