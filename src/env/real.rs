use std::ffi::OsString;
use std::fmt;
use std::io::{self, IsTerminal};
use std::path::Path;

use domain::net::client::protocol::{AsyncConnect, AsyncDgramRecv, AsyncDgramSend, UdpConnect};
use domain::resolv::stub::conf::ResolvConf;
use domain::resolv::StubResolver;

use super::Env;
use super::Stream;

/// Use real I/O
pub struct RealEnv;

impl Env for RealEnv {
    fn args_os(&self) -> impl Iterator<Item = OsString> {
        std::env::args_os()
    }

    fn stdout(&self) -> Stream<impl fmt::Write> {
        Stream::new(FmtWriter(io::stdout()), io::stdout().is_terminal())
    }

    fn stderr(&self) -> Stream<impl fmt::Write> {
        Stream::new(FmtWriter(io::stderr()), io::stderr().is_terminal())
    }

    fn in_cwd<'a>(&self, path: &'a impl AsRef<Path>) -> std::borrow::Cow<'a, std::path::Path> {
        path.as_ref().into()
    }

    fn dgram(
        &self,
        addr: std::net::SocketAddr,
    ) -> impl AsyncConnect<Connection: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static>
           + Clone
           + Send
           + Sync
           + 'static {
        UdpConnect::new(addr)
    }

    async fn stub_resolver_from_conf(&self, config: ResolvConf) -> StubResolver {
        StubResolver::from_conf(config)
    }
}

struct FmtWriter<T: io::Write>(T);

impl<T: io::Write> fmt::Write for FmtWriter<T> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.write_all(s.as_bytes()).map_err(|_| fmt::Error)
    }

    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        self.0.write_fmt(args).map_err(|_| fmt::Error)
    }
}
