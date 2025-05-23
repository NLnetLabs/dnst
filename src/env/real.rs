use std::ffi::OsString;
use std::io::{self, IsTerminal};
use std::path::Path;
use std::sync::Mutex;

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

    fn stdout(&self) -> Stream<impl io::Write> {
        let stdout = io::stdout();
        Stream {
            is_terminal: stdout.is_terminal(),
            writer: Mutex::new(stdout),
        }
    }

    fn stderr(&self) -> Stream<impl io::Write + Send + Sync + 'static> {
        let stderr = io::stderr();
        Stream {
            is_terminal: stderr.is_terminal(),
            writer: Mutex::new(stderr),
        }
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
