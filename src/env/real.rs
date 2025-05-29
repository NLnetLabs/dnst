use core::future::Future;
use core::pin::Pin;

use std::ffi::OsString;
use std::io::{self, IsTerminal};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Mutex;

use domain::net::client::protocol::{AsyncConnect, AsyncDgramRecv, AsyncDgramSend};
use domain::resolv::stub::conf::ResolvConf;
use domain::resolv::StubResolver;
use tokio::net::UdpSocket;

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
        src: SocketAddr,
        dest: SocketAddr,
    ) -> impl AsyncConnect<Connection: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static>
           + Clone
           + Send
           + Sync
           + 'static {
        SpecificIpUdpConnect::new(src, dest)
    }

    async fn stub_resolver_from_conf(&self, config: ResolvConf) -> StubResolver {
        StubResolver::from_conf(config)
    }
}

//-------- SpecficIpUdpConnect -----------------------------------------------
//
// Based on domain::net::client::protocol::UdpConnect.

/// How many times do we try a new random port if we get ‘address in use.’
const RETRY_RANDOM_PORT: usize = 10;

/// Create new UDP connections from a specific local address.
#[derive(Clone, Copy, Debug)]
pub struct SpecificIpUdpConnect {
    /// Local address to connect from.
    src: SocketAddr,

    /// Remote address to connect to.
    dest: SocketAddr,
}

impl SpecificIpUdpConnect {
    /// Create new UDP connections.
    ///
    /// src is the source address to connect from.
    /// dest is the destination address to connect to.
    ///
    /// If the src port is 0 a random port will be chosen.
    ///
    /// If the src address is 0 local interface will be chosen.
    pub fn new(src: SocketAddr, dest: SocketAddr) -> Self {
        Self { src, dest }
    }

    /// Bind to a random local UDP port.
    async fn bind_and_connect(self) -> Result<UdpSocket, io::Error> {
        let mut i = 0;
        let sock = loop {
            match UdpSocket::bind(&self.src).await {
                Ok(sock) => break sock,
                Err(err) => {
                    if i == RETRY_RANDOM_PORT {
                        return Err(err);
                    } else {
                        i += 1
                    }
                }
            }
        };
        sock.connect(self.dest).await?;
        Ok(sock)
    }
}

impl AsyncConnect for SpecificIpUdpConnect {
    type Connection = UdpSocket;
    type Fut =
        Pin<Box<dyn Future<Output = Result<Self::Connection, std::io::Error>> + Send + Sync>>;

    fn connect(&self) -> Self::Fut {
        Box::pin(self.bind_and_connect())
    }
}
