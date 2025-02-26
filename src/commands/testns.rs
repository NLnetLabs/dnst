use core::future::pending;

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use crate::env::Env;
use crate::error::Error;
use crate::Args;

use domain::base::wire::Composer;
use domain::dep::octseq::{OctetsBuilder, Truncate};
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
use domain::net::server::service::{CallResult, ServiceError, ServiceResult};
use domain::net::server::stream::StreamServer;
use domain::net::server::util::service_fn;
use domain::stelline::client::CurrStepValue;
use domain::stelline::parse_stelline::{self, Stelline};
use domain::stelline::server::do_server;
use lexopt::Arg;
use tokio::net::{TcpListener, UdpSocket};

use super::{parse_os, Command, LdnsCommand};

#[derive(Clone, Debug, clap::Args, PartialEq, Eq)]
pub struct TestNs {
    /// Listens on the specified port, default 53.
    #[arg(short = 'p', value_name = "PORT")]
    port: Option<u16>,
    
    /// Verbose output.
    #[arg(short = 'v')]
    verbose: bool,

    /// Datafile
    #[arg()]
    datafile: PathBuf,

    /// Running in LDNS mode?
    #[arg(skip)]
    is_ldns: bool,
}

const LDNS_HELP: &str = "\
Usage: ldns-testns [options] <datafile>
  -p    listens on the specified port, default 53.
The program answers queries with canned replies from the datafile.\
";

impl LdnsCommand for TestNs {
    const NAME: &'static str = "testns";
    const HELP: &'static str = LDNS_HELP;
    const COMPATIBLE_VERSION: &'static str = "1.8.4";

    fn parse_ldns<I: IntoIterator<Item = OsString>>(args: I) -> Result<Args, Error> {
        let mut port = 53;
        let mut verbose = false;
        let mut datafile = None;

        let mut parser = lexopt::Parser::from_args(args);

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Short('p') => {
                    let val = parser.value()?;
                    port = parse_os("port (-p)", &val)?;
                }
                Arg::Short('v') => {
                    verbose = true:
                }
                Arg::Value(val) => {
                    if datafile.is_some() {
                        return Err("Only one datafile is allowed".into());
                    }
                    datafile = Some(val);
                }
                Arg::Short('v') => return Ok(Self::report_version()),
                Arg::Short(x) => return Err(format!("Invalid short option: -{x}").into()),
                Arg::Long(x) => {
                    return Err(format!("Long options are not supported, but `--{x}` given").into())
                }
            }
        }

        let Some(datafile) = datafile else {
            return Err("No datafile given".into());
        };

        Ok(Args::from(Command::TestNs(Self {
            port: Some(port),
            verbose,
            datafile: datafile.into(),
            is_ldns: true,
        })))
    }
}

impl TestNs {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(self.run(&env))
    }

    /// Run the command as an async function
    pub async fn run(self, env: &impl Env) -> Result<(), Error> {
        let port = self.port.unwrap();
        let mut datafile = std::fs::read_to_string(&self.datafile)?;

        if !datafile.contains("RANGE_BEGIN") {
            datafile.insert_str(0, "RANGE_BEGIN 0 999\n");
            datafile.push_str("RANGE_END\n");
        }
        if !datafile.contains("SCENARIO_BEGIN") {
            datafile.insert_str(0, "SCENARIO_BEGIN Scenario to emulate\n");
            datafile.push_str("SCENARIO_END\n");
        }
        if !datafile.contains("CONFIG_END") {
            datafile.insert_str(0, "CONFIG_END\n");
        }

        let stelline = Arc::new(parse_stelline::parse_file(
            datafile.as_bytes(),
            self.datafile.to_str().unwrap(),
        ));

        let svc = service_fn(refuse_service, stelline);

        let sock = UdpSocket::bind(format!("127.0.0.1:{port}")).await.unwrap();
        let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .unwrap();

        if self.is_ldns && self.verbose {
            writeln!(env.stdout(), "Listening on port {port}");
        }

        let udp_srv = DgramServer::new(sock, VecBufSource, svc.clone());
        tokio::spawn(async move { udp_srv.run().await });

        let tcp_srv = StreamServer::new(listener, VecBufSource, svc);
        tokio::spawn(async move { tcp_srv.run().await });

        Ok(pending().await)
    }
}

fn refuse_service(
    req: Request<Vec<u8>>,
    stelline: Arc<Stelline>,
) -> ServiceResult<AtLeastTwoBytesVec> {
    let step_value = CurrStepValue::new();
    match do_server(&req, &stelline, &step_value) {
        Some(builder) => Ok(CallResult::new(builder)),
        None => Err(ServiceError::Refused),
    }
}

// Hacky work around for the fact that StreamTarget::default() calls
// Target::default() which in our case creates an empty Vec, which will then
// cause a panic when the Stelline code creates an empty target via the
// Default trait thereby invoking truncate() which attempts to truncate to len
// + 2, but truncation of len + 2 is a NO-OP and then the Vec doesn't have the
// expected two leading TCP stream length header bytes and an out of bounds
// access occurs.
#[derive(Clone)]
struct AtLeastTwoBytesVec(Vec<u8>);

impl Default for AtLeastTwoBytesVec {
    fn default() -> Self {
        Self(vec![0, 0])
    }
}

impl std::ops::Deref for AtLeastTwoBytesVec {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for AtLeastTwoBytesVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Composer for AtLeastTwoBytesVec {}

impl Truncate for AtLeastTwoBytesVec {
    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

impl AsMut<[u8]> for AtLeastTwoBytesVec {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl AsRef<[u8]> for AtLeastTwoBytesVec {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl OctetsBuilder for AtLeastTwoBytesVec {
    type AppendError = <Vec<u8> as OctetsBuilder>::AppendError;

    fn append_slice(&mut self, slice: &[u8]) -> Result<(), Self::AppendError> {
        self.0.append_slice(slice)
    }
}
