use std::borrow::Cow;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::{fmt, io};

use domain::net::client::dgram;
use domain::net::client::protocol::{AsyncConnect, AsyncDgramRecv, AsyncDgramSend};
use domain::resolv::stub::conf::ResolvConf;
use domain::resolv::StubResolver;
use domain::stelline::client::CurrStepValue;
use domain::stelline::dgram::Dgram;
use domain::stelline::parse_stelline::{self, Stelline};

use crate::error::Error;
use crate::{parse_args, run, Args};

use super::Env;
use super::Stream;

/// A command to run in a [`FakeEnv`]
///
/// This is used for testing the utilities, running the real code in a fake
/// environment.
#[derive(Clone)]
pub struct FakeCmd {
    /// The command to run, including `argv[0]`
    cmd: Vec<OsString>,
    cwd: Option<PathBuf>,
    stelline: Option<Stelline>,
}

/// The result of running a [`FakeCmd`]
///
/// The fields are public to allow for easy assertions in tests.
#[derive(Debug)]
pub struct FakeResult {
    pub exit_code: u8,
    pub stdout: String,
    pub stderr: String,
}

/// An environment that mocks interaction with the outside world
pub struct FakeEnv {
    /// Description of the command being run
    pub cmd: FakeCmd,

    /// The mocked stdout
    pub stdout: FakeStream,

    /// The mocked stderr
    pub stderr: FakeStream,

    pub stelline: Option<(Stelline, Arc<CurrStepValue>)>,
}

impl Env for FakeEnv {
    fn args_os(&self) -> impl Iterator<Item = OsString> {
        self.cmd.cmd.iter().map(Into::into)
    }

    fn stdout(&self) -> Stream<impl io::Write> {
        Stream {
            writer: Mutex::new(self.stdout.clone()),
            is_terminal: false,
        }
    }

    fn stderr(&self) -> Stream<impl io::Write + Send + Sync + 'static> {
        Stream {
            writer: Mutex::new(self.stderr.clone()),
            is_terminal: false,
        }
    }

    fn in_cwd<'a>(&self, path: &'a impl AsRef<Path>) -> Cow<'a, Path> {
        match &self.cmd.cwd {
            Some(cwd) => cwd.join(path).into(),
            None => path.as_ref().into(),
        }
    }

    fn dgram(
        &self,
        _src: SocketAddr,
        _dst: SocketAddr,
    ) -> impl AsyncConnect<Connection: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static>
           + Clone
           + Send
           + Sync
           + 'static {
        if let Some((stelline, step)) = &self.stelline {
            Dgram::new(stelline.clone(), step.clone())
        } else {
            panic!("Tried making a stelline connection without setting up stelline")
        }
    }

    async fn stub_resolver_from_conf(&self, mut config: ResolvConf) -> StubResolver {
        let Some((stelline, step)) = &self.stelline else {
            panic!("Tried making a stelline connection without setting up stelline")
        };

        config.servers = vec![];
        let resolver = StubResolver::from_conf(config);
        resolver
            .add_connection(Box::new(dgram::Connection::new(Dgram::new(
                stelline.clone(),
                step.clone(),
            ))))
            .await;
        resolver
    }
}

impl FakeCmd {
    /// Construct a new [`FakeCmd`] with a given command.
    ///
    /// The command can consist of multiple strings to specify a subcommand.
    pub fn new<S: Into<OsString>>(cmd: impl IntoIterator<Item = S>) -> Self {
        Self {
            cmd: cmd.into_iter().map(Into::into).collect(),
            cwd: None,
            stelline: None,
        }
    }

    pub fn cwd(&self, path: impl AsRef<Path>) -> Self {
        Self {
            cwd: Some(path.as_ref().to_path_buf()),
            ..self.clone()
        }
    }

    pub fn stelline(&self, file: impl fmt::Debug + io::Read, name: impl ToString) -> Self {
        Self {
            stelline: Some(parse_stelline::parse_file(file, name)),
            ..self.clone()
        }
    }

    /// Add arguments to a clone of the [`FakeCmd`]
    ///
    /// ```rust,ignore
    /// let cmd = FakeCmd::new(["dnst"])
    /// let sub1 = cmd.args(["sub1"]);  // dnst sub1
    /// let sub2 = cmd.args(["sub2"]);  // dnst sub2
    /// let sub3 = sub2.args(["sub3"]); // dnst sub2 sub3
    /// ```
    pub fn args<S: Into<OsString>>(&self, args: impl IntoIterator<Item = S>) -> Self {
        let mut new = self.clone();
        new.cmd.extend(args.into_iter().map(Into::into));
        new
    }

    /// Parse the arguments of this [`FakeCmd`] and return the result
    pub fn parse(&self) -> Result<Args, Error> {
        debug_assert!(
            self.stelline.is_none(),
            "We shouldn't need Stelline for argument parsing"
        );
        let env = FakeEnv {
            cmd: self.clone(),
            stdout: Default::default(),
            stderr: Default::default(),
            stelline: None,
        };
        parse_args(env)
    }

    /// Run the [`FakeCmd`] in a [`FakeEnv`], returning a [`FakeResult`]
    pub fn run(&self) -> FakeResult {
        let env = FakeEnv {
            cmd: self.clone(),
            stdout: Default::default(),
            stderr: Default::default(),
            stelline: self
                .stelline
                .clone()
                .map(|s| (s, Arc::new(CurrStepValue::new()))),
        };

        let exit_code = run(&env);

        FakeResult {
            exit_code,
            stdout: env.get_stdout(),
            stderr: env.get_stderr(),
        }
    }
}

impl FakeEnv {
    pub fn get_stdout(&self) -> String {
        String::from_utf8(self.stdout.0.lock().unwrap().clone()).unwrap()
    }

    pub fn get_stderr(&self) -> String {
        String::from_utf8(self.stderr.0.lock().unwrap().clone()).unwrap()
    }
}

/// A type to used to mock stdout and stderr
#[derive(Clone, Default)]
pub struct FakeStream(Arc<Mutex<Vec<u8>>>);

impl io::Write for FakeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // do nothing
        Ok(())
    }
}

impl fmt::Display for FakeStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(std::str::from_utf8(&self.0.lock().unwrap()).unwrap())
    }
}
