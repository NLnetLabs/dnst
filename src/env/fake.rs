use std::borrow::Cow;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;

use crate::{error::Error, parse_args, run, Args};

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
    // pub stelline: Option<Stelline>,
    // pub curr_step_value: Option<Arc<CurrStepValue>>,
}

impl Env for FakeEnv {
    fn args_os(&self) -> impl Iterator<Item = OsString> {
        self.cmd.cmd.iter().map(Into::into)
    }

    fn stdout(&self) -> Stream<impl fmt::Write> {
        Stream(self.stdout.clone(), false)
    }

    fn stderr(&self) -> Stream<impl fmt::Write> {
        Stream(self.stderr.clone(), false)
    }

    fn in_cwd<'a>(&self, path: &'a impl AsRef<Path>) -> Cow<'a, Path> {
        match &self.cmd.cwd {
            Some(cwd) => cwd.join(path).into(),
            None => path.as_ref().into(),
        }
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
        }
    }

    pub fn cwd(&self, path: impl AsRef<Path>) -> Self {
        Self {
            cwd: Some(path.as_ref().to_path_buf()),
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
        let env = FakeEnv {
            cmd: self.clone(),
            stdout: Default::default(),
            stderr: Default::default(),
        };
        parse_args(env)
    }

    /// Run the [`FakeCmd`] in a [`FakeEnv`], returning a [`FakeResult`]
    pub fn run(&self) -> FakeResult {
        let env = FakeEnv {
            cmd: self.clone(),
            stdout: Default::default(),
            stderr: Default::default(),
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
        self.stdout.0.lock().unwrap().clone()
    }

    pub fn get_stderr(&self) -> String {
        self.stderr.0.lock().unwrap().clone()
    }
}

/// A type to used to mock stdout and stderr
#[derive(Clone, Default)]
pub struct FakeStream(Arc<Mutex<String>>);

impl fmt::Write for FakeStream {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.lock().unwrap().push_str(s);
        Ok(())
    }
}

impl fmt::Display for FakeStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.lock().unwrap().as_ref())
    }
}
