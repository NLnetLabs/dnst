use std::cell::RefCell;
use std::ffi::OsString;
use std::fmt;
use std::sync::Arc;

use crate::{error::Error, parse_args, run, Args};

use super::Env;

#[derive(Clone)]
pub struct FakeCmd {
    /// The (sub)command to run, including `argv[0]`
    pub cmd: Vec<OsString>,

    /// The arguments for the commands
    pub args: Vec<OsString>,
}

pub struct FakeResult {
    pub exit_code: u8,
    pub stdout: String,
    pub stderr: String,
}

/// Use fake I/O and Stelline for testing
pub struct FakeEnv {
    // pub stelline: Option<Stelline>,
    // pub curr_step_value: Option<Arc<CurrStepValue>>,
    pub cmd: FakeCmd,

    /// The collected stdout
    pub stdout: FakeStream,

    /// The collected stderr
    pub stderr: FakeStream,
}

impl Env for FakeEnv {
    fn args_os(&self) -> impl Iterator<Item = OsString> {
        self.cmd
            .cmd
            .iter()
            .map(Into::into)
            .chain(self.cmd.args.clone())
    }

    fn stdout(&self) -> impl fmt::Write {
        self.stdout.clone()
    }

    fn stderr(&self) -> impl fmt::Write {
        self.stderr.clone()
    }
}

impl FakeCmd {
    pub fn new<S: Into<OsString>>(cmd: impl IntoIterator<Item = S>) -> Self {
        Self {
            cmd: cmd.into_iter().map(Into::into).collect(),
            args: Vec::new(),
        }
    }

    pub fn args<S: Into<OsString>>(&self, args: impl IntoIterator<Item = S>) -> Self {
        Self {
            args: args.into_iter().map(Into::into).collect(),
            ..self.clone()
        }
    }

    pub fn parse(&self) -> Result<Args, Error> {
        let env = FakeEnv {
            cmd: self.clone(),
            stdout: Default::default(),
            stderr: Default::default(),
        };
        parse_args(env)
    }

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
        let r: &RefCell<_> = &self.stdout.0;
        r.borrow().clone()
    }

    pub fn get_stderr(&self) -> String {
        let r: &RefCell<_> = &self.stdout.0;
        r.borrow().clone()
    }
}

#[derive(Clone, Default)]
pub struct FakeStream(Arc<RefCell<String>>);

impl fmt::Write for FakeStream {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.borrow_mut().push_str(s);
        Ok(())
    }
}

impl fmt::Display for FakeStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r: &RefCell<_> = &self.0;
        f.write_str(r.borrow().as_ref())
    }
}
