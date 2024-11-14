use std::fmt;
use std::sync::Arc;
use std::{cell::RefCell, ffi::OsString};

use dnst::env::Env;

#[macro_export]
macro_rules! vec_os {
    ($($xs:expr),*) => {
        vec![$(std::ffi::OsString::from($xs)),*]
    };
}

/// Use fake I/O and Stelline for testing
#[derive(Default)]
pub struct FakeEnv {
    // pub stelline: Option<Stelline>,
    // pub curr_step_value: Option<Arc<CurrStepValue>>,
    pub args: Vec<OsString>,
    pub stdout: FakeOutput,
    pub stderr: FakeOutput,
}

impl Env for FakeEnv {
    // fn make_connection(&self) {
    //     todo!()
    // }

    // fn make_stub_resolver(&self) {
    //     todo!()
    // }

    fn args_os(&self) -> impl Iterator<Item = OsString> {
        self.args.clone().into_iter()
    }

    fn stdout(&self) -> impl fmt::Write {
        self.stdout.clone()
    }

    fn stderr(&self) -> impl fmt::Write {
        self.stderr.clone()
    }
}

impl FakeEnv {
    pub fn get_stdout(&self) -> String {
        let r: &RefCell<_> = &self.stdout.0;
        r.borrow().clone()
    }
}

#[derive(Clone, Default)]
pub struct FakeOutput(Arc<RefCell<String>>);

impl fmt::Write for FakeOutput {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.borrow_mut().push_str(s);
        Ok(())
    }
}

impl fmt::Display for FakeOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r: &RefCell<_> = &self.0;
        f.write_str(r.borrow().as_ref())
    }
}
