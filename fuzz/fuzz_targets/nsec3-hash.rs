#![no_main]

use libfuzzer_sys::fuzz_target;

use dnst::commands::nsec3hash::Nsec3Hash;
use dnst::env::fake::{FakeCmd, FakeEnv};

fuzz_target!(|cmd: Nsec3Hash| {
    let _ = cmd.execute(FakeEnv::from(FakeCmd::new(vec!["nsec3-hash"])));
});
