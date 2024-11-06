#![no_main]

use libfuzzer_sys::fuzz_target;

use dnst::commands::nsec3hash::Nsec3Hash;

fuzz_target!(|cmd: Nsec3Hash| {
    let _ = cmd.execute();
});
