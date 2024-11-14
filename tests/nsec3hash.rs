mod common;

use common::FakeEnv;

#[test]
fn simple_hash() {
    let mut env = FakeEnv {
        args: vec_os!["dnst", "nsec3-hash", "example.test"],
        ..Default::default()
    };

    let exit = dnst::run(&mut env);

    assert_eq!(exit, 0);
    assert_eq!(env.get_stdout(), "o09614ibh1cq1rcc86289olr22ea0fso.\n")
}
