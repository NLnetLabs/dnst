use std::process::Command;

#[ignore = "should only be run if ldns command line tools are installed"]
#[test]
fn nsec3_hash() {
    assert_ldns_eq_dnst("ldns-nsec3-hash", "nsec3-hash", &["example.com"]);
    assert_ldns_eq_dnst("ldns-nsec3-hash", "nsec3-hash", &["-a", "1", "example.com"]);
    assert_ldns_eq_dnst("ldns-nsec3-hash", "nsec3-hash", &["-s", "", "example.com"]);
    assert_ldns_eq_dnst(
        "ldns-nsec3-hash",
        "nsec3-hash",
        &["-s", "DEADBEEF", "example.com"],
    );

    for iterations in 0..10 {
        assert_ldns_eq_dnst(
            "ldns-nsec3-hash",
            "nsec3-hash",
            &["-t", &iterations.to_string(), "example.com"],
        );
    }
}

fn assert_ldns_eq_dnst(ldns_command: &str, dnst_subcommand: &str, args: &[&str]) {
    let ldns_output = Command::new(ldns_command)
        .args(args)
        .output()
        .unwrap();

    let dnst_output = test_bin::get_test_bin("dnst")
        .arg(dnst_subcommand)
        .args(args)
        .output()
        .unwrap();

    assert_eq!(std::str::from_utf8(&ldns_output.stderr), Ok(""));
    assert_eq!(std::str::from_utf8(&dnst_output.stderr), Ok(""));
    assert!(!ldns_output.stdout.is_empty());
    assert!(!dnst_output.stdout.is_empty());

    // This will only work for LDNS commands whose output we are able to
    // replicate exactly.
    assert_eq!(
        std::str::from_utf8(&ldns_output.stdout),
        std::str::from_utf8(&dnst_output.stdout)
    );
}
