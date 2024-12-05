use std::process::Command;

pub fn assert_org_ldns_cmd_eq_new_ldns_cmd(
    org_ldns_cmd: &[&str],
    new_ldns_cmd: &[&str],
    expect_stdout_content: bool,
) {
    let org_ldns_cmd_out = Command::new(org_ldns_cmd[0])
        .args(&org_ldns_cmd[1..])
        .output()
        .unwrap();

    let new_ldns_cmd_out = test_bin::get_test_bin("ldns")
        .args(new_ldns_cmd)
        .output()
        .unwrap();

    assert_eq!(
        std::str::from_utf8(&org_ldns_cmd_out.stderr),
        Ok(""),
        "Unexpected stderr content for original ldns command: {}",
        org_ldns_cmd.join(" ")
    );
    assert_eq!(
        std::str::from_utf8(&new_ldns_cmd_out.stderr),
        Ok(""),
        "Unexpected stderr content for reimplemented ldns command: {}",
        new_ldns_cmd.join(" ")
    );
    if expect_stdout_content {
        assert!(
            !org_ldns_cmd_out.stdout.is_empty(),
            "Expected stdout content for original ldns command: {}: {:?}",
            org_ldns_cmd.join(" "),
            std::str::from_utf8(&org_ldns_cmd_out.stdout)
        );
        assert!(
            !new_ldns_cmd_out.stdout.is_empty(),
            "Expected stdout content for reimplemented ldns command: {}: {:?}",
            new_ldns_cmd.join(" "),
            std::str::from_utf8(&new_ldns_cmd_out.stdout)
        );
    }
    assert_eq!(
        org_ldns_cmd_out.status.code(),
        new_ldns_cmd_out.status.code(),
        "Exit code mismatch for original ldns command: {}",
        org_ldns_cmd.join(" ")
    );

    // This will only work for LDNS commands whose output we are able to
    // replicate exactly.
    assert_eq!(
        std::str::from_utf8(&org_ldns_cmd_out.stdout),
        std::str::from_utf8(&new_ldns_cmd_out.stdout),
        "Stdout content mismatch for original ldns command: {}",
        {
            eprintln!("{}", std::str::from_utf8(&new_ldns_cmd_out.stdout).unwrap());
            org_ldns_cmd.join(" ")
        }
    );
}
