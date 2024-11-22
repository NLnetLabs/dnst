use std::process::Command;

const TEST_ZONE_NAME: &str = "nlnetlabs.nl";
const LDNS_NSEC3_CMD: &str = "ldns-nsec3-hash";
const DNST_NSEC3_SUBCMD: &str = "nsec3-hash";

#[ignore = "should only be run if ldns command line tools are installed"]
#[test]
fn nsec3_hash() {
    // Note: ldns-nsec3-hash defaults NSEC3 iterations to 1, while dnst
    // nsec-hash defaults NSEC3 iterations to 0.
    assert_cmds_eq(
        &[LDNS_NSEC3_CMD, TEST_ZONE_NAME],
        &[DNST_NSEC3_SUBCMD, "--iterations", "1", TEST_ZONE_NAME],
    );
    assert_cmds_eq(
        &[LDNS_NSEC3_CMD, TEST_ZONE_NAME, "-t", "0"],
        &[DNST_NSEC3_SUBCMD, TEST_ZONE_NAME],
    );
    assert_cmds_eq(
        &[LDNS_NSEC3_CMD, "-a", "1", TEST_ZONE_NAME],
        &[
            DNST_NSEC3_SUBCMD,
            "--iterations",
            "1",
            "--algorithm",
            "1",
            TEST_ZONE_NAME,
        ],
    );
    assert_cmds_eq(
        &[LDNS_NSEC3_CMD, "-s", "", TEST_ZONE_NAME],
        &[
            DNST_NSEC3_SUBCMD,
            "--iterations",
            "1",
            "--salt",
            "",
            TEST_ZONE_NAME,
        ],
    );
    assert_cmds_eq(
        &[LDNS_NSEC3_CMD, "-s", "DEADBEEF", TEST_ZONE_NAME],
        &[
            DNST_NSEC3_SUBCMD,
            "--iterations",
            "1",
            "--salt",
            "DEADBEEF",
            TEST_ZONE_NAME,
        ],
    );

    for iterations in 0..10 {
        assert_cmds_eq(
            &[
                LDNS_NSEC3_CMD,
                "-t",
                &iterations.to_string(),
                TEST_ZONE_NAME,
            ],
            &[
                DNST_NSEC3_SUBCMD,
                "-i",
                &iterations.to_string(),
                TEST_ZONE_NAME,
            ],
        );
    }
}

fn assert_cmds_eq(cmd1: &[&str], cmd2: &[&str]) {
    let cmd1_output = Command::new(cmd1[0]).args(&cmd1[1..]).output().unwrap();

    let cmd2_output = test_bin::get_test_bin("dnst").args(cmd2).output().unwrap();

    assert_eq!(
        std::str::from_utf8(&cmd1_output.stderr),
        Ok(""),
        "Unexpected stderr content for command: {}",
        cmd1.join(" ")
    );
    assert_eq!(
        std::str::from_utf8(&cmd2_output.stderr),
        Ok(""),
        "Unexpected stderr content for command: {}",
        cmd2.join(" ")
    );
    assert!(
        !cmd1_output.stdout.is_empty(),
        "Expected stdout content for command: {}: {:?}",
        cmd1.join(" "),
        std::str::from_utf8(&cmd1_output.stdout)
    );
    assert!(
        !cmd2_output.stdout.is_empty(),
        "Expected stdout content for command: {}: {:?}",
        cmd2.join(" "),
        std::str::from_utf8(&cmd2_output.stdout)
    );
    assert_eq!(
        cmd1_output.status.code(),
        cmd2_output.status.code(),
        "Exit code mismatch for command: {}",
        cmd1.join(" ")
    );

    // This will only work for LDNS commands whose output we are able to
    // replicate exactly.
    assert_eq!(
        std::str::from_utf8(&cmd1_output.stdout),
        std::str::from_utf8(&cmd2_output.stdout),
        "Stdout content mismatch for command: {}",
        cmd1.join(" ")
    );
}
