mod common;

use common::assert_org_ldns_cmd_eq_new_ldns_cmd;

const LDNS_NSEC3_CMD: &str = "ldns-nsec3-hash";
const DNST_NSEC3_SUBCMD: &str = "nsec3-hash";
const TEST_ZONE_NAME: &str = "nlnetlabs.nl";

#[ignore = "should only be run if ldns command line tools are installed"]
#[test]
fn nsec3_hash() {
    // Note: ldns-nsec3-hash defaults NSEC3 iterations to 1, while dnst
    // nsec-hash defaults NSEC3 iterations to 0.
    assert_org_ldns_cmd_eq_new_ldns_cmd(
        &[LDNS_NSEC3_CMD, TEST_ZONE_NAME],
        &[DNST_NSEC3_SUBCMD, "--iterations", "1", TEST_ZONE_NAME],
        true,
    );
    assert_org_ldns_cmd_eq_new_ldns_cmd(
        &[LDNS_NSEC3_CMD, TEST_ZONE_NAME, "-t", "0"],
        &[DNST_NSEC3_SUBCMD, TEST_ZONE_NAME],
        true,
    );
    assert_org_ldns_cmd_eq_new_ldns_cmd(
        &[LDNS_NSEC3_CMD, "-a", "1", TEST_ZONE_NAME],
        &[
            DNST_NSEC3_SUBCMD,
            "--iterations",
            "1",
            "--algorithm",
            "1",
            TEST_ZONE_NAME,
        ],
        true,
    );
    assert_org_ldns_cmd_eq_new_ldns_cmd(
        &[LDNS_NSEC3_CMD, "-s", "", TEST_ZONE_NAME],
        &[
            DNST_NSEC3_SUBCMD,
            "--iterations",
            "1",
            "--salt",
            "",
            TEST_ZONE_NAME,
        ],
        true,
    );
    assert_org_ldns_cmd_eq_new_ldns_cmd(
        &[LDNS_NSEC3_CMD, "-s", "DEADBEEF", TEST_ZONE_NAME],
        &[
            DNST_NSEC3_SUBCMD,
            "--iterations",
            "1",
            "--salt",
            "DEADBEEF",
            TEST_ZONE_NAME,
        ],
        true,
    );

    for iterations in 0..10 {
        assert_org_ldns_cmd_eq_new_ldns_cmd(
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
            true,
        );
    }
}
