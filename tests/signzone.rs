// Based on: https://github.com/NLnetLabs/ldns/tree/1.8.4/test/20-sign-zone.tpkg
// But uses a newer algorithm as algorithm 5 is not supported by DNST.

mod common;

use common::assert_org_ldns_cmd_eq_new_ldns_cmd;
use const_format::concatcp;
use std::process::Command;
use tempfile::tempdir;

const LDNS_CMD: &str = "ldns-signzone";
const TEST_DATA_DIR: &str = "test-data/";
const JELTE_ZONE_PATH: &str = concatcp!(TEST_DATA_DIR, "jelte.nlnetlabs.nl");
const JELTE_KSK_PATH: &str = concatcp!(TEST_DATA_DIR, "Kjelte.nlnetlabs.nl.+008+31310");
const JELTE_ZSK_PATH: &str = concatcp!(TEST_DATA_DIR, "Kjelte.nlnetlabs.nl.+008+19779");
const ORIGINLESS_ZONE_PATH: &str = concatcp!(TEST_DATA_DIR, "example.rfc8976-simple");
const ORIGINLESS_KSK_PATH: &str = concatcp!(TEST_DATA_DIR, "Kexample.+008+31967");
const ORIGINLESS_ZSK_PATH: &str = concatcp!(TEST_DATA_DIR, "Kexample.+008+38353");

#[ignore = "should only be run if ldns command line tools are installed"]
#[test]
fn signzone_only_zsk() {
    let temp_dir = tempdir().unwrap().into_path();
    let ldns_out_path = format!("{}/ldns.signed", temp_dir.display());
    let dnst_out_path = format!("{}/dnst.signed", temp_dir.display());

    assert_org_ldns_cmd_eq_new_ldns_cmd(
        &[
            LDNS_CMD,
            "-b",
            "-f",
            &ldns_out_path,
            JELTE_ZONE_PATH,
            JELTE_ZSK_PATH,
        ],
        &[
            LDNS_CMD,
            "-b",
            "-f",
            &dnst_out_path,
            JELTE_ZONE_PATH,
            JELTE_ZSK_PATH,
        ],
        false,
    );

    verify_signed_zone(dnst_out_path);
}

#[ignore = "should only be run if ldns command line tools are installed"]
#[test]
fn signzone_only_ksk() {
    let temp_dir = tempdir().unwrap().into_path();
    let ldns_out_path = format!("{}/ldns.signed", temp_dir.display());
    let dnst_out_path = format!("{}/dnst.signed", temp_dir.display());

    assert_org_ldns_cmd_eq_new_ldns_cmd(
        &[
            LDNS_CMD,
            "-b",
            "-f",
            &ldns_out_path,
            JELTE_ZONE_PATH,
            JELTE_KSK_PATH,
        ],
        &[
            LDNS_CMD,
            "-b",
            "-f",
            &dnst_out_path,
            JELTE_ZONE_PATH,
            JELTE_KSK_PATH,
        ],
        false,
    );

    verify_signed_zone(dnst_out_path);
}

#[ignore = "should only be run if ldns command line tools are installed"]
#[test]
fn signzone_detect_origin() {
    let temp_dir = tempdir().unwrap().into_path();
    let ldns_out_path = format!("{}/ldns.signed", temp_dir.display());
    let dnst_out_path = format!("{}/dnst.signed", temp_dir.display());

    assert_org_ldns_cmd_eq_new_ldns_cmd(
        &[
            LDNS_CMD,
            "-f",
            &ldns_out_path,
            ORIGINLESS_ZONE_PATH,
            ORIGINLESS_KSK_PATH,
            ORIGINLESS_ZSK_PATH,
        ],
        &[
            LDNS_CMD,
            "-f",
            &dnst_out_path,
            ORIGINLESS_ZONE_PATH,
            ORIGINLESS_KSK_PATH,
            ORIGINLESS_ZSK_PATH,
        ],
        false,
    );

    verify_signed_zone(dnst_out_path);
}

fn verify_signed_zone(dnst_out_path: String) {
    let verify_output = Command::new("ldns-verify-zone")
        .args([&dnst_out_path])
        .output()
        .unwrap();

    if !verify_output.status.success() {
        eprintln!(
            "ldns-verify-zone failed with exit code {:?} and stderr output:\n{}",
            verify_output.status.code(),
            std::str::from_utf8(&verify_output.stderr).unwrap()
        );
    }

    assert!(
        verify_output.status.success(),
        "Expected zone verification to succeed"
    );
}
