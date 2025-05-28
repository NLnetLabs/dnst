// Based on: https://github.com/NLnetLabs/ldns/tree/1.8.4/test/20-sign-zone.tpkg
// But uses a newer algorithm as algorithm 5 is not supported by DNST.

mod common;

use common::assert_org_ldns_cmd_eq_new_ldns_cmd;
use const_format::concatcp;
use jiff::{ToSpan, Unit, Zoned};
use std::process::Command;
use tempfile::tempdir;

const LDNS_CMD: &str = "ldns-signzone";
const TEST_DATA_DIR: &str = "test-data/";
const JELTE_ZONE_PATH: &str = concatcp!(TEST_DATA_DIR, "jelte.nlnetlabs.nl");
const JELTE_KSK_PATH: &str = concatcp!(TEST_DATA_DIR, "Kjelte.nlnetlabs.nl.+008+31310");
const JELTE_ZSK_PATH: &str = concatcp!(TEST_DATA_DIR, "Kjelte.nlnetlabs.nl.+008+19779");
const RFC_5155_ZONE_PATH: &str = concatcp!(TEST_DATA_DIR, "example.rfc5155");
const RFC_5155_KSK_PATH: &str = concatcp!(TEST_DATA_DIR, "Kexample.+008+31967");
const RFC_5155_ZSK_PATH: &str = concatcp!(TEST_DATA_DIR, "Kexample.+008+38353");

#[ignore = "should only be run if ldns command line tools are installed"]
#[test]
fn signzone_only_zsk() {
    let temp_dir = tempdir().unwrap().keep();
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
    let temp_dir = tempdir().unwrap().keep();
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
fn signzone_with_both_ksk_and_zsk() {
    let temp_dir = tempdir().unwrap().keep();
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
            JELTE_ZSK_PATH,
        ],
        &[
            LDNS_CMD,
            "-b",
            "-f",
            &dnst_out_path,
            JELTE_ZONE_PATH,
            JELTE_KSK_PATH,
            JELTE_ZSK_PATH,
        ],
        false,
    );

    verify_signed_zone(dnst_out_path);
}

#[ignore = "should only be run if ldns command line tools are installed"]
#[test]
fn signzone_nsec_minus_b() {
    let temp_dir = tempdir().unwrap().keep();
    let ldns_out_path = format!("{}/ldns.signed", temp_dir.display());
    let dnst_out_path = format!("{}/dnst.signed", temp_dir.display());

    const TS_FMT: &str = "%Y%m%d%H%M%S";
    let now = Zoned::now().round(Unit::Second).unwrap();
    let inception_ts = now.saturating_sub(1.month()).strftime(TS_FMT).to_string();
    let expiration_ts = now.saturating_add(1.month()).strftime(TS_FMT).to_string();

    assert_org_ldns_cmd_eq_new_ldns_cmd(
        &[
            LDNS_CMD,
            "-b",
            "-n",
            "-e",
            &expiration_ts,
            "-i",
            &inception_ts,
            "-f",
            &ldns_out_path,
            JELTE_ZONE_PATH,
            JELTE_KSK_PATH,
        ],
        &[
            LDNS_CMD,
            "-b",
            "-n",
            "-e",
            &expiration_ts,
            "-i",
            &inception_ts,
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
fn signzone_with_nsec3_no_opt_out() {
    let temp_dir = tempdir().unwrap().keep();
    let ldns_out_path = format!("{}/ldns.signed", temp_dir.display());
    let dnst_out_path = format!("{}/dnst.signed", temp_dir.display());

    assert_org_ldns_cmd_eq_new_ldns_cmd(
        &[
            LDNS_CMD,
            "-n",
            "-f",
            &ldns_out_path,
            RFC_5155_ZONE_PATH,
            RFC_5155_KSK_PATH,
            RFC_5155_ZSK_PATH,
        ],
        &[
            LDNS_CMD,
            "-n",
            "-f",
            &dnst_out_path,
            RFC_5155_ZONE_PATH,
            RFC_5155_KSK_PATH,
            RFC_5155_ZSK_PATH,
        ],
        false,
    );

    verify_signed_zone(dnst_out_path);
}

#[ignore = "should only be run if ldns command line tools are installed"]
#[test]
fn signzone_with_nsec3_opt_out() {
    let temp_dir = tempdir().unwrap().keep();
    let ldns_out_path = format!("{}/ldns.signed", temp_dir.display());
    let dnst_out_path = format!("{}/dnst.signed", temp_dir.display());

    assert_org_ldns_cmd_eq_new_ldns_cmd(
        &[
            LDNS_CMD,
            "-n",
            "-p",
            "-f",
            &ldns_out_path,
            RFC_5155_ZONE_PATH,
            RFC_5155_KSK_PATH,
            RFC_5155_ZSK_PATH,
        ],
        &[
            LDNS_CMD,
            "-n",
            "-p",
            "-f",
            &dnst_out_path,
            RFC_5155_ZONE_PATH,
            RFC_5155_KSK_PATH,
            RFC_5155_ZSK_PATH,
        ],
        false,
    );

    verify_signed_zone(dnst_out_path);
}

// Note: We don't test for correct handling of early glue due to the original
// LDNS signzone and verify commands not handling this case correctly. See:
// https://github.com/NLnetLabs/ldns/issues/277.

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
