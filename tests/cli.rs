use common::{load_fixtures, setup_command};
use predicates::{prelude::*, str::contains};
use tempfile::tempdir;

mod common;

const POLICIES: &[&str] = &[
    // SHA: 59e34f482b40
    "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9",
    // SHA: 828617a7cf3e
    "registry://ghcr.io/kubewarden/tests/safe-labels:v0.1.13",
];

#[test]
fn test_policies_empty() {
    let tempdir = tempdir().unwrap();

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("policies");
    cmd.assert().success();
    cmd.assert().stdout("");
}

#[test]
fn test_policies() {
    let tempdir = tempdir().unwrap();
    load_fixtures(tempdir.path(), POLICIES);

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("policies");
    cmd.assert().success();
    cmd.assert()
        .stdout(contains("pod-privileged"))
        .stdout(contains("v0.1.9"))
        .stdout(contains("safe-labels"))
        .stdout(contains("v0.1.13"));
}

#[test]
fn test_rm() {
    let tempdir = tempdir().unwrap();
    load_fixtures(tempdir.path(), POLICIES);

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("rm")
        .arg("registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9");
    cmd.assert().success();
    cmd.assert().stdout("");

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("policies").assert().success();
    cmd.assert().stdout(contains("pod-privileged").not());
}

#[test]
fn test_rm_with_sha() {
    let tempdir = tempdir().unwrap();
    load_fixtures(tempdir.path(), POLICIES);

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("rm").arg("59e3");
    cmd.assert().success();
    cmd.assert().stdout("");

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("policies").assert().success();
    cmd.assert().stdout(contains("59e3").not());
}
