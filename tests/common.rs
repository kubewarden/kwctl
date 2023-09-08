use std::path::Path;

use assert_cmd::Command;

pub fn setup_command(path: &Path) -> Command {
    let mut cmd = Command::cargo_bin("kwctl").unwrap();

    cmd.current_dir(path)
        .env("XDG_CONFIG_HOME", path.join(".config"))
        .env("XDG_CACHE_HOME", path.join(".cache"))
        .env("XDG_DATA_HOME", path.join(".local/share"));

    cmd
}

pub fn load_fixtures(path: &Path, policies: &[&str]) {
    for policy in policies {
        let mut cmd = setup_command(path);
        cmd.arg("pull").arg(policy);

        cmd.assert().success();
    }
}
