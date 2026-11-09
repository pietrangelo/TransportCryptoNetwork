//! R-3 on the `zt-agent` binary: `check`, exit code 78 for a configuration error and a clean
//! exit on `SIGTERM` (resilience.md §5.4; catalogue R3-C2, R3-C4).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use zt_crypto::Identity;

const BIN: &str = env!("CARGO_BIN_EXE_zt-agent");
const EX_CONFIG: i32 = 78;

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn setup(name: &str) -> Dir {
    let dir = std::env::temp_dir().join(format!("zt-agent-life-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    set_mode(&dir, 0o755);
    let key = dir.join("agent.key");
    std::fs::write(&key, Identity::generate().unwrap().to_secret_hex().as_str()).unwrap();
    set_mode(&key, 0o600);
    std::fs::write(dir.join("clients.toml"), "").unwrap();
    set_mode(&dir.join("clients.toml"), 0o644);
    Dir(dir)
}

fn command(dir: &Dir, sub: &str) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(["--log-format", "json", sub, "--node", "web-01", "--relay"])
        // Nothing listens there: the agent keeps retrying.
        .arg("127.0.0.1:9")
        .arg("--relay-key")
        .arg(Identity::generate().unwrap().public_key().to_string())
        .arg("--key")
        .arg(dir.0.join("agent.key"))
        .arg("--authorized-clients")
        .arg(dir.0.join("clients.toml"))
        .env_remove("TCN_ACCEPT_CLIENT_SUITES")
        .env_remove("NOTIFY_SOCKET")
        .env_remove("WATCHDOG_USEC");
    cmd
}

#[test]
fn check_accepts_a_valid_configuration() {
    let dir = setup("ok");
    let out = command(&dir, "check").output().unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("sha256:"));
}

#[test]
fn check_and_run_refuse_invalid_clients_with_ex_config() {
    let dir = setup("bad");
    std::fs::write(dir.0.join("clients.toml"), "[[clients]]\nname = 1\n").unwrap();
    let out = command(&dir, "check").output().unwrap();
    assert_eq!(out.status.code(), Some(EX_CONFIG), "{out:?}");
    let out = command(&dir, "run").output().unwrap();
    assert_eq!(out.status.code(), Some(EX_CONFIG), "{out:?}");
}

#[test]
fn sigterm_stops_the_agent_cleanly() {
    let dir = setup("term");
    let mut child = command(&dir, "run")
        .args(["--drain-timeout", "5"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    for _ in 0..50 {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{:?}: {stderr}", out.status);
    assert!(stderr.contains("agent_drained"), "{stderr}");
}
