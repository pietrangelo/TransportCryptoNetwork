//! R-3 on the `zt-agent` binary: `check`, exit code 78 for a configuration error and a clean
//! exit on `SIGTERM` (resilience.md §5.4; catalogue R3-C2, R3-C4).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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
    std::fs::create_dir_all(dir.join("run")).unwrap();
    set_mode(&dir.join("run"), 0o700);
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
        .env("RUNTIME_DIRECTORY", dir.0.join("run"))
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

fn text(out: &std::process::Output) -> String {
    format!(
        "{:?}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A running agent whose stderr is collected; killed on drop.
struct Running {
    child: Child,
    lines: std::sync::mpsc::Receiver<String>,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Running {
    fn start(dir: &Dir, extra: &[&str]) -> Self {
        let mut child = command(dir, "run")
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { return };
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        let r = Self { child, lines };
        r.wait_for("configuration_loaded");
        r
    }

    fn wait_for(&self, kind: &str) -> String {
        let needle = format!("\"event_kind\":\"{kind}\"");
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(10))
                .unwrap_or_else(|_| panic!("no {kind}"));
            if line.contains(&needle) {
                return line;
            }
        }
    }

    fn reload(&self, dir: &Dir) -> std::process::Output {
        Command::new(BIN)
            .args(["--log-format", "json", "reload", "--pid"])
            .arg(self.child.id().to_string())
            .env("RUNTIME_DIRECTORY", dir.0.join("run"))
            .output()
            .unwrap()
    }
}

/// Clients pinned through a CA, which need `--revocations`.
fn ca_clients(dir: &Dir) {
    let ca = Identity::generate().unwrap();
    std::fs::write(
        dir.0.join("clients.toml"),
        format!(
            "[[authorities]]\nname = \"ops-ca\"\npublic_key = \"{}\"\nallow = [\"web-01\"]\n",
            ca.public_key()
        ),
    )
    .unwrap();
    std::fs::write(dir.0.join("revoked.toml"), "serials = []\nkeys = []\n").unwrap();
    set_mode(&dir.0.join("revoked.toml"), 0o644);
}

/// Finding A10-1: an agent started with arguments that only `ExecStart=` has (a drop-in with
/// `--revocations`, `--relay-suite`) is reloaded by `reload --pid`, which validates inside the
/// running agent; a file the agent rejects fails the reload with its reason.
#[test]
fn reload_is_validated_by_the_running_agent() {
    let dir = setup("reload");
    ca_clients(&dir);
    let rev = dir.0.join("revoked.toml").display().to_string();
    let agent = Running::start(
        &dir,
        &[
            "--revocations",
            &rev,
            "--relay-suite",
            "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s",
        ],
    );
    let out = agent.reload(&dir);
    assert!(out.status.success(), "{}", text(&out));
    let line = agent.wait_for("authorized_clients_reloaded");
    assert!(line.contains("\"generation\":2"), "{line}");
    std::fs::write(dir.0.join("clients.toml"), "[[clients]]\nname = 1\n").unwrap();
    let out = agent.reload(&dir);
    assert_eq!(out.status.code(), Some(EX_CONFIG), "{}", text(&out));
    agent.wait_for("authorized_clients_reload_failed");
}

/// Finding A10-8: a key file that is not there yet is exit 1 (restarted), not 78.
#[test]
fn a_missing_key_is_restarted_not_ex_config() {
    let dir = setup("missing");
    std::fs::remove_file(dir.0.join("agent.key")).unwrap();
    for sub in ["check", "run"] {
        let out = command(&dir, sub).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{sub}: {}", text(&out));
    }
}
