//! R-3 on the `zt-relay` binary: `check` (used by `ExecReload`), exit code 78 for a
//! configuration error (`RestartPreventExitStatus=78`), `SIGTERM` drain, configuration digests
//! and generations, and the lifecycle directives of the systemd units (resilience.md §5.4;
//! catalogue R3-C1, R3-C3, R3-C4, R3-C8).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::io::{BufRead, BufReader};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use zt_crypto::Identity;

const BIN: &str = env!("CARGO_BIN_EXE_zt-relay");
/// `EX_CONFIG` of `sysexits.h`.
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
    let dir = std::env::temp_dir().join(format!("zt-relay-life-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    set_mode(&dir, 0o755);
    let key = dir.join("relay.key");
    std::fs::write(&key, Identity::generate().unwrap().to_secret_hex().as_str()).unwrap();
    set_mode(&key, 0o600);
    let agent = Identity::generate().unwrap();
    write(
        &dir,
        "policy.toml",
        &format!(
            "[[agents]]\nnode = \"web-01\"\npublic_key = \"{}\"\n",
            agent.public_key()
        ),
    );
    Dir(dir)
}

fn write(dir: &Path, name: &str, text: &str) {
    std::fs::write(dir.join(name), text).unwrap();
    set_mode(&dir.join(name), 0o644);
}

fn sha256(path: &Path) -> String {
    let out = Command::new("sha256sum").arg(path).output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

fn command(dir: &Dir, sub: &str) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(["--log-format", "json", sub]);
    if sub == "run" {
        cmd.args(["--listen", "127.0.0.1:0"]);
    }
    cmd.arg("--key")
        .arg(dir.0.join("relay.key"))
        .arg("--policy")
        .arg(dir.0.join("policy.toml"))
        .env("RUST_LOG", "info")
        .env_remove("NOTIFY_SOCKET")
        .env_remove("WATCHDOG_USEC");
    cmd
}

struct Running {
    child: Child,
    lines: mpsc::Receiver<serde_json::Value>,
    addr: String,
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
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { return };
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                    continue;
                };
                if tx.send(v).is_err() {
                    return;
                }
            }
        });
        let mut r = Self {
            child,
            lines,
            addr: String::new(),
        };
        let listening = r.wait_for(|v| v["fields"]["message"] == "relay listening");
        r.addr = listening["fields"]["addr"]
            .as_str()
            .unwrap()
            .trim_start_matches("Some(")
            .trim_end_matches(')')
            .to_owned();
        r
    }

    fn wait_for(&self, pred: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let v = self
                .lines
                .recv_timeout(left)
                .expect("expected log line never came");
            if pred(&v) {
                return v;
            }
        }
    }

    fn event(&self, kind: &str) -> serde_json::Value {
        self.wait_for(|v| v["fields"]["event_kind"] == kind)
    }

    fn signal(&self, sig: &str) {
        let ok = Command::new("kill")
            .args([sig, &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(ok.success());
    }

    fn exit_within(&mut self, within: Duration) -> std::process::ExitStatus {
        let deadline = std::time::Instant::now() + within;
        while std::time::Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the relay did not exit within {within:?}");
    }
}

/// R3-C4: `check` validates every file the service would load, prints their digests and does
/// not listen.
#[test]
fn check_accepts_a_valid_configuration_and_prints_digests() {
    let dir = setup("check-ok");
    let out = command(&dir, "check").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let digest = sha256(&dir.0.join("policy.toml"));
    assert!(stdout.contains(&digest), "{stdout}");
}

/// R3-C4: a configuration error is `EX_CONFIG` (78), which the unit does not restart on.
#[test]
fn check_and_run_refuse_an_invalid_policy_with_ex_config() {
    let dir = setup("check-bad");
    write(&dir.0, "policy.toml", "[[agents]]\nnode = \"web-01\"\n");
    let out = command(&dir, "check").output().unwrap();
    assert_eq!(out.status.code(), Some(EX_CONFIG), "{out:?}");
    let out = command(&dir, "run")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(EX_CONFIG), "{out:?}");
}

/// R3-C1: `SIGTERM` starts the drain: the port closes at once and, with no sessions, the
/// relay exits cleanly (0) right away.
#[test]
fn sigterm_drains_and_exits_cleanly() {
    let dir = setup("term");
    let mut relay = Running::start(&dir, &["--drain-timeout", "30"]);
    relay.signal("-TERM");
    relay.event("relay_draining");
    relay.event("relay_drained");
    let status = relay.exit_within(Duration::from_secs(5));
    assert!(status.success(), "{status:?}");
    assert!(std::net::TcpStream::connect(&relay.addr).is_err());
}

/// R3-C1 attack: a `SIGTERM` right at startup, before the drain machinery exists, must not
/// leave a crash or a core behind.
#[test]
fn an_early_sigterm_is_clean() {
    let dir = setup("early");
    for delay in [0, 5, 20, 50] {
        let mut child = command(&dir, "run")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(delay));
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() || out.status.signal() == Some(15),
            "{:?}: {stderr}",
            out.status
        );
        assert!(!stderr.contains("panicked"), "{stderr}");
    }
}

/// R3-C8: the configuration in force is identifiable from the log: a generation and the
/// SHA-256 of every file, at startup and on every reload.
#[test]
fn configuration_generations_and_digests_are_logged() {
    let dir = setup("gen");
    let relay = Running::start(&dir, &[]);
    let policy = dir.0.join("policy.toml");
    let first = relay.event("configuration_loaded");
    assert_eq!(first["fields"]["generation"], 1, "{first}");
    let files = first["fields"]["files"].as_str().unwrap().to_owned();
    assert!(files.contains(&sha256(&policy)), "{first}");
    let agent = Identity::generate().unwrap();
    write(
        &dir.0,
        "policy.toml",
        &format!(
            "[[agents]]\nnode = \"web-02\"\npublic_key = \"{}\"\n",
            agent.public_key()
        ),
    );
    relay.signal("-HUP");
    let reloaded = relay.event("policy_reloaded");
    let generation = reloaded["fields"]["generation"].as_u64().unwrap();
    assert!(generation >= 2, "{reloaded}");
    let files = reloaded["fields"]["files"].as_str().unwrap().to_owned();
    assert!(files.contains(&sha256(&policy)), "{reloaded}");
}

fn unit(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging/systemd")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}

/// R3-C3, R3-C5, R3-C9: the units carry the lifecycle directives.
#[test]
fn the_units_carry_the_lifecycle_directives() {
    for (name, bin) in [
        ("zt-relay.service", "zt-relay"),
        ("zt-agent.service", "zt-agent"),
    ] {
        let text = unit(name);
        for directive in [
            "WatchdogSec=",
            "TimeoutStopSec=",
            "time-sync.target",
            "RestartPreventExitStatus=78",
            "LimitCORE=0",
            "StartLimitIntervalSec=0",
            "NotifyAccess=main",
        ] {
            assert!(text.contains(directive), "{name}: {directive} missing");
        }
        let reload = text
            .lines()
            .find(|l| l.starts_with("ExecReload="))
            .unwrap_or_else(|| panic!("{name}: no ExecReload"));
        assert!(
            reload.contains(&format!("{bin} --log-format json check")),
            "{name}: {reload}"
        );
    }
}
