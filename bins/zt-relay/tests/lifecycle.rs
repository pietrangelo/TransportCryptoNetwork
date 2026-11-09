//! R-3 on the `zt-relay` binary: `check`, `reload` (used by `ExecReload`), exit code 78 for a
//! configuration error (`RestartPreventExitStatus=78`), `SIGTERM` drain, configuration digests
//! and generations, and the lifecycle directives of the systemd units (resilience.md §5.4;
//! catalogue R3-C1, R3-C3, R3-C4, R3-C8).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    clippy::assigning_clones
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
    // What systemd's `RuntimeDirectory=` creates.
    std::fs::create_dir_all(dir.join("run")).unwrap();
    set_mode(&dir.join("run"), 0o700);
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
        .env("RUNTIME_DIRECTORY", dir.0.join("run"))
        .env_remove("NOTIFY_SOCKET")
        .env_remove("WATCHDOG_USEC");
    cmd
}

struct Running {
    child: Child,
    lines: mpsc::Receiver<serde_json::Value>,
    /// Lines read while waiting for another one.
    seen: std::cell::RefCell<Vec<serde_json::Value>>,
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
            seen: std::cell::RefCell::default(),
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
        {
            let mut seen = self.seen.borrow_mut();
            if let Some(i) = seen.iter().position(&pred) {
                return seen.remove(i);
            }
        }
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
            self.seen.borrow_mut().push(v);
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
        let child = command(&dir, "run")
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
        // Finding A10-1: the reload is validated by the running process with its own
        // arguments; `ExecReload=` repeats none of them, so a drop-in that replaces
        // `ExecStart=` cannot make the two disagree.
        let reloads: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("ExecReload="))
            .collect();
        assert_eq!(
            reloads,
            [
                format!("ExecReload=/usr/local/bin/{bin} --log-format json reload --pid $MAINPID")
                    .as_str()
            ],
            "{name}"
        );
        assert!(
            text.lines().any(|l| l == format!("RuntimeDirectory={bin}")),
            "{name}: RuntimeDirectory missing"
        );
        assert!(text.contains("RuntimeDirectoryMode=0700"), "{name}");
    }
}

/// The CA directory of OPERATIONS §10.2: a policy with `[[authorities]]`, which needs
/// `--revocations`, given to `run` only (what a drop-in for `ExecStart=` does).
fn setup_ca(name: &str) -> Dir {
    let dir = setup(name);
    let agent = Identity::generate().unwrap();
    let ca = Identity::generate().unwrap();
    write(
        &dir.0,
        "policy.toml",
        &format!(
            "[[agents]]\nnode = \"web-01\"\npublic_key = \"{}\"\n\n[[authorities]]\nname = \"ops-ca\"\npublic_key = \"{}\"\nallow = [\"web-01\"]\n",
            agent.public_key(),
            ca.public_key()
        ),
    );
    write(&dir.0, "revoked.toml", "serials = []\nkeys = []\n");
    dir
}

fn revocations(dir: &Dir) -> String {
    dir.0.join("revoked.toml").display().to_string()
}

/// `zt-relay reload --pid <relay>`: what `ExecReload=` runs.
fn reload(dir: &Dir, relay: &Running) -> std::process::Output {
    Command::new(BIN)
        .args(["--log-format", "json", "reload", "--pid"])
        .arg(relay.child.id().to_string())
        .env("RUNTIME_DIRECTORY", dir.0.join("run"))
        .env("RUST_LOG", "info")
        .output()
        .unwrap()
}

fn text(out: &std::process::Output) -> String {
    format!(
        "{:?}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn new_agent_policy(dir: &Dir) {
    let agent = Identity::generate().unwrap();
    let policy = std::fs::read_to_string(dir.0.join("policy.toml")).unwrap();
    write(
        &dir.0,
        "policy.toml",
        &format!(
            "{policy}\n[[agents]]\nnode = \"web-02\"\npublic_key = \"{}\"\n",
            agent.public_key()
        ),
    );
}

/// Finding A10-1: a relay started with `--revocations` (a drop-in for `ExecStart=`, as
/// OPERATIONS §10.2 prescribes for a pinned CA) is reloaded by `reload`, which carries no file
/// arguments: the running relay validates its own files.
#[test]
fn reload_works_with_arguments_only_execstart_has() {
    let dir = setup_ca("reload-ca");
    let rev = revocations(&dir);
    let relay = Running::start(&dir, &["--revocations", &rev]);
    relay.event("configuration_loaded");
    new_agent_policy(&dir);
    let out = reload(&dir, &relay);
    assert!(out.status.success(), "{}", text(&out));
    let reloaded = relay.event("policy_reloaded");
    assert_eq!(reloaded["fields"]["generation"], 2, "{reloaded}");
}

/// Finding A10-1: a reload that the running relay rejects fails `reload` (and with it
/// `systemctl reload`), with the relay's own reason; the relay keeps its policy and runs on.
#[test]
fn a_rejected_reload_fails_the_reload_command() {
    let dir = setup_ca("reload-bad");
    let rev = revocations(&dir);
    let mut relay = Running::start(&dir, &["--revocations", &rev]);
    write(&dir.0, "policy.toml", "[[agents]]\nnode = \"web-01\"\n");
    let out = reload(&dir, &relay);
    assert_eq!(out.status.code(), Some(EX_CONFIG), "{}", text(&out));
    assert!(text(&out).contains("policy.toml"), "{}", text(&out));
    relay.event("policy_reload_failed");
    assert!(relay.child.try_wait().unwrap().is_none(), "the relay died");
    assert!(std::net::TcpStream::connect(&relay.addr).is_ok());
}

/// Finding A10-2: files the reload does not apply (`relay.toml`) or applies separately (the
/// keys) do not block the policy: a broken `relay.toml` changes nothing, a broken key file is
/// a warning, and the policy, the urgent part, is applied.
#[test]
fn a_reload_is_not_blocked_by_files_it_does_not_apply() {
    let dir = setup("reload-keys");
    write(
        &dir.0,
        "relay.toml",
        "[handshake]\nagent_suites = [\"Noise_IK_25519_ChaChaPoly_BLAKE2s\"]\n",
    );
    let config = dir.0.join("relay.toml").display().to_string();
    let relay = Running::start(&dir, &["--config", &config]);
    let started = relay.event("configuration_loaded");
    assert!(
        started["fields"]["files"]
            .as_str()
            .unwrap()
            .contains("relay.toml"),
        "{started}"
    );
    write(
        &dir.0,
        "relay.toml",
        "[handshake]\nagent_suites = [\"nope\"]\n",
    );
    std::fs::write(dir.0.join("relay.key"), "not a key").unwrap();
    new_agent_policy(&dir);
    let out = reload(&dir, &relay);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("warning"), "{}", text(&out));
    let reloaded = relay.event("policy_reloaded");
    // The digest is of the policy that was applied, and relay.toml, never reloaded, is not
    // named.
    let files = reloaded["fields"]["files"].as_str().unwrap();
    assert!(
        files.contains(&sha256(&dir.0.join("policy.toml"))),
        "{reloaded}"
    );
    assert!(!files.contains("relay.toml"), "{reloaded}");
    relay.event("relay_keys_reload_failed");
}

/// Finding A10-10: one `SIGHUP` is one generation, shared by the policy and the keys.
#[test]
fn one_reload_is_one_generation() {
    let dir = setup("reload-gen");
    let relay = Running::start(&dir, &[]);
    relay.event("configuration_loaded");
    let out = reload(&dir, &relay);
    assert!(out.status.success(), "{}", text(&out));
    let policy = relay.event("policy_reloaded");
    let keys = relay.event("relay_keys_reloaded");
    assert_eq!(policy["fields"]["generation"], 2, "{policy}");
    assert_eq!(keys["fields"]["generation"], 2, "{keys}");
    let out = reload(&dir, &relay);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(relay.event("policy_reloaded")["fields"]["generation"], 3);
}

/// Finding A10-1: `reload` without a running relay (or without its runtime directory) fails
/// instead of reporting success.
#[test]
fn reload_without_a_relay_fails() {
    let dir = setup("reload-none");
    let out = Command::new(BIN)
        .args(["reload", "--pid", "999999999"])
        .env("RUNTIME_DIRECTORY", dir.0.join("run"))
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", text(&out));
}

/// Finding A10-8: a file that is missing or unreadable (provisioning not done yet, a late
/// mount) is not a configuration error: exit 1, which the unit restarts with its backoff,
/// not 78, which leaves it dead.
#[test]
fn a_missing_file_is_restarted_not_ex_config() {
    let dir = setup("missing");
    std::fs::remove_file(dir.0.join("policy.toml")).unwrap();
    for sub in ["check", "run"] {
        let out = command(&dir, sub)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{sub}: {}", text(&out));
    }
    let dir = setup("missing-key");
    std::fs::remove_file(dir.0.join("relay.key")).unwrap();
    let out = command(&dir, "run").output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
}

/// The exit code of `run` at startup: its code if it exits within a few seconds, 0 once it
/// listens.
fn startup_code(dir: &Dir, extra: &[&str]) -> Option<i32> {
    let mut child = command(dir, "run")
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { return };
            if line.contains("relay listening") {
                let _ = tx.send(());
            }
        }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let code = loop {
        if rx.try_recv().is_ok() {
            break Some(0);
        }
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "run neither exited nor listened"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = child.kill();
    let _ = child.wait();
    code
}

/// R3-C8 (finding A10-6): `check` accepts exactly what `run` accepts at startup, with the same
/// exit code.
#[test]
fn check_and_run_accept_the_same_files() {
    let cases: [(&str, fn(&Dir) -> Vec<String>); 5] = [
        ("valid", |_| Vec::new()),
        ("bad-policy", |d| {
            write(&d.0, "policy.toml", "[[agents]]\nnode = 1\n");
            Vec::new()
        }),
        ("ca-without-revocations", |d| {
            let ca = Identity::generate().unwrap();
            let policy = std::fs::read_to_string(d.0.join("policy.toml")).unwrap();
            write(
                &d.0,
                "policy.toml",
                &format!(
                    "{policy}\n[[authorities]]\nname = \"ca\"\npublic_key = \"{}\"\nallow = [\"*\"]\n",
                    ca.public_key()
                ),
            );
            Vec::new()
        }),
        ("bad-settings", |d| {
            write(&d.0, "relay.toml", "[handshake]\nagent_suites = []\n");
            vec![
                "--config".into(),
                d.0.join("relay.toml").display().to_string(),
            ]
        }),
        ("missing-key", |d| {
            std::fs::remove_file(d.0.join("relay.key")).unwrap();
            Vec::new()
        }),
    ];
    for (name, prepare) in cases {
        let dir = setup(&format!("same-{name}"));
        let extra = prepare(&dir);
        let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
        let check = command(&dir, "check").args(&extra).output().unwrap();
        let run = startup_code(&dir, &extra);
        assert_eq!(check.status.code(), run, "{name}: check {}", text(&check));
    }
}

/// A datagram socket standing in for systemd's `NOTIFY_SOCKET`.
struct Notify {
    socket: std::os::unix::net::UnixDatagram,
}

impl Notify {
    fn new(dir: &Dir) -> (Self, PathBuf) {
        let path = dir.0.join("notify.sock");
        let socket = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        (Self { socket }, path)
    }

    /// The messages received within `within`.
    fn collect(&self, within: Duration) -> Vec<String> {
        let deadline = std::time::Instant::now() + within;
        let mut out = Vec::new();
        let mut buf = [0_u8; 4096];
        while std::time::Instant::now() < deadline {
            if let Ok(n) = self.socket.recv(&mut buf) {
                out.push(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
        }
        out
    }
}

/// Findings A10-1 and A10-3 with a fake systemd: a `SIGHUP` is announced with `RELOADING=1`
/// (and `MONOTONIC_USEC`) and closed with `READY=1`; the watchdog is kicked from the start,
/// with no `watchdog_stalled` at startup.
#[test]
fn reloads_are_announced_and_the_watchdog_does_not_stall_at_start() {
    let dir = setup("notify");
    let (notify, path) = Notify::new(&dir);
    let mut child = command(&dir, "run")
        .env("NOTIFY_SOCKET", &path)
        .env("WATCHDOG_USEC", "3000000")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let first = notify.collect(Duration::from_millis(2_500));
    let ready = first.iter().position(|m| m == "READY=1");
    assert!(ready.is_some(), "{first:?}");
    assert!(
        first.iter().skip(ready.unwrap()).any(|m| m == "WATCHDOG=1"),
        "no watchdog kick soon after the start: {first:?}"
    );
    Command::new("kill")
        .args(["-HUP", &child.id().to_string()])
        .status()
        .unwrap();
    let reload = notify.collect(Duration::from_millis(1_500));
    let reloading = reload
        .iter()
        .position(|m| m.starts_with("RELOADING=1\nMONOTONIC_USEC="));
    assert!(reloading.is_some(), "{reload:?}");
    assert!(
        reload
            .iter()
            .skip(reloading.unwrap())
            .any(|m| m == "READY=1"),
        "{reload:?}"
    );
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("watchdog_stalled"), "{stderr}");
}

/// Finding A10-3: a `WatchdogSec` below three hub ticks would get a healthy relay killed; it
/// is refused at startup as a configuration error.
#[test]
fn a_too_short_watchdog_is_a_configuration_error() {
    let dir = setup("short-watchdog");
    let (_notify, path) = Notify::new(&dir);
    let out = command(&dir, "run")
        .env("NOTIFY_SOCKET", &path)
        .env("WATCHDOG_USEC", "1000000")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(EX_CONFIG), "{}", text(&out));
    assert!(text(&out).contains("WatchdogSec"), "{}", text(&out));
}
