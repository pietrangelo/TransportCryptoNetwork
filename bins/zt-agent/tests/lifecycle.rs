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

// ---------------------------------------------------------------------------------------------
// R-5: the metrics textfile and `status` (resilience.md §5.5, review 0007 AP-21)
// ---------------------------------------------------------------------------------------------

/// TCP sockets in the `LISTEN` state, by inode, from `/proc/net/tcp*` (world-readable).
fn listeners() -> Vec<(String, u32)> {
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .flat_map(|t| t.lines().skip(1).map(str::to_owned).collect::<Vec<_>>())
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() > 9 && f.get(3) == Some(&"0A"))
                .then(|| Some(((*f.get(9)?).to_owned(), f.get(7)?.parse().ok()?)))
                .flatten()
        })
        .collect()
}

/// The socket inodes `pid` holds, or `None` if its descriptors cannot be read.
fn socket_inodes(pid: &str) -> Option<std::collections::HashSet<String>> {
    Some(
        std::fs::read_dir(format!("/proc/{pid}/fd"))
            .ok()?
            .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
            .filter_map(|t| {
                let t = t.to_string_lossy().into_owned();
                Some(t.strip_prefix("socket:[")?.strip_suffix(']')?.to_owned())
            })
            .collect(),
    )
}

/// Listening sockets of this user that the test process itself does not hold.
fn foreign_listeners() -> std::collections::HashSet<String> {
    use std::os::unix::fs::MetadataExt as _;
    let uid = std::fs::metadata("/proc/self").unwrap().uid();
    let own = socket_inodes("self").unwrap_or_default();
    listeners()
        .into_iter()
        .filter(|(inode, owner)| *owner == uid && !own.contains(inode))
        .map(|(inode, _)| inode)
        .collect()
}

/// TCP sockets of `pid` in the `LISTEN` state.
///
/// As root the child's descriptors are read directly. As another user they cannot be: the
/// binary makes itself non-dumpable (`PR_SET_DUMPABLE` 0, so keys never reach a core file),
/// which also makes `/proc/<pid>/fd` root-only. Then every listening socket of this user that
/// is neither the test's own nor in `baseline` (taken before the child started) is counted:
/// the caller makes sure the child is the only process of this user that may listen meanwhile.
fn listening_sockets(pid: u32, baseline: &std::collections::HashSet<String>) -> usize {
    match socket_inodes(&pid.to_string()) {
        Some(inodes) => listeners()
            .iter()
            .filter(|(inode, _)| inodes.contains(inode))
            .count(),
        None => foreign_listeners().difference(baseline).count(),
    }
}

/// R5-M5 and AP-21: the agent writes its metrics textfile, `status` reads it, and the agent
/// still has no listening socket at all.
#[test]
fn the_agent_writes_its_metrics_and_never_listens() {
    let dir = setup("metrics");
    let path = dir.0.join("run/agent.prom");
    let p = path.display().to_string();
    // Agents never listen: the other tests' agents cannot add to the count.
    let baseline = foreign_listeners();
    let agent = Running::start(&dir, &["--metrics-file", &p, "--metrics-interval", "1"]);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let text = loop {
        if let Ok(text) = std::fs::read_to_string(&path)
            && text.contains("tcn_agent_relay_session_failures_total{relay=\"0\"} ")
            && !text.contains("tcn_agent_relay_session_failures_total{relay=\"0\"} 0\n")
        {
            break text;
        }
        assert!(std::time::Instant::now() < deadline, "no failure counted");
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(text.contains("tcn_agent_relay_up{relay=\"0\"} 0"), "{text}");
    assert!(text.contains("tcn_build_info{role=\"agent\""), "{text}");
    let out = Command::new(BIN)
        .args(["status", "--metrics-file", &p])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text_of(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("role: agent"));
    assert_eq!(listening_sockets(agent.child.id(), &baseline), 0);
}

fn text_of(out: &std::process::Output) -> String {
    text(out)
}
