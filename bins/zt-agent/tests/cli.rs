//! Validation of the `zt-agent` command line (Phase 5): relay list and previous key. Errors
//! arrive before any connection.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Command, Output};

use zt_crypto::Identity;

const BIN: &str = env!("CARGO_BIN_EXE_zt-agent");

struct Dir(std::path::PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn set_mode(p: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn setup(name: &str) -> Dir {
    let dir = std::env::temp_dir().join(format!("zt-agent-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    set_mode(&dir, 0o755);
    for k in ["agent.key", "old.key"] {
        let p = dir.join(k);
        std::fs::write(&p, Identity::generate().unwrap().to_secret_hex().as_str()).unwrap();
        set_mode(&p, 0o600);
    }
    std::fs::write(dir.join("clients.toml"), "").unwrap();
    set_mode(&dir.join("clients.toml"), 0o644);
    Dir(dir)
}

fn key() -> String {
    Identity::generate().unwrap().public_key().to_string()
}

fn run(dir: &Dir, extra: &[&str]) -> Output {
    run_env(dir, extra, &[])
}

/// Like [`run`], with extra environment variables.
fn run_env(dir: &Dir, extra: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(["run", "--node", "web-01", "--key"])
        .arg(dir.0.join("agent.key"))
        .arg("--authorized-clients")
        .arg(dir.0.join("clients.toml"))
        .args(extra)
        .env_remove("RUST_LOG")
        .env_remove("TCN_ACCEPT_CLIENT_SUITES")
        .envs(env.iter().copied());
    // A valid agent does not terminate: it is stopped after a moment.
    let mut child = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..30 {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    child.wait_with_output().unwrap()
}

fn fails_with(out: &Output, needle: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "should fail: {stderr}");
    assert!(stderr.contains(needle), "expected {needle:?} in: {stderr}");
}

#[test]
fn several_relays_are_accepted_as_repeated_or_comma_separated_options() {
    let dir = setup("ok");
    let (a, b) = (key(), key());
    // Valid: the agent starts and keeps running (relays unreachable, it retries).
    for args in [
        vec![
            "--relay",
            "127.0.0.1:9",
            "--relay",
            "127.0.0.1:10",
            "--relay-key",
            &a,
            "--relay-key",
            &b,
        ],
        vec![
            "--relay",
            "127.0.0.1:9,127.0.0.1:10",
            "--relay-key",
            &format!("{a},{b}"),
        ],
    ] {
        let out = run(&dir, &args);
        assert!(
            out.status.code().is_none() || out.status.success(),
            "valid relay list refused: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn a_relay_list_with_mismatched_or_repeated_entries_is_refused() {
    let dir = setup("bad");
    let (a, b) = (key(), key());
    fails_with(
        &run(
            &dir,
            &["--relay", "127.0.0.1:9,127.0.0.1:10", "--relay-key", &a],
        ),
        "relay",
    );
    fails_with(
        &run(
            &dir,
            &[
                "--relay",
                "127.0.0.1:9,127.0.0.1:9",
                "--relay-key",
                &format!("{a},{b}"),
            ],
        ),
        "relay",
    );
    fails_with(
        &run(
            &dir,
            &[
                "--relay",
                "127.0.0.1:9,127.0.0.1:10",
                "--relay-key",
                &format!("{a},{a}"),
            ],
        ),
        "relay",
    );
    let nine: Vec<String> = (0..9).map(|i| format!("127.0.0.1:{}", 100 + i)).collect();
    let keys: Vec<String> = (0..9).map(|_| key()).collect();
    fails_with(
        &run(
            &dir,
            &["--relay", &nine.join(","), "--relay-key", &keys.join(",")],
        ),
        "relay",
    );
}

#[test]
fn the_previous_key_cannot_be_the_current_key() {
    let dir = setup("prev");
    let a = key();
    let current = dir.0.join("agent.key");
    fails_with(
        &run(
            &dir,
            &[
                "--relay",
                "127.0.0.1:9",
                "--relay-key",
                &a,
                "--previous-key",
                current.to_str().unwrap(),
            ],
        ),
        "previous key",
    );
    // A different previous key is accepted.
    let old = dir.0.join("old.key");
    let out = run(
        &dir,
        &[
            "--relay",
            "127.0.0.1:9",
            "--relay-key",
            &a,
            "--previous-key",
            old.to_str().unwrap(),
        ],
    );
    assert!(out.status.code().is_none() || out.status.success());
    // Finding 0005-3: the previous key still accepted is declared in the logs.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let old_fp = Identity::from_secret_hex(std::fs::read_to_string(&old).unwrap().trim())
        .unwrap()
        .fingerprint()
        .to_string();
    assert!(stderr.contains("keys_in_use"), "{stderr}");
    assert!(stderr.contains(&old_fp), "{stderr}");
}

/// Finding 0005b-4: a huge `--max-streams` made the agent panic (tokio semaphore); now it is
/// rejected by the CLI, like zero.
#[test]
fn max_streams_out_of_range_is_refused_without_panic() {
    let dir = setup("maxstreams");
    let a = key();
    let huge = usize::MAX.to_string();
    for bad in ["0", "4097", huge.as_str()] {
        let out = run(
            &dir,
            &[
                "--relay",
                "127.0.0.1:9",
                "--relay-key",
                &a,
                "--max-streams",
                bad,
            ],
        );
        fails_with(&out, "max-streams");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("panicked"), "{stderr}");
    }
    // The limits are accepted.
    for ok in ["1", "4096"] {
        let out = run(
            &dir,
            &[
                "--relay",
                "127.0.0.1:9",
                "--relay-key",
                &a,
                "--max-streams",
                ok,
            ],
        );
        assert!(
            out.status.code().is_none() || out.status.success(),
            "--max-streams {ok} refused: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

// ---------- Phase 6, step 9: pinned CAs and denylist (PROTOCOL §15.8, §15.9) ----------

fn authority_text(ca: &str) -> String {
    format!("[[authorities]]\nname = \"ops-ca\"\npublic_key = \"{ca}\"\nallow = [\"web-01\"]\n")
}

fn write(dir: &Dir, name: &str, text: &str) -> String {
    let p = dir.0.join(name);
    std::fs::write(&p, text).unwrap();
    set_mode(&p, 0o644);
    p.to_str().unwrap().to_owned()
}

fn public_of(file: &std::path::Path) -> String {
    Identity::from_secret_hex(std::fs::read_to_string(file).unwrap().trim())
        .unwrap()
        .public_key()
        .to_string()
}

/// A valid agent keeps running: `run` stops it (no exit code) or it has exited
/// successfully.
fn keeps_running(out: &Output) {
    assert!(
        out.status.code().is_none() || out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn authorities_without_revocations_refuse_to_start() {
    let dir = setup("ca-no-revocations");
    let relay = key();
    write(&dir, "clients.toml", &authority_text(&key()));
    let out = run(&dir, &["--relay", "127.0.0.1:9", "--relay-key", &relay]);
    fails_with(&out, "revocations");
    // Positive control: with the (empty) denylist the agent starts and announces the CA.
    let revoked = write(&dir, "revoked.toml", "serials = []\nkeys = []\n");
    let out = run(
        &dir,
        &[
            "--relay",
            "127.0.0.1:9",
            "--relay-key",
            &relay,
            "--revocations",
            &revoked,
        ],
    );
    keeps_running(&out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("authorities_in_use"), "{stderr}");
}

#[test]
fn a_ca_key_equal_to_the_process_key_refuses_to_start() {
    let dir = setup("ca-is-me");
    let relay = key();
    let revoked = write(&dir, "revoked.toml", "serials = []\nkeys = []\n");
    let (current, old) = (dir.0.join("agent.key"), dir.0.join("old.key"));
    let base = [
        "--relay",
        "127.0.0.1:9",
        "--relay-key",
        relay.as_str(),
        "--revocations",
        revoked.as_str(),
    ];
    // The CA is the agent's key.
    write(&dir, "clients.toml", &authority_text(&public_of(&current)));
    let out = run(&dir, &base);
    assert!(
        out.status.code().is_some_and(|c| c != 0),
        "the agent started"
    );
    // The CA is the agent's previous key.
    write(&dir, "clients.toml", &authority_text(&public_of(&old)));
    let mut with_previous = base.to_vec();
    with_previous.extend(["--previous-key", old.to_str().unwrap()]);
    let out = run(&dir, &with_previous);
    assert!(
        out.status.code().is_some_and(|c| c != 0),
        "the agent started"
    );
    // Positive control: another CA is fine.
    write(&dir, "clients.toml", &authority_text(&key()));
    keeps_running(&run(&dir, &with_previous));
}

/// Finding 0006-1: a CA equal to a pinned `--relay-key` is rejected at startup and on every
/// `SIGHUP`. Otherwise a compromised relay, with its own node seed turned into a CA file,
/// would sign certificates that the agent admits.
#[test]
fn a_ca_key_equal_to_a_pinned_relay_key_is_refused_at_start_and_on_reload() {
    let dir = setup("ca-is-relay");
    let (first, second) = (key(), key());
    let revoked = write(&dir, "revoked.toml", "serials = []\nkeys = []\n");
    let relays = format!("{first},{second}");
    let base = [
        "--relay",
        "127.0.0.1:9,127.0.0.1:10",
        "--relay-key",
        relays.as_str(),
        "--revocations",
        revoked.as_str(),
    ];
    // At startup: the CA is any one of the pinned relays.
    for relay in [&first, &second] {
        write(&dir, "clients.toml", &authority_text(relay));
        fails_with(&run(&dir, &base), "authority key equals the relay key");
    }
    // On reload: the agent starts with another CA, then `clients.toml` pins a relay's key.
    write(&dir, "clients.toml", &authority_text(&key()));
    let mut child = Command::new(BIN)
        .args(["run", "--node", "web-01", "--key"])
        .arg(dir.0.join("agent.key"))
        .arg("--authorized-clients")
        .arg(dir.0.join("clients.toml"))
        .args(base)
        .env_remove("RUST_LOG")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(child.try_wait().unwrap().is_none(), "the agent exited");
    write(&dir, "clients.toml", &authority_text(&second));
    let hup = Command::new("kill")
        .args(["-HUP", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(hup.success());
    std::thread::sleep(std::time::Duration::from_secs(1));
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("authorized_clients_reload_failed")
            && stderr.contains("authority key equals the relay key"),
        "{stderr}"
    );
    assert!(!stderr.contains("authorized_clients_reloaded"), "{stderr}");
}

// ---------- PQ-1: end-to-end handshake suites ----------

const CLASSIC: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const HFS: &str = "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s";

/// The hybrid suite is accepted from clients end to end, alone or with the classical one.
#[test]
fn the_agent_accepts_the_hybrid_suite_from_clients() {
    let dir = setup("pq-accept");
    let relay = key();
    for accepted in [format!("{CLASSIC},{HFS}"), HFS.to_owned()] {
        let out = run(
            &dir,
            &[
                "--relay",
                "127.0.0.1:9",
                "--relay-key",
                &relay,
                "--accept-client-suites",
                &accepted,
            ],
        );
        keeps_running(&out);
    }
}

/// New installations set the accepted suites in `agent.env` (OPERATIONS §9), so the option
/// has an environment variable. An unset variable keeps the built-in default.
#[test]
fn the_accepted_suites_can_come_from_the_environment() {
    let dir = setup("pq-env");
    let relay = key();
    let args = ["--relay", "127.0.0.1:9", "--relay-key", &relay];
    let both = format!("{CLASSIC},{HFS}");
    keeps_running(&run_env(
        &dir,
        &args,
        &[("TCN_ACCEPT_CLIENT_SUITES", both.as_str())],
    ));
    fails_with(
        &run_env(
            &dir,
            &args,
            &[("TCN_ACCEPT_CLIENT_SUITES", "Noise_XX_25519_ChaChaPoly_BLAKE2s")],
        ),
        "suite",
    );
}

/// The relay pin is the outer channel, which stays classical in this release.
#[test]
fn the_hybrid_suite_towards_the_relays_is_refused() {
    let dir = setup("pq-relay");
    let relay = key();
    fails_with(
        &run(
            &dir,
            &[
                "--relay",
                "127.0.0.1:9",
                "--relay-key",
                &relay,
                "--relay-suite",
                HFS,
            ],
        ),
        "suite",
    );
}

#[test]
fn repeated_or_unknown_accepted_suites_are_refused() {
    let dir = setup("pq-bad");
    let relay = key();
    for accepted in [
        format!("{HFS},{HFS}"),
        "noise_ikhfs_25519+mlkem768_chachapoly_blake2s".to_owned(),
        "Noise_IKhfs_25519+Kyber1024_ChaChaPoly_BLAKE2s".to_owned(),
    ] {
        fails_with(
            &run(
                &dir,
                &[
                    "--relay",
                    "127.0.0.1:9",
                    "--relay-key",
                    &relay,
                    "--accept-client-suites",
                    &accepted,
                ],
            ),
            "suite",
        );
    }
}
