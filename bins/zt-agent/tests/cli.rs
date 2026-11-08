//! Validazione della riga di comando di `zt-agent` (Fase 5): elenco dei relay e chiave
//! precedente. Gli errori arrivano prima di qualsiasi connessione.
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
    let mut cmd = Command::new(BIN);
    cmd.args(["run", "--node", "web-01", "--key"])
        .arg(dir.0.join("agent.key"))
        .arg("--authorized-clients")
        .arg(dir.0.join("clients.toml"))
        .args(extra)
        .env_remove("RUST_LOG");
    // Un agent valido non termina: lo si ferma dopo un attimo.
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
    // Valida: l'agent parte e resta in esecuzione (relay irraggiungibili, riprova).
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
    // Una precedente diversa è accettata.
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
    // Finding 0005-3: la chiave precedente ancora accettata è dichiarata nei log.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let old_fp = Identity::from_secret_hex(std::fs::read_to_string(&old).unwrap().trim())
        .unwrap()
        .fingerprint()
        .to_string();
    assert!(stderr.contains("keys_in_use"), "{stderr}");
    assert!(stderr.contains(&old_fp), "{stderr}");
}
