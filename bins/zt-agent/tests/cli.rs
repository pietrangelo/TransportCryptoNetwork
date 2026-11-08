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

/// Finding 0005b-4: un `--max-streams` enorme faceva andare in panic l'agent (semaforo di
/// tokio); ora è rifiutato dalla CLI, come lo zero.
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
    // I limiti sono accettati.
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

// ---------- Fase 6, passo 9: CA pinnate e denylist (PROTOCOL §15.8, §15.9) ----------

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

/// Un agent valido resta in esecuzione: `run` lo ferma (nessun codice d'uscita) o è uscito
/// con successo.
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
    // Controllo positivo: con la denylist (vuota) l'agent parte e annuncia la CA.
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
    // La CA è la chiave dell'agent.
    write(&dir, "clients.toml", &authority_text(&public_of(&current)));
    let out = run(&dir, &base);
    assert!(
        out.status.code().is_some_and(|c| c != 0),
        "the agent started"
    );
    // La CA è la chiave precedente dell'agent.
    write(&dir, "clients.toml", &authority_text(&public_of(&old)));
    let mut with_previous = base.to_vec();
    with_previous.extend(["--previous-key", old.to_str().unwrap()]);
    let out = run(&dir, &with_previous);
    assert!(
        out.status.code().is_some_and(|c| c != 0),
        "the agent started"
    );
    // Controllo positivo: un'altra CA va bene.
    write(&dir, "clients.toml", &authority_text(&key()));
    keeps_running(&run(&dir, &with_previous));
}

/// Finding 0006-1: una CA uguale a un `--relay-key` pinnato è rifiutata all'avvio e a ogni
/// `SIGHUP`. Altrimenti un relay compromesso, con il proprio seme di nodo trasformato in file di
/// CA, firmerebbe certificati che l'agent ammette.
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
    // All'avvio: la CA è uno qualsiasi dei relay pinnati.
    for relay in [&first, &second] {
        write(&dir, "clients.toml", &authority_text(relay));
        fails_with(&run(&dir, &base), "authority key equals the relay key");
    }
    // Alla ricarica: l'agent parte con un'altra CA, poi `clients.toml` pinna la chiave di un relay.
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
    std::thread::sleep(std::time::Duration::from_millis(1_000));
    assert!(child.try_wait().unwrap().is_none(), "the agent exited");
    write(&dir, "clients.toml", &authority_text(&second));
    let hup = Command::new("kill")
        .args(["-HUP", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(hup.success());
    std::thread::sleep(std::time::Duration::from_millis(1_000));
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
