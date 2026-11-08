//! Esercizio del relay (Fase 4): audit log JSON leggibile da una macchina e ricarica della
//! policy con SIGHUP, che si applica anche alle connessioni già aperte.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::format_push_string,
    clippy::arithmetic_side_effects,
    clippy::assigning_clones
)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use zt_crypto::Identity;
use zt_domain::NodeId;
use zt_net::client::{self, ClientConfig};
use zt_net::{NetError, Timeouts};

const BIN: &str = env!("CARGO_BIN_EXE_zt-relay");

struct Relay {
    child: Child,
    lines: mpsc::Receiver<serde_json::Value>,
    addr: String,
    key: Identity,
    dir: std::path::PathBuf,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn set_mode(p: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn policy_text(clients: &[&Identity]) -> String {
    let agent = Identity::generate().unwrap();
    let mut t = format!(
        "[[agents]]\nnode = \"web-01\"\npublic_key = \"{}\"\n",
        agent.public_key()
    );
    for (i, c) in clients.iter().enumerate() {
        t.push_str(&format!(
            "[[clients]]\nname = \"c{i}\"\npublic_key = \"{}\"\nallow = [\"*\"]\n",
            c.public_key()
        ));
    }
    t
}

impl Relay {
    fn start(name: &str, clients: &[&Identity]) -> Self {
        let dir = std::env::temp_dir().join(format!("zt-relay-ops-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_mode(&dir, 0o755);
        let key = Identity::generate().unwrap();
        std::fs::write(dir.join("relay.key"), key.to_secret_hex().as_str()).unwrap();
        set_mode(&dir.join("relay.key"), 0o600);
        std::fs::write(dir.join("policy.toml"), policy_text(clients)).unwrap();
        set_mode(&dir.join("policy.toml"), 0o644);
        let mut child = Command::new(BIN)
            .args([
                "--log-format",
                "json",
                "run",
                "--listen",
                "127.0.0.1:0",
                "--key",
            ])
            .arg(dir.join("relay.key"))
            .arg("--policy")
            .arg(dir.join("policy.toml"))
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { return };
                let value: serde_json::Value = serde_json::from_str(&line)
                    .unwrap_or_else(|e| panic!("log line is not JSON ({e}): {line}"));
                if tx.send(value).is_err() {
                    return;
                }
            }
        });
        let mut relay = Self {
            child,
            lines,
            addr: String::new(),
            key,
            dir,
        };
        let listening = relay.wait_for(|v| v["fields"]["message"] == "relay listening");
        let addr = listening["fields"]["addr"].as_str().unwrap().to_owned();
        relay.addr = addr
            .trim_start_matches("Some(")
            .trim_end_matches(')')
            .to_owned();
        relay
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

    /// Le righe "relay listening" e `keys_in_use` dell'avvio, in qualsiasi ordine: le chiavi
    /// accettate sono dichiarate all'avvio (finding 0005-3).
    fn startup(&self) -> (serde_json::Value, serde_json::Value) {
        let (mut listening, mut in_use) = (None, None);
        while listening.is_none() || in_use.is_none() {
            let v = self.wait_for(|_| true);
            if v["fields"]["message"] == "relay listening" {
                listening = Some(v);
            } else if v["fields"]["event_kind"] == "keys_in_use" {
                in_use = Some(v);
            }
        }
        (listening.unwrap(), in_use.unwrap())
    }

    fn config(&self) -> ClientConfig {
        ClientConfig {
            relays: vec![zt_net::RelayEndpoint {
                address: self.addr.clone(),
                public_key: self.key.public_key(),
            }],
            node: NodeId::try_from("web-01").unwrap(),
            node_key: Identity::generate().unwrap().public_key(),
            timeouts: Timeouts {
                handshake: Duration::from_secs(2),
                open: Duration::from_secs(2),
                ..Timeouts::default()
            },
        }
    }

    fn hup(&self) {
        let ok = Command::new("kill")
            .args(["-HUP", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(ok.success());
    }
}

/// Esito di una connessione: autenticata (il relay risponde, il nodo è offline) o no.
async fn try_connect(relay: &Relay, who: &Identity) -> Result<(), NetError> {
    let (_app, local) = tokio::io::duplex(1024);
    tokio::time::timeout(
        Duration::from_secs(5),
        client::connect(who, &relay.config(), local),
    )
    .await
    .expect("connect hung")
}

#[tokio::test]
async fn audit_events_are_json_with_a_stable_kind_and_no_secrets() {
    let stranger = Identity::generate().unwrap();
    let relay = Relay::start("audit", &[]);
    let _ = try_connect(&relay, &stranger).await;
    let event =
        relay.wait_for(|v| v["target"] == "zt_audit" && v["fields"]["event_kind"] != "keys_in_use");
    assert_eq!(event["fields"]["event_kind"], "authentication_failed");
    assert_eq!(event["level"], "WARN");
    assert!(event["timestamp"].is_string());
    // Campi strutturati, non una stringa `Debug` da analizzare (finding 0004-4).
    assert_eq!(
        event["fields"]["peer"],
        stranger.fingerprint().to_string(),
        "{event}"
    );
    assert_eq!(event["fields"]["reason"], "UnknownPeer", "{event}");
    assert!(event["fields"].get("event").is_none(), "{event}");
    let text = event.to_string();
    assert!(!text.contains(relay.key.to_secret_hex().as_str()));
}

#[tokio::test]
async fn sighup_reloads_the_policy_and_revokes_live_connections() {
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let relay = Relay::start("hup", &[&alice]);
    // alice è autenticata: il nodo è solo offline. bob non è nella policy.
    assert!(matches!(
        try_connect(&relay, &alice).await,
        Err(NetError::Rejected(_))
    ));
    assert!(!matches!(
        try_connect(&relay, &bob).await,
        Err(NetError::Rejected(_))
    ));

    std::fs::write(relay.dir.join("policy.toml"), policy_text(&[&bob])).unwrap();
    relay.hup();
    let reloaded = relay.wait_for(|v| v["fields"]["event_kind"] == "policy_reloaded");
    assert_eq!(reloaded["target"], "zt_audit");
    assert!(matches!(
        try_connect(&relay, &bob).await,
        Err(NetError::Rejected(_))
    ));
    assert!(!matches!(
        try_connect(&relay, &alice).await,
        Err(NetError::Rejected(_))
    ));
}

#[tokio::test]
async fn an_invalid_policy_on_reload_keeps_the_previous_one() {
    let alice = Identity::generate().unwrap();
    let relay = Relay::start("bad", &[&alice]);
    std::fs::write(
        relay.dir.join("policy.toml"),
        "[[agents]]\nnode = \"BAD\"\n",
    )
    .unwrap();
    relay.hup();
    let failed = relay.wait_for(|v| v["fields"]["event_kind"] == "policy_reload_failed");
    assert_eq!(failed["level"], "ERROR");
    assert!(matches!(
        try_connect(&relay, &alice).await,
        Err(NetError::Rejected(_))
    ));
    // Anche un file diventato scrivibile da altri viene rifiutato e la policy resta quella.
    std::fs::write(relay.dir.join("policy.toml"), policy_text(&[])).unwrap();
    set_mode(&relay.dir.join("policy.toml"), 0o666);
    relay.hup();
    relay.wait_for(|v| v["fields"]["event_kind"] == "policy_reload_failed");
    assert!(matches!(
        try_connect(&relay, &alice).await,
        Err(NetError::Rejected(_))
    ));
}

/// Finding 0004-2: con `Type=notify` systemd invia `reload` solo dopo `READY=1`. Da quel momento
/// un `SIGHUP`, anche immediato, ricarica la policy e non termina il relay.
#[test]
fn ready_is_notified_only_once_sighup_is_handled() {
    use std::os::unix::net::UnixDatagram;
    let dir = std::env::temp_dir().join(format!("zt-relay-notify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    set_mode(&dir, 0o755);
    let key = Identity::generate().unwrap();
    std::fs::write(dir.join("relay.key"), key.to_secret_hex().as_str()).unwrap();
    set_mode(&dir.join("relay.key"), 0o600);
    std::fs::write(dir.join("policy.toml"), policy_text(&[])).unwrap();
    set_mode(&dir.join("policy.toml"), 0o644);
    let notify = UnixDatagram::bind(dir.join("notify.sock")).unwrap();
    notify
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    for round in 0..10 {
        let mut child = Command::new(BIN)
            .args(["run", "--listen", "127.0.0.1:0", "--key"])
            .arg(dir.join("relay.key"))
            .arg("--policy")
            .arg(dir.join("policy.toml"))
            .env("NOTIFY_SOCKET", dir.join("notify.sock"))
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut buf = [0_u8; 64];
        let n = notify.recv(&mut buf).expect("no READY=1 from the relay");
        assert_eq!(&buf[..n], b"READY=1");
        let ok = Command::new("kill")
            .args(["-HUP", &child.id().to_string()])
            .status()
            .unwrap();
        assert!(ok.success());
        std::thread::sleep(Duration::from_millis(200));
        let status = child.try_wait().unwrap();
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            status.is_none(),
            "round {round}: SIGHUP after READY killed the relay"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Fase 5 (PROTOCOL §14): la chiave del relay ruota con `SIGHUP`, senza riavvio. Dopo la
/// ricarica valgono la chiave nuova e la precedente; quella ancora più vecchia no.
fn assert_keys(in_use: &serde_json::Value, current: &Identity, previous: &Identity) {
    let fields = &in_use["fields"];
    assert_eq!(
        fields["current_fingerprint"],
        current.fingerprint().to_string()
    );
    assert_eq!(
        fields["previous_fingerprint"],
        previous.fingerprint().to_string()
    );
}

#[tokio::test]
async fn sighup_rotates_the_relay_key_without_a_restart() {
    let client = Identity::generate().unwrap();
    let dir = std::env::temp_dir().join(format!("zt-relay-rotate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    set_mode(&dir, 0o755);
    let (oldest, old, new) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    let write_key = |name: &str, id: &Identity| {
        let p = dir.join(name);
        std::fs::write(&p, id.to_secret_hex().as_str()).unwrap();
        set_mode(&p, 0o600);
    };
    write_key("cur.key", &old);
    write_key("prev.key", &oldest);
    std::fs::write(dir.join("policy.toml"), policy_text(&[&client])).unwrap();
    set_mode(&dir.join("policy.toml"), 0o644);
    let mut child = Command::new(BIN)
        .args([
            "--log-format",
            "json",
            "run",
            "--listen",
            "127.0.0.1:0",
            "--key",
        ])
        .arg(dir.join("cur.key"))
        .arg("--previous-key")
        .arg(dir.join("prev.key"))
        .arg("--policy")
        .arg(dir.join("policy.toml"))
        .env("RUST_LOG", "info")
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
    let mut relay = Relay {
        child,
        lines,
        addr: String::new(),
        key: Identity::from_secret_hex(&old.to_secret_hex()).unwrap(),
        dir: dir.clone(),
    };
    let (listening, in_use) = relay.startup();
    relay.addr = listening["fields"]["addr"].as_str().unwrap().to_owned();
    assert_eq!(in_use["target"], "zt_audit");
    assert_keys(&in_use, &old, &oldest);

    let reaches = |relay: &Relay, pin: &Identity| {
        let mut config = relay.config();
        config.relays[0].public_key = pin.public_key();
        let who = Identity::from_secret_hex(&client.to_secret_hex()).unwrap();
        async move {
            let (_app, local) = tokio::io::duplex(1024);
            let r = tokio::time::timeout(
                Duration::from_secs(5),
                client::connect(&who, &config, local),
            )
            .await
            .expect("connect hung");
            // Autenticato: il relay risponde che il nodo è offline.
            matches!(r, Err(NetError::Rejected(_)))
        }
    };
    assert!(reaches(&relay, &old).await);
    assert!(reaches(&relay, &oldest).await);
    assert!(!reaches(&relay, &new).await);

    // Rotazione: nuova chiave corrente, la vecchia diventa precedente.
    write_key("cur.key", &new);
    write_key("prev.key", &old);
    relay.hup();
    let in_use = relay.wait_for(|v| v["fields"]["event_kind"] == "keys_in_use");
    assert_keys(&in_use, &new, &old);
    assert!(reaches(&relay, &new).await, "new key after SIGHUP");
    assert!(reaches(&relay, &old).await, "previous key after SIGHUP");
    assert!(
        !reaches(&relay, &oldest).await,
        "the retired key must stop working"
    );

    // Un file non valido lascia in vigore le chiavi di prima.
    std::fs::write(dir.join("cur.key"), "not a key").unwrap();
    relay.hup();
    relay.wait_for(|v| v["fields"]["event_kind"] == "relay_keys_reload_failed");
    assert!(reaches(&relay, &new).await);
}

/// Finding 0005b-2: due chiavi di agent per un nodo nella policy (rotazione dell'agent non
/// completata) sono segnalate alla ricarica con `agent_rotation_pending`.
#[test]
fn a_pending_agent_rotation_in_the_policy_is_reported() {
    let relay = Relay::start("agent-rotation", &[]);
    let (new, old) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    std::fs::write(
        relay.dir.join("policy.toml"),
        format!(
            "[[agents]]\nnode = \"web-01\"\npublic_keys = [\"{}\", \"{}\"]\n",
            new.public_key(),
            old.public_key()
        ),
    )
    .unwrap();
    relay.hup();
    let event = relay.wait_for(|v| v["fields"]["event_kind"] == "agent_rotation_pending");
    assert_eq!(event["target"], "zt_audit");
    assert_eq!(event["level"], "WARN");
    assert_eq!(event["fields"]["node"], "web-01");
    let fingerprints = event["fields"]["fingerprints"].as_str().unwrap();
    assert!(
        fingerprints.contains(&new.fingerprint().to_string()),
        "{event}"
    );
    assert!(
        fingerprints.contains(&old.fingerprint().to_string()),
        "{event}"
    );
}
