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
            certificate: None,
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

// ---------- Fase 6, passo 9: CA pinnate e denylist (PROTOCOL §15.8, §15.9; OPERATIONS §10) ----------

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn authority_text(ca: &zt_crypto::PublicKey) -> String {
    format!("[[authorities]]\nname = \"ops-ca\"\npublic_key = \"{ca}\"\nallow = [\"*\"]\n")
}

const EMPTY_REVOCATIONS: &str = "serials = []\nkeys = []\n";

/// Directory di un relay della Fase 6: `relay.key`, `prev.key`, `policy.toml`, `revoked.toml`.
struct CaDir {
    dir: std::path::PathBuf,
    key: Identity,
    previous: Identity,
}

impl CaDir {
    fn new(name: &str, policy: &str, revoked: Option<&str>) -> Self {
        let dir = std::env::temp_dir().join(format!("zt-relay-ca-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_mode(&dir, 0o755);
        let (key, previous) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        for (file, id) in [("relay.key", &key), ("prev.key", &previous)] {
            std::fs::write(dir.join(file), id.to_secret_hex().as_str()).unwrap();
            set_mode(&dir.join(file), 0o600);
        }
        let this = Self { dir, key, previous };
        this.write("policy.toml", policy);
        if let Some(r) = revoked {
            this.write("revoked.toml", r);
        }
        this
    }
    fn write(&self, name: &str, text: &str) {
        std::fs::write(self.dir.join(name), text).unwrap();
        set_mode(&self.dir.join(name), 0o644);
    }
    fn command(&self, extra: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.args([
            "--log-format",
            "json",
            "run",
            "--listen",
            "127.0.0.1:0",
            "--key",
        ])
        .arg(self.dir.join("relay.key"))
        .arg("--policy")
        .arg(self.dir.join("policy.toml"))
        .args(extra)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
        cmd
    }
    fn revocations_arg(&self) -> String {
        self.dir.join("revoked.toml").to_str().unwrap().to_owned()
    }
    fn previous_arg(&self) -> String {
        self.dir.join("prev.key").to_str().unwrap().to_owned()
    }
    /// Il processo deve terminare da solo, con errore, entro pochi secondi.
    fn refuses(&self, extra: &[&str]) -> String {
        let mut child = self.command(extra).spawn().unwrap();
        for _ in 0..50 {
            if let Some(status) = child.try_wait().unwrap() {
                let out = child.wait_with_output().unwrap();
                assert!(!status.success());
                return String::from_utf8_lossy(&out.stderr).into_owned();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        panic!(
            "the relay started: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    /// Avvia il relay e attende «relay listening».
    fn start(self, extra: &[&str]) -> Relay {
        let mut child = self.command(extra).spawn().unwrap();
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
        let Self { dir, key, .. } = self;
        let mut relay = Relay {
            child,
            lines,
            addr: String::new(),
            key,
            dir,
        };
        let listening = relay.wait_for(|v| v["fields"]["message"] == "relay listening");
        relay.addr = listening["fields"]["addr"]
            .as_str()
            .unwrap()
            .trim_start_matches("Some(")
            .trim_end_matches(')')
            .to_owned();
        relay
    }
}

fn issue(ca: &zt_crypto::CaSigningKey, subject: &Identity) -> (Vec<u8>, zt_domain::CertSerial) {
    let now = now_secs();
    let mut b = [0_u8; 16];
    b[..8].copy_from_slice(&now.to_be_bytes());
    b[15] = 0x99;
    let serial = zt_domain::CertSerial::try_from(b).unwrap();
    let body = zt_domain::CertBody::new(
        zt_crypto::cert_key(&ca.public_key()),
        zt_crypto::cert_key(&subject.public_key()),
        serial,
        zt_domain::UnixTime::from_secs(now - 60),
        zt_domain::UnixTime::from_secs(now + 3_600),
        NodeId::try_from("alice").unwrap(),
        zt_domain::CertScope::All,
    )
    .unwrap();
    (zt_crypto::sign_certificate(ca, &body).unwrap(), serial)
}

/// Autenticato dal relay con il certificato: il relay risponde che il nodo è offline.
async fn certified(relay: &Relay, who: &Identity, cert: &[u8]) -> bool {
    let mut config = relay.config();
    config.certificate = Some(std::sync::Arc::from(cert));
    let (_app, local) = tokio::io::duplex(1024);
    let r = tokio::time::timeout(Duration::from_secs(5), client::connect(who, &config, local))
        .await
        .expect("connect hung");
    matches!(r, Err(NetError::Rejected(_)))
}

#[test]
fn authorities_without_revocations_refuse_to_start() {
    let ca = Identity::generate().unwrap().public_key();
    let dir = CaDir::new(
        "no-revocations",
        &format!("{}\n{}", policy_text(&[]), authority_text(&ca)),
        Some(EMPTY_REVOCATIONS),
    );
    let stderr = dir.refuses(&[]);
    assert!(stderr.contains("revocations"), "{stderr}");
    // Controllo positivo: con la denylist (vuota) il relay parte e annuncia la CA.
    let revocations = dir.revocations_arg();
    let relay = dir.start(&["--revocations", &revocations]);
    let event = relay.wait_for(|v| v["fields"]["event_kind"] == "authorities_in_use");
    assert_eq!(event["fields"]["authority"], "ops-ca");
    assert!(
        event.to_string().contains(&ca.fingerprint().to_string()),
        "{event}"
    );
}

#[test]
fn a_ca_key_equal_to_the_process_key_refuses_to_start() {
    let dir = CaDir::new("ca-is-me", &policy_text(&[]), Some(EMPTY_REVOCATIONS));
    let (revocations, previous) = (dir.revocations_arg(), dir.previous_arg());
    // La CA è la chiave corrente del relay.
    dir.write(
        "policy.toml",
        &format!(
            "{}\n{}",
            policy_text(&[]),
            authority_text(&dir.key.public_key())
        ),
    );
    dir.refuses(&["--revocations", &revocations]);
    // La CA è la chiave precedente del relay.
    dir.write(
        "policy.toml",
        &format!(
            "{}\n{}",
            policy_text(&[]),
            authority_text(&dir.previous.public_key())
        ),
    );
    dir.refuses(&["--revocations", &revocations, "--previous-key", &previous]);
    // Controllo positivo: un'altra CA va bene.
    let other = Identity::generate().unwrap().public_key();
    dir.write(
        "policy.toml",
        &format!("{}\n{}", policy_text(&[]), authority_text(&other)),
    );
    let _relay = dir.start(&["--revocations", &revocations, "--previous-key", &previous]);
}

#[tokio::test]
async fn sighup_reloads_revocations_and_cuts_a_revoked_certificate() {
    let ca = zt_crypto::CaSigningKey::generate().unwrap();
    let alice = Identity::generate().unwrap();
    let (cert, serial) = issue(&ca, &alice);
    let policy = format!("{}\n{}", policy_text(&[]), authority_text(&ca.public_key()));
    let dir = CaDir::new("hup-revocations", &policy, Some(EMPTY_REVOCATIONS));
    let revocations = dir.revocations_arg();
    let relay = dir.start(&["--revocations", &revocations]);
    // L'annuncio dell'avvio (denylist vuota) arriva dopo «relay listening»: va letto qui, o
    // `wait_all` lo scambierebbe per quello della ricarica.
    let startup = relay.wait_for(|v| v["fields"]["event_kind"] == "revocations_in_use");
    assert_eq!(startup["fields"]["serials"], 0, "{startup}");
    assert!(certified(&relay, &alice, &cert).await);

    // Una connessione aperta con il certificato.
    let tcp = tokio::net::TcpStream::connect(&relay.addr).await.unwrap();
    let mut live = zt_net::channel::connect_with_payload(
        tcp,
        &alice,
        &relay.key.public_key(),
        zt_crypto::noise::Channel::Outer,
        &cert,
        &relay.config().timeouts,
    )
    .await
    .unwrap();

    std::fs::write(
        relay.dir.join("revoked.toml"),
        format!("serials = [\"{serial}\"]\nkeys = []\n"),
    )
    .unwrap();
    relay.hup();
    let events = wait_all(
        &relay,
        &["policy_reloaded", "access_revoked", "revocations_in_use"],
    );
    let revoked = &events["access_revoked"];
    assert_eq!(revoked["fields"]["serial"], serial.to_string(), "{revoked}");
    let in_use = &events["revocations_in_use"];
    assert_eq!(in_use["fields"]["serials"], 1, "{in_use}");
    let cut = tokio::time::timeout(Duration::from_secs(5), live.recv())
        .await
        .expect("the revoked connection is still open");
    assert!(!matches!(cut, Ok(Some(_))), "{cut:?}");
    assert!(!certified(&relay, &alice, &cert).await);
}

/// Attende un evento per ciascun `event_kind` di `kinds`, in qualsiasi ordine.
fn wait_all(relay: &Relay, kinds: &[&str]) -> std::collections::HashMap<String, serde_json::Value> {
    let mut seen = std::collections::HashMap::new();
    while seen.len() < kinds.len() {
        let v = relay.wait_for(|v| {
            v["fields"]["event_kind"]
                .as_str()
                .is_some_and(|k| kinds.contains(&k))
        });
        let kind = v["fields"]["event_kind"].as_str().unwrap().to_owned();
        seen.entry(kind).or_insert(v);
    }
    seen
}

#[tokio::test]
async fn a_bad_revocation_file_on_reload_keeps_both_previous_files() {
    let ca = zt_crypto::CaSigningKey::generate().unwrap();
    let alice = Identity::generate().unwrap();
    let (cert, serial) = issue(&ca, &alice);
    let policy = format!("{}\n{}", policy_text(&[]), authority_text(&ca.public_key()));
    let dir = CaDir::new("bad-revocations", &policy, Some(EMPTY_REVOCATIONS));
    let revocations = dir.revocations_arg();
    let relay = dir.start(&["--revocations", &revocations]);
    assert!(certified(&relay, &alice, &cert).await);

    // Policy nuova valida (senza la CA) + denylist non valida: non entra nessuna delle due.
    std::fs::write(relay.dir.join("policy.toml"), policy_text(&[])).unwrap();
    std::fs::write(
        relay.dir.join("revoked.toml"),
        "serials = [\"zz\"]\nkeys = []\n",
    )
    .unwrap();
    relay.hup();
    let failed = relay.wait_for(|v| v["fields"]["event_kind"] == "policy_reload_failed");
    assert_eq!(failed["level"], "ERROR");
    assert!(
        certified(&relay, &alice, &cert).await,
        "the new policy entered"
    );

    // Denylist nuova valida (revoca alice) + policy non valida: la revoca non entra.
    std::fs::write(
        relay.dir.join("policy.toml"),
        "[[agents]]\nnode = \"BAD\"\n",
    )
    .unwrap();
    std::fs::write(
        relay.dir.join("revoked.toml"),
        format!("serials = [\"{serial}\"]\nkeys = []\n"),
    )
    .unwrap();
    relay.hup();
    relay.wait_for(|v| v["fields"]["event_kind"] == "policy_reload_failed");
    assert!(
        certified(&relay, &alice, &cert).await,
        "the new denylist entered"
    );
}

/// Finding 0006-2: una rotazione con `SIGHUP` verso una chiave del relay uguale a una CA della
/// policy in vigore è rifiutata come all'avvio (`relay_keys_reload_failed`, messaggio esplicito)
/// e restano le chiavi precedenti; la policy si ricarica ancora. Controllo positivo: una chiave
/// nuova qualsiasi entra.
#[tokio::test]
async fn a_relay_key_reload_equal_to_a_pinned_ca_key_is_refused() {
    let ca = zt_crypto::CaSigningKey::generate().unwrap();
    let alice = Identity::generate().unwrap();
    let (cert, _) = issue(&ca, &alice);
    let policy = format!("{}\n{}", policy_text(&[]), authority_text(&ca.public_key()));
    let dir = CaDir::new("rotate-to-ca", &policy, Some(EMPTY_REVOCATIONS));
    let revocations = dir.revocations_arg();
    let relay = dir.start(&["--revocations", &revocations]);
    let secret = ca.to_secret_text();
    let seed = secret
        .trim_end()
        .strip_prefix(zt_crypto::CaSigningKey::FILE_PREFIX)
        .unwrap()
        .to_owned();
    let key_file = relay.dir.join("relay.key");
    std::fs::write(&key_file, format!("{seed}\n")).unwrap();
    set_mode(&key_file, 0o600);
    relay.hup();
    let failed = relay.wait_for(|v| {
        v["fields"]["event_kind"] == "relay_keys_reloaded"
            || v["fields"]["event_kind"] == "relay_keys_reload_failed"
    });
    assert_eq!(failed["fields"]["event_kind"], "relay_keys_reload_failed");
    let error = failed["fields"]["error"].as_str().unwrap();
    assert!(
        error.contains("authority key equals the relay key")
            && error.contains(&ca.public_key().fingerprint().to_string()),
        "{failed}"
    );
    // Le chiavi precedenti restano: il relay risponde ancora con la sua chiave e ammette il
    // certificato.
    assert!(certified(&relay, &alice, &cert).await);
    // La policy si ricarica ancora (prima della correzione falliva da qui in poi); lo stesso
    // `SIGHUP` rifiuta di nuovo la chiave. Si attendono entrambi prima di cambiare il file.
    relay.hup();
    let (mut policy_event, mut keys_event) = (None, None);
    while policy_event.is_none() || keys_event.is_none() {
        let v = relay.wait_for(|_| true);
        let kind = v["fields"]["event_kind"].as_str().unwrap_or_default().to_owned();
        if kind.starts_with("policy_reload") {
            policy_event = Some(kind);
        } else if kind.starts_with("relay_keys_reload") {
            keys_event = Some(kind);
        }
    }
    assert_eq!(policy_event.unwrap(), "policy_reloaded");
    assert_eq!(keys_event.unwrap(), "relay_keys_reload_failed");
    // Controllo positivo: una chiave nuova che non è una CA entra.
    let fresh = Identity::generate().unwrap();
    std::fs::write(&key_file, fresh.to_secret_hex().as_str()).unwrap();
    set_mode(&key_file, 0o600);
    relay.hup();
    let ok = relay.wait_for(|v| {
        v["fields"]["event_kind"] == "relay_keys_reloaded"
            || v["fields"]["event_kind"] == "relay_keys_reload_failed"
    });
    assert_eq!(ok["fields"]["event_kind"], "relay_keys_reloaded", "{ok}");
}
