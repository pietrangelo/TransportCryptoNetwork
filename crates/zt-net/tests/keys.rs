//! Finding 0005-3: le chiavi accettate sono visibili nei log, e una chiave precedente rimasta
//! attiva viene ricordata finché non la si toglie.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zt_crypto::{Identity, Keyring};
use zt_net::Revocable;
use zt_net::keys::watch;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn kinds(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter_map(|l| serde_json_lite(l, "event_kind"))
            .collect()
    }
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// Estrae `"key":"value"` da una riga JSON senza dipendere da `serde_json`.
fn serde_json_lite(line: &str, key: &str) -> Option<String> {
    let (_, rest) = line.split_once(&format!("\"{key}\":\""))?;
    let (value, _) = rest.split_once('"')?;
    Some(value.to_owned())
}

fn id() -> Identity {
    Identity::generate().unwrap()
}

#[tokio::test(start_paused = true)]
async fn a_previous_key_is_announced_and_reminded_until_it_is_removed() {
    let log = Captured::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (current, previous) = (id(), id());
    let (cur_fp, prev_fp) = (current.fingerprint(), previous.fingerprint());
    let (keys, updater) = Revocable::new(Keyring::rotating(current, previous).unwrap());
    let task = tokio::spawn(watch("relay", keys, Duration::from_secs(60)));

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(log.kinds(), ["keys_in_use"]);
    assert!(log.text().contains(&cur_fp.to_string()));
    assert!(log.text().contains(&prev_fp.to_string()));

    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(
        log.kinds(),
        [
            "keys_in_use",
            "previous_key_still_accepted",
            "previous_key_still_accepted"
        ]
    );

    // Rotazione completata: la precedente sparisce, e con lei i promemoria.
    let only = id();
    let only_fp = only.fingerprint();
    updater.replace(Keyring::single(only));
    tokio::time::sleep(Duration::from_secs(600)).await;
    let kinds = log.kinds();
    assert_eq!(kinds.len(), 4, "{kinds:?}");
    assert_eq!(kinds.last().map(String::as_str), Some("keys_in_use"));
    assert!(log.text().contains(&only_fp.to_string()));
    task.abort();
}

#[tokio::test(start_paused = true)]
async fn a_single_key_is_announced_once_and_never_reminded() {
    let log = Captured::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let task = tokio::spawn(watch(
        "agent",
        Revocable::fixed(Keyring::single(id())),
        Duration::from_secs(60),
    ));
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(log.kinds(), ["keys_in_use"]);
    assert!(log.text().contains("\"previous_fingerprint\":\"none\""));
    task.abort();
}

/// Finding 0005b-2: un nodo con due chiavi di agent nella policy del relay (rotazione non
/// completata) è segnalato al caricamento, a ogni ricarica e ogni `every` finché resta.
#[tokio::test(start_paused = true)]
async fn an_agent_rotation_left_in_the_policy_is_reported_until_it_is_completed() {
    use zt_domain::{AccessPolicy, NodeId};
    use zt_net::keys::watch_agent_rotations;
    let log = Captured::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let node = |n: &str| NodeId::try_from(n).unwrap();
    let (new, old, db) = (id(), id(), id());
    let policy = |rotating: bool| {
        let mut p = AccessPolicy::new();
        let keys: Vec<_> = if rotating {
            vec![new.fingerprint(), old.fingerprint()]
        } else {
            vec![new.fingerprint()]
        };
        p.add_agent_keys(node("web-01"), &keys).unwrap();
        p.add_agent(db.fingerprint(), node("db-01")).unwrap();
        p
    };
    let (current, updater) = Revocable::new(policy(true));
    let task = tokio::spawn(watch_agent_rotations(current, Duration::from_secs(60)));

    // Al caricamento: solo il nodo con due chiavi, con entrambe le fingerprint.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(log.kinds(), ["agent_rotation_pending"]);
    let text = log.text();
    assert!(text.contains("\"node\":\"web-01\""), "{text}");
    assert!(!text.contains("db-01"), "{text}");
    assert!(text.contains(&new.fingerprint().to_string()), "{text}");
    assert!(text.contains(&old.fingerprint().to_string()), "{text}");
    assert!(text.contains("\"level\":\"WARN\""), "{text}");

    // Promemoria periodico.
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(log.kinds().len(), 3);

    // Ricarica ancora in rotazione: subito un altro avviso.
    updater.replace(policy(true));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(log.kinds().len(), 4);

    // Rotazione completata: niente più avvisi.
    updater.replace(policy(false));
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(log.kinds().len(), 4, "{:?}", log.kinds());
    task.abort();
}

// ---------- Fase 6, passo 8: CA pinnate e denylist (PROTOCOL §15.9, §15.11) ----------

use zt_domain::limits::DEFAULT_AUTHORITY_LIFETIME_SECS;
use zt_domain::trust::{CertTrust, Revocations, TrustedCaKey};
use zt_domain::{AllowedNodes, CertSerial, NodeId};
use zt_net::keys::{announce_authorities, watch_authorities};

fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

fn ca_key() -> TrustedCaKey {
    zt_crypto::trusted_ca_key(&id().public_key())
}

fn capture() -> (Captured, tracing::subscriber::DefaultGuard) {
    let log = Captured::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .finish();
    (log, tracing::subscriber::set_default(subscriber))
}

fn lines_of<'a>(text: &'a str, kind: &str) -> Vec<&'a str> {
    text.lines()
        .filter(|l| serde_json_lite(l, "event_kind").as_deref() == Some(kind))
        .collect()
}

/// `ops-ca` con `keys`, `lab-ca` con una chiave, e una denylist di 2 serie e 1 chiave.
fn trust(ops: &[TrustedCaKey], lab: &TrustedCaKey) -> CertTrust {
    let mut t = CertTrust::new();
    t.add_authority(
        node("ops-ca"),
        ops,
        AllowedNodes::All,
        DEFAULT_AUTHORITY_LIFETIME_SECS,
    )
    .unwrap();
    t.add_authority(
        node("lab-ca"),
        std::slice::from_ref(lab),
        AllowedNodes::Only([node("lab-01")].into_iter().collect()),
        3_600,
    )
    .unwrap();
    t.set_revocations(
        Revocations::new(
            [
                CertSerial::try_from([0x3f; 16]).unwrap(),
                CertSerial::try_from([0x40; 16]).unwrap(),
            ],
            [id().fingerprint()],
        )
        .unwrap(),
    );
    t
}

#[test]
fn authorities_and_revocations_are_announced() {
    let (log, _guard) = capture();
    let (ops, lab) = (ca_key(), ca_key());
    announce_authorities("relay", &trust(std::slice::from_ref(&ops), &lab));
    let text = log.text();

    let authorities = lines_of(&text, "authorities_in_use");
    assert_eq!(authorities.len(), 2, "{text}");
    let ops_line = authorities
        .iter()
        .find(|l| serde_json_lite(l, "authority").as_deref() == Some("ops-ca"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(
        ops_line.contains(&ops.fingerprint.to_string()),
        "{ops_line}"
    );
    assert!(ops_line.contains("\"max_lifetime\":28800"), "{ops_line}");
    assert!(ops_line.contains("\"level\":\"INFO\""), "{ops_line}");
    let lab_line = authorities
        .iter()
        .find(|l| serde_json_lite(l, "authority").as_deref() == Some("lab-ca"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(
        lab_line.contains(&lab.fingerprint.to_string()),
        "{lab_line}"
    );
    assert!(lab_line.contains("\"max_lifetime\":3600"), "{lab_line}");

    let revocations = lines_of(&text, "revocations_in_use");
    assert_eq!(revocations.len(), 1, "{text}");
    assert!(
        revocations[0].contains("\"serials\":2"),
        "{}",
        revocations[0]
    );
    assert!(revocations[0].contains("\"keys\":1"), "{}", revocations[0]);
    assert!(lines_of(&text, "ca_rotation_pending").is_empty(), "{text}");

    // Una CA con due chiavi è annunciata come WARN, con entrambe le fingerprint.
    let (log, _guard2) = capture();
    let (new, old) = (ca_key(), ca_key());
    announce_authorities("agent", &trust(&[new, old], &lab));
    let text = log.text();
    let rotating = lines_of(&text, "authorities_in_use")
        .into_iter()
        .find(|l| serde_json_lite(l, "authority").as_deref() == Some("ops-ca"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(rotating.contains("\"level\":\"WARN\""), "{rotating}");
    assert!(
        rotating.contains(&new.fingerprint.to_string()),
        "{rotating}"
    );
    assert!(
        rotating.contains(&old.fingerprint.to_string()),
        "{rotating}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_ca_rotation_is_reported_until_it_is_completed() {
    let (log, _guard) = capture();
    let (new, old, lab) = (ca_key(), ca_key(), ca_key());
    let (current, updater) = Revocable::new(trust(&[new, old], &lab));
    let task = tokio::spawn(watch_authorities(
        "relay",
        current,
        Duration::from_secs(3_600),
    ));
    let pending = |log: &Captured| lines_of(&log.text(), "ca_rotation_pending").len();

    // All'avvio: annunci e un avviso per la sola CA in rotazione.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let text = log.text();
    assert_eq!(lines_of(&text, "authorities_in_use").len(), 2, "{text}");
    assert_eq!(lines_of(&text, "revocations_in_use").len(), 1, "{text}");
    let warn = lines_of(&text, "ca_rotation_pending");
    assert_eq!(warn.len(), 1, "{text}");
    assert!(warn[0].contains("ops-ca"), "{}", warn[0]);
    assert!(!warn[0].contains("lab-ca"), "{}", warn[0]);
    assert!(warn[0].contains(&new.fingerprint.to_string()));
    assert!(warn[0].contains(&old.fingerprint.to_string()));
    assert!(warn[0].contains("\"level\":\"WARN\""));

    // Ogni ora.
    tokio::time::sleep(Duration::from_secs(2 * 3_600)).await;
    assert_eq!(pending(&log), 3, "{}", log.text());

    // Ricarica ancora in rotazione: annunci e avviso subito.
    updater.replace(trust(&[new, old], &lab));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(pending(&log), 4, "{}", log.text());
    assert_eq!(lines_of(&log.text(), "authorities_in_use").len(), 4);
    assert_eq!(lines_of(&log.text(), "revocations_in_use").len(), 2);

    // Rotazione completata: annunci nuovi, niente più avvisi.
    updater.replace(trust(&[new], &lab));
    tokio::time::sleep(Duration::from_secs(10 * 3_600)).await;
    assert_eq!(pending(&log), 4, "{}", log.text());
    assert_eq!(lines_of(&log.text(), "authorities_in_use").len(), 6);
    task.abort();
}

#[test]
fn announcements_never_contain_certificate_bytes_or_secrets() {
    let (log, _guard) = capture();
    let ca = zt_crypto::CaSigningKey::generate().unwrap();
    let trusted = zt_crypto::trusted_ca_key(&ca.public_key());
    let revoked_key = id().fingerprint();
    let serial = CertSerial::try_from([0x77; 16]).unwrap();
    let mut t = CertTrust::new();
    t.add_authority(
        node("ops-ca"),
        &[trusted, ca_key()],
        AllowedNodes::All,
        DEFAULT_AUTHORITY_LIFETIME_SECS,
    )
    .unwrap();
    t.set_revocations(Revocations::new([serial], [revoked_key]).unwrap());
    announce_authorities("relay", &t);
    let text = log.text();
    // Controllo positivo: gli annunci ci sono, con la fingerprint della CA.
    assert!(text.contains(&trusted.fingerprint.to_string()), "{text}");
    assert_eq!(lines_of(&text, "revocations_in_use").len(), 1, "{text}");
    // Solo fingerprint e conteggi.
    let secret = ca.to_secret_text();
    assert!(!secret.is_empty());
    assert!(!text.contains(secret.trim()), "{text}");
    assert!(
        !text.contains(zt_crypto::CaSigningKey::FILE_PREFIX),
        "{text}"
    );
    assert!(!text.contains(&ca.public_key().to_string()), "{text}");
    assert!(!text.contains(&serial.to_string()), "{text}");
    assert!(!text.contains(&revoked_key.to_string()), "{text}");
    assert!(!text.contains(zt_crypto::CERT_FILE_PREFIX), "{text}");
}
