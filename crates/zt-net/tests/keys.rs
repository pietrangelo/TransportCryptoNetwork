//! Finding 0005-3: le chiavi accettate sono visibili nei log, e una chiave precedente rimasta
//! attiva viene ricordata finché non la si toglie.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
