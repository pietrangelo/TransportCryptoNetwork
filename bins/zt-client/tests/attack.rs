//! Test d'attacco su `zt-client`. Regola trasversale: in caso di errore stdout resta vuoto
//! (è il canale SSH) e, quando il problema è locale, non parte nessuna connessione.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

mod common;

use std::time::Duration;

use common::{ClientDir, Counting, Fleet, echo_through, finish, set_mode, spawn_with};
use zt_crypto::Identity;

const LIMIT: Duration = Duration::from_secs(15);

/// Un relay "esca" che conta le connessioni: deve restare a zero.
async fn bait_dir(who: &Identity, nodes: &[(&str, zt_crypto::PublicKey)]) -> (Counting, ClientDir) {
    let bait = Counting::start(false).await;
    let relay_key = Identity::generate().unwrap().public_key();
    let dir = ClientDir::new(who, &bait.addr.to_string(), &relay_key, nodes);
    (bait, dir)
}

fn some_key() -> zt_crypto::PublicKey {
    Identity::generate().unwrap().public_key()
}

#[tokio::test]
async fn unknown_node_is_refused_without_touching_the_network() {
    // Niente trust-on-first-use: senza chiave pinnata non si contatta il relay.
    let me = Identity::generate().unwrap();
    let (bait, dir) = bait_dir(&me, &[("web-01", some_key())]).await;
    let out = finish(dir.spawn("db-01"), LIMIT).await;
    assert!(!out.success);
    assert!(out.stdout.is_empty());
    assert!(out.stderr.contains("db-01"), "stderr: {}", out.stderr);
    assert_eq!(bait.count(), 0);
}

#[tokio::test]
async fn malformed_node_names_are_refused_without_touching_the_network() {
    // %n/%h arrivano da ciò che l'utente (o un inventario Ansible) scrive.
    let me = Identity::generate().unwrap();
    let (bait, dir) = bait_dir(&me, &[("web-01", some_key())]).await;
    let long = "a".repeat(64);
    for name in [
        "Web-01",
        "web-01 ",
        "../web-01",
        "-web",
        "web-",
        "web_01",
        "web.01",
        "",
        long.as_str(),
        "web-01\n",
        "wéb",
    ] {
        let out = finish(dir.spawn(name), LIMIT).await;
        assert!(!out.success, "accepted {name:?}");
        assert!(out.stdout.is_empty(), "{name:?} wrote to stdout");
    }
    assert_eq!(bait.count(), 0);
}

#[tokio::test]
async fn strip_suffix_does_not_widen_the_accepted_names() {
    let me = Identity::generate().unwrap();
    let (bait, dir) = bait_dir(&me, &[("web-01", some_key())]).await;
    let config = dir.config();
    let c = config.to_str().unwrap();
    // Il suffisso si toglie una volta sola e solo se presente per intero.
    for name in ["web-01.tcn.tcn", "web-01tcn", ".tcn", "WEB-01.tcn"] {
        let out = finish(
            spawn_with(
                &["--config", c, "connect", "--strip-suffix", ".tcn", name],
                &[],
            ),
            LIMIT,
        )
        .await;
        assert!(!out.success, "accepted {name:?}");
        assert!(out.stdout.is_empty());
    }
    assert_eq!(bait.count(), 0);
}

#[tokio::test]
async fn trust_file_writable_by_others_is_refused() {
    // Chi può scrivere client.toml può sostituire il pin del nodo e fare MITM.
    let me = Identity::generate().unwrap();
    let (bait, dir) = bait_dir(&me, &[("web-01", some_key())]).await;
    for mode in [0o664, 0o646, 0o666] {
        set_mode(&dir.config(), mode);
        let out = finish(dir.spawn("web-01"), LIMIT).await;
        assert!(!out.success, "accepted mode {mode:o}");
        assert!(out.stdout.is_empty());
    }
    assert_eq!(bait.count(), 0);
}

#[tokio::test]
async fn readable_secret_key_is_refused() {
    let me = Identity::generate().unwrap();
    let (bait, dir) = bait_dir(&me, &[("web-01", some_key())]).await;
    set_mode(&dir.dir.join("client.key"), 0o640);
    let out = finish(dir.spawn("web-01"), LIMIT).await;
    assert!(!out.success);
    assert!(out.stdout.is_empty());
    assert_eq!(bait.count(), 0);
}

#[tokio::test]
async fn missing_or_garbage_config_is_refused() {
    let me = Identity::generate().unwrap();
    let (bait, dir) = bait_dir(&me, &[("web-01", some_key())]).await;
    let out = finish(
        spawn_with(
            &["--config", "/nonexistent/tcn.toml", "connect", "web-01"],
            &[],
        ),
        LIMIT,
    )
    .await;
    assert!(!out.success && out.stdout.is_empty());
    std::fs::write(dir.config(), "relay = [").unwrap();
    let out = finish(dir.spawn("web-01"), LIMIT).await;
    assert!(!out.success && out.stdout.is_empty());
    assert_eq!(bait.count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn impostor_relay_is_detected_and_nothing_reaches_stdout() {
    // Il client parla con il relay vero, ma ha pinnato un'altra chiave (DNS/BGP hijack).
    let fleet = Fleet::start().await;
    let ssh = Counting::start(true).await;
    fleet.start_agent(ssh.addr).await;
    let dir = ClientDir::new(
        &fleet.ansible,
        &fleet.relay.to_string(),
        &some_key(),
        &[("web-01", fleet.agent_id.public_key())],
    );
    let out = finish(dir.spawn("web-01"), LIMIT).await;
    assert!(!out.success);
    assert!(out.stdout.is_empty());
    assert_eq!(ssh.count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn impostor_agent_is_detected_and_sshd_is_never_dialed() {
    // Il relay instrada verso un agent la cui chiave non è quella pinnata dal client
    // (relay compromesso o agent sostituito).
    let fleet = Fleet::start().await;
    let ssh = Counting::start(true).await;
    fleet.start_agent(ssh.addr).await;
    let dir = ClientDir::new(
        &fleet.ansible,
        &fleet.relay.to_string(),
        &fleet.relay_id.public_key(),
        &[("web-01", some_key())],
    );
    let mut child = dir.spawn("web-01");
    let _stdin = child.stdin.take();
    let out = tokio::time::timeout(LIMIT, child.wait_with_output())
        .await
        .expect("hung")
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert_eq!(ssh.count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_denied_by_policy_gets_a_clear_error_and_no_stdout() {
    let fleet = Fleet::start().await;
    let ssh = Counting::start(true).await;
    fleet.start_agent(ssh.addr).await;
    let dir = fleet.client_dir(&fleet.outsider);
    let out = finish(dir.spawn("web-01"), LIMIT).await;
    assert!(!out.success);
    assert!(out.stdout.is_empty());
    assert!(
        out.stderr.to_lowercase().contains("denied"),
        "stderr: {}",
        out.stderr
    );
    assert_eq!(ssh.count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trace_logging_never_reaches_stdout_nor_leaks_the_secret() {
    let fleet = Fleet::start().await;
    let ssh = Counting::start(true).await;
    fleet.start_agent(ssh.addr).await;
    let dir = fleet.client_dir(&fleet.ansible);
    let config = dir.config();
    let mut child = spawn_with(
        &["--config", config.to_str().unwrap(), "connect", "web-01"],
        &[("RUST_LOG", "trace")],
    );
    let data = b"SSH-2.0-OpenSSH_9.9\r\nsecret payload marker 7f3a";
    assert_eq!(echo_through(&mut child, data).await, data);
    let out = finish(child, LIMIT).await;
    assert!(out.success, "stderr: {}", out.stderr);
    assert!(out.stdout.is_empty(), "extra bytes on stdout");
    let secret = fleet.ansible.to_secret_hex();
    assert!(!out.stderr.contains(secret.as_str()), "secret key in logs");
    assert!(!out.stderr.contains("payload marker"), "payload in logs");
}

// ======================= regressioni adversary review 0003 =======================

/// 0003-3: se l'agent non raggiunge sshd il client usciva con 0 e senza messaggi.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_sshd_is_an_error_with_a_message() {
    let fleet = Fleet::start().await;
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    fleet.start_agent(closed).await;
    let dir = fleet.client_dir(&fleet.ansible);
    let mut child = dir.spawn("web-01");
    let _stdin = child.stdin.take();
    let out = tokio::time::timeout(LIMIT, child.wait_with_output())
        .await
        .expect("hung")
        .unwrap();
    assert!(!out.status.success(), "exit 0 although no session was made");
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("web-01") && stderr.contains("unreachable"),
        "stderr: {stderr}"
    );
}

/// 0003-4: ssh esegue `sh -c "exec zt-client ... %n"`. Con un OpenSSH vecchio un nome host
/// con spazi diventa argomenti in più: nessuna opzione dopo il nome del nodo viene letta.
#[tokio::test]
async fn options_after_the_node_name_are_never_parsed() {
    let me = Identity::generate().unwrap();
    let (good_relay, good) = bait_dir(&me, &[("web-01", some_key())]).await;
    let (evil_relay, evil) = bait_dir(&me, &[("web-01", some_key())]).await;
    let g = good.config();
    let e = evil.config();
    for extra in [
        vec!["--config", e.to_str().unwrap()],
        vec!["--strip-suffix", "-01"],
        vec!["db-01"],
    ] {
        let mut args = vec!["--config", g.to_str().unwrap(), "connect", "web-01"];
        args.extend(extra.iter().copied());
        let out = finish(spawn_with(&args, &[]), LIMIT).await;
        assert!(!out.success, "accepted {args:?}");
        assert!(out.stdout.is_empty());
    }
    assert_eq!(good_relay.count(), 0);
    assert_eq!(evil_relay.count(), 0);
}
