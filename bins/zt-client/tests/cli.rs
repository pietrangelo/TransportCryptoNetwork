//! Specifica del bridge stdio di `zt-client` (modalità `ProxyCommand` di OpenSSH).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]

mod common;

use std::time::Duration;

use common::{Counting, Fleet, banner_then_close, echo_through, finish, spawn_with};
use tokio::io::AsyncReadExt;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridges_stdin_and_stdout_to_the_node() {
    let fleet = Fleet::start().await;
    let ssh = Counting::start(true).await;
    fleet.start_agent(ssh.addr).await;
    let dir = fleet.client_dir(&fleet.ansible);

    let mut child = dir.spawn("web-01");
    let data = pattern(1024 * 1024 + 17);
    assert_eq!(echo_through(&mut child, &data).await, data);
    // OpenSSH chiude stdin a fine sessione: il bridge termina con successo.
    let out = finish(child, Duration::from_secs(10)).await;
    assert!(out.success, "stderr: {}", out.stderr);
    assert!(out.stdout.is_empty());
    assert_eq!(ssh.count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exits_when_the_node_closes_even_if_stdin_stays_open() {
    let fleet = Fleet::start().await;
    fleet.start_agent(banner_then_close().await).await;
    let dir = fleet.client_dir(&fleet.ansible);

    let mut child = dir.spawn("web-01");
    let _stdin = child.stdin.take(); // resta aperto, come fa ssh
    let mut stdout = child.stdout.take().unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stdout.read_to_end(&mut got))
        .await
        .expect("stdout not closed after the node closed")
        .unwrap();
    assert_eq!(got, b"SSH-2.0-bye\r\n");
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("zt-client still running after the node closed")
        .unwrap();
    assert!(status.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_path_comes_from_flag_env_or_xdg_default() {
    let fleet = Fleet::start().await;
    let ssh = Counting::start(true).await;
    fleet.start_agent(ssh.addr).await;
    let dir = fleet.client_dir(&fleet.ansible);
    let config = dir.config();

    // 1. variabile d'ambiente
    let mut child = spawn_with(
        &["connect", "web-01"],
        &[("TCN_CLIENT_CONFIG", config.to_str().unwrap())],
    );
    assert_eq!(echo_through(&mut child, b"env").await, b"env");
    assert!(finish(child, Duration::from_secs(10)).await.success);

    // 2. $XDG_CONFIG_HOME/tcn/client.toml
    let xdg = dir.dir.join("xdg");
    std::fs::create_dir_all(xdg.join("tcn")).unwrap();
    std::fs::copy(&config, xdg.join("tcn/client.toml")).unwrap();
    std::fs::copy(dir.dir.join("client.key"), xdg.join("tcn/client.key")).unwrap();
    let mut child = spawn_with(
        &["connect", "web-01"],
        &[("XDG_CONFIG_HOME", xdg.to_str().unwrap())],
    );
    assert_eq!(echo_through(&mut child, b"xdg").await, b"xdg");
    assert!(finish(child, Duration::from_secs(10)).await.success);

    assert_eq!(ssh.count(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strip_suffix_maps_ssh_host_names_to_nodes() {
    // `Host *.tcn` + `ProxyCommand zt-client connect --strip-suffix .tcn %h`
    let fleet = Fleet::start().await;
    let ssh = Counting::start(true).await;
    fleet.start_agent(ssh.addr).await;
    let dir = fleet.client_dir(&fleet.ansible);
    let config = dir.config();
    let mut child = spawn_with(
        &[
            "--config",
            config.to_str().unwrap(),
            "connect",
            "--strip-suffix",
            ".tcn",
            "web-01.tcn",
        ],
        &[],
    );
    assert_eq!(echo_through(&mut child, b"sfx").await, b"sfx");
    assert!(finish(child, Duration::from_secs(10)).await.success);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_sessions_are_independent() {
    let fleet = Fleet::start().await;
    let ssh = Counting::start(true).await;
    fleet.start_agent(ssh.addr).await;
    let dir = fleet.client_dir(&fleet.ansible);
    let mut tasks = Vec::new();
    for i in 0..8_usize {
        let mut child = dir.spawn("web-01");
        tasks.push(tokio::spawn(async move {
            let data = pattern(64 * 1024 + i);
            assert_eq!(echo_through(&mut child, &data).await, data);
            finish(child, Duration::from_secs(10)).await.success
        }));
    }
    for t in tasks {
        assert!(t.await.unwrap());
    }
    assert_eq!(ssh.count(), 8);
}

/// Fase 5 (PROTOCOL §13): con più relay in `client.toml`, se il primo è giù `ssh` passa dal
/// successivo senza che l'utente se ne accorga.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn falls_back_to_the_next_relay_when_the_first_is_down() {
    let fleet = Fleet::start().await;
    let ssh = Counting::start(true).await;
    fleet.start_agent(ssh.addr).await;
    let dead = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let other = zt_crypto::Identity::generate().unwrap().public_key();
    let dir = common::ClientDir::with_relays(
        &fleet.ansible,
        &[
            (dead.to_string(), other),
            (fleet.relay.to_string(), fleet.relay_id.public_key()),
        ],
        &[("web-01", fleet.agent_id.public_key())],
    );
    let mut child = dir.spawn("web-01");
    let data = pattern(4096);
    assert_eq!(echo_through(&mut child, &data).await, data);
    let out = finish(child, Duration::from_secs(10)).await;
    assert!(out.success, "stderr: {}", out.stderr);
}

// ---------- Fase 6, passo 9: certificati (OPERATIONS §10.4, PROTOCOL §15.6) ----------

/// Spec: `zt-client certificate` stampa nome, nodi, CA, serie e validità del certificato
/// configurato, senza toccare la rete.
#[tokio::test]
async fn certificate_subcommand_prints_status() {
    use common::{ClientDir, issue, now_secs, utc_date};
    let me = zt_crypto::Identity::generate().unwrap();
    let bait = Counting::start(false).await;
    let relay_key = zt_crypto::Identity::generate().unwrap().public_key();
    let dir = ClientDir::new(
        &me,
        &bait.addr.to_string(),
        &relay_key,
        // Il nodo ha una chiave sua: una chiave di relay non può essere anche quella di un nodo.
        &[(
            "web-01",
            zt_crypto::Identity::generate().unwrap().public_key(),
        )],
    );
    let now = now_secs();
    let not_after = now + 3_600;
    let (cert, ca, serial) = issue(&me.public_key(), &["web-01", "db-01"], now - 60, not_after);
    dir.add_certificate(&cert, 0o644);
    let out = finish(
        spawn_with(
            &["--config", dir.config().to_str().unwrap(), "certificate"],
            &[],
        ),
        Duration::from_secs(10),
    )
    .await;
    assert!(out.success, "stderr: {}", out.stderr);
    let text = String::from_utf8(out.stdout).unwrap();
    for needle in [
        "alice".to_owned(),
        "web-01".to_owned(),
        "db-01".to_owned(),
        ca.fingerprint().to_string(),
        serial.to_string(),
        utc_date(not_after),
    ] {
        assert!(text.contains(&needle), "missing {needle}: {text}");
    }
    assert_eq!(bait.count(), 0);
}

/// Spec: un certificato che scade entro 15 minuti, o non ancora valido, provoca un avviso su
/// stderr; stdout (il canale SSH) resta vuoto. Un certificato lontano dalla scadenza no.
#[tokio::test]
async fn a_certificate_expiring_soon_warns_on_stderr_only() {
    use common::{ClientDir, closed_port, issue, now_secs};
    let now = now_secs();
    let relay = closed_port().await;
    for (what, nb, na, warns) in [
        ("expiring soon", now - 3_000, now + 600, "expire"),
        ("not yet valid", now + 60, now + 3_600, "not yet valid"),
        ("fine", now - 60, now + 3_600, ""),
    ] {
        let me = zt_crypto::Identity::generate().unwrap();
        let relay_key = zt_crypto::Identity::generate().unwrap().public_key();
        let dir = ClientDir::new(
            &me,
            &relay.to_string(),
            &relay_key,
            &[(
                "web-01",
                zt_crypto::Identity::generate().unwrap().public_key(),
            )],
        );
        let (cert, _, _) = issue(&me.public_key(), &["web-01"], nb, na);
        dir.add_certificate(&cert, 0o644);
        let out = finish(dir.spawn("web-01"), Duration::from_secs(15)).await;
        assert!(out.stdout.is_empty(), "{what}: stdout must stay empty");
        let stderr = out.stderr.to_lowercase();
        if warns.is_empty() {
            assert!(!stderr.contains("expire"), "{what}: {stderr}");
            assert!(!stderr.contains("not yet valid"), "{what}: {stderr}");
        } else {
            assert!(stderr.contains(warns), "{what}: {stderr}");
        }
        // Il problema è la rete (porta chiusa), non il certificato: l'avviso non è un errore.
        assert!(!stderr.contains("not supported"), "{what}: {stderr}");
    }
}

/// Finding 0006-6: un certificato il cui `subject_key` è il **segreto** del client (`--subject`
/// di `zt-ca` con il contenuto del file della chiave) è rifiutato da `zt-client certificate` e
/// prima di qualsiasi connessione, con un messaggio che dice di rigenerare la chiave e non
/// riporta il segreto.
#[tokio::test]
async fn a_certificate_carrying_the_client_secret_is_refused() {
    use common::{ClientDir, issue, now_secs};
    // Un client il cui seme (32 byte) è anche una chiave pubblica valida, come serve a zt-ca.
    let (me, leaked) = loop {
        let id = zt_crypto::Identity::generate().unwrap();
        let secret = id.to_secret_hex();
        if let Ok(pk) = secret.parse::<zt_crypto::PublicKey>() {
            break (id, pk);
        }
    };
    let secret = me.to_secret_hex().to_string();
    let bait = Counting::start(false).await;
    let relay_key = zt_crypto::Identity::generate().unwrap().public_key();
    let dir = ClientDir::new(
        &me,
        &bait.addr.to_string(),
        &relay_key,
        &[(
            "web-01",
            zt_crypto::Identity::generate().unwrap().public_key(),
        )],
    );
    let now = now_secs();
    let (cert, _, _) = issue(&leaked, &["web-01"], now - 60, now + 3_600);
    dir.add_certificate(&cert, 0o644);
    let config = dir.config();
    for child in [
        spawn_with(&["--config", config.to_str().unwrap(), "certificate"], &[]),
        dir.spawn("web-01"),
    ] {
        let out = finish(child, Duration::from_secs(10)).await;
        assert!(!out.success, "stderr: {}", out.stderr);
        assert!(out.stdout.is_empty());
        assert!(
            out.stderr
                .contains("secret key leaked into a certificate: regenerate the client key"),
            "{}",
            out.stderr
        );
        assert!(!out.stderr.contains(&secret), "the secret was echoed");
    }
    assert_eq!(bait.count(), 0, "a connection was attempted");
    // Controllo positivo: lo stesso client con un certificato per la sua chiave pubblica.
    let (cert, _, _) = issue(&me.public_key(), &["web-01"], now - 60, now + 3_600);
    std::fs::write(
        dir.config().with_file_name("client.cert"),
        zt_crypto::encode_certificate_text(&cert),
    )
    .unwrap();
    let out = finish(
        spawn_with(&["--config", config.to_str().unwrap(), "certificate"], &[]),
        Duration::from_secs(10),
    )
    .await;
    assert!(out.success, "stderr: {}", out.stderr);
}
