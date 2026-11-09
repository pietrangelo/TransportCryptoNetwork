//! Specification of the `zt-client` stdio bridge (OpenSSH `ProxyCommand` mode).
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
    // OpenSSH closes stdin at the end of the session: the bridge exits successfully.
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
    let _stdin = child.stdin.take(); // stays open, as ssh does
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

    // 1. environment variable
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

/// Phase 5 (PROTOCOL §13): with multiple relays in `client.toml`, if the first one is down
/// `ssh` goes through the next one without the user noticing.
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

/// A relay that accepts TCP and never answers (overloaded, or a proxy that swallows the
/// connection). The accepted sockets are kept open for as long as the task runs.
async fn silent_relay() -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s);
        }
    });
    addr
}

/// Prepends `line` to `client.toml` (top-level keys must precede the tables).
fn prepend(dir: &common::ClientDir, line: &str) {
    let path = dir.config();
    let toml = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{line}\n{toml}")).unwrap();
}

/// R-4 (A5-4): a relay that never completes the handshake is hedged after the stagger (2 s
/// plus jitter): the session goes through the next relay in about 2 s, not after the 10 s of
/// the handshake timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_first_relay_is_hedged_after_the_stagger() {
    let fleet = Fleet::start().await;
    let ssh = Counting::start(true).await;
    fleet.start_agent(ssh.addr).await;
    let silent = silent_relay().await;
    let other = zt_crypto::Identity::generate().unwrap().public_key();
    let dir = common::ClientDir::with_relays(
        &fleet.ansible,
        &[
            (silent.to_string(), other),
            (fleet.relay.to_string(), fleet.relay_id.public_key()),
        ],
        &[("web-01", fleet.agent_id.public_key())],
    );
    let started = std::time::Instant::now();
    let mut child = dir.spawn("web-01");
    assert_eq!(echo_through(&mut child, b"hedged").await, b"hedged");
    let at = started.elapsed();
    assert!(
        at >= Duration::from_secs(2) && at < Duration::from_secs(5),
        "{at:?}"
    );
    let out = finish(child, Duration::from_secs(10)).await;
    assert!(out.success, "stderr: {}", out.stderr);
}

/// R-4: when no relay completes the connection within `connect_deadline_secs`, `zt-client`
/// exits with 75 (EX_TEMPFAIL: try again later) and says so on stderr; stdout (the SSH channel)
/// stays empty. OpenSSH then exits with 255, which Ansible retries (`retries`, OPERATIONS §5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_deadline_exits_with_tempfail_and_a_clear_message() {
    let silent = silent_relay().await;
    let me = zt_crypto::Identity::generate().unwrap();
    let dir = common::ClientDir::new(
        &me,
        &silent.to_string(),
        &zt_crypto::Identity::generate().unwrap().public_key(),
        &[(
            "web-01",
            zt_crypto::Identity::generate().unwrap().public_key(),
        )],
    );
    prepend(&dir, "connect_deadline_secs = 1");
    let started = std::time::Instant::now();
    let child = dir.spawn("web-01");
    let out = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .expect("zt-client did not give up")
        .unwrap();
    let at = started.elapsed();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(75), "stderr: {stderr}");
    assert!(out.stdout.is_empty());
    assert!(at < Duration::from_secs(3), "{at:?}");
    assert!(
        stderr.contains("zt-client: no relay completed the connection within 1 s")
            && stderr.contains("connect_deadline_secs"),
        "{stderr}"
    );
}

// ---------- Phase 6, step 9: certificates (OPERATIONS §10.4, PROTOCOL §15.6) ----------

/// Spec: `zt-client certificate` prints name, nodes, CA, serial and validity of the
/// configured certificate, without touching the network.
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
        // The node has its own key: a relay key cannot also be that of a node.
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

/// Spec: a certificate that expires within 15 minutes, or is not yet valid, causes a warning
/// on stderr; stdout (the SSH channel) stays empty. A certificate far from expiry does not.
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
        // The problem is the network (closed port), not the certificate: the warning is not
        // an error.
        assert!(!stderr.contains("not supported"), "{what}: {stderr}");
    }
}

/// Finding 0006-6: a certificate whose `subject_key` is the client's **secret** (`--subject`
/// of `zt-ca` with the content of the key file) is rejected by `zt-client certificate` and
/// before any connection, with a message that says to regenerate the key and does not
/// report the secret.
#[tokio::test]
async fn a_certificate_carrying_the_client_secret_is_refused() {
    use common::{ClientDir, issue, now_secs};
    // A client whose seed (32 bytes) is also a valid public key, as zt-ca requires.
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
    // Positive control: the same client with a certificate for its public key.
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
