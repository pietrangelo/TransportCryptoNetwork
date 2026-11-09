//! Attack tests on `zt-client`. Cross-cutting rule: on error stdout stays empty (it is the
//! SSH channel) and, when the problem is local, no connection is started.
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

/// A "bait" relay that counts connections: it must stay at zero.
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
    // No trust-on-first-use: without a pinned key the relay is not contacted.
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
    // %n/%h come from what the user (or an Ansible inventory) writes.
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
    // The suffix is stripped only once and only if present in full.
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
    // Whoever can write client.toml can replace the node's pin and perform a MITM.
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
    // The client talks to the real relay, but has pinned another key (DNS/BGP hijack).
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
    // The relay routes toward an agent whose key is not the one pinned by the client
    // (compromised relay or replaced agent).
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

// ======================= regressions from adversary review 0003 =======================

/// 0003-3: if the agent could not reach sshd the client exited with 0 and no messages.
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

/// 0003-4: ssh runs `sh -c "exec zt-client ... %n"`. With an old OpenSSH a host name with
/// spaces becomes extra arguments: no option after the node name is read.
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

// ---------- Phase 6, step 9: certificates (PROTOCOL §15.6, OPERATIONS §10.4) ----------

/// Common positive control: the same test bench, with a valid certificate, contacts the relay.
async fn a_valid_certificate_reaches_the_relay() {
    let me = Identity::generate().unwrap();
    let (bait, dir) = bait_dir(&me, &[("web-01", some_key())]).await;
    let now = common::now_secs();
    let (cert, _, _) = common::issue(&me.public_key(), &["web-01"], now - 60, now + 3_600);
    dir.add_certificate(&cert, 0o644);
    assert!(
        common::reaches(&bait, dir.spawn("web-01"), Duration::from_secs(10)).await,
        "a valid certificate never reached the relay"
    );
}

#[tokio::test]
async fn an_expired_certificate_fails_before_any_connection() {
    a_valid_certificate_reaches_the_relay().await;
    let me = Identity::generate().unwrap();
    let (bait, dir) = bait_dir(&me, &[("web-01", some_key())]).await;
    let now = common::now_secs();
    let (cert, _, _) = common::issue(&me.public_key(), &["web-01"], now - 3_600, now - 10);
    dir.add_certificate(&cert, 0o644);
    let out = finish(dir.spawn("web-01"), LIMIT).await;
    assert!(!out.success);
    assert!(out.stdout.is_empty());
    assert!(
        out.stderr.to_lowercase().contains("expired"),
        "{}",
        out.stderr
    );
    assert_eq!(bait.count(), 0);
}

#[tokio::test]
async fn a_certificate_for_another_key_fails_before_any_connection() {
    a_valid_certificate_reaches_the_relay().await;
    let me = Identity::generate().unwrap();
    let (bait, dir) = bait_dir(&me, &[("web-01", some_key())]).await;
    let now = common::now_secs();
    let (cert, _, _) = common::issue(&some_key(), &["web-01"], now - 60, now + 3_600);
    dir.add_certificate(&cert, 0o644);
    let out = finish(dir.spawn("web-01"), LIMIT).await;
    assert!(!out.success);
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
    assert_eq!(bait.count(), 0);
}

#[tokio::test]
async fn an_insecure_certificate_file_is_refused() {
    a_valid_certificate_reaches_the_relay().await;
    for mode in [0o666, 0o646, 0o664] {
        let me = Identity::generate().unwrap();
        let (bait, dir) = bait_dir(&me, &[("web-01", some_key())]).await;
        let now = common::now_secs();
        let (cert, _, _) = common::issue(&me.public_key(), &["web-01"], now - 60, now + 3_600);
        dir.add_certificate(&cert, mode);
        let out = finish(dir.spawn("web-01"), LIMIT).await;
        assert!(!out.success, "mode {mode:o} accepted");
        assert!(out.stdout.is_empty());
        assert!(out.stderr.contains("client.cert"), "{}", out.stderr);
        assert_eq!(bait.count(), 0, "mode {mode:o}");
    }
}
