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
