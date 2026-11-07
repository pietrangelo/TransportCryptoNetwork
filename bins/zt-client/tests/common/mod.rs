//! Banco di prova condiviso: relay e agent nello stesso processo del test, `zt-client` come
//! processo figlio (come lo lancia OpenSSH).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects
)]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use zt_crypto::{Identity, PublicKey};
use zt_domain::{AccessPolicy, AllowedNodes, ClientGrant, NodeId};
use zt_net::Timeouts;
use zt_net::agent::{self, AgentConfig};
use zt_net::relay::{RelayConfig, RelayServer};

pub const BIN: &str = env!("CARGO_BIN_EXE_zt-client");

pub fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

pub fn fast_timeouts() -> Timeouts {
    Timeouts {
        handshake: Duration::from_secs(2),
        idle: Duration::from_secs(10),
        write: Duration::from_secs(5),
        open: Duration::from_secs(3),
        ssh_connect: Duration::from_secs(2),
        keepalive: Duration::from_secs(3),
    }
}

/// Listener TCP che conta le connessioni ricevute. Con `echo` rimanda indietro i byte.
pub struct Counting {
    pub addr: SocketAddr,
    pub accepted: Arc<AtomicUsize>,
}

impl Counting {
    pub async fn start(echo: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    return;
                };
                count.fetch_add(1, Ordering::SeqCst);
                if echo {
                    tokio::spawn(async move {
                        let (mut r, mut w) = tcp.split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
            }
        });
        Self { addr, accepted }
    }

    pub fn count(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// Finto sshd che invia un banner e chiude subito.
pub async fn banner_then_close() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = tcp.write_all(b"SSH-2.0-bye\r\n").await;
                let _ = tcp.shutdown().await;
            });
        }
    });
    addr
}

pub struct Fleet {
    pub relay: SocketAddr,
    pub relay_id: Arc<Identity>,
    pub agent_id: Arc<Identity>,
    pub ansible: Identity,
    pub outsider: Identity,
}

impl Fleet {
    /// Relay con policy: agent `web-01`; client `ansible` ammesso a `web-01`; `outsider`
    /// presente in policy ma senza nodi.
    pub async fn start() -> Self {
        let relay_id = Arc::new(Identity::generate().unwrap());
        let agent_id = Arc::new(Identity::generate().unwrap());
        let ansible = Identity::generate().unwrap();
        let outsider = Identity::generate().unwrap();
        let mut policy = AccessPolicy::new();
        policy
            .add_agent(agent_id.fingerprint(), node("web-01"))
            .unwrap();
        policy
            .add_client(
                ansible.fingerprint(),
                ClientGrant {
                    name: node("ansible"),
                    allowed: AllowedNodes::Only([node("web-01")].into_iter().collect()),
                },
            )
            .unwrap();
        policy
            .add_client(
                outsider.fingerprint(),
                ClientGrant {
                    name: node("outsider"),
                    allowed: AllowedNodes::Only(std::collections::BTreeSet::new()),
                },
            )
            .unwrap();
        let server = RelayServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_hex(&relay_id.to_secret_hex()).unwrap(),
            policy,
            RelayConfig {
                timeouts: fast_timeouts(),
                ..RelayConfig::default()
            },
        )
        .await
        .unwrap();
        let relay = server.local_addr().unwrap();
        tokio::spawn(server.run());
        Self {
            relay,
            relay_id,
            agent_id,
            ansible,
            outsider,
        }
    }

    /// Avvia l'agent di `web-01` verso `ssh` e attende che sia registrato.
    pub async fn start_agent(&self, ssh: SocketAddr) {
        let config = AgentConfig {
            relay: self.relay.to_string(),
            relay_key: self.relay_id.public_key(),
            node: node("web-01"),
            ssh_target: ssh.to_string(),
            authorized_clients: Arc::new(HashSet::from([self.ansible.fingerprint()])),
            timeouts: fast_timeouts(),
            max_streams: 16,
        };
        tokio::spawn(agent::run(Arc::clone(&self.agent_id), config));
        // La registrazione è asincrona: lascia il tempo all'agent di completarla.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    /// Directory di configurazione per il client `who`, con i pin corretti.
    pub fn client_dir(&self, who: &Identity) -> ClientDir {
        ClientDir::new(
            who,
            &self.relay.to_string(),
            &self.relay_id.public_key(),
            &[("web-01", self.agent_id.public_key())],
        )
    }
}

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Directory temporanea con `client.key` (0600) e `client.toml`.
pub struct ClientDir {
    pub dir: PathBuf,
}

impl ClientDir {
    pub fn new(
        who: &Identity,
        relay: &str,
        relay_key: &PublicKey,
        nodes: &[(&str, PublicKey)],
    ) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "zt-client-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("client.key");
        std::fs::write(&key, format!("{}\n", who.to_secret_hex().as_str())).unwrap();
        set_mode(&key, 0o600);
        let mut toml =
            format!("relay = \"{relay}\"\nrelay_key = \"{relay_key}\"\nkey = \"client.key\"\n");
        for (name, k) in nodes {
            toml.push_str(&format!(
                "\n[[nodes]]\nnode = \"{name}\"\npublic_key = \"{k}\"\n"
            ));
        }
        std::fs::write(dir.join("client.toml"), toml).unwrap();
        set_mode(&dir.join("client.toml"), 0o644);
        Self { dir }
    }

    pub fn config(&self) -> PathBuf {
        self.dir.join("client.toml")
    }

    /// `zt-client --config <dir>/client.toml connect <node>` con stdio in pipe.
    pub fn spawn(&self, target: &str) -> Child {
        spawn_with(
            &[
                "--config",
                self.config().to_str().unwrap(),
                "connect",
                target,
            ],
            &[],
        )
    }
}

impl Drop for ClientDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub fn spawn_with(args: &[&str], env: &[(&str, &str)]) -> Child {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .env_remove("TCN_CLIENT_CONFIG")
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.spawn().unwrap()
}

/// Esito di un processo terminato.
pub struct Outcome {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// Chiude stdin e attende la fine del processo (al massimo `limit`).
pub async fn finish(mut child: Child, limit: Duration) -> Outcome {
    drop(child.stdin.take());
    let out = tokio::time::timeout(limit, child.wait_with_output())
        .await
        .expect("zt-client did not exit in time")
        .unwrap();
    Outcome {
        success: out.status.success(),
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Scrive `data` su stdin del figlio e legge esattamente `data.len()` byte da stdout.
pub async fn echo_through(child: &mut Child, data: &[u8]) -> Vec<u8> {
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let owned = data.to_vec();
    let writer = tokio::spawn(async move {
        stdin.write_all(&owned).await.unwrap();
        stdin
    });
    let mut got = vec![0_u8; data.len()];
    tokio::time::timeout(Duration::from_secs(20), stdout.read_exact(&mut got))
        .await
        .expect("echo timed out")
        .unwrap();
    child.stdin = Some(writer.await.unwrap());
    child.stdout = Some(stdout);
    got
}
