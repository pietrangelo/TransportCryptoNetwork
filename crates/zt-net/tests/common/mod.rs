//! Fixture comuni ai test di rete della Fase 6 (certificati client, PROTOCOL §15).
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use zt_crypto::noise::Channel;
use zt_crypto::{CaSigningKey, Identity, PublicKey, cert_key, sign_certificate, trusted_ca_key};
use zt_domain::limits::DEFAULT_AUTHORITY_LIFETIME_SECS;
use zt_domain::trust::{CertTrust, Revocations, TrustedCaKey};
use zt_domain::{
    AccessPolicy, AllowedNodes, AuthorizedClients, CertBody, CertScope, CertSerial, ClientGrant,
    CloseReason, Fingerprint, Frame, FramePayload, NodeId, StreamId,
};
use zt_net::channel::{self, Established};
use zt_net::client::{self, ClientConfig};
use zt_net::relay::{RelayConfig, RelayServer};
use zt_net::{NetError, Revocable, Timeouts, Updater};

pub fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}
pub fn sid(n: u32) -> StreamId {
    StreamId::try_from(n).unwrap()
}
pub fn nodes(list: &[&str]) -> AllowedNodes {
    AllowedNodes::Only(list.iter().map(|n| node(n)).collect())
}
pub fn scope(list: &[&str]) -> CertScope {
    CertScope::Only(list.iter().map(|n| node(n)).collect())
}

pub fn timeouts() -> Timeouts {
    Timeouts {
        handshake: Duration::from_secs(2),
        idle: Duration::from_secs(10),
        write: Duration::from_secs(5),
        open: Duration::from_secs(3),
        ssh_connect: Duration::from_secs(2),
        keepalive: Duration::from_secs(3),
    }
}

/// L'orologio di sistema, letto qui e non con `zt_net::unix_now` (ancora da implementare).
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Un'identità con il seme noto, per costruire messaggi 1 con `snow` senza `zt-crypto`.
pub fn seeded(b: u8) -> ([u8; 32], Arc<Identity>) {
    let seed = [b; 32];
    (
        seed,
        Arc::new(Identity::from_secret_hex(&hex::encode(seed)).unwrap()),
    )
}

pub fn copy_of(id: &Identity) -> Identity {
    Identity::from_secret_hex(&id.to_secret_hex()).unwrap()
}

/// Un messaggio 1 Noise IK scritto con `snow`, con `payload` qualsiasi (anche oltre il
/// massimo che `zt-crypto` accetterebbe di inviare).
pub fn raw_msg1(seed: [u8; 32], responder: &PublicKey, ch: Channel, payload: &[u8]) -> Vec<u8> {
    let secret = ed25519_dalek::SigningKey::from_bytes(&seed).to_scalar_bytes();
    let prologue: &[u8] = match ch {
        Channel::Outer => b"TCN/1 outer",
        Channel::EndToEnd => b"TCN/1 end-to-end",
    };
    let mut state = snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
        .prologue(prologue)
        .unwrap()
        .local_private_key(&secret)
        .unwrap()
        .remote_public_key(&responder.x25519())
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut out = vec![0_u8; 65_535];
    let len = state.write_message(payload, &mut out).unwrap();
    out.truncate(len);
    out
}

/// Invia `msg1` grezzo al relay (lunghezza a 2 byte big-endian, come il codec) e restituisce
/// il messaggio 2, se arriva. `None`: il relay ha chiuso senza rispondere.
pub async fn probe_relay(relay: SocketAddr, msg1: &[u8]) -> Option<Vec<u8>> {
    let mut tcp = TcpStream::connect(relay).await.unwrap();
    let len = u16::try_from(msg1.len()).unwrap().to_be_bytes();
    tcp.write_all(&len).await.unwrap();
    tcp.write_all(msg1).await.unwrap();
    let mut head = [0_u8; 2];
    match tokio::time::timeout(Duration::from_secs(4), tcp.read_exact(&mut head)).await {
        Ok(Ok(_)) => {
            let mut body = vec![0_u8; usize::from(u16::from_be_bytes(head))];
            tcp.read_exact(&mut body).await.ok()?;
            Some(body)
        }
        _ => None,
    }
}

/// Finto sshd che conta le connessioni e fa eco (il «tripwire»).
pub async fn counting_echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&count);
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (addr, count)
}

static SERIAL: AtomicU64 = AtomicU64::new(1);

/// Un numero di serie nuovo, mai zero.
pub fn next_serial() -> CertSerial {
    let mut b = [0_u8; 16];
    b[..8].copy_from_slice(&SERIAL.fetch_add(1, Ordering::SeqCst).to_be_bytes());
    b[8..12].copy_from_slice(&std::process::id().to_be_bytes());
    b[15] = 0x5e;
    CertSerial::try_from(b).unwrap()
}

/// Una CA offline.
pub struct Ca {
    pub key: CaSigningKey,
}

impl Ca {
    pub fn new() -> Self {
        Self {
            key: CaSigningKey::generate().unwrap(),
        }
    }
    pub fn trusted(&self) -> TrustedCaKey {
        trusted_ca_key(&self.key.public_key())
    }
    /// Un certificato per `subject` valido in `[nb, na)`.
    pub fn issue_at(
        &self,
        subject: &PublicKey,
        scope: CertScope,
        nb: u64,
        na: u64,
    ) -> (Arc<[u8]>, CertSerial) {
        let serial = next_serial();
        let body = CertBody::new(
            cert_key(&self.key.public_key()),
            cert_key(subject),
            serial,
            zt_domain::UnixTime::from_secs(nb),
            zt_domain::UnixTime::from_secs(na),
            node("alice"),
            scope,
        )
        .unwrap();
        (
            Arc::from(sign_certificate(&self.key, &body).unwrap()),
            serial,
        )
    }
    /// Un certificato valido da un minuto fa per un'ora.
    pub fn issue(&self, subject: &PublicKey, scope: CertScope) -> (Arc<[u8]>, CertSerial) {
        let now = now_secs();
        self.issue_at(subject, scope, now - 60, now + 3_540)
    }
}

/// CA pinnate (ognuna con il proprio `allow`) e denylist.
pub fn trust(
    cas: &[(&Ca, AllowedNodes)],
    serials: &[CertSerial],
    keys: &[Fingerprint],
) -> CertTrust {
    let mut t = CertTrust::new();
    for (i, (ca, allow)) in cas.iter().enumerate() {
        t.add_authority(
            node(&format!("ca-{i}")),
            &[ca.trusted()],
            allow.clone(),
            DEFAULT_AUTHORITY_LIFETIME_SECS,
        )
        .unwrap();
    }
    t.set_revocations(Revocations::new(serials.iter().copied(), keys.iter().copied()).unwrap());
    t
}

/// Policy del relay: l'agent di `web-01`, i client della whitelist (tutti i nodi) e `trust`.
pub fn relay_policy(
    agent: &Fingerprint,
    whitelist: &[Fingerprint],
    trust: CertTrust,
) -> AccessPolicy {
    let mut p = AccessPolicy::new();
    p.add_agent(*agent, node("web-01")).unwrap();
    for (i, key) in whitelist.iter().enumerate() {
        p.add_client(
            *key,
            ClientGrant {
                name: node(&format!("static-{i}")),
                allowed: AllowedNodes::All,
            },
        )
        .unwrap();
    }
    if !trust.is_empty() {
        p.set_cert_trust(trust).unwrap();
    }
    p
}

/// Client autorizzati dell'agent: la whitelist e `trust`.
pub fn agent_clients(whitelist: &[Fingerprint], trust: CertTrust) -> AuthorizedClients {
    let mut c: AuthorizedClients = whitelist.iter().copied().collect();
    if !trust.is_empty() {
        c.set_cert_trust(trust).unwrap();
    }
    c
}

pub fn relay_config() -> RelayConfig {
    RelayConfig {
        timeouts: timeouts(),
        handshake_burst: 1_000,
        wide_handshake_burst: 1_000,
        ..RelayConfig::default()
    }
}

/// Un relay vero, in ascolto.
pub struct Relay {
    pub addr: SocketAddr,
    pub key: PublicKey,
    pub policy: Updater<AccessPolicy>,
}

pub async fn start_relay(policy: AccessPolicy) -> Relay {
    let id = Identity::generate().unwrap();
    let key = id.public_key();
    let (rx, updater) = Revocable::new(policy);
    let server = RelayServer::bind("127.0.0.1:0".parse().unwrap(), id, rx, relay_config())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());
    Relay {
        addr,
        key,
        policy: updater,
    }
}

/// Relay veri, l'agent di `web-01` (registrato su tutti) e il suo sshd che fa eco.
pub struct Lab {
    pub relays: Vec<Relay>,
    pub agent: Arc<Identity>,
    pub clients: Updater<AuthorizedClients>,
    pub sshd: Arc<AtomicUsize>,
}

impl Lab {
    /// `policies` riceve la fingerprint dell'agent e restituisce la policy di ogni relay.
    pub async fn start(
        policies: impl FnOnce(&Fingerprint) -> Vec<AccessPolicy>,
        clients: AuthorizedClients,
    ) -> Self {
        let agent = Arc::new(Identity::generate().unwrap());
        let policies = policies(&agent.fingerprint());
        Self::start_with(agent, policies, clients).await
    }

    /// Come [`Lab::start`], con l'identità dell'agent e le policy già pronte.
    pub async fn start_with(
        agent: Arc<Identity>,
        policies: Vec<AccessPolicy>,
        clients: AuthorizedClients,
    ) -> Self {
        let mut relays = Vec::new();
        for p in policies {
            relays.push(start_relay(p).await);
        }
        let (ssh, sshd) = counting_echo().await;
        let (clients_rx, clients) = Revocable::new(clients);
        tokio::spawn(zt_net::agent::run(
            Arc::new(zt_crypto::Keyring::single(copy_of(&agent))),
            zt_net::agent::AgentConfig {
                relays: relays
                    .iter()
                    .map(|r| zt_net::RelayEndpoint {
                        address: r.addr.to_string(),
                        public_key: r.key,
                    })
                    .collect(),
                node: node("web-01"),
                ssh_target: ssh.to_string(),
                authorized_clients: clients_rx,
                timeouts: timeouts(),
                max_streams: 16,
            },
        ));
        tokio::time::sleep(Duration::from_millis(400)).await;
        Self {
            relays,
            agent,
            clients,
            sshd,
        }
    }

    pub fn config(&self, certificate: Option<&Arc<[u8]>>) -> ClientConfig {
        ClientConfig {
            relays: self
                .relays
                .iter()
                .map(|r| zt_net::RelayEndpoint {
                    address: r.addr.to_string(),
                    public_key: r.key,
                })
                .collect(),
            node: node("web-01"),
            node_key: self.agent.public_key(),
            certificate: certificate.cloned(),
            timeouts: timeouts(),
        }
    }

    /// Apre una sessione e verifica l'eco; altrimenti restituisce l'esito del client.
    pub async fn session(
        &self,
        who: &Arc<Identity>,
        certificate: Option<&Arc<[u8]>>,
    ) -> Result<(DuplexStream, JoinHandle<Result<(), NetError>>), String> {
        let (mut app, local) = tokio::io::duplex(64 * 1024);
        let (who, config) = (Arc::clone(who), self.config(certificate));
        let task = tokio::spawn(async move { client::connect(&who, &config, local).await });
        app.write_all(b"ping").await.map_err(|e| e.to_string())?;
        let mut buf = [0_u8; 4];
        match tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut buf)).await {
            Ok(Ok(_)) if &buf == b"ping" => Ok((app, task)),
            _ => {
                let outcome = tokio::time::timeout(Duration::from_secs(5), task).await;
                Err(format!("no echo; client outcome: {outcome:?}"))
            }
        }
    }

    /// L'esito di un client che non deve ottenere una sessione.
    pub async fn refused(
        &self,
        who: &Arc<Identity>,
        certificate: Option<&Arc<[u8]>>,
    ) -> Result<(), NetError> {
        let (_app, local) = tokio::io::duplex(1024);
        tokio::time::timeout(
            Duration::from_secs(10),
            client::connect(who, &self.config(certificate), local),
        )
        .await
        .expect("client hung")
    }
}

pub async fn assert_alive(app: &mut DuplexStream) {
    app.write_all(b"ping").await.unwrap();
    let mut buf = [0_u8; 4];
    tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut buf))
        .await
        .expect("session not answering")
        .unwrap();
    assert_eq!(&buf, b"ping");
}

pub async fn ended(
    task: JoinHandle<Result<(), NetError>>,
    within: Duration,
) -> Result<(), NetError> {
    tokio::time::timeout(within, task)
        .await
        .expect("session still running")
        .unwrap()
}

/// Un relay compromesso: accetta l'agent di `web-01` e parla con lui direttamente.
pub struct FakeRelay {
    pub ch: Established<TcpStream>,
    pub agent: Arc<Identity>,
    pub sshd: Arc<AtomicUsize>,
}

/// Cosa risponde l'agent al messaggio 1 end-to-end di uno stream.
#[derive(Debug, PartialEq, Eq)]
pub enum AgentAnswer {
    /// Un `Data`: il messaggio 2.
    Msg2,
    /// Un `Close` senza messaggio 2.
    Closed(CloseReason),
    /// Nulla entro il tempo.
    Silent,
}

impl FakeRelay {
    pub async fn start(clients: AuthorizedClients) -> Self {
        let relay_id = Identity::generate().unwrap();
        let relay_keys = zt_crypto::Keyring::single(copy_of(&relay_id));
        let agent = Arc::new(Identity::generate().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (ssh, sshd) = counting_echo().await;
        tokio::spawn(zt_net::agent::run(
            Arc::new(zt_crypto::Keyring::single(copy_of(&agent))),
            zt_net::agent::AgentConfig {
                relays: vec![zt_net::RelayEndpoint {
                    address: addr.to_string(),
                    public_key: relay_id.public_key(),
                }],
                node: node("web-01"),
                ssh_target: ssh.to_string(),
                authorized_clients: Revocable::fixed(clients),
                timeouts: timeouts(),
                max_streams: 16,
            },
        ));
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ch = channel::accept(tcp, &relay_keys, Channel::Outer, &timeouts())
            .await
            .unwrap()
            .establish(&timeouts())
            .await
            .unwrap();
        assert!(matches!(
            ch.recv().await.unwrap(),
            Some(Frame::Register { .. })
        ));
        Self { ch, agent, sshd }
    }

    /// `Open web-01` sullo stream `n`, poi `msg1` in un `Data`: che cosa risponde l'agent.
    pub async fn offer(&mut self, n: u32, msg1: Vec<u8>) -> AgentAnswer {
        self.ch
            .send(
                &Frame::Open {
                    stream: sid(n),
                    target: node("web-01"),
                },
                &timeouts(),
            )
            .await
            .unwrap();
        self.ch
            .send(
                &Frame::Data {
                    stream: sid(n),
                    payload: FramePayload::try_from(msg1).unwrap(),
                },
                &timeouts(),
            )
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let Ok(frame) = tokio::time::timeout_at(deadline, self.ch.recv()).await else {
                return AgentAnswer::Silent;
            };
            match frame.unwrap() {
                Some(Frame::Data { stream, .. }) if stream == sid(n) => return AgentAnswer::Msg2,
                Some(Frame::Close { stream, reason }) if stream == sid(n) => {
                    return AgentAnswer::Closed(reason);
                }
                Some(_) => {}
                None => return AgentAnswer::Silent,
            }
        }
    }

    pub fn sshd_connections(&self) -> usize {
        self.sshd.load(Ordering::SeqCst)
    }
}

/// Log JSON catturati (il runtime dei test che li usano è `current_thread`, così ogni task
/// scrive sul subscriber del test).
#[derive(Clone, Default)]
pub struct Captured(Arc<Mutex<Vec<u8>>>);

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
    pub fn install(&self) -> tracing::subscriber::DefaultGuard {
        let writer = self.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::set_default(subscriber)
    }
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
    /// Le righe con `"event_kind":"<kind>"`.
    pub fn events(&self, kind: &str) -> Vec<String> {
        let needle = format!("\"event_kind\":\"{kind}\"");
        self.text()
            .lines()
            .filter(|l| l.contains(&needle))
            .map(str::to_owned)
            .collect()
    }
}

/// `"key":"value"` in una riga JSON.
pub fn field(line: &str, key: &str) -> Option<String> {
    let (_, rest) = line.split_once(&format!("\"{key}\":\""))?;
    let (value, _) = rest.split_once('"')?;
    Some(value.to_owned())
}
