//! Phase 6, step 7: attacks on client certificates over real TCP (PROTOCOL §15.3, §15.4,
//! §15.5, §15.6, §15.8, §15.14). Every rejection has a positive check in the same test, so an
//! implementation that rejects everything does not pass.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{
    AgentAnswer, Ca, Captured, FakeRelay, Lab, agent_clients, field, nodes, now_secs, probe_relay,
    raw_msg1, relay_policy, scope, seeded, start_relay, trust,
};
use zt_crypto::Identity;
use zt_crypto::noise::Channel;
use zt_domain::limits::{MAX_CERT_LEN, MAX_PAYLOAD_LEN, NOISE_MSG1_OVERHEAD};
use zt_domain::{AllowedNodes, CloseReason, Fingerprint};
use zt_net::NetError;
use zt_net::config::{ConfigError, load_authorized_clients, load_relay_policy};

fn some_agent() -> Fingerprint {
    Identity::generate().unwrap().fingerprint()
}

/// A: a stolen certificate presented with a different static key does not get message 2 from
/// either the relay or the agent; the audit log says `key_mismatch` and, since the signature
/// has not been verified, names neither CA nor serial (§15.4 step 4, §15.11).
#[tokio::test]
async fn a_stolen_certificate_with_another_key_never_gets_msg2() {
    let log = Captured::default();
    let _guard = log.install();
    let ca = Ca::new();
    let (alice_seed, alice) = seeded(0x11);
    let (thief_seed, thief) = seeded(0x22);
    let (cert, serial) = ca.issue(&alice.public_key(), scope(&["web-01"]));

    let relay = start_relay(relay_policy(
        &some_agent(),
        &[],
        trust(&[(&ca, AllowedNodes::All)], &[], &[]),
    ))
    .await;
    // Check: the owner gets message 2.
    assert!(
        probe_relay(
            relay.addr,
            &raw_msg1(alice_seed, &relay.key, Channel::Outer, &cert)
        )
        .await
        .is_some()
    );
    assert!(
        probe_relay(
            relay.addr,
            &raw_msg1(thief_seed, &relay.key, Channel::Outer, &cert)
        )
        .await
        .is_none(),
        "the relay answered a stolen certificate"
    );
    let failed = log.events("authentication_failed");
    let thief_line = failed
        .iter()
        .find(|l| field(l, "peer") == Some(thief.fingerprint().to_string()))
        .unwrap_or_else(|| panic!("no authentication_failed for the thief: {}", log.text()));
    assert_eq!(
        field(thief_line, "cert_check").as_deref(),
        Some("key_mismatch")
    );
    assert_eq!(field(thief_line, "reason").as_deref(), Some("certificate"));
    assert!(field(thief_line, "serial").is_none(), "{thief_line}");
    assert!(field(thief_line, "ca").is_none(), "{thief_line}");
    // No rejection names the serial: the thief's signature was never verified.
    assert!(failed.iter().all(|l| !l.contains(&serial.to_string())));

    // The same on the end-to-end channel, towards the agent.
    let mut fake = FakeRelay::start(agent_clients(
        &[],
        trust(&[(&ca, AllowedNodes::All)], &[], &[]),
    ))
    .await;
    let agent_key = fake.agent.public_key();
    assert_eq!(
        fake.offer(
            1,
            raw_msg1(alice_seed, &agent_key, Channel::EndToEnd, &cert)
        )
        .await,
        AgentAnswer::Msg2
    );
    assert_eq!(
        fake.offer(
            3,
            raw_msg1(thief_seed, &agent_key, Channel::EndToEnd, &cert)
        )
        .await,
        AgentAnswer::Closed(CloseReason::Unauthorized)
    );
    assert_eq!(fake.sshd_connections(), 0);
}

/// The malformed payloads used against both the relay and the agent.
fn bad_payloads(cert: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    // The tag is already part of NOISE_MSG1_OVERHEAD: this is the largest payload whose msg1
    // still fits a `Data` frame.
    let max_in_data = MAX_PAYLOAD_LEN - NOISE_MSG1_OVERHEAD;
    let mut bad_sig = cert.to_vec();
    *bad_sig.last_mut().unwrap() ^= 0x01;
    let mut trailing = cert.to_vec();
    trailing.push(0);
    vec![
        ("one byte", vec![0]),
        ("169 bytes", vec![0; 169]),
        ("garbage", vec![0xff; 200]),
        ("bad signature", bad_sig),
        ("truncated", cert[..cert.len() - 1].to_vec()),
        ("trailing byte", trailing),
        ("MAX_CERT_LEN + 1", vec![0; MAX_CERT_LEN + 1]),
        ("as large as a Data frame allows", vec![0x54; max_in_data]),
    ]
}

/// A: malformed or overlong message 1 payloads do not get message 2, on the relay and on the
/// agent; the relay keeps serving the others.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn garbage_or_oversized_msg1_payloads_get_no_msg2() {
    let ca = Ca::new();
    let (alice_seed, alice) = seeded(0x31);
    let (static_seed, static_client) = seeded(0x32);
    let (cert, _) = ca.issue(&alice.public_key(), scope(&["web-01"]));

    let relay = start_relay(relay_policy(
        &some_agent(),
        &[static_client.fingerprint()],
        trust(&[(&ca, AllowedNodes::All)], &[], &[]),
    ))
    .await;
    for (what, payload) in bad_payloads(&cert) {
        // Even a whitelisted client: a presented certificate is always verified.
        for seed in [alice_seed, static_seed] {
            assert!(
                probe_relay(
                    relay.addr,
                    &raw_msg1(seed, &relay.key, Channel::Outer, &payload)
                )
                .await
                .is_none(),
                "relay answered a msg1 with payload {what}"
            );
        }
    }
    // The relay survives: a whitelisted client and a certified one still get through.
    assert!(
        probe_relay(
            relay.addr,
            &raw_msg1(static_seed, &relay.key, Channel::Outer, &[])
        )
        .await
        .is_some()
    );
    assert!(
        probe_relay(
            relay.addr,
            &raw_msg1(alice_seed, &relay.key, Channel::Outer, &cert)
        )
        .await
        .is_some()
    );

    let mut fake = FakeRelay::start(agent_clients(
        &[static_client.fingerprint()],
        trust(&[(&ca, AllowedNodes::All)], &[], &[]),
    ))
    .await;
    let agent_key = fake.agent.public_key();
    let mut n = 1;
    for (what, payload) in bad_payloads(&cert) {
        for seed in [alice_seed, static_seed] {
            let answer = fake
                .offer(n, raw_msg1(seed, &agent_key, Channel::EndToEnd, &payload))
                .await;
            assert_eq!(
                answer,
                AgentAnswer::Closed(CloseReason::Unauthorized),
                "agent: payload {what}"
            );
            n += 2;
        }
    }
    assert_eq!(
        fake.offer(
            n,
            raw_msg1(alice_seed, &agent_key, Channel::EndToEnd, &cert)
        )
        .await,
        AgentAnswer::Msg2
    );
    assert_eq!(fake.sshd_connections(), 0);
}

/// A: a compromised relay forwards to the `web-01` agent a certificate that does not grant
/// `web-01` (outside the certificate's list, or outside the CA's `allow`): `Close
/// Unauthorized` before message 2 and sshd never contacted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_compromised_relay_cannot_open_a_node_outside_the_certificate_scope() {
    let ca = Ca::new();
    let (seed, alice) = seeded(0x41);
    let (db_only, _) = ca.issue(&alice.public_key(), scope(&["db-01"]));
    let (web, _) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    let (all, _) = ca.issue(&alice.public_key(), zt_domain::CertScope::All);

    let mut fake = FakeRelay::start(agent_clients(
        &[],
        trust(&[(&ca, AllowedNodes::All)], &[], &[]),
    ))
    .await;
    let key = fake.agent.public_key();
    assert_eq!(
        fake.offer(1, raw_msg1(seed, &key, Channel::EndToEnd, &db_only))
            .await,
        AgentAnswer::Closed(CloseReason::Unauthorized)
    );
    assert_eq!(
        fake.offer(3, raw_msg1(seed, &key, Channel::EndToEnd, &web))
            .await,
        AgentAnswer::Msg2
    );
    assert_eq!(fake.sshd_connections(), 0);

    // The CA is valid only for `db-01`: not even a certificate that lists `web-01` or
    // `scope = 0x01` opens `web-01`.
    let mut fake = FakeRelay::start(agent_clients(
        &[],
        trust(&[(&ca, nodes(&["db-01"]))], &[], &[]),
    ))
    .await;
    let key = fake.agent.public_key();
    for (n, cert) in [(1, &web), (3, &all)] {
        assert_eq!(
            fake.offer(n, raw_msg1(seed, &key, Channel::EndToEnd, cert))
                .await,
            AgentAnswer::Closed(CloseReason::Unauthorized)
        );
    }
    assert_eq!(fake.sshd_connections(), 0);
}

/// A: a compromised relay with its own CA signs certificates (for a key of its own, or for a
/// real client's key) and presents them to the agent: rejected, sshd never contacted. It
/// cannot even strip the certificate from a real message 1 (the agent would treat it as an
/// unknown client).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_compromised_relay_cannot_substitute_a_certificate_toward_the_agent() {
    let (ca, rogue) = (Ca::new(), Ca::new());
    let (alice_seed, alice) = seeded(0x51);
    let (mallory_seed, mallory) = seeded(0x52);
    let (genuine, _) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    let (for_mallory, _) = rogue.issue(&mallory.public_key(), zt_domain::CertScope::All);
    let (for_alice, _) = rogue.issue(&alice.public_key(), zt_domain::CertScope::All);

    let mut fake = FakeRelay::start(agent_clients(
        &[],
        trust(&[(&ca, AllowedNodes::All)], &[], &[]),
    ))
    .await;
    let key = fake.agent.public_key();
    let attempts = [
        ("rogue CA, relay's own key", mallory_seed, &for_mallory[..]),
        (
            "rogue CA for alice, relay's key",
            mallory_seed,
            &for_alice[..],
        ),
        (
            "genuine certificate, relay's key",
            mallory_seed,
            &genuine[..],
        ),
        ("alice's msg1 without certificate", alice_seed, &[][..]),
    ];
    let mut n = 1;
    for (what, seed, payload) in attempts {
        assert_eq!(
            fake.offer(n, raw_msg1(seed, &key, Channel::EndToEnd, payload))
                .await,
            AgentAnswer::Closed(CloseReason::Unauthorized),
            "{what}"
        );
        n += 2;
    }
    assert_eq!(
        fake.offer(n, raw_msg1(alice_seed, &key, Channel::EndToEnd, &genuine))
            .await,
        AgentAnswer::Msg2
    );
    assert_eq!(fake.sshd_connections(), 0);
}

/// A (defense in depth): the relay pins CAs X and Y, the agent only Y. A certificate from X
/// passes the relay but not the agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_agent_rejects_an_authority_it_does_not_pin_even_if_the_relay_does() {
    let (x, y) = (Ca::new(), Ca::new());
    let alice = Arc::new(Identity::generate().unwrap());
    let bob = Arc::new(Identity::generate().unwrap());
    let lab = Lab::start(
        |agent| {
            vec![relay_policy(
                agent,
                &[],
                trust(
                    &[(&x, AllowedNodes::All), (&y, AllowedNodes::All)],
                    &[],
                    &[],
                ),
            )]
        },
        agent_clients(&[], trust(&[(&y, AllowedNodes::All)], &[], &[])),
    )
    .await;
    let (from_y, _) = y.issue(&alice.public_key(), scope(&["web-01"]));
    let (from_x, _) = x.issue(&bob.public_key(), scope(&["web-01"]));
    let (_app, _task) = lab.session(&alice, Some(&from_y)).await.unwrap();
    assert!(matches!(
        lab.refused(&bob, Some(&from_x)).await,
        Err(NetError::StreamClosed(CloseReason::Unauthorized))
    ));
    assert_eq!(lab.sshd.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// A (§15.3): a replayed outer message 1 with a valid certificate gets at most a useless
/// message 2: no `session_established`, no event with that serial. Afterwards, a real session
/// logs the serial (positive check).
#[tokio::test]
async fn replaying_a_certified_msg1_logs_no_session() {
    let log = Captured::default();
    let _guard = log.install();
    let ca = Ca::new();
    let (seed, alice) = seeded(0x61);
    let lab = Lab::start(
        |agent| {
            vec![relay_policy(
                agent,
                &[],
                trust(&[(&ca, AllowedNodes::All)], &[], &[]),
            )]
        },
        agent_clients(&[], trust(&[(&ca, AllowedNodes::All)], &[], &[])),
    )
    .await;
    let (cert, serial) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    let relay = &lab.relays[0];
    let captured = raw_msg1(seed, &relay.key, Channel::Outer, &cert);
    for _ in 0..3 {
        let _ = probe_relay(relay.addr, &captured).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        log.events("session_established").is_empty(),
        "{}",
        log.text()
    );
    assert!(
        !log.text().contains(&serial.to_string()),
        "an event names the serial of a replayed msg1: {}",
        log.text()
    );

    let (_app, _task) = lab.session(&alice, Some(&cert)).await.unwrap();
    let established = log.events("session_established");
    assert_eq!(established.len(), 1, "{}", log.text());
    assert_eq!(field(&established[0], "serial"), Some(serial.to_string()));
}

/// A (§15.6): expired (even recently) or not yet valid beyond the tolerance: rejected by relay
/// and agent. Within the tolerance on `not_before`, accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_and_not_yet_valid_certificates_are_refused_on_relay_and_agent() {
    let ca = Ca::new();
    let (seed, alice) = seeded(0x71);
    let now = now_secs();
    let issue = |nb: u64, na: u64| {
        ca.issue_at(&alice.public_key(), scope(&["web-01"]), nb, na)
            .0
    };
    let refused = [
        ("expired", issue(now - 700, now - 100)),
        ("just expired", issue(now - 600, now - 2)),
        ("not yet valid", issue(now + 300, now + 900)),
        ("just beyond the skew", issue(now + 125, now + 900)),
    ];
    let accepted = [
        ("valid", issue(now - 60, now + 900)),
        ("within the skew", issue(now + 60, now + 900)),
    ];

    let relay = start_relay(relay_policy(
        &some_agent(),
        &[],
        trust(&[(&ca, AllowedNodes::All)], &[], &[]),
    ))
    .await;
    for (what, cert) in &refused {
        assert!(
            probe_relay(
                relay.addr,
                &raw_msg1(seed, &relay.key, Channel::Outer, cert)
            )
            .await
            .is_none(),
            "relay: {what}"
        );
    }
    for (what, cert) in &accepted {
        assert!(
            probe_relay(
                relay.addr,
                &raw_msg1(seed, &relay.key, Channel::Outer, cert)
            )
            .await
            .is_some(),
            "relay: {what}"
        );
    }

    let mut fake = FakeRelay::start(agent_clients(
        &[],
        trust(&[(&ca, AllowedNodes::All)], &[], &[]),
    ))
    .await;
    let key = fake.agent.public_key();
    let mut n = 1;
    for (what, cert) in &refused {
        assert_eq!(
            fake.offer(n, raw_msg1(seed, &key, Channel::EndToEnd, cert))
                .await,
            AgentAnswer::Closed(CloseReason::Unauthorized),
            "agent: {what}"
        );
        n += 2;
    }
    for (what, cert) in &accepted {
        assert_eq!(
            fake.offer(n, raw_msg1(seed, &key, Channel::EndToEnd, cert))
                .await,
            AgentAnswer::Msg2,
            "agent: {what}"
        );
        n += 2;
    }
    assert_eq!(fake.sshd_connections(), 0);
}

/// Temporary `0755` directory for the configuration files, deleted at the end.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("zt-adversary-certs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_mode(&dir, 0o755);
        Self(dir)
    }
    fn write(&self, name: &str, text: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, text).unwrap();
        set_mode(&p, 0o644);
        p
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn set_mode(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A (§15.8): with `[[authorities]]` and no denylist, the relay and agent loaders fail (and
/// so neither `RelayServer` nor `agent::run` start). With the denylist, relay and agent built
/// from the loaders serve a certified client.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_without_revocations_for_its_authorities_does_not_start() {
    let dir = Dir::new("revocations");
    let ca = Ca::new();
    let agent = Arc::new(Identity::generate().unwrap());
    let static_client = Identity::generate().unwrap();
    let authority = format!(
        "[[authorities]]\nname = \"ops-ca\"\npublic_key = \"{}\"\nallow = [\"web-01\"]\n",
        ca.key.public_key()
    );
    let policy = dir.write(
        "policy.toml",
        &format!(
            "[[agents]]\nnode = \"web-01\"\npublic_key = \"{}\"\n\n{authority}",
            agent.public_key()
        ),
    );
    let clients = dir.write(
        "clients.toml",
        &format!(
            "[[clients]]\nname = \"ansible\"\npublic_key = \"{}\"\n\n{authority}",
            static_client.public_key()
        ),
    );
    assert!(matches!(
        load_relay_policy(&policy, None),
        Err(ConfigError::RevocationsRequired(_))
    ));
    assert!(matches!(
        zt_net::config::load_policy(&policy),
        Err(ConfigError::RevocationsRequired(_))
    ));
    assert!(matches!(
        load_authorized_clients(&clients, None),
        Err(ConfigError::RevocationsRequired(_))
    ));

    // Positive check: with an empty denylist everything starts and the certificate works.
    let revoked = dir.write("revoked.toml", "serials = []\nkeys = []\n");
    let relay_policy = load_relay_policy(&policy, Some(&revoked)).unwrap();
    let agent_clients = load_authorized_clients(&clients, Some(&revoked)).unwrap();
    assert!(!relay_policy.cert_trust().is_empty());
    assert!(!agent_clients.cert_trust().is_empty());
    let lab = Lab::start_with(agent, vec![relay_policy], agent_clients).await;
    let alice = Arc::new(Identity::generate().unwrap());
    let (cert, _) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    let (_app, _task) = lab.session(&alice, Some(&cert)).await.unwrap();
}

/// Finding 0006-3: a rejection after signature verification (here `serial_revoked` on the
/// relay, `serial_revoked` and `node_out_of_scope` on the agent) reports `ca` and `serial`
/// (§15.11); a rejection before the signature (`bad_signature`) never does.
#[tokio::test]
async fn authentication_failed_after_the_signature_names_ca_and_serial() {
    let log = Captured::default();
    let _guard = log.install();
    let ca = Ca::new();
    let (alice_seed, alice) = seeded(0x31);
    let (bob_seed, bob) = seeded(0x32);
    let (carol_seed, carol) = seeded(0x33);
    let (revoked, revoked_serial) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    let (elsewhere, elsewhere_serial) = ca.issue(&bob.public_key(), scope(&["db-01"]));
    let (good, good_serial) = ca.issue(&carol.public_key(), scope(&["web-01"]));
    let mut forged = good.to_vec();
    *forged.last_mut().unwrap() ^= 0x01;
    let ca_fp = ca.key.public_key().fingerprint().to_string();
    let line_for = |peer: &Identity| {
        log.events("authentication_failed")
            .into_iter()
            .find(|l| field(l, "peer") == Some(peer.fingerprint().to_string()))
            .unwrap_or_else(|| panic!("no authentication_failed for {peer:?}: {}", log.text()))
    };
    let names_certificate = |line: &str, check: &str, serial: &zt_domain::CertSerial| {
        assert_eq!(field(line, "cert_check").as_deref(), Some(check), "{line}");
        assert_eq!(field(line, "ca"), Some(ca_fp.clone()), "{line}");
        assert_eq!(field(line, "serial"), Some(serial.to_string()), "{line}");
    };
    let names_nothing = |line: &str| {
        assert_eq!(
            field(line, "cert_check").as_deref(),
            Some("bad_signature"),
            "{line}"
        );
        assert!(field(line, "ca").is_none(), "{line}");
        assert!(field(line, "serial").is_none(), "{line}");
        assert!(!line.contains(&good_serial.to_string()), "{line}");
    };

    // Relay.
    let relay = start_relay(relay_policy(
        &some_agent(),
        &[],
        trust(&[(&ca, AllowedNodes::All)], &[revoked_serial], &[]),
    ))
    .await;
    let msg1 = raw_msg1(alice_seed, &relay.key, Channel::Outer, &revoked);
    assert!(probe_relay(relay.addr, &msg1).await.is_none());
    names_certificate(&line_for(&alice), "serial_revoked", &revoked_serial);
    let msg1 = raw_msg1(carol_seed, &relay.key, Channel::Outer, &forged);
    assert!(probe_relay(relay.addr, &msg1).await.is_none());
    names_nothing(&line_for(&carol));
    // Positive check: the intact certificate passes.
    let msg1 = raw_msg1(carol_seed, &relay.key, Channel::Outer, &good);
    assert!(probe_relay(relay.addr, &msg1).await.is_some());

    // Agent: start over with a clean log.
    log.clear();
    let mut fake = FakeRelay::start(agent_clients(
        &[],
        trust(&[(&ca, AllowedNodes::All)], &[revoked_serial], &[]),
    ))
    .await;
    let agent_key = fake.agent.public_key();
    let offers = [
        (
            1,
            raw_msg1(alice_seed, &agent_key, Channel::EndToEnd, &revoked),
        ),
        (
            3,
            raw_msg1(bob_seed, &agent_key, Channel::EndToEnd, &elsewhere),
        ),
        (
            5,
            raw_msg1(carol_seed, &agent_key, Channel::EndToEnd, &forged),
        ),
    ];
    for (stream, msg1) in offers {
        assert_eq!(
            fake.offer(stream, msg1).await,
            AgentAnswer::Closed(CloseReason::Unauthorized)
        );
    }
    names_certificate(&line_for(&alice), "serial_revoked", &revoked_serial);
    names_certificate(&line_for(&bob), "node_out_of_scope", &elsewhere_serial);
    names_nothing(&line_for(&carol));
    assert_eq!(
        fake.offer(
            7,
            raw_msg1(carol_seed, &agent_key, Channel::EndToEnd, &good)
        )
        .await,
        AgentAnswer::Msg2
    );
}
