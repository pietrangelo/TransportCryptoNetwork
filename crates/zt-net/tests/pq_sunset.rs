//! Phase 7, PQ-SUNSET (docs/pq-resilience-plan.md §4; analysis/pq.md PQ-5; OPERATIONS §19):
//! retiring the classical-only paths is a configuration step, never a new default. The
//! `pq_only` profile (`[handshake] pq_only` in `relay.toml`, `--pq-only` on the agent,
//! `pq_only` in `client.toml`) refuses at load time any setting that would still accept a
//! classical suite, a v1 identity or a v1 certificate, and the end-state fleet of OPERATIONS
//! §19, loaded from its files through the loading code of the binaries, refuses each of them on
//! every channel: both outer hops and end to end. The rollback follows the order of §19.3.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{Ca, Captured, Lab, assert_alive, copy_of, field, number, relay_config, scope};
use zt_crypto::{Identity, Keyring};
use zt_domain::{AcceptedSuites, AccessPolicy, AuthorizedClients, HandshakeSuite, SuitePolicy};
use zt_net::config::{
    self, ConfigError, RelaySettings, parse_authorized_clients, parse_certificate_file,
    parse_client_settings, parse_policy, parse_relay_settings,
};
use zt_net::sunset;

const HYBRID: HandshakeSuite = HandshakeSuite::NoiseIkHybrid25519MlKem768;
const IKHFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;
const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HYBRID_NAME: &str = "Noise_IKhfs+psk0+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s";
const IKHFS_NAME: &str = "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s";
const CLASSIC_NAME: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

fn id() -> Arc<Identity> {
    Arc::new(Identity::generate().unwrap())
}

/// The end-state `relay.toml` of OPERATIONS §19.
fn relay_toml() -> String {
    format!(
        "[handshake]\npq_only = true\nagent_suites = [\"{HYBRID_NAME}\"]\nclient_suites = [\"{HYBRID_NAME}\"]\n"
    )
}

/// The end-state relay policy of OPERATIONS §19: both roles required hybrid, v2 keys only, a
/// composite CA only.
fn policy_toml(agent: &Identity, alice: &Identity, ca: &Ca) -> String {
    format!(
        "require_hybrid_identity = [\"agents\", \"clients\"]\n\n\
         [[agents]]\nnode = \"web-01\"\npublic_key = \"{}\"\n\n\
         [[clients]]\nname = \"alice\"\npublic_key = \"{}\"\nallow = [\"*\"]\n\n\
         [[authorities]]\nname = \"ops\"\npublic_key = \"{}\"\nallow = [\"*\"]\n",
        agent.hybrid_public_key(),
        alice.hybrid_public_key(),
        ca.v2.as_ref().unwrap().public_key(),
    )
}

/// The end-state `clients.toml` of OPERATIONS §19.
fn clients_toml(alice: &Identity, ca: &Ca) -> String {
    format!(
        "require_hybrid_identity = [\"clients\"]\n\n\
         [[clients]]\nname = \"alice\"\npublic_key = \"{}\"\n\n\
         [[authorities]]\nname = \"ops\"\npublic_key = \"{}\"\nallow = [\"*\"]\n",
        alice.hybrid_public_key(),
        ca.v2.as_ref().unwrap().public_key(),
    )
}

/// The end-state `client.toml` of OPERATIONS §19.
fn client_toml(relay: &Identity, agent: &Identity) -> String {
    format!(
        "pq_only = true\nkey = \"client.key\"\nrequire_outer_suite = \"{HYBRID_NAME}\"\n\n\
         [[relays]]\naddress = \"r1.example:7000\"\npublic_key = \"{}\"\nsuite = \"{HYBRID_NAME}\"\n\n\
         [[nodes]]\nnode = \"web-01\"\npublic_key = \"{}\"\nsuite = \"{HYBRID_NAME}\"\n",
        relay.hybrid_public_key(),
        agent.hybrid_public_key(),
    )
}

fn pq_only_error(err: &ConfigError) {
    assert!(
        matches!(err, ConfigError::PqOnly { .. }),
        "not a pq_only refusal: {err:?}"
    );
    assert!(err.to_string().contains("pq_only"), "{err}");
}

// --- the defaults stay compatible ---------------------------------------------------------

/// Spec: the built-in defaults are not pq-only and never change: an empty `relay.toml` accepts
/// the classical suite, an agent without flags pins it, a client without `pq_only` too.
#[test]
fn the_defaults_stay_compatible_with_a_mixed_fleet() {
    let defaults = RelaySettings::default();
    assert!(!defaults.pq_only);
    assert_eq!(defaults.suites, zt_domain::SuitePolicy::classical());
    let empty = parse_relay_settings("relay.toml", "").unwrap();
    assert!(!empty.pq_only);
    assert_eq!(empty.suites, zt_domain::SuitePolicy::classical());
    let (relay, agent) = (id(), id());
    let plain = format!(
        "key = \"client.key\"\nrelay = \"r1.example:7000\"\nrelay_key = \"{}\"\n\n\
         [[nodes]]\nnode = \"web-01\"\npublic_key = \"{}\"\n",
        relay.public_key(),
        agent.public_key()
    );
    let settings = parse_client_settings("client.toml", Path::new("/etc/tcn"), &plain).unwrap();
    assert!(!settings.pq_only);
    assert_eq!(settings.relays[0].suite, CLASSIC);
}

/// Spec: outside the profile, `check` names every classical path the configuration still
/// accepts, so the operator sees what the sunset has left to do; the end state names none.
#[test]
fn the_report_names_the_classical_paths_still_accepted() {
    let (agent, alice, ca) = (id(), id(), Ca::new_v2());
    let old = Ca::new();
    let mixed_policy = parse_policy(
        "policy.toml",
        &format!(
            "[[agents]]\nnode = \"web-01\"\npublic_key = \"{}\"\n\n\
             [[authorities]]\nname = \"old\"\npublic_key = \"{}\"\nallow = [\"*\"]\n",
            agent.public_key(),
            old.key.public_key(),
        ),
    )
    .unwrap();
    let report = sunset::relay_report(&RelaySettings::default(), &mixed_policy);
    let text = report.join("\n");
    assert!(text.contains(CLASSIC_NAME), "{text}");
    assert!(text.contains("agents"), "{text}");
    assert!(text.contains("clients"), "{text}");
    assert!(
        text.contains("old"),
        "the v1 authority is not named: {text}"
    );
    let end = parse_relay_settings("relay.toml", &relay_toml()).unwrap();
    let policy = parse_policy("policy.toml", &policy_toml(&agent, &alice, &ca)).unwrap();
    assert_eq!(sunset::relay_report(&end, &policy), Vec::<String>::new());
    let clients = parse_authorized_clients("clients.toml", &clients_toml(&alice, &ca)).unwrap();
    assert_eq!(
        sunset::agent_report(&[], AcceptedSuites::only(HYBRID), &clients),
        Vec::<String>::new()
    );
    let classical = sunset::agent_report(
        &[],
        AcceptedSuites::new([CLASSIC, HYBRID]).unwrap(),
        &AuthorizedClients::new(),
    );
    assert!(classical.join("\n").contains(CLASSIC_NAME), "{classical:?}");
}

// --- the profile refuses at load time -----------------------------------------------------

/// Spec: `[handshake] pq_only = true` accepts only the hybrid IK suite in both sets, given
/// explicitly; the classical suite or `IKhfs` (hybrid key exchange, classical authentication)
/// in either set, or a set left to its classical default, is a load error.
#[test]
fn a_pq_only_relay_accepts_only_the_hybrid_ik_suite() {
    let settings = parse_relay_settings("relay.toml", &relay_toml()).unwrap();
    assert!(settings.pq_only);
    assert_eq!(settings.suites.agents, AcceptedSuites::only(HYBRID));
    assert_eq!(settings.suites.clients, AcceptedSuites::only(HYBRID));
    for bad in [
        "[handshake]\npq_only = true\n".to_owned(),
        format!("[handshake]\npq_only = true\nagent_suites = [\"{HYBRID_NAME}\"]\n"),
        format!("[handshake]\npq_only = true\nclient_suites = [\"{HYBRID_NAME}\"]\n"),
        format!(
            "[handshake]\npq_only = true\nagent_suites = [\"{HYBRID_NAME}\", \"{CLASSIC_NAME}\"]\nclient_suites = [\"{HYBRID_NAME}\"]\n"
        ),
        format!(
            "[handshake]\npq_only = true\nagent_suites = [\"{HYBRID_NAME}\"]\nclient_suites = [\"{IKHFS_NAME}\"]\n"
        ),
    ] {
        let err = parse_relay_settings("relay.toml", &bad).unwrap_err();
        pq_only_error(&err);
    }
    // `pq_only = false` is the default, written out.
    let off = parse_relay_settings("relay.toml", "[handshake]\npq_only = false\n").unwrap();
    assert!(!off.pq_only);
}

/// Spec: with the profile, the relay policy must require hybrid identities for agents and
/// clients and pin composite (v2) CA keys only; a v1 CA, even next to a v2 one in a rotation,
/// is refused.
#[test]
fn a_pq_only_relay_policy_requires_hybrid_identities_and_v2_authorities() {
    let (agent, alice, ca, old) = (id(), id(), Ca::new_v2(), Ca::new());
    let good = parse_policy("policy.toml", &policy_toml(&agent, &alice, &ca)).unwrap();
    sunset::check_policy("policy.toml", &good).unwrap();
    let text = policy_toml(&agent, &alice, &ca);
    for bad in [
        text.replace(
            "require_hybrid_identity = [\"agents\", \"clients\"]",
            "require_hybrid_identity = [\"agents\"]",
        ),
        text.replace(
            "require_hybrid_identity = [\"agents\", \"clients\"]",
            "require_hybrid_identity = [\"clients\"]",
        ),
        text.replace("require_hybrid_identity = [\"agents\", \"clients\"]\n", ""),
        text.replace(
            &format!("public_key = \"{}\"", ca.v2.as_ref().unwrap().public_key()),
            &format!(
                "public_keys = [\"{}\", \"{}\"]",
                ca.v2.as_ref().unwrap().public_key(),
                old.key.public_key()
            ),
        ),
        text.replace(
            &format!("public_key = \"{}\"", ca.v2.as_ref().unwrap().public_key()),
            &format!("public_key = \"{}\"", old.key.public_key()),
        ),
    ] {
        let policy = parse_policy("policy.toml", &bad).unwrap();
        pq_only_error(&sunset::check_policy("policy.toml", &policy).unwrap_err());
    }
}

/// Spec: with `--pq-only` the agent pins the hybrid IK suite towards every relay and accepts
/// only it from clients; `clients.toml` requires hybrid clients and pins v2 CAs only.
#[test]
fn a_pq_only_agent_pins_and_accepts_only_the_hybrid_ik_suite() {
    let (relay, alice, ca, old) = (id(), id(), Ca::new_v2(), Ca::new());
    let endpoint = |suite: HandshakeSuite| zt_net::RelayEndpoint {
        address: "r1.example:7000".into(),
        public_key: common::pin_of(&relay, suite),
        suite,
    };
    sunset::check_agent_suites(&[endpoint(HYBRID)], AcceptedSuites::only(HYBRID)).unwrap();
    for (relays, accepted) in [
        (vec![endpoint(CLASSIC)], AcceptedSuites::only(HYBRID)),
        (vec![endpoint(IKHFS)], AcceptedSuites::only(HYBRID)),
        (
            vec![endpoint(HYBRID), endpoint(CLASSIC)],
            AcceptedSuites::only(HYBRID),
        ),
        (vec![endpoint(HYBRID)], AcceptedSuites::only(CLASSIC)),
        (
            vec![endpoint(HYBRID)],
            AcceptedSuites::new([HYBRID, IKHFS]).unwrap(),
        ),
    ] {
        pq_only_error(&sunset::check_agent_suites(&relays, accepted).unwrap_err());
    }
    let text = clients_toml(&alice, &ca);
    let good = parse_authorized_clients("clients.toml", &text).unwrap();
    sunset::check_authorized_clients("clients.toml", &good).unwrap();
    for bad in [
        text.replace("require_hybrid_identity = [\"clients\"]\n", ""),
        text.replace(
            &format!("public_key = \"{}\"", ca.v2.as_ref().unwrap().public_key()),
            &format!("public_key = \"{}\"", old.key.public_key()),
        ),
    ] {
        let clients = parse_authorized_clients("clients.toml", &bad).unwrap();
        pq_only_error(&sunset::check_authorized_clients("clients.toml", &clients).unwrap_err());
    }
}

/// Spec: `pq_only = true` in `client.toml` needs the hybrid IK suite pinned for every relay
/// and every node (a node left to its classical default is refused), and a certificate v2
/// bound to the client's hybrid identity.
#[test]
fn a_pq_only_client_pins_only_the_hybrid_ik_suite() {
    let (relay, agent, alice, ca, old) = (id(), id(), id(), Ca::new_v2(), Ca::new());
    let base = Path::new("/etc/tcn");
    let text = client_toml(&relay, &agent);
    let settings = parse_client_settings("client.toml", base, &text).unwrap();
    assert!(settings.pq_only);
    let relay_line = format!("suite = \"{HYBRID_NAME}\"\n\n[[nodes]]");
    for bad in [
        text.replace(
            &relay_line,
            &format!("suite = \"{IKHFS_NAME}\"\n\n[[nodes]]"),
        )
        .replace(&format!("require_outer_suite = \"{HYBRID_NAME}\"\n"), ""),
        text.replace(&format!("require_outer_suite = \"{HYBRID_NAME}\"\n"), "")
            .replace(&relay_line, "\n[[nodes]]")
            .replace(
                &relay.hybrid_public_key().to_string(),
                &relay.public_key().to_string(),
            ),
        text.strip_suffix(&format!("suite = \"{HYBRID_NAME}\"\n"))
            .unwrap()
            .to_owned(),
        format!(
            "{text}\n[[nodes]]\nnode = \"web-02\"\npublic_key = \"{}\"\nsuite = \"{CLASSIC_NAME}\"\n",
            alice.hybrid_public_key()
        ),
    ] {
        let err = parse_client_settings("client.toml", base, &bad).unwrap_err();
        pq_only_error(&err);
    }
    let (hybrid_bound, _) = ca.issue_hybrid(&alice.hybrid_public_key(), scope(&["web-01"]));
    let (classical_v2, _) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    let (v1, _) = old.issue(&alice.public_key(), scope(&["web-01"]));
    let file = |bytes: &Arc<[u8]>| {
        parse_certificate_file("alice.cert", &zt_crypto::encode_certificate_text(bytes)).unwrap()
    };
    sunset::check_certificate("alice.cert", &file(&hybrid_bound)).unwrap();
    pq_only_error(&sunset::check_certificate("alice.cert", &file(&classical_v2)).unwrap_err());
    pq_only_error(&sunset::check_certificate("alice.cert", &file(&v1)).unwrap_err());
}

// --- the fleet, loaded through the loading code of the binaries -------------------------

/// A directory of configuration files as an operator writes them (0644 in a 0755 directory),
/// removed on drop.
struct Files(PathBuf);

impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

static NEXT_FILES: AtomicUsize = AtomicUsize::new(0);

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

impl Files {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "zt-pq-sunset-{}-{}",
            std::process::id(),
            NEXT_FILES.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_mode(&dir, 0o755);
        Self(dir)
    }

    fn put(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, text).unwrap();
        set_mode(&path, 0o644);
        path
    }
}

/// What the operator writes for one relay and the `web-01` agent: `relay.toml`, the relay
/// policy, the agent's `clients.toml` and the agent's options.
#[derive(Clone)]
struct FleetFiles {
    relay_toml: String,
    policy: String,
    clients: String,
    /// `--pq-only` of the agent.
    agent_pq_only: bool,
    /// `--relay-suite` of the agent.
    agent_relay_suite: HandshakeSuite,
    /// `--accept-client-suites` of the agent.
    agent_client_suites: AcceptedSuites,
}

impl FleetFiles {
    /// The end state of OPERATIONS §19.1.
    fn end_state(agent: &Identity, alice: &Identity, ca: &Ca) -> Self {
        Self {
            relay_toml: relay_toml(),
            policy: policy_toml(agent, alice, ca),
            clients: clients_toml(alice, ca),
            agent_pq_only: true,
            agent_relay_suite: HYBRID,
            agent_client_suites: AcceptedSuites::only(HYBRID),
        }
    }

    /// The same files and options without the profile, on the relay and on the agent.
    fn without_profile(&self) -> Self {
        Self {
            relay_toml: self.relay_toml.replace("pq_only = true", "pq_only = false"),
            agent_pq_only: false,
            ..self.clone()
        }
    }
}

fn edited(base: &FleetFiles, edit: impl FnOnce(&mut FleetFiles)) -> FleetFiles {
    let mut files = base.clone();
    edit(&mut files);
    files
}

/// The fleet's configuration as `zt-relay` and `zt-agent` load it, at startup, in `check` and
/// on every reload: the profile is applied by the loading code under test, never by the test
/// (review 0014, A14-5).
struct Loaded {
    suites: SuitePolicy,
    policy: AccessPolicy,
    clients: AuthorizedClients,
    client_suites: AcceptedSuites,
    relay_suite: HandshakeSuite,
}

/// The relay's policy and the agent's `clients.toml` through their loading code, with the
/// relay's `pq_only` and the agent's `--pq-only`.
fn load_trust(
    files: &FleetFiles,
    agent: &Identity,
    relay_pq_only: bool,
) -> (
    Result<AccessPolicy, ConfigError>,
    Result<AuthorizedClients, ConfigError>,
) {
    let dir = Files::new();
    let revoked = dir.put("revoked.toml", "");
    let relay_keys = Keyring::single(Identity::generate().unwrap());
    let policy = config::load_relay_policy_checked(
        &dir.put("policy.toml", &files.policy),
        Some(&revoked),
        &relay_keys,
        relay_pq_only,
    )
    .map(|(policy, _)| policy);
    let agent_keys = Keyring::single(copy_of(agent));
    let clients = config::load_agent_clients_checked(
        &dir.put("clients.toml", &files.clients),
        Some(&revoked),
        &config::own_keys(&agent_keys, "agent"),
        files.agent_pq_only,
    )
    .map(|(clients, _)| clients);
    (policy, clients)
}

fn load_fleet(files: &FleetFiles, agent: &Identity) -> Result<Loaded, ConfigError> {
    let dir = Files::new();
    let (settings, _) =
        config::load_relay_settings_digested(&dir.put("relay.toml", &files.relay_toml))?;
    let relay = Identity::generate().unwrap();
    let relays = [zt_net::RelayEndpoint {
        address: "r1.example:7000".into(),
        public_key: common::pin_of(&relay, files.agent_relay_suite),
        suite: files.agent_relay_suite,
    }];
    if files.agent_pq_only {
        sunset::check_agent_suites(&relays, files.agent_client_suites)?;
    }
    let (policy, clients) = load_trust(files, agent, settings.pq_only);
    Ok(Loaded {
        suites: settings.suites,
        policy: policy?,
        clients: clients?,
        client_suites: files.agent_client_suites,
        relay_suite: files.agent_relay_suite,
    })
}

async fn start_fleet(loaded: Loaded, agent: Arc<Identity>) -> Lab {
    let mut relay = relay_config();
    relay.suites = loaded.suites;
    Lab::start_outer(
        agent,
        vec![(loaded.policy, relay)],
        loaded.clients,
        loaded.client_suites,
        loaded.relay_suite,
    )
    .await
}

/// The end-state fleet of OPERATIONS §19.1, loaded from its files.
async fn end_state_fleet(agent: Arc<Identity>, alice: &Identity, ca: &Ca) -> Lab {
    let loaded = load_fleet(&FleetFiles::end_state(&agent, alice, ca), &agent).unwrap();
    start_fleet(loaded, agent).await
}

/// `SIGHUP` on the relay and on the agent: the files go through the same loading code, and a
/// refused file leaves the configuration in force (the relay's `Reloader`, the agent's `load`).
fn reload_fleet(
    lab: &Lab,
    files: &FleetFiles,
    agent: &Identity,
) -> (Result<(), ConfigError>, Result<(), ConfigError>) {
    // `relay.toml` is read at startup only: the reload keeps its `pq_only`.
    let relay_pq_only = parse_relay_settings("relay.toml", &files.relay_toml)
        .unwrap()
        .pq_only;
    let (policy, clients) = load_trust(files, agent, relay_pq_only);
    (
        policy.map(|p| lab.relays[0].policy.replace(p)),
        clients.map(|c| lab.clients.replace(c)),
    )
}

fn reasons(log: &Captured) -> Vec<String> {
    log.events("authentication_failed")
        .iter()
        .filter_map(|l| field(l, "reason"))
        .collect()
}

/// Attack (review 0014, A14-5 and mutants M2/M3): the profile itself, through the loading code
/// of both binaries. Each file below keeps one classical path next to the end state; the
/// profile refuses every one of them, and the same files load without it, so what keeps them
/// out is the profile and not the parser. `IKhfs` (classical authentication) is refused like
/// the classical suite, and a v1 CA key like a v1 identity, also inside a rotation pair.
#[test]
fn the_profile_refuses_every_file_that_keeps_a_classical_path() {
    let (agent, alice, ca, old) = (id(), id(), Ca::new_v2(), Ca::new());
    let end = FleetFiles::end_state(&agent, &alice, &ca);
    load_fleet(&end, &agent).unwrap();
    let v2 = ca.v2.as_ref().unwrap().public_key().to_string();
    let v2_ca = format!("public_key = \"{v2}\"");
    let v1_ca = format!("public_key = \"{}\"", old.key.public_key());
    let rotation = format!("public_keys = [\"{v2}\", \"{}\"]", old.key.public_key());
    let hybrid_set = format!("[\"{HYBRID_NAME}\"]");
    let cases = [
        (
            "relay: IKhfs for agents",
            edited(&end, |f| {
                f.relay_toml = f.relay_toml.replacen(
                    &hybrid_set,
                    &format!("[\"{HYBRID_NAME}\", \"{IKHFS_NAME}\"]"),
                    1,
                );
            }),
        ),
        (
            "relay: the classical suite for clients",
            edited(&end, |f| {
                f.relay_toml = f.relay_toml.replace(
                    &format!("client_suites = {hybrid_set}"),
                    &format!("client_suites = [\"{HYBRID_NAME}\", \"{CLASSIC_NAME}\"]"),
                );
            }),
        ),
        (
            "relay: v1 clients",
            edited(&end, |f| {
                f.policy = f.policy.replace(
                    "require_hybrid_identity = [\"agents\", \"clients\"]",
                    "require_hybrid_identity = [\"agents\"]",
                );
            }),
        ),
        (
            "relay: a v1 CA key in a rotation pair",
            edited(&end, |f| f.policy = f.policy.replace(&v2_ca, &rotation)),
        ),
        (
            "agent: a v1 CA key",
            edited(&end, |f| f.clients = f.clients.replace(&v2_ca, &v1_ca)),
        ),
        (
            "agent: v1 clients",
            edited(&end, |f| {
                f.clients = f
                    .clients
                    .replace("require_hybrid_identity = [\"clients\"]\n", "");
            }),
        ),
        (
            "agent: IKhfs end to end",
            edited(&end, |f| {
                f.agent_client_suites = AcceptedSuites::new([HYBRID, IKHFS]).unwrap();
            }),
        ),
        (
            "agent: IKhfs towards the relay",
            edited(&end, |f| f.agent_relay_suite = IKHFS),
        ),
    ];
    for (name, files) in &cases {
        match load_fleet(files, &agent) {
            Ok(_) => panic!("{name}: loaded under the profile"),
            Err(err) => pq_only_error(&err),
        }
        if let Err(err) = load_fleet(&files.without_profile(), &agent) {
            panic!("{name}: refused without the profile: {err}");
        }
    }
}

/// Spec: the end-state fleet works: a whitelisted client and a client with a hybrid-bound
/// certificate v2 reach their node over the hybrid IK suite on both hops and end to end.
#[tokio::test]
async fn the_end_state_fleet_admits_hybrid_clients() {
    let (agent, alice, bob, ca) = (id(), id(), id(), Ca::new_v2());
    let lab = end_state_fleet(agent, &alice, &ca).await;
    let (mut app, _t) = lab
        .session_with(&alice, lab.config_outer(None, HYBRID, HYBRID))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    let (cert, _) = ca.issue_hybrid(&bob.hybrid_public_key(), scope(&["web-01"]));
    let (mut app, _t) = lab
        .session_with(&bob, lab.config_outer(Some(&cert), HYBRID, HYBRID))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 2);
}

/// Attack (Downgrade, client → relay): the classical suite and `IKhfs` on the outer hop are
/// refused by the end-state relay, whatever the end-to-end suite.
#[tokio::test]
async fn the_end_state_fleet_refuses_classical_suites_on_the_client_hop() {
    let (agent, alice, ca) = (id(), id(), Ca::new_v2());
    let lab = end_state_fleet(agent, &alice, &ca).await;
    for outer in [CLASSIC, IKHFS] {
        for e2e in [HYBRID, CLASSIC] {
            assert!(
                lab.refused_with(&alice, &lab.config_outer(None, outer, e2e))
                    .await
                    .is_err(),
                "{outer:?} / {e2e:?}"
            );
        }
    }
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
}

/// Attack (Downgrade, end to end): over a hybrid outer hop, the classical suite and `IKhfs`
/// end to end are refused by the end-state agent.
#[tokio::test]
async fn the_end_state_fleet_refuses_classical_suites_end_to_end() {
    let log = Captured::default();
    let _guard = log.install();
    let (agent, alice, ca) = (id(), id(), Ca::new_v2());
    let lab = end_state_fleet(agent, &alice, &ca).await;
    for e2e in [CLASSIC, IKHFS] {
        assert!(
            lab.refused_with(&alice, &lab.config_outer(None, HYBRID, e2e))
                .await
                .is_err(),
            "{e2e:?}"
        );
    }
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
    // The relay admitted the client (hybrid hop); the agent refused it end to end.
    assert!(
        !log.events("session_established").is_empty(),
        "{}",
        log.text()
    );
}

/// Attack (Downgrade, agent → relay; A14-2): an agent outside the profile (an agent older than
/// Phase 7 ignores it) that pins the classical suite or `IKhfs` never registers with the
/// pq-only relay, so its node stays unreachable.
#[tokio::test]
async fn a_pq_only_relay_refuses_agents_outside_the_profile() {
    for agent_suite in [CLASSIC, IKHFS] {
        let (agent, alice, ca) = (id(), id(), Ca::new_v2());
        let mut files = FleetFiles::end_state(&agent, &alice, &ca);
        files.agent_pq_only = false;
        files.agent_relay_suite = agent_suite;
        let lab = start_fleet(load_fleet(&files, &agent).unwrap(), agent).await;
        assert!(
            lab.refused_with(&alice, &lab.config_outer(None, HYBRID, HYBRID))
                .await
                .is_err(),
            "{agent_suite:?}"
        );
        assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
    }
}

/// Attack (v1 identities and certificates): over the hybrid IK suite, a key that is neither
/// whitelisted nor certified, a certificate v1 (its CA is not pinned: the profile refuses v1
/// CAs) and a certificate v2 bound only to the classical identity are all refused, on the
/// relay and on the agent.
#[tokio::test]
async fn the_end_state_fleet_refuses_v1_identities_and_v1_certificates() {
    let log = Captured::default();
    let _guard = log.install();
    let (agent, alice, mallory, ca, old) = (id(), id(), id(), Ca::new_v2(), Ca::new());
    let lab = end_state_fleet(agent, &alice, &ca).await;
    let (v1, _) = old.issue(&mallory.public_key(), scope(&["web-01"]));
    let (classical_v2, _) = ca.issue(&mallory.public_key(), scope(&["web-01"]));
    for cert in [None, Some(&v1), Some(&classical_v2)] {
        assert!(
            lab.refused_with(&mallory, &lab.config_outer(cert, HYBRID, HYBRID))
                .await
                .is_err()
        );
    }
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
    let reasons = reasons(&log);
    assert!(
        reasons.iter().any(|r| r == "identity_downgrade"),
        "{reasons:?}"
    );
    // The certificate v2 bound to the classical identity only is refused by name; the
    // certificate v1 names a CA the relay does not pin, an unknown identity that the relay
    // counts in its aggregate (no per-event line).
}

/// Attack (review 0014, A14-3 and A14-5, on the network): under the profile, a reload that
/// re-admits a v1 identity (no `require_hybrid_identity`, mallory pinned by her X25519 key)
/// is refused by the loading code of both binaries, the end-state configuration stays in
/// force and mallory stays out. The same reload outside the profile is applied and lets her
/// in: the outcome on the wire depends on the profile.
#[tokio::test]
async fn a_reload_that_readmits_v1_identities_is_refused_under_the_profile() {
    for pq_only in [true, false] {
        let (agent, alice, mallory, ca) = (id(), id(), id(), Ca::new_v2());
        let end = FleetFiles::end_state(&agent, &alice, &ca);
        let files = if pq_only { end } else { end.without_profile() };
        let lab = start_fleet(load_fleet(&files, &agent).unwrap(), Arc::clone(&agent)).await;
        let readmit = edited(&files, |f| {
            f.policy = format!(
                "{}\n[[clients]]\nname = \"mallory\"\npublic_key = \"{}\"\nallow = [\"*\"]\n",
                f.policy
                    .replace("require_hybrid_identity = [\"agents\", \"clients\"]\n", ""),
                mallory.public_key()
            );
            f.clients = format!(
                "{}\n[[clients]]\nname = \"mallory\"\npublic_key = \"{}\"\n",
                f.clients
                    .replace("require_hybrid_identity = [\"clients\"]\n", ""),
                mallory.public_key()
            );
        });
        let (relay, agent_reload) = reload_fleet(&lab, &readmit, &agent);
        let session = lab
            .session_with(&mallory, lab.config_outer(None, HYBRID, HYBRID))
            .await;
        if pq_only {
            pq_only_error(&relay.unwrap_err());
            pq_only_error(&agent_reload.unwrap_err());
            assert!(session.is_err(), "mallory got in under the profile");
            assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
        } else {
            relay.unwrap();
            agent_reload.unwrap();
            let (mut app, _t) = session.unwrap();
            assert_alive(&mut app).await;
        }
    }
}

/// Spec (rollback, OPERATIONS §19.3), step by step in the documented order: clients, relays,
/// agents, and only then the §16 rollback. While `require_hybrid_identity` stays, a client
/// pinned by its v2 key cannot come back over the classical suite (`identity_downgrade`, on
/// the relay after step 2 and on the agent after step 3); after step 4 a v1 client gets in,
/// and a certificate bound to a hybrid identity still passes only over the hybrid IK suite
/// (`key_mismatch` over the classical one). There is no downgrade window.
#[tokio::test]
async fn the_rollback_follows_the_documented_order_without_a_downgrade_window() {
    let log = Captured::default();
    let _guard = log.install();
    let (agent, alice, bob, ca) = (id(), id(), id(), Ca::new_v2());
    let end = FleetFiles::end_state(&agent, &alice, &ca);
    let (bob_cert, _) = ca.issue_hybrid(&bob.hybrid_public_key(), scope(&["web-01"]));

    // Step 1, clients: `pq_only` removed from `client.toml`, nothing changes on the wire.
    let client = client_toml(&id(), &agent).replace("pq_only = true\n", "");
    let client = parse_client_settings("client.toml", Path::new("/etc/tcn"), &client).unwrap();
    assert!(!client.pq_only);

    // Step 2, relays: the profile off and the classical suite back in both sets. The policy
    // still requires hybrid identities.
    let step2 = edited(&end, |f| {
        f.relay_toml = format!(
            "[handshake]\npq_only = false\nagent_suites = [\"{HYBRID_NAME}\", \"{CLASSIC_NAME}\"]\nclient_suites = [\"{HYBRID_NAME}\", \"{CLASSIC_NAME}\"]\n"
        );
    });
    let lab = start_fleet(load_fleet(&step2, &agent).unwrap(), Arc::clone(&agent)).await;
    log.clear();
    assert!(
        lab.refused_with(&alice, &lab.config_outer(None, CLASSIC, HYBRID))
            .await
            .is_err()
    );
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
    assert!(
        reasons(&log).iter().any(|r| r == "identity_downgrade"),
        "step 2: {}",
        log.text()
    );
    let (mut app, _t) = lab
        .session_with(&alice, lab.config_outer(None, HYBRID, HYBRID))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    drop((app, lab));

    // Step 3, agents: `--pq-only` removed and the classical suite accepted end to end.
    // `clients.toml` still requires hybrid clients.
    let step3 = edited(&step2, |f| {
        f.agent_pq_only = false;
        f.agent_client_suites = AcceptedSuites::new([HYBRID, CLASSIC]).unwrap();
    });
    let lab = start_fleet(load_fleet(&step3, &agent).unwrap(), Arc::clone(&agent)).await;
    log.clear();
    assert!(
        lab.refused_with(&alice, &lab.config_outer(None, HYBRID, CLASSIC))
            .await
            .is_err()
    );
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
    assert!(
        reasons(&log).iter().any(|r| r == "identity_downgrade"),
        "step 3: {}",
        log.text()
    );
    // The relay admitted the hybrid hop; the refusal was the agent's.
    assert!(
        !log.events("session_established").is_empty(),
        "{}",
        log.text()
    );
    drop(lab);

    // Step 4, the §16 rollback: `require_hybrid_identity` removed, alice back to her v1 key.
    // The composite CA stays pinned.
    let step4 = edited(&step3, |f| {
        let v1 = |text: &str| {
            text.replace(
                &alice.hybrid_public_key().to_string(),
                &alice.public_key().to_string(),
            )
        };
        f.policy = v1(&f
            .policy
            .replace("require_hybrid_identity = [\"agents\", \"clients\"]\n", ""));
        f.clients = v1(&f
            .clients
            .replace("require_hybrid_identity = [\"clients\"]\n", ""));
    });
    let lab = start_fleet(load_fleet(&step4, &agent).unwrap(), Arc::clone(&agent)).await;
    log.clear();
    let (mut app, _t) = lab
        .session_with(&alice, lab.config_outer(None, CLASSIC, CLASSIC))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    assert!(
        lab.refused_with(&bob, &lab.config_outer(Some(&bob_cert), CLASSIC, CLASSIC))
            .await
            .is_err()
    );
    assert!(
        reasons(&log).iter().any(|r| r == "key_mismatch"),
        "step 4: {}",
        log.text()
    );
    let (mut app, _t) = lab
        .session_with(&bob, lab.config_outer(Some(&bob_cert), HYBRID, HYBRID))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 2);
}

// --- the sunset signal ----------------------------------------------------------------------

/// Spec (review 0014, A14-1): `outer_suites_confirmed` counts each suite under its own name.
/// In the end-state fleet every confirmed handshake is hybrid IK, and it is counted as such
/// (`agents_hybrid_ik`, `clients_hybrid_ik`); no field calls `IKhfs` "hybrid" any more.
#[tokio::test]
async fn the_sunset_audit_counts_hybrid_ik_handshakes() {
    let log = Captured::default();
    let _guard = log.install();
    let (agent, alice, ca) = (id(), id(), Ca::new_v2());
    let loaded = load_fleet(&FleetFiles::end_state(&agent, &alice, &ca), &agent).unwrap();
    let mut relay = relay_config();
    relay.suites = loaded.suites;
    relay.admission.summary_interval = std::time::Duration::from_secs(1);
    let lab = Lab::start_outer(
        agent,
        vec![(loaded.policy, relay)],
        loaded.clients,
        loaded.client_suites,
        loaded.relay_suite,
    )
    .await;
    let (mut app, _t) = lab
        .session_with(&alice, lab.config_outer(None, HYBRID, HYBRID))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    tokio::time::sleep(std::time::Duration::from_millis(1_600)).await;
    let lines = log.events("outer_suites_confirmed");
    assert!(!lines.is_empty(), "{}", log.text());
    let sum = |key: &str| lines.iter().filter_map(|l| number(l, key)).sum::<u64>();
    assert_eq!(sum("agents_hybrid_ik"), 1, "{lines:?}");
    assert_eq!(sum("clients_hybrid_ik"), 1, "{lines:?}");
    for key in [
        "agents_ik",
        "agents_ikhfs",
        "clients_ik",
        "clients_ikhfs",
        "agents_hybrid",
        "clients_hybrid",
        "agents_classical",
        "clients_classical",
    ] {
        assert_eq!(sum(key), 0, "{key}: {lines:?}");
    }
}
