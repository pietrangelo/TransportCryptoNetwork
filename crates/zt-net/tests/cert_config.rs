//! Phase 6, step 5: certificate configuration (PROTOCOL §15.8, §15.9; OPERATIONS §10):
//! `[[authorities]]` in the policy and in `clients.toml`, the `revoked.toml` denylist, the
//! client certificate file and the CA key file.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::format_push_string
)]

use std::fmt::Write as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use zt_crypto::{CaSigningKey, Identity};
use zt_domain::limits::{DEFAULT_AUTHORITY_LIFETIME_SECS, MAX_REVOKED_KEYS, MAX_REVOKED_SERIALS};
use zt_domain::{AllowedNodes, CertSerial, NodeId};
use zt_net::config::{
    ConfigError, create_ca_key, load_authorized_clients, load_ca_key, load_certificate,
    load_identity, load_policy, load_relay_policy, parse_authorized_clients,
    parse_certificate_file, parse_client_settings, parse_policy, parse_revocations,
};

/// The reference vector from PROTOCOL §15.13 (valid format).
const REF_CERT_HEX: &str = concat!(
    "54434e4301018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf374",
    "8801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df6",
    "0f5b8fc9b3940102030405060708090a0b0c0d0e0f10000000006b49d2000000",
    "00006b49e01005616c69636500020564622d3031067765622d3031659fa00c94",
    "7c7c513c256db9673ba40a895ee8adba9e4da97e578f6743f976ac5301b6aad1",
    "203e4a03a87dd2cffca22d964126ae7d5b26a9d16067697e5b530f",
);

/// Weak or non-canonical Ed25519 keys, in hexadecimal.
const BAD_KEYS: [&str; 4] = [
    // Identity (order 1).
    "0100000000000000000000000000000000000000000000000000000000000000",
    // Non-canonical identity (y = p + 1).
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // Identity with the sign bit set (x = 0): non-canonical.
    "0100000000000000000000000000000000000000000000000000000000000080",
    // Order 8.
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
];

fn key() -> String {
    Identity::generate().unwrap().public_key().to_string()
}
fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Temporary `0755` directory, deleted at the end.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "zt-cert-config-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
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

fn authority(name: &str, keys: &[&str], allow: &str, extra: &str) -> String {
    let keys = match keys {
        [one] => format!("public_key = \"{one}\""),
        many => format!(
            "public_keys = [{}]",
            many.iter()
                .map(|k| format!("\"{k}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    format!("[[authorities]]\nname = \"{name}\"\n{keys}\nallow = {allow}\n{extra}\n")
}

/// Policy with a `web-01` agent, a whitelisted client and `authorities`.
fn policy_text(authorities: &str) -> String {
    format!(
        "[[agents]]\nnode = \"web-01\"\npublic_key = \"{}\"\n\n[[clients]]\nname = \"ansible\"\npublic_key = \"{}\"\nallow = [\"web-01\"]\n\n{authorities}",
        key(),
        key()
    )
}

fn clients_text(authorities: &str) -> String {
    format!(
        "[[clients]]\nname = \"ansible\"\npublic_key = \"{}\"\n\n{authorities}",
        key()
    )
}

fn serial_hex(b: u8) -> String {
    hex::encode([b; 16])
}

// ======================= specification =======================

#[test]
fn authorities_parse_with_one_or_two_keys() {
    let (a, b, c) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    let text = policy_text(&format!(
        "{}{}",
        authority(
            "ops-ca",
            &[&a.public_key().to_string()],
            "[\"web-01\", \"web-02\"]",
            "max_lifetime = 3600"
        ),
        authority(
            "deploy-ca",
            &[&b.public_key().to_string(), &c.public_key().to_string()],
            "[\"*\"]",
            ""
        ),
    ));
    let policy = parse_policy("policy.toml", &text).unwrap();
    let trust = policy.cert_trust();
    let all: Vec<_> = trust.authorities().collect();
    assert_eq!(all.len(), 2);
    let ops = all.iter().find(|x| x.name() == &node("ops-ca")).unwrap();
    assert_eq!(ops.keys().len(), 1);
    assert_eq!(ops.keys()[0].fingerprint, a.fingerprint());
    assert_eq!(ops.keys()[0].key.as_bytes(), &a.public_key().to_bytes());
    assert_eq!(
        ops.allowed(),
        &AllowedNodes::Only([node("web-01"), node("web-02")].into_iter().collect())
    );
    assert_eq!(ops.max_lifetime_secs(), 3600);
    let deploy = all.iter().find(|x| x.name() == &node("deploy-ca")).unwrap();
    assert_eq!(deploy.keys().len(), 2);
    assert_eq!(deploy.allowed(), &AllowedNodes::All);
    assert_eq!(trust.rotations_pending().count(), 1);

    // Never both forms, never neither.
    let k = key();
    for bad in [
        format!(
            "[[authorities]]\nname = \"x\"\npublic_key = \"{k}\"\npublic_keys = [\"{}\"]\nallow = [\"*\"]\n",
            key()
        ),
        "[[authorities]]\nname = \"x\"\nallow = [\"*\"]\n".to_owned(),
        "[[authorities]]\nname = \"x\"\npublic_keys = []\nallow = [\"*\"]\n".to_owned(),
    ] {
        assert!(
            parse_policy("policy.toml", &policy_text(&bad)).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn max_lifetime_defaults_to_eight_hours() {
    let text = policy_text(&authority("ops-ca", &[&key()], "[\"*\"]", ""));
    let policy = parse_policy("policy.toml", &text).unwrap();
    let ops = policy.cert_trust().authorities().next().unwrap();
    assert_eq!(ops.max_lifetime_secs(), DEFAULT_AUTHORITY_LIFETIME_SECS);
    assert_eq!(ops.max_lifetime_secs(), 28_800);
}

#[test]
fn revocations_parse_serials_and_keys() {
    let lost = Identity::generate().unwrap();
    let text = format!(
        "serials = [\"{}\", \"{}\"]\nkeys = [\"{}\"]\n",
        serial_hex(0x3f),
        serial_hex(0x40),
        lost.public_key()
    );
    let revoked = parse_revocations("revoked.toml", &text).unwrap();
    assert_eq!(revoked.counts(), (2, 1));
    assert!(revoked.is_serial_revoked(&CertSerial::try_from([0x3f; 16]).unwrap()));
    assert!(!revoked.is_serial_revoked(&CertSerial::try_from([0x41; 16]).unwrap()));
    assert!(revoked.is_key_revoked(&lost.fingerprint()));
    assert!(!revoked.is_key_revoked(&Identity::generate().unwrap().fingerprint()));
    // The empty file and the one with the empty lists from OPERATIONS §10.2 are valid.
    for empty in ["", "serials = []\nkeys = []\n"] {
        assert_eq!(
            parse_revocations("revoked.toml", empty).unwrap().counts(),
            (0, 0)
        );
    }
}

#[test]
fn the_same_authorities_block_works_for_relay_and_agent() {
    let ca = Identity::generate().unwrap();
    let block = authority(
        "ops-ca",
        &[&ca.public_key().to_string()],
        "[\"web-01\"]",
        "max_lifetime = 7200",
    );
    let policy = parse_policy("policy.toml", &policy_text(&block)).unwrap();
    let clients = parse_authorized_clients("clients.toml", &clients_text(&block)).unwrap();
    let relay_side = policy.cert_trust().authorities().next().unwrap();
    let agent_side = clients.cert_trust().authorities().next().unwrap();
    assert_eq!(relay_side, agent_side);
    assert_eq!(agent_side.keys()[0].fingerprint, ca.fingerprint());
    // In `clients.toml` the clients' `allow` is still ignored, the CAs' is not.
    assert_eq!(
        agent_side.allowed(),
        &AllowedNodes::Only([node("web-01")].into_iter().collect())
    );
}

#[test]
fn client_settings_resolve_the_certificate_next_to_the_file() {
    let text = format!(
        "relay = \"relay.example.org:7443\"\nrelay_key = \"{}\"\nkey = \"client.key\"\ncertificate = \"client.cert\"\n",
        key()
    );
    let base = Path::new("/home/alice/.config/tcn");
    let s = parse_client_settings("client.toml", base, &text).unwrap();
    assert_eq!(s.certificate, Some(base.join("client.cert")));
    let abs = text.replace("\"client.cert\"", "\"/etc/tcn/alice.cert\"");
    let s = parse_client_settings("client.toml", base, &abs).unwrap();
    assert_eq!(s.certificate, Some(PathBuf::from("/etc/tcn/alice.cert")));
    // Without the entry: no certificate.
    let none = text.replace("certificate = \"client.cert\"\n", "");
    assert_eq!(
        parse_client_settings("client.toml", base, &none)
            .unwrap()
            .certificate,
        None
    );
    // Empty: error, as for `key`.
    let empty = text.replace("\"client.cert\"", "\"\"");
    assert!(parse_client_settings("client.toml", base, &empty).is_err());
}

#[test]
fn ca_key_files_are_created_private_and_never_overwritten() {
    let dir = Dir::new("cakey");
    let path = dir.0.join("ops-ca.key");
    let created = create_ca_key(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with(CaSigningKey::FILE_PREFIX), "wrong format");
    assert_eq!(
        load_ca_key(&path).unwrap().public_key(),
        created.public_key()
    );
    // Never overwritten: the contents remain the previous ones.
    assert!(create_ca_key(&path).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    // The secret key rules apply here too.
    set_mode(&path, 0o640);
    assert!(matches!(
        load_ca_key(&path),
        Err(ConfigError::InsecurePermissions(_))
    ));
    set_mode(&path, 0o600);
    // It is not a node key, and a node key is not a CA.
    assert!(load_identity(&path).is_err());
    let node_key = dir.0.join("node.key");
    zt_net::config::create_identity(&node_key).unwrap();
    assert!(load_ca_key(&node_key).is_err());
}

// ======================= attacks =======================

#[test]
fn authorities_require_a_revocation_list() {
    let dir = Dir::new("required");
    let block = authority("ops-ca", &[&key()], "[\"*\"]", "");
    let policy = dir.write("policy.toml", &policy_text(&block));
    let clients = dir.write("clients.toml", &clients_text(&block));
    let revoked = dir.write("revoked.toml", "serials = []\nkeys = []\n");
    assert!(matches!(
        load_relay_policy(&policy, None),
        Err(ConfigError::RevocationsRequired(_))
    ));
    assert!(matches!(
        load_policy(&policy),
        Err(ConfigError::RevocationsRequired(_))
    ));
    assert!(matches!(
        load_authorized_clients(&clients, None),
        Err(ConfigError::RevocationsRequired(_))
    ));
    // With the denylist (even empty) it loads, and the denylist is in force.
    let p = load_relay_policy(&policy, Some(&revoked)).unwrap();
    assert!(!p.cert_trust().needs_revocations());
    assert_eq!(p.cert_trust().revocations().unwrap().counts(), (0, 0));
    let c = load_authorized_clients(&clients, Some(&revoked)).unwrap();
    assert!(!c.cert_trust().needs_revocations());
    // Without a CA the denylist remains optional, and can already be provided.
    let plain = dir.write("plain.toml", &policy_text(""));
    assert!(load_relay_policy(&plain, None).is_ok());
    assert!(load_relay_policy(&plain, Some(&revoked)).is_ok());
}

#[test]
fn authority_typos_and_bad_values_are_refused() {
    let k = key();
    let agent = Identity::generate().unwrap().public_key().to_string();
    let mut cases = vec![
        // Unknown field.
        format!(
            "[[authorities]]\nname = \"a\"\npublic_key = \"{k}\"\nallow = [\"*\"]\nscope = \"x\"\n"
        ),
        // Wrong section.
        format!("[[authority]]\nname = \"a\"\npublic_key = \"{k}\"\nallow = [\"*\"]\n"),
        // Invalid name.
        authority("Ops", &[&k], "[\"*\"]", ""),
        authority("", &[&k], "[\"*\"]", ""),
        // Invalid node in `allow`.
        authority("a", &[&k], "[\"../etc\"]", ""),
        authority("a", &[&k], "[\"Web-01\"]", ""),
        // `max_lifetime` outside 60..=86400.
        authority("a", &[&k], "[\"*\"]", "max_lifetime = 59"),
        authority("a", &[&k], "[\"*\"]", "max_lifetime = 86401"),
        authority("a", &[&k], "[\"*\"]", "max_lifetime = 0"),
        authority("a", &[&k], "[\"*\"]", "max_lifetime = -1"),
        // Three keys, repeated keys.
        authority("a", &[&k, &key(), &key()], "[\"*\"]", ""),
        authority("a", &[&k, &k], "[\"*\"]", ""),
        // Same name twice, same key in two entries.
        format!(
            "{}{}",
            authority("a", &[&k], "[\"*\"]", ""),
            authority("a", &[&key()], "[\"*\"]", "")
        ),
        format!(
            "{}{}",
            authority("a", &[&k], "[\"*\"]", ""),
            authority("b", &[&k], "[\"web-01\"]", "")
        ),
        // Short key.
        authority("a", &["00"], "[\"*\"]", ""),
    ];
    // Weak or non-canonical keys.
    for bad in BAD_KEYS {
        cases.push(authority("a", &[bad], "[\"*\"]", ""));
    }
    // 17 CAs.
    let mut many = String::new();
    for i in 0..17 {
        many.push_str(&authority(&format!("ca-{i}"), &[&key()], "[\"*\"]", ""));
    }
    cases.push(many);
    for block in &cases {
        assert!(
            parse_policy("policy.toml", &policy_text(block)).is_err(),
            "policy accepted:\n{block}"
        );
        assert!(
            parse_authorized_clients("clients.toml", &clients_text(block)).is_err(),
            "clients accepted:\n{block}"
        );
    }
    // A CA key equal to the key of an agent or of a client in the same file.
    let with_agent = format!(
        "[[agents]]\nnode = \"web-01\"\npublic_key = \"{agent}\"\n\n{}",
        authority("a", &[&agent], "[\"*\"]", "")
    );
    assert!(parse_policy("policy.toml", &with_agent).is_err());
    let with_client = format!(
        "[[clients]]\nname = \"c\"\npublic_key = \"{agent}\"\n\n{}",
        authority("a", &[&agent], "[\"*\"]", "")
    );
    assert!(parse_policy("policy.toml", &with_client).is_err());
    assert!(parse_authorized_clients("clients.toml", &with_client).is_err());
    // Check: 16 valid CAs are accepted.
    let mut sixteen = String::new();
    for i in 0..16 {
        sixteen.push_str(&authority(
            &format!("ca-{i}"),
            &[&key()],
            "[\"*\"]",
            "max_lifetime = 60",
        ));
    }
    assert_eq!(
        parse_policy("policy.toml", &policy_text(&sixteen))
            .unwrap()
            .cert_trust()
            .authorities()
            .count(),
        16
    );
}

#[test]
fn revocation_files_reject_bad_entries() {
    let good = format!(
        "serials = [\"{}\"]\nkeys = [\"{}\"]\n",
        serial_hex(7),
        key()
    );
    assert!(parse_revocations("revoked.toml", &good).is_ok());
    let mut cases = vec![
        format!("serials = [\"{}\"]\n", &serial_hex(7)[..31]),
        format!("serials = [\"{}0\"]\n", serial_hex(7)),
        format!("serials = [\"{}\"]\n", "zz".repeat(16)),
        format!("serials = [\"{}\"]\n", " ".repeat(32)),
        format!("serials = [\"{}\"]\n", "00".repeat(16)),
        "serials = [\"\"]\n".to_owned(),
        format!("serials = [\"0x{}\"]\n", &serial_hex(7)[..30]),
        format!("keys = [\"{}\"]\n", &key()[..63]),
        "keys = [\"not a key\"]\n".to_owned(),
        format!("serial = [\"{}\"]\n", serial_hex(7)),
        format!("serials = [\"{}\"]\nreason = \"lost\"\n", serial_hex(7)),
        "[[serials]]\nvalue = 1\n".to_owned(),
        "serials = 1\n".to_owned(),
    ];
    for bad in BAD_KEYS {
        cases.push(format!("keys = [\"{bad}\"]\n"));
    }
    // Over the limits.
    let mut serials = String::from("serials = [");
    for i in 0..=MAX_REVOKED_SERIALS {
        let _ = write!(serials, "\"{:032x}\",", i + 1);
    }
    serials.push_str("]\n");
    cases.push(serials);
    let mut keys = String::from("keys = [");
    for _ in 0..=MAX_REVOKED_KEYS {
        let _ = write!(keys, "\"{}\",", key());
    }
    keys.push_str("]\n");
    cases.push(keys);
    for text in &cases {
        assert!(
            parse_revocations("revoked.toml", text).is_err(),
            "accepted: {}",
            &text[..text.len().min(120)]
        );
    }
}

#[test]
fn certificate_files_reject_other_formats() {
    let good = format!("tcn-client-cert-v1:{REF_CERT_HEX}\n");
    let parsed = parse_certificate_file("client.cert", &good).unwrap();
    assert_eq!(parsed.bytes.len(), 187);
    assert_eq!(parsed.body.name(), &node("alice"));
    assert!(parse_certificate_file("client.cert", good.trim_end()).is_ok());
    let node_secret = Identity::generate().unwrap().to_secret_hex();
    let ca_secret = format!("tcn-ca-secret-v1:{}\n", "01".repeat(32));
    for bad in [
        format!("{}\n", node_secret.as_str()),
        ca_secret,
        format!("{good}{good}"),
        format!("{good}\n"),
        format!(" {good}"),
        format!("tcn-client-cert-v1: {REF_CERT_HEX}\n"),
        format!("tcn-client-cert-v1:{REF_CERT_HEX} \n"),
        format!("tcn-client-cert-v2:{REF_CERT_HEX}\n"),
        format!("tcn-ca-secret-v1:{REF_CERT_HEX}\n"),
        format!("{REF_CERT_HEX}\n"),
        // Valid text but malformed certificate (version 2).
        format!(
            "tcn-client-cert-v1:{}02{}\n",
            &REF_CERT_HEX[..8],
            &REF_CERT_HEX[10..]
        ),
        String::new(),
    ] {
        assert!(
            parse_certificate_file("client.cert", &bad).is_err(),
            "a malformed certificate file was accepted"
        );
    }
}

#[test]
fn certificate_and_revocation_files_follow_trust_file_rules() {
    let dir = Dir::new("rules");
    let cert = dir.write(
        "client.cert",
        &format!("tcn-client-cert-v1:{REF_CERT_HEX}\n"),
    );
    let policy = dir.write(
        "policy.toml",
        &policy_text(&authority("ops-ca", &[&key()], "[\"*\"]", "")),
    );
    let revoked = dir.write("revoked.toml", "serials = []\nkeys = []\n");
    assert!(load_certificate(&cert).is_ok());
    assert!(load_relay_policy(&policy, Some(&revoked)).is_ok());
    for mode in [0o664, 0o646, 0o666] {
        set_mode(&cert, mode);
        assert!(
            matches!(
                load_certificate(&cert),
                Err(ConfigError::WritableByOthers(_))
            ),
            "certificate {mode:o}"
        );
        set_mode(&revoked, mode);
        assert!(
            matches!(
                load_relay_policy(&policy, Some(&revoked)),
                Err(ConfigError::WritableByOthers(_))
            ),
            "revocations {mode:o}"
        );
    }
    set_mode(&cert, 0o644);
    set_mode(&revoked, 0o644);
    // A FIFO in place of the file is rejected without blocking.
    let fifo = dir.0.join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .args(["-m", "644"])
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let (f, p) = (fifo.clone(), policy.clone());
    std::thread::spawn(move || {
        let a = matches!(load_certificate(&f), Err(ConfigError::NotRegular(_)));
        let b = matches!(
            load_relay_policy(&p, Some(&f)),
            Err(ConfigError::NotRegular(_))
        );
        let _ = tx.send(a && b);
    });
    assert!(
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("open blocked on a FIFO")
    );
    // Directory writable by others.
    set_mode(&dir.0, 0o777);
    assert!(matches!(
        load_certificate(&cert),
        Err(ConfigError::InsecureDirectory(_))
    ));
    assert!(matches!(
        load_relay_policy(&policy, Some(&revoked)),
        Err(ConfigError::InsecureDirectory(_))
    ));
    set_mode(&dir.0, 0o755);
    // A file owned by another user: the same pure check as for trust files (finding 0003-1).
    let meta = std::fs::metadata(&cert).unwrap();
    if meta.uid() != 0 {
        assert!(matches!(
            zt_net::config::check_trusted(&meta, meta.uid() + 1, &cert, false),
            Err(ConfigError::UntrustedOwner(_))
        ));
    }
    // A huge certificate is rejected without reading all of it.
    let big = dir.write("big.cert", &"a".repeat(64 * 1024));
    assert!(load_certificate(&big).is_err());
}

#[test]
fn a_ca_secret_pasted_into_a_trust_file_is_not_echoed() {
    let secret_hex = "5c".repeat(32);
    let secret = format!("tcn-ca-secret-v1:{secret_hex}");
    // Check: without the secret the files are readable.
    assert!(parse_revocations("revoked.toml", "serials = []\n").is_ok());
    assert!(
        parse_certificate_file("client.cert", &format!("tcn-client-cert-v1:{REF_CERT_HEX}"))
            .is_ok()
    );
    for text in [
        format!("{secret}\n"),
        format!("{secret_hex}\n"),
        format!("serials = [\"{secret}\"]\n"),
        format!("serials = [\"{secret_hex}\"]\n"),
        format!("keys = [\"{secret_hex}\"]\n"),
        format!("{secret_hex} = 1\n"),
        format!("[[authorities]]\nname = \"x\"\npublic_key = \"{secret_hex}\"\nallow = [\"*\"]\n"),
        format!("[[authorities]]\nname = \"x\"\n{secret_hex} = \"\"\n"),
    ] {
        let errors = [
            parse_revocations("revoked.toml", &text).err(),
            parse_certificate_file("client.cert", &text).err(),
            parse_policy("policy.toml", &text).err(),
            parse_authorized_clients("clients.toml", &text).err(),
            parse_client_settings("client.toml", Path::new("/etc/tcn"), &text).err(),
        ];
        assert!(
            errors.iter().all(Option::is_some),
            "a pasted secret was accepted"
        );
        for err in errors.into_iter().flatten() {
            let message = err.to_string();
            assert!(
                !message.contains(&secret_hex),
                "an error message echoed the pasted secret"
            );
            assert!(
                !message.contains("5c5c5c5c5c5c5c5c"),
                "an error message echoed the pasted secret"
            );
        }
    }
}

#[test]
fn an_invalid_revocation_file_fails_the_whole_load() {
    let dir = Dir::new("whole");
    let block = authority("ops-ca", &[&key()], "[\"*\"]", "");
    let policy = dir.write("policy.toml", &policy_text(&block));
    let clients = dir.write("clients.toml", &clients_text(&block));
    let good = dir.write(
        "revoked.toml",
        &format!("serials = [\"{}\"]\n", serial_hex(9)),
    );
    let p = load_relay_policy(&policy, Some(&good)).unwrap();
    assert_eq!(p.cert_trust().revocations().unwrap().counts(), (1, 0));
    assert!(load_authorized_clients(&clients, Some(&good)).is_ok());
    let broken = dir.write("broken.toml", "serials = [\"not hex\"]\n");
    let err = load_relay_policy(&policy, Some(&broken)).unwrap_err();
    assert!(err.to_string().contains("broken.toml"), "{err}");
    assert!(load_authorized_clients(&clients, Some(&broken)).is_err());
    // And the reverse: valid denylist, broken policy.
    let bad_policy = dir.write("bad.toml", "[[agents]]\nnode = \"BAD\"\n");
    assert!(load_relay_policy(&bad_policy, Some(&good)).is_err());
    // A missing denylist is an error, not an empty denylist.
    assert!(load_relay_policy(&policy, Some(&dir.0.join("missing.toml"))).is_err());
}

/// Finding 0006-1: a CA with the key of a pinned relay (or of the agent, current or previous)
/// is rejected; the message says which role the key has. Positive check: another CA passes.
#[test]
fn an_authority_equal_to_a_relay_or_own_key_is_refused() {
    use zt_net::config::{ForbiddenKey, own_keys, reject_infrastructure_keys_as_authority};
    let relay = Identity::generate().unwrap();
    let (agent, old) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let (agent_pk, old_pk) = (agent.public_key(), old.public_key());
    let keyring = zt_crypto::Keyring::rotating(agent, old).unwrap();
    let mut forbidden = own_keys(&keyring, "agent");
    forbidden.push(ForbiddenKey {
        fingerprint: relay.fingerprint(),
        role: "relay",
    });
    for (ca, role) in [
        (relay.public_key(), "relay"),
        (agent_pk, "agent"),
        (old_pk, "agent"),
    ] {
        let block = authority("ops-ca", &[&ca.to_string()], "[\"*\"]", "");
        let clients = parse_authorized_clients("clients.toml", &clients_text(&block)).unwrap();
        let err = reject_infrastructure_keys_as_authority(
            "clients.toml",
            clients.cert_trust(),
            &forbidden,
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::AuthorityIsInfrastructureKey { ref ca, .. } if *ca == ca_fp(&block)),
            "{err:?}"
        );
        assert!(
            err.to_string()
                .contains(&format!("authority key equals the {role} key")),
            "{err}"
        );
    }
    let block = authority("ops-ca", &[&key()], "[\"*\"]", "");
    let clients = parse_authorized_clients("clients.toml", &clients_text(&block)).unwrap();
    reject_infrastructure_keys_as_authority("clients.toml", clients.cert_trust(), &forbidden)
        .unwrap();
}

/// The fingerprint of the only CA in an `[[authorities]]` block.
fn ca_fp(block: &str) -> zt_domain::Fingerprint {
    let clients = parse_authorized_clients("clients.toml", &clients_text(block)).unwrap();
    clients.cert_trust().ca_fingerprints().next().unwrap()
}
