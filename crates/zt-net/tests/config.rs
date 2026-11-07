//! Configurazione: input validi e input malevoli o sbagliati.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::Write;

use zt_crypto::Identity;
use zt_domain::NodeId;
use zt_net::config::{
    ConfigError, create_identity, load_identity, parse_authorized_clients, parse_known_nodes,
    parse_policy,
};

fn key() -> String {
    Identity::generate().unwrap().public_key().to_string()
}

#[test]
fn policy_grants_what_it_says_and_nothing_more() {
    let (agent, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let text = format!(
        r#"
        [[agents]]
        node = "web-01"
        public_key = "{}"

        [[clients]]
        name = "ansible"
        public_key = "{}"
        allow = ["web-01"]
        "#,
        agent.public_key(),
        client.public_key()
    );
    let policy = parse_policy("t", &text).unwrap();
    let web = NodeId::try_from("web-01").unwrap();
    assert!(policy.may_open(&client.fingerprint(), &web));
    assert!(!policy.may_open(&agent.fingerprint(), &web));
}

#[test]
fn rejects_typos_unknown_fields_and_bad_values() {
    let k = key();
    let cases = [
        format!("[[agent]]\nnode = \"web\"\npublic_key = \"{k}\""), // sezione sbagliata
        format!("[[agents]]\nnode = \"web\"\npublic_key = \"{k}\"\nrole = \"x\""), // campo sconosciuto
        format!("[[agents]]\nnode = \"Web\"\npublic_key = \"{k}\""), // NodeId non valido
        "[[agents]]\nnode = \"web\"\npublic_key = \"00\"".to_string(), // chiave corta
        format!("[[clients]]\nname = \"a\"\npublic_key = \"{k}\"\nallow = [\"../etc\"]"),
        format!(
            "[[agents]]\nnode = \"a\"\npublic_key = \"{k}\"\n[[agents]]\nnode = \"b\"\npublic_key = \"{k}\""
        ), // chiave duplicata
        format!(
            "[[agents]]\nnode = \"a\"\npublic_key = \"{k}\"\n[[clients]]\nname = \"c\"\npublic_key = \"{k}\""
        ), // due ruoli
    ];
    for text in cases {
        assert!(parse_policy("t", &text).is_err(), "accepted:\n{text}");
    }
}

#[test]
fn empty_allow_list_grants_nothing() {
    let client = Identity::generate().unwrap();
    let text = format!(
        "[[clients]]\nname = \"c\"\npublic_key = \"{}\"",
        client.public_key()
    );
    let policy = parse_policy("t", &text).unwrap();
    assert!(!policy.may_open(&client.fingerprint(), &NodeId::try_from("web-01").unwrap()));
}

#[test]
fn authorized_clients_and_known_nodes_parse() {
    let c = Identity::generate().unwrap();
    let clients = parse_authorized_clients(
        "t",
        &format!(
            "[[clients]]\nname = \"c\"\npublic_key = \"{}\"",
            c.public_key()
        ),
    )
    .unwrap();
    assert!(clients.contains(&c.fingerprint()));
    let k = key();
    let nodes = parse_known_nodes(
        "t",
        &format!("[[nodes]]\nnode = \"web-01\"\npublic_key = \"{k}\""),
    )
    .unwrap();
    assert_eq!(nodes.len(), 1);
    let dup = format!(
        "[[nodes]]\nnode = \"a\"\npublic_key = \"{k}\"\n[[nodes]]\nnode = \"a\"\npublic_key = \"{k}\""
    );
    assert!(parse_known_nodes("t", &dup).is_err());
}

#[cfg(unix)]
#[test]
fn secret_keys_require_private_permissions_and_are_never_overwritten() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("zt-config-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("id.key");
    let _ = std::fs::remove_file(&path);

    let created = create_identity(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        load_identity(&path).unwrap().fingerprint(),
        created.fingerprint()
    );
    assert!(
        create_identity(&path).is_err(),
        "must not overwrite an existing key"
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        load_identity(&path),
        Err(ConfigError::InsecurePermissions(_))
    ));

    let big = dir.join("big.toml");
    let mut f = std::fs::File::create(&big).unwrap();
    f.write_all(&vec![b'#'; 2 * 1024 * 1024]).unwrap();
    assert!(matches!(
        zt_net::config::load_policy(&big),
        Err(ConfigError::TooLarge(_))
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

// ======================= Fase 3: configurazione del client =======================

fn client_toml(relay_key: &str, extra: &str) -> String {
    format!(
        "relay = \"relay.example.org:7443\"\nrelay_key = \"{relay_key}\"\nkey = \"client.key\"\n{extra}"
    )
}

#[test]
fn client_settings_parse_and_resolve_the_key_next_to_the_file() {
    let (r, n) = (key(), key());
    let text = client_toml(
        &r,
        &format!("[[nodes]]\nnode = \"web-01\"\npublic_key = \"{n}\""),
    );
    let base = std::path::Path::new("/etc/tcn");
    let s = zt_net::config::parse_client_settings("t", base, &text).unwrap();
    assert_eq!(s.relay, "relay.example.org:7443");
    assert_eq!(s.relay_key.to_string(), r);
    assert_eq!(s.key, base.join("client.key"));
    let web = NodeId::try_from("web-01").unwrap();
    let cfg = s.client_config(&web, zt_net::Timeouts::default()).unwrap();
    assert_eq!(cfg.node, web);
    assert_eq!(cfg.node_key.to_string(), n);

    // Un percorso assoluto resta tale.
    let abs = text.replace("key = \"client.key\"", "key = \"/secrets/c.key\"");
    let s = zt_net::config::parse_client_settings("t", base, &abs).unwrap();
    assert_eq!(s.key, std::path::PathBuf::from("/secrets/c.key"));
}

#[test]
fn client_settings_have_no_trust_on_first_use() {
    // Un nodo che non è in [[nodes]] non ha chiave pinnata: niente connessione.
    let text = client_toml(
        &key(),
        &format!("[[nodes]]\nnode = \"web-01\"\npublic_key = \"{}\"", key()),
    );
    let s = zt_net::config::parse_client_settings("t", std::path::Path::new("/"), &text).unwrap();
    let db = NodeId::try_from("db-01").unwrap();
    assert!(matches!(
        s.client_config(&db, zt_net::Timeouts::default()),
        Err(ConfigError::UnknownNode(_))
    ));
}

#[test]
fn client_settings_reject_typos_and_bad_values() {
    let (r, n) = (key(), key());
    let node = format!("[[nodes]]\nnode = \"web-01\"\npublic_key = \"{n}\"");
    let cases = [
        client_toml(&r, &format!("{node}\nport = 22")), // campo sconosciuto nel nodo
        format!("{}\nproxy = \"x\"", client_toml(&r, "")), // campo sconosciuto in radice
        client_toml("00", &node),                       // chiave del relay corta
        client_toml(&r, &node.replace("web-01", "Web-01")), // NodeId non valido
        client_toml(&r, &format!("{node}\n{node}")),    // nodo duplicato
        client_toml(&r, &node).replace("relay.example.org:7443", ""), // relay vuoto
        client_toml(&r, &node).replace("relay.example.org:7443", "relay.example.org"), // senza porta
        client_toml(&r, &node).replace("key = \"client.key\"\n", ""), // chiave mancante
        client_toml(&r, &node).replace("key = \"client.key\"", "key = \"\""), // chiave vuota
        client_toml(&r, &node).replace(&format!("relay_key = \"{r}\"\n"), ""), // niente pin del relay
    ];
    for text in cases {
        assert!(
            zt_net::config::parse_client_settings("t", std::path::Path::new("/"), &text).is_err(),
            "accepted:\n{text}"
        );
    }
}

#[test]
fn client_relay_key_cannot_be_reused_as_a_node_key() {
    // Una chiave pinnata due volte con ruoli diversi è quasi certamente un errore di copia.
    let r = key();
    let text = client_toml(
        &r,
        &format!("[[nodes]]\nnode = \"web-01\"\npublic_key = \"{r}\""),
    );
    assert!(zt_net::config::parse_client_settings("t", std::path::Path::new("/"), &text).is_err());
}

/// Attacco: chi può scrivere un file di trust (pin delle chiavi, policy, client autorizzati)
/// può sostituire una chiave e mettersi in mezzo. Come OpenSSH con `StrictModes`, un file
/// scrivibile da gruppo o altri viene rifiutato.
#[cfg(unix)]
#[test]
fn trust_files_writable_by_others_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("zt-config-trust-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let k = key();
    let files = [
        (
            "client.toml",
            client_toml(
                &key(),
                &format!("[[nodes]]\nnode = \"web-01\"\npublic_key = \"{k}\""),
            ),
        ),
        (
            "policy.toml",
            format!("[[agents]]\nnode = \"web-01\"\npublic_key = \"{k}\""),
        ),
        (
            "clients.toml",
            format!("[[clients]]\nname = \"c\"\npublic_key = \"{k}\""),
        ),
        (
            "nodes.toml",
            format!("[[nodes]]\nnode = \"web-01\"\npublic_key = \"{k}\""),
        ),
    ];
    for (name, text) in &files {
        std::fs::write(dir.join(name), text).unwrap();
    }
    let load = |name: &str| -> Result<(), ConfigError> {
        let p = dir.join(name);
        match name {
            "client.toml" => zt_net::config::load_client_settings(&p).map(drop),
            "policy.toml" => zt_net::config::load_policy(&p).map(drop),
            "clients.toml" => zt_net::config::load_authorized_clients(&p).map(drop),
            _ => zt_net::config::load_known_nodes(&p).map(drop),
        }
    };
    for (name, _) in &files {
        let p = dir.join(name);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        load(name).unwrap_or_else(|e| panic!("{name} 0644 refused: {e}"));
        for mode in [0o664, 0o646, 0o666] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(load(name), Err(ConfigError::WritableByOthers(_))),
                "{name} accepted with mode {mode:o}"
            );
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
