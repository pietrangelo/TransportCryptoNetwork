//! Configurazione: input validi e input malevoli o sbagliati.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

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
