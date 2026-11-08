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
    assert_eq!(s.relays.len(), 1);
    assert_eq!(s.relays[0].address, "relay.example.org:7443");
    assert_eq!(s.relays[0].public_key.to_string(), r);
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

// ======================= regressioni adversary review 0003 =======================

/// 0003-1: un file di trust di un altro utente (non root) viene rifiutato anche se i bit di
/// modo sono corretti. Il controllo è puro, così si prova senza `chown`.
#[cfg(unix)]
#[test]
fn trust_files_owned_by_another_user_are_refused() {
    use std::os::unix::fs::MetadataExt;
    let dir = std::env::temp_dir().join(format!("zt-config-owner-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("f.toml");
    std::fs::write(&p, "").unwrap();
    let meta = std::fs::metadata(&p).unwrap();
    let owner = meta.uid();
    assert!(zt_net::config::check_trusted(&meta, owner, &p, false).is_ok());
    let stranger = if owner == 1234 { 4321 } else { 1234 };
    if owner != 0 {
        assert!(matches!(
            zt_net::config::check_trusted(&meta, stranger, &p, false),
            Err(ConfigError::UntrustedOwner(_))
        ));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 0003-1: un FIFO al posto del file bloccava per sempre `open`; ora è rifiutato subito.
#[cfg(unix)]
#[test]
fn non_regular_trust_and_key_files_are_refused_without_blocking() {
    let dir = std::env::temp_dir().join(format!("zt-config-fifo-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join("f.toml");
    let _ = std::fs::remove_file(&fifo);
    assert!(
        std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let path = fifo.clone();
    std::thread::spawn(move || {
        let a = matches!(
            zt_net::config::load_policy(&path),
            Err(ConfigError::NotRegular(_))
        );
        let b = matches!(
            zt_net::config::load_identity(&path),
            Err(ConfigError::NotRegular(_))
        );
        let c = matches!(
            zt_net::config::load_client_settings(&path),
            Err(ConfigError::NotRegular(_))
        );
        let _ = tx.send(a && b && c);
    });
    let ok = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("open blocked on a FIFO");
    assert!(ok);
    // Anche una directory non è un file di configurazione.
    assert!(matches!(
        zt_net::config::load_policy(&dir),
        Err(ConfigError::NotRegular(_))
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 0003-1: chi può scrivere nella directory può sostituire il file (rename), quindi la
/// directory che lo contiene deve essere protetta quanto il file.
#[cfg(unix)]
#[test]
fn trust_files_in_a_directory_writable_by_others_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("zt-config-dir-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let k = key();
    let p = dir.join("nodes.toml");
    std::fs::write(
        &p,
        format!("[[nodes]]\nnode = \"web-01\"\npublic_key = \"{k}\""),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    for mode in [0o755, 0o700] {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            zt_net::config::load_known_nodes(&p).is_ok(),
            "dir {mode:o} refused"
        );
    }
    for mode in [0o775, 0o757, 0o777, 0o1777] {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            matches!(
                zt_net::config::load_known_nodes(&p),
                Err(ConfigError::InsecureDirectory(_))
            ),
            "dir {mode:o} accepted"
        );
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Finding 0004-6 (dal fuzzer `config_parsers`): una chiave privata incollata per errore in un
/// file di trust non deve finire nel messaggio d'errore, e quindi nel journal.
#[test]
fn a_secret_pasted_into_a_trust_file_is_not_echoed_in_the_error() {
    let secret = Identity::generate().unwrap().to_secret_hex();
    let secret = secret.as_str();
    for text in [
        format!("{secret}\n"),
        format!("{secret} = 1\n"),
        format!(
            "[[clients]]\nname = \"x\"\npublic_key = \"k\"\nallow = [\"*\"]\n{secret} = \"\"\n"
        ),
    ] {
        for err in [
            parse_policy("policy.toml", &text).err(),
            parse_authorized_clients("clients.toml", &text).err(),
            parse_known_nodes("nodes.toml", &text).err(),
        ]
        .into_iter()
        .flatten()
        {
            let message = err.to_string();
            assert!(!message.contains(secret), "{message}");
        }
    }
}

// ======================= Fase 5: più relay e rotazione =======================

fn relays_toml(entries: &[(&str, &str)], extra: &str) -> String {
    use std::fmt::Write as _;
    let mut t = String::from("key = \"client.key\"\n");
    for (addr, k) in entries {
        let _ = write!(
            t,
            "\n[[relays]]\naddress = \"{addr}\"\npublic_key = \"{k}\"\n"
        );
    }
    t.push_str(extra);
    t
}

fn parse_client(text: &str) -> Result<zt_net::config::ClientSettings, ConfigError> {
    zt_net::config::parse_client_settings("t", std::path::Path::new("/etc/tcn"), text)
}

#[test]
fn a_client_lists_several_relays_in_order() {
    let (a, b) = (key(), key());
    let s = parse_client(&relays_toml(
        &[("r1.example.org:7443", &a), ("r2.example.org:7443", &b)],
        "",
    ))
    .unwrap();
    let got: Vec<_> = s
        .relays
        .iter()
        .map(|r| (r.address.as_str(), r.public_key.to_string()))
        .collect();
    assert_eq!(
        got,
        vec![("r1.example.org:7443", a), ("r2.example.org:7443", b)]
    );
}

#[test]
fn a_relay_list_must_be_unambiguous_and_bounded() {
    let (a, b) = (key(), key());
    // Entrambe le forme insieme, o nessuna.
    let both = format!(
        "relay = \"r0.example.org:7443\"\nrelay_key = \"{a}\"\n{}",
        relays_toml(&[("r1.example.org:7443", &b)], "")
    );
    assert!(parse_client(&both).is_err(), "relay and relays together");
    assert!(
        parse_client("key = \"client.key\"\n").is_err(),
        "no relay at all"
    );
    assert!(
        parse_client("relay = \"r.example.org:7443\"\nkey = \"client.key\"\n").is_err(),
        "relay without relay_key"
    );
    // Indirizzo o chiave ripetuti.
    assert!(
        parse_client(&relays_toml(
            &[("r1.example.org:7443", &a), ("r1.example.org:7443", &b)],
            ""
        ))
        .is_err()
    );
    assert!(
        parse_client(&relays_toml(
            &[("r1.example.org:7443", &a), ("r2.example.org:7443", &a)],
            ""
        ))
        .is_err()
    );
    // Indirizzo non valido.
    assert!(parse_client(&relays_toml(&[("r1.example.org", &a)], "")).is_err());
    // Al massimo MAX_RELAYS.
    let many: Vec<(String, String)> = (0..=zt_net::MAX_RELAYS)
        .map(|i| (format!("r{i}.example.org:7443"), key()))
        .collect();
    let refs: Vec<(&str, &str)> = many.iter().map(|(a, k)| (a.as_str(), k.as_str())).collect();
    assert!(
        parse_client(&relays_toml(&refs, "")).is_err(),
        "too many relays"
    );
    assert!(parse_client(&relays_toml(&refs[..zt_net::MAX_RELAYS], "")).is_ok());
}

#[test]
fn no_relay_key_may_double_as_a_node_key() {
    let (a, b) = (key(), key());
    let text = relays_toml(
        &[("r1.example.org:7443", &a), ("r2.example.org:7443", &b)],
        &format!("\n[[nodes]]\nnode = \"web-01\"\npublic_key = \"{b}\"\n"),
    );
    assert!(parse_client(&text).is_err());
}

#[test]
fn relay_endpoints_pair_addresses_and_keys() {
    use zt_crypto::PublicKey;
    let k = || key().parse::<PublicKey>().unwrap();
    let (a, b) = (k(), k());
    let addrs = |n: usize| {
        (0..n)
            .map(|i| format!("r{i}.example.org:7443"))
            .collect::<Vec<_>>()
    };
    let ok = zt_net::config::relay_endpoints("t", &addrs(2), &[a, b]).unwrap();
    assert_eq!(ok.len(), 2);
    assert_eq!(ok[1].public_key, b);
    assert!(
        zt_net::config::relay_endpoints("t", &addrs(2), &[a]).is_err(),
        "count mismatch"
    );
    assert!(
        zt_net::config::relay_endpoints("t", &[], &[]).is_err(),
        "empty"
    );
    assert!(
        zt_net::config::relay_endpoints("t", &addrs(2), &[a, a]).is_err(),
        "same key twice"
    );
    let nine: Vec<_> = (0..=zt_net::MAX_RELAYS).map(|_| k()).collect();
    assert!(zt_net::config::relay_endpoints("t", &addrs(nine.len()), &nine).is_err());
}

#[test]
fn a_rotating_agent_lists_two_keys_in_the_policy() {
    let (old, new) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let text = format!(
        "[[agents]]\nnode = \"web-01\"\npublic_keys = [\"{}\", \"{}\"]\n",
        new.public_key(),
        old.public_key()
    );
    let p = parse_policy("p", &text).unwrap();
    for k in [&old, &new] {
        assert!(p.role(&k.fingerprint()).is_some());
    }
}

#[test]
fn agent_key_lists_are_validated() {
    let (a, b, c) = (key(), key(), key());
    for bad in [
        format!("[[agents]]\nnode = \"web-01\"\npublic_key = \"{a}\"\npublic_keys = [\"{b}\"]\n"),
        format!("[[agents]]\nnode = \"web-01\"\npublic_keys = [\"{a}\", \"{b}\", \"{c}\"]\n"),
        format!("[[agents]]\nnode = \"web-01\"\npublic_keys = [\"{a}\", \"{a}\"]\n"),
        "[[agents]]\nnode = \"web-01\"\npublic_keys = []\n".to_owned(),
        "[[agents]]\nnode = \"web-01\"\n".to_owned(),
    ] {
        assert!(parse_policy("p", &bad).is_err(), "{bad}");
    }
}

#[cfg(unix)]
#[test]
fn a_keyring_loads_both_keys_and_refuses_the_same_key_twice() {
    let dir = std::env::temp_dir().join(format!("zt-keyring-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cur, prev) = (dir.join("cur.key"), dir.join("prev.key"));
    let c = create_identity(&cur).unwrap();
    let p = create_identity(&prev).unwrap();
    let ring = zt_net::config::load_keyring(&cur, Some(&prev)).unwrap();
    assert_eq!(ring.current().fingerprint(), c.fingerprint());
    assert_eq!(ring.previous().unwrap().fingerprint(), p.fingerprint());
    assert!(
        zt_net::config::load_keyring(&cur, None)
            .unwrap()
            .previous()
            .is_none()
    );
    assert!(zt_net::config::load_keyring(&cur, Some(&cur)).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}
