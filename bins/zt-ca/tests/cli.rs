//! Fase 6, passo 9: la CLI di `zt-ca` (OPERATIONS §10.1, §10.3, §10.5; PROTOCOL §15.1, §15.2).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::type_complexity
)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use zt_crypto::{CERT_FILE_PREFIX, CaSigningKey, Identity, PublicKey};

const BIN: &str = env!("CARGO_BIN_EXE_zt-ca");

/// Chiavi Ed25519 deboli o non canoniche (come in `zt-net/tests/cert_config.rs`).
const BAD_KEYS: [&str; 4] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
];

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Directory di lavoro `0700` della macchina della CA, cancellata alla fine.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "zt-ca-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn arg(&self, name: &str) -> String {
        self.path(name).to_str().unwrap().to_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}
fn all(o: &Output) -> String {
    format!("{}{}", stdout(o), stderr(o))
}

/// Il valore di una riga `name = value` (o `name = "value"`) di stdout.
fn value(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == name).then(|| v.trim().trim_matches('"').to_owned())
    })
}

/// `zt-ca keygen` in `dir/ca.key`: la chiave pubblica stampata.
fn keygen(dir: &Dir) -> PublicKey {
    let out = run(&["keygen", "--out", &dir.arg("ca.key")]);
    assert!(out.status.success(), "{}", all(&out));
    value(&stdout(&out), "public_key")
        .unwrap_or_else(|| panic!("no public_key line: {}", stdout(&out)))
        .parse()
        .unwrap()
}

fn subject() -> String {
    Identity::generate().unwrap().public_key().to_string()
}

/// `zt-ca sign` con argomenti di default e `extra` al posto di quelli con lo stesso nome.
fn sign(dir: &Dir, out_name: &str, overrides: &[(&str, Option<&str>)]) -> Output {
    let (ca, log, out) = (dir.arg("ca.key"), dir.arg("issued.tsv"), dir.arg(out_name));
    let subject = subject();
    let mut args: Vec<(&str, Option<String>)> = vec![
        ("--ca", Some(ca)),
        ("--log", Some(log)),
        ("--subject", Some(subject)),
        ("--name", Some("alice".to_owned())),
        ("--nodes", Some("web-01,web-02".to_owned())),
        ("--validity", Some("8h".to_owned())),
        ("--out", Some(out)),
    ];
    for (flag, v) in overrides {
        if let Some(slot) = args.iter_mut().find(|(f, _)| f == flag) {
            slot.1 = v.map(str::to_owned);
        } else {
            args.push((flag, v.map(str::to_owned)));
        }
    }
    let mut command = vec!["sign".to_owned()];
    for (flag, v) in args {
        match v {
            Some(v) if v == "<flag>" => command.push(flag.to_owned()),
            Some(v) => {
                command.push(flag.to_owned());
                command.push(v);
            }
            None => {}
        }
    }
    let borrowed: Vec<&str> = command.iter().map(String::as_str).collect();
    run(&borrowed)
}

fn log_lines(dir: &Dir) -> Vec<String> {
    std::fs::read_to_string(dir.path("issued.tsv"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn is_hex32(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Spec (§10.1): file nuovo `0600` con il prefisso della CA; stdout con chiave e fingerprint;
/// un file esistente non è mai sovrascritto.
#[test]
fn keygen_creates_a_private_ca_key_and_prints_its_public_key() {
    let dir = Dir::new();
    let out = run(&["keygen", "--out", &dir.arg("ca.key")]);
    assert!(out.status.success(), "{}", all(&out));
    let text = stdout(&out);
    let key: PublicKey = value(&text, "public_key").unwrap().parse().unwrap();
    assert_eq!(
        value(&text, "fingerprint"),
        Some(key.fingerprint().to_string()),
        "{text}"
    );
    let meta = std::fs::metadata(dir.path("ca.key")).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o600);
    let secret = std::fs::read_to_string(dir.path("ca.key")).unwrap();
    assert!(
        secret.starts_with(CaSigningKey::FILE_PREFIX),
        "wrong prefix"
    );
    let ca = CaSigningKey::from_secret_text(&secret).unwrap();
    assert_eq!(ca.public_key(), key);
    // Il segreto non compare mai a terminale.
    let hex = secret.trim().trim_start_matches(CaSigningKey::FILE_PREFIX);
    assert!(!all(&out).contains(hex));

    // Mai sovrascritto.
    let again = run(&["keygen", "--out", &dir.arg("ca.key")]);
    assert!(!again.status.success());
    assert_eq!(std::fs::read_to_string(dir.path("ca.key")).unwrap(), secret);
}

/// Spec (§10.3, §10.5): `sign` scrive un file di certificato; `inspect --ca-key` ne conferma
/// la firma e i campi; con un'altra chiave di CA fallisce.
#[test]
fn sign_writes_a_certificate_that_inspect_verifies() {
    let dir = Dir::new();
    let ca = keygen(&dir);
    let subject_key = Identity::generate().unwrap().public_key();
    let subject_hex = subject_key.to_string();
    let out = sign(
        &dir,
        "alice.cert",
        &[
            ("--subject", Some(&subject_hex)),
            ("--validity", Some("90m")),
        ],
    );
    assert!(out.status.success(), "{}", all(&out));
    let text = stdout(&out);
    let serial = value(&text, "serial").unwrap();
    assert!(is_hex32(&serial), "{text}");
    assert_eq!(
        value(&text, "subject"),
        Some(subject_key.fingerprint().to_string())
    );
    let nb = value(&text, "not_before").unwrap();
    let na = value(&text, "not_after").unwrap();
    assert!(nb.ends_with('Z') && nb.contains('T'), "UTC dates: {text}");
    assert!(na.ends_with('Z') && na.contains('T'), "UTC dates: {text}");

    let file = std::fs::read_to_string(dir.path("alice.cert")).unwrap();
    assert!(file.starts_with(CERT_FILE_PREFIX));
    let bytes = zt_crypto::decode_certificate_text(&file).unwrap();
    let parsed = zt_domain::decode_certificate(&bytes).unwrap();
    assert_eq!(parsed.body.ca_key(), &zt_crypto::cert_key(&ca));
    assert_eq!(
        parsed.body.subject_key(),
        &zt_crypto::cert_key(&subject_key)
    );
    assert_eq!(parsed.body.serial().to_string(), serial);
    assert_eq!(parsed.body.lifetime_secs(), 90 * 60);

    let ok = run(&[
        "inspect",
        "--cert",
        &dir.arg("alice.cert"),
        "--ca-key",
        &ca.to_string(),
    ]);
    assert!(ok.status.success(), "{}", all(&ok));
    let shown = stdout(&ok);
    for field in ["alice", "web-01", "web-02", serial.as_str()] {
        assert!(shown.contains(field), "inspect misses {field}: {shown}");
    }
    assert!(
        shown.contains(&subject_key.fingerprint().to_string()),
        "{shown}"
    );

    let other = Identity::generate().unwrap().public_key().to_string();
    let bad = run(&[
        "inspect",
        "--cert",
        &dir.arg("alice.cert"),
        "--ca-key",
        &other,
    ]);
    assert!(!bad.status.success(), "inspect accepted the wrong CA key");
}

/// Spec (§10.3): una riga TSV per certificato, `0600`, prima di `--out`.
#[test]
fn sign_appends_one_line_per_certificate_to_the_log() {
    let dir = Dir::new();
    keygen(&dir);
    let first = sign(&dir, "a.cert", &[]);
    assert!(first.status.success(), "{}", all(&first));
    let second = sign(
        &dir,
        "b.cert",
        &[
            ("--name", Some("bob")),
            ("--nodes", None),
            ("--all-nodes", Some("<flag>")),
        ],
    );
    assert!(second.status.success(), "{}", all(&second));
    let meta = std::fs::metadata(dir.path("issued.tsv")).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o600);
    let lines = log_lines(&dir);
    assert_eq!(lines.len(), 2, "{lines:?}");
    for (line, out, name) in [(&lines[0], &first, "alice"), (&lines[1], &second, "bob")] {
        let cols: Vec<&str> = line.split('\t').collect();
        assert_eq!(cols.len(), 6, "{line}");
        assert_eq!(Some(cols[0].to_owned()), value(&stdout(out), "serial"));
        assert_eq!(Some(cols[1].to_owned()), value(&stdout(out), "subject"));
        assert_eq!(cols[2], name);
        let (nb, na): (u64, u64) = (cols[3].parse().unwrap(), cols[4].parse().unwrap());
        assert_eq!(na - nb, 8 * 3_600);
    }
    assert!(lines[0].split('\t').nth(5).unwrap().contains("web-01"));
    assert_ne!(lines[0].split('\t').next(), lines[1].split('\t').next());
}

/// Spec (§10.5): `inspect` stampa la riga da incollare nella denylist.
#[test]
fn inspect_prints_the_denylist_line() {
    let dir = Dir::new();
    keygen(&dir);
    let out = sign(&dir, "alice.cert", &[]);
    assert!(out.status.success(), "{}", all(&out));
    let serial = value(&stdout(&out), "serial").unwrap();
    let shown = run(&["inspect", "--cert", &dir.arg("alice.cert")]);
    assert!(shown.status.success(), "{}", all(&shown));
    assert!(
        stdout(&shown)
            .lines()
            .any(|l| l.trim() == format!("serials = [\"{serial}\"]")),
        "{}",
        stdout(&shown)
    );
}

/// A: `--out` esistente non è mai sovrascritto; soggetti deboli, non esadecimali o non
/// canonici sono rifiutati senza creare il certificato.
#[test]
fn sign_never_overwrites_and_refuses_bad_subjects() {
    let dir = Dir::new();
    keygen(&dir);
    std::fs::write(dir.path("taken.cert"), "keep me\n").unwrap();
    let out = sign(&dir, "taken.cert", &[]);
    assert!(!out.status.success());
    assert_eq!(
        std::fs::read_to_string(dir.path("taken.cert")).unwrap(),
        "keep me\n"
    );

    let short = "ab".repeat(31);
    let upper = subject().to_uppercase();
    let mut bad: Vec<&str> = BAD_KEYS.to_vec();
    bad.extend(["", "zz", short.as_str(), upper.as_str(), "SHA256:00"]);
    for (i, subject) in bad.iter().enumerate() {
        let name = format!("bad-{i}.cert");
        let out = sign(&dir, &name, &[("--subject", Some(subject))]);
        assert!(!out.status.success(), "accepted subject {subject:?}");
        assert!(
            !dir.path(&name).exists(),
            "certificate written for {subject:?}"
        );
    }
    // Controllo positivo.
    assert!(sign(&dir, "good.cert", &[]).status.success());
}

/// A: durate fuori da `1s..=24h` o non nel formato `n{s,m,h}`.
#[test]
fn sign_refuses_bad_durations() {
    let dir = Dir::new();
    keygen(&dir);
    let overflow = format!("{}h", u64::MAX);
    for (i, validity) in [
        "0s",
        "25h",
        "86401s",
        "1d",
        "-1h",
        "1h30m",
        "",
        "h",
        "8",
        "8 h",
        "+8h",
        "8H",
        overflow.as_str(),
    ]
    .iter()
    .enumerate()
    {
        let name = format!("d-{i}.cert");
        let out = sign(&dir, &name, &[("--validity", Some(validity))]);
        assert!(!out.status.success(), "accepted validity {validity:?}");
        assert!(!dir.path(&name).exists());
    }
    assert!(log_lines(&dir).is_empty(), "refused durations were logged");
    for (i, validity) in ["24h", "1440m", "60s"].iter().enumerate() {
        let out = sign(
            &dir,
            &format!("ok-{i}.cert"),
            &[("--validity", Some(validity))],
        );
        assert!(out.status.success(), "{validity}: {}", all(&out));
    }
}

/// A: il file di una chiave di nodo non è una CA (formati diversi, OPERATIONS §10.1).
#[test]
fn sign_refuses_a_node_key_as_ca() {
    let dir = Dir::new();
    keygen(&dir);
    let node_key = dir.path("node.key");
    let id = Identity::generate().unwrap();
    std::fs::write(&node_key, format!("{}\n", id.to_secret_hex().as_str())).unwrap();
    std::fs::set_permissions(&node_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = sign(
        &dir,
        "x.cert",
        &[("--ca", Some(node_key.to_str().unwrap()))],
    );
    assert!(!out.status.success());
    assert!(!dir.path("x.cert").exists());
    assert!(!all(&out).contains(id.to_secret_hex().as_str()));
    assert!(sign(&dir, "y.cert", &[]).status.success());
}

/// A: esattamente uno fra `--nodes` e `--all-nodes`; al massimo 64 nodi validi.
#[test]
fn sign_requires_exactly_one_of_nodes_and_all_nodes() {
    let dir = Dir::new();
    keygen(&dir);
    let sixty_five = (0..65)
        .map(|i| format!("n-{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let sixty_four = (0..64)
        .map(|i| format!("n-{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let cases: [(&str, Vec<(&str, Option<&str>)>); 7] = [
        ("neither", vec![("--nodes", None)]),
        ("both", vec![("--all-nodes", Some("<flag>"))]),
        ("65 nodes", vec![("--nodes", Some(&sixty_five))]),
        ("invalid node", vec![("--nodes", Some("web-01,Web_02"))]),
        ("empty node", vec![("--nodes", Some("web-01,,web-02"))]),
        ("duplicate node", vec![("--nodes", Some("web-01,web-01"))]),
        ("empty list", vec![("--nodes", Some(""))]),
    ];
    for (i, (what, overrides)) in cases.iter().enumerate() {
        let name = format!("s-{i}.cert");
        let out = sign(&dir, &name, overrides);
        assert!(!out.status.success(), "accepted: {what}");
        assert!(!dir.path(&name).exists(), "{what}");
    }
    assert!(log_lines(&dir).is_empty());
    let out = sign(&dir, "64.cert", &[("--nodes", Some(&sixty_four))]);
    assert!(out.status.success(), "{}", all(&out));
    let out = sign(
        &dir,
        "all.cert",
        &[("--nodes", None), ("--all-nodes", Some("<flag>"))],
    );
    assert!(out.status.success(), "{}", all(&out));
}

/// A: se la riga del registro non si scrive, il certificato non esiste.
#[test]
fn a_failed_log_write_creates_no_certificate() {
    let dir = Dir::new();
    keygen(&dir);
    // Un registro che è una directory, o in una directory inesistente.
    std::fs::create_dir(dir.path("log-dir")).unwrap();
    let missing = dir.path("missing").join("issued.tsv");
    for log in [dir.path("log-dir"), missing] {
        let out = sign(&dir, "x.cert", &[("--log", Some(log.to_str().unwrap()))]);
        assert!(!out.status.success());
        assert!(
            !dir.path("x.cert").exists(),
            "certificate without a log line"
        );
    }
    assert!(sign(&dir, "x.cert", &[]).status.success());
    assert_eq!(log_lines(&dir).len(), 1);
}

/// A: nessun errore stampa il segreto della CA (nemmeno un file di CA corrotto o una chiave di
/// CA passata dove si aspetta una chiave pubblica).
#[test]
fn errors_never_print_secret_material() {
    let dir = Dir::new();
    keygen(&dir);
    let secret = std::fs::read_to_string(dir.path("ca.key")).unwrap();
    let hex = secret
        .trim()
        .trim_start_matches(CaSigningKey::FILE_PREFIX)
        .to_owned();
    assert_eq!(hex.len(), 64);

    let mut failures = vec![
        sign(&dir, "a.cert", &[("--validity", Some("25h"))]),
        sign(&dir, "b.cert", &[("--subject", Some(&hex))]),
        sign(&dir, "c.cert", &[("--subject", Some(secret.trim()))]),
        sign(&dir, "d.cert", &[("--nodes", Some(&hex))]),
        sign(&dir, "e.cert", &[("--name", Some(&hex))]),
        sign(
            &dir,
            "f.cert",
            &[("--log", Some(dir.path("nope/x").to_str().unwrap()))],
        ),
        run(&["inspect", "--cert", &dir.arg("ca.key")]),
        run(&["inspect", "--cert", &dir.arg("missing"), "--ca-key", &hex]),
    ];
    // Un file di CA corrotto (un carattere in meno) e uno leggibile da tutti.
    let corrupt = dir.path("corrupt.key");
    std::fs::write(&corrupt, &secret[..secret.trim_end().len() - 1]).unwrap();
    std::fs::set_permissions(&corrupt, std::fs::Permissions::from_mode(0o600)).unwrap();
    failures.push(sign(
        &dir,
        "g.cert",
        &[("--ca", Some(corrupt.to_str().unwrap()))],
    ));
    let open = dir.path("open.key");
    std::fs::write(&open, &secret).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
    failures.push(sign(
        &dir,
        "h.cert",
        &[("--ca", Some(open.to_str().unwrap()))],
    ));

    let prefix_of_secret = &hex[..16];
    for out in &failures {
        assert!(!out.status.success(), "{}", all(out));
        let text = all(out);
        assert!(!text.contains(prefix_of_secret), "secret echoed: {text}");
        assert!(!text.is_empty(), "an error must say something");
    }
    assert!(!Path::new(&dir.path("a.cert")).exists());
}
