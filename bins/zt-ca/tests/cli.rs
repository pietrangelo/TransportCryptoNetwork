//! Phase 6, step 9: the `zt-ca` CLI (OPERATIONS §10.1, §10.3, §10.5; PROTOCOL §15.1, §15.2).
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

/// Weak or non-canonical Ed25519 keys (as in `zt-net/tests/cert_config.rs`).
const BAD_KEYS: [&str; 4] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
];

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// `0700` working directory of the CA machine, deleted at the end.
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

/// The value of a `name = value` (or `name = "value"`) line of stdout.
fn value(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == name).then(|| v.trim().trim_matches('"').to_owned())
    })
}

/// `zt-ca keygen` into `dir/ca.key`: the printed public key.
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

/// `zt-ca sign` with default arguments and `extra` in place of those with the same name.
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

/// Spec (§10.1): new `0600` file with the CA prefix; stdout with key and fingerprint; an
/// existing file is never overwritten.
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
    // The secret never appears on the terminal.
    let hex = secret.trim().trim_start_matches(CaSigningKey::FILE_PREFIX);
    assert!(!all(&out).contains(hex));

    // Never overwritten.
    let again = run(&["keygen", "--out", &dir.arg("ca.key")]);
    assert!(!again.status.success());
    assert_eq!(std::fs::read_to_string(dir.path("ca.key")).unwrap(), secret);
}

/// Spec (§10.3, §10.5): `sign` writes a certificate file; `inspect --ca-key` confirms its
/// signature and fields; with another CA key it fails.
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

/// Spec (§10.3): one TSV line per certificate, `0600`, before `--out`.
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
        // PQ-AUTH: the certificate version and the subject's hybrid fingerprint (`-`).
        assert_eq!(cols.len(), 8, "{line}");
        assert_eq!(cols[6], "v1");
        assert_eq!(cols[7], "-");
        assert_eq!(Some(cols[0].to_owned()), value(&stdout(out), "serial"));
        assert_eq!(Some(cols[1].to_owned()), value(&stdout(out), "subject"));
        assert_eq!(cols[2], name);
        let (nb, na): (u64, u64) = (cols[3].parse().unwrap(), cols[4].parse().unwrap());
        assert_eq!(na - nb, 8 * 3_600);
    }
    assert!(lines[0].split('\t').nth(5).unwrap().contains("web-01"));
    assert_ne!(lines[0].split('\t').next(), lines[1].split('\t').next());
}

/// Spec (§10.5): `inspect` prints the line to paste into the denylist.
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

/// A: an existing `--out` is never overwritten; weak, non-hex or non-canonical subjects are
/// rejected without creating the certificate.
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
    // Positive control.
    assert!(sign(&dir, "good.cert", &[]).status.success());
}

/// A: lifetimes outside `1s..=24h` or not in the `n{s,m,h}` format.
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

/// A: a node key file is not a CA (different formats, OPERATIONS §10.1).
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

/// A: exactly one of `--nodes` and `--all-nodes`; at most 64 valid nodes.
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

/// A: if the log line cannot be written, the certificate does not exist.
#[test]
fn a_failed_log_write_creates_no_certificate() {
    let dir = Dir::new();
    keygen(&dir);
    // A log that is a directory, or in a nonexistent directory.
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

/// A: no error prints the CA secret (not even a corrupted CA file or a CA key passed where a
/// public key is expected).
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
    // A corrupted CA file (one character short) and one readable by everyone.
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

/// Finding 0006-5: a `--log` equal to `--ca`, a symbolic link or a hard link to the key file,
/// or a copy of the key, is rejected without touching the key or creating the certificate.
/// Positive control: a separate log works and the CA still signs.
#[test]
fn an_issuance_log_that_is_the_ca_key_is_refused() {
    let dir = Dir::new();
    keygen(&dir);
    let before = std::fs::read(dir.path("ca.key")).unwrap();
    std::os::unix::fs::symlink(dir.path("ca.key"), dir.path("link.tsv")).unwrap();
    std::fs::hard_link(dir.path("ca.key"), dir.path("hard.tsv")).unwrap();
    std::fs::copy(dir.path("ca.key"), dir.path("copy.tsv")).unwrap();
    std::fs::set_permissions(dir.path("copy.tsv"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let copy_before = std::fs::read(dir.path("copy.tsv")).unwrap();
    // Also a symbolic link to a real log: the log does not follow links.
    std::fs::write(dir.path("real.tsv"), "").unwrap();
    std::fs::set_permissions(dir.path("real.tsv"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(dir.path("real.tsv"), dir.path("to-real.tsv")).unwrap();
    for (log, needle) in [
        ("ca.key", "CA key file"),
        ("link.tsv", "symbolic link"),
        ("hard.tsv", "CA key file"),
        ("copy.tsv", "looks like a CA key file"),
        ("to-real.tsv", "symbolic link"),
    ] {
        let out = sign(&dir, "a.cert", &[("--log", Some(&dir.arg(log)))]);
        assert!(!out.status.success(), "{log}: {}", all(&out));
        assert!(stderr(&out).contains(needle), "{log}: {}", all(&out));
        assert!(!dir.path("a.cert").exists(), "{log}");
    }
    assert_eq!(std::fs::read(dir.path("ca.key")).unwrap(), before);
    assert_eq!(std::fs::read(dir.path("copy.tsv")).unwrap(), copy_before);
    assert!(std::fs::read(dir.path("real.tsv")).unwrap().is_empty());
    let out = sign(&dir, "a.cert", &[]);
    assert!(out.status.success(), "{}", all(&out));
    let out = sign(&dir, "b.cert", &[]);
    assert!(
        out.status.success(),
        "the CA key still loads: {}",
        all(&out)
    );
}

// ======================= PQ-AUTH: composite CA, certificate v2 =======================

/// `zt-ca keygen --v2` into `dir/ca.key`: the printed composite public key.
fn keygen_v2(dir: &Dir) -> zt_crypto::CompositeCaPublicKey {
    let out = run(&["keygen", "--v2", "--out", &dir.arg("ca.key")]);
    assert!(out.status.success(), "{}", all(&out));
    value(&stdout(&out), "public_key")
        .unwrap_or_else(|| panic!("no public_key line: {}", stdout(&out)))
        .parse()
        .unwrap()
}

/// Spec (OPERATIONS §10.8): `keygen --v2` writes a `0600` `tcn-ca-secret-v2:` file and prints
/// the composite key, its fingerprint and `ca_fp`; the secret never reaches the terminal.
#[test]
fn keygen_v2_creates_a_composite_ca_key() {
    let dir = Dir::new();
    let out = run(&["keygen", "--v2", "--out", &dir.arg("ca.key")]);
    assert!(out.status.success(), "{}", all(&out));
    let text = stdout(&out);
    let key: zt_crypto::CompositeCaPublicKey = value(&text, "public_key").unwrap().parse().unwrap();
    assert_eq!(value(&text, "ca_fp"), Some(key.ca_fp().to_string()));
    assert_eq!(
        value(&text, "fingerprint"),
        Some(key.fingerprint().to_string())
    );
    let meta = std::fs::metadata(dir.path("ca.key")).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o600);
    let secret = std::fs::read_to_string(dir.path("ca.key")).unwrap();
    assert!(secret.starts_with(zt_crypto::CompositeCaSigningKey::FILE_PREFIX));
    let ca = zt_crypto::CompositeCaSigningKey::from_secret_text(&secret).unwrap();
    assert_eq!(ca.public_key(), key);
    let hex = secret
        .trim()
        .trim_start_matches(zt_crypto::CompositeCaSigningKey::FILE_PREFIX);
    assert!(!all(&out).contains(&hex[..64]));
    assert!(!all(&out).contains(&hex[64..]));
}

/// Spec: a composite CA signs certificates v2 (verified after signing), logged as `v2`;
/// `inspect` shows the version and verifies with the composite key, and refuses a v1 key.
#[test]
fn a_composite_ca_signs_v2_certificates_that_inspect_verifies() {
    let dir = Dir::new();
    let ca = keygen_v2(&dir);
    let subject_key = Identity::generate().unwrap().public_key();
    let subject_hex = subject_key.to_string();
    let out = sign(&dir, "alice.cert", &[("--subject", Some(&subject_hex))]);
    assert!(out.status.success(), "{}", all(&out));
    let file = std::fs::read_to_string(dir.path("alice.cert")).unwrap();
    assert!(file.starts_with(zt_crypto::CERT_FILE_PREFIX_V2));
    let bytes = zt_crypto::decode_certificate_text(&file).unwrap();
    let parsed = zt_domain::decode_certificate_v2(&bytes).unwrap();
    assert_eq!(parsed.body.ca_fp(), &ca.ca_fp());
    assert_eq!(
        parsed.body.subject().classical(),
        &subject_key.fingerprint()
    );
    let lines = log_lines(&dir);
    let cols: Vec<&str> = lines[0].split('\t').collect();
    assert_eq!(cols.len(), 8);
    assert_eq!(cols[1], subject_key.fingerprint().to_string());
    assert_eq!(cols[6], "v2");

    let ok = run(&[
        "inspect",
        "--cert",
        &dir.arg("alice.cert"),
        "--ca-key",
        &ca.to_string(),
    ]);
    assert!(ok.status.success(), "{}", all(&ok));
    let shown = stdout(&ok);
    assert_eq!(value(&shown, "version").as_deref(), Some("2"));
    assert_eq!(value(&shown, "ca_fp"), Some(ca.ca_fp().to_string()));
    assert!(shown.contains("signature   = verified"), "{shown}");
    // The composite's Ed25519 component alone, as a v1 key: not this certificate's CA.
    let ed_only = ca.ed25519().to_string();
    let bad = run(&[
        "inspect",
        "--cert",
        &dir.arg("alice.cert"),
        "--ca-key",
        &ed_only,
    ]);
    assert!(!bad.status.success(), "a v1 key verified a v2 certificate");
}

/// Attack: either 32-byte half of the composite secret pasted as `--subject` is refused (each
/// half has the shape of a public key), and a log that starts like a v2 key is refused.
#[test]
fn composite_secret_halves_are_never_certified() {
    let dir = Dir::new();
    keygen_v2(&dir);
    let secret = std::fs::read_to_string(dir.path("ca.key")).unwrap();
    let hex = secret
        .trim()
        .trim_start_matches(zt_crypto::CompositeCaSigningKey::FILE_PREFIX)
        .to_owned();
    for half in [&hex[..64], &hex[64..]] {
        let out = sign(&dir, "x.cert", &[("--subject", Some(half))]);
        // The ML-DSA seed half may not decode as a curve point at all: refused either way.
        assert!(!out.status.success());
        assert!(!all(&out).contains(half));
        assert!(!dir.path("x.cert").exists());
    }
    std::fs::copy(dir.path("ca.key"), dir.path("copy.tsv")).unwrap();
    std::fs::set_permissions(dir.path("copy.tsv"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = sign(&dir, "y.cert", &[("--log", Some(&dir.arg("copy.tsv")))]);
    assert!(!out.status.success(), "{}", all(&out));
}
