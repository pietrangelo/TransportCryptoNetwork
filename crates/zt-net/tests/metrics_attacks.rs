//! R-5 observability, attacks and failures (resilience.md §7 R-5, review 0007 AP-21): label
//! injection, partial writes, the file's permissions and symlinks, cardinality, identities in
//! labels, write failures, a tampered file read by `status`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::format_collect,
    clippy::case_sensitive_file_extension_comparisons
)]

mod common;
mod observed;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use common::{agent_clients, relay_config, relay_policy};
use zt_crypto::Identity;
use zt_domain::Fingerprint;
use zt_domain::trust::CertTrust;
use zt_net::metrics::{
    self, AgentMetrics, RelayMetrics, Snapshot, StatusError, escape_label_value, write_textfile,
};

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zt-metrics-atk-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One sample line of the text format, strictly: a metric name, optional labels with quoted
/// values whose only escapes are `\\`, `\"` and `\n`, one value. Anything else (a raw newline,
/// an unbalanced quote, a second sample on the line) fails.
fn valid_sample(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut i = 0;
    let name_char = |c: u8, first: bool| {
        c.is_ascii_alphabetic() || c == b'_' || c == b':' || (!first && c.is_ascii_digit())
    };
    if bytes.is_empty() || !name_char(bytes[0], true) {
        return false;
    }
    while i < bytes.len() && name_char(bytes[i], i == 0) {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'{' {
        i += 1;
        loop {
            let start = i;
            while i < bytes.len() && name_char(bytes[i], i == start) {
                i += 1;
            }
            if i == start || i + 1 >= bytes.len() || bytes[i] != b'=' || bytes[i + 1] != b'"' {
                return false;
            }
            i += 2;
            loop {
                match bytes.get(i) {
                    None | Some(b'\n') => return false,
                    Some(b'\\') => match bytes.get(i + 1) {
                        Some(b'\\' | b'"' | b'n') => i += 2,
                        _ => return false,
                    },
                    Some(b'"') => {
                        i += 1;
                        break;
                    }
                    Some(_) => i += 1,
                }
            }
            match bytes.get(i) {
                Some(b',') => i += 1,
                Some(b'}') => {
                    i += 1;
                    break;
                }
                _ => return false,
            }
        }
    }
    if bytes.get(i) != Some(&b' ') {
        return false;
    }
    let value = &line[i + 1..];
    !value.contains(' ') && (value.parse::<f64>().is_ok() || value == "+Inf" || value == "NaN")
}

fn assert_well_formed(text: &str) {
    for line in text.lines() {
        if line.starts_with("# HELP ") || line.starts_with("# TYPE ") {
            continue;
        }
        assert!(valid_sample(line), "malformed line {line:?} in\n{text}");
    }
}

/// Label injection: a value carrying a quote, a backslash, a newline and a fake sample stays
/// one quoted value.
#[test]
fn label_values_are_escaped() {
    let evil = "x\"} 1\ntcn_fake_total 999\n\\";
    let escaped = escape_label_value(evil);
    assert!(!escaped.contains('\n'));
    let line = format!("tcn_test{{reason=\"{escaped}\"}} 1");
    assert!(valid_sample(&line), "{line}");
    let snap = Snapshot::parse(&format!("{line}\n")).unwrap();
    assert_eq!(snap.get("tcn_test", &[("reason", evil)]), Some(1.0));
    assert_eq!(snap.get("tcn_fake_total", &[]), None);
}

/// Every line the relay and the agent can write is well formed, whatever they counted.
#[test]
fn rendered_output_is_always_well_formed() {
    assert_well_formed(&RelayMetrics::new().render());
    assert_well_formed(&AgentMetrics::new(8).render());
    assert_well_formed(&metrics::ClientMetrics::new().render());
}

fn lab_policy(agent: &Fingerprint, client: &Identity) -> zt_domain::AccessPolicy {
    relay_policy(agent, &[client.fingerprint()], CertTrust::default())
}

/// R5-O2/R5-O3: no fingerprint, node name or address in the output, and the number of lines
/// does not grow with the number of peers or failures.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_identities_and_bounded_cardinality() {
    let client = Arc::new(Identity::generate().unwrap());
    let relay_metrics = RelayMetrics::new();
    let agent_metrics = AgentMetrics::new(1);
    let agent = Arc::new(Identity::generate().unwrap());
    let mut config = relay_config();
    config.metrics = Arc::clone(&relay_metrics);
    let lab = observed::start_observed(
        Arc::clone(&agent),
        vec![(lab_policy(&agent.fingerprint(), &client), config)],
        agent_clients(&[client.fingerprint()], CertTrust::default()),
        Arc::clone(&agent_metrics),
    )
    .await;
    let (_app, _task) = lab.session(&client, None).await.unwrap();
    let lines_before = relay_metrics.render().lines().count();
    let mut strangers = Vec::new();
    for _ in 0..20 {
        let s = Arc::new(Identity::generate().unwrap());
        assert!(lab.refused(&s, None).await.is_err());
        strangers.push(s);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let relay_text = relay_metrics.render();
    let agent_text = agent_metrics.render();
    assert_eq!(relay_text.lines().count(), lines_before, "{relay_text}");
    for text in [&relay_text, &agent_text] {
        for id in strangers.iter().chain([&client, &agent]) {
            let fp = id.fingerprint().to_string();
            assert!(!text.contains(&fp), "fingerprint in metrics:\n{text}");
            assert!(!text.contains(&fp[..16]), "fingerprint prefix in metrics");
        }
        assert!(!text.contains("web-01"), "node name in metrics:\n{text}");
        assert!(!text.contains("127.0.0.1"), "address in metrics:\n{text}");
    }
}

/// Partial writes: a reader polling the file while it is rewritten never sees a truncated or
/// mixed file, only one of the complete versions.
#[test]
fn readers_never_see_a_partial_file() {
    let dir = tmp("partial");
    let path = dir.join("relay.prom");
    let versions: Vec<String> = (0..4)
        .map(|v| {
            (0..5_000)
                .map(|i| format!("tcn_test_{i} {v}\n"))
                .collect::<String>()
        })
        .collect();
    write_textfile(&path, &versions[0]).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let (path, stop, versions) = (path.clone(), Arc::clone(&stop), versions.clone());
        std::thread::spawn(move || {
            let mut reads = 0_u32;
            while !stop.load(Ordering::Relaxed) {
                let text = std::fs::read_to_string(&path).unwrap();
                assert!(
                    versions.contains(&text),
                    "partial read of {} bytes",
                    text.len()
                );
                reads += 1;
            }
            reads
        })
    };
    for round in 0..200 {
        write_textfile(&path, &versions[round % versions.len()]).unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    assert!(reader.join().unwrap() > 0);
    let _ = std::fs::remove_dir_all(dir);
}

/// Permissions: whatever the umask and whatever was there before, the file is 0644 (readable by
/// `node_exporter`, writable only by the owner), never group- or world-writable.
#[test]
fn the_file_mode_is_fixed_and_never_writable_by_others() {
    let dir = tmp("mode");
    let path = dir.join("relay.prom");
    std::fs::write(&path, "old 1\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    write_textfile(&path, "new 1\n").unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o644);
    let _ = std::fs::remove_dir_all(dir);
}

/// A symlink planted at the metrics path is replaced, never followed: its target is not
/// overwritten.
#[test]
fn a_symlink_at_the_path_is_not_followed() {
    let dir = tmp("symlink");
    let victim = dir.join("victim");
    std::fs::write(&victim, "precious\n").unwrap();
    let path = dir.join("relay.prom");
    std::os::unix::fs::symlink(&victim, &path).unwrap();
    write_textfile(&path, "tcn_x 1\n").unwrap();
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious\n");
    assert!(!std::fs::symlink_metadata(&path).unwrap().is_symlink());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "tcn_x 1\n");
    let _ = std::fs::remove_dir_all(dir);
}

/// Symlinks planted at the temporary names an attacker can predict are not followed either.
#[test]
fn planted_temporary_names_are_not_followed() {
    let dir = tmp("plant");
    let victim = dir.join("victim");
    std::fs::write(&victim, "precious\n").unwrap();
    let pid = std::process::id();
    for n in 0..64 {
        let _ = std::os::unix::fs::symlink(&victim, dir.join(format!(".relay.prom.{pid}.{n}")));
        let _ = std::os::unix::fs::symlink(&victim, dir.join(format!(".relay.prom.tmp.{n}")));
    }
    let path = dir.join("relay.prom");
    // It may fail (every name taken), but it must never write through a link.
    let _ = write_textfile(&path, "tcn_x 1\n");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious\n");
    let _ = std::fs::remove_dir_all(dir);
}

/// The temporary file never ends in `.prom`: `node_exporter` must not read it half-written.
#[test]
fn the_temporary_file_is_invisible_to_node_exporter() {
    let dir = tmp("tmpname");
    let path = dir.join("relay.prom");
    let names = metrics::temporary_name(&path, 1).unwrap();
    let name = names.file_name().unwrap().to_string_lossy().into_owned();
    assert!(!name.ends_with(".prom"), "{name}");
    assert!(name.starts_with('.'), "{name}");
    assert_eq!(names.parent(), path.parent());
    let _ = std::fs::remove_dir_all(dir);
}

/// R5-O5: a write that fails (missing directory, read-only, disk full) is not fatal: the
/// exporter keeps going and writes again once it can.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_write_is_not_fatal() {
    let dir = tmp("fail");
    let sub = dir.join("later");
    let path = sub.join("agent.prom");
    let m = AgentMetrics::new(1);
    let task = tokio::spawn(metrics::export(
        path.clone(),
        Duration::from_millis(50),
        move || m.render(),
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!task.is_finished(), "the exporter gave up");
    std::fs::create_dir_all(&sub).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(path.exists(), "no write after the directory appeared");
    task.abort();
    let _ = std::fs::remove_dir_all(dir);
}

/// `status` on a tampered file prints no control character (no terminal escape injection).
#[test]
fn status_strips_control_characters() {
    let dir = tmp("ansi");
    let path = dir.join("relay.prom");
    let mut text = RelayMetrics::new().render();
    text.push_str("tcn_evil{reason=\"\u{1b}[2J\u{7}x\"} 1\n");
    write_textfile(&path, &text).unwrap();
    let report = metrics::status(&path, SystemTime::now()).unwrap();
    assert!(
        !report.text.chars().any(|c| c.is_control() && c != '\n'),
        "{:?}",
        report.text
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// `status` refuses a file larger than any it writes, without reading it whole.
#[test]
fn status_refuses_an_oversized_file() {
    let dir = tmp("huge");
    let path = dir.join("relay.prom");
    let f = std::fs::File::create(&path).unwrap();
    f.set_len(64 * 1024 * 1024).unwrap();
    let err = metrics::status(&path, SystemTime::now()).unwrap_err();
    assert!(matches!(err, StatusError::TooLarge), "{err:?}");
    let _ = std::fs::remove_dir_all(dir);
}

/// `status` on garbage reports it instead of trusting it: no timestamp, no verdict of fresh.
#[test]
fn status_of_a_garbled_file_is_an_error() {
    let dir = tmp("garbled");
    let path = dir.join("relay.prom");
    std::fs::write(&path, "this is { not metrics\n").unwrap();
    let err = metrics::status(&path, SystemTime::now()).unwrap_err();
    assert!(matches!(err, StatusError::Invalid(_)), "{err:?}");
    let _ = std::fs::remove_dir_all(dir);
}
