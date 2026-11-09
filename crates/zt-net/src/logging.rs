//! Log initialization for the binaries: always to stderr, text or JSON (one line per event).
//!
//! Audit events have target `zt_audit` and the `event_kind` field; in JSON they can be filtered
//! with `jq 'select(.target == "zt_audit")'` or forwarded as-is to a SIEM.

use tracing_subscriber::EnvFilter;

/// Log format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable text.
    Text,
    /// One JSON line per event, with `timestamp`, `level`, `target` and `fields`.
    Json,
}

/// Installs the global subscriber. The level comes from `RUST_LOG`, otherwise `default_level`.
pub fn init(format: LogFormat, default_level: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    let builder = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter);
    match format {
        LogFormat::Text => builder.init(),
        LogFormat::Json => builder.json().with_current_span(false).init(),
    }
}
