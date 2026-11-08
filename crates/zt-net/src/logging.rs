//! Inizializzazione dei log dei binari: sempre su stderr, testo o JSON (una riga per evento).
//!
//! Gli eventi di audit hanno target `zt_audit` e il campo `event_kind`; in JSON si filtrano con
//! `jq 'select(.target == "zt_audit")'` o si inoltrano così come sono a un SIEM.

use tracing_subscriber::EnvFilter;

/// Formato dei log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Testo leggibile.
    Text,
    /// Una riga JSON per evento, con `timestamp`, `level`, `target` e `fields`.
    Json,
}

/// Installa il subscriber globale. Il livello viene da `RUST_LOG`, altrimenti `default_level`.
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
