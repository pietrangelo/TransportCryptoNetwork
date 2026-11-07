//! `zt-relay`: punto d'incontro pubblico: autentica i peer e inoltra flussi cifrati senza leggerli.
//!
//! Fase 1: solo l'interfaccia a riga di comando. La logica di rete arriva nella Fase 2.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;

/// punto d'incontro pubblico: autentica i peer e inoltra flussi cifrati senza leggerli.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Indirizzo su cui accettare connessioni outbound di agent e client.
    #[arg(long, default_value = "0.0.0.0:7443")]
    listen: String,
}

fn main() -> ExitCode {
    // I log vanno sempre su stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    let args = Args::parse();
    tracing::error!(?args, "network layer not implemented yet (phase 2)");
    ExitCode::FAILURE
}
