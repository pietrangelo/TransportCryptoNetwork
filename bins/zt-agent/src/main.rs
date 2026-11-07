//! `zt-agent`: gira sui server target, nessuna porta in ascolto: si connette in uscita al relay.
//!
//! Fase 1: solo l'interfaccia a riga di comando. La logica di rete arriva nella Fase 2.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;

/// gira sui server target, nessuna porta in ascolto: si connette in uscita al relay.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Indirizzo del relay (host:porta).
    #[arg(long)]
    relay: String,
    /// Nome logico di questo nodo (alias Ansible).
    #[arg(long)]
    node: String,
    /// Demone SSH locale verso cui inoltrare il traffico autorizzato.
    #[arg(long, default_value = "127.0.0.1:22")]
    ssh_target: String,
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
