//! `zt-client`: bridge stdio per OpenSSH `ProxyCommand` verso un nodo, attraverso il relay.
//!
//! Fase 1: solo l'interfaccia a riga di comando. La logica di rete arriva nella Fase 2.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;

/// bridge stdio per OpenSSH `ProxyCommand` verso un nodo, attraverso il relay.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Indirizzo del relay (host:porta).
    #[arg(long)]
    relay: String,
    /// Nodo di destinazione (in `ssh_config`: `ProxyCommand zt-client --relay R %h`).
    node: String,
}

fn main() -> ExitCode {
    // I log vanno sempre su stderr.
    // Per zt-client è vitale: stdout è il canale SSH e un solo byte estraneo lo corrompe.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    let args = Args::parse();
    tracing::error!(?args, "network layer not implemented yet (phase 2)");
    ExitCode::FAILURE
}
