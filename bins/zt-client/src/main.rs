//! `zt-client`: bridge stdio per OpenSSH `ProxyCommand` verso un nodo, attraverso il relay.
//!
//! Fase 2: generazione della chiave. Il bridge stdio (già disponibile in `zt_net::client`)
//! viene collegato e verificato con OpenSSH e Ansible nella Fase 3.
#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use zt_net::config;

/// Client TCN.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Genera la chiave del client (file nuovo, permessi 0600) e stampa la chiave pubblica.
    Keygen {
        /// File da creare.
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    // I log vanno sempre su stderr: in modalità ProxyCommand stdout è il canale SSH.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let Command::Keygen { out } = Cli::parse().command;
    let result = config::create_identity(&out)
        .map_err(|e| e.to_string())
        .and_then(|identity| {
            writeln!(
                std::io::stdout(),
                "public_key  = \"{}\"\nfingerprint = {}",
                identity.public_key(),
                identity.fingerprint()
            )
            .map_err(|e| e.to_string())
        });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            tracing::error!("{message}");
            ExitCode::FAILURE
        }
    }
}
