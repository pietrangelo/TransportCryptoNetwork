//! `zt-ca`: la CA offline dei certificati client (PROTOCOL §15, OPERATIONS §10).
//!
//! Gira solo sulla macchina della CA, senza rete: genera la chiave della CA, firma certificati
//! brevi e li ispeziona. Nessun runtime tokio.
//!
//! **Fase 6, RED**: la riga di comando è quella del piano (`docs/phase6-plan.md` §3.5); ogni
//! comando è uno stub che fallisce senza scrivere nulla.
#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgGroup, Parser, Subcommand};

/// CA offline di TCN.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Genera la chiave della CA (file nuovo, permessi 0600) e stampa la chiave pubblica.
    Keygen {
        /// File da creare.
        #[arg(long)]
        out: PathBuf,
    },
    /// Firma un certificato per la chiave pubblica di un client.
    #[command(group(ArgGroup::new("scope").required(true).multiple(false).args(["nodes", "all_nodes"])))]
    Sign {
        /// Chiave segreta della CA (`tcn-ca-secret-v1:`).
        #[arg(long)]
        ca: PathBuf,
        /// Registro delle emissioni (TSV, in append, 0600). Obbligatorio.
        #[arg(long)]
        log: PathBuf,
        /// Chiave pubblica del client (64 caratteri esadecimali).
        #[arg(long)]
        subject: String,
        /// Nome del client, per gli audit log (`[a-z0-9-]`, 1..=63).
        #[arg(long)]
        name: String,
        /// Nodi concessi (al massimo 64), separati da virgole.
        #[arg(long, value_delimiter = ',')]
        nodes: Vec<String>,
        /// Tutti i nodi in `allow` della CA.
        #[arg(long)]
        all_nodes: bool,
        /// Durata: `<n>s`, `<n>m` o `<n>h`, al massimo 24 ore.
        #[arg(long)]
        validity: String,
        /// Inizio della validità in secondi Unix (default: adesso).
        #[arg(long)]
        not_before: Option<u64>,
        /// File del certificato da creare (mai sovrascritto).
        #[arg(long)]
        out: PathBuf,
    },
    /// Mostra i campi di un certificato e la riga per la denylist.
    Inspect {
        /// File del certificato.
        #[arg(long)]
        cert: PathBuf,
        /// Chiave pubblica della CA con cui verificare la firma (64 caratteri esadecimali).
        #[arg(long)]
        ca_key: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "zt-ca: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: &Command) -> Result<(), String> {
    // RED: stub, nessun comando è ancora implementato.
    match command {
        Command::Keygen { .. } => Err("keygen is not implemented yet".into()),
        Command::Sign { .. } => Err("sign is not implemented yet".into()),
        Command::Inspect { .. } => Err("inspect is not implemented yet".into()),
    }
}
