//! A [`Lab`] whose agent records its metrics (R-5) and uses a buffer budget (R-6).
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::missing_panics_doc
)]

use std::sync::Arc;
use std::time::Duration;

use zt_crypto::Identity;
use zt_domain::{AccessPolicy, AuthorizedClients, HandshakeSuite};
use zt_net::Revocable;
use zt_net::agent::Observed;
use zt_net::metrics::AgentMetrics;
use zt_net::relay::RelayConfig;

use crate::common::{Lab, copy_of, counting_echo, node, start_relay_with, timeouts};

/// Like `Lab::start_configured`, with the agent's metrics and buffer budget.
pub async fn start_observed_with(
    agent: Arc<Identity>,
    relays_config: Vec<(AccessPolicy, RelayConfig)>,
    clients: AuthorizedClients,
    observed: Observed,
) -> Lab {
    let mut relays = Vec::new();
    for (p, c) in relays_config {
        relays.push(start_relay_with(p, c).await);
    }
    let (ssh, sshd) = counting_echo().await;
    let (clients_rx, clients) = Revocable::new(clients);
    let suite = HandshakeSuite::NoiseIk25519;
    tokio::spawn(zt_net::agent::run_observed(
        Arc::new(zt_crypto::Keyring::single(copy_of(&agent))),
        zt_net::agent::AgentConfig {
            relays: relays
                .iter()
                .map(|r| zt_net::RelayEndpoint {
                    address: r.addr.to_string(),
                    public_key: r.pin(suite),
                    suite,
                })
                .collect(),
            node: node("web-01"),
            ssh_target: ssh.to_string(),
            authorized_clients: clients_rx,
            timeouts: timeouts(),
            max_streams: 16,
            client_suites: zt_domain::AcceptedSuites::only(suite),
            identity_log_interval: zt_net::agent::IDENTITY_LOG_INTERVAL,
            reconnect: zt_application::reconnect::ReconnectConfig::default(),
        },
        zt_net::net::TcpDialer,
        std::future::pending(),
        Duration::from_secs(1),
        observed,
    ));
    tokio::time::sleep(Duration::from_millis(400)).await;
    Lab {
        relays,
        agent,
        clients,
        sshd,
    }
}

/// [`start_observed_with`] with `metrics` and the default budget.
pub async fn start_observed(
    agent: Arc<Identity>,
    relays_config: Vec<(AccessPolicy, RelayConfig)>,
    clients: AuthorizedClients,
    metrics: Arc<AgentMetrics>,
) -> Lab {
    start_observed_with(
        agent,
        relays_config,
        clients,
        Observed {
            metrics,
            ..Observed::default()
        },
    )
    .await
}
