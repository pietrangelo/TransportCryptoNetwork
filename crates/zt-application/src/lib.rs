//! # zt-application
//!
//! Casi d'uso di TCN (RED: stub).
#![forbid(unsafe_code)]

/// Relay core (RED: stub).
pub mod relay {
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use zt_domain::{AccessPolicy, DomainEvent, Fingerprint, Frame, SessionId};

    /// Identificativo di connessione.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct ConnId(pub u64);
    /// Input.
    #[derive(Debug)]
    pub enum Input {
        /// Connesso.
        Connected { /** c */ conn: ConnId, /** p */ peer: Fingerprint },
        /// Ricevuto.
        Received { /** c */ conn: ConnId, /** f */ frame: Frame },
        /// Disconnesso.
        Disconnected { /** c */ conn: ConnId },
        /// Tick.
        Tick,
    }
    /// Output.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Output {
        /// Invia.
        Send { /** c */ conn: ConnId, /** f */ frame: Frame },
        /// Chiudi.
        Close { /** c */ conn: ConnId },
        /// Audit.
        Audit(DomainEvent),
    }
    /// Sorgente di session id.
    pub trait SessionIds {
        /// Prossimo.
        fn next_session_id(&mut self) -> SessionId;
    }
    /// Limiti.
    #[derive(Debug, Clone)]
    pub struct RelayLimits {
        /// a
        pub max_streams_per_client: usize,
        /// b
        pub max_streams_per_agent: usize,
        /// c
        pub register_timeout: Duration,
        /// d
        pub ping_burst: u32,
        /// e
        pub ping_refill: Duration,
    }
    impl Default for RelayLimits {
        fn default() -> Self {
            Self { max_streams_per_client: 0, max_streams_per_agent: 0, register_timeout: Duration::ZERO, ping_burst: 0, ping_refill: Duration::ZERO }
        }
    }
    /// Core.
    #[derive(Debug)]
    pub struct RelayCore<S> { ids: S }
    impl<S: SessionIds> RelayCore<S> {
        /// Nuovo.
        pub fn new(_p: Arc<AccessPolicy>, _l: RelayLimits, ids: S) -> Self { Self { ids } }
        /// Gestisci.
        pub fn handle(&mut self, _i: Input, _now: Instant) -> Vec<Output> { let _ = &mut self.ids; Vec::new() }
        /// Route.
        #[must_use]
        pub fn route_count(&self) -> usize { 1 }
        /// Conn.
        #[must_use]
        pub fn connection_count(&self) -> usize { 1 }
    }
}
