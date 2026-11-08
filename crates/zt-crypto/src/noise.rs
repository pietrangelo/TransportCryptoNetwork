//! Handshake Noise IK sans-IO con typestate.
//!
//! ```text
//! initiator (agent/client)                          responder (relay/agent)
//!   initiate() ── msg1: e, es, s, ss ──────────────▶ respond()  → AuthorizationPending
//!                                                     peer() → decisione di policy
//!   AwaitingResponse ◀───────── msg2: e, ee, se ──── accept()  → Transport
//!   complete() → Transport
//! ```
//!
//! IK: l'initiator conosce e **pinna** la chiave statica del responder; il responder impara
//! quella dell'initiator dal primo messaggio. Se la decisione è negativa il responder
//! semplicemente non risponde: l'initiator non impara nulla, nemmeno se la sua chiave esiste.

use snow::{Builder, HandshakeState, TransportState};
use zt_domain::Fingerprint;

use crate::error::CryptoError;
use crate::identity::{Identity, PublicKey, fingerprint_of_x25519};
use crate::keyring::Keyring;

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Lunghezza massima di un messaggio Noise.
pub const MAX_MESSAGE_LEN: usize = 65_535;

/// Tag AEAD aggiunto a ogni messaggio di trasporto.
pub const TAG_LEN: usize = 16;

/// Plaintext massimo di un messaggio di trasporto.
pub const MAX_PLAINTEXT_LEN: usize = MAX_MESSAGE_LEN - TAG_LEN;

/// Su quale canale avviene l'handshake. Il valore entra nel *prologue* di Noise, quindi un
/// messaggio di un canale non è mai valido sull'altro (separazione di dominio).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Peer ↔ relay.
    Outer,
    /// Client ↔ agent, attraverso il relay (che non può leggerlo).
    EndToEnd,
}

impl Channel {
    const fn prologue(self) -> &'static [u8] {
        match self {
            Self::Outer => b"TCN/1 outer",
            Self::EndToEnd => b"TCN/1 end-to-end",
        }
    }
}

fn builder(
    local: &Identity,
    channel: Channel,
) -> Result<(Builder<'static>, zeroize::Zeroizing<[u8; 32]>), CryptoError> {
    let params = PATTERN.parse().map_err(|_| CryptoError::Handshake)?;
    let secret = local.x25519_secret();
    let builder = Builder::new(params)
        .prologue(channel.prologue())
        .map_err(|_| CryptoError::Handshake)?;
    Ok((builder, secret))
}

/// Initiator: produce il primo messaggio verso un responder di cui conosce la chiave.
///
/// # Errors
/// [`CryptoError::Handshake`] se lo stato Noise non può essere costruito.
pub fn initiate(
    local: &Identity,
    remote: &PublicKey,
    channel: Channel,
) -> Result<(Vec<u8>, AwaitingResponse), CryptoError> {
    let (builder, secret) = builder(local, channel)?;
    let remote_static = remote.x25519();
    let mut state = builder
        .local_private_key(secret.as_ref())
        .and_then(|b| b.remote_public_key(&remote_static))
        .and_then(Builder::build_initiator)
        .map_err(|_| CryptoError::Handshake)?;
    let msg1 = write(&mut state)?;
    Ok((
        msg1,
        AwaitingResponse {
            state,
            responder: remote.fingerprint(),
        },
    ))
}

/// Responder: legge il primo messaggio e scopre chi è l'initiator.
///
/// # Errors
/// [`CryptoError::Handshake`] se il messaggio non è valido per questa identità e canale.
pub fn respond(
    local: &Identity,
    msg1: &[u8],
    channel: Channel,
) -> Result<AuthorizationPending, CryptoError> {
    if msg1.len() > MAX_MESSAGE_LEN {
        return Err(CryptoError::Handshake);
    }
    let (builder, secret) = builder(local, channel)?;
    let mut state = builder
        .local_private_key(secret.as_ref())
        .and_then(Builder::build_responder)
        .map_err(|_| CryptoError::Handshake)?;
    let mut payload = vec![0_u8; MAX_MESSAGE_LEN];
    state
        .read_message(msg1, &mut payload)
        .map_err(|_| CryptoError::Handshake)?;
    let peer = remote_fingerprint(&state)?;
    Ok(AuthorizationPending { state, peer })
}

/// Responder con un [`Keyring`]: accetta un `msg1` cifrato verso la chiave corrente o verso
/// quella precedente (PROTOCOL §14).
///
/// # Errors
/// [`CryptoError::Handshake`] se `msg1` non è valido per nessuna delle due chiavi.
pub fn respond_any(
    keys: &Keyring,
    msg1: &[u8],
    channel: Channel,
) -> Result<AuthorizationPending, CryptoError> {
    // Un tentativo fallito non lascia stato: ogni `respond` costruisce un handshake nuovo.
    // Il tempo rivela quale chiave ha funzionato; non è un segreto (sono entrambe pubbliche).
    match (respond(keys.current(), msg1, channel), keys.previous()) {
        (Ok(pending), _) => Ok(pending),
        (Err(_), Some(previous)) => respond(previous, msg1, channel),
        (Err(err), None) => Err(err),
    }
}

/// L'initiator ha inviato `msg1` e attende la risposta.
#[derive(Debug)]
#[must_use = "the handshake is not complete until `complete` is called"]
pub struct AwaitingResponse {
    state: HandshakeState,
    responder: Fingerprint,
}

impl AwaitingResponse {
    /// Completa l'handshake con il secondo messaggio.
    ///
    /// # Errors
    /// [`CryptoError::Handshake`] se `msg2` non proviene dal responder pinnato.
    pub fn complete(mut self, msg2: &[u8]) -> Result<Transport, CryptoError> {
        if msg2.len() > MAX_MESSAGE_LEN {
            return Err(CryptoError::Handshake);
        }
        let mut payload = vec![0_u8; MAX_MESSAGE_LEN];
        self.state
            .read_message(msg2, &mut payload)
            .map_err(|_| CryptoError::Handshake)?;
        Transport::from_handshake(self.state, self.responder)
    }
}

/// Il responder conosce l'identità dell'initiator e deve decidere se accettarla.
///
/// Rifiutare significa semplicemente scartare questo valore: non esiste un messaggio di
/// rifiuto.
#[derive(Debug)]
#[must_use = "drop to reject, or call `accept`"]
pub struct AuthorizationPending {
    state: HandshakeState,
    peer: Fingerprint,
}

impl AuthorizationPending {
    /// L'identità autenticata dell'initiator.
    #[must_use]
    pub fn peer(&self) -> Fingerprint {
        self.peer
    }

    /// Accetta l'initiator: produce `msg2` e il canale di trasporto.
    ///
    /// # Errors
    /// [`CryptoError::Handshake`] se lo stato Noise non può avanzare.
    pub fn accept(mut self) -> Result<(Vec<u8>, Transport), CryptoError> {
        let msg2 = write(&mut self.state)?;
        let transport = Transport::from_handshake(self.state, self.peer)?;
        Ok((msg2, transport))
    }
}

/// Messaggi per direzione dopo i quali entrambe le parti eseguono il rekey di Noise.
///
/// Il rekey è implicito: nessun messaggio sul filo, entrambe le parti lo eseguono allo stesso
/// contatore (TCP consegna in ordine e un messaggio rifiutato chiude il canale). Ogni periodo ha
/// una chiave derivata a senso unico dalla precedente: chi legge la memoria del processo non
/// decifra il traffico dei periodi passati. Con il keepalive a 30 s un canale inattivo cambia
/// chiave ogni ~8,5 ore; con traffico SSH ogni 16 MiB circa.
pub const REKEY_INTERVAL: usize = 1024;

/// Canale cifrato e autenticato dopo l'handshake.
#[derive(Debug)]
pub struct Transport {
    state: TransportState,
    peer: Fingerprint,
    sent: usize,
    received: usize,
}

impl Transport {
    fn from_handshake(state: HandshakeState, peer: Fingerprint) -> Result<Self, CryptoError> {
        let state = state
            .into_transport_mode()
            .map_err(|_| CryptoError::Handshake)?;
        Ok(Self {
            state,
            peer,
            sent: 0,
            received: 0,
        })
    }

    /// L'identità autenticata dell'altra parte.
    #[must_use]
    pub fn peer(&self) -> Fingerprint {
        self.peer
    }

    /// Rekey eseguiti in invio.
    #[must_use]
    pub const fn send_epoch(&self) -> usize {
        self.sent / REKEY_INTERVAL
    }

    /// Rekey eseguiti in ricezione.
    #[must_use]
    pub const fn recv_epoch(&self) -> usize {
        self.received / REKEY_INTERVAL
    }

    /// Cifra un messaggio.
    ///
    /// # Errors
    /// [`CryptoError::MessageTooLarge`] oltre [`MAX_PLAINTEXT_LEN`].
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(CryptoError::MessageTooLarge);
        }
        let mut out = vec![0_u8; plaintext.len().saturating_add(TAG_LEN)];
        let len = self
            .state
            .write_message(plaintext, &mut out)
            .map_err(|_| CryptoError::Handshake)?;
        out.truncate(len);
        self.sent = self.sent.wrapping_add(1);
        if self.sent.is_multiple_of(REKEY_INTERVAL) {
            self.state.rekey_outgoing();
        }
        Ok(out)
    }

    /// Decifra un messaggio in un buffer **nuovo**, dimensionato sul messaggio.
    ///
    /// Un buffer per messaggio fa sì che un frame tenuto in coda trattenga solo la propria
    /// memoria, mai un buffer di lettura condiviso (finding 10 della review 0001).
    ///
    /// # Errors
    /// [`CryptoError::Decrypt`] se il messaggio non è autentico, è fuori ordine o ripetuto.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < TAG_LEN || ciphertext.len() > MAX_MESSAGE_LEN {
            return Err(CryptoError::Decrypt);
        }
        let mut out = vec![0_u8; ciphertext.len().saturating_sub(TAG_LEN)];
        let len = self
            .state
            .read_message(ciphertext, &mut out)
            .map_err(|_| CryptoError::Decrypt)?;
        out.truncate(len);
        // Solo i messaggi autentici contano: un falso non sposta il rekey.
        self.received = self.received.wrapping_add(1);
        if self.received.is_multiple_of(REKEY_INTERVAL) {
            self.state.rekey_incoming();
        }
        Ok(out)
    }
}

fn write(state: &mut HandshakeState) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0_u8; MAX_MESSAGE_LEN];
    let len = state
        .write_message(&[], &mut out)
        .map_err(|_| CryptoError::Handshake)?;
    out.truncate(len);
    Ok(out)
}

fn remote_fingerprint(state: &HandshakeState) -> Result<Fingerprint, CryptoError> {
    let raw = state.get_remote_static().ok_or(CryptoError::Handshake)?;
    let key: [u8; 32] = raw.try_into().map_err(|_| CryptoError::Handshake)?;
    Ok(fingerprint_of_x25519(&key))
}
