//! Canale Noise su un trasporto a byte (TCP).
//!
//! Sul filo ogni messaggio Noise è preceduto dalla sua lunghezza (`u16` big-endian), come
//! raccomanda la specifica Noise. Dopo l'handshake ogni messaggio contiene **esattamente un**
//! frame TCN: byte in eccesso sono una violazione.
//!
//! Typestate: l'unico modo di ottenere un [`Established`] è completare un handshake; il
//! responder passa per [`Pending`], dove deve decidere se accettare il peer.

use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use zt_crypto::noise::{self, Channel, MAX_MESSAGE_LEN};
use zt_crypto::{Identity, PublicKey};
use zt_domain::{Fingerprint, Frame};
use zt_proto::FrameDecoder;

use crate::{NetError, Timeouts};

fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(2)
        .max_frame_length(MAX_MESSAGE_LEN)
        .new_codec()
}

async fn read_message<IO>(
    framed: &mut Framed<IO, LengthDelimitedCodec>,
) -> Result<BytesMut, NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    match framed.next().await {
        Some(Ok(message)) => Ok(message),
        Some(Err(err)) => Err(NetError::Io(err)),
        None => Err(NetError::Closed),
    }
}

/// Handshake lato initiator (agent, client): pinna la chiave del responder.
///
/// # Errors
/// [`NetError::Timeout`] oltre `timeouts.handshake`, [`NetError::Crypto`] se il responder non
/// prova di possedere `remote`.
pub async fn connect<IO>(
    io: IO,
    local: &Identity,
    remote: &PublicKey,
    channel: Channel,
    timeouts: &Timeouts,
) -> Result<Established<IO>, NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut framed = Framed::new(io, codec());
    let handshake = async {
        let (msg1, waiting) = noise::initiate(local, remote, channel)?;
        framed.send(Bytes::from(msg1)).await?;
        let msg2 = read_message(&mut framed).await?;
        Ok::<_, NetError>(waiting.complete(&msg2)?)
    };
    let transport = timeout(timeouts.handshake, handshake)
        .await
        .map_err(|_| NetError::Timeout("handshake"))??;
    Ok(Established {
        framed,
        transport,
        decoder: FrameDecoder::new(),
    })
}

/// Handshake lato responder (relay): legge il primo messaggio e si ferma prima di rispondere.
///
/// # Errors
/// [`NetError::Timeout`] oltre `timeouts.handshake`, [`NetError::Crypto`] su messaggi non validi.
pub async fn accept<IO>(
    io: IO,
    local: &Identity,
    channel: Channel,
    timeouts: &Timeouts,
) -> Result<Pending<IO>, NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut framed = Framed::new(io, codec());
    let msg1 = timeout(timeouts.handshake, read_message(&mut framed))
        .await
        .map_err(|_| NetError::Timeout("handshake"))??;
    let pending = noise::respond(local, &msg1, channel)?;
    Ok(Pending { framed, pending })
}

/// Handshake a metà: il responder conosce il peer e deve decidere.
///
/// Scartare questo valore chiude la connessione senza aver risposto: il peer non impara nulla.
#[must_use = "drop to reject, or call `establish`"]
pub struct Pending<IO> {
    framed: Framed<IO, LengthDelimitedCodec>,
    pending: noise::AuthorizationPending,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Pending<IO> {
    /// L'identità provata dal peer.
    #[must_use]
    pub fn peer(&self) -> Fingerprint {
        self.pending.peer()
    }

    /// Accetta il peer e completa l'handshake.
    ///
    /// # Errors
    /// Errori di I/O o di timeout nell'invio della risposta.
    pub async fn establish(self, timeouts: &Timeouts) -> Result<Established<IO>, NetError> {
        let Self {
            mut framed,
            pending,
        } = self;
        let (msg2, transport) = pending.accept()?;
        timeout(timeouts.write, framed.send(Bytes::from(msg2)))
            .await
            .map_err(|_| NetError::Timeout("handshake write"))??;
        Ok(Established {
            framed,
            transport,
            decoder: FrameDecoder::new(),
        })
    }
}

/// Canale autenticato: l'unico stato in cui si possono scambiare frame.
pub struct Established<IO> {
    framed: Framed<IO, LengthDelimitedCodec>,
    transport: noise::Transport,
    decoder: FrameDecoder,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Established<IO> {
    /// L'identità autenticata del peer.
    #[must_use]
    pub fn peer(&self) -> Fingerprint {
        self.transport.peer()
    }

    /// Riceve il prossimo frame. `Ok(None)` su chiusura pulita tra un messaggio e l'altro.
    ///
    /// È cancellation-safe: può essere usato in `tokio::select!`.
    ///
    /// # Errors
    /// Messaggio non autentico, frame malformato o con byte in eccesso, errore di I/O.
    pub async fn recv(&mut self) -> Result<Option<Frame>, NetError> {
        let message = match self.framed.next().await {
            Some(Ok(message)) => message,
            Some(Err(err)) => return Err(NetError::Io(err)),
            None => return Ok(None),
        };
        let plaintext = self.transport.decrypt(&message)?;
        let mut buf = BytesMut::from(plaintext.as_slice());
        let frame = self
            .decoder
            .decode(&mut buf)?
            .ok_or(NetError::Protocol("truncated frame"))?;
        if !buf.is_empty() {
            return Err(NetError::Protocol("trailing bytes after frame"));
        }
        Ok(Some(frame))
    }

    /// Invia un frame, entro `timeouts.write`.
    ///
    /// # Errors
    /// Errori di I/O o timeout.
    pub async fn send(&mut self, frame: &Frame, timeouts: &Timeouts) -> Result<(), NetError> {
        let mut plaintext = BytesMut::with_capacity(zt_proto::encoded_len(frame));
        zt_proto::encode(frame, &mut plaintext);
        let message = self.transport.encrypt(&plaintext)?;
        timeout(timeouts.write, self.framed.send(Bytes::from(message)))
            .await
            .map_err(|_| NetError::Timeout("write"))??;
        Ok(())
    }
}
