//! Un singolo stream end-to-end (client ↔ agent) sopra la connessione con il relay.
//!
//! Lo stesso codice gira ai due capi: legge byte locali (SSH), li cifra con il canale
//! end-to-end e li invia come `Data` nei limiti del credito; all'arrivo decifra, consegna e
//! restituisce credito con `WindowUpdate`.

use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;
use zt_crypto::noise::{TAG_LEN, Transport};
use zt_domain::flow::{INITIAL_WINDOW, MAX_WINDOW, MIN_CHARGE, MIN_WINDOW_UPDATE, Window, charge};
use zt_domain::{CloseReason, Credit, Frame, FramePayload, StreamId};

use crate::{NetError, Timeouts};

/// Byte locali letti per ogni `Data`.
pub(crate) const CHUNK: usize = 16 * 1024;

/// Credito restituito quando se ne è consumato almeno questo.
const UPDATE_THRESHOLD: u32 = INITIAL_WINDOW / 4;

/// Frame in coda per uno stream: il massimo che un peer corretto può inviare entro il credito.
pub(crate) const STREAM_QUEUE: usize = {
    let frames = MAX_WINDOW / MIN_CHARGE + MAX_WINDOW / MIN_WINDOW_UPDATE + 8;
    frames as usize
};

/// Cosa è arrivato su uno stream.
enum Inbound {
    Data(bytes::Bytes),
    Closed(CloseReason),
}

/// Le code e il credito di uno stream.
pub(crate) struct StreamIo {
    stream: StreamId,
    rx: mpsc::Receiver<Frame>,
    tx: mpsc::Sender<Frame>,
    /// Credito che abbiamo per inviare.
    send: Window,
    /// Credito che il peer ha verso di noi (per accorgersi di un relay che non lo applica).
    recv: Window,
    /// Byte consegnati e non ancora restituiti come credito.
    consumed: u32,
}

impl StreamIo {
    pub(crate) fn new(
        stream: StreamId,
        rx: mpsc::Receiver<Frame>,
        tx: mpsc::Sender<Frame>,
    ) -> Self {
        Self {
            stream,
            rx,
            tx,
            send: Window::initial(),
            recv: Window::initial(),
            consumed: 0,
        }
    }

    pub(crate) async fn send_frame(&self, frame: Frame) -> Result<(), NetError> {
        self.tx.send(frame).await.map_err(|_| NetError::Closed)
    }

    pub(crate) async fn close(&self, reason: CloseReason) {
        // Best effort: se la connessione è già caduta non c'è nessuno da avvisare.
        let _ = self
            .send_frame(Frame::Close {
                stream: self.stream,
                reason,
            })
            .await;
    }

    /// Invia un messaggio cifrato come `Data`, consumando credito.
    pub(crate) async fn send_data(&mut self, ciphertext: Vec<u8>) -> Result<(), NetError> {
        self.send
            .consume(ciphertext.len())
            .map_err(NetError::Protocol)?;
        let payload =
            FramePayload::try_from(ciphertext).map_err(|_| NetError::Protocol("oversized data"))?;
        self.send_frame(Frame::Data {
            stream: self.stream,
            payload,
        })
        .await
    }

    /// Elabora frame di controllo finché arriva un `Data` o una chiusura.
    async fn next_inbound(&mut self) -> Result<Inbound, NetError> {
        loop {
            match self.rx.recv().await {
                None => return Ok(Inbound::Closed(CloseReason::PeerGone)),
                Some(Frame::Data { payload, .. }) => {
                    self.recv
                        .consume(payload.len())
                        .map_err(NetError::Protocol)?;
                    return Ok(Inbound::Data(payload.into_bytes()));
                }
                Some(Frame::WindowUpdate { credit, .. }) => {
                    self.send.grant(credit.get()).map_err(NetError::Protocol)?;
                }
                Some(Frame::Close { reason, .. }) => return Ok(Inbound::Closed(reason)),
                Some(_) => return Err(NetError::Protocol("unexpected frame on stream")),
            }
        }
    }

    /// Attende il prossimo messaggio end-to-end (usato durante l'handshake).
    pub(crate) async fn recv_message(
        &mut self,
        timeouts: &Timeouts,
    ) -> Result<bytes::Bytes, NetError> {
        let inbound = timeout(timeouts.open, self.next_inbound())
            .await
            .map_err(|_| NetError::Timeout("stream"))??;
        let message = match inbound {
            Inbound::Data(message) => message,
            Inbound::Closed(reason) => return Err(NetError::StreamClosed(reason)),
        };
        self.delivered(message.len()).await?;
        Ok(message)
    }

    /// Registra la consegna di `len` byte e, oltre la soglia, restituisce credito.
    async fn delivered(&mut self, len: usize) -> Result<(), NetError> {
        self.consumed = self.consumed.saturating_add(charge(len));
        if self.consumed >= UPDATE_THRESHOLD {
            let credit =
                Credit::try_from(self.consumed).map_err(|_| NetError::Protocol("zero credit"))?;
            self.recv.grant(self.consumed).map_err(NetError::Protocol)?;
            self.consumed = 0;
            self.send_frame(Frame::WindowUpdate {
                stream: self.stream,
                credit,
            })
            .await?;
        }
        Ok(())
    }
}

/// Collega uno stream già autenticato end-to-end a un flusso locale, fino alla chiusura.
///
/// Le due direzioni girano in parallelo: se fossero sequenziali, un demone SSH che non legge
/// finché non può scrivere bloccherebbe entrambe (deadlock classico dei proxy). Il credito
/// di invio è un semaforo in byte: la direzione in uscita lo consuma, i `WindowUpdate` della
/// direzione in entrata lo ricaricano.
pub(crate) async fn pump<L>(
    io: StreamIo,
    transport: Transport,
    local: L,
    timeouts: &Timeouts,
) -> Result<(), NetError>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let StreamIo {
        stream,
        rx,
        tx,
        send,
        recv,
        consumed,
    } = io;
    let credit = Semaphore::new(usize::try_from(send.available()).unwrap_or(0));
    let transport = Mutex::new(transport);
    let (reader, mut writer) = tokio::io::split(local);
    let mut down = Downlink {
        stream,
        rx,
        tx: tx.clone(),
        recv,
        consumed,
        credit: &credit,
        transport: &transport,
    };
    let up = uplink(stream, reader, &tx, &credit, &transport);
    let result = tokio::select! {
        r = up => r,
        r = down.run(&mut writer, timeouts) => r,
    };
    let _ = writer.shutdown().await;
    if result.is_err() {
        let _ = tx
            .send(Frame::Close {
                stream,
                reason: CloseReason::ProtocolViolation,
            })
            .await;
    }
    result
}

fn lock(transport: &Mutex<Transport>) -> Result<std::sync::MutexGuard<'_, Transport>, NetError> {
    transport
        .lock()
        .map_err(|_| NetError::Protocol("transport lock poisoned"))
}

/// Locale → peer: legge, cifra, invia entro il credito.
async fn uplink<R: AsyncRead + Unpin>(
    stream: StreamId,
    mut reader: R,
    tx: &mpsc::Sender<Frame>,
    credit: &Semaphore,
    transport: &Mutex<Transport>,
) -> Result<(), NetError> {
    let mut buf = vec![0_u8; CHUNK];
    loop {
        // Attende credito per almeno un frame minimo prima di leggere.
        drop(
            credit
                .acquire_many(MIN_CHARGE)
                .await
                .map_err(|_| NetError::Closed)?,
        );
        let room = credit
            .available_permits()
            .saturating_sub(TAG_LEN)
            .min(CHUNK);
        let target = buf
            .get_mut(..room)
            .ok_or(NetError::Protocol("read buffer"))?;
        let n = reader.read(target).await?;
        if n == 0 {
            let _ = tx
                .send(Frame::Close {
                    stream,
                    reason: CloseReason::Normal,
                })
                .await;
            return Ok(());
        }
        let chunk = buf.get(..n).ok_or(NetError::Protocol("read overflow"))?;
        let ciphertext = lock(transport)?.encrypt(chunk)?;
        // Solo questa direzione consuma credito: i permessi sono già disponibili.
        credit
            .acquire_many(charge(ciphertext.len()))
            .await
            .map_err(|_| NetError::Closed)?
            .forget();
        let payload =
            FramePayload::try_from(ciphertext).map_err(|_| NetError::Protocol("oversized data"))?;
        tx.send(Frame::Data { stream, payload })
            .await
            .map_err(|_| NetError::Closed)?;
    }
}

/// Peer → locale: decifra, consegna, restituisce credito; applica i `WindowUpdate` ricevuti.
struct Downlink<'a> {
    stream: StreamId,
    rx: mpsc::Receiver<Frame>,
    tx: mpsc::Sender<Frame>,
    recv: Window,
    consumed: u32,
    credit: &'a Semaphore,
    transport: &'a Mutex<Transport>,
}

impl Downlink<'_> {
    async fn run<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        timeouts: &Timeouts,
    ) -> Result<(), NetError> {
        loop {
            match self.rx.recv().await {
                None | Some(Frame::Close { .. }) => return Ok(()),
                Some(Frame::Data { payload, .. }) => {
                    self.recv
                        .consume(payload.len())
                        .map_err(NetError::Protocol)?;
                    let plaintext = lock(self.transport)?.decrypt(payload.as_bytes())?;
                    timeout(timeouts.write, writer.write_all(&plaintext))
                        .await
                        .map_err(|_| NetError::Timeout("local write"))??;
                    self.consumed = self.consumed.saturating_add(charge(payload.len()));
                    if self.consumed >= UPDATE_THRESHOLD {
                        let credit = Credit::try_from(self.consumed)
                            .map_err(|_| NetError::Protocol("zero credit"))?;
                        self.recv.grant(self.consumed).map_err(NetError::Protocol)?;
                        self.consumed = 0;
                        self.tx
                            .send(Frame::WindowUpdate {
                                stream: self.stream,
                                credit,
                            })
                            .await
                            .map_err(|_| NetError::Closed)?;
                    }
                }
                Some(Frame::WindowUpdate { credit, .. }) => {
                    let total = self
                        .credit
                        .available_permits()
                        .saturating_add(usize::try_from(credit.get()).unwrap_or(usize::MAX));
                    if credit.get() < MIN_WINDOW_UPDATE
                        || total > usize::try_from(MAX_WINDOW).unwrap_or(usize::MAX)
                    {
                        return Err(NetError::Protocol("invalid window update"));
                    }
                    self.credit
                        .add_permits(usize::try_from(credit.get()).unwrap_or(0));
                }
                Some(_) => return Err(NetError::Protocol("unexpected frame on stream")),
            }
        }
    }
}
