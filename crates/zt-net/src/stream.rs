//! A single end-to-end stream (client ↔ agent) on top of the connection with the relay.
//!
//! The same code runs at both ends: it reads local bytes (SSH), encrypts them with the
//! end-to-end channel and sends them as `Data` within the credit limits; on arrival it
//! decrypts, delivers and returns credit with `WindowUpdate`.

use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;
use zt_application::efficiency::WindowTuner;
use zt_crypto::noise::{TAG_LEN, Transport};
use zt_domain::flow::{INITIAL_WINDOW, MAX_WINDOW, MIN_CHARGE, MIN_WINDOW_UPDATE, Window, charge};
use zt_domain::{CloseReason, Credit, Frame, FramePayload, StreamId};

use crate::budget::Reservation;
use crate::metrics::Traffic;
use crate::{NetError, Timeouts};

/// Local bytes read for each `Data`.
pub(crate) const CHUNK: usize = 16 * 1024;

/// Credit is returned once at least this much has been consumed (during the handshake, before
/// the window tuner takes over).
const UPDATE_THRESHOLD: u32 = INITIAL_WINDOW / 4;

/// The bytes a queued `Data` frame stands for when estimating a backlog.
const FRAME_ESTIMATE: u32 = 16 * 1024 + 16;
const _: () = assert!(FRAME_ESTIMATE as usize == CHUNK + TAG_LEN);

/// Frames queued for a stream: the most a well-behaved peer can send within the credit.
pub(crate) const STREAM_QUEUE: usize = {
    let frames = MAX_WINDOW / MIN_CHARGE + MAX_WINDOW / MIN_WINDOW_UPDATE + 8;
    frames as usize
};

/// What arrived on a stream.
enum Inbound {
    Data(bytes::Bytes),
    Closed(CloseReason),
}

/// The queues and credit of a stream.
pub(crate) struct StreamIo {
    stream: StreamId,
    rx: mpsc::Receiver<Frame>,
    tx: mpsc::Sender<Frame>,
    /// Credit we have for sending.
    send: Window,
    /// Credit the peer has towards us (to notice a relay that does not enforce it).
    recv: Window,
    /// Bytes delivered and not yet returned as credit.
    consumed: u32,
    /// The receive window, reserved from the byte budget (R-6); `None` until the peer is
    /// authenticated on the agent (review 0013, A13-2), and then without growth.
    window: Option<Reservation>,
}

impl StreamIo {
    /// `window` holds the initial receive window, reserved from the byte budget; the agent
    /// passes `None` and reserves it with [`Self::hold_window`] once the client is
    /// authenticated.
    pub(crate) fn new(
        stream: StreamId,
        rx: mpsc::Receiver<Frame>,
        tx: mpsc::Sender<Frame>,
        window: Option<Reservation>,
    ) -> Self {
        Self {
            stream,
            rx,
            tx,
            send: Window::initial(),
            recv: Window::initial(),
            consumed: 0,
            window,
        }
    }

    /// The initial receive window, reserved from the byte budget after authentication.
    pub(crate) fn hold_window(&mut self, window: Reservation) {
        self.window = Some(window);
    }

    pub(crate) async fn send_frame(&self, frame: Frame) -> Result<(), NetError> {
        self.tx.send(frame).await.map_err(|_| NetError::Closed)
    }

    /// A handle that can close the stream even after `self` has been moved into the pump.
    /// The stream identifier on the connection with the relay.
    pub(crate) const fn id(&self) -> StreamId {
        self.stream
    }

    pub(crate) fn closer(&self) -> Closer {
        Closer {
            stream: self.stream,
            tx: self.tx.clone(),
        }
    }

    pub(crate) async fn close(&self, reason: CloseReason) {
        // Best effort: if the connection is already down there is nobody to notify.
        let _ = self
            .send_frame(Frame::Close {
                stream: self.stream,
                reason,
            })
            .await;
    }

    /// Sends an encrypted message as `Data`, consuming credit.
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

    /// Processes control frames until a `Data` or a close arrives.
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

    /// Waits for the next end-to-end message (used during the handshake).
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

    /// Records the delivery of `len` bytes and, past the threshold, returns credit.
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

/// Connects a stream already authenticated end-to-end to a local stream, until it closes.
///
/// The two directions run in parallel: if they were sequential, an SSH daemon that does not
/// read until it can write would block both (the classic proxy deadlock). The send credit is
/// a semaphore in bytes: the outbound direction consumes it, the `WindowUpdate`s of the
/// inbound direction replenish it.
///
/// `local_write` bounds the time of a write to `local`. The agent uses it towards sshd; the
/// client does not: a suspended `ssh` (`~^Z`) stops reading and the session must survive,
/// while memory is bounded by the window anyway (finding 0003-2).
pub(crate) async fn pump<L>(
    io: StreamIo,
    transport: Transport,
    local: L,
    local_write: Option<std::time::Duration>,
    traffic: Traffic<'_>,
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
        window,
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
        delivered: traffic.to_local,
        tuning: Tuning {
            tuner: WindowTuner::new(),
            window,
            starved: false,
            min_queued: usize::MAX,
            grows: traffic.window_grows,
            refusals: traffic.window_refusals,
        },
    };
    let up = uplink(stream, reader, &tx, &credit, &transport, traffic.from_local);
    let result = tokio::select! {
        r = up => r,
        r = down.run(&mut writer, local_write) => r,
    };
    let _ = writer.shutdown().await;
    // A stream already closed by the peer is not closed again.
    if result.is_err() && !matches!(result, Err(NetError::StreamClosed(_))) {
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

/// Local → peer: reads, encrypts, sends within the credit.
async fn uplink<R: AsyncRead + Unpin>(
    stream: StreamId,
    mut reader: R,
    tx: &mpsc::Sender<Frame>,
    credit: &Semaphore,
    transport: &Mutex<Transport>,
    read: &crate::metrics::Counter,
) -> Result<(), NetError> {
    let mut buf = vec![0_u8; CHUNK];
    loop {
        // Waits for credit for at least a minimal frame before reading.
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
        read.add(u64::try_from(n).unwrap_or(u64::MAX));
        let chunk = buf.get(..n).ok_or(NetError::Protocol("read overflow"))?;
        let ciphertext = lock(transport)?.encrypt(chunk)?;
        // Only this direction consumes credit: the permits are already available.
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

/// Peer → local: decrypts, delivers, returns credit; applies the received `WindowUpdate`s.
struct Downlink<'a> {
    stream: StreamId,
    rx: mpsc::Receiver<Frame>,
    tx: mpsc::Sender<Frame>,
    recv: Window,
    consumed: u32,
    credit: &'a Semaphore,
    transport: &'a Mutex<Transport>,
    /// Plaintext bytes written to the local side.
    delivered: &'a crate::metrics::Counter,
    tuning: Tuning<'a>,
}

/// Receive-window auto-tuning inside the byte budget (R6-E4).
struct Tuning<'a> {
    tuner: WindowTuner,
    /// The reservation the window grows in; none: the window never grows.
    window: Option<Reservation>,
    /// The receiver waited on an empty queue since the last `WindowUpdate`: it keeps up, the
    /// sender (or its window) is the bottleneck.
    starved: bool,
    /// The fewest frames queued at a receive since the last `WindowUpdate`.
    min_queued: usize,
    grows: Option<&'a crate::metrics::Counter>,
    refusals: Option<&'a crate::metrics::Counter>,
}

impl Tuning<'_> {
    /// Notes the queue before a receive.
    fn before_recv(&mut self, queued: usize) {
        if queued == 0 {
            self.starved = true;
        }
        self.min_queued = self.min_queued.min(queued);
    }

    /// The growth of the window to grant with the next `WindowUpdate` (0 if none), taken from
    /// the byte budget.
    fn growth(&mut self) -> u32 {
        let backlog = if self.starved {
            0
        } else {
            u32::try_from(self.min_queued)
                .unwrap_or(u32::MAX)
                .saturating_mul(FRAME_ESTIMATE)
        };
        self.starved = false;
        self.min_queued = usize::MAX;
        let wanted = self.tuner.wants_growth(backlog);
        if wanted == 0 {
            return 0;
        }
        if self
            .window
            .as_mut()
            .is_some_and(|w| w.try_grow(usize::try_from(wanted).unwrap_or(usize::MAX)))
        {
            self.tuner.grew(wanted);
            if let Some(c) = self.grows {
                c.inc();
            }
            wanted
        } else {
            self.tuner.refused();
            if let Some(c) = self.refusals {
                c.inc();
            }
            0
        }
    }
}

impl Downlink<'_> {
    async fn run<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        local_write: Option<std::time::Duration>,
    ) -> Result<(), NetError> {
        loop {
            self.tuning.before_recv(self.rx.len());
            match self.rx.recv().await {
                None
                | Some(Frame::Close {
                    reason: CloseReason::Normal,
                    ..
                }) => return Ok(()),
                // A close due to a peer error is an error here too (finding 0003-3).
                Some(Frame::Close { reason, .. }) => return Err(NetError::StreamClosed(reason)),
                Some(Frame::Data { payload, .. }) => {
                    self.recv
                        .consume(payload.len())
                        .map_err(NetError::Protocol)?;
                    let plaintext = lock(self.transport)?.decrypt(payload.as_bytes())?;
                    // Flush on every message: the stdout of `zt-client` is line-buffered and
                    // SSH does not send lines (finding 0003-1).
                    let write = async {
                        writer.write_all(&plaintext).await?;
                        writer.flush().await
                    };
                    match local_write {
                        Some(limit) => timeout(limit, write)
                            .await
                            .map_err(|_| NetError::Timeout("local write"))??,
                        None => write.await?,
                    }
                    self.delivered
                        .add(u64::try_from(plaintext.len()).unwrap_or(u64::MAX));
                    let cost = charge(payload.len());
                    self.tuning.tuner.on_delivered(cost);
                    self.consumed = self.consumed.saturating_add(cost);
                    if self.consumed >= self.tuning.tuner.update_threshold() {
                        // The consumed bytes come back, plus the growth of the window if the
                        // tuner asks for one and the budget has room for it.
                        let granted = self.consumed.saturating_add(self.tuning.growth());
                        let credit = Credit::try_from(granted)
                            .map_err(|_| NetError::Protocol("zero credit"))?;
                        self.recv.grant(granted).map_err(NetError::Protocol)?;
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

/// Closes a stream from outside the pump (for example when the client is revoked).
pub(crate) struct Closer {
    stream: StreamId,
    tx: mpsc::Sender<Frame>,
}

impl Closer {
    /// Sends `Close` with the given reason. Best effort.
    pub(crate) async fn close(&self, reason: CloseReason) {
        let _ = self
            .tx
            .send(Frame::Close {
                stream: self.stream,
                reason,
            })
            .await;
    }
}
