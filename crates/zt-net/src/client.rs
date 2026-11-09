//! Client library: opens a stream to a node through the relay and connects it to a local
//! stream (in `zt-client`, the stdin/stdout of OpenSSH).

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use futures::StreamExt;
use futures::stream::FuturesUnordered;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, timeout_at};
pub use zt_application::failover::FailoverConfig;
use zt_application::failover::{Action, Event, FailoverPlan, Failure, GiveUp, MAX_IN_FLIGHT, Step};
use zt_crypto::noise::{self, Channel};
use zt_crypto::{Identity, PublicKey};
use zt_domain::flow::Window;
use zt_domain::{CloseReason, Frame, NodeId, RejectReason, StreamId};

use crate::channel::Established;
use crate::stream::{STREAM_QUEUE, StreamIo, pump};
use crate::{NetError, Timeouts, channel};

/// Configuration of a client connection.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Relays to try, in order (at most [`crate::MAX_RELAYS`], PROTOCOL §13).
    pub relays: Vec<crate::RelayEndpoint>,
    /// Destination node.
    pub node: NodeId,
    /// Public key of the node's agent, pinned for the end-to-end channel.
    pub node_key: PublicKey,
    /// Handshake suite pinned for the end-to-end channel with the node (PROTOCOL §7.5).
    pub node_suite: zt_domain::HandshakeSuite,
    /// Client certificate (PROTOCOL §15), sent in message 1 of both channels.
    pub certificate: Option<std::sync::Arc<[u8]>>,
    /// Network timeouts.
    pub timeouts: Timeouts,
    /// Overall deadline, per-step timeouts and hedge of the relay attempts (resilience R-4).
    pub failover: FailoverConfig,
    /// The outer suite every relay must be pinned to (`require_outer_suite`, finding A10-9):
    /// a relay pinned to another one is refused before any connection, so neither failover
    /// nor a hedge can land on it.
    pub require_outer_suite: Option<zt_domain::HandshakeSuite>,
}

/// How long a cancelled attempt that already sent `Open` may take to send its `Close`: the
/// agent's stream slot is released at once instead of at the relay's own timeout.
const CLOSE_GRACE: Duration = Duration::from_secs(1);

/// Connects to the node and forwards `local` until either side closes.
///
/// Tries the relays with the [`FailoverPlan`] of `config.failover` (PROTOCOL §13): in order,
/// hedging an attempt that has not completed its outer handshake after the stagger, moving on
/// only for failures that precede the `OpenAck` and say nothing about the right of access,
/// within an overall deadline.
///
/// # Errors
/// [`NetError::Rejected`] if a relay denies the stream, [`NetError::StreamClosed`] if the
/// agent rejects the client, [`NetError::Deadline`] if no relay answered in time, in addition
/// to network and handshake errors (of the last relay tried).
pub async fn connect<L>(
    identity: &Identity,
    config: &ClientConfig,
    local: L,
) -> Result<(), NetError>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    connect_with(identity, config, local, crate::net::TcpDialer).await
}

/// Like [`connect`], dialing the relays through `dialer` (the network port, [`crate::net`]).
///
/// # Errors
/// Like [`connect`].
pub async fn connect_with<L, D>(
    identity: &Identity,
    config: &ClientConfig,
    local: L,
    dialer: D,
) -> Result<(), NetError>
where
    L: AsyncRead + AsyncWrite + Unpin,
    D: crate::net::Dialer,
{
    let t = &config.timeouts;
    if config.relays.is_empty() || config.relays.len() > crate::MAX_RELAYS {
        return Err(NetError::Protocol(
            "the client needs between 1 and 8 relays",
        ));
    }
    config.failover.validate().map_err(NetError::Protocol)?;
    if let Some(required) = config.require_outer_suite
        && config.relays.iter().any(|r| r.suite != required)
    {
        return Err(NetError::Protocol(
            "a relay is pinned to another suite than require_outer_suite",
        ));
    }
    // The same certificate in message 1 of both channels (PROTOCOL §15.3): relay and agent each
    // verify it against their own CAs.
    let certificate: &[u8] = config.certificate.as_deref().unwrap_or(&[]);
    let stream = StreamId::try_from(1).map_err(|_| NetError::Protocol("stream id"))?;
    let ctx = AttemptCtx {
        identity,
        node: &config.node,
        stream,
        certificate,
        t,
        dialer: &dialer,
    };
    let (relay, ch, losers) = establish(&ctx, config).await?;
    // During the rollout of OPERATIONS §13 pins are mixed: an attacker who resets the
    // hybrid-pinned relays makes failover land on a classical one. Say so (finding A10-9);
    // `require_outer_suite` rules it out.
    if let (Some(first), Some(used)) = (config.relays.first(), config.relays.get(relay))
        && first.suite != used.suite
    {
        tracing::warn!(
            relay = %used.address,
            suite = used.suite.protocol_name(),
            preferred_suite = first.suite.protocol_name(),
            "failover to a relay pinned to another outer suite"
        );
    }

    let (to_stream, from_driver) = mpsc::channel(STREAM_QUEUE);
    let (out_tx, out_rx) = mpsc::channel(1024);
    let relay_link = drive(ch, stream, to_stream, out_rx, t);
    let session = async {
        let mut io = StreamIo::new(stream, from_driver, out_tx);
        let (msg1, waiting) = noise::initiate_suite(
            identity,
            &config.node_key,
            Channel::EndToEnd,
            config.node_suite,
            certificate,
        )?;
        io.send_data(msg1).await?;
        let msg2 = io.recv_message(t).await?;
        let mut transport = waiting.complete(&msg2)?;
        // Proves to the agent that this client completed the handshake (PROTOCOL §7.3): a relay
        // replaying message 1 cannot produce it.
        io.send_data(transport.encrypt(config.node_suite.confirmation())?)
            .await?;
        pump(io, transport, local, None).await
    };
    // The losers close in the background of the session, without delaying it.
    let (link, session, ()) = tokio::join!(relay_link, session, losers.close());
    session.and(link)
}

/// What every attempt shares.
struct AttemptCtx<'a, D> {
    identity: &'a Identity,
    node: &'a NodeId,
    stream: StreamId,
    certificate: &'a [u8],
    t: &'a Timeouts,
    dialer: &'a D,
}

/// The outcome of one attempt: its relay and its connection after the `OpenAck`.
type AttemptResult<S> = (usize, Result<Established<S>, NetError>);
/// Attempts in flight. They are futures of this task, not spawned tasks: dropping the set
/// drops every connection (RAII), nothing outlives the client.
type Attempts<'a, S> =
    FuturesUnordered<Pin<Box<dyn Future<Output = AttemptResult<S>> + Send + 'a>>>;

/// The attempts cancelled after the winner: each ends at once, or after sending `Close` for
/// an `Open` already sent (bounded by [`CLOSE_GRACE`]); a late winner is closed the same way.
struct Losers<'a, S> {
    attempts: Attempts<'a, S>,
    stream: StreamId,
    t: &'a Timeouts,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Losers<'_, S> {
    async fn close(mut self) {
        while let Some((_, result)) = self.attempts.next().await {
            if let Ok(mut ch) = result {
                close_politely(&mut ch, self.stream, self.t).await;
            }
        }
    }
}

/// Runs the [`FailoverPlan`] until a relay acknowledges the stream.
async fn establish<'a, D: crate::net::Dialer>(
    ctx: &'a AttemptCtx<'a, D>,
    config: &'a ClientConfig,
) -> Result<(usize, Established<D::Stream>, Losers<'a, D::Stream>), NetError> {
    let mut plan = FailoverPlan::new(
        config.failover,
        config.relays.len(),
        getrandom::u64().unwrap_or(0),
    );
    let started = tokio::time::Instant::now();
    let mut attempts: Attempts<'a, D::Stream> = FuturesUnordered::new();
    // A dropped sender cancels its attempt.
    let mut cancels: Vec<Option<oneshot::Sender<()>>> = std::iter::repeat_with(|| None)
        .take(config.relays.len())
        .collect();
    // Each attempt reports at most two steps: the queue never fills.
    let (progress_tx, mut progress_rx) =
        mpsc::channel::<Event>(MAX_IN_FLIGHT.saturating_mul(crate::MAX_RELAYS));
    let mut last = NetError::Closed;
    let mut actions = plan.start();
    loop {
        for action in std::mem::take(&mut actions) {
            match action {
                Action::Start(i) => {
                    let Some(relay) = config.relays.get(i) else {
                        continue;
                    };
                    let (cancel_tx, cancel_rx) = oneshot::channel();
                    if let Some(slot) = cancels.get_mut(i) {
                        *slot = Some(cancel_tx);
                    }
                    attempts.push(Box::pin(attempt(
                        ctx,
                        i,
                        relay,
                        progress_tx.clone(),
                        cancel_rx,
                    )));
                }
                Action::Cancel(i) => cancel(&mut cancels, i),
                Action::TimedOut(i, step) => {
                    cancel(&mut cancels, i);
                    if let Some(relay) = config.relays.get(i) {
                        tracing::warn!(relay = %relay.address, step = step_name(step), "relay timed out, trying the next one");
                    }
                    last = NetError::Timeout(step_name(step));
                }
                Action::GiveUp(GiveUp::Deadline) => {
                    return Err(NetError::Deadline(config.failover.deadline));
                }
                Action::GiveUp(_) => return Err(last),
                Action::Proceed(_) => {}
            }
        }
        let wake = plan
            .next_wake()
            .and_then(|w| started.checked_add(w))
            .unwrap_or(started);
        // Biased: a step already reported counts before a timer that fires at the same
        // moment, so a handshake that just completed is never hedged.
        tokio::select! {
            biased;
            Some(event) = progress_rx.recv() => {
                actions = plan.handle(started.elapsed(), event);
            }
            Some((i, result)) = attempts.next(), if !attempts.is_empty() => {
                let now = started.elapsed();
                match result {
                    Ok(ch) => {
                        actions = plan.handle(now, Event::Acked(i));
                        if actions.contains(&Action::Proceed(i)) {
                            for a in &actions {
                                if let Action::Cancel(j) = a {
                                    cancel(&mut cancels, *j);
                                }
                            }
                            return Ok((i, ch, Losers { attempts, stream: ctx.stream, t: ctx.t }));
                        }
                        // Not in flight any more (timed out in the meantime): close it.
                        let mut ch = ch;
                        close_politely(&mut ch, ctx.stream, ctx.t).await;
                    }
                    Err(NetError::Stopped(CANCELLED)) => {}
                    Err(err) => {
                        let failure = if may_try_next_relay(&err) {
                            Failure::Unavailable
                        } else {
                            Failure::Refused
                        };
                        actions = plan.handle(now, Event::Failed(i, failure));
                        if let Some(Action::GiveUp(GiveUp::Refused(_))) = actions.last() {
                            return Err(err);
                        }
                        if config.relays.get(i.saturating_add(1)).is_some()
                            && let Some(relay) = config.relays.get(i)
                        {
                            tracing::warn!(relay = %relay.address, error = %err, "relay unavailable, trying the next one");
                        }
                        last = err;
                    }
                }
            }
            () = tokio::time::sleep_until(wake) => {
                actions = plan.tick(started.elapsed());
            }
        }
    }
}

/// Cancels attempt `i` by dropping its sender.
fn cancel(cancels: &mut [Option<oneshot::Sender<()>>], i: usize) {
    if let Some(slot) = cancels.get_mut(i) {
        slot.take();
    }
}

/// The marker error of a cancelled attempt.
const CANCELLED: &str = "attempt cancelled";

const fn step_name(step: Step) -> &'static str {
    match step {
        Step::Connect => "connect",
        Step::Handshake => "handshake",
        Step::Open => "open",
    }
}

/// One attempt: connection, outer handshake and stream opening on `relay`, reporting each
/// step; it ends as soon as `cancel` fires (or its sender is dropped), with a `Close` for an
/// `Open` already sent.
async fn attempt<'a, D: crate::net::Dialer>(
    ctx: &'a AttemptCtx<'a, D>,
    index: usize,
    relay: &'a crate::RelayEndpoint,
    progress: mpsc::Sender<Event>,
    mut cancel: oneshot::Receiver<()>,
) -> AttemptResult<D::Stream> {
    let t = ctx.t;
    let cancelled = || (index, Err(NetError::Stopped(CANCELLED)));
    let tcp = tokio::select! {
        r = timeout(t.handshake, ctx.dialer.connect(&relay.address)) => match r {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(e)) => return (index, Err(e.into())),
            Err(_) => return (index, Err(NetError::Timeout("connect"))),
        },
        _ = &mut cancel => return cancelled(),
    };
    let _ = progress.try_send(Event::Connected(index));
    let opened = tokio::select! {
        r = async {
            let mut ch = channel::connect_suite(
                tcp,
                ctx.identity,
                &relay.public_key,
                Channel::Outer,
                relay.suite,
                ctx.certificate,
                t,
            )
            .await?;
            ch.send(
                &Frame::Open {
                    stream: ctx.stream,
                    target: ctx.node.clone(),
                },
                t,
            )
            .await?;
            Ok::<_, NetError>(ch)
        } => r,
        _ = &mut cancel => return cancelled(),
    };
    let mut ch = match opened {
        Ok(ch) => ch,
        Err(e) => return (index, Err(e)),
    };
    let _ = progress.try_send(Event::OuterReady(index));
    let acked = tokio::select! {
        r = timeout(t.open, await_ack(&mut ch, ctx.stream)) => Some(r),
        _ = &mut cancel => None,
    };
    match acked {
        Some(Ok(Ok(()))) => (index, Ok(ch)),
        Some(Ok(Err(e))) => (index, Err(e)),
        Some(Err(_)) => (index, Err(NetError::Timeout("open"))),
        None => {
            close_politely(&mut ch, ctx.stream, t).await;
            cancelled()
        }
    }
}

/// `Close Normal` for the stream, then EOF when the connection is dropped: the relay and the
/// agent release the stream at once.
async fn close_politely<S: AsyncRead + AsyncWrite + Unpin>(
    ch: &mut Established<S>,
    stream: StreamId,
    t: &Timeouts,
) {
    let close = Frame::Close {
        stream,
        reason: CloseReason::Normal,
    };
    let _ = timeout(CLOSE_GRACE, ch.send(&close, t)).await;
}

/// `true` for a failure, before the `OpenAck`, that justifies trying the next relay. A policy
/// response is final (fail closed): the client does not look for a more permissive relay.
const fn may_try_next_relay(err: &NetError) -> bool {
    match err {
        NetError::Rejected(reason) => matches!(
            reason,
            RejectReason::NodeOffline | RejectReason::RateLimited
        ),
        NetError::Io(_)
        | NetError::Timeout(_)
        | NetError::Crypto(_)
        | NetError::Decode(_)
        | NetError::Protocol(_)
        | NetError::Closed => true,
        _ => false,
    }
}

async fn await_ack<IO>(ch: &mut Established<IO>, stream: StreamId) -> Result<(), NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match ch.recv().await?.ok_or(NetError::Closed)? {
            Frame::OpenAck { stream: s } if s == stream => return Ok(()),
            Frame::Reject { stream: s, reason } if s == stream => {
                return Err(NetError::Rejected(reason));
            }
            Frame::Pong { .. } => {}
            _ => return Err(NetError::Protocol("unexpected frame while opening")),
        }
    }
}

/// Forwards frames between the relay connection and the stream, until the stream ends.
async fn drive<IO>(
    mut ch: Established<IO>,
    stream: StreamId,
    to_stream: mpsc::Sender<Frame>,
    mut out_rx: mpsc::Receiver<Frame>,
    t: &Timeouts,
) -> Result<(), NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut keepalive = tokio::time::interval(t.keepalive);
    keepalive.tick().await;
    let mut deadline = crate::deadline(t.idle);
    let mut nonce: u64 = 0;
    // Relay credit towards the stream, enforced before enqueuing (finding 0002-14).
    let mut recv = Window::initial();
    loop {
        tokio::select! {
            inbound = timeout_at(deadline, ch.recv()) => {
                let frame = inbound.map_err(|_| NetError::Timeout("relay idle"))??.ok_or(NetError::Closed)?;
                deadline = crate::deadline(t.idle);
                match &frame {
                    Frame::Data { stream: s, .. } | Frame::WindowUpdate { stream: s, .. } | Frame::Close { stream: s, .. }
                        if *s == stream =>
                    {
                        if let Frame::Data { payload, .. } = &frame {
                            recv.consume(payload.len()).map_err(NetError::Protocol)?;
                        }
                        if to_stream.try_send(frame).is_err() {
                            return Err(NetError::Protocol("stream queue overflow"));
                        }
                    }
                    Frame::Pong { .. } => {}
                    _ => return Err(NetError::Protocol("unexpected frame from relay")),
                }
            }
            outbound = out_rx.recv() => match outbound {
                Some(frame) => {
                    if let Frame::WindowUpdate { credit, .. } = &frame {
                        recv.grant(credit.get()).map_err(NetError::Protocol)?;
                    }
                    ch.send(&frame, t).await?;
                }
                None => return Ok(()),
            },
            _ = keepalive.tick() => {
                nonce = nonce.wrapping_add(1);
                ch.send(&Frame::Ping { nonce }, t).await?;
            }
        }
    }
}
