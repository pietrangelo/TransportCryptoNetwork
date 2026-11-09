//! How the client tries its relays (docs/analysis/resilience.md §5.3, D-4; review 0007 AP-10;
//! backlog A5-4): sans-IO, with time passed in as the time elapsed since the plan started and
//! the jitter as a random sample.
//!
//! - **Order:** the relays are tried in the configured order, the first one alone.
//! - **Overall deadline** (`deadline`, 8 s): establishment (connect, outer handshake,
//!   `OpenAck`) ends there; after `Proceed` the plan has no timer left. It fits inside the 10 s
//!   `ConnectTimeout` that Ansible passes to `ssh` by default, end-to-end handshake and SSH
//!   banner included (review 0011, A11-2).
//! - **Per-step timeouts:** connect 3 s from the start of the attempt, outer handshake 5 s
//!   from the connect, `OpenAck` from the end of the handshake: the time left before the
//!   deadline shared out over this relay and those not yet started, at least the stagger and at
//!   most `open` (4 s). Relays that handshake and then sit on `Open` therefore cannot use up
//!   the deadline before a healthy later relay is tried (A11-3).
//! - **Staggered hedge:** a new attempt starts when nothing is in flight, or when the only
//!   attempt in flight has **not completed connect and outer handshake** after the stagger
//!   (2 s plus a jitter of at most a quarter of it). That is the black-hole signal. A relay that
//!   handshakes and is then slow to answer `Open` is overloaded, not dead: hedging it would
//!   double the load when the relays can least take it (AP-10), so the plan waits for its
//!   `OpenAck` up to the open timeout instead. At most [`MAX_IN_FLIGHT`] attempts are in flight.
//! - **First `OpenAck` wins:** `Proceed` for it, `Cancel` for every other attempt, then nothing
//!   more. The end-to-end message 1 is therefore sent on one relay only.
//! - **Fail closed:** a policy answer ([`Failure::Refused`]) before any `OpenAck` cancels every
//!   attempt and gives up. A refusal that arrives after `Proceed` is ignored (accepted in §5.3:
//!   mismatched relay policies are a configuration error).

use core::time::Duration;

/// The most attempts in flight at once.
pub const MAX_IN_FLIGHT: usize = 2;

/// The longest overall deadline accepted: an `ssh` that hangs longer is a bug, not a policy.
pub const MAX_DEADLINE: Duration = Duration::from_secs(300);

/// The failover parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailoverConfig {
    /// Overall deadline of establishment.
    pub deadline: Duration,
    /// TCP connect of one attempt.
    pub connect: Duration,
    /// Outer handshake (and sending `Open`) of one attempt, from its connect.
    pub handshake: Duration,
    /// The longest wait for the `OpenAck`, from the end of the outer handshake (the plan shares
    /// out the time left over the relays left, see the module documentation).
    pub open: Duration,
    /// Delay before hedging an attempt that has not completed its outer handshake.
    pub stagger: Duration,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(8),
            connect: Duration::from_secs(3),
            handshake: Duration::from_secs(5),
            open: Duration::from_secs(4),
            stagger: Duration::from_secs(2),
        }
    }
}

impl FailoverConfig {
    /// `Ok` for a usable configuration.
    ///
    /// # Errors
    /// A zero duration, or a deadline over [`MAX_DEADLINE`].
    pub fn validate(&self) -> Result<(), &'static str> {
        if [
            self.deadline,
            self.connect,
            self.handshake,
            self.open,
            self.stagger,
        ]
        .iter()
        .any(Duration::is_zero)
        {
            return Err("failover durations must not be zero");
        }
        if self.deadline > MAX_DEADLINE {
            return Err("the connect deadline is at most 300 s");
        }
        Ok(())
    }
}

/// The step an attempt is in, for its timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// TCP connect.
    Connect,
    /// Outer handshake and `Open`.
    Handshake,
    /// Waiting for the `OpenAck`.
    Open,
}

/// Why an attempt failed, as the adapter reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Says nothing about the right of access (I/O, timeout, handshake, `NodeOffline`,
    /// `RateLimited`): the next relay may be tried.
    Unavailable,
    /// A policy answer (`NotAuthorized`, `UnknownNode`...): final for every attempt.
    Refused,
}

/// What happened to an attempt (relay index in the configured list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// TCP connected.
    Connected(usize),
    /// Outer handshake completed and `Open` sent.
    OuterReady(usize),
    /// `OpenAck` received.
    Acked(usize),
    /// The attempt ended without an `OpenAck`.
    Failed(usize, Failure),
}

/// Why the plan gave up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GiveUp {
    /// The overall deadline passed.
    Deadline,
    /// Every relay was tried and failed.
    Exhausted,
    /// This relay answered with a policy refusal.
    Refused(usize),
}

/// What the adapter must do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Start an attempt on this relay.
    Start(usize),
    /// Cancel this attempt (another one won, or the plan gave up).
    Cancel(usize),
    /// Cancel this attempt: its step timed out.
    TimedOut(usize, Step),
    /// Use this relay's connection for the session.
    Proceed(usize),
    /// Stop: no session.
    GiveUp(GiveUp),
}

/// An attempt in flight.
#[derive(Debug, Clone, Copy)]
struct Attempt {
    relay: usize,
    started: Duration,
    step: Step,
    /// When the current step started.
    since: Duration,
    /// The `OpenAck` wait, fixed when the attempt enters [`Step::Open`].
    open: Duration,
}

impl Attempt {
    fn expires(&self, config: &FailoverConfig) -> Duration {
        let limit = match self.step {
            Step::Connect => config.connect,
            Step::Handshake => config.handshake,
            Step::Open => self.open,
        };
        self.since.saturating_add(limit)
    }
}

/// The failover state of one connection.
#[derive(Debug, Clone)]
pub struct FailoverPlan {
    config: FailoverConfig,
    relays: usize,
    hedge_delay: Duration,
    /// The next relay to start.
    next: usize,
    flying: Vec<Attempt>,
    finished: bool,
}

impl FailoverPlan {
    /// A plan over `relays` relays. `jitter` is a random sample: the stagger is delayed by
    /// `jitter mod (stagger/4 + 1 ms)`, so the same sample gives the same plan.
    #[must_use]
    pub fn new(config: FailoverConfig, relays: usize, jitter: u64) -> Self {
        let quarter = u64::try_from(config.stagger.as_millis() / 4).unwrap_or(u64::MAX);
        let extra = jitter.checked_rem(quarter.saturating_add(1)).unwrap_or(0);
        Self {
            config,
            relays,
            hedge_delay: config.stagger.saturating_add(Duration::from_millis(extra)),
            next: 0,
            flying: Vec::with_capacity(MAX_IN_FLIGHT),
            finished: false,
        }
    }

    /// The stagger with its jitter.
    #[must_use]
    pub const fn hedge_delay(&self) -> Duration {
        self.hedge_delay
    }

    /// Attempts in flight.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.flying.len()
    }

    /// `true` while an attempt on `relay` is in flight: an outcome reported for any other
    /// relay is one the plan ignores (cancelled, timed out, never started).
    #[must_use]
    pub fn is_in_flight(&self, relay: usize) -> bool {
        self.flying.iter().any(|a| a.relay == relay)
    }

    /// `true` after `Proceed` or `GiveUp`.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// The first actions, at time zero.
    pub fn start(&mut self) -> Vec<Action> {
        self.tick(Duration::ZERO)
    }

    /// The timer fired (or any other moment): deadline, step timeouts, hedge.
    pub fn tick(&mut self, now: Duration) -> Vec<Action> {
        let mut out = Vec::new();
        if !self.finished {
            self.expire(now, &mut out);
            self.fill(now, &mut out);
        }
        out
    }

    /// An attempt reported `event` at `now`. Events about attempts not in flight (never
    /// started, cancelled, failed, out of range) and every event after the end are ignored.
    pub fn handle(&mut self, now: Duration, event: Event) -> Vec<Action> {
        let mut out = Vec::new();
        if self.finished {
            return out;
        }
        self.expire(now, &mut out);
        if self.finished {
            return out;
        }
        match event {
            Event::Connected(relay) => {
                if let Some(a) = self.attempt(relay).filter(|a| a.step == Step::Connect) {
                    a.step = Step::Handshake;
                    a.since = now;
                }
            }
            Event::OuterReady(relay) => {
                let open = self.open_wait(now);
                if let Some(a) = self.attempt(relay).filter(|a| a.step != Step::Open) {
                    a.step = Step::Open;
                    a.since = now;
                    a.open = open;
                }
            }
            Event::Acked(relay) => {
                if self.attempt(relay).is_some() {
                    self.flying.retain(|a| a.relay != relay);
                    out.push(Action::Proceed(relay));
                    self.end(None, &mut out);
                }
            }
            Event::Failed(relay, failure) => {
                if self.attempt(relay).is_some() {
                    self.flying.retain(|a| a.relay != relay);
                    if failure == Failure::Refused {
                        self.end(Some(GiveUp::Refused(relay)), &mut out);
                    }
                }
            }
        }
        self.fill(now, &mut out);
        out
    }

    /// When to call [`Self::tick`] next; `None` once finished.
    #[must_use]
    pub fn next_wake(&self) -> Option<Duration> {
        if self.finished {
            return None;
        }
        let mut wake = self.config.deadline;
        for a in &self.flying {
            wake = wake.min(a.expires(&self.config));
        }
        if let Some(hedge) = self.hedge_at() {
            wake = wake.min(hedge);
        }
        Some(wake)
    }

    /// The `OpenAck` wait of an attempt whose outer handshake completes at `now`: the time
    /// left shared out over it and the relays not yet started, between the stagger and `open`
    /// (finding A11-3).
    fn open_wait(&self, now: Duration) -> Duration {
        let left = self.config.deadline.saturating_sub(now);
        let unstarted = self.relays.saturating_sub(self.next);
        let share = u32::try_from(unstarted.saturating_add(1))
            .ok()
            .and_then(|n| left.checked_div(n))
            .unwrap_or(Duration::ZERO);
        let floor = self.config.stagger.min(self.config.open);
        share.max(floor).min(self.config.open)
    }

    fn attempt(&mut self, relay: usize) -> Option<&mut Attempt> {
        self.flying.iter_mut().find(|a| a.relay == relay)
    }

    /// When the attempt in flight may be hedged, if it may be at all.
    fn hedge_at(&self) -> Option<Duration> {
        match self.flying.as_slice() {
            [only] if self.next < self.relays && only.step != Step::Open => {
                Some(only.started.saturating_add(self.hedge_delay))
            }
            _ => None,
        }
    }

    /// Deadline, then step timeouts.
    fn expire(&mut self, now: Duration, out: &mut Vec<Action>) {
        if now >= self.config.deadline {
            self.end(Some(GiveUp::Deadline), out);
            return;
        }
        let config = self.config;
        self.flying.retain(|a| {
            let step = a.step;
            if now >= a.expires(&config) {
                out.push(Action::TimedOut(a.relay, step));
                false
            } else {
                true
            }
        });
    }

    /// Starts what may start, or gives up when nothing is left.
    fn fill(&mut self, now: Duration, out: &mut Vec<Action>) {
        if self.finished {
            return;
        }
        while self.next < self.relays {
            let may_start = self.flying.is_empty() || self.hedge_at().is_some_and(|t| now >= t);
            if !may_start {
                break;
            }
            self.flying.push(Attempt {
                relay: self.next,
                started: now,
                step: Step::Connect,
                since: now,
                open: self.config.open,
            });
            out.push(Action::Start(self.next));
            self.next = self.next.saturating_add(1);
        }
        if self.flying.is_empty() && self.next >= self.relays {
            self.end(Some(GiveUp::Exhausted), out);
        }
    }

    /// Cancels every attempt in flight, then gives up (`Some`) or just ends (after `Proceed`).
    fn end(&mut self, reason: Option<GiveUp>, out: &mut Vec<Action>) {
        for a in self.flying.drain(..) {
            out.push(Action::Cancel(a.relay));
        }
        if let Some(reason) = reason {
            out.push(Action::GiveUp(reason));
        }
        self.finished = true;
    }
}
