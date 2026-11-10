//! Token bucket rate limiting, with an injected clock.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Token bucket: up to `capacity` events in a burst, then one every `refill_every`.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: u32,
    tokens: u32,
    refill_every: Duration,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket.
    #[must_use]
    pub const fn new(capacity: u32, refill_every: Duration, now: Instant) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_every,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_nanos();
        let Some(earned) = elapsed.checked_div(self.refill_every.as_nanos()) else {
            // refill_every == 0: no rate limit beyond the capacity.
            self.tokens = self.capacity;
            self.last = now;
            return;
        };
        if earned == 0 {
            return;
        }
        let earned = u32::try_from(earned).unwrap_or(u32::MAX);
        self.tokens = self.tokens.saturating_add(earned).min(self.capacity);
        // Advance `last` only by the whole periods consumed, or up to `now` if the bucket is full.
        self.last = if self.tokens == self.capacity {
            now
        } else {
            self.refill_every
                .checked_mul(earned)
                .and_then(|d| self.last.checked_add(d))
                .unwrap_or(now)
        };
    }

    /// Consumes a token if available.
    pub fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        match self.tokens.checked_sub(1) {
            Some(left) => {
                self.tokens = left;
                true
            }
            None => false,
        }
    }

    /// Gives one token back, never above the capacity (R-1: the refund after key confirmation).
    pub fn refund(&mut self, now: Instant) {
        self.refill(now);
        self.tokens = self.tokens.saturating_add(1).min(self.capacity);
    }

    /// `true` if the bucket is full (equivalent to a new one, hence removable).
    pub fn is_full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens == self.capacity
    }
}

/// Rate-limiting key for a source address.
///
/// IPv4 (also in IPv4-mapped form) per address; IPv6 per /64 prefix, because a single
/// customer typically receives a whole /64 and could otherwise show up with 2^64 different
/// addresses (finding 0002-5).
#[must_use]
pub fn source_key(addr: IpAddr) -> [u8; 9] {
    let mut key = [0_u8; 9];
    match addr.to_canonical() {
        IpAddr::V4(v4) => {
            if let Some(slot) = key.get_mut(1..5) {
                slot.copy_from_slice(&v4.octets());
            }
        }
        IpAddr::V6(v6) => {
            if let Some(tag) = key.first_mut() {
                *tag = 6;
            }
            if let (Some(slot), Some(prefix)) = (key.get_mut(1..9), v6.octets().get(..8)) {
                slot.copy_from_slice(prefix);
            }
        }
    }
    key
}

/// One token bucket per key (for example per IP address), with a bounded number of keys.
///
/// When the table is full the already-full buckets are removed; if that is not enough, new
/// keys are **rejected** (fail closed): an attacker with many addresses cannot make the
/// relay's memory grow.
#[derive(Debug)]
pub struct KeyedRateLimiter<K> {
    buckets: HashMap<K, TokenBucket>,
    max_keys: usize,
    capacity: u32,
    refill_every: Duration,
}

impl<K: Hash + Eq + Clone> KeyedRateLimiter<K> {
    /// An empty limiter.
    #[must_use]
    pub fn new(max_keys: usize, capacity: u32, refill_every: Duration) -> Self {
        Self {
            buckets: HashMap::new(),
            max_keys,
            capacity,
            refill_every,
        }
    }

    /// `true` if the event for `key` is allowed.
    pub fn check(&mut self, key: &K, now: Instant) -> bool {
        if let Some(bucket) = self.buckets.get_mut(key) {
            return bucket.try_take(now);
        }
        if self.buckets.len() >= self.max_keys {
            self.buckets.retain(|_, b| !b.is_full(now));
            if self.buckets.len() >= self.max_keys {
                return false;
            }
        }
        let mut bucket = TokenBucket::new(self.capacity, self.refill_every, now);
        let allowed = bucket.try_take(now);
        self.buckets.insert(key.clone(), bucket);
        allowed
    }

    /// Gives one token back to `key`. Nothing happens for a key without a bucket (it was
    /// evicted because it was full, so there is nothing to give back).
    pub fn refund(&mut self, key: &K, now: Instant) {
        if let Some(bucket) = self.buckets.get_mut(key) {
            bucket.refund(now);
        }
    }

    /// `true` if `key` already has a bucket.
    #[must_use]
    pub fn contains(&self, key: &K) -> bool {
        self.buckets.contains_key(key)
    }

    /// Number of tracked keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// `true` if it tracks no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(3, Duration::from_secs(1), t0);
        assert!(b.try_take(t0) && b.try_take(t0) && b.try_take(t0));
        assert!(!b.try_take(t0));
        assert!(!b.try_take(t0 + Duration::from_millis(999)));
        assert!(b.try_take(t0 + Duration::from_secs(1)));
        assert!(!b.try_take(t0 + Duration::from_secs(1)));
    }

    #[test]
    fn long_idle_never_exceeds_capacity() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(2, Duration::from_nanos(1), t0);
        let later = t0 + Duration::from_secs(3600 * 24 * 365);
        assert!(b.try_take(later) && b.try_take(later));
        assert!(!b.try_take(later));
    }

    #[test]
    fn clock_going_backwards_does_not_refill() {
        let t0 = Instant::now() + Duration::from_secs(10);
        let mut b = TokenBucket::new(1, Duration::from_secs(1), t0);
        assert!(b.try_take(t0));
        assert!(!b.try_take(t0.checked_sub(Duration::from_secs(5)).unwrap()));
    }

    #[test]
    fn keyed_limiter_is_per_key() {
        let t0 = Instant::now();
        let mut l = KeyedRateLimiter::new(10, 1, Duration::from_secs(60));
        assert!(l.check(&"a", t0));
        assert!(!l.check(&"a", t0));
        assert!(l.check(&"b", t0));
    }

    #[test]
    fn keyed_limiter_fails_closed_when_the_table_is_full() {
        let t0 = Instant::now();
        let mut l = KeyedRateLimiter::new(2, 1, Duration::from_secs(60));
        assert!(l.check(&1, t0));
        assert!(l.check(&2, t0));
        assert!(!l.check(&3, t0), "no room and nothing to evict");
        assert_eq!(l.len(), 2);
        // After the refill the full buckets are removed and there is room again.
        assert!(l.check(&3, t0 + Duration::from_secs(60)));
        assert!(l.len() <= 2);
    }
}

/// "Wide" key of the rate limiter: the /48 prefix for IPv6, none for IPv4.
///
/// A /48 is the typical allocation of a site: whoever controls it has 65,536 /64 prefixes and
/// with only the per-/64 key could fill the limiter table and block new addresses for
/// everyone (residue of finding 0002-5). For IPv4 it is not needed: an attacker with many
/// IPv4 addresses is already limited by the table size and by the cost of addresses.
#[must_use]
pub fn wide_source_key(addr: IpAddr) -> Option<[u8; 7]> {
    match addr.to_canonical() {
        IpAddr::V4(_) => None,
        IpAddr::V6(v6) => {
            let mut key = [6_u8; 7];
            let (slot, prefix) = (key.get_mut(1..7)?, v6.octets().get(..6)?.to_owned());
            slot.copy_from_slice(&prefix);
            Some(key)
        }
    }
}

/// Handshake gate of the relay: one bucket per IPv4 address or IPv6 /64 prefix and, for
/// IPv6, a second bucket per /48 prefix that limits the appearance of **new** /64s, so a
/// hostile /48 cannot fill the /64 table.
///
/// The /48 bucket is consumed only for a /64 the limiter does not already know: a single
/// persistent host is throttled by its own bucket and cannot exhaust the /48 one, blocking
/// its neighbors (finding 0004-1).
#[derive(Debug)]
pub struct HandshakeGate {
    narrow: KeyedRateLimiter<[u8; 9]>,
    wide: KeyedRateLimiter<[u8; 7]>,
}

impl HandshakeGate {
    /// `burst`/`refill` per address or /64; `wide_burst`/`wide_refill` per /48.
    #[must_use]
    pub fn new(
        max_keys: usize,
        burst: u32,
        refill: Duration,
        wide_burst: u32,
        wide_refill: Duration,
        max_wide_keys: usize,
    ) -> Self {
        Self {
            narrow: KeyedRateLimiter::new(max_keys, burst, refill),
            wide: KeyedRateLimiter::new(max_wide_keys, wide_burst, wide_refill),
        }
    }

    /// `true` if the handshake from `addr` is allowed now.
    pub fn admit(&mut self, addr: IpAddr, now: Instant) -> bool {
        let narrow = source_key(addr);
        if !self.narrow.contains(&narrow)
            && let Some(wide) = wide_source_key(addr)
            && !self.wide.check(&wide, now)
        {
            return false;
        }
        self.narrow.check(&narrow, now)
    }

    /// Gives back the per-address token of a handshake from `addr` whose key was confirmed
    /// (R-1, finding G1). The /48 token is not given back: it counts the appearance of new
    /// /64s, which a confirmation does not undo.
    pub fn refund(&mut self, addr: IpAddr, now: Instant) {
        self.narrow.refund(&source_key(addr), now);
    }
}
