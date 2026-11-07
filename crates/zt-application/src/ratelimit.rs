//! Rate limiting a token bucket, con orologio iniettato.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Token bucket: fino a `capacity` eventi a raffica, poi uno ogni `refill_every`.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: u32,
    tokens: u32,
    refill_every: Duration,
    last: Instant,
}

impl TokenBucket {
    /// Un bucket pieno.
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
            // refill_every == 0: nessun limite di frequenza oltre la capacità.
            self.tokens = self.capacity;
            self.last = now;
            return;
        };
        if earned == 0 {
            return;
        }
        let earned = u32::try_from(earned).unwrap_or(u32::MAX);
        self.tokens = self.tokens.saturating_add(earned).min(self.capacity);
        // Avanza `last` solo dei periodi interi consumati, oppure fino a `now` se il bucket è pieno.
        self.last = if self.tokens == self.capacity {
            now
        } else {
            self.refill_every
                .checked_mul(earned)
                .and_then(|d| self.last.checked_add(d))
                .unwrap_or(now)
        };
    }

    /// Consuma un token se disponibile.
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

    /// `true` se il bucket è pieno (equivalente a uno nuovo, quindi eliminabile).
    pub fn is_full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens == self.capacity
    }
}

/// Chiave di rate limiting per un indirizzo sorgente.
///
/// IPv4 (anche nella forma IPv4-mapped) per indirizzo; IPv6 per prefisso /64, perché un
/// singolo cliente riceve tipicamente un intero /64 e potrebbe altrimenti presentarsi con
/// 2^64 indirizzi diversi (finding 0002-5).
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

/// Un token bucket per chiave (per esempio per indirizzo IP), con numero di chiavi limitato.
///
/// Quando la tabella è piena si eliminano i bucket già pieni; se non basta, le chiavi nuove
/// vengono **rifiutate** (fail closed): un attaccante con molti indirizzi non può far crescere
/// la memoria del relay.
#[derive(Debug)]
pub struct KeyedRateLimiter<K> {
    buckets: HashMap<K, TokenBucket>,
    max_keys: usize,
    capacity: u32,
    refill_every: Duration,
}

impl<K: Hash + Eq + Clone> KeyedRateLimiter<K> {
    /// Un limiter vuoto.
    #[must_use]
    pub fn new(max_keys: usize, capacity: u32, refill_every: Duration) -> Self {
        Self {
            buckets: HashMap::new(),
            max_keys,
            capacity,
            refill_every,
        }
    }

    /// `true` se l'evento per `key` è ammesso.
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

    /// Numero di chiavi tracciate.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// `true` se non traccia nessuna chiave.
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
        // Dopo il refill i bucket pieni vengono eliminati e c'è di nuovo spazio.
        assert!(l.check(&3, t0 + Duration::from_secs(60)));
        assert!(l.len() <= 2);
    }
}
