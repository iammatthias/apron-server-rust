//! A port of `golang.org/x/time/rate`: a token bucket limiter. Only what the
//! server uses is here: `Every`, `NewLimiter`, `Allow`, `ReserveN`, and a
//! reservation's `DelayFrom` and `CancelAt`.

use rust_stdlib::time::{self, Duration, Time};

/// Events per second.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Limit(pub f64);

pub const INF: Limit = Limit(f64::MAX);
pub const INF_DURATION: Duration = Duration::from_nanos(i64::MAX);

/// Go's `rate.Every`: the limit that allows one event every `interval`.
pub fn every(interval: Duration) -> Limit {
    if interval.as_nanos() <= 0 {
        return INF;
    }
    Limit(1.0 / interval.seconds())
}

impl Limit {
    fn duration_from_tokens(self, tokens: f64) -> Duration {
        if self.0 <= 0.0 {
            return INF_DURATION;
        }
        let duration = (tokens / self.0) * time::SECOND.as_nanos() as f64;
        if duration > i64::MAX as f64 {
            return INF_DURATION;
        }
        Duration::from_nanos(duration as i64)
    }

    fn tokens_from_duration(self, d: Duration) -> f64 {
        if self.0 <= 0.0 {
            return 0.0;
        }
        d.seconds() * self.0
    }
}

/// A token bucket of `burst` tokens refilled at `limit` per second. Go's
/// Limiter has its own mutex; here the server guards it with `State`'s.
#[derive(Debug)]
pub struct Limiter {
    limit: Limit,
    burst: i64,
    tokens: f64,
    last: Time,
    last_event: Time,
}

/// The outcome of `reserve_n`.
#[derive(Debug, Clone)]
pub struct Reservation {
    ok: bool,
    tokens: i64,
    time_to_act: Time,
    limit: Limit,
}

impl Limiter {
    pub fn new(r: Limit, b: i64) -> Limiter {
        Limiter {
            limit: r,
            burst: b,
            tokens: b as f64,
            last: Time::default(),
            last_event: Time::default(),
        }
    }

    pub fn tokens_at(&self, t: &Time) -> f64 {
        self.advance(t)
    }

    pub fn tokens(&self) -> f64 {
        self.tokens_at(&time::now())
    }

    pub fn allow(&mut self) -> bool {
        self.allow_n(&time::now(), 1)
    }

    pub fn allow_n(&mut self, t: &Time, n: i64) -> bool {
        self.reserve(t, n, Duration::from_nanos(0)).ok
    }

    pub fn reserve_n(&mut self, t: &Time, n: i64) -> Reservation {
        self.reserve(t, n, INF_DURATION)
    }

    fn reserve(&mut self, t: &Time, n: i64, max_future_reserve: Duration) -> Reservation {
        if self.limit == INF {
            return Reservation {
                ok: true,
                tokens: n,
                time_to_act: t.clone(),
                limit: self.limit,
            };
        }
        let mut tokens = self.advance(t);
        tokens -= n as f64;
        let mut wait = Duration::from_nanos(0);
        if tokens < 0.0 {
            wait = self.limit.duration_from_tokens(-tokens);
        }
        let ok = n <= self.burst && wait.as_nanos() <= max_future_reserve.as_nanos();
        let mut r = Reservation {
            ok,
            tokens: 0,
            time_to_act: Time::default(),
            limit: self.limit,
        };
        if ok {
            r.tokens = n;
            r.time_to_act = t.add(wait);
            self.last = t.clone();
            self.tokens = tokens;
            self.last_event = r.time_to_act.clone();
        }
        r
    }

    /// The tokens at `t`, without changing the limiter.
    fn advance(&self, t: &Time) -> f64 {
        let mut last = self.last.clone();
        if t.before(&last) {
            last = t.clone();
        }
        let elapsed = t.sub(&last);
        let delta = self.limit.tokens_from_duration(elapsed);
        let tokens = self.tokens + delta;
        let burst = self.burst as f64;
        if tokens > burst {
            return burst;
        }
        tokens
    }

    /// Go's `Reservation.CancelAt`: gives the tokens back as far as no later
    /// reservation depends on them.
    pub fn cancel_at(&mut self, r: &Reservation, t: &Time) {
        if !r.ok {
            return;
        }
        if self.limit == INF || r.tokens == 0 || r.time_to_act.before(t) {
            return;
        }
        let restore = r.tokens as f64
            - r.limit
                .tokens_from_duration(self.last_event.sub(&r.time_to_act));
        if restore <= 0.0 {
            return;
        }
        let mut tokens = self.advance(t) + restore;
        let burst = self.burst as f64;
        if tokens > burst {
            tokens = burst;
        }
        self.last = t.clone();
        self.tokens = tokens;
        if r.time_to_act.equal(&self.last_event) {
            let prev = r
                .time_to_act
                .add(r.limit.duration_from_tokens(-(r.tokens as f64)));
            if !prev.before(t) {
                self.last_event = prev;
            }
        }
    }
}

impl Reservation {
    pub fn ok(&self) -> bool {
        self.ok
    }

    /// Go's `DelayFrom`: how long the holder must wait from `t` to act.
    pub fn delay_from(&self, t: &Time) -> Duration {
        if !self.ok {
            return INF_DURATION;
        }
        let delay = self.time_to_act.sub(t);
        if delay.as_nanos() < 0 {
            return Duration::from_nanos(0);
        }
        delay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill() {
        let t0 = time::unix(1_700_000_000, 0);
        let mut lim = Limiter::new(every(time::MINUTE), 3);
        // Three events at once are the burst.
        for _ in 0..3 {
            assert!(lim.allow_n(&t0, 1));
        }
        assert!(!lim.allow_n(&t0, 1));
        // A reservation past the burst waits for one token: a minute.
        let r = lim.reserve_n(&t0, 1);
        assert!(r.ok());
        assert_eq!(r.delay_from(&t0), time::MINUTE);
        // Cancelling it gives the token back, so the next reservation at
        // the same time waits the same minute again, not two.
        lim.cancel_at(&r, &t0);
        let r = lim.reserve_n(&t0, 1);
        assert_eq!(r.delay_from(&t0), time::MINUTE);
        // After a minute one token is back.
        let t1 = t0.add(time::MINUTE.mul(2));
        assert!(lim.allow_n(&t1, 1));
        assert!(!lim.allow_n(&t1, 1));
    }

    #[test]
    fn infinite_limit_always_allows() {
        let mut lim = Limiter::new(every(Duration::from_nanos(0)), 1);
        let t = time::now();
        for _ in 0..100 {
            assert!(lim.allow_n(&t, 1));
        }
        assert_eq!(lim.reserve_n(&t, 5).delay_from(&t), Duration::from_nanos(0));
    }

    #[test]
    fn over_burst_is_not_ok() {
        let mut lim = Limiter::new(every(time::SECOND), 2);
        let t = time::now();
        let r = lim.reserve_n(&t, 3);
        assert!(!r.ok());
        assert_eq!(r.delay_from(&t), INF_DURATION);
    }
}
