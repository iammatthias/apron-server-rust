//! Rate and count limits, apron-server-cloudflare's (its SPEC.md, sections
//! 5 and 6): who a client is for them (its IP key), the configured
//! allowances, and the table that counts each principal's use of them.
//!
//! Every per-minute allowance is a token bucket (Cloudflare's limiter.ts),
//! and every daily one a count for the UTC day. The table lives in memory,
//! so a restart starts every principal afresh.

use std::collections::HashMap;
use std::fmt;

use rust_stdlib::net;
use rust_stdlib::time;

const MINUTE_MS: f64 = 60_000.0;
const DAY_MS: i64 = 86_400_000;

/// The configured limits. A zero allowance is no limit.
#[derive(Clone, Debug, PartialEq)]
pub struct Limits {
    /// Open connections from one IP, signed in or not.
    pub connections_per_ip: usize,
    /// Open connections from one IP that are not signed in to an account:
    /// guests and connections that have not signed in yet.
    pub guest_connections_per_ip: usize,
    /// Open connections of one account.
    pub connections_per_user: usize,
    /// New connections one IP may open, a minute.
    pub admissions_per_ip_minute: u32,
    /// Posts (every logged change, and joins and leaves) of the guests of
    /// one IP together; of an account; of an account holding any role, in
    /// place of `posts`; of one IP's users together, raised to
    /// `trusted_posts` for a trusted user's; and of everyone.
    pub guest_posts: Posts,
    pub posts: Posts,
    pub trusted_posts: Posts,
    pub ip_posts: Posts,
    pub server_posts: Posts,
}

/// Posts a minute and a day; zero is no limit.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Posts {
    pub minute: u32,
    pub day: u32,
}

impl Posts {
    pub fn allowance(self) -> Allowance {
        Allowance {
            day: self.day,
            ..Allowance::minute(self.minute)
        }
    }

    fn max(self, other: Posts) -> Posts {
        Posts {
            minute: self.minute.max(other.minute),
            day: self.day.max(other.day),
        }
    }
}

/// Who a post is charged to beside its IP and the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poster {
    Guest,
    Account,
    /// An account holding any role, and no bot: only an admin gives roles.
    Trusted,
}

impl Limits {
    /// The allowances a post of `poster` is charged against: its own, its
    /// IP's and the server's.
    pub fn post_allowances(&self, poster: Poster) -> [Allowance; 3] {
        let (own, ip) = match poster {
            Poster::Guest => (self.guest_posts, self.ip_posts),
            Poster::Account => (self.posts, self.ip_posts),
            Poster::Trusted => (self.trusted_posts, self.ip_posts.max(self.trusted_posts)),
        };
        [
            own.allowance(),
            ip.allowance(),
            self.server_posts.allowance(),
        ]
    }
}

impl Default for Limits {
    /// Cloudflare's defaults.
    fn default() -> Limits {
        Limits {
            connections_per_ip: 10,
            guest_connections_per_ip: 6,
            connections_per_user: 3,
            admissions_per_ip_minute: 12,
            guest_posts: Posts {
                minute: 5,
                day: 200,
            },
            posts: Posts {
                minute: 20,
                day: 1_000,
            },
            trusted_posts: Posts {
                minute: 50,
                day: 4_000,
            },
            ip_posts: Posts {
                minute: 30,
                day: 2_000,
            },
            server_posts: Posts {
                minute: 120,
                day: 10_000,
            },
        }
    }
}

impl Limits {
    /// No limits, for tests about something else: they all connect from
    /// one address.
    pub fn unlimited() -> Limits {
        Limits {
            connections_per_ip: 0,
            guest_connections_per_ip: 0,
            connections_per_user: 0,
            admissions_per_ip_minute: 0,
            guest_posts: Posts::default(),
            posts: Posts::default(),
            trusted_posts: Posts::default(),
            ip_posts: Posts::default(),
            server_posts: Posts::default(),
        }
    }
}

/// A sustained rate, `per_minute`, which a quiet principal may exceed at
/// once up to `burst` events.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rate {
    pub per_minute: u32,
    pub burst: u32,
}

impl Rate {
    /// A rate whose burst is a minute's allowance, as a rolling minute
    /// allows.
    pub const fn per_minute(per_minute: u32) -> Rate {
        Rate {
            per_minute,
            burst: per_minute,
        }
    }
}

/// A principal's outstanding events, `level`, as of `at` (Unix ms); the
/// level drains at the rate. Draining in events rather than keeping one
/// arrival time makes a lower rate after a higher one count what was spent.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Bucket {
    pub level: f64,
    pub at: i64,
}

impl Bucket {
    /// Charges `weight` events at `now`: the bucket to keep, or the
    /// milliseconds before the same charge fits. A weight past the whole
    /// burst fits once the bucket is empty.
    pub fn charge(self, now: i64, rate: Rate, weight: u32) -> Result<Bucket, i64> {
        let per_ms = f64::from(rate.per_minute) / MINUTE_MS;
        let (burst, weight) = (f64::from(rate.burst), f64::from(weight));
        let level = (self.level - (now - self.at).max(0) as f64 * per_ms).max(0.0);
        // Float noise must not refuse an event that drains exactly in time.
        if level + weight <= burst + 1e-9 || level == 0.0 {
            return Ok(Bucket {
                level: level + weight,
                at: now.max(self.at),
            });
        }
        let over = if weight > burst {
            level
        } else {
            level + weight - burst
        };
        Err((over / per_ms - 1e-6).ceil() as i64)
    }
}

/// What a limit counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    Admission,
    Post,
}

/// Whose use a row counts.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Principal {
    Ip(IpKey),
    /// The guests of an IP, together.
    Guests(IpKey),
    User(String),
    Server,
}

/// An allowance a minute, as a rate, and a day; a zero one is no limit.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Allowance {
    pub minute: Option<Rate>,
    pub day: u32,
}

impl Allowance {
    pub fn minute(per_minute: u32) -> Allowance {
        Allowance {
            minute: (per_minute > 0).then(|| Rate::per_minute(per_minute)),
            day: 0,
        }
    }
}

/// One charge of a [`LimitTable::charge`]: a scope, its principal and the
/// allowance that applies to it.
pub struct Charge<'a> {
    pub scope: Scope,
    pub principal: &'a Principal,
    pub allowance: Allowance,
}

/// Why a charge was refused: the one of its rows that waits longest, and
/// whether that row's day was full rather than its minute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub row: usize,
    pub daily: bool,
    pub retry_after_ms: i64,
}

impl Refusal {
    /// The wait in whole seconds, rounded up, at least one.
    pub fn retry_after(&self) -> i64 {
        ((self.retry_after_ms + 999) / 1000).max(1)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Row {
    bucket: Bucket,
    day: i64,
    count: u32,
}

/// Counts each principal's use of each limit.
#[derive(Default)]
pub struct LimitTable {
    rows: HashMap<(Scope, Principal), Row>,
    prune_at: usize,
}

impl LimitTable {
    /// Charges `weight` events to every row of `charges` at once, or to none
    /// when any of them lacks room for them.
    pub fn charge(&mut self, charges: &[Charge<'_>], weight: u32) -> Result<(), Refusal> {
        self.charge_at(time::now().unix_milli(), charges, weight)
    }

    pub fn charge_at(
        &mut self,
        now: i64,
        charges: &[Charge<'_>],
        weight: u32,
    ) -> Result<(), Refusal> {
        let today = now.div_euclid(DAY_MS);
        let mut refusal: Option<Refusal> = None;
        let mut updated = Vec::with_capacity(charges.len());
        for (i, charge) in charges.iter().enumerate() {
            let mut row = self
                .rows
                .get(&(charge.scope, charge.principal.clone()))
                .copied()
                .unwrap_or_default();
            let mut refuse = |retry_after_ms: i64, daily: bool| {
                let retry_after_ms = retry_after_ms.max(1);
                if refusal.is_none_or(|r| retry_after_ms > r.retry_after_ms) {
                    refusal = Some(Refusal {
                        row: i,
                        daily,
                        retry_after_ms,
                    });
                }
            };
            if let Some(rate) = charge.allowance.minute {
                match row.bucket.charge(now, rate, weight) {
                    Ok(bucket) => row.bucket = bucket,
                    Err(wait) => refuse(wait, false),
                }
            }
            if row.day != today {
                (row.day, row.count) = (today, 0);
            }
            if charge.allowance.day > 0 && row.count.saturating_add(weight) > charge.allowance.day {
                refuse(DAY_MS - now.rem_euclid(DAY_MS), true);
            }
            row.count = row.count.saturating_add(weight);
            updated.push(row);
        }
        if let Some(refusal) = refusal {
            return Err(refusal);
        }
        for (charge, row) in charges.iter().zip(updated) {
            self.rows
                .insert((charge.scope, charge.principal.clone()), row);
        }
        if self.rows.len() > self.prune_at {
            // Yesterday's rows have at most a minute left to count.
            self.rows.retain(|_, row| row.day == today);
            self.prune_at = (self.rows.len() * 2).max(4096);
        }
        Ok(())
    }
}

/// The principal a client's per-IP limits count: an IPv4 address, with an
/// IPv4-mapped IPv6 one folded into it, or a native IPv6 address's /56, the
/// size ISPs most often delegate to one home or site, so one subscriber
/// cannot multiply its limits across its /64s.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpKey(String);

impl IpKey {
    /// The key of an address, or `None` when `address` is not one.
    pub fn parse(address: &str) -> Option<IpKey> {
        let ip = net::parse_ip(address.trim())?;
        if let Some(v4) = ip.to4() {
            return Some(IpKey(format!("v4:{v4}")));
        }
        let prefix = ip.mask(&net::cidr_mask(56, 128)?)?;
        Some(IpKey(format!("v6:{prefix}/56")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(address: &str) -> String {
        IpKey::parse(address).expect(address).to_string()
    }

    /// Cloudflare's config-ip-frame.test.ts, "joins dotted and hexadecimal
    /// IPv4-mapped IPv6 with IPv4".
    #[test]
    fn mapped_ipv4_joins_ipv4_and_ipv6_groups_by_56() {
        assert_eq!(key("192.0.2.10"), "v4:192.0.2.10");
        assert_eq!(key("::ffff:192.0.2.10"), "v4:192.0.2.10");
        assert_eq!(key("0:0:0:0:0:ffff:c000:020a"), "v4:192.0.2.10");
        assert_eq!(key("2001:db8:1:2::1"), key("2001:0db8:0001:0002:abcd::5"));
        assert_eq!(key("2001:db8:1:ff::1"), key("2001:db8:1:2::1"));
        assert_ne!(key("2001:db8:1:102::1"), key("2001:db8:1:2::1"));
        assert_eq!(key("2001:db8:1:2::1"), "v6:2001:db8:1::/56");
        assert_eq!(key("2001:db8:1:abcd::1"), "v6:2001:db8:1:ab00::/56");
    }

    fn fits(result: Result<Bucket, i64>) -> Bucket {
        result.unwrap_or_else(|wait| panic!("refused for {wait} ms"))
    }

    /// Cloudflare's limiter.test.ts, case by case.
    #[test]
    fn spends_a_burst_then_refuses_with_the_exact_wait() {
        let rate = Rate {
            per_minute: 20,
            burst: 60,
        };
        let mut state = Bucket::default();
        for _ in 0..60 {
            state = fits(state.charge(1_000, rate, 1));
        }
        assert_eq!(state.charge(1_000, rate, 1), Err(3_000));
        assert_eq!(state.charge(3_999, rate, 1), Err(1));
        state = fits(state.charge(4_000, rate, 1));
        assert_eq!(state.charge(4_000, rate, 1), Err(3_000));
    }

    #[test]
    fn burst_defaults_to_a_minute_of_the_rate() {
        let rate = Rate::per_minute(5);
        let mut state = Bucket::default();
        for _ in 0..5 {
            state = fits(state.charge(0, rate, 1));
        }
        assert_eq!(state.charge(0, rate, 1), Err(12_000));
        assert_eq!(fits(state.charge(60_000, rate, 1)).level, 1.0);
    }

    #[test]
    fn weight_past_the_burst_fits_only_when_empty() {
        let rate = Rate::per_minute(10);
        let half = fits(Bucket::default().charge(0, rate, 4));
        assert_eq!(half.level, 4.0);
        assert_eq!(half.charge(0, rate, 7), Err(6_000));
        assert_eq!(half.charge(0, rate, 30), Err(24_000));
        let big = fits(half.charge(24_000, rate, 30));
        assert_eq!(big.level, 30.0);
        assert_eq!(big.charge(24_000, rate, 1), Err(126_000));
    }

    #[test]
    fn lower_rate_counts_what_a_higher_one_spent() {
        let mut state = Bucket::default();
        for _ in 0..20 {
            state = fits(state.charge(0, Rate::per_minute(50), 1));
        }
        assert_eq!(state.charge(0, Rate::per_minute(20), 1), Err(3_000));
    }

    #[test]
    fn a_clock_that_went_back_drains_nothing_twice() {
        let state = fits(Bucket::default().charge(10_000, Rate::per_minute(1), 1));
        assert_eq!(state.charge(5_000, Rate::per_minute(1), 1), Err(60_000));
        let rate = Rate {
            per_minute: 60,
            burst: 2,
        };
        let behind = fits(fits(Bucket::default().charge(10_000, rate, 1)).charge(5_000, rate, 1));
        assert_eq!(
            behind,
            Bucket {
                level: 2.0,
                at: 10_000
            }
        );
        assert_eq!(behind.charge(10_000, rate, 1), Err(1_000));
    }

    /// A charge to several rows takes all of them or none, and its refusal
    /// names the row that waits longest.
    #[test]
    fn table_charges_all_rows_or_none() {
        let (a, b) = (Principal::User("a".into()), Principal::Server);
        let row = |principal, minute, day| Charge {
            scope: Scope::Admission,
            principal,
            allowance: Allowance {
                minute: Some(Rate::per_minute(minute)),
                day,
            },
        };
        let mut table = LimitTable::default();
        let now = 5 * DAY_MS + 1_000;
        table
            .charge_at(now, &[row(&a, 2, 0), row(&b, 60, 3)], 1)
            .unwrap();
        table
            .charge_at(now, &[row(&a, 2, 0), row(&b, 60, 3)], 1)
            .unwrap();
        assert_eq!(
            table.charge_at(now, &[row(&a, 2, 0), row(&b, 60, 3)], 1),
            Err(Refusal {
                row: 0,
                daily: false,
                retry_after_ms: 30_000
            })
        );
        // The refused charge spent nothing on the server's row.
        table.charge_at(now, &[row(&b, 60, 3)], 1).unwrap();
        assert_eq!(
            table.charge_at(now + 60_000, &[row(&a, 2, 0), row(&b, 60, 3)], 1),
            Err(Refusal {
                row: 1,
                daily: true,
                retry_after_ms: DAY_MS - 61_000
            })
        );
        table.charge_at(6 * DAY_MS, &[row(&b, 60, 3)], 1).unwrap();
    }

    #[test]
    fn non_addresses_have_no_key() {
        for value in [
            "",
            "garbage-x",
            "203.0.113.7:80",
            "fe80::1%en0",
            "256.1.1.1",
        ] {
            assert_eq!(IpKey::parse(value), None, "{value:?}");
        }
    }
}
