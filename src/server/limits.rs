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

use super::client::{Client, Conn};
use super::config::RETRY_AFTER_SECONDS;
use super::protocol::*;
use super::remap::{Fate, Remap};
use super::server::State;
use super::users::Identity;
use crate::obj;

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
    /// `auth` requests one IP may send a minute, failed ones included.
    pub auth_attempts_per_ip_minute: u32,
    /// Posts (every logged change, and joins and leaves) of the guests of
    /// one IP together; of an account; of an account holding any role, in
    /// place of `posts`; of one IP's users together, raised to
    /// `trusted_posts` for a trusted user's; and of everyone.
    pub guest_posts: Posts,
    pub posts: Posts,
    pub trusted_posts: Posts,
    pub ip_posts: Posts,
    pub server_posts: Posts,
    /// `room_list` requests of one user a minute; the first `joined`
    /// listing after each sign-in is free.
    pub room_lists_per_user_minute: u32,
    /// New uploads (a message's new `upload` embeds, `/avatar`, `/emoji
    /// add` and `/server avatar`) of one user, and of everyone, a UTC day.
    pub uploads_per_user_day: u32,
    pub uploads_per_day: u32,
    /// Frames one connection may send in a rolling minute, past which it is
    /// closed with 1008; of one IP, past which the connection is closed
    /// with 1013; and of everyone, past which a request is refused for a
    /// while and a notification dropped. Pings are not frames.
    pub frames_per_connection_minute: usize,
    pub frames_per_ip_minute: u32,
    pub server_frames_per_minute: u32,
    /// Malformed or invalid requests (parse_error, invalid_request,
    /// invalid_params, too_large) within a minute that close a connection
    /// with 1008.
    pub policy_violations: usize,
    /// How often a user's status changes their connections cause go to
    /// others, the latest winning; and how long a change a closed
    /// connection caused waits, so a reconnect within it shows nothing.
    pub status_coalesce: time::Duration,
    pub offline_grace: time::Duration,
    /// History pages one user, and one IP, may request: a minute, with a
    /// larger burst for a quiet one, and a UTC day; and everyone, a day.
    pub user_history: Rate,
    pub ip_history: Rate,
    pub user_history_day: u32,
    pub ip_history_day: u32,
    pub server_history_day: u32,
    /// Registrations (new accounts and bots, and passkeys added to an
    /// account) from one IP, and on the server, a UTC day; and the accounts
    /// and bots the server holds, past which a new one is refused.
    pub registrations_per_ip_day: u32,
    pub registrations_per_day: u32,
    pub identities: usize,
}

/// Posts a minute and a day; zero is no limit.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Posts {
    pub minute: u32,
    pub day: u32,
}

impl Posts {
    pub fn allowance(self) -> Allowance {
        Allowance::rate(Rate::per_minute(self.minute), self.day)
    }

    fn max(self, other: Posts) -> Posts {
        Posts {
            minute: self.minute.max(other.minute),
            day: self.day.max(other.day),
        }
    }
}

/// The times of the events within the last minute, for a limit kept as a
/// rolling window by one connection.
#[derive(Debug, Default)]
pub struct Window(std::collections::VecDeque<i64>);

impl Window {
    /// Notes an event at `now` (Unix ms) and returns the events within the
    /// last minute, it included.
    pub fn note(&mut self, now: i64) -> usize {
        while self.0.front().is_some_and(|&at| at <= now - 60_000) {
            self.0.pop_front();
        }
        self.0.push_back(now);
        self.0.len()
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
            auth_attempts_per_ip_minute: 10,
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
            room_lists_per_user_minute: 6,
            uploads_per_user_day: 20,
            uploads_per_day: 500,
            frames_per_connection_minute: 60,
            frames_per_ip_minute: 120,
            server_frames_per_minute: 600,
            policy_violations: 3,
            status_coalesce: time::Duration::from_secs(60),
            offline_grace: time::Duration::from_secs(60),
            user_history: Rate {
                per_minute: 20,
                burst: 60,
            },
            ip_history: Rate {
                per_minute: 60,
                burst: 120,
            },
            user_history_day: 3_000,
            ip_history_day: 6_000,
            server_history_day: 40_000,
            registrations_per_ip_day: 5,
            registrations_per_day: 300,
            identities: 10_000,
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
            auth_attempts_per_ip_minute: 0,
            guest_posts: Posts::default(),
            posts: Posts::default(),
            trusted_posts: Posts::default(),
            ip_posts: Posts::default(),
            server_posts: Posts::default(),
            room_lists_per_user_minute: 0,
            uploads_per_user_day: 0,
            uploads_per_day: 0,
            frames_per_connection_minute: 0,
            frames_per_ip_minute: 0,
            server_frames_per_minute: 0,
            policy_violations: 0,
            status_coalesce: time::Duration::from_secs(0),
            offline_grace: time::Duration::from_secs(0),
            user_history: Rate::per_minute(0),
            ip_history: Rate::per_minute(0),
            user_history_day: 0,
            ip_history_day: 0,
            server_history_day: 0,
            registrations_per_ip_day: 0,
            registrations_per_day: 0,
            identities: 0,
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
    Auth,
    Post,
    RoomList,
    Upload,
    Frame,
    History,
    Registration,
}

/// What a client holds back after a refusal (EXTENSIONS.md `ext:limits`):
/// `history` or `room_list` alone after `Read`; every request the posting
/// limits count after `Write`; requests with a new upload after `Upload`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Read,
    Write,
    Upload,
}

impl Category {
    fn as_str(self) -> &'static str {
        match self {
            Category::Read => "read",
            Category::Write => "write",
            Category::Upload => "upload",
        }
    }
}

/// The retry_after error of a refusal, naming the limit and, where the
/// refused request is one its row counts, its category.
pub fn refused(message: &str, retry_after: i64, category: Option<Category>) -> RpcError {
    let mut data = obj! {"retry_after" => retry_after};
    if let Some(category) = category {
        data.insert("ext".into(), obj! {"limits" => category.as_str()}.into());
    }
    RpcError::with_data(CODE_RETRY_AFTER, message, data)
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
        Allowance::rate(Rate::per_minute(per_minute), 0)
    }

    /// A rate and a day; a zero rate is no minute limit.
    pub fn rate(rate: Rate, day: u32) -> Allowance {
        Allowance {
            minute: (rate.per_minute > 0).then_some(rate),
            day,
        }
    }
}

/// One row of a [`LimitTable::charge`]: its principal, the allowance that
/// applies to it, and what a refusal says when its minute, or its day, is
/// full.
pub struct Charge<'a> {
    pub principal: &'a Principal,
    pub allowance: Allowance,
    pub minute_message: &'static str,
    pub day_message: &'static str,
}

impl<'a> Charge<'a> {
    /// A row whose refusals say `message`, minute or day.
    pub fn new(principal: &'a Principal, allowance: Allowance, message: &'static str) -> Self {
        Charge {
            principal,
            allowance,
            minute_message: message,
            day_message: message,
        }
    }

    /// The row with its own message for a full day.
    pub fn daily(self, message: &'static str) -> Self {
        Charge {
            day_message: message,
            ..self
        }
    }
}

/// Why a charge was refused: the one of its rows that waits longest,
/// whether that row's day was full rather than its minute, and the row's
/// message for that.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub row: usize,
    pub daily: bool,
    pub retry_after_ms: i64,
    pub message: &'static str,
}

impl Refusal {
    /// The wait in whole seconds, rounded up, at least one.
    pub fn retry_after(&self) -> i64 {
        ((self.retry_after_ms + 999) / 1000).max(1)
    }

    /// The retry_after error (`refused`) of the refusal.
    pub fn error(&self, category: Option<Category>) -> RpcError {
        refused(self.message, self.retry_after(), category)
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
    /// Charges `weight` events of `scope` to every row of `charges` at
    /// once, or to none when any of them lacks room for them.
    pub fn charge(
        &mut self,
        scope: Scope,
        charges: &[Charge<'_>],
        weight: u32,
    ) -> Result<(), Refusal> {
        self.charge_at(time::now().unix_milli(), scope, charges, weight)
    }

    pub fn charge_at(
        &mut self,
        now: i64,
        scope: Scope,
        charges: &[Charge<'_>],
        weight: u32,
    ) -> Result<(), Refusal> {
        let today = now.div_euclid(DAY_MS);
        let mut refusal: Option<Refusal> = None;
        let mut updated = Vec::with_capacity(charges.len());
        for (i, charge) in charges.iter().enumerate() {
            let mut row = self
                .rows
                .get(&(scope, charge.principal.clone()))
                .copied()
                .unwrap_or_default();
            let mut refuse = |retry_after_ms: i64, daily: bool| {
                let retry_after_ms = retry_after_ms.max(1);
                if refusal.is_none_or(|r| retry_after_ms > r.retry_after_ms) {
                    refusal = Some(Refusal {
                        row: i,
                        daily,
                        retry_after_ms,
                        message: if daily {
                            charge.day_message
                        } else {
                            charge.minute_message
                        },
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
            self.rows.insert((scope, charge.principal.clone()), row);
        }
        if self.rows.len() > self.prune_at {
            // Yesterday's rows have only their last few minutes left to
            // count; forgetting them at a new day costs at most one burst.
            self.rows.retain(|_, row| row.day == today);
            self.prune_at = (self.rows.len() * 2).max(4096);
        }
        Ok(())
    }

    /// The user_ids with rows, for tests that check none is left behind.
    #[cfg(test)]
    pub fn users(&self) -> Vec<String> {
        self.rows
            .keys()
            .filter_map(|(_, principal)| match principal {
                Principal::User(id) => Some(id.clone()),
                _ => None,
            })
            .collect()
    }

    /// Forgets the rows of the users `remap` drops, or moves the renamed
    /// user's, so a rename spends nothing.
    pub(super) fn remap(&mut self, remap: &Remap) {
        let keys: Vec<_> = self
            .rows
            .keys()
            .filter(|(_, principal)| {
                matches!(principal, Principal::User(id) if remap.fate(id) != Fate::Keep)
            })
            .cloned()
            .collect();
        for key in keys {
            let row = self.rows.remove(&key).expect("listed above");
            if let (scope, Principal::User(id)) = &key {
                if let Fate::Rename(to) = remap.fate(id) {
                    self.rows
                        .insert((*scope, Principal::User(to.to_owned())), row);
                }
            }
        }
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

/// The charges and caps each request and connection is held to.
impl State {
    /// Charges one frame of `c`'s to the server's minute and its address's.
    pub fn charge_frame_locked(&mut self, c: &Client) -> Result<(), Refusal> {
        let ip = Principal::Ip(c.ip_key.clone());
        let limits = &self.config.limits;
        let charges = [
            Charge::new(
                &Principal::Server,
                Allowance::minute(limits.server_frames_per_minute),
                "Server is busy with too many requests",
            ),
            Charge::new(
                &ip,
                Allowance::minute(limits.frames_per_ip_minute),
                "Frame rate limit reached",
            ),
        ];
        self.limits.charge(Scope::Frame, &charges, 1)
    }

    /// Why a new connection from `ip` would be refused now, with the
    /// seconds to wait: the server's connection cap, then the IP's caps.
    /// A connection not signed in to an account counts as a guest's.
    pub fn capacity_locked(&self, ip: &IpKey) -> Option<(&'static str, i64)> {
        let limits = &self.config.limits;
        let full = |max: usize, n: usize| max > 0 && n >= max;
        if full(self.config.max_connections, self.clients.len()) {
            return Some(("Server at capacity", RETRY_AFTER_SECONDS));
        }
        let from_ip: Vec<&Conn> = self
            .clients
            .values()
            .filter(|conn| conn.client.ip_key == *ip)
            .collect();
        let guests = from_ip
            .iter()
            .filter(|conn| {
                conn.user
                    .as_ref()
                    .and_then(|id| self.users.get(id))
                    .is_none_or(|u| !u.persists())
            })
            .count();
        if full(limits.connections_per_ip, from_ip.len())
            || full(limits.guest_connections_per_ip, guests)
        {
            return Some((
                "Connection limit reached for this network",
                RETRY_AFTER_SECONDS,
            ));
        }
        None
    }

    /// Admits a new connection from `ip`, or the retry_after error that
    /// refuses it: the caps of `capacity_locked`, then the IP's admissions
    /// a minute.
    pub fn admit_locked(&mut self, ip: &IpKey) -> Result<(), RpcError> {
        if let Some((message, retry_after)) = self.capacity_locked(ip) {
            return Err(refused(message, retry_after, None));
        }
        let principal = Principal::Ip(ip.clone());
        let allowance = Allowance::minute(self.config.limits.admissions_per_ip_minute);
        let charge = Charge::new(&principal, allowance, "Connection admission limit reached");
        self.limits
            .charge(Scope::Admission, &[charge], 1)
            .map_err(|refusal| refusal.error(None))
    }

    /// Charges one `auth` request of `c`'s IP (Cloudflare's
    /// reserveAuthAttempt), or refuses it with retry_after.
    pub fn charge_auth_locked(&mut self, c: &Client) -> Result<(), RpcError> {
        let principal = Principal::Ip(c.ip_key.clone());
        let allowance = Allowance::minute(self.config.limits.auth_attempts_per_ip_minute);
        let charge = Charge::new(&principal, allowance, "Authentication attempts limited");
        self.limits
            .charge(Scope::Auth, &[charge], 1)
            .map_err(|refusal| refusal.error(None))
    }

    /// Charges one post of the user's (apron-server-cloudflare's posting
    /// limits) to their own, their IP's and the server's minute and day, or
    /// to none, refusing it with retry_after naming the limit. Every
    /// accepted change is one: a message saved, a reaction set changed, a
    /// room saved, a join or leave, a profile change.
    /// `category` is `Write` for the requests ext:limits' write row lists,
    /// and `None` for `me` and commands.
    pub fn charge_post_locked(
        &mut self,
        c: &Client,
        user_id: &str,
        category: Option<Category>,
    ) -> Result<(), RpcError> {
        self.note_bot_active_locked(user_id);
        let poster = match self.users.get(user_id).map(|u| (u.kind(), u)) {
            Some((Identity::Account, u)) if !u.roles.is_empty() => Poster::Trusted,
            Some((Identity::Account | Identity::Bot, _)) => Poster::Account,
            _ => Poster::Guest,
        };
        let own = if poster == Poster::Guest {
            Principal::Guests(c.ip_key.clone())
        } else {
            Principal::User(user_id.to_owned())
        };
        let ip = Principal::Ip(c.ip_key.clone());
        let [own_allowance, ip_allowance, server_allowance] =
            self.config.limits.post_allowances(poster);
        let own_message = if poster == Poster::Guest {
            "Guest posting limit reached"
        } else {
            "Posting limit reached"
        };
        let daily = "Daily posting limit reached";
        let charges = [
            Charge::new(&own, own_allowance, own_message).daily(daily),
            Charge::new(&ip, ip_allowance, "Posting limit reached").daily(daily),
            Charge::new(
                &Principal::Server,
                server_allowance,
                "Posting limit reached",
            )
            .daily("Daily posting limit reached for the server"),
        ];
        self.limits
            .charge(Scope::Post, &charges, 1)
            .map_err(|refusal| refusal.error(category))
    }

    /// Charges `n` new uploads of the user's to their day and the server's,
    /// or none.
    pub fn charge_uploads_locked(&mut self, user_id: &str, n: u32) -> Result<(), RpcError> {
        let limits = &self.config.limits;
        let user = Principal::User(user_id.to_owned());
        let daily = |day| Allowance { minute: None, day };
        let charges = [
            Charge::new(
                &user,
                daily(limits.uploads_per_user_day),
                "Daily upload limit reached",
            ),
            Charge::new(
                &Principal::Server,
                daily(limits.uploads_per_day),
                "Daily upload limit reached for the server",
            ),
        ];
        self.limits
            .charge(Scope::Upload, &charges, n)
            .map_err(|refusal| refusal.error(Some(Category::Upload)))
    }

    /// Charges one registration from `c`'s IP to its day and the server's,
    /// as Cloudflare's chargeRegistration does: a new account or bot, or a
    /// passkey added to an account. A new identity (`new_identity`) is first
    /// refused with `registration_closed` when the server holds
    /// Limits::identities accounts and bots.
    pub fn charge_registration_locked(
        &mut self,
        c: &Client,
        new_identity: bool,
    ) -> Result<(), RpcError> {
        let limits = &self.config.limits;
        if new_identity
            && limits.identities > 0
            && self.users.values().filter(|u| u.persists()).count() >= limits.identities
        {
            return Err(RpcError::new(CODE_DENIED, "registration_closed"));
        }
        let ip = Principal::Ip(c.ip_key.clone());
        let daily = |day| Allowance { minute: None, day };
        let charges = [
            Charge::new(
                &ip,
                daily(limits.registrations_per_ip_day),
                "Registration limit reached for this network",
            ),
            Charge::new(
                &Principal::Server,
                daily(limits.registrations_per_day),
                "Registration limit reached",
            ),
        ];
        self.limits
            .charge(Scope::Registration, &charges, 1)
            .map_err(|refusal| refusal.error(None))
    }

    /// Charges a history page to the user's and the IP's minute and day, and
    /// the server's day, or to none.
    pub(super) fn charge_history_locked(
        &mut self,
        c: &Client,
        user_id: &str,
    ) -> Result<(), RpcError> {
        let limits = &self.config.limits;
        let (user, ip) = (
            Principal::User(user_id.to_owned()),
            Principal::Ip(c.ip_key.clone()),
        );
        let minute = "History request limit reached";
        let charges = [
            Charge::new(
                &user,
                Allowance::rate(limits.user_history, limits.user_history_day),
                minute,
            )
            .daily("Daily history limit reached"),
            Charge::new(
                &ip,
                Allowance::rate(limits.ip_history, limits.ip_history_day),
                minute,
            )
            .daily("Daily history limit reached for this network"),
            Charge::new(
                &Principal::Server,
                Allowance::rate(Rate::per_minute(0), limits.server_history_day),
                minute,
            )
            .daily("Daily history limit reached for the server"),
        ];
        self.limits
            .charge(Scope::History, &charges, 1)
            .map_err(|refusal| refusal.error(Some(Category::Read)))
    }

    /// Charges a `room_list` to the user's minute, except the first
    /// `joined` listing after a sign-in, which is how a client learns its
    /// rooms.
    pub(super) fn charge_room_list_locked(
        &mut self,
        c: &Client,
        req: &Request,
    ) -> Result<(), RpcError> {
        let Some(conn) = self.clients.get_mut(&c.id) else {
            return Ok(());
        };
        let Some(user_id) = conn.user.clone() else {
            return Ok(());
        };
        let joined = parse_string(&req.params, "filter", false).is_ok_and(|f| f == "joined");
        if joined && !conn.listed_joined {
            conn.listed_joined = true;
            return Ok(());
        }
        let user = Principal::User(user_id);
        let allowance = Allowance::minute(self.config.limits.room_lists_per_user_minute);
        let charge = Charge::new(&user, allowance, "Room listing limited");
        self.limits
            .charge(Scope::RoomList, &[charge], 1)
            .map_err(|refusal| refusal.error(Some(Category::Read)))
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
        let row = |principal, minute, day| {
            let allowance = Allowance {
                minute: Some(Rate::per_minute(minute)),
                day,
            };
            Charge::new(principal, allowance, "minute").daily("day")
        };
        let mut table = LimitTable::default();
        let now = 5 * DAY_MS + 1_000;
        table
            .charge_at(now, Scope::Admission, &[row(&a, 2, 0), row(&b, 60, 3)], 1)
            .unwrap();
        table
            .charge_at(now, Scope::Admission, &[row(&a, 2, 0), row(&b, 60, 3)], 1)
            .unwrap();
        assert_eq!(
            table.charge_at(now, Scope::Admission, &[row(&a, 2, 0), row(&b, 60, 3)], 1),
            Err(Refusal {
                row: 0,
                daily: false,
                retry_after_ms: 30_000,
                message: "minute",
            })
        );
        // The refused charge spent nothing on the server's row.
        table
            .charge_at(now, Scope::Admission, &[row(&b, 60, 3)], 1)
            .unwrap();
        assert_eq!(
            table.charge_at(
                now + 60_000,
                Scope::Admission,
                &[row(&a, 2, 0), row(&b, 60, 3)],
                1
            ),
            Err(Refusal {
                row: 1,
                daily: true,
                retry_after_ms: DAY_MS - 61_000,
                message: "day",
            })
        );
        table
            .charge_at(6 * DAY_MS, Scope::Admission, &[row(&b, 60, 3)], 1)
            .unwrap();
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
