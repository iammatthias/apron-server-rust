//! Push (§4.9): registrations, the wake scopes, the payload, and their
//! delivery to relays and Web Push services.

use std::ops::{BitAnd, BitOr, BitOrAssign};
use std::sync::Arc;
use std::thread;

use rust_stdlib::net::netip::Addr;
use rust_stdlib::net::url;
use rust_stdlib::time::{self, Duration, Time};

use super::client::Client as Connection;
use super::messages::mentions;
use super::outbound::public_address;
use super::protocol::*;
use super::push_delivery::DoneFn;
use super::server::{Server, State};
use super::status::retry_after;
use super::users::UserState;
use super::webpush::{self, PushKeys};
use crate::obj;
use crate::rate::{every, Limiter};

pub const MAX_PUSH_TEXT_RUNES: usize = 200;
pub const MAX_PUSHES_PER_USER: usize = 5;
pub const MAX_PUSH_URL_BYTES: usize = 512;
pub const MAX_PUSH_TOKEN_LEN: usize = 4096;
/// Bounds the JSON payload every kind delivers (§4.9).
pub const MAX_PUSH_PAYLOAD_BYTES: usize = 2048;
/// Bound the wake names a server reads: those beyond the first
/// MAX_WAKE_SCOPES, and longer ones, are ignored.
pub const MAX_WAKE_SCOPES: usize = 16;
pub const MAX_WAKE_SCOPE_BYTES: usize = 64;
/// How long a registration lasts unless registered again (§4.9); clients
/// register on each connection. PUSH_SWEEP_INTERVAL is how often expired
/// registrations are looked for.
pub const PUSH_EXPIRY: Duration = Duration::from_hours(7 * 24);
pub const PUSH_SWEEP_INTERVAL: Duration = Duration::from_hours(1);
pub const PUSH_TIMEOUT: Duration = Duration::from_secs(10);
/// Deliveries run in lanes per push host, at most MAX_PUSH_PER_HOST at once
/// to one host, and at most MAX_CONCURRENT_PUSH_POST in all. A user has at
/// most MAX_PUSH_QUEUED_PER_USER deliveries waiting or running, a host
/// MAX_PUSH_QUEUED_PER_HOST, and the server MAX_PUSH_QUEUED; beyond them a
/// delivery is dropped, as pushes are best effort.
pub const MAX_CONCURRENT_PUSH_POST: usize = 32;
pub const MAX_PUSH_PER_HOST: usize = 8;
pub const MAX_PUSH_QUEUED_PER_USER: usize = 20;
pub const MAX_PUSH_QUEUED_PER_HOST: usize = 256;
pub const MAX_PUSH_QUEUED: usize = 1024;
/// Bounds the pushes delivered to one user in a UTC day, counting only those
/// the endpoint accepted (2xx).
pub const MAX_PUSHES_PER_USER_DAY: i64 = 1000;
/// `push_register` requests one user may make a minute, across their
/// connections, refused ones included (apron-server-cloudflare's
/// `registersPerUserMinute`).
pub const PUSH_REGISTERS_PER_MINUTE: i64 = 10;
/// How much of a push service's answer is read so that its connection can
/// be reused.
pub const MAX_PUSH_RESPONSE_DRAIN: u64 = 64 << 10;

/// The browsers' own push services, which endpoints may name when
/// `--push.hosts` is not set (apron-server-cloudflare's `PUSH_HOSTS`).
pub const DEFAULT_PUSH_HOSTS: [&str; 5] = [
    "fcm.googleapis.com",
    "*.push.services.mozilla.com",
    "web.push.apple.com",
    "*.push.apple.com",
    "*.notify.windows.com",
];

/// The push services endpoints may name (`--push.hosts`), for every kind:
/// a relay's host is allowed only once it is listed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushHosts {
    Any,
    /// Exact host names, and `*.` suffixes, lowercase.
    Listed(Vec<String>),
}

impl Default for PushHosts {
    fn default() -> PushHosts {
        PushHosts::Listed(DEFAULT_PUSH_HOSTS.iter().map(|h| (*h).to_owned()).collect())
    }
}

impl PushHosts {
    /// Reads `--push.hosts`: host names or `*.` suffixes, or a standalone
    /// `*`; none gives DEFAULT_PUSH_HOSTS.
    pub fn parse(entries: &[String]) -> Result<PushHosts, String> {
        let hosts: Vec<String> = entries
            .iter()
            .flat_map(|entry| entry.split(','))
            .map(|host| host.trim().to_ascii_lowercase())
            .filter(|host| !host.is_empty())
            .collect();
        if hosts.is_empty() {
            return Ok(PushHosts::default());
        }
        if hosts == ["*"] {
            return Ok(PushHosts::Any);
        }
        for host in &hosts {
            if !valid_host_pattern(host) {
                return Err(format!(
                    "invalid --push.hosts {}: list host names, *.host suffixes, or a standalone *",
                    rust_stdlib::strconv::quote(host)
                ));
            }
        }
        Ok(PushHosts::Listed(hosts))
    }

    /// Whether an endpoint's host, lowercase without a trailing dot, is one
    /// of these.
    pub fn allows(&self, host: &str) -> bool {
        match self {
            PushHosts::Any => true,
            PushHosts::Listed(hosts) => hosts.iter().any(|entry| match entry.strip_prefix('*') {
                Some(suffix) => host.ends_with(suffix),
                None => host == entry,
            }),
        }
    }

    pub fn allows_url(&self, endpoint: &str) -> bool {
        url::parse(endpoint).is_ok_and(|u| self.allows(&u.hostname().to_ascii_lowercase()))
    }
}

/// `^(\*\.)?label(\.label)+$`, each label letters, digits and inner `-`.
fn valid_host_pattern(host: &str) -> bool {
    let name = host.strip_prefix("*.").unwrap_or(host);
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// A set of wake scopes (§4.9).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WakeScope(pub u8);

impl WakeScope {
    pub const MENTIONS: WakeScope = WakeScope(1);
    pub const REPLIES: WakeScope = WakeScope(2);
    pub const PRIVATE: WakeScope = WakeScope(4);
    pub const JOINED: WakeScope = WakeScope(8);
    pub const BADGE: WakeScope = WakeScope(16);
    pub const NONE: WakeScope = WakeScope(0);
    /// The scopes of a registration without wake.
    pub const DEFAULT: WakeScope = WakeScope(1 | 2);
    /// The scopes that push with Urgency high; joined is normal, badge low.
    pub const URGENT: WakeScope = WakeScope(1 | 2 | 4);

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The scopes in the set, in advertised order.
    pub fn names(self) -> Vec<String> {
        WAKE_SCOPE_NAMES
            .iter()
            .filter(|(_, scope)| !(self & *scope).is_empty())
            .map(|(name, _)| (*name).to_owned())
            .collect()
    }
}

impl BitOr for WakeScope {
    type Output = WakeScope;
    fn bitor(self, other: WakeScope) -> WakeScope {
        WakeScope(self.0 | other.0)
    }
}

impl BitOrAssign for WakeScope {
    fn bitor_assign(&mut self, other: WakeScope) {
        self.0 |= other.0;
    }
}

impl BitAnd for WakeScope {
    type Output = WakeScope;
    fn bitand(self, other: WakeScope) -> WakeScope {
        WakeScope(self.0 & other.0)
    }
}

/// The scopes this server implements, in the order server.push.wake
/// advertises them.
pub const WAKE_SCOPE_NAMES: [(&str, WakeScope); 5] = [
    ("mentions", WakeScope::MENTIONS),
    ("replies", WakeScope::REPLIES),
    ("private", WakeScope::PRIVATE),
    ("joined", WakeScope::JOINED),
    ("badge", WakeScope::BADGE),
];

/// Reads a wake list, ignoring scopes this server does not implement
/// (§4.9).
pub fn parse_wake_names(names: &[String]) -> WakeScope {
    let mut wake = WakeScope::NONE;
    for name in names {
        for (scope_name, scope) in WAKE_SCOPE_NAMES {
            if scope_name == name {
                wake |= scope;
            }
        }
    }
    wake
}

/// Reports whether s is the shape of a client's push_id (§4.9),
/// `^[A-Za-z0-9_-]{1,64}$`.
pub fn valid_push_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// One push endpoint of a user (§4.9), identified by the user and its url,
/// keyed in `State.pushes` by `push_key`.
#[derive(Clone, Debug)]
pub struct PushRegistration {
    pub user_id: String,
    pub kind: String,
    pub url: String,
    /// A relay's bearer token.
    pub token: String,
    pub push_id: String,
    /// The SHA-256 of the /invite-device token the registering connection
    /// signed in with, zero for none, so replacing that token removes only
    /// the registrations it made.
    pub device: [u8; 32],
    /// For webpush and optionally relay, encrypt the payload.
    pub keys: Option<PushKeys>,
    pub wake: WakeScope,
    /// When the client last registered it; it expires PUSH_EXPIRY later.
    pub renewed: Time,
    /// The unread count the endpoint last accepted, -1 when none was since
    /// the server started; a badge push is sent only when the count differs
    /// (§4.9). sent numbers the pushes handed to the deliverer and accepted
    /// the latest of them the endpoint accepted, so a push accepted late
    /// does not record an older count.
    pub last_unread: i64,
    pub sent: u64,
    pub accepted: u64,
    /// The count of the latest push sent, while in_flight: a badge push for
    /// the same count waits on its outcome.
    pub pending_unread: i64,
    pub in_flight: bool,
    /// Tells this registration from a later one of the same user and url, so
    /// a delivery's outcome applies only to the registration it was sent
    /// for (Go compares the pointers).
    pub generation: u64,
}

impl Default for PushRegistration {
    fn default() -> PushRegistration {
        PushRegistration {
            user_id: String::new(),
            kind: "relay".into(),
            url: String::new(),
            token: String::new(),
            push_id: String::new(),
            device: [0; 32],
            keys: None,
            wake: WakeScope::NONE,
            renewed: time::now(),
            last_unread: -1,
            sent: 0,
            accepted: 0,
            pending_unread: 0,
            in_flight: false,
            generation: 0,
        }
    }
}

impl PushRegistration {
    /// Reports whether the registration has not expired at now.
    pub fn live(&self, now: &Time) -> bool {
        now.before(&self.renewed.add(PUSH_EXPIRY))
    }

    /// Reports whether the registration gets badge pushes: it has scope
    /// badge, which webpush ignores (§4.9).
    pub fn takes_badges(&self) -> bool {
        !(self.wake & WakeScope::BADGE).is_empty() && self.kind != "webpush"
    }
}

/// Identifies a registration in `State.pushes` and the store: its user and
/// url, which holds no space.
pub fn push_key(user_id: &str, url: &str) -> String {
    format!("{user_id} {url}")
}

/// The roles whose holders may wake for `joined` (§4.9.4), every message
/// in a room they joined: moderators, as apron-server-cloudflare's
/// JOINED_WAKE_ROLES.
pub const JOINED_WAKE_ROLES: [&str; 2] = ["admin", "mod"];

/// The `push` object of the server frame (§3.1), sent only with push
/// enabled. `joined` is listed only where the connection's user may wake
/// for it, since a server advertises only the scopes it implements.
pub fn server_push_params(st: &State, joined: bool) -> Object {
    let mut wake = WakeScope::URGENT | WakeScope::BADGE;
    if joined {
        wake |= WakeScope::JOINED;
    }
    let mut push = obj! {
        "relay" => Object::new(),
        "wake" => wake.names(),
    };
    if let Some(vapid) = &st.vapid {
        push.insert(
            "webpush".into(),
            obj! {"key" => vapid.public.as_str()}.into(),
        );
    }
    push
}

impl UserState {
    /// How many pushes the user's endpoints accepted on now's UTC day.
    pub fn pushes_today_locked(&mut self, now: &Time) -> i64 {
        let day = now.utc().format("2006-01-02");
        if day != self.push_day {
            self.push_day = day;
            self.pushes_today = 0;
        }
        self.pushes_today
    }
}

impl State {
    /// Whether a user may be woken for `joined`: an account holding one of
    /// JOINED_WAKE_ROLES, and no bot, since has_any_role never holds for a
    /// bot.
    pub fn wakes_joined(&self, user_id: &str) -> bool {
        self.users
            .get(user_id)
            .is_some_and(|u| u.persists() && u.has_any_role(&JOINED_WAKE_ROLES))
    }

    /// The keys of a user's registrations, ordered by url.
    pub fn sorted_pushes(&self, user_id: &str) -> Vec<String> {
        let prefix = format!("{user_id} ");
        self.pushes
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub fn user_has_pushes(&self, user_id: &str) -> bool {
        !self.sorted_pushes(user_id).is_empty()
    }

    pub fn user_takes_badges(&self, user_id: &str) -> bool {
        self.sorted_pushes(user_id)
            .iter()
            .any(|k| self.pushes[k].takes_badges())
    }

    pub fn touch_push(&mut self, key: &str) {
        self.dirty.pushes.insert(key.to_owned());
    }

    /// Records a registration, replacing the user's registration of the
    /// same url.
    pub fn add_push_locked(&mut self, mut p: PushRegistration) {
        p.generation = self.next_generation;
        self.next_generation += 1;
        let key = push_key(&p.user_id, &p.url);
        self.pushes.insert(key.clone(), p);
        self.touch_push(&key);
    }

    /// Forgets a registration. A user left without registrations has no
    /// unread counts kept.
    pub fn remove_push_locked(&mut self, key: &str) {
        let Some(p) = self.pushes.remove(key) else {
            return;
        };
        self.touch_push(key);
        if !self.user_has_pushes(&p.user_id) {
            if let Some(u) = self.users.get_mut(&p.user_id) {
                u.unread = None;
            }
            self.stop_badge_locked(&p.user_id);
        }
    }

    /// Forgets the user's registrations that were not registered again
    /// within PUSH_EXPIRY.
    pub fn expire_pushes_locked(&mut self, user_id: &str, now: &Time) {
        for key in self.sorted_pushes(user_id) {
            if !self.pushes[&key].live(now) {
                self.remove_push_locked(&key);
            }
        }
    }

    /// Hands a payload carrying the count unread to the deliverer, unless
    /// the user has had MAX_PUSHES_PER_USER_DAY pushes today. A push the
    /// endpoint accepts, with a 2xx, counts toward them and records unread
    /// as the count the endpoint has; one answered 403, 404 or 410 forgets
    /// the registration. A badge push replaces one still waiting for the same
    /// registration.
    pub fn deliver_push_locked(
        &mut self,
        key: &str,
        unread: i64,
        payload: Vec<u8>,
        urgency: &'static str,
        badge: bool,
    ) {
        let Some(p) = self.pushes.get(key) else {
            return;
        };
        // --push.hosts as configured now: a registration kept from a wider
        // list is passed over.
        if !self.config.push_hosts.allows_url(&p.url) {
            return;
        }
        let now = time::now();
        let Some(u) = self.users.get_mut(&p.user_id) else {
            return;
        };
        if u.pushes_today_locked(&now) >= MAX_PUSHES_PER_USER_DAY {
            return;
        }
        let p = self.pushes.get_mut(key).expect("registration exists");
        p.sent += 1;
        let seq = p.sent;
        p.pending_unread = unread;
        p.in_flight = true;
        let registration = p.clone();
        let generation = p.generation;
        let server = self.server.clone();
        let done_key = key.to_owned();
        let done: DoneFn = Box::new(move |status: u16| {
            let accepted = (200..300).contains(&status);
            // 404 and 410: the subscription is gone (RFC 8030 §7.3). 403:
            // the endpoint refuses this server's key, as after a key change.
            let gone = matches!(status, 403 | 404 | 410);
            let Some(server) = server.upgrade() else {
                return;
            };
            let mut st = server.lock();
            let current = st
                .pushes
                .get_mut(&done_key)
                .filter(|p| p.generation == generation);
            let current = match current {
                Some(p) => {
                    if seq == p.sent {
                        p.in_flight = false;
                    }
                    true
                }
                None => false,
            };
            if !accepted && !gone {
                return;
            }
            let user_id = registration_user(&done_key);
            let Some(u) = st.users.get_mut(user_id) else {
                return;
            };
            if accepted {
                u.pushes_today_locked(&time::now());
                u.pushes_today += 1;
                if let Some(p) = st.pushes.get_mut(&done_key).filter(|_| current) {
                    if seq > p.accepted {
                        p.accepted = seq;
                        p.last_unread = unread;
                    }
                }
            } else if current {
                st.remove_push_locked(&done_key);
            }
        });
        let latest = if badge { key.to_owned() } else { String::new() };
        self.push
            .deliver(registration, payload, urgency, latest, done);
    }
}

/// The user_id part of a push_key.
pub(super) fn registration_user(key: &str) -> &str {
    key.split_once(' ').map_or(key, |(user, _)| user)
}

/// The payload every kind delivers (§4.9): push_id, unread, and the message
/// without log_id, format, embeds, or ext, its text truncated to
/// MAX_PUSH_TEXT_RUNES. When the JSON is longer than MAX_PUSH_PAYLOAD_BYTES
/// the message is cut to fit: mentions go first, then text is shortened,
/// and then body is dropped, from keeps only user_id, and reply_to goes, in
/// turn.
pub fn push_payload(push_id: &str, unread: i64, snapshot: &Object) -> Vec<u8> {
    let field = |name: &str| snapshot.get(name).cloned().unwrap_or(Json::Null);
    let mut message = obj! {
        "message_id" => field("message_id"),
        "room_id" => field("room_id"),
        "from" => field("from"),
    };
    if let Some(reply) = snapshot.get("reply_to").and_then(Json::as_object) {
        let id = reply.get("message_id").cloned().unwrap_or(Json::Null);
        message.insert("reply_to".into(), obj! {"message_id" => id}.into());
    }
    let mut text = String::new();
    let mut mentioned = Vec::new();
    if let Some(body) = snapshot.get("body").and_then(Json::as_object) {
        text = body
            .get("text")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned();
        mentioned = mentions(Some(body));
    }
    if text.chars().count() > MAX_PUSH_TEXT_RUNES {
        text = text
            .chars()
            .take(MAX_PUSH_TEXT_RUNES - 1)
            .collect::<String>()
            + "…";
    }
    let encode = |message: &Object| -> Vec<u8> {
        let mut envelope = obj! {"unread" => unread, "message" => message.clone()};
        if !push_id.is_empty() {
            envelope.insert("push_id".into(), push_id.into());
        }
        encode_json(&envelope).unwrap_or_default()
    };
    let set_body = |message: &mut Object, text: &str, mentioned: &[String]| {
        let mut body = Object::new();
        if !text.is_empty() {
            body.insert("text".into(), text.into());
        }
        if !mentioned.is_empty() {
            body.insert("mentions".into(), mentioned.to_vec().into());
        }
        if body.is_empty() {
            message.remove("body");
        } else {
            message.insert("body".into(), body.into());
        }
    };
    let fits = |payload: &[u8]| payload.len() <= MAX_PUSH_PAYLOAD_BYTES;
    set_body(&mut message, &text, &mentioned);
    let payload = encode(&message);
    if fits(&payload) {
        return payload;
    }
    set_body(&mut message, &text, &[]);
    let payload = encode(&message);
    if fits(&payload) {
        return payload;
    }
    // The longest prefix of the text that fits, found by bisection.
    let runes: Vec<char> = text.chars().collect();
    let prefix = |message: &mut Object, n: usize| -> (bool, Vec<u8>) {
        let shortened: String = runes[..n].iter().collect::<String>() + "…";
        set_body(message, &shortened, &[]);
        let payload = encode(message);
        (fits(&payload), payload)
    };
    let (mut low, mut high) = (0, runes.len());
    while low < high {
        let middle = (low + high).div_ceil(2);
        if prefix(&mut message, middle).0 {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    if low > 0 {
        let (ok, payload) = prefix(&mut message, low);
        if ok {
            return payload;
        }
    }
    let mut payload = Vec::new();
    for cut in 0..3 {
        match cut {
            0 => set_body(&mut message, "", &[]),
            1 => {
                if let Some(Json::Object(from)) = message.get("from") {
                    let id = from.get("user_id").cloned().unwrap_or(Json::Null);
                    message.insert("from".into(), obj! {"user_id" => id}.into());
                }
            }
            _ => {
                message.remove("reply_to");
            }
        }
        payload = encode(&message);
        if fits(&payload) {
            break;
        }
    }
    payload
}

/// An endpoint in the one form a registration is kept under: an absolute
/// URL without credentials, whitespace, or a host ending in a dot, with its
/// scheme and host lowercased and no default port. The error says why it is
/// not one.
pub fn normalize_push_url(endpoint: &str) -> Result<String, &'static str> {
    let mut parsed = match url::parse(endpoint) {
        Ok(parsed)
            if !parsed.host.is_empty()
                && parsed.user.is_none()
                && parsed.opaque.is_empty()
                && !endpoint.chars().any(|c| c <= ' ') =>
        {
            parsed
        }
        _ => return Err("url must be an absolute URL"),
    };
    parsed.scheme = parsed.scheme.to_lowercase();
    let host = parsed.hostname().to_lowercase();
    if host.is_empty() || host.ends_with('.') {
        return Err("url must name a host without a trailing dot");
    }
    parsed.host = webpush::host_port(&parsed.scheme.clone(), &parsed);
    parsed.host_raw = None;
    Ok(parsed.to_string())
}

/// Normalizes an endpoint (normalize_push_url) and requires https (http too
/// with allow_insecure), a host that is not an internal address literal or
/// localhost, and one `hosts` allows. Names that resolve to internal
/// addresses are refused when dialing.
pub fn check_push_url(
    endpoint: &str,
    allow_insecure: bool,
    hosts: &PushHosts,
) -> Result<String, &'static str> {
    let endpoint = normalize_push_url(endpoint)?;
    let parsed = url::parse(&endpoint).map_err(|_| "url must be an absolute URL")?;
    if parsed.scheme != "https" && !(allow_insecure && parsed.scheme == "http") {
        return Err("url must use https");
    }
    let host = parsed.hostname();
    if !allow_insecure
        && ((host.parse::<Addr>().is_ok() && !public_address(&host))
            || host == "localhost"
            || host.ends_with(".localhost"))
    {
        return Err("url must name a public host");
    }
    if !hosts.allows(&host) {
        return Err("push service not allowed here");
    }
    Ok(endpoint)
}

impl Server {
    /// Forgets expired registrations every PUSH_SWEEP_INTERVAL until the
    /// server shuts down, so the store drops them though their users stay
    /// away, and discards the history Config.retention expired.
    pub(crate) fn sweep(self: &Arc<Self>) {
        let server = Arc::downgrade(self);
        let stopped = self.stopped.clone();
        thread::spawn(move || loop {
            if stopped.wait_timeout(PUSH_SWEEP_INTERVAL) {
                return;
            }
            let Some(server) = server.upgrade() else {
                return;
            };
            let mut st = server.lock();
            let now = time::now();
            let ids: Vec<String> = st.users.keys().cloned().collect();
            for id in ids {
                st.expire_pushes_locked(&id, &now);
            }
            let window = st.push_coalesce.max(st.joined_coalesce);
            st.push_woken.retain(|_, woken| now.sub(woken) < window);
            st.expire_history_locked(&now);
            st.sweep_idle_bots_locked(&now);
        });
    }

    /// Records a push endpoint for the caller (§4.9): kind relay, with an
    /// optional bearer token, or webpush, with the subscription's keys; a
    /// relay with keys gets the payload encrypted as for webpush.
    /// Registering a url again replaces the caller's registration of it and
    /// renews it; other users' registrations of the same url are their own.
    /// A user holds at most MAX_PUSHES_PER_USER: another replaces the one
    /// least recently registered. Accounts and bots only: a guest's identity
    /// lasts one connection, so there is no one to wake. At most
    /// PUSH_REGISTERS_PER_MINUTE a user, counted before the params are
    /// checked, so refused registrations count too.
    pub(crate) fn register_push(
        self: &Arc<Self>,
        c: &Arc<Connection>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let mut st = self.lock();
        let user_id = st.push_user(c)?;
        admit_push_register(st.users.get_mut(&user_id).expect("user exists"))?;
        let kind = parse_string(&req.params, "kind", true)?;
        if kind != "relay" && kind != "webpush" {
            return Err(invalid_params(format!(
                "Unknown push kind {}; this server supports relay and webpush",
                quote(&kind)
            )));
        }
        let endpoint = parse_string(&req.params, "url", true)?;
        let mut token = parse_string(&req.params, "token", false)?;
        let too_large = |endpoint: &str| {
            (endpoint.len() > MAX_PUSH_URL_BYTES || token.len() > MAX_PUSH_TOKEN_LEN).then(|| {
                RpcError::new(
                    CODE_TOO_LARGE,
                    format!(
                        "url is at most {MAX_PUSH_URL_BYTES} bytes and token at most {MAX_PUSH_TOKEN_LEN}"
                    ),
                )
            })
        };
        // Its size first, so a url past it is too_large whatever else is
        // wrong with it (§1.1), then again as kept.
        if let Some(err) = too_large(&endpoint) {
            return Err(err);
        }
        let endpoint = check_push_url(
            &endpoint,
            self.config.allow_insecure_push,
            &self.config.push_hosts,
        )
        .map_err(invalid_params)?;
        if let Some(err) = too_large(&endpoint) {
            return Err(err);
        }
        let push_id = parse_string(&req.params, "push_id", false)?;
        if req.params.contains_key("push_id") && !valid_push_id(&push_id) {
            return Err(invalid_params("push_id is 1 to 64 letters, digits, _ or -"));
        }
        let keys = parse_keys_param(&req.params)?;
        if kind == "webpush" {
            if keys.is_none() {
                return Err(invalid_params(
                    "A webpush registration needs keys with p256dh and auth",
                ));
            }
            // A webpush subscription has no bearer token.
            token.clear();
        }
        let mut wake = WakeScope::DEFAULT;
        if let Some(raw) = req.params.get("wake") {
            let Some(mut names) = decode_non_null::<Vec<String>>(&raw.0) else {
                return Err(invalid_params("wake must be an array of scope names"));
            };
            // Past the bounds, names are ignored like unknown scopes.
            names.truncate(MAX_WAKE_SCOPES);
            names.retain(|name| name.len() <= MAX_WAKE_SCOPE_BYTES);
            wake = parse_wake_names(&names);
        }

        // joined is kept only for those who may wake for it.
        if !st.wakes_joined(&user_id) {
            wake = WakeScope(wake.0 & !WakeScope::JOINED.0);
        }
        let device = st.clients[&c.id].device;
        let now = time::now();
        st.expire_pushes_locked(&user_id, &now);
        let keys_held = st.sorted_pushes(&user_id);
        let key = push_key(&user_id, &endpoint);
        if !keys_held.contains(&key) && keys_held.len() >= MAX_PUSHES_PER_USER {
            let mut oldest = &keys_held[0];
            for k in &keys_held {
                if st.pushes[k].renewed.before(&st.pushes[oldest].renewed) {
                    oldest = k;
                }
            }
            let oldest = oldest.clone();
            st.remove_push_locked(&oldest);
        }
        st.add_push_locked(PushRegistration {
            user_id,
            kind,
            url: endpoint,
            token,
            push_id,
            device,
            keys,
            wake,
            renewed: now,
            ..PushRegistration::default()
        });
        Ok((Json::Object(Object::new()), false))
    }

    /// Removes the caller's registration of a url; an unknown url is already
    /// unregistered (§4.9).
    pub(crate) fn unregister_push(
        self: &Arc<Self>,
        c: &Arc<Connection>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let mut endpoint = parse_string(&req.params, "url", true)?;
        if let Ok(normalized) = normalize_push_url(&endpoint) {
            endpoint = normalized;
        }
        let mut st = self.lock();
        let user_id = st.push_user(c)?;
        st.remove_push_locked(&push_key(&user_id, &endpoint));
        Ok((Json::Object(Object::new()), false))
    }
}

impl State {
    fn push_user(&self, c: &Connection) -> Result<String, RpcError> {
        let Some(user_id) = self.client_user(c) else {
            return Err(RpcError::new(CODE_DENIED, "Not authenticated"));
        };
        if !self.users[&user_id].persists() {
            return Err(RpcError::new(
                CODE_DENIED,
                "Sign in to receive push notifications",
            ));
        }
        Ok(user_id)
    }
}

/// Takes one of the user's PUSH_REGISTERS_PER_MINUTE, or says how long to
/// wait for the next.
fn admit_push_register(u: &mut UserState) -> Result<(), RpcError> {
    let limiter = u.push_registers.get_or_insert_with(|| {
        Limiter::new(
            every(Duration::from_nanos(
                time::MINUTE.as_nanos() / PUSH_REGISTERS_PER_MINUTE,
            )),
            PUSH_REGISTERS_PER_MINUTE,
        )
    });
    let now = time::now();
    let reservation = limiter.reserve_n(&now, 1);
    let delay = reservation.delay_from(&now);
    if delay.as_nanos() > 0 {
        limiter.cancel_at(&reservation, &now);
        return Err(retry_after("Push registrations limited", delay));
    }
    Ok(())
}

/// Reads a registration's optional keys (§4.9).
fn parse_keys_param(params: &Params) -> Result<Option<PushKeys>, RpcError> {
    let Some(raw) = params.get("keys") else {
        return Ok(None);
    };
    let Some(raw) = decode_non_null::<Params>(&raw.0) else {
        return Err(invalid_params(
            "keys must be an object with p256dh and auth",
        ));
    };
    let p256dh = parse_string(&raw, "p256dh", true)
        .map_err(|_| invalid_params("keys.p256dh must be a string"))?;
    let auth = parse_string(&raw, "auth", true)
        .map_err(|_| invalid_params("keys.auth must be a string"))?;
    webpush::parse_push_keys(&p256dh, &auth)
        .map(Some)
        .map_err(invalid_params)
}
