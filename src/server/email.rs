//! Email sign-in (§4.11): email.go.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rust_stdlib::context::Context;
use rust_stdlib::log::slog;
use rust_stdlib::net::{self, mail, url};
use rust_stdlib::time::{self, Duration, Time};
use rust_stdlib_crypto::bigint::Int;
use rust_stdlib_crypto::{rand, subtle};

use super::bots::BOT_SIGNS_IN_WITH_TOKEN;
use super::protocol::*;
use super::server::{Client, Conn, State};
use super::status::retry_after;
use super::users::{normalize_name, requestable};
use crate::rate::{every, Limiter};

/// How long a proposal and its tokens, emailed as it is made, stay valid.
pub const EMAIL_CODE_LIFETIME: Duration = Duration::from_mins(10);
/// Wrong tokens, on any connection, that cancel a proposal.
pub const MAX_EMAIL_ATTEMPTS: u32 = 5;
/// Starts each link token with a handle naming its proposal, so a wrong
/// secret behind it counts against that proposal from any connection.
pub const LINK_HANDLE_BYTES: usize = 10;
/// Bounds the state a proposal carries (§4.11.1).
pub const MAX_STATE_BYTES: usize = 256;
/// The least time between emails to one address, and the window of
/// `MAX_EMAIL_SENDS_PER_WINDOW` emails to it.
pub const EMAIL_RESEND_INTERVAL: Duration = Duration::from_secs(30);
pub const EMAIL_WINDOW: Duration = Duration::from_hours(1);
pub const MAX_EMAIL_SENDS_PER_WINDOW: usize = 6;
/// Per client address (IP, or IPv6 /64): a burst of `CLIENT_SEND_BURST`
/// proposals, refilled one per `CLIENT_SEND_REFILL`.
pub const CLIENT_SEND_BURST: i64 = 10;
pub const CLIENT_SEND_REFILL: Duration = Duration::from_mins(3);
/// The tables of addresses and clients, and the outstanding link tokens,
/// are bounded.
pub const MAX_TRACKED_EMAIL_STATE: usize = 10_000;
pub const MAX_TRACKED_CLIENTS: usize = 100_000;
pub const MAX_EMAIL_LINKS: usize = 10_000;
/// Bounds deliveries in progress; beyond it a proposal is retry_after.
pub const MAX_CONCURRENT_EMAIL_SENDS: usize = 16;
/// Proposals one connection may make at once, refilled one per
/// `EMAIL_SEND_REFILL`.
pub const EMAIL_SENDS_PER_CONNECTION: i64 = 5;
pub const EMAIL_SEND_REFILL: Duration = Duration::from_mins(2);
/// Bounds one delivery by the EmailSender.
pub const EMAIL_SEND_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_EMAIL_BYTES: usize = 254;
/// Starts the user_ids assigned to new email accounts that did not request
/// one.
pub const ACCOUNT_ID_PREFIX: &str = "user_";
/// How many of the least recently used entries a full table looks at for
/// one it may forget.
pub const EVICTION_SCAN: usize = 256;

pub type SendError = Box<dyn std::error::Error + Send + Sync>;

/// Delivers the codes of email sign-in (PROTOCOL.md §4.11). The server
/// calls it on its own thread, outside any lock; an error is logged, and the
/// person asks for another code.
pub trait EmailSender: Send + Sync {
    fn send_sign_in_code(&self, ctx: &Context, message: &SignInEmail) -> Result<(), SendError>;
}

/// One email sign-in code to deliver.
#[derive(Clone, Debug)]
pub struct SignInEmail {
    /// The address, as the server normalized it.
    pub to: String,
    /// The short token to type, six digits, which works only on the
    /// connection that made the proposal.
    pub code: String,
    /// Opens `Config.email_link_url` with the long token in its fragment,
    /// which works on any connection: for a sign-in, one not signed in, and
    /// for an addition, one signed in to the proposing account. Empty when
    /// no link is configured.
    pub link: String,
    /// When the code and the link stop working.
    pub expires: Time,
    /// A proposal to add the address to a signed-in account, which signs
    /// nobody in.
    pub add: bool,
}

impl SignInEmail {
    /// Renders the message as plain text, for senders without templates.
    pub fn text(&self) -> String {
        let mut b = if self.add {
            format!(
                "Your code to add this address to your account is {}.\n",
                self.code
            )
        } else {
            format!("Your sign-in code is {}.\n", self.code)
        };
        if self.link.is_empty() {
        } else if self.add {
            b += &format!(
                "\nOr open this link where you are signed in to add it:\n{}\n",
                self.link
            );
        } else {
            b += &format!("\nOr open this link to sign in:\n{}\n", self.link);
        }
        let minutes =
            time::until(&self.expires).round(time::MINUTE).as_nanos() / time::MINUTE.as_nanos();
        b += &format!(
            "\nThe code expires in {minutes} minutes. If you did not ask for it, ignore this email.\n"
        );
        b
    }
}

/// Logs sign-in codes instead of sending them, for development: whoever
/// reads the server's log can sign in as any address.
#[derive(Clone, Default)]
pub struct LogEmailSender {
    pub logger: Option<slog::Logger>,
}

impl EmailSender for LogEmailSender {
    fn send_sign_in_code(&self, _ctx: &Context, m: &SignInEmail) -> Result<(), SendError> {
        let logger = self.logger.clone().unwrap_or_else(slog::default);
        logger.info(
            "email sign-in code (not sent; development sender)",
            &[
                "to".into(),
                slog::Value::from(m.to.as_str()).into(),
                "code".into(),
                slog::Value::from(m.code.as_str()).into(),
                "link".into(),
                slog::Value::from(m.link.as_str()).into(),
            ],
        );
        Ok(())
    }
}

/// Names a proposal in `EmailState.proposals`.
pub type ProposalId = u64;

/// A connection's pending proposal (§4.11.1): to sign in with an address,
/// or to add it to the proposing account. Its short code works only on that
/// connection; its link token, a handle and an unguessable secret, works on
/// any connection that may approve it (§4.11.3). It outlives its
/// connection's disconnect, until it expires or is approved, and holds
/// neither the connection nor the account. Go's `dropped` flag is its
/// absence from `EmailState.proposals`.
#[derive(Clone, Debug)]
pub struct EmailProposal {
    pub email: String,
    /// The user_id of the proposing account, for an addition. User_ids are
    /// never reissued, so only a connection signed in to that account has
    /// it.
    pub account_id: String,
    pub add: bool,
    pub code: String,
    /// The halves of the link token; both are empty when no link is sent.
    pub handle: String,
    pub secret: String,
    /// The client's, returned in the link.
    pub state: String,
    pub expires: Time,
    pub attempts: u32,
    /// What the proposing connection requested for a new account.
    pub name: String,
    pub user_id: String,
}

/// What the server keeps about one address, in memory only: the proposals
/// accepted for it in the last `EMAIL_WINDOW`, emailed or not, so its limit
/// reads the same whether or not it has an account.
#[derive(Debug, Default)]
pub struct EmailAddress {
    pub sends: Vec<Time>,
}

impl EmailAddress {
    /// Forgets sends older than `EMAIL_WINDOW`, and reports whether nothing
    /// is left to keep.
    pub fn prune(&mut self, now: &Time) -> bool {
        let lapsed = self
            .sends
            .iter()
            .take_while(|sent| !now.before(&sent.add(EMAIL_WINDOW)))
            .count();
        self.sends.drain(..lapsed);
        self.sends.is_empty()
    }
}

/// The budget of one client address, kept like `EmailAddress`.
#[derive(Debug)]
pub struct EmailClient {
    pub sends: Limiter,
}

/// A table kept in least recently used order, Go's map plus
/// `container/list`. Each entry carries the tick of its last use, and
/// `order` indexes the entries by tick, oldest first.
#[derive(Debug)]
pub struct Lru<V> {
    entries: BTreeMap<String, (u64, V)>,
    order: BTreeMap<u64, String>,
    tick: u64,
}

impl<V> Default for Lru<V> {
    fn default() -> Self {
        Lru {
            entries: BTreeMap::new(),
            order: BTreeMap::new(),
            tick: 0,
        }
    }
}

impl<V> Lru<V> {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// The entry under `key`, leaving the order as it is.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        self.entries.get_mut(key).map(|(_, value)| value)
    }

    /// Makes `key` the most recently used entry.
    pub fn move_to_front(&mut self, key: &str) {
        if let Some((tick, _)) = self.entries.get_mut(key) {
            self.order.remove(tick);
            self.tick += 1;
            *tick = self.tick;
            self.order.insert(self.tick, key.to_owned());
        }
    }

    /// Adds `value` under `key` as the most recently used entry.
    pub fn push_front(&mut self, key: &str, value: V) {
        self.remove(key);
        self.tick += 1;
        self.order.insert(self.tick, key.to_owned());
        self.entries.insert(key.to_owned(), (self.tick, value));
    }

    pub fn remove(&mut self, key: &str) -> Option<V> {
        let (tick, value) = self.entries.remove(key)?;
        self.order.remove(&tick);
        Some(value)
    }

    /// Removes the least recently used entry, among the oldest `scan`, that
    /// `forget` accepts, and reports whether there was one. `forget` may
    /// change the entries it declines.
    pub fn evict(&mut self, scan: usize, mut forget: impl FnMut(&mut V) -> bool) -> bool {
        let oldest: Vec<String> = self.order.values().take(scan).cloned().collect();
        for key in oldest {
            if let Some((_, value)) = self.entries.get_mut(&key) {
                if forget(value) {
                    self.remove(&key);
                    return true;
                }
            }
        }
        false
    }
}

/// The email sign-in state of a server, guarded by its lock.
#[derive(Debug, Default)]
pub struct EmailState {
    pub addresses: Lru<EmailAddress>,
    pub clients: Lru<EmailClient>,
    /// Every live proposal: held by its connection, by its link, or both.
    pub proposals: BTreeMap<ProposalId, EmailProposal>,
    next_proposal: ProposalId,
    /// The handle of each outstanding link token to its proposal.
    pub links: BTreeMap<String, ProposalId>,
    /// Counts the deliveries in progress. Only the lock holder adds to it,
    /// so a check and an add under the lock cannot overshoot; a delivery
    /// thread subtracts when it finishes.
    pub slots: Arc<AtomicUsize>,
}

impl EmailState {
    /// The state of an address, pruned, or `None` when there is none to
    /// keep. It creates nothing: a request that is refused leaves no trace
    /// in the table.
    pub fn address(&mut self, email: &str, now: &Time) -> Option<&mut EmailAddress> {
        if self.addresses.get_mut(email)?.prune(now) {
            self.addresses.remove(email);
            return None;
        }
        self.addresses.move_to_front(email);
        self.addresses.get_mut(email)
    }

    /// The state of an address, created if need be. When the table is full
    /// it forgets the least recently used entry with no email in the
    /// window, and returns `None` when it finds none, so a proposal is
    /// refused rather than erasing another address's limit.
    pub fn create_address(&mut self, email: &str, now: &Time) -> Option<&mut EmailAddress> {
        if self.address(email, now).is_some() {
            return self.addresses.get_mut(email);
        }
        if self.addresses.len() >= MAX_TRACKED_EMAIL_STATE
            && !self.addresses.evict(EVICTION_SCAN, |a| a.prune(now))
        {
            return None;
        }
        self.addresses.push_front(email, EmailAddress::default());
        self.addresses.get_mut(email)
    }

    /// The budget of a client address, created if need be. When the table
    /// is full it forgets the least recently used client whose budget is
    /// full again, and returns `None` when it finds none.
    pub fn client(&mut self, key: &str, now: &Time) -> Option<&mut EmailClient> {
        if !self.clients.contains_key(key) {
            if self.clients.len() >= MAX_TRACKED_CLIENTS
                && !self.clients.evict(EVICTION_SCAN, |old| {
                    old.sends.tokens_at(now) >= CLIENT_SEND_BURST as f64
                })
            {
                return None;
            }
            self.clients.push_front(
                key,
                EmailClient {
                    sends: Limiter::new(every(CLIENT_SEND_REFILL), CLIENT_SEND_BURST),
                },
            );
        }
        self.clients.move_to_front(key);
        self.clients.get_mut(key)
    }
}

/// How long until `limiter` allows one more event, or zero.
fn wait(limiter: &mut Limiter, now: &Time) -> Duration {
    let reservation = limiter.reserve_n(now, 1);
    let delay = reservation.delay_from(now);
    limiter.cancel_at(&reservation, now);
    delay
}

/// Identifies a connection's client for rate limits: its IP, or the /64 of
/// an IPv6 address, which one household or host usually has.
pub fn client_key(ip: &str) -> String {
    let Some(parsed) = net::parse_ip(ip) else {
        return ip.to_owned();
    };
    if let Some(v4) = parsed.to4() {
        return v4.to_string();
    }
    match net::cidr_mask(64, 128).and_then(|mask| parsed.mask(&mask)) {
        Some(prefix) => format!("{prefix}/64"),
        None => ip.to_owned(),
    }
}

/// A bare address, lowercased, or "" if `value` is not one. The domain must
/// be a DNS name with a dot: address literals such as a@[10.0.0.5] and
/// single labels such as a@localhost are refused, so codes go only to
/// public mail domains.
pub fn normalize_email(value: &str) -> String {
    let value = value.trim().to_lowercase();
    if value.is_empty() || value.len() > MAX_EMAIL_BYTES {
        return String::new();
    }
    match mail::parse_address(&value) {
        Ok(parsed) if parsed.name.is_empty() && parsed.address == value => {}
        _ => return String::new(),
    }
    let domain = value.split_once('@').map_or("", |(_, domain)| domain);
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return String::new();
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return String::new();
        }
    }
    if labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit()) {
        return String::new(); // an IPv4 address, not a domain
    }
    value
}

/// A link built from the configured page, never from request fields other
/// than state, with the token in the fragment so it stays out of server
/// logs (§4.11.2): #token=<token>, &state=<state> with the proposal's
/// state, unchanged, when it carried one, and &server=<URL> with this
/// server's public WebSocket URL when it is known, so a client that speaks
/// to several servers presents it to the right one. Values are
/// form-encoded.
pub fn sign_in_link(page: &str, token: &str, state: &str, server: &str) -> String {
    let page = page.split_once('#').map_or(page, |(page, _)| page);
    let mut link = format!("{page}#token={}", url::query_escape(token));
    if !state.is_empty() {
        link += &format!("&state={}", url::query_escape(state));
    }
    if !server.is_empty() {
        link += &format!("&server={}", url::query_escape(server));
    }
    link
}

/// The WebSocket endpoint under `base`, such as wss://chat.example/ws for
/// https://chat.example: a connection's base URL, `Config.public_url` or
/// else the scheme and host it arrived on. It is "" for a base that isn't
/// an http or https URL.
pub fn web_socket_url(base: &str) -> String {
    if base.is_empty() {
        return String::new();
    }
    let Ok(mut parsed) = url::parse(base) else {
        return String::new();
    };
    parsed.scheme = match parsed.scheme.as_str() {
        "https" => "wss".into(),
        "http" => "ws".into(),
        _ => return String::new(),
    };
    parsed.path = parsed.path.trim_end_matches('/').to_owned() + "/ws";
    parsed.raw_query.clear();
    parsed.fragment.clear();
    parsed.to_string()
}

/// Parses the name and user_id that a proposal or an approval may request
/// for a new account.
pub fn parse_requested(req: &Request) -> Result<(String, String), RpcError> {
    let name = parse_string(&req.params, "name", false)?;
    let requested = parse_string(&req.params, "user_id", false)?;
    Ok((name, requested))
}

/// A uniform six-digit code.
fn new_code() -> Option<String> {
    let number = rand::int(&Int::from_u64(1_000_000)).ok()?;
    let bytes = number.fill_bytes(8)?;
    let number = u64::from_be_bytes(bytes.try_into().ok()?);
    Some(format!("{number:06}"))
}

fn denied(message: &str) -> RpcError {
    RpcError::new(CODE_DENIED, message)
}

impl State {
    fn conn_mut(&mut self, c: &Client) -> Result<&mut Conn, RpcError> {
        self.clients
            .get_mut(&c.id)
            .ok_or_else(|| RpcError::new(CODE_INTERNAL_ERROR, "Internal error"))
    }

    /// Forgets a proposal: its connection's, and its link.
    pub fn drop_proposal_locked(&mut self, id: ProposalId) {
        let Some(p) = self.email.proposals.remove(&id) else {
            return;
        };
        if !p.handle.is_empty() && self.email.links.get(&p.handle) == Some(&id) {
            self.email.links.remove(&p.handle);
        }
    }

    /// Forgets the proposal of a closed connection unless its link keeps it
    /// approvable elsewhere. Go lets the garbage collector do this once
    /// neither the connection nor `links` points at it.
    pub fn release_proposal_locked(&mut self, conn: &Conn) {
        if let Some(id) = conn.proposal {
            if self
                .email
                .proposals
                .get(&id)
                .is_some_and(|p| p.handle.is_empty())
            {
                self.drop_proposal_locked(id);
            }
        }
    }

    /// Runs the email scheme (§4.11). A request without token proposes, by
    /// email; one with token approves a proposal (§4.11.3), which takes
    /// either scheme the server offers, or token (`authenticate_token`).
    pub fn authenticate_email(&mut self, c: &Arc<Client>, req: &Request) -> Result<Json, RpcError> {
        if req.params.contains_key("token") {
            return self.approve_locked(c, req);
        }
        self.propose_email_locked(c, req)
    }

    /// Replaces the connection's proposal with a new one (§4.11.1) and
    /// emails its tokens in the background: a code to type and, when a link
    /// page is configured, a link with the proposal's state. On a connection
    /// signed in, guests included, it proposes adding the address to that
    /// account, else signing in with it. It returns {}, whether or not the
    /// address has an account, and changes no authentication. An addition
    /// is emailed only when the address could be added: no account holds
    /// it, and the proposing one has none.
    ///
    /// Emails to one address are at least `EMAIL_RESEND_INTERVAL` apart and
    /// at most `MAX_EMAIL_SENDS_PER_WINDOW` an hour; a client address and a
    /// connection may propose a few; and at most
    /// `MAX_CONCURRENT_EMAIL_SENDS` deliveries run at once. Beyond any of
    /// these the request is retry_after, whether or not the address has an
    /// account.
    pub fn propose_email_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<Json, RpcError> {
        let (name, requested) = parse_requested(req)?;
        let state = parse_string(&req.params, "state", false)?;
        if state.len() > MAX_STATE_BYTES {
            return Err(RpcError::new(
                CODE_TOO_LARGE,
                format!("state is at most {MAX_STATE_BYTES} bytes"),
            ));
        }
        let raw = parse_string(&req.params, "email", true)?;
        let email = normalize_email(&raw);
        if email.is_empty() {
            return Err(invalid_params(
                "email must be an email address at a domain name",
            ));
        }
        // An address would make the bot an account (bots.rs).
        if self
            .client_user(c)
            .is_some_and(|id| self.users.get(&id).is_some_and(|u| u.bot()))
        {
            return Err(denied(BOT_SIGNS_IN_WITH_TOKEN));
        }
        let now = time::now();
        let busy = || {
            retry_after(
                "Too many sign-ins in progress; try again shortly",
                EMAIL_RESEND_INTERVAL,
            )
        };
        let mut known = false;
        if let Some(address) = self.email.address(&email, &now) {
            known = true;
            let n = address.sends.len();
            let wait = address.sends[n - 1].add(EMAIL_RESEND_INTERVAL).sub(&now);
            if wait.as_nanos() > 0 {
                return Err(retry_after(
                    "An email was just sent to this address; try again shortly",
                    wait,
                ));
            }
            if n >= MAX_EMAIL_SENDS_PER_WINDOW {
                return Err(retry_after(
                    "Too many emails were sent to this address; try again later",
                    address.sends[0].add(EMAIL_WINDOW).sub(&now),
                ));
            }
        }
        let Some(budget) = self.email.client(&c.client_key, &now) else {
            return Err(busy());
        };
        let delay = wait(&mut budget.sends, &now);
        if delay.as_nanos() > 0 {
            return Err(retry_after(
                "Too many sign-ins proposed; try again later",
                delay,
            ));
        }
        let conn = self.conn_mut(c)?;
        let sends = conn.email_sends.get_or_insert_with(|| {
            Limiter::new(every(EMAIL_SEND_REFILL), EMAIL_SENDS_PER_CONNECTION)
        });
        let delay = wait(sends, &now);
        if delay.as_nanos() > 0 {
            return Err(retry_after(
                "Too many sign-ins proposed; try again later",
                delay,
            ));
        }
        let account = conn.user.clone();
        let deliver = match &account {
            None => true,
            Some(id) => {
                !self.emails.contains_key(&email)
                    && self.users.get(id).is_some_and(|u| u.email.is_empty())
            }
        };
        let linked = deliver && !self.config.email_link_url.is_empty();
        if linked && self.email.links.len() >= MAX_EMAIL_LINKS {
            let expired: Vec<ProposalId> = self
                .email
                .links
                .values()
                .copied()
                .filter(|id| {
                    self.email
                        .proposals
                        .get(id)
                        .is_none_or(|p| !now.before(&p.expires))
                })
                .collect();
            for id in expired {
                self.drop_proposal_locked(id);
            }
            if self.email.links.len() >= MAX_EMAIL_LINKS {
                return Err(busy());
            }
        }
        // The entry is made only for a proposal that is accepted, emailed or
        // not: an addition sends nothing for an address with an account, and
        // must count the same as one that does.
        if !known && self.email.create_address(&email, &now).is_none() {
            return Err(busy());
        }
        if self.email.slots.load(Ordering::SeqCst) >= MAX_CONCURRENT_EMAIL_SENDS {
            return Err(retry_after(
                "Too many emails are being sent; try again shortly",
                EMAIL_RESEND_INTERVAL,
            ));
        }
        self.email.slots.fetch_add(1, Ordering::SeqCst);
        let Some(code) = new_code() else {
            self.email.slots.fetch_sub(1, Ordering::SeqCst);
            return Err(RpcError::new(
                CODE_INTERNAL_ERROR,
                "Unable to create a code",
            ));
        };
        if let Some(budget) = self.email.clients.get_mut(&c.client_key) {
            budget.sends.allow_n(&now, 1);
        }
        if let Some(address) = self.email.addresses.get_mut(&email) {
            address.sends.push(now.clone());
        }
        let conn = self.conn_mut(c)?;
        if let Some(sends) = conn.email_sends.as_mut() {
            sends.allow_n(&now, 1);
        }
        if let Some(previous) = conn.proposal.take() {
            self.drop_proposal_locked(previous);
        }
        let add = account.is_some();
        let mut p = EmailProposal {
            email: email.clone(),
            account_id: account.unwrap_or_default(),
            add,
            code,
            handle: String::new(),
            secret: String::new(),
            state: state.clone(),
            expires: now.add(EMAIL_CODE_LIFETIME),
            attempts: 0,
            name,
            user_id: requested,
        };
        let mut message = SignInEmail {
            to: email,
            code: p.code.clone(),
            link: String::new(),
            expires: p.expires.clone(),
            add,
        };
        self.email.next_proposal += 1;
        let id = self.email.next_proposal;
        if linked {
            p.handle = self.new_link_handle_locked();
            p.secret = rand::text();
            self.email.links.insert(p.handle.clone(), id);
            // The server's address goes in the link even without a public
            // URL, so a link that opens a client not tied to one server,
            // such as one on link.apron.chat, says where to sign in
            // (§4.11.2).
            message.link = sign_in_link(
                &self.config.email_link_url,
                &format!("{}{}", p.handle, p.secret),
                &state,
                &web_socket_url(&c.base_url),
            );
        }
        self.email.proposals.insert(id, p);
        self.conn_mut(c)?.proposal = Some(id);
        let slots = self.email.slots.clone();
        match (
            deliver,
            self.config.email_sender.clone(),
            self.server.upgrade(),
        ) {
            (true, Some(sender), Some(server)) => server.mailing.spawn(move || {
                let (ctx, cancel) = Context::background().with_timeout(EMAIL_SEND_TIMEOUT);
                if let Err(e) = sender.send_sign_in_code(&ctx, &message) {
                    slog::error(
                        "cannot send an email code",
                        &["error".into(), slog::Value::from(e.to_string()).into()],
                    );
                }
                cancel();
                slots.fetch_sub(1, Ordering::SeqCst);
            }),
            _ => {
                slots.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let result = Object::new();
        c.send_result(req, result.clone().into());
        Ok(result.into())
    }

    /// A link handle no outstanding link has.
    fn new_link_handle_locked(&self) -> String {
        loop {
            let handle = rand::text()[..LINK_HANDLE_BYTES].to_owned();
            if !self.email.links.contains_key(&handle) {
                return handle;
            }
        }
    }

    /// Approves a proposal with its temporary token (§4.11.3), under either
    /// scheme the server offers: the code of the connection's own proposal,
    /// or the link token of a proposal made on any connection. Approving a
    /// sign-in authenticates this connection, which must not be signed in,
    /// to the address's account or a new one, taking a requested user_id as
    /// guests do, or user_<n>, and returns {you, token}. Approving an
    /// addition, only on a connection signed in to the proposing account,
    /// adds the address to that account and returns {}. A token presented
    /// on a connection that may not approve it is denied, and its proposal
    /// stays for one that may.
    pub fn approve_locked(&mut self, c: &Arc<Client>, req: &Request) -> Result<Json, RpcError> {
        let token = parse_string(&req.params, "token", true)?;
        let (name, requested) = parse_requested(req)?;
        let now = time::now();
        let Some(id) = self.proposal_locked(c, &token, &now) else {
            return Err(denied("The code is invalid or expired; ask for a new one"));
        };
        let p = self.email.proposals[&id].clone();
        let current = self.client_user(c);

        if p.add {
            // Only the proposing account approves an addition: otherwise
            // someone could lead a victim to add the victim's address to the
            // other person's account.
            let Some(account) = current.filter(|id| *id == p.account_id) else {
                return Err(denied(
                    "Open this link where the account that asked for it is signed in",
                ));
            };
            self.drop_proposal_locked(id);
            if self.emails.contains_key(&p.email) {
                return Err(denied("This address belongs to an account"));
            }
            if self
                .users
                .get(&account)
                .is_some_and(|u| !u.email.is_empty())
            {
                return Err(denied("This account has an email address already"));
            }
            if let Some(u) = self.users.get_mut(&account) {
                u.email = p.email.clone();
            }
            self.emails.insert(p.email.clone(), account.clone());
            self.touch_user(&account);
            if self.grant_roles_locked(&account) {
                // The account's roles changed with its address.
                self.notify_profile_locked(&account, None, &ExtObject::new(), &[]);
            }
            let result = Object::new();
            c.send_result(req, result.clone().into());
            return Ok(result.into());
        }

        // A sign-in authenticates a connection that is not signed in; the
        // proposal stays for one that is not.
        if current.is_some() {
            return Err(denied(
                "Sign-in codes work on a connection that is not signed in",
            ));
        }
        let own = self.clients.get(&c.id).and_then(|conn| conn.proposal) == Some(id);
        self.drop_proposal_locked(id);
        if let Some(user_id) = self.emails.get(&p.email).cloned() {
            return self.sign_in_locked(c, req, &user_id, &now, true, false);
        }
        // A proposal's own name and user_id apply only on its connection: a
        // link opened elsewhere is someone reading the email, whose account
        // the proposer must not name.
        let (mut name, mut requested) = (name, requested);
        if own {
            if name.is_empty() {
                name = p.name.clone();
            }
            if requested.is_empty() {
                requested = p.user_id.clone();
            }
        }
        let user_id = self.assign_account_id_locked(&requested);
        let mut user = self.new_user_locked(&user_id, &normalize_name(&name));
        user.email = p.email.clone();
        self.users.insert(user_id.clone(), user);
        self.emails.insert(p.email.clone(), user_id.clone());
        self.touch_user(&user_id);
        self.grant_roles_locked(&user_id);
        // A new account joins the default room, as a new guest does, after
        // the result (§3.2.2).
        self.sign_in_locked(c, req, &user_id, &now, true, true)
    }

    /// Reports whether `token` is one that `proposal_locked` would check
    /// against a proposal: the connection's own, or the one its link handle
    /// names. Then a wrong token counts as a failed attempt under any
    /// scheme; any other token is no temporary token.
    pub fn may_approve_locked(&self, c: &Client, token: &str) -> bool {
        self.clients
            .get(&c.id)
            .is_some_and(|conn| conn.proposal.is_some())
            || link_handle(token).is_some_and(|handle| self.email.links.contains_key(handle))
    }

    /// The live proposal that `token` approves: the connection's own, by its
    /// code, or any, by its link token. Otherwise `None`, and a failed
    /// attempt counts against the proposal that `token` names by its link
    /// handle, else against the connection's own, whichever connection
    /// presents it (§4.11.1): `MAX_EMAIL_ATTEMPTS` of them cancel it.
    /// Expired proposals are dropped.
    pub fn proposal_locked(&mut self, c: &Client, token: &str, now: &Time) -> Option<ProposalId> {
        let mut own = self.clients.get(&c.id).and_then(|conn| conn.proposal);
        if let Some(id) = own {
            let live = self
                .email
                .proposals
                .get(&id)
                .is_some_and(|p| now.before(&p.expires));
            if !live {
                self.drop_proposal_locked(id);
                if let Some(conn) = self.clients.get_mut(&c.id) {
                    conn.proposal = None;
                }
                own = None;
            }
        }
        if let Some(id) = own {
            let code = &self.email.proposals[&id].code;
            if subtle::constant_time_compare(token.as_bytes(), code.as_bytes()) == 1 {
                return Some(id);
            }
        }
        let mut target = own;
        if let Some(&id) = link_handle(token).and_then(|handle| self.email.links.get(handle)) {
            let p = &self.email.proposals[&id];
            if !now.before(&p.expires) {
                self.drop_proposal_locked(id);
                return None;
            }
            let secret = &token.as_bytes()[LINK_HANDLE_BYTES..];
            if subtle::constant_time_compare(secret, p.secret.as_bytes()) == 1 {
                return Some(id);
            }
            target = Some(id);
        }
        if let Some(id) = target {
            if let Some(p) = self.email.proposals.get_mut(&id) {
                p.attempts += 1;
                if p.attempts >= MAX_EMAIL_ATTEMPTS {
                    self.drop_proposal_locked(id);
                }
            }
        }
        None
    }

    /// Honors a requested user_id as `assign_user_id_locked` does, and
    /// otherwise assigns the next unused user_<n>.
    pub fn assign_account_id_locked(&mut self, requested: &str) -> String {
        if requestable(requested) && self.claim_user_id_locked(requested) {
            return requested.to_owned();
        }
        loop {
            self.account_number += 1;
            let id = format!("{ACCOUNT_ID_PREFIX}{}", self.account_number);
            if self.claim_user_id_locked(&id) {
                return id;
            }
        }
    }
}

/// The handle a link token starts with, when the token is longer than one.
/// Go slices bytes; a token whose first bytes are not text names no handle.
fn link_handle(token: &str) -> Option<&str> {
    if token.len() <= LINK_HANDLE_BYTES {
        return None;
    }
    std::str::from_utf8(&token.as_bytes()[..LINK_HANDLE_BYTES]).ok()
}
