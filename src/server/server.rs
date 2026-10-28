use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread;

use rust_stdlib::concurrent::WaitGroup;
use rust_stdlib::context::Context;
use rust_stdlib::encoding::json::v2::MarshalTo;
use rust_stdlib::log::slog;
use rust_stdlib::net::http::{self, Handler, Request as HttpRequest, ResponseWriter, ServeMux};
use rust_stdlib::time::{self, Duration};
use rust_stdlib_crypto::sha256;

use super::bots::BotTokens;
use super::devices::DeviceTokens;
use super::email::{EmailSender, EmailState, ProposalId};
use super::embeds::EmbedState;
use super::messages::MessageState;
use super::persist::{DirtySet, StoredMeta};
use super::protocol::*;
use super::push::{PushDeliverer, PushRegistration};
use super::rooms::RoomState;
use super::status::optional_statuses;
use super::users::{DedupEntry, UserState};
use super::webauthn::{PasskeyCeremony, Sessions, WebAuthn};
use super::webpush::VapidKey;
use crate::obj;
use crate::rate::Limiter;
use crate::store::{self, Entry, Store};
use crate::ws;

pub const DEFAULT_READ_LIMIT: i64 = 256 << 10;
pub const DEFAULT_OUTGOING_QUEUE: usize = 128;
pub const DEFAULT_HISTORY_PAGE_SIZE: usize = 100;
pub const MAX_HISTORY_PAGE_SIZE: usize = 1000;
pub const DEFAULT_PING_INTERVAL: Duration = Duration::from_secs(30);
pub const DEFAULT_PING_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_MAX_UPLOAD_BYTES: i64 = 20 << 20;
pub const DEFAULT_MAX_AVATAR_BYTES: i64 = 2 << 20;
pub const DEFAULT_MAX_MESSAGE_UPLOADS: i64 = 20 << 20;
pub const DEFAULT_MAX_UPLOAD_STORAGE: i64 = 1000 << 20;
/// Bounds the records in one history page; a page always holds at least one
/// record.
pub const MAX_HISTORY_REPLY_BYTES: usize = 4 << 20;
pub const DEFAULT_UPLOAD_START_TIMEOUT: Duration = Duration::from_mins(5);
pub const DEFAULT_STREAM_KEEP_BYTES: usize = 64 << 10;
pub const DEFAULT_STREAM_MAX_BYTES: i64 = 16 << 20;
pub const DEFAULT_STREAM_MAX_DURATION: Duration = Duration::from_hours(1);
pub const DEFAULT_MAX_LISTED_MEMBERS: usize = 1000;
/// The delay suggested by connection-level retry_after errors (capacity and
/// shutdown).
pub const RETRY_AFTER_SECONDS: i64 = 30;

/// Controls the HTTP and WebSocket behavior of a Server. The fields are Go's
/// `Config`; the ones later phases implement are kept so a configuration
/// written against the Go server type-checks here.
#[derive(Clone)]
pub struct Config {
    /// Enables passkeys with an explicitly configured RP and frontend
    /// origins.
    pub web_authn: Option<Arc<WebAuthn>>,
    /// Passed to the WebSocket origin checker. `None` uses the local
    /// development origins for localhost, 127.0.0.1, and ::1.
    pub origin_patterns: Option<Vec<String>>,
    /// Disables origin checking. Use only for a trusted deployment.
    pub allow_any_origin: bool,
    /// Serves a built frontend from the HTTP root when non-empty. Phase 3.
    pub static_dir: String,
    pub read_limit: i64,
    pub outgoing_queue: usize,
    pub history_page_size: usize,
    pub ping_interval: Duration,
    pub ping_timeout: Duration,
    pub write_timeout: Duration,
    /// The external base URL (scheme and host) of write, file, and stream
    /// URLs. Empty derives it from each WebSocket request's Host header.
    pub public_url: String,
    pub max_upload_bytes: i64,
    pub max_avatar_bytes: i64,
    pub max_message_upload_bytes: i64,
    pub max_upload_storage_bytes: i64,
    pub upload_dir: String,
    pub upload_start_timeout: Duration,
    pub stream_keep_bytes: usize,
    pub stream_max_bytes: i64,
    pub stream_max_duration: Duration,
    /// Keeps the server's state across restarts; `None` keeps it in memory
    /// for this Server only. The server closes it on `shutdown`.
    pub store: Option<Arc<dyn Store>>,
    /// Omits server.push and push registration.
    pub disable_push: bool,
    /// Accepts http push endpoints and internal addresses.
    pub allow_insecure_push: bool,
    /// The server's VAPID key for webpush (§4.9), the P-256 scalar in
    /// base64url; empty uses the one kept in the store, or generates one.
    pub vapid_private_key: String,
    /// The contact push services may use, a mailto: or https: URL, sent in
    /// VAPID tokens. Empty uses public_url, if any.
    pub vapid_subject: String,
    /// Bounds concurrent WebSockets; 0 is unlimited.
    pub max_connections: usize,
    /// Bounds each user's new messages; 0 is unlimited.
    pub messages_per_minute: i64,
    /// Bounds a room's members in room_list and room_update joined; a larger
    /// room lists its most recently active members and member_count
    /// (§4.2.1). 0 is unlimited.
    pub max_listed_members: usize,
    /// Bounds the top-level private rooms (§4.2.4) one user is in at once.
    /// 0 is unlimited.
    pub max_private_rooms: usize,
    /// server.welcome (§3.2): Markdown shown on the sign-in screen.
    pub welcome: String,
    /// Grants server roles (§3.3), such as "admin", to accounts: each role
    /// lists the user_ids or email addresses that hold it.
    pub roles: BTreeMap<String, Vec<String>>,
    /// Enables email sign-in (§4.11) and delivers its codes; `None`
    /// disables it. `LogEmailSender` logs codes, for development.
    pub email_sender: Option<Arc<dyn EmailSender>>,
    /// Names the request header a reverse proxy puts the client's address
    /// in, such as X-Forwarded-For (its last entry is used) or X-Real-IP.
    pub client_ip_header: String,
    pub email_link_url: String,
    /// An extension Go lacks (docs/DEVIATIONS.md): the iOS apps, as
    /// `<team ID>.<bundle ID>`, that /.well-known/apple-app-site-association
    /// lists for passkeys (`webcredentials`). Empty serves no such route.
    pub apple_app_ids: Vec<String>,
}

impl Default for Config {
    fn default() -> Config {
        default_config()
    }
}

/// Go's `DefaultConfig`.
pub fn default_config() -> Config {
    Config {
        web_authn: None,
        origin_patterns: Some(vec![
            "http://localhost:*".into(),
            "http://127.0.0.1:*".into(),
            "http://[[]::1]:*".into(),
        ]),
        allow_any_origin: false,
        static_dir: String::new(),
        read_limit: DEFAULT_READ_LIMIT,
        outgoing_queue: DEFAULT_OUTGOING_QUEUE,
        history_page_size: DEFAULT_HISTORY_PAGE_SIZE,
        ping_interval: DEFAULT_PING_INTERVAL,
        ping_timeout: DEFAULT_PING_TIMEOUT,
        write_timeout: DEFAULT_WRITE_TIMEOUT,
        public_url: String::new(),
        max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        max_avatar_bytes: DEFAULT_MAX_AVATAR_BYTES,
        max_message_upload_bytes: DEFAULT_MAX_MESSAGE_UPLOADS,
        max_upload_storage_bytes: DEFAULT_MAX_UPLOAD_STORAGE,
        upload_dir: String::new(),
        upload_start_timeout: DEFAULT_UPLOAD_START_TIMEOUT,
        stream_keep_bytes: DEFAULT_STREAM_KEEP_BYTES,
        stream_max_bytes: DEFAULT_STREAM_MAX_BYTES,
        stream_max_duration: DEFAULT_STREAM_MAX_DURATION,
        store: None,
        disable_push: false,
        allow_insecure_push: false,
        vapid_private_key: String::new(),
        vapid_subject: String::new(),
        max_connections: 0,
        messages_per_minute: 0,
        max_listed_members: DEFAULT_MAX_LISTED_MEMBERS,
        max_private_rooms: 0,
        welcome: String::new(),
        roles: BTreeMap::new(),
        email_sender: None,
        client_ip_header: String::new(),
        email_link_url: String::new(),
        apple_app_ids: Vec::new(),
    }
}

impl Config {
    fn with_defaults(mut self) -> Config {
        let defaults = default_config();
        if self.origin_patterns.is_none() && !self.allow_any_origin {
            self.origin_patterns = defaults.origin_patterns;
        }
        if self.read_limit <= 0 {
            self.read_limit = defaults.read_limit;
        }
        if self.outgoing_queue == 0 {
            self.outgoing_queue = defaults.outgoing_queue;
        }
        if self.history_page_size == 0 {
            self.history_page_size = defaults.history_page_size;
        }
        if self.ping_interval.as_nanos() <= 0 {
            self.ping_interval = defaults.ping_interval;
        }
        if self.ping_timeout.as_nanos() <= 0 {
            self.ping_timeout = defaults.ping_timeout;
        }
        if self.write_timeout.as_nanos() <= 0 {
            self.write_timeout = defaults.write_timeout;
        }
        if self.max_upload_bytes <= 0 {
            self.max_upload_bytes = defaults.max_upload_bytes;
        }
        if self.max_avatar_bytes <= 0 {
            self.max_avatar_bytes = defaults.max_avatar_bytes;
        }
        if self.max_message_upload_bytes <= 0 {
            self.max_message_upload_bytes = defaults.max_message_upload_bytes;
        }
        if self.max_upload_storage_bytes <= 0 {
            self.max_upload_storage_bytes = defaults.max_upload_storage_bytes;
        }
        if self.upload_start_timeout.as_nanos() <= 0 {
            self.upload_start_timeout = defaults.upload_start_timeout;
        }
        if self.stream_keep_bytes == 0 {
            self.stream_keep_bytes = defaults.stream_keep_bytes;
        }
        if self.stream_max_bytes <= 0 {
            self.stream_max_bytes = defaults.stream_max_bytes;
        }
        if self.stream_max_duration.as_nanos() <= 0 {
            self.stream_max_duration = defaults.stream_max_duration;
        }
        self.public_url = self.public_url.trim_end_matches('/').to_owned();
        self
    }
}

/// Partitions the server's single append-only log (PROTOCOL.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    Room = 0,
    Message = 1,
    Reactions = 2,
    Membership = 3,
}

impl RecordKind {
    pub fn from_i64(n: i64) -> Option<RecordKind> {
        match n {
            0 => Some(RecordKind::Room),
            1 => Some(RecordKind::Message),
            2 => Some(RecordKind::Reactions),
            3 => Some(RecordKind::Membership),
            _ => None,
        }
    }
}

/// One committed change: `raw` is the complete wire object (including
/// log_id) as it was at commit time, kept as JSON, which history and
/// broadcasts send as is. Only redaction (§4.4) rewrites a record. A record
/// is referenced from the log of every room it belongs to, so a move
/// snapshot appears in both the source and destination room logs (§4.3.1).
#[derive(Clone, Debug)]
pub struct LogRecord {
    pub id: i64,
    pub kind: RecordKind,
    pub raw: Vec<u8>,
    /// The rooms whose logs hold the record.
    pub rooms: Vec<String>,
    /// The message_id of a message snapshot.
    pub message: String,
}

impl LogRecord {
    /// Encodes `value`. Values hold only JSON-decoded data and server-built
    /// strings, maps, and lists, so encoding cannot fail.
    pub fn new(id: i64, kind: RecordKind, value: &Object) -> LogRecord {
        LogRecord {
            id,
            kind,
            raw: encode_json(value).unwrap_or_default(),
            rooms: Vec::new(),
            message: String::new(),
        }
    }

    /// Decodes the record. Its ext keeps its values as raw JSON, so
    /// re-encoding the record keeps them exactly.
    pub fn value(&self) -> Object {
        decode_object(&self.raw).unwrap_or_default()
    }

    /// Replaces the record with `edit` applied to its decoded value.
    pub fn rewrite(&mut self, edit: impl FnOnce(&mut Object)) {
        let mut value = self.value();
        edit(&mut value);
        self.raw = encode_json(&value).unwrap_or_default();
    }
}

/// A rendered frame, shared by every connection it goes to.
pub type Frame = Arc<[u8]>;

/// Renders a frame once, for sending to many connections.
pub fn render<T: MarshalTo>(value: &T) -> Option<Frame> {
    encode_json(value).map(Frame::from)
}

/// The exact client liveness ping (§1); `pong_frame` answers it.
pub const PING_FRAME: &[u8] = br#"{"method":"ping"}"#;
pub fn pong_frame() -> Frame {
    Frame::from(br#"{"method":"pong"}"#.as_slice())
}

/// Keeps a sequence of protocol frames together in the writer's queue while
/// each frame is still written as its own WebSocket message, such as a
/// room_list result and the read cursors that follow it. A batch with
/// `close_reason` is the connection's last: the writer closes the connection
/// after writing it.
pub struct OutboundBatch {
    pub frames: Vec<Frame>,
    pub close_reason: String,
    stop: bool,
}

/// Go's closed `done` channel: set once, waited on with a timeout.
#[derive(Default)]
pub struct Done {
    flag: Mutex<bool>,
    cv: Condvar,
}

impl Done {
    pub fn set(&self) {
        *self.flag.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.cv.notify_all();
    }

    pub fn is_done(&self) -> bool {
        *self.flag.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Waits up to `d` and reports whether done was set.
    pub fn wait_timeout(&self, d: Duration) -> bool {
        let timeout = std::time::Duration::from_nanos(d.as_nanos().max(0) as u64);
        let guard = self.flag.lock().unwrap_or_else(|e| e.into_inner());
        let (guard, _) = self
            .cv
            .wait_timeout_while(guard, timeout, |done| !*done)
            .unwrap_or_else(|e| e.into_inner());
        *guard
    }

    pub fn wait(&self) {
        let guard = self.flag.lock().unwrap_or_else(|e| e.into_inner());
        let _unused = self
            .cv
            .wait_while(guard, |done| !*done)
            .unwrap_or_else(|e| e.into_inner());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientId(pub u64);

static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);

/// One WebSocket connection: what its threads read without the lock. The
/// identity and idle flag that Go guards with `s.mu` live in `State.clients`.
pub struct Client {
    pub id: ClientId,
    pub ws: ws::Conn,
    out: SyncSender<OutboundBatch>,
    pub done: Done,
    /// Prefixes the write, file, and stream URLs this connection mints.
    pub base_url: String,
    pub origin: String,
    /// Names the client address for the limits of all its connections.
    pub client_key: String,
    write_timeout: Duration,
    ping_interval: Duration,
    ping_timeout: Duration,
    /// Set once the final batch is queued; later frames are dropped.
    closing: AtomicBool,
    /// Set by the first liveness ping (§1); `last_frame` is when the latest
    /// frame arrived, in Unix nanoseconds.
    pinged: AtomicBool,
    last_frame: AtomicI64,
}

/// The lock-guarded half of a connection.
pub struct Conn {
    pub client: Arc<Client>,
    /// The connection's identity, `None` before authentication.
    pub user: Option<String>,
    /// Reports that nobody is attending the connection (§4.5): false until
    /// the connection says otherwise.
    pub idle: bool,
    /// The pending passkey ceremony, if any (§4.10).
    pub ceremony: Option<PasskeyCeremony>,
    /// The SHA-256 of the bearer token the connection signed in with, zero
    /// without one.
    pub token: [u8; 32],
    /// Limits the email proposals made on the connection (email.rs).
    pub email_sends: Option<Limiter>,
    /// The connection's latest proposal, which may have been dropped since.
    pub proposal: Option<ProposalId>,
}

impl Client {
    fn write_loop(self: Arc<Self>, out: Receiver<OutboundBatch>) {
        loop {
            let Ok(batch) = out.recv() else { return };
            if self.done.is_done() || batch.stop {
                return;
            }
            for payload in &batch.frames {
                if self.done.is_done() {
                    return;
                }
                if self
                    .ws
                    .write(ws::MessageType::Text, payload, self.write_timeout)
                    .is_err()
                {
                    self.stop_connection();
                    return;
                }
            }
            if !batch.close_reason.is_empty() {
                // The error frame explains the close; a close handshake would
                // wait on a peer that may not be reading.
                self.stop_connection();
                return;
            }
        }
    }

    /// Pings at the WebSocket level, which finds dead transports, and closes
    /// a connection whose client sent liveness pings (§1) and then fell
    /// silent for three intervals: its page is frozen or gone even if the
    /// socket is not. Three intervals leave room for background timer
    /// throttling.
    fn ping_loop(self: Arc<Self>) {
        let silence = self
            .ping_interval
            .mul(3)
            .checked_add(self.ping_timeout)
            .unwrap_or(self.ping_interval);
        loop {
            if self.done.wait_timeout(self.ping_interval) {
                return;
            }
            if self.pinged.load(Ordering::Relaxed) {
                let last = time::unix(0, self.last_frame.load(Ordering::Relaxed));
                if time::since(&last).as_nanos() > silence.as_nanos() {
                    self.stop_connection();
                    return;
                }
            }
            if self.ws.ping(self.ping_timeout).is_err() {
                self.stop_connection();
                return;
            }
        }
    }

    /// Answers a liveness ping, before authentication too (§1).
    pub fn pong(&self) {
        self.pinged.store(true, Ordering::Relaxed);
        self.enqueue_frame(pong_frame());
    }

    pub fn stop_connection(&self) {
        if !self.done.is_done() {
            self.done.set();
            self.ws.close_now();
            let _ = self.out.try_send(OutboundBatch {
                frames: Vec::new(),
                close_reason: String::new(),
                stop: true,
            });
        }
    }

    /// Sends an error about the connection as a whole, without id
    /// (PROTOCOL.md §1.1), after the frames already queued, then closes the
    /// connection.
    pub fn close_with_error(&self, e: RpcError) {
        let Some(payload) = render(&error_response(None, e.clone())) else {
            return;
        };
        if self.closing.swap(true, Ordering::SeqCst) {
            return;
        }
        let batch = OutboundBatch {
            frames: vec![payload],
            close_reason: e.message,
            stop: false,
        };
        if self.out.try_send(batch).is_err() {
            self.stop_connection();
        }
    }

    /// Reports whether a connection-level error is queued, after which the
    /// connection sends nothing more and runs none of its frames.
    pub fn is_closing(&self) -> bool {
        self.closing.load(Ordering::SeqCst)
    }

    pub fn enqueue<T: MarshalTo>(&self, value: &T) -> bool {
        match render(value) {
            Some(frame) => self.enqueue_frames(vec![frame]),
            None => {
                self.stop_connection();
                false
            }
        }
    }

    pub fn enqueue_frame(&self, frame: Frame) -> bool {
        self.enqueue_frames(vec![frame])
    }

    /// Queues frames as one batch. A frame rendered once for many
    /// connections is shared as is; the writer never modifies it.
    pub fn enqueue_frames(&self, frames: Vec<Frame>) -> bool {
        if frames.is_empty() {
            return true;
        }
        if self.closing.load(Ordering::Relaxed) || self.done.is_done() {
            return false;
        }
        match self.out.try_send(OutboundBatch {
            frames,
            close_reason: String::new(),
            stop: false,
        }) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                // A slow client cannot hold the room lock or the server's
                // broadcast path.
                self.stop_connection();
                false
            }
        }
    }

    pub fn send_result(&self, req: &Request, result: Json) {
        self.enqueue(&response(&req.id, result));
    }

    pub fn send_error(&self, req: &Request, err: RpcError) {
        self.enqueue(&error_response(Some(&req.id), err));
    }
}

/// The state Go guards with `s.mu`.
pub struct State {
    pub server: Weak<Server>,
    pub config: Arc<Config>,
    /// The single log_id sequence shared by every record kind and room.
    pub last_id: i64,
    pub rooms: BTreeMap<String, RoomState>,
    pub messages: BTreeMap<String, MessageState>,
    pub records: BTreeMap<i64, LogRecord>,
    pub clients: BTreeMap<ClientId, Conn>,
    /// Every live identity: connected guests and accounts.
    pub users: BTreeMap<String, UserState>,
    /// Every user_id ever assigned, lowercased, so none is reissued (§3.3).
    pub used_ids: BTreeSet<String>,
    /// The user_ids Config.roles names, lowercased, which are never assigned
    /// to a new identity unless already used.
    pub granted_ids: BTreeSet<String>,
    pub guest_number: u64,
    /// Numbers the user_<n> of new email accounts.
    pub account_number: u64,
    pub embed_number: u64,
    pub embeds: BTreeMap<String, EmbedState>,
    /// Each unused write token to its embed.
    pub writes: BTreeMap<String, String>,
    /// The finished uploads, oldest first, by (seq, embed_id), and their
    /// total size; the oldest leave when the total passes
    /// max_upload_storage_bytes.
    pub uploads: BTreeSet<(i64, String)>,
    pub upload_bytes: i64,
    pub upload_seq: i64,
    /// Holds upload content; a temporary one is removed on shutdown.
    pub upload_dir: String,
    pub temp_upload_dir: bool,
    /// Numbers the identities, so a timer can tell the user it was scheduled
    /// for from a later one with the same user_id.
    pub next_generation: u64,
    /// The state changed under the lock since it was last written to the
    /// store.
    pub dirty: DirtySet,
    pub store_closed: bool,
    pub stored_meta: StoredMeta,
    pub pushes: BTreeMap<String, PushRegistration>,
    pub closed: bool,
    /// Sign-in addresses to their accounts (§4.11).
    pub emails: BTreeMap<String, String>,
    /// Each registered passkey's credential ID to its account's user_id.
    pub credentials: BTreeMap<Vec<u8>, String>,
    /// Bearer token sign-ins by the SHA-256 of the token (§3.2).
    pub sessions: Sessions,
    /// `/invite-device` tokens by the SHA-256 of the token (devices.rs).
    pub devices: DeviceTokens,
    /// `/invite-bot` tokens by the SHA-256 of the token (bots.rs).
    pub bots: BotTokens,
    pub email: EmailState,
    /// The webpush key (§4.9); vapid_stored reports that it is the store's,
    /// rather than Config's, so a flush keeps it there.
    pub vapid: Option<Arc<VapidKey>>,
    pub vapid_stored: bool,
    /// How long badge pushes wait to coalesce the changes to one user's
    /// unread count; badges counts the waits in progress.
    pub badge_delay: Duration,
    pub badges: WaitGroup,
    pub push: Arc<PushDeliverer>,
}

/// The Apron server. Go's `Server`, shared by the HTTP handlers, the
/// connection threads, and timers as an `Arc`.
pub struct Server {
    pub config: Arc<Config>,
    state: Mutex<State>,
    store: Arc<dyn Store>,
    store_writes: Mutex<Option<SyncSender<Vec<Entry>>>>,
    store_done: Mutex<Option<thread::JoinHandle<()>>>,
    pub(crate) connections: WaitGroup,
    /// Email deliveries in progress, which `shutdown` awaits.
    pub(crate) mailing: WaitGroup,
    /// Pending badge pushes and push deliveries, which `shutdown` awaits.
    pub(crate) badges: WaitGroup,
    pub(crate) push: Arc<PushDeliverer>,
    /// Set by `shutdown`; ends the sweep of expired registrations.
    pub(crate) stopped: Arc<Done>,
    pub(crate) ops: BTreeMap<&'static str, Operation>,
}

/// The lock on `State`. Dropping it writes the changes made under the lock
/// through to the store, Go's `s.unlock()`.
pub struct Locked<'a> {
    server: &'a Server,
    guard: MutexGuard<'a, State>,
}

impl Deref for Locked<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        &self.guard
    }
}

impl DerefMut for Locked<'_> {
    fn deref_mut(&mut self) -> &mut State {
        &mut self.guard
    }
}

impl Drop for Locked<'_> {
    fn drop(&mut self) {
        self.server.flush_locked(&mut self.guard);
    }
}

/// Bounds the batches waiting for the store writer; beyond it, requests
/// wait for the store.
pub const STORE_QUEUE: usize = 1024;

/// The seeded room that requests without room_id address (§3.5.1, §4.3) and
/// that new guests join.
pub const DEFAULT_ROOM_ID: &str = "general";

/// A request handler. When it succeeds and has already queued its own reply,
/// it reports replied. Handlers whose results describe state queue them
/// while holding the lock, so that a result reflects every notification sent
/// before it on the connection, and after the notifications the request
/// causes, which precede its result (§1).
pub type Operation = fn(&Arc<Server>, &Arc<Client>, &Request) -> Result<(Json, bool), RpcError>;

fn operations(config: &Config) -> BTreeMap<&'static str, Operation> {
    let mut ops: BTreeMap<&'static str, Operation> = BTreeMap::new();
    ops.insert("me", Server::update_profile);
    #[cfg(test)]
    ops.insert("test_panic", Server::test_panic);
    ops.insert("message", Server::save_message);
    ops.insert("command", Server::command);
    ops.insert("history", Server::history);
    ops.insert("room_set", Server::set_room);
    ops.insert("room_list", Server::list_rooms);
    ops.insert("room_join", Server::join_room);
    ops.insert("room_leave", Server::leave_room);
    ops.insert("reactions", Server::react);
    ops.insert("activity", Server::activity);
    ops.insert("status", Server::status);
    if !config.disable_push {
        ops.insert("push_register", Server::register_push);
        ops.insert("push_unregister", Server::unregister_push);
    }
    ops
}

/// The operations that change nothing, so their results are not kept for
/// deduplication (§1.2): a duplicate after the original finished runs again.
fn read_only_op(method: &str) -> bool {
    matches!(method, "history" | "room_list")
}

/// Starts a server with the state in `config.store`, or an empty memory
/// store when it is `None`.
pub fn open(config: Config) -> Result<Arc<Server>, store::StoreError> {
    let mut config = config.with_defaults();
    let mut vapid = None;
    if !config.vapid_private_key.is_empty() {
        vapid = Some(Arc::new(VapidKey::parse(&config.vapid_private_key)?));
    }
    let mut subject = config.vapid_subject.clone();
    if subject.is_empty() && config.public_url.starts_with("https://") {
        subject = config.public_url.clone();
    }
    let push = PushDeliverer::new(config.allow_insecure_push, subject);
    let badges = WaitGroup::new();
    let store: Arc<dyn Store> = match config.store.take() {
        Some(store) => store,
        None => Arc::new(store::Memory::new()),
    };
    let config = Arc::new(config);
    let (tx, rx) = sync_channel::<Vec<Entry>>(STORE_QUEUE);
    let writer_store = store.clone();
    let writer = thread::spawn(move || Server::write_store(writer_store, rx));
    let server = Arc::new_cyclic(|weak: &Weak<Server>| {
        let mut granted_ids = BTreeSet::new();
        for holders in config.roles.values() {
            for holder in holders {
                granted_ids.insert(holder.to_lowercase());
            }
        }
        Server {
            config: config.clone(),
            state: Mutex::new(State {
                server: weak.clone(),
                config: config.clone(),
                last_id: 0,
                rooms: BTreeMap::new(),
                messages: BTreeMap::new(),
                records: BTreeMap::new(),
                clients: BTreeMap::new(),
                users: BTreeMap::new(),
                used_ids: BTreeSet::new(),
                granted_ids,
                guest_number: 0,
                account_number: 0,
                embed_number: 0,
                embeds: BTreeMap::new(),
                writes: BTreeMap::new(),
                uploads: BTreeSet::new(),
                upload_bytes: 0,
                upload_seq: 0,
                upload_dir: String::new(),
                temp_upload_dir: false,
                next_generation: 1,
                dirty: DirtySet::default(),
                store_closed: false,
                stored_meta: StoredMeta::default(),
                pushes: BTreeMap::new(),
                closed: false,
                emails: BTreeMap::new(),
                credentials: BTreeMap::new(),
                sessions: Sessions::default(),
                devices: DeviceTokens::default(),
                bots: BotTokens::default(),
                email: EmailState::default(),
                vapid,
                vapid_stored: false,
                badge_delay: super::unread::BADGE_DELAY,
                badges: badges.clone(),
                push: push.clone(),
            }),
            store,
            store_writes: Mutex::new(Some(tx)),
            store_done: Mutex::new(Some(writer)),
            connections: WaitGroup::new(),
            mailing: WaitGroup::new(),
            badges,
            push,
            stopped: Arc::new(Done::default()),
            ops: operations(&config),
        }
    });
    {
        let mut st = server.lock();
        server.open_upload_dir(&mut st);
        let files = match server.restore_locked(&mut st) {
            Ok(files) => files,
            Err(e) => {
                st.store_closed = true;
                drop(st);
                server.close_store_writer();
                return Err(e);
            }
        };
        if let Some(vapid) = &st.vapid {
            let _ = server.push.vapid.set(vapid.clone());
        }
        if !st.rooms.contains_key(DEFAULT_ROOM_ID) {
            // The seeded default room has a logged creation record like any
            // other room, so its history_log_id is never null.
            st.commit_room_locked(DEFAULT_ROOM_ID, None, false, obj! {"title" => "General"});
        }
        st.remove_stale_uploads(&files);
    }
    server.sweep_pushes();
    Ok(server)
}

/// Serves a built frontend without directory listings or dotfiles.
struct StaticFs(http::Dir);

impl http::FileSystem for StaticFs {
    fn open(&self, name: &str) -> std::io::Result<Box<dyn http::File>> {
        let not_exist = || std::io::Error::from(std::io::ErrorKind::NotFound);
        if rust_stdlib::path::clean(name)
            .split('/')
            .any(|part| part.starts_with('.'))
        {
            return Err(not_exist());
        }
        let mut file = self.0.open(name)?;
        if file.stat().is_ok_and(|info| info.is_dir()) {
            // A directory is served only through its index.html.
            let index = format!("{}/index.html", name.strip_suffix('/').unwrap_or(name));
            match self.0.open(&index) {
                Ok(mut index) => {
                    let _ = index.close();
                }
                Err(_) => {
                    let _ = file.close();
                    return Err(not_exist());
                }
            }
        }
        Ok(file)
    }
}

impl Server {
    /// Takes the state lock. Dropping the guard flushes to the store.
    pub fn lock(&self) -> Locked<'_> {
        Locked {
            server: self,
            guard: self.state.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }

    /// Returns the HTTP handler serving /ws, /healthz, the upload, file, and
    /// stream endpoints, and StaticDir.
    pub fn handler(self: &Arc<Self>) -> Arc<dyn Handler> {
        let mux = ServeMux::new();
        let server = self.clone();
        mux.handle_func("/ws", move |w, r| server.handle_web_socket(w, r))
            .expect("constant pattern");
        let server = self.clone();
        mux.handle_func("/healthz", move |w, r| server.handle_health(w, r))
            .expect("constant pattern");
        let server = self.clone();
        mux.handle_func(super::embeds::WRITE_PATH, move |w, r| {
            server.handle_write(w, r)
        })
        .expect("constant pattern");
        let server = self.clone();
        mux.handle_func(super::embeds::FILE_PATH, move |w, r| {
            server.handle_file(w, r)
        })
        .expect("constant pattern");
        let server = self.clone();
        mux.handle_func(super::embeds::STREAM_PATH, move |w, r| {
            server.handle_stream(w, r)
        })
        .expect("constant pattern");
        if !self.config.apple_app_ids.is_empty() {
            let apps: Vec<Json> = self
                .config
                .apple_app_ids
                .iter()
                .map(|id| Json::from(id.clone()))
                .collect();
            let body = encode_json(&obj! {"webcredentials" => obj! {"apps" => Json::Array(apps)}})
                .expect("strings encode");
            mux.handle_func(
                "GET /.well-known/apple-app-site-association",
                move |w, _| {
                    w.header().set("Content-Type", "application/json");
                    let _ = std::io::Write::write_all(w, &body);
                },
            )
            .expect("constant pattern");
        }
        if !self.config.static_dir.is_empty() {
            let root = rust_stdlib::path::filepath::clean(&self.config.static_dir);
            mux.handle("/", http::file_server(Arc::new(StaticFs(http::Dir(root)))))
                .expect("constant pattern");
        } else {
            mux.handle_func("/", |w, r| http::not_found(w, r))
                .expect("constant pattern");
        }
        Arc::new(mux)
    }

    fn handle_health(&self, w: &mut dyn ResponseWriter, _r: &mut HttpRequest) {
        let closed = self.lock().closed;
        w.header().set("Content-Type", "application/json");
        if closed {
            w.write_header(http::STATUS_SERVICE_UNAVAILABLE);
        }
        let _ = std::io::Write::write_all(w, br#"{"status":"ok"}"#);
    }

    /// Tells active WebSockets to retry later, closes them, and waits for
    /// the connection handlers to finish.
    pub fn shutdown(self: &Arc<Self>, ctx: &Context) -> Result<(), rust_stdlib::context::Error> {
        {
            let mut st = self.lock();
            if !st.closed {
                st.closed = true;
                self.stopped.set();
                for conn in st.clients.values() {
                    conn.client.close_with_error(RpcError::with_data(
                        CODE_RETRY_AFTER,
                        "Server is shutting down; reconnect shortly",
                        obj! {"retry_after" => 5i64},
                    ));
                }
                for e in st.embeds.values() {
                    e.end_stream();
                }
                // Pending badge pushes would only be dropped once they fire,
                // and the ends of timed mutes and coalesced statuses would
                // find the server closed: none is kept waiting past it.
                let ids: Vec<String> = st.users.keys().cloned().collect();
                for id in ids {
                    st.stop_timers_locked(&id);
                }
                if st.temp_upload_dir {
                    let _ = rust_stdlib::os::remove_all(&st.upload_dir);
                }
            }
        }
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let server = self.clone();
        thread::spawn(move || {
            server.connections.wait();
            server.badges.wait();
            server.push.wait();
            server.mailing.wait();
            {
                let mut st = server.lock();
                server.close_store_locked(&mut st);
            }
            let _ = tx.send(());
        });
        loop {
            if let Some(err) = ctx.err() {
                return Err(err);
            }
            if rx.recv_timeout(std::time::Duration::from_millis(5)).is_ok() {
                return Ok(());
            }
        }
    }

    fn handle_web_socket(self: &Arc<Self>, w: &mut dyn ResponseWriter, r: &mut HttpRequest) {
        if self.lock().closed {
            http::http_error(
                w,
                "server is shutting down",
                http::STATUS_SERVICE_UNAVAILABLE,
            );
            return;
        }
        self.connections.add(1);
        let _finished = ConnectionDone(&self.connections);

        let options = if self.config.allow_any_origin {
            ws::AcceptOptions {
                insecure_skip_verify: true,
                origin_patterns: Vec::new(),
            }
        } else {
            ws::AcceptOptions {
                insecure_skip_verify: false,
                origin_patterns: self.config.origin_patterns.clone().unwrap_or_default(),
            }
        };
        let Ok(socket) = ws::accept(w, r, &options) else {
            return;
        };
        socket.set_read_limit(self.config.read_limit);

        let (out, rx) = sync_channel(self.config.outgoing_queue);
        let client = Arc::new(Client {
            id: ClientId(NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed)),
            ws: socket,
            out,
            done: Done::default(),
            base_url: self.base_url(r),
            origin: r.header.get("Origin").unwrap_or("").to_owned(),
            client_key: super::email::client_key(&self.client_ip(r)),
            write_timeout: self.config.write_timeout,
            ping_interval: self.config.ping_interval,
            ping_timeout: self.config.ping_timeout,
            closing: AtomicBool::new(false),
            pinged: AtomicBool::new(false),
            last_frame: AtomicI64::new(time::now().unix_nano()),
        });
        thread::spawn({
            let client = client.clone();
            move || client.write_loop(rx)
        });
        thread::spawn({
            let client = client.clone();
            move || client.ping_loop()
        });
        let _detach = Detach {
            server: self,
            client: &client,
        };
        {
            let mut st = self.lock();
            if st.closed {
                return;
            }
            if self.config.max_connections > 0 && st.clients.len() >= self.config.max_connections {
                // An error about the connection as a whole omits id (§1.1).
                client.enqueue(&obj! {"method" => "server", "params" => st.server_params()});
                client.close_with_error(RpcError::with_data(
                    CODE_RETRY_AFTER,
                    "Server at capacity; try again shortly",
                    obj! {"retry_after" => RETRY_AFTER_SECONDS},
                ));
                drop(st);
                client.done.wait();
                return;
            }
            st.clients.insert(
                client.id,
                Conn {
                    client: client.clone(),
                    user: None,
                    idle: false,
                    ceremony: None,
                    token: [0; 32],
                    email_sends: None,
                    proposal: None,
                },
            );
            // The server announcement is queued before the reader starts
            // accepting auth.
            client.enqueue(&obj! {"method" => "server", "params" => st.server_params()});
        }

        while let Ok((message_type, payload)) = client.ws.read() {
            if message_type != ws::MessageType::Text {
                let _ = client
                    .ws
                    .close(ws::STATUS_UNSUPPORTED_DATA, "text frames required");
                break;
            }
            client
                .last_frame
                .store(time::now().unix_nano(), Ordering::Relaxed);
            // The liveness ping has fixed bytes, answered without parsing (§1).
            if payload == PING_FRAME {
                client.pong();
                continue;
            }
            // Frames are processed in order, each to completion before the
            // next is read, which makes auth a barrier (§3.2).
            self.process_frame(&client, &payload);
        }
    }

    /// The address of the client that opened a request: with
    /// `client_ip_header`, the last entry across every line of that header,
    /// which the proxy in front added itself, without a port; else, or when
    /// that is not an IP address, the connection's own address.
    pub(crate) fn client_ip(&self, r: &HttpRequest) -> String {
        let remote = match rust_stdlib::net::split_host_port(&r.remote_addr) {
            Ok((host, _)) => host,
            Err(_) => r.remote_addr.clone(),
        };
        let header = &self.config.client_ip_header;
        if header.is_empty() {
            return remote;
        }
        let joined = r.header.values(header).join(",");
        let mut entry = joined.rsplit(',').next().unwrap_or("").trim().to_owned();
        if let Ok((host, _)) = rust_stdlib::net::split_host_port(&entry) {
            entry = host;
        }
        let entry = entry.strip_prefix('[').unwrap_or(&entry);
        let entry = entry.strip_suffix(']').unwrap_or(entry);
        if rust_stdlib::net::parse_ip(entry).is_none() {
            return remote;
        }
        entry.to_owned()
    }

    /// The configured public URL or the scheme and host the WebSocket
    /// request arrived on.
    fn base_url(&self, r: &HttpRequest) -> String {
        if !self.config.public_url.is_empty() {
            return self.config.public_url.clone();
        }
        let scheme = if r.tls.is_some() { "https" } else { "http" };
        format!("{scheme}://{}", r.host)
    }

    fn write_store(store: Arc<dyn Store>, rx: Receiver<Vec<Entry>>) {
        for batch in rx {
            if let Err(e) = store.apply(&batch) {
                slog::error(
                    "cannot write to the store",
                    &["error".into(), slog::Value::from(e.to_string()).into()],
                );
            }
        }
    }

    /// Queues the marked changes as one batch for the store writer.
    pub(crate) fn flush_locked(&self, st: &mut State) {
        if st.store_closed {
            st.dirty = DirtySet::default();
            return;
        }
        let mut batch = st.entries_locked();
        let meta = st.meta_locked();
        if meta != st.stored_meta {
            st.stored_meta = meta.clone();
            if let Some(value) = encode_json(&meta) {
                batch.push(Entry::put(super::persist::ENTRY_META, "counters", value));
            }
        }
        st.dirty = DirtySet::default();
        if !batch.is_empty() {
            if let Some(tx) = self
                .store_writes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
            {
                let _ = tx.send(batch);
            }
        }
    }

    fn close_store_writer(&self) {
        self.store_writes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(writer) = self
            .store_done
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = writer.join();
        }
    }

    /// Writes the last changes and closes the store.
    pub(crate) fn close_store_locked(&self, st: &mut State) {
        if st.store_closed {
            return;
        }
        self.flush_locked(st);
        st.store_closed = true;
        self.close_store_writer();
        if let Err(e) = self.store.close() {
            slog::error(
                "cannot close the store",
                &["error".into(), slog::Value::from(e.to_string()).into()],
            );
        }
    }

    pub(crate) fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    pub(crate) fn process_frame(self: &Arc<Self>, c: &Arc<Client>, payload: &[u8]) {
        // Once a connection-level error is queued, any reply would be
        // dropped, and the connection may have lost its sign-in: its later
        // frames are ignored rather than run (docs/DEVIATIONS.md).
        if c.is_closing() {
            return;
        }
        let (req, parse_err) = parse_request(payload);
        if let Some(parse_err) = parse_err {
            if notification_only(&req.method) {
                // The id of a notification method may be ignored, and the
                // frame handled as a notification (§1.1): it is never
                // answered, even with invalid params, and a ping is still a
                // ping.
                if req.method == "ping" {
                    c.pong();
                }
                return;
            }
            if parse_err.code == CODE_INVALID_PARAMS && !req.has_id {
                return;
            }
            if req.has_id {
                c.send_error(&req, parse_err);
            } else {
                c.enqueue(&error_response(None, parse_err));
            }
            return;
        }

        // parse_request drops the id of a notification method, which a
        // server may ignore, handling the frame as a notification (§1.1):
        // activity and ping are never answered.
        if req.method == "ping" {
            c.pong();
            return;
        }
        // Clients send every other method they send as a request, with an
        // id. A server may ignore a request method sent without one (§1.1),
        // and this one does, whatever its method and params.
        if !req.has_id && !notification_only(&req.method) {
            return;
        }
        // auth is a barrier (§3.2): the read loop processes one frame at a
        // time, so auth finishes before any later frame on the connection is
        // read.
        if req.method == "auth" {
            if let Err(err) = self.authenticate(c, &req) {
                c.send_error(&req, err);
            }
            return;
        }

        let (user_id, op, entry) = {
            let mut st = self.lock();
            let Some(user_id) = st.client_user(c) else {
                drop(st);
                if req.has_id {
                    c.send_error(
                        &req,
                        RpcError::new(CODE_DENIED, "Sign in before sending requests"),
                    );
                }
                return;
            };
            let Some(op) = self.ops.get(req.method.as_str()).copied() else {
                drop(st);
                if req.has_id {
                    c.send_error(
                        &req,
                        RpcError::new(
                            CODE_UNSUPPORTED,
                            format!("Unsupported method {}", quote(&req.method)),
                        ),
                    );
                }
                return;
            };
            // Requests deduplicate per user (§1.2): a duplicate waits for the
            // original, even one running on another connection, and replies
            // with its outcome, brought up to date with the current state.
            let mut entry = None;
            if req.has_id {
                let fingerprint = sha256::sum256(request_fingerprint(&req).as_bytes());
                let prior = st.users.get(&user_id).and_then(|u| u.dedup.get(&req.id));
                if let Some(prior) = prior {
                    drop(st);
                    if prior.fingerprint != fingerprint {
                        c.send_error(
                            &req,
                            invalid_params(format!(
                                "Request id {} was already used for another operation",
                                quote(&req.id)
                            )),
                        );
                        return;
                    }
                    match prior.wait() {
                        Err(err) => c.send_error(&req, err),
                        Ok(result) => {
                            let st = self.lock();
                            let result = st.current_result_locked(&user_id, &req.method, result);
                            c.send_result(&req, result);
                        }
                    }
                    return;
                }
                let new_entry = Arc::new(DedupEntry::new(fingerprint));
                if let Some(u) = st.users.get_mut(&user_id) {
                    u.dedup.put(&req.id, new_entry.clone());
                }
                entry = Some(new_entry);
            }
            (user_id, op, entry)
        };

        let _abandon = entry.as_ref().map(|entry| AbandonDedup {
            server: self,
            user_id: &user_id,
            req_id: &req.id,
            entry,
        });
        let outcome = op(self, c, &req);
        if req.has_id {
            match &outcome {
                Ok((_, true)) => {}
                Ok((result, false)) => c.send_result(&req, result.clone()),
                Err(err) => c.send_error(&req, err.clone()),
            }
        }
        if let Some(entry) = &entry {
            let mut st = self.lock();
            let failed = outcome.is_err();
            if failed || read_only_op(&req.method) {
                // Failed operations are not cached, and neither are reads,
                // whose results can be large and which are safe to run
                // again: a retry executes again. Concurrent duplicates still
                // share the outcome.
                if let Some(u) = st.users.get_mut(&user_id) {
                    u.dedup.remove(&req.id, entry);
                }
            }
            entry.finish(outcome.map(|(result, _)| result));
        }
    }
}

impl Server {
    /// Panics after the request has been registered for deduplication, with
    /// the state lock held, for the cleanup test.
    #[cfg(test)]
    fn test_panic(
        self: &Arc<Self>,
        _c: &Arc<Client>,
        _req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let _st = self.lock();
        panic!("test_panic");
    }
}

/// Stops a connection and removes it from the state when its handler
/// returns or unwinds, as Go's deferred cleanup in handleWebSocket does, so
/// a panicking operation leaves no connection behind.
struct Detach<'a> {
    server: &'a Arc<Server>,
    client: &'a Arc<Client>,
}

impl Drop for Detach<'_> {
    fn drop(&mut self) {
        self.client.stop_connection();
        let mut st = self.server.lock();
        if let Some(conn) = st.clients.remove(&self.client.id) {
            st.detach_locked(conn);
        }
    }
}

/// Fails a deduplicated request whose operation unwound before finishing,
/// so the duplicates waiting on it (§1.2) answer instead of waiting forever,
/// and a retry runs again.
struct AbandonDedup<'a> {
    server: &'a Arc<Server>,
    user_id: &'a str,
    req_id: &'a str,
    entry: &'a Arc<DedupEntry>,
}

impl Drop for AbandonDedup<'_> {
    fn drop(&mut self) {
        if self.entry.is_closed() {
            return;
        }
        if let Some(u) = self.server.lock().users.get_mut(self.user_id) {
            u.dedup.remove(self.req_id, self.entry);
        }
        self.entry
            .finish(Err(RpcError::new(CODE_INTERNAL_ERROR, "Internal error")));
    }
}

/// Counts a connection handler down when it returns, on every path.
struct ConnectionDone<'a>(&'a WaitGroup);

impl Drop for ConnectionDone<'_> {
    fn drop(&mut self) {
        self.0.done();
    }
}

impl State {
    pub fn client_user(&self, c: &Client) -> Option<String> {
        self.clients.get(&c.id).and_then(|conn| conn.user.clone())
    }

    /// Queues a frame to every connection of the user.
    pub fn send_to_user(&self, user_id: &str, frame: &Frame) {
        self.send_frames_to_user(user_id, vec![frame.clone()]);
    }

    pub fn send_frames_to_user(&self, user_id: &str, frames: Vec<Frame>) {
        let Some(u) = self.users.get(user_id) else {
            return;
        };
        for id in &u.clients {
            if let Some(conn) = self.clients.get(id) {
                conn.client.enqueue_frames(frames.clone());
            }
        }
    }

    /// The `server` frame (PROTOCOL.md §3.1).
    pub fn server_params(&self) -> Object {
        let mut auth_schemes: Vec<String> = Vec::new();
        if self.config.web_authn.is_some() {
            auth_schemes.push("webauthn".into());
        }
        if self.config.email_sender.is_some() {
            auth_schemes.push("email".into());
        }
        if !auth_schemes.is_empty() {
            auth_schemes.push("token".into());
        }
        auth_schemes.push("guest".into());
        // signup (§3.2) lists the schemes that can create an account: every
        // one but token, which only resumes one.
        let signup: Vec<String> = auth_schemes
            .iter()
            .filter(|s| *s != "token")
            .cloned()
            .collect();
        let mut capabilities: Vec<String> = [
            "history",
            "edit",
            "rooms",
            "reactions",
            "activity",
            "embed:upload",
            "embed:stream",
            "command",
            "status",
            "ext",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let mut params = obj! {
            "apron" => 9i64,
            "agent" => "apron-rust/9",
            "auth" => auth_schemes.clone(),
            "ping" => (self.config.ping_interval.as_nanos() / time::SECOND.as_nanos()).max(1),
            // The optional statuses accepted with `me` (§4.5); online and ""
            // always are, and are not listed.
            "status" => optional_statuses(),
        };
        if !self.config.disable_push {
            params.insert("push".into(), super::push::server_push_params(self).into());
        }
        if !self.config.welcome.is_empty() {
            params.insert("welcome".into(), self.config.welcome.as_str().into());
        }
        if self.config.max_private_rooms > 0 {
            // ext:settings, the extension apron-web defines (its EXT.md §3):
            // private_rooms is a number, where its other keys are booleans
            // that an absent key makes true, as they are here.
            capabilities.push("ext:settings".into());
            params.insert(
                "ext".into(),
                obj! {"settings" => obj! {"private_rooms" => self.config.max_private_rooms}}.into(),
            );
        }
        params.insert("capabilities".into(), capabilities.into());
        if signup != auth_schemes {
            params.insert("signup".into(), signup.into());
        }
        params
    }

    /// Brings a duplicate's result up to date (§1.2): `me` answers with the
    /// current profile, and a message result lists only the write URLs that
    /// are still unused. Other results name what the request made, which
    /// does not change.
    pub fn current_result_locked(&self, user_id: &str, method: &str, result: Json) -> Json {
        match method {
            "me" => match self.users.get(user_id) {
                Some(u) => obj! {"you" => u.you()}.into(),
                None => result,
            },
            "message" | "command" => {
                let Json::Object(original) = &result else {
                    return result;
                };
                if original.get("embeds").is_none() {
                    return result;
                }
                let mut current = original.clone();
                let writes: Vec<Json> = original
                    .get("embeds")
                    .map(|e| e.as_list().to_vec())
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|written| {
                        let id = written
                            .as_object()
                            .and_then(|w| w.get("embed_id"))
                            .and_then(Json::as_str)
                            .unwrap_or("");
                        self.embeds
                            .get(id)
                            .is_some_and(|e| !e.started && self.writes.get(&e.token) == Some(&e.id))
                    })
                    .collect();
                if writes.is_empty() {
                    current.remove("embeds");
                } else {
                    current.insert("embeds".into(), writes.into());
                }
                current.into()
            }
            _ => result,
        }
    }

    /// Returns the next log_id in the server-wide sequence: the commit time
    /// in milliseconds, or the previous log_id + 1.
    pub fn next_id_locked(&mut self) -> i64 {
        self.last_id = time::now().unix_milli().max(self.last_id + 1);
        self.last_id
    }

    /// Adds a committed record to the log of each room it belongs to.
    pub fn append_locked(&mut self, mut record: LogRecord, rooms: &[String]) {
        for room_id in rooms {
            if let Some(r) = self.rooms.get_mut(room_id) {
                r.log.push(record.id);
                r.latest_id = record.id;
                record.rooms.push(room_id.clone());
                self.dirty.rooms.insert(room_id.clone());
            }
        }
        self.dirty.records.insert(record.id);
        self.records.insert(record.id, record);
    }

    pub fn touch_record(&mut self, id: i64) {
        self.dirty.records.insert(id);
    }
    pub fn touch_room(&mut self, id: &str) {
        self.dirty.rooms.insert(id.to_owned());
    }
    pub fn touch_message(&mut self, id: &str) {
        self.dirty.messages.insert(id.to_owned());
    }
    pub fn touch_user(&mut self, id: &str) {
        self.dirty.users.insert(id.to_owned());
    }
    pub fn touch_embed(&mut self, id: &str) {
        self.dirty.embeds.insert(id.to_owned());
    }
    pub fn touch_session(&mut self, key: [u8; 32]) {
        self.dirty.sessions.insert(key);
    }
    pub fn touch_used_id(&mut self, lowercased: &str) {
        self.dirty.used_ids.push(lowercased.to_owned());
    }

    /// The server, for scheduling timers that take the lock again.
    pub fn server(&self) -> Option<Arc<Server>> {
        self.server.upgrade()
    }
}
