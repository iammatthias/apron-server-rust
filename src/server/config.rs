//! The server's configuration, its defaults, and the fixed bounds it applies.

use std::collections::BTreeMap;
use std::sync::Arc;

use rust_stdlib::time::Duration;

use super::custom_emoji::{DEFAULT_MAX_EMOJI, DEFAULT_MAX_EMOJI_BYTES};
use super::email::EmailSender;
use super::limits::Limits;
use super::media_types::UPLOAD_TYPES;
use super::metadata::ServerMetadata;
use super::protocol::*;
use super::push::PushHosts;
use super::unfurl::{self};
use super::webauthn::WebAuthn;
use crate::store::Store;

pub const DEFAULT_OUTGOING_QUEUE: usize = 128;
/// apron-server-cloudflare's history_default_limit and history_max_limit.
pub const DEFAULT_HISTORY_PAGE_SIZE: usize = 20;
pub const MAX_HISTORY_PAGE_SIZE: usize = 50;
pub const DEFAULT_PING_INTERVAL: Duration = Duration::from_secs(30);
pub const DEFAULT_PING_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// apron-server-cloudflare's maxFileBytes and maxAvatarBytes.
pub const DEFAULT_MAX_UPLOAD_BYTES: i64 = 5 << 20;
pub const DEFAULT_MAX_AVATAR_BYTES: i64 = 256 << 10;
pub const DEFAULT_MAX_MESSAGE_UPLOADS: i64 = 20 << 20;
pub const DEFAULT_MAX_UPLOAD_STORAGE: i64 = 1000 << 20;
/// Bounds one history reply, its envelope included (apron-server-
/// cloudflare's history_max_response_bytes); a page always holds at least
/// one record.
pub const MAX_HISTORY_REPLY_BYTES: usize = 256 << 10;
pub const DEFAULT_UPLOAD_START_TIMEOUT: Duration = Duration::from_mins(5);
pub const DEFAULT_STREAM_KEEP_BYTES: usize = 64 << 10;
pub const DEFAULT_STREAM_MAX_BYTES: i64 = 16 << 20;
pub const DEFAULT_STREAM_MAX_DURATION: Duration = Duration::from_hours(1);
pub const DEFAULT_MAX_LISTED_MEMBERS: usize = 1000;
/// The delay suggested by connection-level retry_after errors (capacity and
/// shutdown).
pub const RETRY_AFTER_SECONDS: i64 = 60;
/// apron-server-cloudflare's open_connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 100;
/// Refuses a connection whose client address the proxy did not give.
pub const UNTRUSTED_ADDRESS: &str = "Trusted client address unavailable";

/// How long a connection may stay without signing in (Config.auth_timeout).
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(30);

/// Controls the HTTP and WebSocket behavior of a Server.
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
    /// Bounds on each frame a client sends (FrameLimits).
    pub frame: FrameLimits,
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
    /// The types an attachment may be, as `ext:media` patterns: a MIME
    /// type, `type/*`, or `*/*`; empty takes UPLOAD_TYPES.
    pub upload_types: Vec<String>,
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
    /// The push services endpoints may name (`--push.hosts`), checked when
    /// registering and again before each push.
    pub push_hosts: PushHosts,
    /// How long a message's wake waits before it pushes (`--push.delay`);
    /// zero pushes at once.
    pub push_delay: Duration,
    /// The server's VAPID key for webpush (§4.9), the P-256 scalar in
    /// base64url; empty uses the one kept in the store, or generates one.
    pub vapid_private_key: String,
    /// The contact push services may use, a mailto: or https: URL, sent in
    /// VAPID tokens. Empty uses public_url, if any.
    pub vapid_subject: String,
    /// Bounds concurrent WebSockets; 0 is unlimited.
    pub max_connections: usize,
    /// The per-client limits (limits.rs), apron-server-cloudflare's by
    /// default.
    pub limits: Limits,
    /// Bounds a room's members in room_list and room_update joined; a larger
    /// room lists its most recently active members and member_count
    /// (§4.2.1). 0 is unlimited.
    pub max_listed_members: usize,
    /// Bounds the top-level private rooms (§4.2.4) one user is in at once.
    /// 0 is unlimited.
    pub max_private_rooms: usize,
    /// server.welcome (§3.2): Markdown shown on the sign-in screen.
    pub welcome: String,
    /// The most custom emoji the catalog holds (ext:emoji), and the largest
    /// image of one.
    pub max_emoji: usize,
    pub max_emoji_bytes: i64,
    /// The server frame's `title`, `description` and `avatar` (§3.1)
    /// unless an admin's `/server` sets them.
    pub server: ServerMetadata,
    /// Grants server roles (§3.3), such as "admin", to accounts: each role
    /// lists the user_ids or email addresses that hold it.
    pub roles: BTreeMap<String, Vec<String>>,
    /// The SHA-256 of the token that signs in as the user `admin`
    /// (admin.rs); `None` disables it.
    pub admin_token: Option<[u8; 32]>,
    /// Enables email sign-in (§4.11) and delivers its codes; `None`
    /// disables it. `LogEmailSender` logs codes, for development.
    pub email_sender: Option<Arc<dyn EmailSender>>,
    /// Names the request header a reverse proxy puts the client's address
    /// in, such as X-Forwarded-For (its last entry is used) or X-Real-IP.
    pub client_ip_header: String,
    pub email_link_url: String,
    /// The iOS apps, as
    /// `<team ID>.<bundle ID>`, that /.well-known/apple-app-site-association
    /// lists for passkeys (`webcredentials`). Empty serves no such route.
    pub apple_app_ids: Vec<String>,
    /// Unfurls the links of
    /// messages into `link` embeds with og (§4.8.1).
    pub unfurl: bool,
    /// Lets unfurls reach internal addresses on any port, for tests.
    pub unfurl_allow_internal: bool,
    /// How long an unfurl waits for its pages; FETCH_TIMEOUT unless a test
    /// shortens it.
    pub unfurl_timeout: Duration,
    /// How long a connection may stay without signing in before it is
    /// closed with 1008.
    pub auth_timeout: Duration,
    /// False keeps guests
    /// read-only, as apron-server-cloudflare's `GUEST_POSTING` does.
    pub guest_posting: bool,
    /// Relays read cursors to the room's members, an extension: without
    /// it, as on apron-server-cloudflare, they go only to the user's own
    /// connections.
    pub read_receipts: bool,
    /// How long history is
    /// kept; `None` keeps it forever.
    pub retention: Option<Duration>,
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
        frame: FrameLimits::default(),
        outgoing_queue: DEFAULT_OUTGOING_QUEUE,
        history_page_size: DEFAULT_HISTORY_PAGE_SIZE,
        ping_interval: DEFAULT_PING_INTERVAL,
        ping_timeout: DEFAULT_PING_TIMEOUT,
        write_timeout: DEFAULT_WRITE_TIMEOUT,
        public_url: String::new(),
        max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        max_avatar_bytes: DEFAULT_MAX_AVATAR_BYTES,
        upload_types: Vec::new(),
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
        push_hosts: PushHosts::default(),
        push_delay: super::wake::PUSH_DELAY,
        vapid_private_key: String::new(),
        vapid_subject: String::new(),
        max_connections: DEFAULT_MAX_CONNECTIONS,
        limits: Limits::default(),
        max_listed_members: DEFAULT_MAX_LISTED_MEMBERS,
        max_private_rooms: 20,
        welcome: String::new(),
        server: ServerMetadata::default(),
        max_emoji: DEFAULT_MAX_EMOJI,
        max_emoji_bytes: DEFAULT_MAX_EMOJI_BYTES,
        roles: BTreeMap::new(),
        admin_token: None,
        email_sender: None,
        client_ip_header: String::new(),
        email_link_url: String::new(),
        apple_app_ids: Vec::new(),
        unfurl: false,
        unfurl_allow_internal: false,
        unfurl_timeout: unfurl::FETCH_TIMEOUT,
        auth_timeout: AUTH_TIMEOUT,
        guest_posting: false,
        read_receipts: false,
        retention: None,
    }
}

impl Config {
    pub(super) fn with_defaults(mut self) -> Config {
        let defaults = default_config();
        if self.origin_patterns.is_none() && !self.allow_any_origin {
            self.origin_patterns = defaults.origin_patterns;
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
        if self.upload_types.is_empty() {
            self.upload_types = UPLOAD_TYPES.iter().map(|t| t.to_string()).collect();
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
