use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread;

use rust_stdlib::concurrent::WaitGroup;
use rust_stdlib::context::Context;
use rust_stdlib::log::slog;
use rust_stdlib::net::http::{self, Handler, Request as HttpRequest, ResponseWriter, ServeMux};
use rust_stdlib::time::{self, Duration, Time};

use super::bots::BotTokens;
use super::client::{Client, ClientId, Conn, Done, Frame, PING_FRAME};
use super::config::{Config, UNTRUSTED_ADDRESS};
use super::custom_emoji::{EmojiCatalog, CATALOG_PATH};
use super::devices::DeviceTokens;
use super::dispatch::{methods, Method};
use super::email::EmailState;
use super::embeds::EmbedState;
use super::invites::{InviteTokens, JoinInvite};
use super::limits::{IpKey, LimitTable, Window};
use super::messages::MessageState;
use super::metadata::StoredServer;
use super::outbound;
use super::persist::{DirtySet, StoredMeta};
use super::protocol::*;
use super::push::{PushDeliverer, PushRegistration};
use super::rooms::RoomState;
use super::toggles::Feature;
use super::unfurl::{self, Fetcher, Unfurler};
use super::users::UserState;
use super::webauthn::Sessions;
use super::webpush::VapidKey;
use crate::obj;
use crate::store::{self, Entry, Store};
use crate::ws;

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

/// The state Go guards with `s.mu`.
pub struct State {
    pub server: Weak<Server>,
    pub config: Arc<Config>,
    /// The single log_id sequence shared by every record kind and room.
    pub last_id: i64,
    /// Every record below it was discarded by retention (Config.retention);
    /// 0 until retention first discards one. It never decreases.
    pub history_floor: i64,
    /// The last log_id when retention last removed a thread; 0 if never.
    pub rooms_removed_at: i64,
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
    /// The Config.roles grants given, as `role=holder` with the holder
    /// lowercased (`grant_roles_locked`).
    pub role_grants: BTreeSet<String>,
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
    /// Counts each principal's use of the limits (Config.limits).
    pub limits: LimitTable,
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
    /// `/invite-token` tokens by the SHA-256 of the token (invites.rs).
    pub invites: InviteTokens,
    /// The live `/invite` sign-up invite, if any (invites.rs).
    pub join_invite: Option<JoinInvite>,
    /// The features an admin turned off with `/toggle` (toggles.rs).
    pub features_off: BTreeSet<Feature>,
    /// What admins set with `/server` (metadata.rs).
    pub server_meta: StoredServer,
    /// The custom emoji (custom_emoji.rs).
    pub emoji: EmojiCatalog,
    /// When the idle bot sweep is next due, in Unix milliseconds; 0 until
    /// the first sweep sets it (bots.rs).
    pub bot_sweep_at: i64,
    pub email: EmailState,
    /// The webpush key (§4.9); vapid_stored reports that it is the store's,
    /// rather than Config's, so a flush keeps it there.
    pub vapid: Option<Arc<VapidKey>>,
    pub vapid_stored: bool,
    /// How long badge pushes wait to coalesce the changes to one user's
    /// unread count; badges counts the waits in progress.
    pub badge_delay: Duration,
    pub badges: WaitGroup,
    /// The wakes waiting `--push.delay`, by a counter (wake.rs).
    pub pending_wakes: BTreeMap<u64, super::wake::PendingWake>,
    pub next_wake: u64,
    /// When each user was last woken for each room, for coalescing, and
    /// the windows (wake.rs).
    pub push_woken: BTreeMap<(String, String), Time>,
    pub push_coalesce: Duration,
    pub joined_coalesce: Duration,
    pub push: Arc<PushDeliverer>,
    /// Set with `Config.unfurl`.
    pub unfurler: Option<Arc<Unfurler>>,
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
    /// Link previews in progress, which `shutdown` awaits.
    pub(crate) unfurler: Option<Arc<Unfurler>>,
    /// Set by `shutdown`; ends the sweep of expired registrations.
    pub(crate) stopped: Arc<Done>,
    pub(crate) methods: BTreeMap<&'static str, &'static Method>,
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
    let unfurler = config.unfurl.then(|| {
        let check = if config.unfurl_allow_internal {
            outbound::any_address()
        } else {
            unfurl::dial_check()
        };
        Unfurler::new(
            Fetcher::new(check, config.unfurl_timeout),
            config.unfurl_timeout,
        )
    });
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
                history_floor: 0,
                rooms_removed_at: 0,
                rooms: BTreeMap::new(),
                messages: BTreeMap::new(),
                records: BTreeMap::new(),
                clients: BTreeMap::new(),
                users: BTreeMap::new(),
                used_ids: BTreeSet::new(),
                granted_ids,
                role_grants: BTreeSet::new(),
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
                limits: LimitTable::default(),
                emails: BTreeMap::new(),
                credentials: BTreeMap::new(),
                sessions: Sessions::default(),
                devices: DeviceTokens::default(),
                bots: BotTokens::default(),
                invites: InviteTokens::default(),
                join_invite: None,
                features_off: BTreeSet::new(),
                server_meta: StoredServer::default(),
                emoji: EmojiCatalog::default(),
                bot_sweep_at: 0,
                email: EmailState::default(),
                vapid,
                vapid_stored: false,
                badge_delay: super::unread::BADGE_DELAY,
                pending_wakes: BTreeMap::new(),
                next_wake: 0,
                push_woken: BTreeMap::new(),
                push_coalesce: super::wake::PUSH_COALESCE,
                joined_coalesce: super::wake::JOINED_COALESCE,
                badges: badges.clone(),
                push: push.clone(),
                unfurler: unfurler.clone(),
            }),
            store,
            store_writes: Mutex::new(Some(tx)),
            store_done: Mutex::new(Some(writer)),
            connections: WaitGroup::new(),
            mailing: WaitGroup::new(),
            badges,
            push,
            unfurler,
            stopped: Arc::new(Done::default()),
            methods: methods(&config),
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
        // A restart after a long stop discards what expired meanwhile before
        // anyone reads it.
        st.expire_history_locked(&time::now());
        if !st.rooms.contains_key(DEFAULT_ROOM_ID) {
            // The seeded default room has a logged creation record like any
            // other room, so its history_log_id is never null.
            st.commit_room_locked(
                DEFAULT_ROOM_ID,
                None,
                false,
                obj! {"title" => super::rooms::DEFAULT_ROOM_TITLE},
            );
        }
        st.remove_stale_uploads(&files);
    }
    server.sweep();
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
        let server = self.clone();
        mux.handle_func(CATALOG_PATH, move |w, r| server.handle_catalog(w, r))
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

    /// Says over plain HTTP whether a WebSocket would be admitted now, since
    /// a browser hides why a handshake failed (apron-web EXT.md §5): 403
    /// for a refused origin, 429 at the connection cap, 503 while shutting
    /// down, and otherwise `{"available": true}`, admitting no connection.
    fn connection_status(&self, w: &mut dyn ResponseWriter, r: &HttpRequest) {
        let refused = if !self.config.allow_any_origin
            && ws::authenticate_origin(r, self.config.origin_patterns.as_deref().unwrap_or(&[]))
                .is_err()
        {
            Some((http::STATUS_FORBIDDEN, "Origin not allowed", None))
        } else if self.client_ip(r).is_none() {
            Some((http::STATUS_FORBIDDEN, UNTRUSTED_ADDRESS, None))
        } else {
            let st = self.lock();
            if st.closed {
                Some((
                    http::STATUS_SERVICE_UNAVAILABLE,
                    "Server is shutting down",
                    None,
                ))
            } else {
                let ip = self.client_ip(r).expect("checked above");
                st.capacity_locked(&ip).map(|(message, retry_after)| {
                    (http::STATUS_TOO_MANY_REQUESTS, message, Some(retry_after))
                })
            }
        };
        let header = w.header();
        header.set("Content-Type", "application/json");
        header.set("Cache-Control", "no-store");
        header.set("Access-Control-Allow-Origin", "*");
        header.set(
            "Access-Control-Expose-Headers",
            "Retry-After, Apron-Connection-Status",
        );
        header.set("Apron-Connection-Status", "1");
        let body = match refused {
            Some((status, message, retry_after)) => {
                if let Some(seconds) = retry_after {
                    header.set("Retry-After", &seconds.to_string());
                }
                w.write_header(status);
                obj! {"error" => message}
            }
            None => obj! {"available" => true},
        };
        let _ = std::io::Write::write_all(w, &encode_json(&body).expect("encodes"));
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
                st.stop_wakes_locked();
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
            if let Some(unfurler) = &server.unfurler {
                unfurler.wait();
            }
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
        if r.method == http::METHOD_GET
            && r.url.query().get("apron_connection_status") == "1"
            && r.header.get("Upgrade").is_none()
        {
            self.connection_status(w, r);
            return;
        }
        if self.lock().closed {
            http::http_error(
                w,
                "server is shutting down",
                http::STATUS_SERVICE_UNAVAILABLE,
            );
            return;
        }
        let Some(ip_key) = self.client_ip(r) else {
            http::http_error(w, UNTRUSTED_ADDRESS, http::STATUS_FORBIDDEN);
            return;
        };
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
        socket.set_read_limit(self.config.frame.max_bytes as i64);

        let (out, rx) = sync_channel(self.config.outgoing_queue);
        let client = Arc::new(Client {
            id: ClientId::next(),
            ws: socket,
            out,
            done: Done::default(),
            base_url: self.base_url(r),
            origin: r.header.get("Origin").unwrap_or("").to_owned(),
            ip_key,
            write_timeout: self.config.write_timeout,
            ping_interval: self.config.ping_interval,
            ping_timeout: self.config.ping_timeout,
            closing: AtomicBool::new(false),
            pinged: AtomicBool::new(false),
            last_frame: AtomicI64::new(time::now().unix_nano()),
            violations: Mutex::default(),
            max_violations: self.config.limits.policy_violations,
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
            if let Err(refusal) = st.admit_locked(&client.ip_key) {
                // An error about the connection as a whole omits id (§1.1).
                client.enqueue(&obj! {"method" => "server", "params" => st.server_params(&client)});
                client.close_with_error(refusal);
                drop(st);
                client.done.wait();
                return;
            }
            st.clients.insert(
                client.id,
                Conn {
                    client: client.clone(),
                    user: None,
                    idle_since: None,
                    ceremony: None,
                    token: [0; 32],
                    device: [0; 32],
                    email_sends: None,
                    proposal: None,
                    listed_joined: false,
                    wake_joined: false,
                },
            );
            // The server announcement and the welcome are queued before the
            // reader starts accepting auth.
            client.enqueue(&obj! {"method" => "server", "params" => st.server_params(&client)});
            client.enqueue(&st.welcome_notice(&client.origin));
        }
        let auth_deadline = {
            let server = Arc::downgrade(self);
            let client = Arc::downgrade(&client);
            time::after_func(self.config.auth_timeout, move || {
                let (Some(server), Some(client)) = (server.upgrade(), client.upgrade()) else {
                    return;
                };
                let signed_in = server
                    .lock()
                    .clients
                    .get(&client.id)
                    .is_some_and(|conn| conn.user.is_some());
                if !signed_in {
                    client.close_with_code(ws::STATUS_POLICY_VIOLATION, "Authentication timed out");
                }
            })
        };

        let mut frames = Window::default();
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
            let max = self.config.limits.frames_per_connection_minute;
            if max > 0 && frames.note(time::now().unix_milli()) > max {
                client.close_with_code(ws::STATUS_POLICY_VIOLATION, "Frame rate limit reached");
                break;
            }
            // Frames are processed in order, each to completion before the
            // next is read, which makes auth a barrier (§3.2).
            self.process_frame(&client, &payload);
        }
        auth_deadline.stop();
    }

    /// The key of the client that opened a request: with
    /// `client_ip_header`, of the last entry across every line of that
    /// header, which the proxy in front added itself, without a port; else of
    /// the connection's own address. `None` when the header names no address,
    /// which refuses the connection rather than give it a fresh, unlimited
    /// key, as apron-server-cloudflare does without its trusted address.
    pub(crate) fn client_ip(&self, r: &HttpRequest) -> Option<IpKey> {
        let header = &self.config.client_ip_header;
        if header.is_empty() {
            let remote = match rust_stdlib::net::split_host_port(&r.remote_addr) {
                Ok((host, _)) => host,
                Err(_) => r.remote_addr.clone(),
            };
            return IpKey::parse(&remote);
        }
        let joined = r.header.values(header).join(",");
        let mut entry = joined.rsplit(',').next().unwrap_or("").trim().to_owned();
        if let Ok((host, _)) = rust_stdlib::net::split_host_port(&entry) {
            entry = host;
        }
        let entry = entry.strip_prefix('[').unwrap_or(&entry);
        IpKey::parse(entry.strip_suffix(']').unwrap_or(entry))
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
