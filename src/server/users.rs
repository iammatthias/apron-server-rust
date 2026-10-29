use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};

use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::encoding::json::jsontext::Value;
use rust_stdlib::regexp::Regexp;
use rust_stdlib::time::Timer;
use rust_stdlib::unicode;
use rust_stdlib_crypto::rand;

use super::protocol::*;
use super::server::{Client, ClientId, Frame, Server, State, DEFAULT_ROOM_ID};
use super::status::*;
use super::webauthn::PasskeyUser;
use crate::obj;
use crate::rate::Limiter;

pub const MAX_NAME_RUNES: usize = 64;
pub const MAX_DEDUP_ENTRIES: usize = 1024;
/// Bounds a profile's ext, which is sent to everyone who shares a room with
/// the user.
pub const MAX_PROFILE_EXT_BYTES: usize = 16 << 10;
/// Most roles one user holds (apron-server-cloudflare's MAX_ROLES_PER_USER).
pub const MAX_ROLES: usize = 8;
/// The role that lets a user run the admin commands.
pub const ADMIN_ROLE: &str = "admin";
/// The role that lets a user create and edit top-level rooms and move
/// others' messages, as `admin` does.
pub const MOD_ROLE: &str = "mod";
/// The role that lets a user move others' messages, and nothing else.
pub const THREADER_ROLE: &str = "threader";
/// The roles whose accounts create and edit top-level rooms besides
/// `general` (apron-server-cloudflare's ROOM_CREATOR_ROLES).
pub const ROOM_CREATOR_ROLES: &[&str] = &[ADMIN_ROLE, MOD_ROLE];
/// The roles whose accounts move others' messages between rooms
/// (apron-server-cloudflare's MODERATOR_ROLES).
pub const MODERATOR_ROLES: &[&str] = &[ADMIN_ROLE, MOD_ROLE, THREADER_ROLE];
/// The key of `you`'s ext that lists what the user may do to others'
/// messages and memberships (EXTENSIONS.md, `ext:permissions`).
pub const PERMISSIONS_KEY: &str = "permissions";
pub const INVALID_ROLE: &str =
    "A role is 1 to 24 lowercase letters, digits, _ or -, starting with a letter";

/// Reports whether `role` is a role name: 1 to 24 lowercase letters,
/// digits, `_` or `-`, starting with a letter.
pub fn valid_role(role: &str) -> bool {
    let bytes = role.as_bytes();
    (1..=24).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// Everything the server keeps for one user_id across its connections: the
/// profile (§3.3), joined rooms (§4.2.2), request deduplication (§1.2), and
/// push registrations (§4.9). Guest users are retired when their last
/// connection closes; accounts and bots persist.
pub struct UserState {
    pub id: String,
    pub name: String,
    pub avatar: String,
    pub ext: ExtObject,
    /// The account's sign-in address (§4.11), lowercased; empty for guests
    /// and passkey users without one.
    pub email: String,
    /// The server roles (§3.3), in the order given, at most MAX_ROLES;
    /// guests have none. Stored with the user.
    pub roles: Vec<String>,
    /// The hosted /avatar upload behind avatar, if any (an embed_id).
    pub avatar_embed: Option<String>,
    /// Tells a timer scheduled for this identity from a later one with the
    /// same user_id (Go compares the pointers).
    pub generation: u64,

    pub clients: BTreeSet<ClientId>,
    pub joined: BTreeSet<String>,
    /// Each room the user left, and has not rejoined, to the log_id of the
    /// leave, for room_list's `left` (§4.2.1).
    pub left_at: BTreeMap<String, i64>,
    pub dedup: DedupCache,
    /// A passkey user's handle and credentials (§4.10).
    pub passkey: Option<PasskeyUser>,
    /// The account a `/invite-bot` bot belongs to (bots.rs); `None` for
    /// every other user.
    pub owner: Option<String>,
    /// An account that signs in with a token alone, with no passkey or
    /// email address needed: the user `admin` (admin.rs) and those an admin
    /// invites (invites.rs).
    pub invited: bool,
    /// For a user whose only role is `bot`: when it last signed in, posted
    /// or reacted, in Unix milliseconds, for the idle bot sweep; 0 once the
    /// sweep signed it out (bots.rs).
    pub active: i64,
    /// Bounds the URLs of the user's messages that are unfurled.
    pub unfurls: Option<Limiter>,
    /// Bound the user's typing relays and read cursor relays, each
    /// ACTIVITY_RELAYS_PER_MINUTE; `typing_notice_at` is when the user was
    /// last told typing was throttled, in Unix milliseconds.
    pub typing_relays: Option<Limiter>,
    pub read_relays: Option<Limiter>,
    pub typing_notice_at: i64,

    /// The chosen status, set with `me` (§4.5.1); `mute` and `room_mutes`
    /// their mutes; `shown` the shown status as last noted, and `offline_at`
    /// the Unix milliseconds when it last became offline; `status` the shown
    /// status published to others, and `seen` the Unix milliseconds when it
    /// last became offline, 0 if unknown (§4.5.2).
    pub chosen: String,
    pub mute: MuteState,
    pub room_mutes: BTreeMap<String, MuteState>,
    pub mute_timer: Option<Timer>,
    pub room_mute_timers: BTreeMap<String, Timer>,
    pub shown: String,
    pub offline_at: i64,
    pub seen: i64,
    pub status: String,
    pub status_limit: Option<Limiter>,
    pub status_timer: Option<Timer>,
    pub status_requests: Option<Limiter>,
    /// The rooms the user has not joined where a message mentioned or
    /// replied to them, from the first such message, for unread counts.
    pub pings: BTreeMap<String, i64>,
    /// The counts known per room while the user has registrations.
    pub unread: Option<BTreeMap<String, i64>>,
    pub badge_timer: Option<Timer>,
    /// The UTC day pushes_today counts the pushes delivered to the user on,
    /// against MAX_PUSHES_PER_USER_DAY.
    pub push_day: String,
    pub pushes_today: i64,
    pub push_registers: Option<Limiter>,
    /// The wakes passed over while the user was attended (wake.rs).
    pub held: Vec<super::wake::HeldWake>,
}

impl UserState {
    pub fn new(id: &str, name: &str, generation: u64) -> UserState {
        UserState {
            id: id.to_owned(),
            name: name.to_owned(),
            avatar: String::new(),
            ext: ExtObject::new(),
            email: String::new(),
            roles: Vec::new(),
            avatar_embed: None,
            generation,
            clients: BTreeSet::new(),
            joined: BTreeSet::new(),
            left_at: BTreeMap::new(),
            dedup: DedupCache::default(),
            passkey: None,
            owner: None,
            invited: false,
            active: 0,
            unfurls: None,
            chosen: STATUS_ONLINE.into(),
            mute: MuteState::default(),
            room_mutes: BTreeMap::new(),
            mute_timer: None,
            room_mute_timers: BTreeMap::new(),
            shown: STATUS_OFFLINE.into(),
            offline_at: 0,
            seen: 0,
            status: STATUS_OFFLINE.into(),
            status_limit: None,
            status_timer: None,
            status_requests: None,
            typing_relays: None,
            read_relays: None,
            typing_notice_at: 0,
            pings: BTreeMap::new(),
            unread: None,
            badge_timer: None,
            push_day: String::new(),
            pushes_today: 0,
            push_registers: None,
            held: Vec::new(),
        }
    }

    /// The recorded user object carried in logged records (a message's or
    /// reaction's from, a membership's user): user_id and name. Avatars and
    /// ext travel only in current objects (§3.3, §4.8.6).
    pub fn from(&self) -> Object {
        let mut value = obj! {"user_id" => self.id.as_str()};
        if !self.name.is_empty() {
            value.insert("name".into(), self.name.as_str().into());
        }
        value
    }

    /// Reports whether the user is an account: it signed in with a
    /// passkey, an email address or an account token, so it persists
    /// across connections and restarts, and it is no guest or bot.
    pub fn account(&self) -> bool {
        (self.passkey.is_some() || !self.email.is_empty() || self.invited) && !self.bot()
    }

    /// Reports whether the user is a bot, which signs in only with its
    /// token: an account's `/invite-bot` bot, or a user with the `bot` role.
    pub fn bot(&self) -> bool {
        self.owner.is_some() || self.has_role(super::bots::BOT_ROLE)
    }

    /// Reports whether the user outlives its connections and restarts: an
    /// account or a bot, not a guest.
    pub fn persists(&self) -> bool {
        self.passkey.is_some() || !self.email.is_empty() || self.invited || self.bot()
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Reports whether the user holds one of `roles` and is no bot, whose
    /// roles grant nothing. Guests hold no roles: seeding and `/role` both
    /// refuse them.
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        !self.bot() && roles.iter().any(|role| self.has_role(role))
    }

    /// The complete current user object for user and users (§3.3), with the
    /// published shown status, and seen when it is offline (§4.5.2); `you`
    /// has the chosen status instead.
    pub fn profile(&self) -> Object {
        let mut value = self.from();
        value.insert("status".into(), self.status.as_str().into());
        self.add_seen(&mut value);
        if !self.avatar.is_empty() {
            value.insert("avatar".into(), self.avatar.as_str().into());
        }
        // An account's roles are always sent, [] when it has none, so a
        // role taken away clears the one a client kept (§3.3); guests hold
        // none.
        if self.persists() {
            value.insert("roles".into(), self.roles.clone().into());
        }
        if !self.ext.is_empty() {
            value.insert("ext".into(), Json::Ext(self.ext.clone()));
        }
        value
    }
}

/// Denies a read-only guest's writes (Config.guest_posting).
pub const GUEST_READ_ONLY: &str = "Guests can only read here; sign in to post or join rooms";

/// Reports whether a read-only guest is denied the method outright;
/// `command` and `activity` decide per request, and push registration
/// refuses every guest with its own message.
pub fn guest_write(method: &str) -> bool {
    matches!(
        method,
        "message" | "reactions" | "room_set" | "room_join" | "room_leave"
    )
}

impl State {
    /// Reports whether the user is a guest on a server whose guests only
    /// read.
    pub fn read_only_guest(&self, user_id: &str) -> bool {
        !self.config.guest_posting && self.users.get(user_id).is_some_and(|u| !u.persists())
    }
}

/// The outcome shared with the duplicates of a request (§1.2).
pub struct DedupEntry {
    /// A hash of the request's method and canonical params.
    pub fingerprint: [u8; 32],
    outcome: Mutex<Option<Result<Json, RpcError>>>,
    done: Condvar,
}

impl DedupEntry {
    pub fn new(fingerprint: [u8; 32]) -> DedupEntry {
        DedupEntry {
            fingerprint,
            outcome: Mutex::new(None),
            done: Condvar::new(),
        }
    }

    pub fn finish(&self, outcome: Result<Json, RpcError>) {
        *self.outcome.lock().unwrap_or_else(|e| e.into_inner()) = Some(outcome);
        self.done.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        self.outcome
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Waits for the original to finish and returns its outcome.
    pub fn wait(&self) -> Result<Json, RpcError> {
        let guard = self.outcome.lock().unwrap_or_else(|e| e.into_inner());
        let guard = self
            .done
            .wait_while(guard, |outcome| outcome.is_none())
            .unwrap_or_else(|e| e.into_inner());
        guard
            .clone()
            .unwrap_or_else(|| Err(RpcError::new(CODE_INTERNAL_ERROR, "Internal error")))
    }
}

/// The most recent request IDs of one user. Guarded by the state lock.
#[derive(Default)]
pub struct DedupCache {
    entries: BTreeMap<String, Arc<DedupEntry>>,
    order: VecDeque<String>,
}

impl DedupCache {
    pub fn get(&self, id: &str) -> Option<Arc<DedupEntry>> {
        self.entries.get(id).cloned()
    }

    pub fn put(&mut self, id: &str, entry: Arc<DedupEntry>) {
        self.entries.insert(id.to_owned(), entry);
        self.order.push_back(id.to_owned());
        while self.order.len() > MAX_DEDUP_ENTRIES {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if self.entries.get(&oldest).is_some_and(|e| e.is_closed()) {
                self.entries.remove(&oldest);
            }
        }
    }

    pub fn remove(&mut self, id: &str, entry: &Arc<DedupEntry>) {
        if self.entries.get(id).is_some_and(|e| Arc::ptr_eq(e, entry)) {
            self.entries.remove(id);
        }
    }
}

/// Prepares a requested display name with the PRECIS Nickname profile (RFC
/// 8266): it maps compatibility characters, folds runs of spaces, and
/// trims. Invisible characters, such as controls and bidirectional
/// overrides, are dropped first rather than refused, and a name that still
/// cannot be a nickname becomes empty. The result is capped at
/// MAX_NAME_RUNES. The server may alter names (§3.3) and `you.name` is the
/// answer.
///
/// rust-stdlib has no Unicode normalization (Go's is golang.org/x/text), so
/// NFKC and the FreeformClass check are not applied; see docs/DEVIATIONS.md.
pub fn normalize_name(name: &str) -> String {
    let kept: String = name
        .chars()
        .filter(|&r| {
            !unicode::in_(
                r as i32,
                &[unicode::CC, unicode::CF, unicode::CO, unicode::CS],
            )
        })
        .collect();
    // RFC 8266 §2.1 rule 2: non-ASCII spaces become SPACE, interior runs
    // of spaces collapse to one, and leading and trailing spaces go.
    let mut out = String::new();
    let mut prev_space = false;
    for r in kept.chars() {
        if unicode::is(unicode::ZS, r as i32) {
            prev_space = true;
            continue;
        }
        if prev_space && !out.is_empty() {
            out.push(' ');
        }
        out.push(r);
        prev_space = false;
    }
    if out.chars().count() > MAX_NAME_RUNES {
        out = out
            .chars()
            .take(MAX_NAME_RUNES)
            .collect::<String>()
            .trim()
            .to_owned();
    }
    out
}

/// The shape of a user_id a new email account may request: the suggested convention for
/// user-chosen IDs (Appendix A.3), letters, digits, _, ., and -, starting
/// with a letter, and ending with a letter, digit, or _.
fn requestable_user_id() -> Regexp {
    Regexp::new(r"^[A-Za-z](?:[A-Za-z0-9_.-]{0,62}[A-Za-z0-9_])?$").expect("constant pattern")
}

/// Starts every counter-assigned guest ID. The guest_ namespace, ignoring
/// case, belongs to the counter.
pub const GUEST_ID_PREFIX: &str = "guest_";

/// Reports whether a user may request `id`: it has the requestable shape and
/// lies outside the counters' guest_ and user_ namespaces and the bots'
/// bot_ one (an extension; docs/DEVIATIONS.md).
pub fn requestable(id: &str) -> bool {
    for prefix in [
        GUEST_ID_PREFIX,
        super::email::ACCOUNT_ID_PREFIX,
        super::bots::BOT_ID_PREFIX,
    ] {
        if id.len() >= prefix.len() && id[..prefix.len()].eq_ignore_ascii_case(prefix) {
            return false;
        }
    }
    requestable_user_id().match_string(id)
}

/// The longest name part of a user_id picked from a requested name.
const USER_ID_SLUG_BYTES: usize = 16;
/// The tries at a `<slug>_<4 digits>` user_id before a random one.
pub const USER_ID_SLUG_ATTEMPTS: usize = 8;

/// apron-server-cloudflare's `userIdSlug`: the user_id part a requested
/// name suggests, lowercase ASCII letters and digits with other runs as one
/// `_`, at most 16 characters. Empty when nothing usable is left or when it
/// would pass for a counter's or a bot's user_id. Without NFKD, an accented
/// letter is a run of other characters (docs/DEVIATIONS.md).
pub fn user_id_slug(name: &str) -> String {
    let mut slug = String::new();
    let mut gap = false;
    for ch in name.to_lowercase().chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            if gap && !slug.is_empty() {
                slug.push('_');
            }
            gap = false;
            slug.push(ch);
        } else {
            gap = true;
        }
    }
    slug.truncate(USER_ID_SLUG_BYTES);
    let slug = slug.trim_end_matches('_');
    let reserved = [
        GUEST_ID_PREFIX,
        super::email::ACCOUNT_ID_PREFIX,
        super::bots::BOT_ID_PREFIX,
    ]
    .iter()
    .any(|prefix| slug.starts_with(prefix) || slug == prefix.trim_end_matches('_'));
    if reserved {
        return String::new();
    }
    slug.to_owned()
}

/// apron-server-cloudflare's `candidateUserIdFor`: a new account's user_id,
/// `<slug>_<4 random digits>` for a name with a slug, tried
/// USER_ID_SLUG_ATTEMPTS times while `taken`, else `u_` and 16 random bytes
/// as unpadded base64url.
pub fn candidate_user_id(name: &str, mut taken: impl FnMut(&str) -> bool) -> String {
    let slug = user_id_slug(name);
    if !slug.is_empty() {
        for _ in 0..USER_ID_SLUG_ATTEMPTS {
            let id = format!("{slug}_{}", random_digits::<4>());
            if !taken(&id) {
                return id;
            }
        }
    }
    let mut raw = [0u8; 16];
    rand::read(&mut raw);
    format!("u_{}", URL_SAFE_NO_PAD.encode(raw))
}

/// N decimal digits, each a random u32 modulo 10, as Cloudflare draws them.
fn random_digits<const N: usize>() -> String {
    let mut raw = [[0u8; 4]; N];
    for word in &mut raw {
        rand::read(word);
    }
    raw.iter()
        .map(|word| char::from(b'0' + (u32::from_le_bytes(*word) % 10) as u8))
        .collect()
}

impl State {
    /// What u may do beyond PROTOCOL.md's defaults (`ext:permissions`,
    /// EXTENSIONS.md), as the keys that differ from their defaults:
    /// `write: false` for a guest while guests only read; `add_members` for
    /// an admin, or any account while addmember is on; `move_any` with a
    /// moderator role. A bot has neither.
    pub fn permissions_locked(&self, u: &UserState) -> Vec<(&'static str, bool)> {
        let mut permissions = Vec::new();
        if !u.persists() {
            if !self.config.guest_posting {
                permissions.push(("write", false));
            }
            return permissions;
        }
        if u.account()
            && (u.has_role(ADMIN_ROLE) || self.feature_on(super::toggles::Feature::AddMember))
        {
            permissions.push(("add_members", true));
        }
        if u.has_any_role(MODERATOR_ROLES) {
            permissions.push(("move_any", true));
        }
        permissions
    }

    /// The `ext` of u's `you` holding only their permissions.
    pub fn permissions_ext_locked(&self, u: &UserState) -> ExtObject {
        let fields: Vec<String> = self
            .permissions_locked(u)
            .iter()
            .map(|(key, value)| format!("\"{key}\":{value}"))
            .collect();
        let raw = format!("{{{}}}", fields.join(","));
        ExtObject::from([(PERMISSIONS_KEY.to_owned(), Value::from(raw.into_bytes()))])
    }

    /// The user's own current object, `you` (§3.3), with their permissions
    /// in its ext.
    pub fn you_locked(&self, u: &UserState) -> Object {
        let mut you = u.you();
        let mut ext = ext_of(you.get("ext"));
        ext.extend(self.permissions_ext_locked(u));
        you.insert("ext".into(), Json::Ext(ext));
        you
    }
}

impl State {
    /// Honors a requested user_id when it is requestable and was never
    /// assigned, ignoring case, nor names a room; otherwise assigns the next
    /// unused guest_<n> (§3.2).
    /// Claims the next free `guest_<n>` and returns it with its number.
    pub fn next_guest_id_locked(&mut self) -> (String, u64) {
        loop {
            self.guest_number += 1;
            let id = format!("{GUEST_ID_PREFIX}{}", self.guest_number);
            if self.claim_user_id_locked(&id) {
                return (id, self.guest_number);
            }
        }
    }

    /// Reports whether `id` may not be assigned: it was assigned before,
    /// ignoring case, names a room, is granted a role, or is `admin`, which
    /// only the admin token signs in as.
    pub fn user_id_taken_locked(&self, id: &str) -> bool {
        let key = id.to_lowercase();
        self.used_ids.contains(&key)
            || self.room_named_locked(id)
            || self.granted_ids.contains(&key)
            || key == super::admin::ADMIN_USER_ID
    }

    /// Marks `id` used and reports whether it was free
    /// (`user_id_taken_locked`).
    pub fn claim_user_id_locked(&mut self, id: &str) -> bool {
        if self.user_id_taken_locked(id) {
            return false;
        }
        let key = id.to_lowercase();
        self.used_ids.insert(key.clone());
        self.touch_used_id(&key);
        true
    }

    /// Reports whether `id` names a room, ignoring case, so a user_id never
    /// passes for a room_id to a reader that folds case.
    pub fn room_named_locked(&self, id: &str) -> bool {
        self.rooms.contains_key(id) || id.eq_ignore_ascii_case(DEFAULT_ROOM_ID)
    }

    pub fn new_user_locked(&mut self, id: &str, name: &str) -> UserState {
        let generation = self.next_generation;
        self.next_generation += 1;
        UserState::new(id, name, generation)
    }

    /// Replies with user as `you` and extra fields beside it (§3.2, §3.3),
    /// then makes user the connection's identity. Every notification a
    /// sign-in causes on its connection follows the result (§3.2).
    pub fn switch_user_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
        user_id: &str,
        extra: Object,
        sign_in: bool,
        join_default: bool,
    ) -> Result<Object, RpcError> {
        let max = self.config.limits.connections_per_user;
        let u = &self.users[user_id];
        if max > 0 && u.persists() && u.clients.iter().filter(|id| **id != c.id).count() >= max {
            return Err(RpcError::with_data(
                CODE_RETRY_AFTER,
                "Connection limit reached for this account",
                obj! {"retry_after" => super::server::RETRY_AFTER_SECONDS},
            ));
        }
        self.note_bot_active_locked(user_id);
        let mut result = obj! {"you" => self.you_locked(&self.users[user_id])};
        result.extend(extra);
        c.send_result(req, result.clone().into());
        self.attach_locked(c, user_id);
        if join_default {
            self.join_default_room_locked(user_id);
        }
        if sign_in {
            self.send_after_auth_locked(c);
        }
        Ok(result)
    }

    /// Makes user the connection's identity and announces the status others
    /// see of it and of the identity the connection leaves (§4.5). A guest
    /// identity left without connections is retired, logging its leaves.
    pub fn attach_locked(&mut self, c: &Arc<Client>, user_id: &str) {
        let previous = self.client_user(c);
        if previous.as_deref() == Some(user_id) {
            return;
        }
        if let Some(previous) = &previous {
            if let Some(u) = self.users.get_mut(previous) {
                u.clients.remove(&c.id);
            }
        }
        // A pending email proposal was made by the previous identity: it is
        // dropped, so the connection cannot approve it as the next one
        // (§4.11.3).
        let proposal = self
            .clients
            .get_mut(&c.id)
            .and_then(|conn| conn.proposal.take());
        if let Some(id) = proposal {
            self.drop_proposal_locked(id);
        }
        if let Some(conn) = self.clients.get_mut(&c.id) {
            conn.user = Some(user_id.to_owned());
            conn.listed_joined = false;
        }
        if let Some(u) = self.users.get_mut(user_id) {
            u.clients.insert(c.id);
        }
        // The previous identity's departure goes first, then the user's own
        // status.
        if let Some(previous) = previous {
            let retire = self
                .users
                .get(&previous)
                .is_some_and(|u| u.clients.is_empty() && !u.persists());
            if retire {
                self.retire_locked(&previous);
            } else {
                self.announce_status_locked(&previous);
            }
        }
        self.announce_status_locked(user_id);
        self.sync_server_locked(c);
    }

    /// Forgets a closed connection, retiring its guest identity.
    pub fn detach_locked(&mut self, conn: super::server::Conn) {
        self.release_proposal_locked(&conn);
        let Some(user_id) = conn.user else { return };
        let Some(u) = self.users.get_mut(&user_id) else {
            return;
        };
        u.clients.remove(&conn.client.id);
        if u.clients.is_empty() && !u.persists() {
            self.retire_locked(&user_id);
            return;
        }
        self.announce_status_locked(&user_id);
    }

    /// Closes a connection whose sign-in was revoked, with a connection-level
    /// error, and signs it out at once. The close waits behind the frames
    /// already queued, and every request resolves its identity under the
    /// lock, so from here on nothing the connection sent runs as the user,
    /// in flight or not.
    pub fn revoke_connection_locked(&mut self, id: ClientId, e: RpcError) {
        let Some(conn) = self.clients.get_mut(&id) else {
            return;
        };
        conn.client.close_with_error(e);
        conn.ceremony = None;
        let proposal = conn.proposal.take();
        let Some(user_id) = conn.user.take() else {
            return;
        };
        if let Some(proposal) = proposal {
            self.drop_proposal_locked(proposal);
        }
        let Some(u) = self.users.get_mut(&user_id) else {
            return;
        };
        u.clients.remove(&id);
        if u.clients.is_empty() && !u.persists() {
            self.retire_locked(&user_id);
            return;
        }
        self.announce_status_locked(&user_id);
    }

    /// Removes a guest identity for good. It leaves every room it joined,
    /// logging each leave as a membership for the remaining members
    /// (§4.2.2). Its user_id is never reissued (§3.3).
    pub fn retire_locked(&mut self, user_id: &str) {
        let Some(u) = self.users.get(user_id) else {
            return;
        };
        let mut rooms: Vec<(i64, String)> = u
            .joined
            .iter()
            .filter_map(|id| self.rooms.get(id).map(|r| (r.created_id, id.clone())))
            .collect();
        rooms.sort();
        // Its registrations go first, so its leaves send it no badge pushes.
        let registrations: Vec<String> = self.sorted_pushes(user_id);
        for key in registrations {
            self.remove_push_locked(&key);
        }
        for (_, room_id) in rooms {
            self.leave_locked(user_id, &room_id);
            if let Some(r) = self.rooms.get_mut(&room_id) {
                r.reads.remove(user_id);
            }
        }
        self.stop_timers_locked(user_id);
        self.set_avatar_embed_locked(user_id, None);
        self.users.remove(user_id);
        self.touch_user(user_id);
    }

    /// Stops u's timers: the ends of its timed mutes, its coalesced status,
    /// and its pending badge pushes.
    pub fn stop_timers_locked(&mut self, user_id: &str) {
        if let Some(u) = self.users.get_mut(user_id) {
            if let Some(timer) = u.mute_timer.take() {
                timer.stop();
            }
            if let Some(timer) = u.status_timer.take() {
                timer.stop();
            }
            for (_, timer) in std::mem::take(&mut u.room_mute_timers) {
                timer.stop();
            }
        }
        self.stop_badge_locked(user_id);
    }

    /// Lists the other users who share a joined room with u, by user_id.
    pub fn sharers_locked(&self, user_id: &str) -> Vec<String> {
        let mut seen = BTreeSet::new();
        if let Some(u) = self.users.get(user_id) {
            for room_id in &u.joined {
                if let Some(r) = self.rooms.get(room_id) {
                    for id in &r.members {
                        if id != user_id {
                            seen.insert(id.clone());
                        }
                    }
                }
            }
        }
        seen.into_iter().collect()
    }

    /// Sends a `user` notification after a profile change: `you` to the
    /// user's connections other than `except`, and `new` to everyone who
    /// shares a room with them (§3.3). `removed` lists fields the change
    /// removed, and `cleared` the ext keys it removed, both announced as
    /// empty values.
    pub fn notify_profile_locked(
        &mut self,
        user_id: &str,
        except: Option<&Client>,
        cleared: &ExtObject,
        removed: &[&str],
    ) {
        // The profile goes to every sharer, so it publishes the shown
        // status, one held back to coalesce included.
        self.publish_locked(user_id);
        let Some(u) = self.users.get(user_id) else {
            return;
        };
        let profile = with_cleared(with_removed(u.profile(), removed), cleared);
        let you = Frame::from(notification(
            "user",
            obj! {"you" => with_cleared(with_removed(self.you_locked(u), removed), cleared)},
        ));
        for id in &u.clients {
            if except.is_some_and(|c| c.id == *id) {
                continue;
            }
            if let Some(conn) = self.clients.get(id) {
                conn.client.enqueue_frame(you.clone());
            }
        }
        let others = Frame::from(notification("user", obj! {"new" => profile}));
        for other in self.sharers_locked(user_id) {
            self.send_to_user(&other, &others);
        }
    }

    /// Sends `user` with `new` and `old` to everyone who shares a room
    /// with the user, which took over from the identity `old` under a new
    /// user_id (§3.3.3). The user has no other connections to send `you`.
    pub fn notify_user_id_change_locked(&mut self, user_id: &str, old: Object) {
        self.publish_locked(user_id);
        let Some(u) = self.users.get(user_id) else {
            return;
        };
        let frame = Frame::from(notification(
            "user",
            obj! {"new" => u.profile(), "old" => old},
        ));
        for other in self.sharers_locked(user_id) {
            self.send_to_user(&other, &frame);
        }
    }

    /// Applies a `me` request (§3.3): a given field replaces the current
    /// value, an omitted one stays, and an empty value ("" or {}) removes
    /// the field, which the result and notifications carry as that empty
    /// value.
    pub fn update_profile_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let name = parse_string(&req.params, "name", false)?;
        let avatar = parse_string(&req.params, "avatar", false)?;
        let (mut ext_write, has_ext) = parse_ext(&req.params, "ext")?;
        // The server owns the permissions it sends in `you` (EXTENSIONS.md).
        ext_write.remove(PERMISSIONS_KEY);
        let mut status = parse_string(&req.params, "status", false)?;
        let has_name = req.params.contains_key("name");
        // An avatar comes only from /avatar (§4.8.6), so `me` takes only ""
        // to remove it and ignores any other value, as Cloudflare does.
        let has_avatar = req.params.contains_key("avatar") && avatar.is_empty();
        let has_status = req.params.contains_key("status");

        let Some(user_id) = self.client_user(c) else {
            return Err(RpcError::new(
                CODE_DENIED,
                "Sign in before sending requests",
            ));
        };
        let u = &self.users[&user_id];
        // A guest keeps the name it was given, `Guest <n>`.
        if has_name && !u.persists() {
            return Err(RpcError::new(
                CODE_DENIED,
                "Only registered users may change their name",
            ));
        }
        // A guest keeps no profile, as on Cloudflare.
        if has_ext && !u.persists() {
            return Err(RpcError::new(
                CODE_DENIED,
                "Only registered users may change their profile",
            ));
        }
        // A bot is named after its owner. The bot client sends its name on
        // every connection, so the name it already has is no change.
        if has_name && u.bot() && normalize_name(&name) != u.name {
            return Err(RpcError::new(
                CODE_DENIED,
                if u.owner.is_some() {
                    "A bot is named after its owner, who can rename it with /invite-bot"
                } else {
                    "A bot can't change its name"
                },
            ));
        }
        if has_status && !settable_status(&status) {
            status = STATUS_NONE.into();
        }
        // ext merges into the kept one (§4.12), and the limit applies to the
        // result.
        let mut ext = u.ext.clone();
        if has_ext {
            ext = merge_ext(&u.ext, &ext_write);
            if encoded_size(&Json::Ext(ext.clone())) > MAX_PROFILE_EXT_BYTES {
                return Err(RpcError::new(
                    CODE_TOO_LARGE,
                    format!("Your profile's ext would be over {MAX_PROFILE_EXT_BYTES} bytes"),
                ));
            }
        }
        // A status change counts against the user's limit on status changes,
        // as a `status` request does (§4.5).
        if has_status && status != u.chosen {
            admit_status_locked(self.users.get_mut(&user_id).expect("user exists"))?;
        }
        let u = &self.users[&user_id];
        if (has_name && normalize_name(&name) != u.name)
            || (has_avatar && avatar != u.avatar)
            || (has_ext && ext != u.ext)
        {
            self.charge_post_locked(c, &user_id, None)?;
        }
        let u = &self.users[&user_id];
        let (before, before_you) = (u.profile(), self.you_locked(u));
        self.touch_user(&user_id);
        let mut removed: Vec<&str> = Vec::new();
        if has_name {
            let u = self.users.get_mut(&user_id).expect("user exists");
            u.name = normalize_name(&name);
            if u.name.is_empty() {
                removed.push("name");
            }
        }
        if has_avatar && avatar != self.users[&user_id].avatar {
            self.set_avatar_embed_locked(&user_id, None);
            self.users.get_mut(&user_id).expect("user exists").avatar = avatar.clone();
        }
        if has_avatar && avatar.is_empty() {
            removed.push("avatar");
        }
        let cleared = cleared_ext(&self.users[&user_id].ext, &ext_write);
        self.users.get_mut(&user_id).expect("user exists").ext = ext;
        if has_status {
            // A change of the chosen status is sent at once, with the
            // profile.
            self.users.get_mut(&user_id).expect("user exists").chosen = status;
            self.publish_locked(&user_id);
        }
        let u = &self.users[&user_id];
        let you = self.you_locked(u);
        let result = obj! {"you" => with_removed(you.clone(), &removed)};
        if !json_equal(&before, &u.profile()) || !json_equal(&before_you, &you) {
            self.notify_profile_locked(&user_id, Some(c), &cleared, &removed);
        }
        c.send_result(req, result.clone().into());
        Ok((result.into(), true))
    }

    /// Gives an account the roles Config.roles grants it, by its user_id or
    /// email address, and a bot `bot`, and reports whether its roles
    /// changed. Each grant is given once and remembered in
    /// `State.role_grants`, so a role an admin took away stays away across
    /// restarts while the grant stays configured.
    pub fn grant_roles_locked(&mut self, user_id: &str) -> bool {
        let Some(u) = self.users.get_mut(user_id) else {
            return false;
        };
        let mut changed = false;
        if u.owner.is_some() {
            if !u.has_role(super::bots::BOT_ROLE) {
                u.roles = vec![super::bots::BOT_ROLE.to_owned()];
                changed = true;
            }
        } else if u.account() {
            for (role, holders) in &self.config.roles {
                for holder in holders {
                    let held = holder.eq_ignore_ascii_case(&u.id)
                        || (!u.email.is_empty() && holder.eq_ignore_ascii_case(&u.email));
                    let grant = format!("{role}={}", holder.to_lowercase());
                    if !held || self.role_grants.contains(&grant) {
                        continue;
                    }
                    self.role_grants.insert(grant);
                    if !u.has_role(role) && u.roles.len() < MAX_ROLES {
                        u.roles.push(role.clone());
                        changed = true;
                    }
                }
            }
        }
        if changed {
            self.dirty.users.insert(user_id.to_owned());
        }
        changed
    }
}

/// Adds each removed field to a profile as its empty value.
pub fn with_removed(mut profile: Object, removed: &[&str]) -> Object {
    for field in removed {
        profile.insert((*field).to_owned(), "".into());
    }
    profile
}

/// Adds each cleared ext key to a profile's ext as its empty value (§4.12).
pub fn with_cleared(mut profile: Object, cleared: &ExtObject) -> Object {
    if cleared.is_empty() {
        return profile;
    }
    let mut ext = ext_of(profile.get("ext"));
    ext.extend(cleared.iter().map(|(k, v)| (k.clone(), v.clone())));
    profile.insert("ext".into(), Json::Ext(ext));
    profile
}

pub fn json_equal(a: &Object, b: &Object) -> bool {
    match (encode_json(a), encode_json(b)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

impl Server {
    pub(crate) fn authenticate(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<Json, RpcError> {
        let mut st = self.lock();
        // A revoked connection is closing: an auth read before the close was
        // queued must not sign it in again (revoke_connection_locked).
        if c.is_closing() {
            return Err(RpcError::new(CODE_DENIED, "This connection is closing"));
        }
        let scheme = parse_string(&req.params, "scheme", true)?;
        // A scheme this document defines but the server does not offer is
        // unsupported (§3.2), whatever else the request holds.
        match scheme.as_str() {
            "webauthn" => {
                if self.config.web_authn.is_none() {
                    return Err(RpcError::new(CODE_UNSUPPORTED, "Passkeys are disabled"));
                }
                if !st.passkeys_offered(&c.origin) {
                    return Err(RpcError::new(
                        CODE_UNSUPPORTED,
                        "Passkeys are not offered to this origin",
                    ));
                }
            }
            "email" => {
                if self.config.email_sender.is_none() {
                    return Err(RpcError::new(CODE_UNSUPPORTED, "Email sign-in is disabled"));
                }
            }
            "external" => {
                // This server has no sign-in page (§4.11.5).
                return Err(RpcError::new(
                    CODE_UNSUPPORTED,
                    "External sign-in is not offered",
                ));
            }
            "token" | "guest" => {}
            _ => {
                // A request that depends on a name the server does not know
                // is invalid_params (§1).
                return Err(invalid_params(format!(
                    "Unknown authentication scheme {}",
                    quote(&scheme)
                )));
            }
        }
        // A user_id is never empty, nor contains whitespace or control
        // characters (§2.4): requesting one that could be no user_id is
        // invalid_params, with any scheme.
        if req.params.contains_key("user_id") {
            let requested = parse_string(&req.params, "user_id", true)?;
            if !valid_id(&requested) {
                return Err(invalid_params(
                    "user_id must not be empty, or contain whitespace or control characters",
                ));
            }
        }
        match scheme.as_str() {
            "webauthn" => return st.authenticate_passkey(c, req),
            "email" => return st.authenticate_email(c, req),
            "token" => return st.authenticate_token(c, req),
            _ => {}
        }
        if let Some(user_id) = st.client_user(c) {
            // Guest auth on a signed-in connection answers with the identity
            // it has. It signs the connection in as no other user, so it is
            // no sign-in and sends nothing after its result (§4.5).
            let result = obj! {"you" => st.you_locked(&st.users[&user_id])};
            c.send_result(req, result.clone().into());
            return Ok(result.into());
        }
        // A requested name or user_id is not honored (§3.2 lets the server
        // assign identity), as apron-server-cloudflare's guests are not.
        let (id, number) = st.next_guest_id_locked();
        let user = st.new_user_locked(&id, &format!("Guest {number}"));
        st.users.insert(id.clone(), user);
        st.touch_user(&id);
        // A new guest joins the default room, so their room list is not
        // empty.
        Ok(st
            .switch_user_locked(c, req, &id, Object::new(), true, true)?
            .into())
    }

    pub(crate) fn update_profile(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        self.lock().update_profile_locked(c, req)
    }
}
