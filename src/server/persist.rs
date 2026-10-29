//! Persistence writes the server's state through to a `Store`. Every change
//! made under the lock marks what it changed (`touch_*`); when the lock is
//! released, `flush_locked` serializes the marked state into one batch, and
//! a single writer applies batches to the store in order, off the lock. At
//! start, `restore_locked` rebuilds the state from the store.
//!
//! Entry kinds and IDs:
//!
//! ```text
//! meta     "counters"   log_id, guest, embed, and upload sequences, and
//!                       the --role grants given
//! meta     "vapid"      the webpush VAPID private key (§4.9)
//! used_id  lowercased user_id ever assigned
//! record   log_id       a logged record and the rooms whose logs hold it
//! room     room_id
//! message  message_id
//! user     user_id      guests too, retired at the next start, and
//!                       /invite-bot bots, which Go takes for guests
//! session  hex SHA-256 of the bearer token
//! device   hex SHA-256 of the /invite-device token (an extension; Go
//!          ignores the kind)
//! bot      hex SHA-256 of the /invite-bot token (an extension; Go ignores
//!          the kind)
//! invite   hex SHA-256 of an account's /invite-token token (an extension;
//!          Go ignores the kind)
//! embed    embed_id
//! push     user_id, a space, and url
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rust_stdlib::encoding::hex;
use rust_stdlib::encoding::json::jsontext::Value;
use rust_stdlib::encoding::json::v2 as json;
use rust_stdlib::encoding::json::Bytes;
use rust_stdlib::log::slog;
use rust_stdlib::path;
use rust_stdlib::time::{self, Time};
use rust_stdlib_derive::{MarshalTo, UnmarshalFrom};

use super::bots::BotToken;
use super::devices::DeviceToken;
use super::embeds::{EmbedState, StreamBuffer};
use super::invites::{InviteToken, JoinInvite};
use super::messages::{MessageState, ReactionSet};
use super::protocol::*;
use super::push::{parse_wake_names, PushRegistration};
use super::rooms::{ReadCursor, RoomState};
use super::server::{LogRecord, RecordKind, Server, State};
use super::status::*;
use super::users::{valid_role, UserState, MAX_ROLES};
use super::webauthn::{PasskeyTimes, PasskeyUser, Session};
use super::webpush::{decode_base64_url, encode_base64_url, parse_push_keys, VapidKey};
use crate::store::{Entry, StoreError};
use crate::webauthn::Credential;

pub const ENTRY_META: &str = "meta";
pub const ENTRY_USED_ID: &str = "used_id";
pub const ENTRY_RECORD: &str = "record";
pub const ENTRY_ROOM: &str = "room";
pub const ENTRY_MESSAGE: &str = "message";
pub const ENTRY_USER: &str = "user";
pub const ENTRY_SESSION: &str = "session";
pub const ENTRY_DEVICE: &str = "device";
pub const ENTRY_BOT: &str = "bot";
pub const ENTRY_INVITE: &str = "invite";
pub const ENTRY_EMBED: &str = "embed";
pub const ENTRY_PUSH: &str = "push";

/// The state changed since the last batch, by key. A key missing from the
/// server's maps at flush time is deleted from the store.
#[derive(Debug, Default)]
pub struct DirtySet {
    pub records: BTreeSet<i64>,
    pub rooms: BTreeSet<String>,
    pub messages: BTreeSet<String>,
    pub users: BTreeSet<String>,
    pub sessions: BTreeSet<[u8; 32]>,
    pub devices: BTreeSet<[u8; 32]>,
    pub bots: BTreeSet<[u8; 32]>,
    pub invites: BTreeSet<[u8; 32]>,
    pub embeds: BTreeSet<String>,
    pub pushes: BTreeSet<String>,
    pub used_ids: Vec<String>,
    pub vapid: bool,
}

#[derive(Clone, Debug, Default, PartialEq, MarshalTo, UnmarshalFrom)]
pub struct StoredMeta {
    #[json("last_id")]
    pub last_id: i64,
    #[json("guest_number")]
    pub guest_number: u64,
    #[json("account_number,omitzero")]
    pub account_number: u64,
    #[json("embed_number")]
    pub embed_number: u64,
    #[json("upload_seq")]
    pub upload_seq: i64,
    /// `State.history_floor`, absent until retention discards a record. Go's
    /// decoder skips the member.
    #[json("history_floor,omitzero")]
    pub history_floor: i64,
    /// `State.rooms_removed_at`, absent until retention removes a thread.
    #[json("rooms_removed_at,omitzero")]
    pub rooms_removed_at: i64,
    /// `State.role_grants`, sorted.
    #[json("role_grants,omitzero")]
    pub role_grants: Vec<String>,
    /// `State.join_invite`: the hex SHA-256 of its token, the sign-ups it
    /// has left, and when it expires, in Unix milliseconds; absent without
    /// one.
    #[json("join_invite,omitzero")]
    pub join_invite: String,
    #[json("join_remaining,omitzero")]
    pub join_remaining: i64,
    #[json("join_expires,omitzero")]
    pub join_expires: i64,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredRecord {
    #[json("kind")]
    pub kind: i64,
    #[json("raw")]
    pub raw: Value,
    #[json("rooms")]
    pub rooms: Vec<String>,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredCursor {
    #[json("from")]
    pub from: Object,
    #[json("message_id")]
    pub message_id: String,
    #[json("id")]
    pub id: i64,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredRoom {
    #[json("parent,omitzero")]
    pub parent: String,
    #[json("private,omitzero")]
    pub private: bool,
    #[json("active,omitzero")]
    pub active: BTreeMap<String, i64>,
    #[json("record")]
    pub record: Value,
    #[json("record_log_id")]
    pub record_log_id: i64,
    #[json("created_id")]
    pub created_id: i64,
    #[json("latest_id")]
    pub latest_id: i64,
    #[json("members")]
    pub members: Vec<String>,
    #[json("creator,omitzero")]
    pub creator: String,
    #[json("reads,omitzero")]
    pub reads: BTreeMap<String, StoredCursor>,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredReaction {
    #[json("from")]
    pub from: Object,
    #[json("emojis")]
    pub emojis: Vec<String>,
    /// The record that logged the set, which retention reads; absent in
    /// stores written before it, and Go's decoder skips the member.
    #[json("log_id,omitzero")]
    pub log_id: i64,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredMessage {
    #[json("from")]
    pub from: Object,
    #[json("log_id")]
    pub log_id: i64,
    #[json("owner")]
    pub owner: String,
    #[json("room_id")]
    pub room_id: String,
    #[json("reactions,omitzero")]
    pub reactions: BTreeMap<String, StoredReaction>,
    #[json("records")]
    pub records: Vec<i64>,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredUser {
    #[json("name,omitzero")]
    pub name: String,
    #[json("avatar,omitzero")]
    pub avatar: String,
    #[json("ext,omitzero")]
    pub ext: ExtObject,
    #[json("avatar_embed,omitzero")]
    pub avatar_embed: String,
    #[json("left_at,omitzero")]
    pub left_at: BTreeMap<String, i64>,
    #[json("passkey,omitzero")]
    pub passkey: Option<StoredPasskey>,
    #[json("email,omitzero")]
    pub email: String,
    /// A bot's owner (bots.rs). Go's decoder skips the member.
    #[json("bot,omitzero")]
    pub bot: String,
    /// The user's roles (§3.3), in the order given. Go's decoder skips the
    /// member.
    #[json("roles,omitzero")]
    pub roles: Vec<String>,
    /// `UserState.invited`. Go's decoder skips the member.
    #[json("invited,omitzero")]
    pub invited: bool,
    /// The chosen status (§4.5.1), absent for online.
    #[json("status,omitzero")]
    pub status: Option<String>,
    /// The Unix milliseconds when the shown status others are sent last
    /// became offline, absent if unknown (§4.5.2).
    #[json("seen,omitzero")]
    pub seen: i64,
    /// True while that status is other than offline, which a restart after a
    /// crash finds still set.
    #[json("shown,omitzero")]
    pub shown: bool,
    #[json("mute,omitzero")]
    pub mute: Option<StoredMute>,
    #[json("room_mutes,omitzero")]
    pub room_mutes: BTreeMap<String, StoredMute>,
    /// The rooms they have not joined that count toward unread.
    #[json("pings,omitzero")]
    pub pings: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredPasskey {
    #[json("handle")]
    pub handle: Bytes,
    #[json("credentials")]
    pub credentials: Vec<Credential>,
    /// `PasskeyUser.times` by the base64url credential ID. Go's decoder
    /// skips the member.
    #[json("times,omitzero")]
    pub times: BTreeMap<String, StoredPasskeyTimes>,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredPasskeyTimes {
    #[json("added")]
    pub added: i64,
    #[json("used")]
    pub used: i64,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredPush {
    #[json("user")]
    pub user: String,
    #[json("kind")]
    pub kind: String,
    #[json("url,omitzero")]
    pub url: String,
    #[json("token,omitzero")]
    pub token: String,
    #[json("push_id,omitzero")]
    pub push_id: String,
    /// The hex SHA-256 of the /invite-device token the registering
    /// connection signed in with.
    #[json("device,omitzero")]
    pub device: String,
    /// The subscription's keys, in base64url.
    #[json("p256dh,omitzero")]
    pub p256dh: String,
    #[json("auth,omitzero")]
    pub auth: String,
    /// The registration's scopes.
    #[json("wake")]
    pub wake: Vec<String>,
    #[json("renewed,omitzero")]
    pub renewed: Time,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredSession {
    #[json("user")]
    pub user: String,
    #[json("origin")]
    pub origin: String,
    #[json("expires")]
    pub expires: Time,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredDevice {
    #[json("user")]
    pub user: String,
    #[json("name")]
    pub name: String,
    #[json("created")]
    pub created: Time,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredBot {
    #[json("bot")]
    pub bot: String,
    #[json("owner")]
    pub owner: String,
    #[json("created")]
    pub created: Time,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredInvite {
    #[json("user")]
    pub user: String,
    #[json("created")]
    pub created: Time,
}

/// The store ID of a session: the hex SHA-256 of its bearer token.
pub fn session_id(key: &[u8; 32]) -> String {
    hex::encode(key)
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredMute {
    #[json("forever,omitzero")]
    pub forever: bool,
    #[json("until,omitzero")]
    pub until: Time,
}

#[derive(Clone, Debug, Default, MarshalTo, UnmarshalFrom)]
pub struct StoredEmbed {
    #[json("kind")]
    pub kind: String,
    #[json("message_id,omitzero")]
    pub message_id: String,
    #[json("avatar_for,omitzero")]
    pub avatar_for: String,
    #[json("base_url")]
    pub base_url: String,
    #[json("secret")]
    pub secret: String,
    #[json("title,omitzero")]
    pub title: String,
    #[json("alt,omitzero")]
    pub alt: String,
    #[json("stream,omitzero")]
    pub stream: bool,
    #[json("finished,omitzero")]
    pub finished: bool,
    #[json("owned,omitzero")]
    pub owned: Object,
    /// The upload file's name within the upload directory.
    #[json("file,omitzero")]
    pub file: String,
    #[json("size,omitzero")]
    pub size: i64,
    #[json("content_type,omitzero")]
    pub content_type: String,
    #[json("seq,omitzero")]
    pub seq: i64,
}

impl State {
    /// The counters entry of the current state.
    pub fn meta_locked(&self) -> StoredMeta {
        StoredMeta {
            last_id: self.last_id,
            guest_number: self.guest_number,
            account_number: self.account_number,
            embed_number: self.embed_number,
            upload_seq: self.upload_seq,
            history_floor: self.history_floor,
            rooms_removed_at: self.rooms_removed_at,
            role_grants: self.role_grants.iter().cloned().collect(),
            join_invite: self
                .join_invite
                .as_ref()
                .map_or_else(String::new, |invite| session_id(&invite.key)),
            join_remaining: self
                .join_invite
                .as_ref()
                .map_or(0, |invite| invite.remaining),
            join_expires: self
                .join_invite
                .as_ref()
                .map_or(0, |invite| invite.expires_ms),
        }
    }

    /// Renders the state named by the dirty set as store entries.
    pub fn entries_locked(&self) -> Vec<Entry> {
        self.entries_for(&self.dirty)
    }

    pub fn entries_for(&self, d: &DirtySet) -> Vec<Entry> {
        let mut batch: Vec<Entry> = Vec::new();
        fn put<T: json::MarshalTo>(batch: &mut Vec<Entry>, kind: &str, id: &str, value: &T) {
            match encode_json(value) {
                Some(encoded) => batch.push(Entry::put(kind, id, encoded)),
                None => slog::error(
                    "cannot encode state for the store",
                    &[
                        "kind".into(),
                        slog::Value::from(kind).into(),
                        "id".into(),
                        slog::Value::from(id).into(),
                    ],
                ),
            }
        }
        for id in &d.used_ids {
            put(&mut batch, ENTRY_USED_ID, id, &true);
        }
        for id in &d.records {
            match self.records.get(id) {
                Some(r) => put(
                    &mut batch,
                    ENTRY_RECORD,
                    &format_id(r.id),
                    &StoredRecord {
                        kind: r.kind as i64,
                        raw: Value::from(r.raw.clone()),
                        rooms: r.rooms.clone(),
                    },
                ),
                None => batch.push(Entry::delete(ENTRY_RECORD, &format_id(*id))),
            }
        }
        for id in &d.rooms {
            match self.rooms.get(id) {
                Some(r) => put(&mut batch, ENTRY_ROOM, id, &self.stored_room_locked(r)),
                None => batch.push(Entry::delete(ENTRY_ROOM, id)),
            }
        }
        for id in &d.messages {
            match self.messages.get(id) {
                Some(m) => put(&mut batch, ENTRY_MESSAGE, id, &stored_message_of(m)),
                None => batch.push(Entry::delete(ENTRY_MESSAGE, id)),
            }
        }
        for id in &d.users {
            match self.users.get(id) {
                Some(u) => put(&mut batch, ENTRY_USER, id, &stored_user_of(u)),
                None => batch.push(Entry::delete(ENTRY_USER, id)),
            }
        }
        for key in &d.sessions {
            match self.sessions.get(key) {
                Some(session) => put(
                    &mut batch,
                    ENTRY_SESSION,
                    &session_id(key),
                    &StoredSession {
                        user: session.user.clone(),
                        origin: session.origin.clone(),
                        expires: session.expires.clone(),
                    },
                ),
                None => batch.push(Entry::delete(ENTRY_SESSION, &session_id(key))),
            }
        }
        for key in &d.devices {
            match self.devices.get(key) {
                Some(device) => put(
                    &mut batch,
                    ENTRY_DEVICE,
                    &session_id(key),
                    &StoredDevice {
                        user: device.user.clone(),
                        name: device.name.clone(),
                        created: device.created.clone(),
                    },
                ),
                None => batch.push(Entry::delete(ENTRY_DEVICE, &session_id(key))),
            }
        }
        for key in &d.bots {
            match self.bots.get(key) {
                Some(bot) => put(
                    &mut batch,
                    ENTRY_BOT,
                    &session_id(key),
                    &StoredBot {
                        bot: bot.bot.clone(),
                        owner: bot.owner.clone(),
                        created: bot.created.clone(),
                    },
                ),
                None => batch.push(Entry::delete(ENTRY_BOT, &session_id(key))),
            }
        }
        for key in &d.invites {
            match self.invites.get(key) {
                Some(invite) => put(
                    &mut batch,
                    ENTRY_INVITE,
                    &session_id(key),
                    &StoredInvite {
                        user: invite.user.clone(),
                        created: invite.created.clone(),
                    },
                ),
                None => batch.push(Entry::delete(ENTRY_INVITE, &session_id(key))),
            }
        }
        for id in &d.embeds {
            match self.embeds.get(id) {
                Some(e) => put(&mut batch, ENTRY_EMBED, id, &stored_embed_of(e)),
                None => batch.push(Entry::delete(ENTRY_EMBED, id)),
            }
        }
        for key in &d.pushes {
            match self.pushes.get(key) {
                Some(p) => {
                    let mut stored = StoredPush {
                        user: p.user_id.clone(),
                        kind: p.kind.clone(),
                        url: p.url.clone(),
                        token: p.token.clone(),
                        push_id: p.push_id.clone(),
                        wake: p.wake.names(),
                        renewed: p.renewed.clone(),
                        ..StoredPush::default()
                    };
                    if p.device != [0; 32] {
                        stored.device = session_id(&p.device);
                    }
                    if let Some(keys) = &p.keys {
                        stored.p256dh = encode_base64_url(&keys.p256dh);
                        stored.auth = encode_base64_url(&keys.auth);
                    }
                    put(&mut batch, ENTRY_PUSH, key, &stored);
                }
                None => batch.push(Entry::delete(ENTRY_PUSH, key)),
            }
        }
        if d.vapid && self.vapid_stored {
            if let Some(vapid) = &self.vapid {
                put(&mut batch, ENTRY_META, "vapid", &vapid.encoded());
            }
        }
        batch
    }

    pub fn stored_room_locked(&self, r: &RoomState) -> StoredRoom {
        StoredRoom {
            parent: r.parent.clone().unwrap_or_default(),
            private: r.private,
            active: r.active.clone(),
            record: Value::from(encode_json(&r.record).unwrap_or_default()),
            record_log_id: r.record_log_id,
            created_id: r.created_id,
            latest_id: r.latest_id,
            members: r.members.iter().cloned().collect(),
            creator: r.creator.clone(),
            reads: r
                .reads
                .iter()
                .map(|(id, c)| {
                    (
                        id.clone(),
                        StoredCursor {
                            from: c.from.clone(),
                            message_id: c.message_id.clone(),
                            id: c.id,
                        },
                    )
                })
                .collect(),
        }
    }
}

pub fn stored_embed_of(e: &EmbedState) -> StoredEmbed {
    StoredEmbed {
        kind: e.kind.clone(),
        message_id: e.message_id.clone(),
        avatar_for: e.avatar_for.clone().unwrap_or_default(),
        base_url: e.base_url.clone(),
        secret: e.secret.clone(),
        title: e.title.clone(),
        alt: e.alt.clone(),
        stream: e.stream.is_some(),
        finished: e.finished,
        owned: e.owned.clone(),
        file: if e.path.is_empty() {
            String::new()
        } else {
            path::base(&e.path).to_owned()
        },
        size: e.size,
        content_type: e.content_type.clone(),
        seq: e.seq,
    }
}

pub fn stored_message_of(m: &MessageState) -> StoredMessage {
    StoredMessage {
        from: m.from.clone(),
        log_id: m.log_id,
        owner: m.owner.clone(),
        room_id: m.room_id.clone(),
        reactions: m
            .reactions
            .iter()
            .map(|(id, set)| {
                (
                    id.clone(),
                    StoredReaction {
                        from: set.from.clone(),
                        emojis: set.emojis.clone(),
                        log_id: set.log_id,
                    },
                )
            })
            .collect(),
        records: m.records.clone(),
    }
}

pub fn stored_user_of(u: &UserState) -> StoredUser {
    let now = time::now();
    let mute_of = |m: &MuteState| StoredMute {
        forever: m.forever,
        until: m.until.clone(),
    };
    StoredUser {
        name: u.name.clone(),
        avatar: u.avatar.clone(),
        ext: u.ext.clone(),
        avatar_embed: u.avatar_embed.clone().unwrap_or_default(),
        left_at: u.left_at.clone(),
        passkey: u.passkey.as_ref().map(|p| StoredPasskey {
            handle: Bytes(p.handle.clone()),
            credentials: p.credentials.clone(),
            times: p
                .times
                .iter()
                .map(|(id, t)| {
                    let times = StoredPasskeyTimes {
                        added: t.added,
                        used: t.used,
                    };
                    (encode_base64_url(id), times)
                })
                .collect(),
        }),
        email: u.email.clone(),
        bot: u.owner.clone().unwrap_or_default(),
        roles: u.roles.clone(),
        invited: u.invited,
        status: if u.chosen != STATUS_ONLINE {
            Some(u.chosen.clone())
        } else {
            None
        },
        seen: u.seen,
        shown: u.status != STATUS_OFFLINE,
        mute: if u.mute.active(&now) {
            Some(mute_of(&u.mute))
        } else {
            None
        },
        room_mutes: u
            .room_mutes
            .iter()
            .filter(|(_, m)| m.active(&now))
            .map(|(id, m)| (id.clone(), mute_of(m)))
            .collect(),
        pings: u.pings.clone(),
    }
}

fn decode<T: json::UnmarshalFrom>(kind: &str, id: &str, raw: &[u8]) -> Result<T, StoreError> {
    let mut value = T::zero();
    json::unmarshal(raw, &mut value, &[]).map_err(|e| format!("stored {kind} {id:?}: {e}"))?;
    Ok(value)
}

impl Server {
    /// Sets the webpush VAPID key (§4.9): Config's, else the one in the
    /// store, else a new one, which is stored.
    fn restore_vapid_locked(st: &mut State, raw: Option<&Vec<u8>>) -> Result<(), StoreError> {
        if st.vapid.is_some() {
            return Ok(());
        }
        let key = match raw {
            Some(raw) => {
                let encoded = decode::<String>(ENTRY_META, "vapid", raw)
                    .map_err(|e| format!("stored VAPID key: {e}"))?;
                VapidKey::parse(&encoded).map_err(|e| format!("stored VAPID key: {e}"))?
            }
            None => {
                st.dirty.vapid = true;
                VapidKey::generate()?
            }
        };
        st.vapid = Some(Arc::new(key));
        st.vapid_stored = true;
        Ok(())
    }

    /// Rebuilds the server's state from the store's entries. It returns the
    /// upload files the restored embeds hold.
    pub(crate) fn restore_locked(&self, st: &mut State) -> Result<BTreeSet<String>, StoreError> {
        let mut entries: BTreeMap<String, BTreeMap<String, Vec<u8>>> = BTreeMap::new();
        self.store().load(&mut |e| {
            entries
                .entry(e.kind)
                .or_default()
                .insert(e.id, e.value.unwrap_or_default());
            Ok(())
        })?;
        let empty = BTreeMap::new();
        let of = |kind: &str| entries.get(kind).unwrap_or(&empty);

        if let Some(raw) = of(ENTRY_META).get("counters") {
            st.stored_meta = decode::<StoredMeta>(ENTRY_META, "counters", raw)?;
            st.last_id = st.stored_meta.last_id;
            st.guest_number = st.stored_meta.guest_number;
            st.account_number = st.stored_meta.account_number;
            st.embed_number = st.stored_meta.embed_number;
            st.upload_seq = st.stored_meta.upload_seq;
            st.history_floor = st.stored_meta.history_floor;
            st.rooms_removed_at = st.stored_meta.rooms_removed_at;
            st.role_grants = st.stored_meta.role_grants.iter().cloned().collect();
            st.join_invite = hex::decode(&st.stored_meta.join_invite)
                .ok()
                .and_then(|key| <[u8; 32]>::try_from(key).ok())
                .map(|key| JoinInvite {
                    key,
                    remaining: st.stored_meta.join_remaining,
                    expires_ms: st.stored_meta.join_expires,
                });
        }
        Server::restore_vapid_locked(st, of(ENTRY_META).get("vapid"))?;
        for id in of(ENTRY_USED_ID).keys() {
            st.used_ids.insert(id.clone());
        }

        let mut records: BTreeMap<i64, LogRecord> = BTreeMap::new();
        for (id, raw) in of(ENTRY_RECORD) {
            let stored = decode::<StoredRecord>(ENTRY_RECORD, id, raw)?;
            let log_id: i64 = id.parse().unwrap_or(0);
            let kind = RecordKind::from_i64(stored.kind)
                .ok_or_else(|| format!("stored record {id:?}: unknown kind {}", stored.kind))?;
            records.insert(
                log_id,
                LogRecord {
                    id: log_id,
                    kind,
                    raw: stored.raw.0,
                    rooms: stored.rooms,
                    message: String::new(),
                },
            );
        }

        let mut stored_rooms: BTreeMap<String, StoredRoom> = BTreeMap::new();
        for (id, raw) in of(ENTRY_ROOM) {
            let stored = decode::<StoredRoom>(ENTRY_ROOM, id, raw)?;
            st.rooms.insert(
                id.clone(),
                RoomState {
                    id: id.clone(),
                    record: decode_object(&stored.record.0).unwrap_or_default(),
                    record_log_id: stored.record_log_id,
                    created_id: stored.created_id,
                    latest_id: stored.latest_id,
                    creator: stored.creator.clone(),
                    private: stored.private,
                    active: stored.active.clone(),
                    ..RoomState::default()
                },
            );
            stored_rooms.insert(id.clone(), stored);
        }
        let mut order: Vec<String> = st.rooms.keys().cloned().collect();
        order.sort_by_key(|id| st.rooms[id].created_id);
        for id in &order {
            let stored = &stored_rooms[id];
            if !stored.parent.is_empty() && st.rooms.contains_key(&stored.parent) {
                st.rooms.get_mut(id).expect("room exists").parent = Some(stored.parent.clone());
                st.rooms
                    .get_mut(&stored.parent)
                    .expect("parent exists")
                    .children
                    .push(id.clone());
            }
            let r = st.rooms.get_mut(id).expect("room exists");
            for (user_id, cursor) in &stored.reads {
                r.reads.insert(
                    user_id.clone(),
                    ReadCursor {
                        from: cursor.from.clone(),
                        message_id: cursor.message_id.clone(),
                        id: cursor.id,
                    },
                );
            }
        }
        for (log_id, record) in &records {
            for room_id in &record.rooms {
                if let Some(r) = st.rooms.get_mut(room_id) {
                    r.log.push(*log_id);
                }
            }
        }

        for (id, raw) in of(ENTRY_MESSAGE) {
            let stored = decode::<StoredMessage>(ENTRY_MESSAGE, id, raw)?;
            let mut m = MessageState {
                id: id.clone(),
                from: stored.from,
                log_id: stored.log_id,
                owner: stored.owner,
                room_id: stored.room_id,
                ..MessageState::default()
            };
            for (user_id, set) in stored.reactions {
                m.reactions.insert(
                    user_id,
                    ReactionSet {
                        from: set.from,
                        emojis: set.emojis,
                        // A set stored without its record lives as long as
                        // the message's latest snapshot.
                        log_id: if set.log_id == 0 {
                            stored.log_id
                        } else {
                            set.log_id
                        },
                    },
                );
            }
            for log_id in stored.records {
                if let Some(record) = records.get_mut(&log_id) {
                    record.message = id.clone();
                    m.records.push(log_id);
                }
            }
            if m.records.is_empty() {
                // A message without its records cannot be served, and its
                // entry goes at the first write.
                st.touch_message(id);
                continue;
            }
            st.messages.insert(id.clone(), m);
        }
        st.records = records;

        let mut stored_users: BTreeMap<String, StoredUser> = BTreeMap::new();
        for (id, raw) in of(ENTRY_USER) {
            let stored = decode::<StoredUser>(ENTRY_USER, id, raw)?;
            let mut u = st.new_user_locked(id, &stored.name);
            u.avatar = stored.avatar.clone();
            u.ext = stored.ext.clone();
            if !stored.email.is_empty() {
                u.email = stored.email.clone();
                st.emails.insert(stored.email.clone(), id.clone());
            }
            if !stored.bot.is_empty() {
                u.owner = Some(stored.bot.clone());
            }
            u.invited = stored.invited;
            for role in &stored.roles {
                if valid_role(role) && !u.has_role(role) && u.roles.len() < MAX_ROLES {
                    u.roles.push(role.clone());
                }
            }
            u.left_at = stored.left_at.clone();
            match &stored.status {
                Some(status) if settable_status(status) => u.chosen = status.clone(),
                Some(_) => u.chosen = STATUS_NONE.into(),
                None => {}
            }
            u.seen = stored.seen;
            if let Some(mute) = &stored.mute {
                u.mute = MuteState {
                    forever: mute.forever,
                    until: mute.until.clone(),
                };
            }
            for (room_id, mute) in &stored.room_mutes {
                u.room_mutes.insert(
                    room_id.clone(),
                    MuteState {
                        forever: mute.forever,
                        until: mute.until.clone(),
                    },
                );
            }
            u.pings = stored.pings.clone();
            if let Some(passkey) = &stored.passkey {
                for credential in &passkey.credentials {
                    st.credentials.insert(credential.id.0.clone(), id.clone());
                }
                u.passkey = Some(PasskeyUser {
                    handle: passkey.handle.0.clone(),
                    credentials: passkey.credentials.clone(),
                    times: passkey
                        .times
                        .iter()
                        .filter_map(|(id, t)| {
                            let times = PasskeyTimes {
                                added: t.added,
                                used: t.used,
                            };
                            Some((decode_base64_url(id)?, times))
                        })
                        .collect(),
                });
            }
            st.users.insert(id.clone(), u);
            stored_users.insert(id.clone(), stored);
        }
        for id in &order {
            for user_id in &stored_rooms[id].members {
                if let Some(u) = st.users.get_mut(user_id) {
                    u.joined.insert(id.clone());
                    st.rooms
                        .get_mut(id)
                        .expect("room exists")
                        .members
                        .insert(user_id.clone());
                }
            }
        }
        let mut files: BTreeSet<String> = BTreeSet::new();
        for (id, raw) in of(ENTRY_EMBED) {
            let stored = decode::<StoredEmbed>(ENTRY_EMBED, id, raw)?;
            let mut e = EmbedState {
                id: id.clone(),
                kind: stored.kind,
                message_id: stored.message_id,
                avatar_for: Some(stored.avatar_for).filter(|u| st.users.contains_key(u)),
                base_url: stored.base_url,
                secret: stored.secret,
                title: stored.title,
                alt: stored.alt,
                finished: stored.finished,
                started: stored.finished,
                owned: stored.owned,
                size: stored.size,
                content_type: stored.content_type,
                seq: stored.seq,
                ..EmbedState::default()
            };
            if stored.stream {
                let stream =
                    StreamBuffer::new(st.config.stream_keep_bytes, st.config.stream_max_bytes);
                if stored.finished {
                    stream.end();
                }
                e.stream = Some(Arc::new(stream));
            }
            if !stored.file.is_empty() {
                e.path = path::join(&[st.upload_dir.as_str(), stored.file.as_str()]);
                files.insert(e.path.clone());
                st.uploads.insert((e.seq, id.clone()));
                st.upload_bytes += e.size;
            }
            st.embeds.insert(id.clone(), e);
        }
        for (id, stored) in &stored_users {
            if st.embeds.contains_key(&stored.avatar_embed) {
                if let Some(u) = st.users.get_mut(id) {
                    u.avatar_embed = Some(stored.avatar_embed.clone());
                }
            }
        }
        let now = time::now();
        // With push disabled, stored registrations stay in the store,
        // unused, for when push is enabled again.
        if !st.config.disable_push {
            for (key, raw) in of(ENTRY_PUSH) {
                let stored = decode::<StoredPush>(ENTRY_PUSH, key, raw)?;
                let mut p = PushRegistration {
                    user_id: stored.user.clone(),
                    kind: stored.kind,
                    url: stored.url,
                    token: stored.token,
                    push_id: stored.push_id,
                    wake: parse_wake_names(&stored.wake),
                    renewed: stored.renewed,
                    ..PushRegistration::default()
                };
                if !stored.p256dh.is_empty() {
                    let keys = parse_push_keys(&stored.p256dh, &stored.auth)
                        .map_err(|e| format!("stored push {key:?}: {e}"))?;
                    p.keys = Some(keys);
                }
                if let Some(device) = hex::decode(&stored.device)
                    .ok()
                    .and_then(|device| <[u8; 32]>::try_from(device).ok())
                {
                    p.device = device;
                }
                if st.users.contains_key(&stored.user) && p.live(&now) {
                    st.add_push_locked(p);
                } else {
                    st.touch_push(key);
                }
            }
        }

        for (id, raw) in of(ENTRY_SESSION) {
            let Some(key) = hex::decode(id)
                .ok()
                .and_then(|key| <[u8; 32]>::try_from(key).ok())
            else {
                continue;
            };
            let stored = decode::<StoredSession>(ENTRY_SESSION, id, raw)?;
            if st.users.get(&stored.user).is_some_and(|u| u.account())
                && now.before(&stored.expires)
            {
                st.sessions.insert(
                    key,
                    Session {
                        user: stored.user,
                        origin: stored.origin,
                        expires: stored.expires,
                    },
                );
            } else {
                st.touch_session(key);
            }
        }

        let mut devices = Vec::new();
        for (id, raw) in of(ENTRY_DEVICE) {
            let Some(key) = hex::decode(id)
                .ok()
                .and_then(|key| <[u8; 32]>::try_from(key).ok())
            else {
                continue;
            };
            let stored = decode::<StoredDevice>(ENTRY_DEVICE, id, raw)?;
            if st.users.get(&stored.user).is_some_and(|u| u.account()) {
                devices.push((key, stored));
            } else {
                st.touch_device(key);
            }
        }
        // Each account's tokens are kept oldest first.
        devices.sort_by_key(|(_, stored)| stored.created.unix_nano());
        for (key, stored) in devices {
            st.devices.insert(
                key,
                DeviceToken {
                    user: stored.user,
                    name: stored.name,
                    created: stored.created,
                },
            );
        }

        for (id, raw) in of(ENTRY_INVITE) {
            let Some(key) = hex::decode(id)
                .ok()
                .and_then(|key| <[u8; 32]>::try_from(key).ok())
            else {
                continue;
            };
            let stored = decode::<StoredInvite>(ENTRY_INVITE, id, raw)?;
            if st.users.get(&stored.user).is_some_and(|u| u.persists()) {
                st.invites.insert(
                    key,
                    InviteToken {
                        user: stored.user,
                        created: stored.created,
                    },
                );
            } else {
                st.touch_invite(key);
            }
        }

        // A bot holds one token. Batches apply whole, so a store never holds
        // two; one that does keeps the newest.
        let mut bots = Vec::new();
        for (id, raw) in of(ENTRY_BOT) {
            let Some(key) = hex::decode(id)
                .ok()
                .and_then(|key| <[u8; 32]>::try_from(key).ok())
            else {
                continue;
            };
            let stored = decode::<StoredBot>(ENTRY_BOT, id, raw)?;
            let owned = st
                .users
                .get(&stored.bot)
                .is_some_and(|u| u.owner.as_deref() == Some(stored.owner.as_str()));
            if owned {
                bots.push((key, stored));
            } else {
                st.touch_bot(key);
            }
        }
        bots.sort_by_key(|(_, stored)| stored.created.unix_nano());
        for (key, stored) in bots {
            if let Some(older) = st.bots.of_bot(&stored.bot) {
                st.bots.remove(&older);
                st.touch_bot(older);
            }
            st.bots.insert(
                key,
                BotToken {
                    bot: stored.bot,
                    owner: stored.owner,
                    created: stored.created,
                },
            );
        }

        // Nothing is connected yet: guests are retired as if their last
        // connections had just closed. An account stored as shown other than
        // offline was connected when the server stopped without closing its
        // connections, as in a crash; its shown status becomes offline now,
        // so seen is now (§4.5.2).
        let ids: Vec<String> = st.users.keys().cloned().collect();
        for id in ids {
            if !st.users[&id].persists() {
                st.retire_locked(&id);
                continue;
            }
            st.grant_roles_locked(&id);
            st.schedule_mute_locked(&id);
            let room_ids: Vec<String> = st.users[&id].room_mutes.keys().cloned().collect();
            for room_id in room_ids {
                st.schedule_room_mute_locked(&id, &room_id);
            }
            let attended = st.attended(&st.users[&id]);
            let u = st.users.get_mut(&id).expect("user exists");
            u.shown = u.shown_status(attended);
            u.status = u.shown.clone();
            if stored_users[&id].shown && u.shown == STATUS_OFFLINE {
                u.seen = now.unix_milli();
                st.touch_user(&id);
            }
        }
        // A write that was pending when the server stopped never finishes.
        let pending: Vec<String> = st
            .embeds
            .iter()
            .filter(|(_, e)| !e.finished)
            .map(|(id, _)| id.clone())
            .collect();
        for id in pending {
            st.fail_write_locked(&id);
        }
        Ok(files)
    }
}
