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
//! meta     "server"     the server's title, description and avatar as
//!                       `/server` set them (an extension)
//! meta     "emoji"      the custom emoji catalog (an extension)
//! used_id  lowercased user_id ever assigned
//! record   log_id       a logged record and the rooms whose logs hold it
//! room     room_id
//! message  message_id
//! user     user_id      guests too, retired at the next start, and
//!                       /invite-bot bots
//! session  hex SHA-256 of the bearer token
//! device   hex SHA-256 of the /invite-device token
//! bot      hex SHA-256 of the /invite-bot token
//! invite   hex SHA-256 of an account's /invite-token token
//! embed    embed_id
//! push     user_id, a space, and url
//! dedup    user_id, a space, and request id: an account's accepted
//!          request and its result (§1.2)
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;

use rust_stdlib::encoding::hex;
use rust_stdlib::encoding::json::jsontext::Value;
use rust_stdlib::encoding::json::v2 as json;
use rust_stdlib::encoding::json::Bytes;
use rust_stdlib::log::slog;
use rust_stdlib::path;
use rust_stdlib::time::{self, Time};
use rust_stdlib_derive::{MarshalTo, UnmarshalFrom};

use super::custom_emoji::StoredEmoji;
use super::embeds::{EmbedPurpose, EmbedState};
use super::messages::MessageState;
use super::metadata::StoredServer;
use super::protocol::*;
use super::push::PushRegistration;
use super::rooms::RoomState;
use super::server::State;
use super::status::*;
use super::users::UserState;
use super::webpush::encode_base64_url;
use crate::store::{Entry, Store, StoreError};
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
/// An accepted request's outcome (§1.2), keyed `<user_id> <request id>`.
pub const ENTRY_DEDUP: &str = "dedup";

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
    /// (user_id, request id) of deduplicated requests.
    pub dedup: BTreeSet<(String, String)>,
    pub used_ids: Vec<String>,
    pub vapid: bool,
    pub server: bool,
    pub emoji: bool,
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
    /// The features `/toggle` turned off, by name.
    #[json("features_off,omitzero")]
    pub features_off: Vec<String>,
    /// `State.bot_sweep_at`.
    #[json("bot_sweep,omitzero")]
    pub bot_sweep: i64,
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
    /// stores written before it.
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
    /// A bot's owner (bots.rs).
    #[json("bot,omitzero")]
    pub bot: String,
    /// The user's roles (§3.3), in the order given.
    #[json("roles,omitzero")]
    pub roles: Vec<String>,
    /// `UserState.invited`.
    #[json("invited,omitzero")]
    pub invited: bool,
    /// `UserState.active`.
    #[json("active,omitzero")]
    pub active: i64,
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
    /// `PasskeyUser.times` by the base64url credential ID.
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
pub struct StoredDedup {
    #[json("fingerprint")]
    pub fingerprint: String,
    #[json("at")]
    pub at: i64,
    #[json("result")]
    pub result: Value,
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
    /// The user whose `/avatar` the upload is.
    #[json("avatar_for,omitzero")]
    pub avatar_for: String,
    /// Set for the server's avatar (`/server avatar`).
    #[json("server_avatar,omitzero")]
    pub server_avatar: bool,
    /// The custom emoji key whose image the upload is (`/emoji add`).
    #[json("emoji,omitzero")]
    pub emoji: String,
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

/// The wait after a write the store refused, doubled after each further
/// refusal up to `STORE_RETRY_MAX`.
const STORE_RETRY_MIN: std::time::Duration = std::time::Duration::from_millis(100);
const STORE_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(30);

/// Applies the batches from `rx` to `store` in order until the sender is
/// dropped. A refused write is kept, keyed by kind and ID, and the next
/// batch is merged over it, so a later put or delete of the same entry
/// wins. What is kept is written again with the next batch, after a backoff,
/// or at shutdown, and logged if even that last write fails.
pub(super) fn write_store(store: Arc<dyn Store>, rx: Receiver<Vec<Entry>>) {
    let mut pending: BTreeMap<(String, String), Option<Vec<u8>>> = BTreeMap::new();
    let mut retry: Option<std::time::Duration> = None;
    loop {
        let batch = match retry {
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(wait) => rx.recv_timeout(wait),
        };
        match batch {
            Ok(batch) => {
                for e in batch {
                    pending.insert((e.kind, e.id), e.value);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        match write_pending(store.as_ref(), &mut pending) {
            Ok(()) => retry = None,
            Err(e) => {
                let wait = retry.map_or(STORE_RETRY_MIN, |r| (r * 2).min(STORE_RETRY_MAX));
                retry = Some(wait);
                slog::error(
                    "cannot write to the store; will retry",
                    &[
                        "error".into(),
                        slog::Value::from(e.to_string()).into(),
                        "entries".into(),
                        slog::Value::from(pending.len()).into(),
                        "retry".into(),
                        slog::Value::from(format!("{wait:?}")).into(),
                    ],
                );
            }
        }
    }
    if let Err(e) = write_pending(store.as_ref(), &mut pending) {
        let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
        for (kind, _) in pending.keys() {
            *kinds.entry(kind).or_default() += 1;
        }
        let kinds: Vec<String> = kinds.iter().map(|(k, n)| format!("{k}={n}")).collect();
        slog::error(
            "cannot write to the store at shutdown; changes lost",
            &[
                "error".into(),
                slog::Value::from(e.to_string()).into(),
                "entries".into(),
                slog::Value::from(pending.len()).into(),
                "kinds".into(),
                slog::Value::from(kinds.join(" ")).into(),
            ],
        );
    }
}

/// Writes `pending` as one batch and empties it, or keeps it on failure.
fn write_pending(
    store: &dyn Store,
    pending: &mut BTreeMap<(String, String), Option<Vec<u8>>>,
) -> Result<(), StoreError> {
    if pending.is_empty() {
        return Ok(());
    }
    let batch: Vec<Entry> = pending
        .iter()
        .map(|((kind, id), value)| Entry {
            kind: kind.clone(),
            id: id.clone(),
            value: value.clone(),
        })
        .collect();
    store.apply(&batch)?;
    pending.clear();
    Ok(())
}

/// The entries of one write to the store.
#[derive(Default)]
struct Batch(Vec<Entry>);

impl Batch {
    fn put<T: json::MarshalTo>(&mut self, kind: &str, id: &str, value: &T) {
        match encode_json(value) {
            Some(encoded) => self.0.push(Entry::put(kind, id, encoded)),
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

    /// Puts `value` under `id`, or deletes the entry without one.
    fn put_or_delete<T: json::MarshalTo>(&mut self, kind: &str, id: &str, value: Option<T>) {
        match value {
            Some(value) => self.put(kind, id, &value),
            None => self.0.push(Entry::delete(kind, id)),
        }
    }

    /// Writes each of `ids` of `kind` as the store keeps it, under
    /// `store_id(id)`: `stored(id)` when it still exists, else a delete.
    fn sync<'a, I: ?Sized + 'a, T: json::MarshalTo>(
        &mut self,
        kind: &str,
        ids: impl IntoIterator<Item = &'a I>,
        store_id: impl Fn(&I) -> String,
        stored: impl Fn(&I) -> Option<T>,
    ) {
        for id in ids {
            self.put_or_delete(kind, &store_id(id), stored(id));
        }
    }
}

/// A push registration as the store keeps it.
fn stored_push_of(p: &PushRegistration) -> StoredPush {
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
    stored
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
            features_off: self
                .features_off
                .iter()
                .map(|f| f.name().to_owned())
                .collect(),
            bot_sweep: self.bot_sweep_at,
        }
    }

    /// Renders the state named by the dirty set as store entries.
    pub fn entries_locked(&self) -> Vec<Entry> {
        self.entries_for(&self.dirty)
    }

    pub fn entries_for(&self, d: &DirtySet) -> Vec<Entry> {
        let DirtySet {
            records,
            rooms,
            messages,
            users,
            sessions,
            devices,
            bots,
            invites,
            embeds,
            pushes,
            dedup,
            used_ids,
            vapid,
            server,
            emoji,
        } = d;
        let mut batch = Batch::default();
        for id in used_ids {
            batch.put(ENTRY_USED_ID, id, &true);
        }
        batch.sync(
            ENTRY_RECORD,
            records,
            |id| format_id(*id),
            |id| {
                self.records.get(id).map(|r| StoredRecord {
                    kind: r.kind as i64,
                    raw: Value::from(r.raw.clone()),
                    rooms: r.rooms.clone(),
                })
            },
        );
        batch.sync(ENTRY_ROOM, rooms, String::clone, |id| {
            self.rooms.get(id).map(|r| self.stored_room_locked(r))
        });
        batch.sync(ENTRY_MESSAGE, messages, String::clone, |id| {
            self.messages.get(id).map(stored_message_of)
        });
        batch.sync(ENTRY_USER, users, String::clone, |id| {
            self.users.get(id).map(stored_user_of)
        });
        batch.sync(ENTRY_SESSION, sessions, session_id, |key| {
            self.sessions.get(key).map(|session| StoredSession {
                user: session.user.clone(),
                origin: session.origin.clone(),
                expires: session.expires.clone(),
            })
        });
        batch.sync(ENTRY_DEVICE, devices, session_id, |key| {
            self.devices.get(key).map(|device| StoredDevice {
                user: device.user.clone(),
                name: device.name.clone(),
                created: device.created.clone(),
            })
        });
        batch.sync(ENTRY_BOT, bots, session_id, |key| {
            self.bots.get(key).map(|bot| StoredBot {
                bot: bot.bot.clone(),
                owner: bot.owner.clone(),
                created: bot.created.clone(),
            })
        });
        batch.sync(ENTRY_INVITE, invites, session_id, |key| {
            self.invites.get(key).map(|invite| StoredInvite {
                user: invite.user.clone(),
                created: invite.created.clone(),
            })
        });
        batch.sync(ENTRY_EMBED, embeds, String::clone, |id| {
            self.embeds.get(id).map(stored_embed_of)
        });
        batch.sync(ENTRY_PUSH, pushes, String::clone, |key| {
            self.pushes.get(key).map(stored_push_of)
        });
        batch.sync(
            ENTRY_DEDUP,
            dedup,
            |(user_id, request_id)| format!("{user_id} {request_id}"),
            |(user_id, request_id)| {
                let u = self.users.get(user_id).filter(|u| u.persists())?;
                let e = u.dedup.get(request_id)?;
                let result = e.result()?;
                Some(StoredDedup {
                    fingerprint: hex::encode(&e.fingerprint),
                    at: e.at,
                    result: Value::from(encode_json(&result)?),
                })
            },
        );
        if *server {
            let stored = self.server_meta.clone();
            let stored = (stored != StoredServer::default()).then_some(stored);
            batch.put_or_delete(ENTRY_META, "server", stored);
        }
        if *emoji {
            let stored = self.stored_emoji();
            let stored = (stored != StoredEmoji::default()).then_some(stored);
            batch.put_or_delete(ENTRY_META, "emoji", stored);
        }
        if *vapid && self.vapid_stored {
            if let Some(vapid) = &self.vapid {
                batch.put(ENTRY_META, "vapid", &vapid.encoded());
            }
        }
        batch.0
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
        avatar_for: match &e.purpose {
            EmbedPurpose::Avatar(user_id) => user_id.clone(),
            _ => String::new(),
        },
        server_avatar: e.purpose == EmbedPurpose::ServerAvatar,
        emoji: match &e.purpose {
            EmbedPurpose::Emoji(key) => key.clone(),
            _ => String::new(),
        },
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
        active: u.active,
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
