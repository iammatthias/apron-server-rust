//! Rebuilding the server's state from the store's entries at startup
//! (`Server::restore_locked`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rust_stdlib::encoding::hex;
use rust_stdlib::encoding::json::v2 as json;
use rust_stdlib::path;
use rust_stdlib::time::{self};

use super::bots::{BotToken, BOT_ROLE};
use super::custom_emoji::StoredEmoji;
use super::devices::DeviceToken;
use super::embeds::{EmbedPurpose, EmbedState};
use super::emoji::normalize_entries;
use super::invites::{InviteToken, JoinInvite};
use super::messages::{MessageState, ReactionSet};
use super::metadata::StoredServer;
use super::persist::{
    StoredBot, StoredDedup, StoredDevice, StoredEmbed, StoredInvite, StoredMessage, StoredMeta,
    StoredPush, StoredRecord, StoredRoom, StoredSession, StoredUser, ENTRY_BOT, ENTRY_DEDUP,
    ENTRY_DEVICE, ENTRY_EMBED, ENTRY_INVITE, ENTRY_MESSAGE, ENTRY_META, ENTRY_PUSH, ENTRY_RECORD,
    ENTRY_ROOM, ENTRY_SESSION, ENTRY_USED_ID, ENTRY_USER,
};
use super::protocol::*;
use super::push::{parse_wake_names, PushRegistration};
use super::rooms::{ReadCursor, RoomState};
use super::server::{LogRecord, RecordKind, Server, State};
use super::status::*;
use super::streams::StreamBuffer;
use super::toggles::Feature;
use super::users::{valid_role, MAX_ROLES};
use super::webauthn::{PasskeyTimes, PasskeyUser, Session};
use super::webpush::{decode_base64_url, parse_push_keys, VapidKey};
use crate::store::StoreError;

/// The key a token entry's id encodes (`session_id`), if any.
fn token_key(id: &str) -> Option<[u8; 32]> {
    hex::decode(id).ok().and_then(|key| key.try_into().ok())
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
            st.bot_sweep_at = st.stored_meta.bot_sweep;
            st.features_off = st
                .stored_meta
                .features_off
                .iter()
                .filter_map(|name| Feature::named(name))
                .collect();
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

        let mut migrated: Vec<String> = Vec::new();
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
                // Sets stored before entries were qualified (§4.7) are
                // qualified as they load, and kept so at the next save.
                let emojis = normalize_entries(set.emojis.iter().cloned());
                if emojis != set.emojis {
                    migrated.push(id.clone());
                }
                m.reactions.insert(
                    user_id,
                    ReactionSet {
                        from: set.from,
                        emojis,
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
        for id in migrated {
            st.touch_message(&id);
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
            u.active = stored.active;
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
                purpose: if stored.server_avatar {
                    EmbedPurpose::ServerAvatar
                } else if !stored.emoji.is_empty() {
                    EmbedPurpose::Emoji(stored.emoji)
                } else if st.users.contains_key(&stored.avatar_for) {
                    EmbedPurpose::Avatar(stored.avatar_for)
                } else {
                    EmbedPurpose::Message
                },
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
        if let Some(raw) = of(ENTRY_META).get("emoji") {
            st.restore_emoji(decode::<StoredEmoji>(ENTRY_META, "emoji", raw)?);
        }
        if let Some(raw) = of(ENTRY_META).get("server") {
            st.server_meta = decode::<StoredServer>(ENTRY_META, "server", raw)?;
            if !st.embeds.contains_key(&st.server_meta.avatar_embed) {
                st.server_meta.avatar_embed.clear();
            }
        }
        for (id, stored) in &stored_users {
            let Some(u) = st.users.get_mut(id) else {
                continue;
            };
            // An avatar comes only from /avatar, so one set by URL before
            // that rule, or whose upload is gone, is dropped.
            if st.embeds.contains_key(&stored.avatar_embed) {
                u.avatar_embed = Some(stored.avatar_embed.clone());
            } else {
                u.avatar.clear();
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

        // Kept oldest first, so each user's window drops its oldest.
        let mut dedups: Vec<(i64, String, String, StoredDedup)> = Vec::new();
        for (key, raw) in of(ENTRY_DEDUP) {
            let stored = decode::<StoredDedup>(ENTRY_DEDUP, key, raw)?;
            let (user_id, request_id) = key.split_once(' ').unwrap_or((key, ""));
            dedups.push((stored.at, user_id.to_owned(), request_id.to_owned(), stored));
        }
        dedups.sort_by_key(|d| d.0);
        for (_, user_id, request_id, stored) in dedups {
            let fingerprint = hex::decode(&stored.fingerprint)
                .ok()
                .and_then(|f| <[u8; 32]>::try_from(f).ok());
            let mut result = Json::Null;
            let decoded = json::unmarshal(&stored.result.0, &mut result, &[]).is_ok();
            let entry = fingerprint.filter(|_| decoded).map(|fingerprint| {
                Arc::new(super::dedup::DedupEntry::finished(
                    fingerprint,
                    stored.at,
                    result,
                ))
            });
            let fresh = time::now().unix_milli() - stored.at < super::dedup::DEDUP_WINDOW_MS;
            match (entry, st.users.get_mut(&user_id)) {
                (Some(entry), Some(u)) if fresh && u.persists() => {
                    for dropped in u.dedup.put(&request_id, entry) {
                        st.dirty.dedup.insert((user_id.clone(), dropped));
                    }
                }
                _ => {
                    st.dirty.dedup.insert((user_id, request_id));
                }
            }
        }

        for (id, raw) in of(ENTRY_SESSION) {
            let Some(key) = token_key(id) else {
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
            let Some(key) = token_key(id) else {
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
                    used: stored.used,
                },
            );
        }

        for (id, raw) in of(ENTRY_INVITE) {
            let Some(key) = token_key(id) else {
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
            let Some(key) = token_key(id) else {
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
            if let Some(older) = st.bots.last_of(&stored.bot) {
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
            // A bot stored before activity was kept counts as active now,
            // unless the sweep signed it out, taking its tokens.
            let u = &st.users[&id];
            if u.roles == [BOT_ROLE]
                && u.active == 0
                && (st.bots.last_of(&id).is_some() || st.invites.last_of(&id).is_some())
            {
                st.users.get_mut(&id).expect("user exists").active = now.unix_milli();
                st.touch_user(&id);
            }
            st.schedule_mute_locked(&id);
            let room_ids: Vec<String> = st.users[&id].room_mutes.keys().cloned().collect();
            for room_id in room_ids {
                st.schedule_room_mute_locked(&id, &room_id);
            }
            st.note_shown_locked(&id);
            let u = st.users.get_mut(&id).expect("user exists");
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
