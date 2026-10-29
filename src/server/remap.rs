//! The one walk over every place `State` keeps a user_id, which `/purge`
//! (purge.rs) and `/rename` (rename.rs) share. `remap_fields_locked` names
//! every `State` field, so a new one does not compile until it is handled
//! here or marked as holding no user_id; the purge and rename tests then
//! check the result against `tests::purge_test::traces`, which walks the
//! same fields.

use std::collections::{BTreeMap, BTreeSet};

use super::embeds::EmbedPurpose;
use super::protocol::*;
use super::server::{RecordKind, State};

/// What a walk does to the user_ids it meets.
pub(super) enum Remap<'a> {
    /// Deletes these users and what they left.
    Drop(&'a BTreeSet<String>),
    /// Moves everything under `from` to `to`.
    Rename { from: &'a str, to: &'a str },
}

/// What a walk does to one user_id.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Fate<'a> {
    Keep,
    Drop,
    Rename(&'a str),
}

impl<'a> Remap<'a> {
    pub(super) fn fate(&self, user_id: &str) -> Fate<'a> {
        match *self {
            Remap::Drop(ids) if ids.contains(user_id) => Fate::Drop,
            Remap::Rename { from, to } if from == user_id => Fate::Rename(to),
            _ => Fate::Keep,
        }
    }

    /// The user_ids the walk drops or moves away from.
    pub(super) fn sources(&self) -> Vec<&'a str> {
        match *self {
            Remap::Drop(ids) => ids.iter().map(String::as_str).collect(),
            Remap::Rename { from, .. } => vec![from],
        }
    }
}

/// The list of user objects a logged record keeps, and each element's key
/// for the user: a reactions record's sets and a membership record's
/// members. A message snapshot names one user, its `from`.
fn user_list(kind: RecordKind) -> Option<(&'static str, &'static str)> {
    match kind {
        RecordKind::Reactions => Some(("reactions", "from")),
        RecordKind::Membership => Some(("members", "user")),
        RecordKind::Message | RecordKind::Room => None,
    }
}

/// The user_id of a user object in a record, empty when there is none.
fn user_id_in(element: Option<&Json>) -> &str {
    element
        .and_then(Json::as_object)
        .and_then(|user| user.get("user_id"))
        .and_then(Json::as_str)
        .unwrap_or("")
}

/// Points a user object at `to`, keeping its name.
fn rename_user(user: &mut Json, to: &str) {
    if let Some(user) = user.as_object_mut() {
        user.insert("user_id".into(), to.into());
    }
}

/// What the walk does to a logged record.
enum Edit {
    Keep,
    Rewrite(Object),
    Delete,
}

/// A logged record with `remap` applied: a message snapshot whose sender
/// goes is deleted, and a list loses the users who go, or all of them when
/// its message (one of `gone`) goes, and is deleted once empty.
fn edit_record(
    kind: RecordKind,
    mut value: Object,
    remap: &Remap,
    gone: &BTreeSet<String>,
) -> Edit {
    if kind == RecordKind::Message {
        return match remap.fate(user_id_in(value.get("from"))) {
            Fate::Keep => Edit::Keep,
            Fate::Drop => Edit::Delete,
            Fate::Rename(to) => {
                rename_user(value.get_mut("from").expect("named"), to);
                Edit::Rewrite(value)
            }
        };
    }
    let Some((list, key)) = user_list(kind) else {
        return Edit::Keep;
    };
    let message_gone = value
        .get("message_id")
        .and_then(Json::as_str)
        .is_some_and(|id| gone.contains(id));
    let elements = value.get(list).map(Json::as_list).unwrap_or(&[]);
    let mut changed = message_gone && !elements.is_empty();
    let mut kept = Vec::new();
    for e in elements.iter().filter(|_| !message_gone) {
        match remap.fate(user_id_in(e.as_object().and_then(|e| e.get(key)))) {
            Fate::Keep => kept.push(e.clone()),
            Fate::Drop => changed = true,
            Fate::Rename(to) => {
                let mut e = e.clone();
                if let Some(user) = e.as_object_mut().and_then(|e| e.get_mut(key)) {
                    rename_user(user, to);
                }
                kept.push(e);
                changed = true;
            }
        }
    }
    if !changed {
        Edit::Keep
    } else if kept.is_empty() {
        Edit::Delete
    } else {
        value.insert(list.to_owned(), Json::Array(kept));
        Edit::Rewrite(value)
    }
}

impl State {
    /// Applies `remap` everywhere a user_id is kept. A dropped user's
    /// messages (`gone`, which the caller lists) go with every reaction set
    /// on them and their hosted uploads; so do their reaction sets
    /// elsewhere, memberships, read cursors, avatars, passkeys, addresses,
    /// address proposals, bot, device and invite tokens, push registrations
    /// and wakes, limits and accepted requests; logged records that list
    /// them beside others are rewritten without them; rooms they created
    /// stay, without a creator; their connections close. A renamed user's
    /// all move, and their logged records are rewritten to the new user_id.
    /// Sessions go either way. Neither touches `used_ids`, so a user_id is
    /// never reissued.
    pub(super) fn remap_users_locked(&mut self, remap: &Remap, gone: &BTreeSet<String>) {
        self.remap_fields_locked(remap, gone);
        match *remap {
            Remap::Drop(ids) => {
                for id in gone {
                    self.remove_message_locked(id);
                }
                let avatars: Vec<String> = self
                    .embeds
                    .values()
                    .filter(|e| matches!(&e.purpose, EmbedPurpose::Avatar(id) if ids.contains(id)))
                    .map(|e| e.id.clone())
                    .collect();
                for id in avatars {
                    self.remove_embed_locked(&id);
                }
                for id in ids {
                    self.stop_timers_locked(id);
                    let u = self.users.remove(id).expect("dropped users exist");
                    self.touch_user(id);
                    for (request_id, _) in u.dedup.iter() {
                        self.dirty.dedup.insert((id.clone(), request_id.clone()));
                    }
                    // The user is gone, so closing announces nothing and
                    // logs no leave.
                    for client in u.clients {
                        self.revoke_connection_locked(
                            client,
                            RpcError::new(CODE_DENIED, super::purge::PURGED),
                        );
                    }
                }
            }
            Remap::Rename { from, to } => {
                self.stop_timers_locked(from);
                let mut u = self.users.remove(from).expect("renamed users exist");
                u.id = to.to_owned();
                for (request_id, _) in u.dedup.iter() {
                    self.dirty
                        .dedup
                        .insert((from.to_owned(), request_id.clone()));
                    self.dirty.dedup.insert((to.to_owned(), request_id.clone()));
                }
                let room_mutes: Vec<String> = u.room_mutes.keys().cloned().collect();
                self.users.insert(to.to_owned(), u);
                self.touch_user(from);
                self.touch_user(to);
                self.schedule_mute_locked(to);
                for room_id in room_mutes {
                    self.schedule_room_mute_locked(to, &room_id);
                }
            }
        }
    }

    /// The part of `remap_users_locked` that only rewrites data, field by
    /// field. Dropping messages, avatars and users, which stops timers,
    /// deletes files and closes connections, is left to the caller.
    fn remap_fields_locked(&mut self, remap: &Remap, gone: &BTreeSet<String>) {
        let State {
            records,
            rooms,
            messages,
            users,
            clients,
            embeds,
            sessions,
            credentials,
            emails,
            email,
            devices,
            bots,
            invites,
            pushes,
            push_woken,
            pending_wakes,
            limits,
            dirty,
            // remap_users_locked drops and moves the users themselves, their
            // messages and avatars.

            // A user_id stays used, so it is never reissued.
            used_ids: _,
            // Config.roles grants, by the holder Config names; /rename gives
            // the new user_id the grants Config holds for it.
            granted_ids: _,
            role_grants: _,
            // No user_id.
            server: _,
            config: _,
            last_id: _,
            history_floor: _,
            rooms_removed_at: _,
            guest_number: _,
            account_number: _,
            embed_number: _,
            writes: _,
            uploads: _,
            upload_bytes: _,
            upload_seq: _,
            upload_dir: _,
            temp_upload_dir: _,
            next_generation: _,
            store_closed: _,
            stored_meta: _,
            closed: _,
            join_invite: _,
            features_off: _,
            server_meta: _,
            emoji: _,
            bot_sweep_at: _,
            vapid: _,
            vapid_stored: _,
            badge_delay: _,
            badges: _,
            next_wake: _,
            push_coalesce: _,
            joined_coalesce: _,
            push: _,
            unfurler: _,
        } = self;

        let mut deleted = Vec::new();
        for (log_id, record) in records.iter_mut() {
            match edit_record(record.kind, record.value(), remap, gone) {
                Edit::Keep => {}
                Edit::Delete => deleted.push(*log_id),
                Edit::Rewrite(value) => {
                    record.rewrite(|v| *v = value);
                    dirty.records.insert(*log_id);
                }
            }
        }
        for log_id in deleted {
            let record = records.remove(&log_id).expect("listed above");
            dirty.records.insert(log_id);
            for room_id in &record.rooms {
                if let Some(r) = rooms.get_mut(room_id) {
                    r.log.retain(|id| *id != log_id);
                    dirty.rooms.insert(room_id.clone());
                }
            }
        }

        for (room_id, r) in rooms.iter_mut() {
            let mut changed = false;
            for id in remap.sources() {
                let fate = remap.fate(id);
                let member = r.members.remove(id);
                let active = r.active.remove(id);
                let read = r.reads.remove(id);
                changed |= member || active.is_some() || read.is_some();
                if let Fate::Rename(to) = fate {
                    if member {
                        r.members.insert(to.to_owned());
                    }
                    if let Some(at) = active {
                        r.active.insert(to.to_owned(), at);
                    }
                    if let Some(mut cursor) = read {
                        cursor.from.insert("user_id".into(), to.into());
                        r.reads.insert(to.to_owned(), cursor);
                    }
                }
            }
            match remap.fate(&r.creator) {
                Fate::Keep => {}
                Fate::Drop => {
                    r.creator.clear();
                    changed = true;
                }
                Fate::Rename(to) => {
                    r.creator = to.to_owned();
                    changed = true;
                }
            }
            if changed {
                dirty.rooms.insert(room_id.clone());
            }
        }

        for (message_id, m) in messages.iter_mut() {
            let mut changed = false;
            if let Fate::Rename(to) = remap.fate(&m.owner) {
                m.owner = to.to_owned();
                m.from.insert("user_id".into(), to.into());
                changed = true;
            }
            for id in remap.sources() {
                let Some(mut set) = m.reactions.remove(id) else {
                    continue;
                };
                changed = true;
                if let Fate::Rename(to) = remap.fate(id) {
                    set.from.insert("user_id".into(), to.into());
                    m.reactions.insert(to.to_owned(), set);
                }
            }
            if changed {
                dirty.messages.insert(message_id.clone());
            }
        }

        for (id, e) in embeds.iter_mut() {
            if let Fate::Rename(to) = remap.fate(&e.uploader) {
                e.uploader = to.to_owned();
            }
            if let EmbedPurpose::Avatar(user_id) = &e.purpose {
                if let Fate::Rename(to) = remap.fate(user_id) {
                    e.purpose = EmbedPurpose::Avatar(to.to_owned());
                    dirty.embeds.insert(id.clone());
                }
            }
        }

        for (id, u) in users.iter_mut() {
            if let Some(Fate::Rename(to)) = u.owner.as_deref().map(|o| remap.fate(o)) {
                u.owner = Some(to.to_owned());
                dirty.users.insert(id.clone());
            }
        }
        if let Remap::Rename { from, to } = *remap {
            for id in &users[from].clients {
                if let Some(conn) = clients.get_mut(id) {
                    conn.user = Some(to.to_owned());
                }
            }
        }

        dirty.sessions.extend(sessions.remap(remap));
        dirty.devices.extend(devices.remap_holders(remap));
        dirty.invites.extend(invites.remap_holders(remap));
        dirty.bots.extend(bots.remap(remap));
        limits.remap(remap);
        super::wake::remap_wakes(pending_wakes, remap);
        email.remap_proposals(remap);

        remap_values(credentials, remap);
        remap_values(emails, remap);

        let moved: Vec<String> = pushes
            .iter()
            .filter(|(_, p)| remap.fate(&p.user_id) != Fate::Keep)
            .map(|(key, _)| key.clone())
            .collect();
        for key in moved {
            let mut p = pushes.remove(&key).expect("listed above");
            dirty.pushes.insert(key);
            if let Fate::Rename(to) = remap.fate(&p.user_id) {
                p.user_id = to.to_owned();
                let key = super::push::push_key(to, &p.url);
                pushes.insert(key.clone(), p);
                dirty.pushes.insert(key);
            }
        }

        let woken: Vec<(String, String)> = push_woken
            .keys()
            .filter(|(id, _)| remap.fate(id) != Fate::Keep)
            .cloned()
            .collect();
        for key in woken {
            let at = push_woken.remove(&key).expect("listed above");
            if let Fate::Rename(to) = remap.fate(&key.0) {
                push_woken.insert((to.to_owned(), key.1), at);
            }
        }
    }
}

/// Applies `remap` to a map whose values are user_ids.
fn remap_values<K: Ord>(map: &mut BTreeMap<K, String>, remap: &Remap) {
    map.retain(|_, id| remap.fate(id) != Fate::Drop);
    for id in map.values_mut() {
        if let Fate::Rename(to) = remap.fate(id) {
            *id = to.to_owned();
        }
    }
}

#[cfg(test)]
impl State {
    /// Every user_id kept in memory, as (place, text holding it), for the
    /// purge and rename tests (`tests::purge_test::traces`), which find the
    /// rest in the store dump. It names every field, as
    /// `remap_fields_locked` does, so a new one is placed in both.
    pub(super) fn user_id_places(&self) -> Vec<(&'static str, String)> {
        let State {
            users,
            clients,
            credentials,
            emails,
            email,
            push_woken,
            pending_wakes: _, // waking_users
            limits,
            messages,
            embeds,
            // In the store dump.
            records: _,
            rooms: _,
            sessions: _,
            devices: _,
            bots: _,
            invites: _,
            pushes: _,
            used_ids: _,
            role_grants: _,
            dirty: _,
            // Config's.
            granted_ids: _,
            // No user_id.
            server: _,
            config: _,
            last_id: _,
            history_floor: _,
            rooms_removed_at: _,
            guest_number: _,
            account_number: _,
            embed_number: _,
            writes: _,
            uploads: _,
            upload_bytes: _,
            upload_seq: _,
            upload_dir: _,
            temp_upload_dir: _,
            next_generation: _,
            store_closed: _,
            stored_meta: _,
            closed: _,
            join_invite: _,
            features_off: _,
            server_meta: _,
            emoji: _,
            bot_sweep_at: _,
            vapid: _,
            vapid_stored: _,
            badge_delay: _,
            badges: _,
            next_wake: _,
            push_coalesce: _,
            joined_coalesce: _,
            push: _,
            unfurler: _,
        } = self;
        let mut places = Vec::new();
        for u in users.values() {
            places.push(("users", u.id.clone()));
            places.extend(u.owner.clone().map(|owner| ("owners", owner)));
        }
        places.extend(credentials.values().map(|id| ("credentials", id.clone())));
        places.extend(emails.values().map(|id| ("emails", id.clone())));
        places.extend(
            email
                .proposals
                .values()
                .map(|p| ("proposals", p.account_id.clone())),
        );
        places.extend(
            push_woken
                .keys()
                .map(|(id, room)| ("push_woken", format!("{id} {room}"))),
        );
        places.extend(self.waking_users().into_iter().map(|id| ("wakes", id)));
        places.extend(limits.users().into_iter().map(|id| ("limits", id)));
        places.extend(
            clients
                .values()
                .map(|conn| ("connections", conn.user.clone().unwrap_or_default())),
        );
        places.extend(
            messages
                .values()
                .map(|m| ("message owners", m.owner.clone())),
        );
        for e in embeds.values() {
            places.push(("embeds", format!("{:?}", e.purpose)));
            places.push(("uploaders", e.uploader.clone()));
        }
        places
    }
}
