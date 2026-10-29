//! `/rename <old_user_id> <new_user_id>`, an extension Go lacks
//! (docs/DEVIATIONS.md), following apron-server-cloudflare's `/rename` (its
//! SPEC.md, section 5, Admins, and store.ts `renameIdentity`).

use std::sync::Arc;

use super::admin::ADMIN_USER_ID;
use super::commands::private_notice;
use super::embeds::EmbedPurpose;
use super::invites::{issuable, NOT_ISSUABLE};
use super::protocol::*;
use super::purge::{truncate_chars, user_id_in, user_list};
use super::push::push_key;
use super::server::{Client, Frame, RecordKind, State};
use crate::obj;

/// Points a user object in a record at `to` when it names `from`, keeping
/// its name, and reports whether it did.
fn rename_user(user: Option<&mut Json>, from: &str, to: &str) -> bool {
    if user_id_in(user.as_deref()) != from {
        return false;
    }
    if let Some(user) = user.and_then(Json::as_object_mut) {
        user.insert("user_id".into(), to.into());
    }
    true
}

impl State {
    /// `/rename <old_user_id> <new_user_id>` (a leading `@` is allowed on
    /// either) gives an account a new user_id. Everything kept under the old
    /// one moves, and what they left in the log is rewritten to the new one
    /// without notifications, so it stays theirs. The old user_id stays used,
    /// never reissued. Their sessions go, so a client resuming one signs in
    /// with its passkey again; their bot keeps its user_id. Their
    /// connections get `user` `you`, and those who share a room with them
    /// `user` `new` with `old` (§3.3). The sender gets a ~private notice
    /// before the result (§1).
    pub(super) fn rename_command(
        &mut self,
        c: &Arc<Client>,
        room_id: &str,
        _body: &Object,
        args: &str,
    ) -> Result<Object, RpcError> {
        let words: Vec<&str> = args.split_whitespace().collect();
        let [from, to] = words.as_slice() else {
            return Err(invalid_params("Usage: /rename <old_user_id> <new_user_id>"));
        };
        let from = from.strip_prefix('@').unwrap_or(from);
        let to = to.strip_prefix('@').unwrap_or(to);
        if from == ADMIN_USER_ID {
            return Err(RpcError::new(
                CODE_DENIED,
                "The admin user's user_id is fixed",
            ));
        }
        let taken = invalid_params(format!("The user_id {to} is taken"));
        if to.eq_ignore_ascii_case(ADMIN_USER_ID) {
            return Err(taken);
        }
        if !issuable(to) {
            return Err(invalid_params(NOT_ISSUABLE));
        }
        let Some(u) = self.users.get(from).filter(|u| u.persists()) else {
            let mut message = format!("No registered user has the user_id {from}");
            truncate_chars(&mut message, 200);
            return Err(invalid_params(message));
        };
        if u.bot() {
            return Err(RpcError::new(CODE_DENIED, "A bot's user_id is fixed"));
        }
        // A user_id --role grants is free for an admin to give, as for
        // /invite-token.
        if self.used_ids.contains(&to.to_lowercase()) || self.room_named_locked(to) {
            return Err(taken);
        }
        let old = self.users[from].from();
        self.move_user_locked(from, to);
        self.grant_roles_locked(to);
        let u = &self.users[to];
        let you = Frame::from(notification("user", obj! {"you" => self.you_locked(u)}));
        for id in &u.clients {
            if let Some(conn) = self.clients.get(id) {
                conn.client.enqueue_frame(you.clone());
            }
        }
        self.notify_user_id_change_locked(to, old);
        c.enqueue(&private_notice(
            &self.rooms[room_id],
            &format!("Renamed `{from}` to `{to}`."),
        ));
        Ok(Object::new())
    }

    /// Moves everything kept under `from` to `to`: the user, with its
    /// profile, passkeys, roles, mutes, status and accepted requests; its
    /// address, invite and device tokens, push registrations, waiting wakes,
    /// coalescing and limits; its memberships, read cursors and the rooms
    /// it created; its messages, reaction sets and avatar; and its
    /// connections. Its logged messages, reaction sets and memberships are
    /// rewritten to `to`. Its sessions are deleted.
    fn move_user_locked(&mut self, from: &str, to: &str) {
        let lower = to.to_lowercase();
        self.used_ids.insert(lower.clone());
        self.touch_used_id(&lower);
        self.stop_timers_locked(from);
        let mut u = self.users.remove(from).expect("checked by the caller");
        u.id = to.to_owned();
        for (request_id, _) in u.dedup.iter() {
            self.dirty
                .dedup
                .insert((from.to_owned(), request_id.clone()));
            self.dirty.dedup.insert((to.to_owned(), request_id.clone()));
        }
        for id in &u.clients {
            if let Some(conn) = self.clients.get_mut(id) {
                conn.user = Some(to.to_owned());
            }
        }
        let room_mutes: Vec<String> = u.room_mutes.keys().cloned().collect();
        self.users.insert(to.to_owned(), u);
        self.touch_user(from);
        self.touch_user(to);
        self.schedule_mute_locked(to);
        for room_id in room_mutes {
            self.schedule_room_mute_locked(to, &room_id);
        }

        for id in self
            .credentials
            .values_mut()
            .chain(self.emails.values_mut())
        {
            if id == from {
                *id = to.to_owned();
            }
        }
        for p in self.email.proposals.values_mut() {
            if p.account_id == from {
                p.account_id = to.to_owned();
            }
        }
        let sessions: Vec<_> = self
            .sessions
            .keys()
            .filter(|key| self.sessions.get(key).expect("listed").user == from)
            .copied()
            .collect();
        for key in sessions {
            self.sessions.remove(&key);
            self.touch_session(key);
        }
        for key in self.devices.move_user(from, to) {
            self.touch_device(key);
        }
        if let Some(key) = self.invites.move_user(from, to) {
            self.touch_invite(key);
        }
        for key in self.sorted_pushes(from) {
            let mut p = self.pushes.remove(&key).expect("listed");
            self.touch_push(&key);
            p.user_id = to.to_owned();
            let moved = push_key(to, &p.url);
            self.pushes.insert(moved.clone(), p);
            self.touch_push(&moved);
        }
        let woken: Vec<_> = self
            .push_woken
            .keys()
            .filter(|(id, _)| id == from)
            .cloned()
            .collect();
        for key in woken {
            let at = self.push_woken.remove(&key).expect("listed");
            self.push_woken.insert((to.to_owned(), key.1), at);
        }
        self.move_wakes_locked(from, to);
        self.limits.move_user(from, to);

        let room_ids: Vec<String> = self.rooms.keys().cloned().collect();
        for room_id in room_ids {
            let r = self.rooms.get_mut(&room_id).expect("listed");
            let mut changed = r.members.remove(from);
            if changed {
                r.members.insert(to.to_owned());
            }
            if let Some(at) = r.active.remove(from) {
                r.active.insert(to.to_owned(), at);
                changed = true;
            }
            if let Some(mut cursor) = r.reads.remove(from) {
                cursor.from.insert("user_id".into(), to.into());
                r.reads.insert(to.to_owned(), cursor);
                changed = true;
            }
            if r.creator == from {
                r.creator = to.to_owned();
                changed = true;
            }
            if changed {
                self.touch_room(&room_id);
            }
        }
        let message_ids: Vec<String> = self.messages.keys().cloned().collect();
        for message_id in message_ids {
            let m = self.messages.get_mut(&message_id).expect("listed");
            let mut changed = false;
            if m.owner == from {
                m.owner = to.to_owned();
                m.from.insert("user_id".into(), to.into());
                changed = true;
            }
            if let Some(mut set) = m.reactions.remove(from) {
                set.from.insert("user_id".into(), to.into());
                m.reactions.insert(to.to_owned(), set);
                changed = true;
            }
            if changed {
                self.touch_message(&message_id);
            }
        }
        let log_ids: Vec<i64> = self.records.keys().copied().collect();
        for log_id in log_ids {
            let record = self.records.get_mut(&log_id).expect("listed");
            let mut value = record.value();
            let mut renamed = false;
            if record.kind == RecordKind::Message {
                renamed = rename_user(value.get_mut("from"), from, to);
            } else if let Some((list, key)) = user_list(record.kind) {
                if let Some(Json::Array(elements)) = value.get_mut(list) {
                    for e in elements.iter_mut().filter_map(Json::as_object_mut) {
                        renamed |= rename_user(e.get_mut(key), from, to);
                    }
                }
            }
            if renamed {
                record.rewrite(|v| *v = value);
                self.touch_record(log_id);
            }
        }
        let avatars: Vec<String> = self
            .embeds
            .values()
            .filter(|e| e.purpose == EmbedPurpose::Avatar(from.to_owned()))
            .map(|e| e.id.clone())
            .collect();
        for id in avatars {
            self.embeds.get_mut(&id).expect("listed").purpose = EmbedPurpose::Avatar(to.to_owned());
            self.touch_embed(&id);
        }
    }
}
