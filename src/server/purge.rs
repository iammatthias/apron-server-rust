//! `/purge <user_id>`, an extension Go lacks (docs/DEVIATIONS.md), following
//! apron-server-cloudflare's `/purge` (its SPEC.md, section 5, Admins, and
//! store.ts `purgeUsers`).

use std::collections::BTreeSet;
use std::sync::Arc;

use super::admin::ADMIN_USER_ID;
use super::bots::BOT_ID_PREFIX;
use super::commands::private_notice;
use super::embeds::EmbedPurpose;
use super::protocol::*;
use super::server::{Client, RecordKind, State};

/// Why the connections of a purged user close.
const PURGED: &str = "Removed by an admin";

/// The list of user objects a logged record keeps, and each element's key
/// for the user: a reactions record's sets and a membership record's
/// members. A message snapshot names one user, its `from`.
pub(super) fn user_list(kind: RecordKind) -> Option<(&'static str, &'static str)> {
    match kind {
        RecordKind::Reactions => Some(("reactions", "from")),
        RecordKind::Membership => Some(("members", "user")),
        RecordKind::Message | RecordKind::Room => None,
    }
}

/// The user_id of a user object in a record, empty when there is none.
pub(super) fn user_id_in(element: Option<&Json>) -> &str {
    element
        .and_then(Json::as_object)
        .and_then(|user| user.get("user_id"))
        .and_then(Json::as_str)
        .unwrap_or("")
}

/// What a purge removed, for the sender's notice.
#[derive(Default)]
struct Purged {
    messages: usize,
    reactions: usize,
    uploads: usize,
}

fn plural(n: usize, one: &str) -> String {
    format!("{n} {one}{}", if n == 1 { "" } else { "s" })
}

impl State {
    /// `/purge <user_id>` (a leading `@` is allowed): closes the connections
    /// of a user and their bot (`bot_<user_id>`), then deletes them and
    /// everything they posted, reacted or uploaded, silently: no record
    /// announces it. Threads it leaves empty are removed. The user_id stays
    /// used, so it is never issued again. The sender gets a ~private notice
    /// with the counts before the result (§1).
    pub(super) fn purge_command(
        &mut self,
        c: &Arc<Client>,
        room_id: &str,
        _body: &Object,
        args: &str,
    ) -> Result<Object, RpcError> {
        let mut words = args.split_whitespace();
        let (Some(word), None) = (words.next(), words.next()) else {
            return Err(invalid_params("Usage: /purge <user_id>"));
        };
        let user_id = word.strip_prefix('@').unwrap_or(word);
        if self.client_user(c).as_deref() == Some(user_id) {
            return Err(RpcError::new(CODE_DENIED, "You can't purge yourself"));
        }
        if user_id == ADMIN_USER_ID {
            return Err(RpcError::new(CODE_DENIED, "The admin user can't be purged"));
        }
        if !self.users.contains_key(user_id) {
            let mut message = format!("No user has the user_id {user_id}");
            truncate_chars(&mut message, 200);
            return Err(invalid_params(message));
        }
        let mut ids = BTreeSet::from([user_id.to_owned()]);
        if !user_id.starts_with(BOT_ID_PREFIX) {
            let bot = format!("{BOT_ID_PREFIX}{user_id}");
            if self.users.contains_key(&bot) {
                ids.insert(bot);
            }
        }
        let rooms: BTreeSet<String> = ids
            .iter()
            .flat_map(|id| self.users[id].joined.iter().cloned())
            .collect();
        let purged = self.erase_users_locked(&ids);
        for room in rooms {
            self.remove_if_empty_locked(&room);
        }
        let text = format!(
            "Purged `{user_id}`: {}, {}, {}.",
            plural(purged.messages, "message"),
            plural(purged.reactions, "reaction set"),
            plural(purged.uploads, "upload"),
        );
        c.enqueue(&private_notice(&self.rooms[room_id], &text));
        Ok(Object::new())
    }

    /// Deletes users and what they left: their message snapshots and
    /// current messages with every reaction set on them, their reaction sets
    /// elsewhere, their memberships and membership records, their uploads
    /// and avatars, and their passkeys, addresses, sessions, bot, device and
    /// invite tokens, push registrations and wakes, limits and accepted
    /// requests. A record that lists them beside others is rewritten without
    /// them; rooms they created stay, without a creator. Their connections
    /// close. Their user_ids stay in `used_ids`, never reissued.
    fn erase_users_locked(&mut self, ids: &BTreeSet<String>) -> Purged {
        let named = |user: Option<&Json>| ids.contains(user_id_in(user));
        let gone: BTreeSet<String> = self
            .messages
            .values()
            .filter(|m| ids.contains(&m.owner))
            .map(|m| m.id.clone())
            .collect();
        let mut purged = Purged {
            messages: gone.len(),
            reactions: self
                .messages
                .values()
                .map(|m| m.reactions.keys().filter(|id| ids.contains(*id)).count())
                .sum(),
            uploads: 0,
        };

        let mut doomed = Vec::new();
        let mut rewritten = Vec::new();
        for (log_id, record) in &self.records {
            let mut value = record.value();
            if record.kind == RecordKind::Message {
                if named(value.get("from")) {
                    doomed.push(*log_id);
                }
                continue;
            }
            let Some((list, key)) = user_list(record.kind) else {
                continue;
            };
            let message_id = value.get("message_id").and_then(Json::as_str);
            let elements = value.get(list).map(Json::as_list).unwrap_or(&[]);
            let kept: Vec<Json> = if message_id.is_some_and(|id| gone.contains(id)) {
                Vec::new()
            } else {
                elements
                    .iter()
                    .filter(|e| !named(e.as_object().and_then(|e| e.get(key))))
                    .cloned()
                    .collect()
            };
            if kept.len() == elements.len() {
                continue;
            }
            if kept.is_empty() {
                doomed.push(*log_id);
            } else {
                value.insert(list.to_owned(), Json::Array(kept));
                rewritten.push((*log_id, value));
            }
        }
        for (log_id, value) in rewritten {
            let record = self.records.get_mut(&log_id).expect("listed above");
            record.rewrite(|v| *v = value);
            self.touch_record(log_id);
        }
        for log_id in doomed {
            self.remove_record_locked(log_id);
        }

        for id in &gone {
            purged.uploads +=
                self.hosted_uploads(|e| e.purpose == EmbedPurpose::Message && e.message_id == *id);
            self.remove_message_locked(id);
        }
        let reacted: Vec<String> = self
            .messages
            .values()
            .filter(|m| m.reactions.keys().any(|id| ids.contains(id)))
            .map(|m| m.id.clone())
            .collect();
        for id in reacted {
            let m = self.messages.get_mut(&id).expect("listed above");
            m.reactions.retain(|user_id, _| !ids.contains(user_id));
            self.touch_message(&id);
        }
        let room_ids: Vec<String> = self.rooms.keys().cloned().collect();
        for room_id in room_ids {
            let r = self.rooms.get_mut(&room_id).expect("listed above");
            let held = (r.members.len(), r.active.len(), r.reads.len());
            r.members.retain(|id| !ids.contains(id));
            r.active.retain(|id, _| !ids.contains(id));
            r.reads.retain(|id, _| !ids.contains(id));
            let mut changed = held != (r.members.len(), r.active.len(), r.reads.len());
            if ids.contains(&r.creator) {
                r.creator.clear();
                changed = true;
            }
            if changed {
                self.touch_room(&room_id);
            }
        }
        let avatars: Vec<String> = self
            .embeds
            .values()
            .filter(|e| matches!(&e.purpose, EmbedPurpose::Avatar(id) if ids.contains(id)))
            .map(|e| e.id.clone())
            .collect();
        purged.uploads += avatars.len();
        for id in avatars {
            self.remove_embed_locked(&id);
        }

        let sessions: Vec<_> = self
            .sessions
            .keys()
            .filter(|key| ids.contains(&self.sessions.get(key).expect("listed").user))
            .copied()
            .collect();
        for key in sessions {
            self.sessions.remove(&key);
            self.touch_session(key);
        }
        self.credentials.retain(|_, user_id| !ids.contains(user_id));
        self.emails.retain(|_, user_id| !ids.contains(user_id));
        let proposals: Vec<_> = self
            .email
            .proposals
            .iter()
            .filter(|(_, p)| ids.contains(&p.account_id))
            .map(|(id, _)| *id)
            .collect();
        for id in proposals {
            self.drop_proposal_locked(id);
        }
        self.push_woken
            .retain(|(user_id, _), _| !ids.contains(user_id));

        for id in ids {
            for key in self.devices.remove_user(id) {
                self.touch_device(key);
            }
            if let Some(key) = self.invites.of_user(id) {
                self.invites.remove(&key);
                self.touch_invite(key);
            }
            if let Some(key) = self.bots.of_bot(id) {
                self.bots.remove(&key);
                self.touch_bot(key);
            }
            for key in self.sorted_pushes(id) {
                self.remove_push_locked(&key);
            }
            self.drop_wakes_locked(id, None);
            self.limits.forget_user(id);
            self.stop_timers_locked(id);
            let u = self.users.remove(id).expect("purged users exist");
            self.touch_user(id);
            for (request_id, _) in u.dedup.iter() {
                self.dirty.dedup.insert((id.clone(), request_id.clone()));
            }
            // The user is gone, so closing announces nothing and logs no
            // leave.
            for client in u.clients {
                self.revoke_connection_locked(client, RpcError::new(CODE_DENIED, PURGED));
            }
        }
        // Unread counts read the log, which changed under them.
        for u in self.users.values_mut() {
            u.unread = None;
        }
        purged
    }

    /// Counts the hosted uploads, not link previews or streams, among the
    /// embeds `which` picks.
    fn hosted_uploads(&self, which: impl Fn(&super::embeds::EmbedState) -> bool) -> usize {
        self.embeds
            .values()
            .filter(|e| which(e) && !e.is_link() && e.stream.is_none())
            .count()
    }

    /// Deletes a logged record from the log and from every room log that
    /// holds it.
    fn remove_record_locked(&mut self, log_id: i64) {
        let Some(record) = self.records.remove(&log_id) else {
            return;
        };
        self.touch_record(log_id);
        for room_id in &record.rooms {
            if let Some(r) = self.rooms.get_mut(room_id) {
                r.log.retain(|id| *id != log_id);
                self.touch_room(room_id);
            }
        }
    }
}

/// Cuts `s` to at most `max` characters.
fn truncate_chars(s: &mut String, max: usize) {
    if let Some((at, _)) = s.char_indices().nth(max) {
        s.truncate(at);
    }
}
