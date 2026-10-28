//! Unread counts (§4.9): one count per user, the same in every push to any
//! of their registrations. A message counts toward a user's unread when it
//! arrived in a room after the user's read position there, is by someone
//! else, is not deleted, is not in a room the user muted, and mentions the
//! user, or is in a joined room, or, in a room they have not joined, replies
//! to them. Counts are kept per user and room for users with push
//! registrations; anything that may change one forgets the counts it
//! touches, which are counted again from the log when next needed.

use std::collections::{BTreeMap, BTreeSet};

use rust_stdlib::time::{self, Duration, Time};

use super::protocol::*;
use super::server::{RecordKind, State};
use crate::obj;

pub const MAX_UNREAD: i64 = 999;
pub const MAX_UNREAD_SCAN: usize = 5000;
/// How long a user's badge pushes wait, so that one push carries the count
/// after a burst of changes.
pub const BADGE_DELAY: Duration = Duration::from_secs(2);

/// Marks a badge wait finished when its callback returns, Go's
/// `defer s.badges.Done()`.
struct BadgeDone<'a>(&'a rust_stdlib::concurrent::WaitGroup);

impl Drop for BadgeDone<'_> {
    fn drop(&mut self) {
        self.0.done();
    }
}

impl State {
    /// The log_id after which messages in r are unread for u, and `None`
    /// when r does not count for u.
    pub fn read_position_locked(&self, user_id: &str, room_id: &str) -> Option<i64> {
        let r = self.rooms.get(room_id)?;
        let u = self.users.get(user_id)?;
        let cursor = r.reads.get(user_id).cloned().unwrap_or_default();
        let mut since = cursor.id;
        // A cursor names a message by its message_id; one moved into r
        // arrived later, at its move.
        if let Some(m) = self.messages.get(&cursor.message_id) {
            if m.room_id == r.id {
                since = since.max(self.arrival(&m.id, room_id));
            }
        }
        if u.joined.contains(room_id) {
            return Some(since.max(r.active.get(user_id).copied().unwrap_or(0)));
        }
        if let Some(ping) = u.pings.get(room_id) {
            return Some(since.max(ping - 1));
        }
        None
    }

    /// The log_id at which message m arrived in room r: its first snapshot
    /// in r's log, a move snapshot for a message moved there.
    pub fn arrival(&self, message_id: &str, room_id: &str) -> i64 {
        let Some(m) = self.messages.get(message_id) else {
            return 0;
        };
        for id in &m.records {
            if self
                .records
                .get(id)
                .is_some_and(|record| record.rooms.iter().any(|r| r == room_id))
            {
                return *id;
            }
        }
        0
    }

    /// Reports whether m, in room r, counts toward u's unread once it is
    /// past the read position.
    pub fn counts_locked(
        &mut self,
        user_id: &str,
        room_id: &str,
        message_id: &str,
        now: &Time,
    ) -> bool {
        if self
            .messages
            .get(message_id)
            .is_none_or(|m| m.owner == user_id)
        {
            return false;
        }
        let info = self.message_info(message_id);
        let u = &self.users[user_id];
        if info.deleted || self.room_muted(u, room_id, now) {
            return false;
        }
        if info.mentions.iter().any(|id| id == user_id) || u.joined.contains(room_id) {
            return true;
        }
        self.messages
            .get(&info.reply_to)
            .is_some_and(|target| target.owner == user_id)
    }

    /// Counts u's unread messages in r from the log.
    pub fn recount_locked(&mut self, user_id: &str, room_id: &str, now: &Time) -> i64 {
        let Some(since) = self.read_position_locked(user_id, room_id) else {
            return 0;
        };
        if !self.room_visible_to(room_id, user_id) {
            return 0;
        }
        let log = self.rooms[room_id].log.clone();
        let mut start = log.partition_point(|id| *id < since + 1);
        start = start.max(log.len().saturating_sub(MAX_UNREAD_SCAN));
        let mut count = 0;
        let mut seen = BTreeSet::new();
        for id in &log[start..] {
            let Some(record) = self.records.get(id) else {
                continue;
            };
            if record.kind != RecordKind::Message {
                continue;
            }
            let message_id = record.message.clone();
            if self
                .messages
                .get(&message_id)
                .is_none_or(|m| m.room_id != room_id)
                || !seen.insert(message_id.clone())
            {
                continue;
            }
            if self.arrival(&message_id, room_id) > since
                && self.counts_locked(user_id, room_id, &message_id, now)
            {
                count += 1;
            }
        }
        count
    }

    /// Returns u's unread count, counting again the rooms whose count is not
    /// known.
    pub fn unread_locked(&mut self, user_id: &str, now: &Time) -> i64 {
        // A room mute that ran out, its timer not yet run, changes what
        // counts in the room and its threads: it ends, and the counts are
        // forgotten.
        let expired: Vec<String> = self.users[user_id]
            .room_mutes
            .iter()
            .filter(|(_, m)| !m.active(now))
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.end_room_mute_locked(user_id, &id);
            self.users.get_mut(user_id).expect("user exists").unread = None;
        }
        let u = self.users.get_mut(user_id).expect("user exists");
        if u.unread.is_none() {
            u.unread = Some(BTreeMap::new());
        }
        let mut rooms: BTreeSet<String> = u.joined.clone();
        rooms.extend(
            u.pings
                .keys()
                .filter(|id| self.rooms.contains_key(*id))
                .cloned(),
        );
        let mut total = 0;
        for id in rooms {
            let known = self.users[user_id]
                .unread
                .as_ref()
                .and_then(|m| m.get(&id).copied());
            let count = match known {
                Some(count) => count,
                None => {
                    let count = self.recount_locked(user_id, &id, now);
                    if let Some(unread) =
                        self.users.get_mut(user_id).and_then(|u| u.unread.as_mut())
                    {
                        unread.insert(id, count);
                    }
                    count
                }
            };
            total += count;
            if total >= MAX_UNREAD {
                return MAX_UNREAD;
            }
        }
        total
    }

    /// Forgets u's count for a room, or every room when `room_id` is empty,
    /// after something that may change it, and schedules a badge push.
    pub fn unread_changed_locked(&mut self, user_id: &str, room_id: &str) {
        if let Some(u) = self.users.get_mut(user_id) {
            if room_id.is_empty() {
                u.unread = None;
            } else if let Some(unread) = u.unread.as_mut() {
                unread.remove(room_id);
            }
        }
        self.schedule_badge_locked(user_id);
    }

    /// Keeps the counts of the users a new or saved message concerns.
    /// `previous` is the snapshot the save replaced, `None` for a new
    /// message, and `from` the room it was in before, for a move.
    pub fn message_unread_locked(
        &mut self,
        message_id: &str,
        previous: Option<&Object>,
        from: Option<&str>,
    ) {
        if self.pushes.is_empty() {
            return;
        }
        let room_id = self.messages[message_id].room_id.clone();
        let owner = self.messages[message_id].owner.clone();
        let mut concerned: BTreeSet<String> = BTreeSet::new();
        let add = |st: &State, id: &str, concerned: &mut BTreeSet<String>| {
            if st.users.contains_key(id) && st.user_has_pushes(id) && id != owner {
                concerned.insert(id.to_owned());
            }
        };
        for room in [Some(room_id.as_str()), from].into_iter().flatten() {
            if let Some(r) = self.rooms.get(room) {
                for id in r.members.clone() {
                    add(self, &id, &mut concerned);
                }
            }
        }
        let mut snapshots = vec![self.snapshot(message_id)];
        if let Some(previous) = previous {
            snapshots.push(previous.clone());
        }
        for snapshot in &snapshots {
            for id in super::messages::mentions(snapshot.get("body").and_then(Json::as_object)) {
                add(self, &id, &mut concerned);
            }
            if let Some(target) = snapshot
                .get("reply_to")
                .and_then(Json::as_object)
                .and_then(|r| r.get("message_id"))
                .and_then(Json::as_str)
                .and_then(|id| self.messages.get(id))
            {
                let owner = target.owner.clone();
                add(self, &owner, &mut concerned);
            }
        }
        let now = time::now();
        let message_log_id = self.messages[message_id].records[0];
        for id in concerned {
            if !self.room_visible_to(&room_id, &id) {
                continue;
            }
            let info = self.message_info(message_id);
            let joined = self.users[&id].joined.contains(&room_id);
            let replied = self
                .messages
                .get(&info.reply_to)
                .is_some_and(|t| t.owner == id);
            if !joined && (info.mentions.contains(&id) || replied) {
                // A room the user has not joined counts from the first
                // message there that mentioned or replied to them.
                let since = self.users[&id].pings.get(&room_id).copied();
                if since.is_none_or(|since| since > message_log_id) {
                    self.users
                        .get_mut(&id)
                        .expect("user exists")
                        .pings
                        .insert(room_id.clone(), message_log_id);
                    self.touch_user(&id);
                    self.unread_changed_locked(&id, &room_id);
                    continue;
                }
            }
            let known = self.users[&id]
                .unread
                .as_ref()
                .and_then(|m| m.get(&room_id).copied());
            if previous.is_some() || from.is_some() {
                // An edit, deletion, or move counted again when it touches a
                // message past the read position.
                let position = self.read_position_locked(&id, &room_id);
                if let Some(from) = from {
                    self.unread_changed_locked(&id, from);
                    self.unread_changed_locked(&id, &room_id);
                } else if position.is_some_and(|since| self.arrival(message_id, &room_id) > since) {
                    self.unread_changed_locked(&id, &room_id);
                }
            } else if let Some(count) = known {
                if self.counts_locked(&id, &room_id, message_id, &now) {
                    if let Some(unread) = self.users.get_mut(&id).and_then(|u| u.unread.as_mut()) {
                        unread.insert(room_id.clone(), count + 1);
                    }
                    self.schedule_badge_locked(&id);
                }
            } else if self.read_position_locked(&id, &room_id).is_some() {
                self.schedule_badge_locked(&id);
            }
        }
    }

    /// Sends u's badge pushes after BADGE_DELAY, when u has a registration
    /// with scope badge (§4.9). Nothing is scheduled once the server is
    /// shutting down.
    pub fn schedule_badge_locked(&mut self, user_id: &str) {
        if self.closed || !self.user_takes_badges(user_id) {
            return;
        }
        let delay = self.badge_delay;
        let badges = self.badges.clone();
        let Some(u) = self.users.get_mut(user_id) else {
            return;
        };
        if u.badge_timer.is_some() {
            return;
        }
        let server = self.server.clone();
        let id = user_id.to_owned();
        let generation = u.generation;
        badges.add(1);
        let finished = badges.clone();
        u.badge_timer = Some(time::after_func(delay, move || {
            let _done = BadgeDone(&finished);
            let Some(server) = server.upgrade() else {
                return;
            };
            let mut st = server.lock();
            let closed = st.closed;
            let Some(u) = st.users.get_mut(&id) else {
                return;
            };
            if u.generation != generation {
                return;
            }
            u.badge_timer = None;
            if !closed {
                st.badge_locked(&id, &time::now());
            }
        }));
    }

    /// Cancels u's pending badge pushes.
    pub fn stop_badge_locked(&mut self, user_id: &str) {
        if let Some(u) = self.users.get_mut(user_id) {
            if let Some(timer) = u.badge_timer.take() {
                if timer.stop() {
                    self.badges.done();
                }
            }
        }
    }

    /// Sends a badge push (§4.9), {push_id, unread} without a message, to
    /// each of the user's registrations that takes them and last accepted
    /// another count.
    pub fn badge_locked(&mut self, user_id: &str, now: &Time) {
        let mut unread = -1;
        for key in self.sorted_pushes(user_id) {
            let Some(p) = self.pushes.get(&key) else {
                continue;
            };
            if !p.takes_badges() || !p.live(now) {
                continue;
            }
            if unread < 0 {
                unread = self.unread_locked(user_id, now);
            }
            let p = &self.pushes[&key];
            if unread == p.last_unread || (p.in_flight && unread == p.pending_unread) {
                continue;
            }
            let mut payload = obj! {"unread" => unread};
            if !p.push_id.is_empty() {
                payload.insert("push_id".into(), p.push_id.as_str().into());
            }
            self.deliver_push_locked(
                &key,
                unread,
                encode_json(&payload).unwrap_or_default(),
                "low",
                true,
            );
        }
    }
}
