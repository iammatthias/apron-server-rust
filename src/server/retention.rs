//! History retention (`Config.retention`), an extension Go lacks that
//! follows apron-server-cloudflare's rolling history (docs/DEVIATIONS.md).
//! Records older than the window are discarded as a prefix of the one
//! server-wide log, and `State.history_floor` moves past them: every room
//! then reports `history_log_id` as at least the floor (§4.3.3).

use std::collections::BTreeMap;

use rust_stdlib::time::Time;

use super::rooms::room_update;
use super::server::State;
use crate::obj;

impl State {
    /// Discards the records logged more than Config.retention before `now`,
    /// and the state they alone held: a message whose latest snapshot went,
    /// with its hosted files, a reaction set whose record went, and a thread
    /// whose whole log went and that has no threads left. Permanent rooms,
    /// those without a parent, stay and keep their latest_log_id. Members
    /// of a removed thread, and everyone else who could see it, get
    /// room_update left; the members of every other room whose
    /// history_log_id moved get room_update updated.
    pub fn expire_history_locked(&mut self, now: &Time) {
        let Some(retention) = self.config.retention else {
            return;
        };
        // A log_id is its commit time in milliseconds, or later when the
        // clock lags, so the expired records are a prefix of the log.
        let cutoff = now.unix_milli().saturating_sub(retention.milliseconds());
        let Some(&newest) = self.records.range(..cutoff).next_back().map(|(id, _)| id) else {
            return;
        };
        let floor = newest + 1;
        let starts: BTreeMap<String, Option<i64>> = self
            .rooms
            .values()
            .map(|r| (r.id.clone(), r.history_log_id(self.history_floor)))
            .collect();
        self.history_floor = floor;

        let kept = self.records.split_off(&floor);
        let expired = std::mem::replace(&mut self.records, kept);
        self.dirty.records.extend(expired.into_keys());
        for r in self.rooms.values_mut() {
            let gone = r.log.partition_point(|id| *id < floor);
            r.log.drain(..gone);
        }
        let message_ids: Vec<String> = self.messages.keys().cloned().collect();
        for id in message_ids {
            let m = self.messages.get_mut(&id).expect("message exists");
            if m.log_id < floor {
                self.remove_message_locked(&id);
                continue;
            }
            let held = (m.records.len(), m.reactions.len());
            m.records.retain(|log_id| *log_id >= floor);
            m.reactions.retain(|_, set| set.log_id >= floor);
            if held != (m.records.len(), m.reactions.len()) {
                self.touch_message(&id);
            }
        }

        // Removing a thread tells its audience first, so room_update left
        // precedes the updates below.
        while let Some(id) = self
            .rooms
            .values()
            .find(|r| r.parent.is_some() && r.latest_id < floor && r.children.is_empty())
            .map(|r| r.id.clone())
        {
            self.remove_thread_locked(&id);
            self.rooms_removed_at = self.last_id;
        }
        for (id, start) in starts {
            match self.rooms.get(&id) {
                Some(r) if r.history_log_id(floor) != start => self.announce_room_locked(&id, None),
                _ => {}
            }
        }
        // Unread counts read the log, which changed under them.
        for u in self.users.values_mut() {
            u.unread = None;
        }
    }

    /// Forgets a message and its hosted embeds.
    fn remove_message_locked(&mut self, message_id: &str) {
        let embeds: Vec<String> = self
            .embeds
            .values()
            .filter(|e| e.message_id == message_id && e.avatar_for.is_none())
            .map(|e| e.id.clone())
            .collect();
        for id in embeds {
            self.remove_embed_locked(&id);
        }
        self.messages.remove(message_id);
        self.touch_message(message_id);
    }

    /// Removes a thread retention emptied, telling everyone who could see it
    /// that it is gone.
    fn remove_thread_locked(&mut self, room_id: &str) {
        let (everyone, audience) = self.audience(room_id);
        let frame = room_update("left", vec![obj! {"room_id" => room_id}.into()]);
        for user_id in self.users.keys() {
            if everyone || audience.contains(user_id) {
                self.send_to_user(user_id, &frame);
            }
        }
        let Some(r) = self.rooms.remove(room_id) else {
            return;
        };
        if let Some(parent) = r.parent.as_ref().and_then(|p| self.rooms.get_mut(p)) {
            parent.children.retain(|id| id != room_id);
        }
        self.touch_room(room_id);
        let user_ids: Vec<String> = self.users.keys().cloned().collect();
        for user_id in user_ids {
            let u = self.users.get_mut(&user_id).expect("user exists");
            let mut held = u.joined.remove(room_id);
            held |= u.left_at.remove(room_id).is_some();
            held |= u.pings.remove(room_id).is_some();
            held |= u.room_mutes.remove(room_id).is_some();
            if let Some(timer) = u.room_mute_timers.remove(room_id) {
                timer.stop();
            }
            if held {
                self.touch_user(&user_id);
            }
        }
    }
}
