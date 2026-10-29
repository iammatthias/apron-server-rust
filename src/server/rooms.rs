use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rust_stdlib::encoding::json::jsontext::Value;

use super::bots::BOT_ID_PREFIX;
use super::limits::{refused, Allowance, Category, Charge, Principal, Scope};
use super::messages::MessageState;
use super::protocol::*;
use super::server::{
    Client, Frame, LogRecord, RecordKind, Server, State, DEFAULT_ROOM_ID, MAX_HISTORY_PAGE_SIZE,
    MAX_HISTORY_REPLY_BYTES,
};
use super::toggles::Feature;
use super::users::{UserState, ADMIN_ROLE, ROOM_CREATOR_ROLES};
use crate::obj;

pub const MAX_THREAD_TITLE_RUNES: usize = 60;
pub const DEFAULT_THREAD_TITLE: &str = "Thread";
/// The titles of `general` and of another public top-level room saved
/// without one (apron-server-cloudflare's ROOM_TITLE and DEFAULT_ROOM_TITLE).
pub const DEFAULT_ROOM_TITLE: &str = "General";
pub const TOP_LEVEL_ROOM_TITLE: &str = "Room";
/// Bounds a room's description, and MAX_ROOM_EXT_BYTES its merged ext, which
/// every room record carries.
pub const MAX_DESCRIPTION_BYTES: usize = 16 << 10;
pub const MAX_ROOM_EXT_BYTES: usize = 16 << 10;
/// Most top-level rooms created besides `general` (apron-server-cloudflare's
/// MAX_CREATED_ROOMS).
pub const MAX_CREATED_ROOMS: usize = 16;
/// Most rooms that exist at once besides `general` and private top-level
/// rooms: threads and created top-level rooms (Cloudflare's threadLimit).
pub const MAX_THREADS: usize = 100;
/// Most live threads one account created (Cloudflare's threadsPerUser).
pub const MAX_THREADS_PER_USER: usize = 25;
/// The longest typing a relay carries, in seconds (Cloudflare's
/// activityMaxTypingSeconds).
pub const MAX_TYPING_SECONDS: i64 = 30;
/// Typing relays, and separately read cursor relays, one user may cause a
/// minute (Cloudflare's activityBroadcastsPerUserMinute).
pub const ACTIVITY_RELAYS_PER_MINUTE: i64 = 10;

fn activity_limiter() -> crate::rate::Limiter {
    crate::rate::Limiter::new(
        crate::rate::every(rust_stdlib::time::Duration::from_nanos(
            rust_stdlib::time::MINUTE.as_nanos() / ACTIVITY_RELAYS_PER_MINUTE,
        )),
        ACTIVITY_RELAYS_PER_MINUTE,
    )
}

/// A room's current record, its log, and its members. Every room, including
/// threads (rooms with parent_room_id), is visible to every authenticated
/// user, except that a private room and its threads are visible only to
/// their members (§4.2.4).
#[derive(Debug, Default)]
pub struct RoomState {
    pub id: String,
    pub parent: Option<String>,
    pub children: Vec<String>,
    /// Fixed at creation and kept in record as "private": true.
    pub private: bool,
    /// The latest logged room record.
    pub record: Object,
    pub record_log_id: i64,
    pub created_id: i64,
    pub latest_id: i64,
    /// The log_ids of the records in the room's log, in order.
    pub log: Vec<i64>,
    pub members: BTreeSet<String>,
    /// Each member to the log_id of their latest join or new message in the
    /// room, which ranks members when a listing truncates them (§4.2.1).
    pub active: BTreeMap<String, i64>,
    /// The user_id that created the room, empty for the seeded room.
    pub creator: String,
    /// Each user's latest read cursor (§4.6).
    pub reads: BTreeMap<String, ReadCursor>,
}

#[derive(Clone, Debug, Default)]
pub struct ReadCursor {
    pub from: Object,
    pub message_id: String,
    pub id: i64,
}

impl RoomState {
    /// Reports whether u may remove target from r with room_leave's
    /// user_id (§4.2.2): an admin anyone, an account its own bot, and the
    /// room's creator, if an account, anyone.
    pub fn may_remove(&self, u: &UserState, target: &str) -> bool {
        u.has_role(ADMIN_ROLE) || (u.account() && (self.creator == u.id || owns_bot(u, target)))
    }

    /// Reports whether the room goes once it empties or its log expires: a
    /// thread or a private room. `general` and the top-level rooms admins
    /// and mods create are permanent.
    pub fn removable(&self) -> bool {
        self.parent.is_some() || self.private
    }

    /// The inclusive lower bound of the room's retained history (§4.3.3):
    /// its creation record, or the server's history floor once retention
    /// passed it, and `None` once retention discarded the whole log.
    pub fn history_log_id(&self, floor: i64) -> Option<i64> {
        let start = floor.max(self.created_id);
        (start <= self.latest_id).then_some(start)
    }

    /// The room's log head and the start of its retained history.
    pub fn delivery_fields(&self, floor: i64) -> Object {
        obj! {
            "latest_log_id" => format_id(self.latest_id),
            "history_log_id" => match self.history_log_id(floor) {
                Some(start) => Json::from(format_id(start)),
                None => Json::Null,
            },
        }
    }

    /// The room's display title, falling back to its room_id (§3.4).
    pub fn title(&self) -> String {
        match self.record.get("title").and_then(Json::as_str) {
            Some(title) if !title.is_empty() => title.to_owned(),
            _ => self.id.clone(),
        }
    }

    /// The room's current record with delivery fields.
    pub fn params(&self, floor: i64) -> Object {
        let mut params = self.record.clone();
        params.extend(self.delivery_fields(floor));
        params
    }
}

/// Reports whether target is u's `/invite-bot` bot.
fn owns_bot(u: &UserState, target: &str) -> bool {
    target.strip_prefix(BOT_ID_PREFIX) == Some(u.id.as_str())
}

/// Renders a room_update notification (§4.2.3) with one field.
pub fn room_update(field: &str, records: Vec<Json>) -> Frame {
    Frame::from(notification("room_update", obj! {field => records}))
}

/// Lists users' complete objects ordered by user_id, for a result's `users`
/// (§3.3).
pub fn profiles(st: &State, users: &BTreeSet<String>) -> Vec<Json> {
    users
        .iter()
        .filter_map(|id| st.users.get(id))
        .map(|u| u.profile().into())
        .collect()
}

/// Derives a default thread title from the first line of its description,
/// or DEFAULT_THREAD_TITLE.
pub fn thread_title(description: &str) -> String {
    let line = description.trim().split('\n').next().unwrap_or("").trim();
    let mut line = line.to_owned();
    if line.chars().count() > MAX_THREAD_TITLE_RUNES {
        line = format!(
            "{}…",
            line.chars()
                .take(MAX_THREAD_TITLE_RUNES)
                .collect::<String>()
                .trim()
        );
    }
    if line.is_empty() {
        return DEFAULT_THREAD_TITLE.into();
    }
    line
}

/// Reads room_join and room_leave params: room_id and an optional user_id
/// (§4.2.2).
fn parse_membership_params(params: &Params) -> Result<(String, String, bool), RpcError> {
    let room_id = parse_string(params, "room_id", true)?;
    let user_id = parse_string(params, "user_id", false)?;
    let has_user = params.contains_key("user_id");
    if has_user && !valid_id(&user_id) {
        return Err(invalid_params(
            "user_id must be a user_id: not empty, without whitespace or control characters",
        ));
    }
    Ok((room_id, user_id, has_user))
}

pub fn parse_bound(params: &Params, name: &str) -> Result<Option<i64>, RpcError> {
    let Some(raw) = params.get(name) else {
        return Ok(None);
    };
    let mut value = String::new();
    if rust_stdlib::encoding::json::v2::unmarshal(&raw.0, &mut value, &[]).is_err() {
        return Err(invalid_params(format!("{name} must be a decimal string")));
    }
    match value.parse::<i64>() {
        Ok(number) if number >= 0 => Ok(Some(number)),
        _ => Err(invalid_params(format!(
            "{name} must be a non-negative decimal string"
        ))),
    }
}

fn parse_limit(params: &Params, default_limit: usize) -> Result<usize, RpcError> {
    let Some(raw) = params.get("limit") else {
        return Ok(default_limit);
    };
    let mut value: i64 = 0;
    if rust_stdlib::encoding::json::v2::unmarshal(&raw.0, &mut value, &[]).is_err() || value <= 0 {
        return Err(invalid_params("limit must be a positive integer"));
    }
    Ok((value as usize).min(MAX_HISTORY_PAGE_SIZE))
}

/// Returns the records of a log, which is in log_id order, within the
/// inclusive bounds.
fn window(log: &[i64], after: Option<i64>, before: Option<i64>) -> &[i64] {
    let mut log = log;
    if let Some(after) = after {
        let start = log.partition_point(|id| *id < after);
        log = &log[start..];
    }
    if let Some(before) = before {
        let end = log.partition_point(|id| *id <= before);
        log = &log[..end];
    }
    log
}

impl State {
    /// Reports whether u may see the room (§4.2.4): unless u is a member of
    /// the room and of every private room it is a thread of, at any depth,
    /// it is invisible, and answered like an unknown one.
    pub fn room_visible_to(&self, room_id: &str, user_id: &str) -> bool {
        let mut room = self.rooms.get(room_id);
        while let Some(r) = room {
            if r.private && !r.members.contains(user_id) {
                return false;
            }
            room = r.parent.as_ref().and_then(|p| self.rooms.get(p));
        }
        true
    }

    /// Who can see the room: everyone, or, for a private room or a thread
    /// of one, the users in every private room on the way up.
    pub fn audience(&self, room_id: &str) -> (bool, BTreeSet<String>) {
        let mut users: Option<BTreeSet<String>> = None;
        let mut room = self.rooms.get(room_id);
        while let Some(r) = room {
            if r.private {
                users = Some(match users {
                    None => r.members.clone(),
                    Some(set) => set.intersection(&r.members).cloned().collect(),
                });
            }
            room = r.parent.as_ref().and_then(|p| self.rooms.get(p));
        }
        match users {
            None => (true, BTreeSet::new()),
            Some(users) => (false, users),
        }
    }

    /// Reports whether a record in `from`, such as a move snapshot naming
    /// another room, would reach someone who cannot see `to`.
    pub fn reveals_to(&self, from: &str, to: &str) -> bool {
        let (to_everyone, to_users) = self.audience(to);
        if to_everyone {
            return false;
        }
        let (everyone, users) = self.audience(from);
        if everyone {
            return true;
        }
        users.iter().any(|id| !to_users.contains(id))
    }

    /// Counts the top-level private rooms u is in, which
    /// Config.max_private_rooms bounds.
    pub fn private_rooms(&self, u: &UserState) -> usize {
        u.joined
            .iter()
            .filter_map(|id| self.rooms.get(id))
            .filter(|r| r.private && r.parent.is_none())
            .count()
    }

    pub fn private_rooms_full_locked(&self, u: &UserState) -> bool {
        self.config.max_private_rooms > 0 && self.private_rooms(u) >= self.config.max_private_rooms
    }

    /// Returns the room named `id` if `user_id` may see it.
    pub fn visible_room_locked(&self, user_id: &str, id: &str) -> Option<&RoomState> {
        let r = self.rooms.get(id)?;
        if self.room_visible_to(id, user_id) {
            Some(r)
        } else {
            None
        }
    }

    /// Returns the message named `id` if `user_id` may see the room it is
    /// in.
    pub fn visible_message_locked(&self, user_id: &str, id: &str) -> Option<&MessageState> {
        let m = self.messages.get(id)?;
        if self.room_visible_to(&m.room_id, user_id) {
            Some(m)
        } else {
            None
        }
    }

    /// Renders the read cursors kept for a room that the server sends after
    /// listing it (§4.6): every member's cursor for a room u has joined,
    /// which delivers read receipts, and otherwise only u's own.
    pub fn cursor_frames_locked(&self, u: &UserState, r: &RoomState) -> Vec<Frame> {
        let mut frames = Vec::new();
        for (user_id, cursor) in &r.reads {
            if *user_id != u.id && !(self.config.read_receipts && u.joined.contains(&r.id)) {
                continue;
            }
            let frame = obj! {"method" => "activity", "params" => obj! {
                "room_id" => r.id.as_str(), "from" => cursor.from.clone(), "read_message_id" => cursor.message_id.as_str(),
            }};
            if let Some(frame) = super::server::render(&frame) {
                frames.push(frame);
            }
        }
        frames
    }

    /// Sends a frame to every connection of every member of the given
    /// rooms, once per connection.
    pub fn deliver_locked(&self, frame: &Frame, rooms: &[String]) {
        self.deliver_except_locked(frame, rooms, "");
    }

    /// `deliver_locked` to every member but `except`.
    fn deliver_except_locked(&self, frame: &Frame, rooms: &[String], except: &str) {
        let mut seen = BTreeSet::new();
        for room_id in rooms {
            if let Some(r) = self.rooms.get(room_id) {
                for id in &r.members {
                    if id != except && seen.insert(id.clone()) {
                        self.send_to_user(id, frame);
                    }
                }
            }
        }
    }

    /// Logs one membership record (§4.2.2) of u in r, advancing the room's
    /// latest_log_id, and returns the record for delivery in a room_update's
    /// memberships (§4.2.3).
    pub fn log_membership_locked(&mut self, user_id: &str, room_id: &str, joined: bool) -> Value {
        let log_id = self.next_id_locked();
        let from = self.users[user_id].from();
        let record = LogRecord::new(
            log_id,
            RecordKind::Membership,
            &obj! {
                "log_id" => format_id(log_id),
                "room_id" => room_id,
                "members" => vec![Json::from(obj! {"user" => from, "joined" => joined})],
            },
        );
        let raw = Value::from(record.raw.clone());
        self.append_locked(record, &[room_id.to_owned()]);
        if !joined {
            if let Some(u) = self.users.get_mut(user_id) {
                u.left_at.insert(room_id.to_owned(), log_id);
            }
        }
        raw
    }

    /// Sends a membership record to the room's members but u, as
    /// room_update memberships (§4.2.3).
    pub fn deliver_membership_locked(&self, membership: &Value, room_id: &str, user_id: &str) {
        let frame = room_update("memberships", vec![membership.clone().into()]);
        if let Some(r) = self.rooms.get(room_id) {
            for id in &r.members {
                if id != user_id {
                    self.send_to_user(id, &frame);
                }
            }
        }
    }

    /// Joins u to r, logs the membership, and delivers it to the room's
    /// other members (§4.2.2). Returns the membership record, `None` if u
    /// was a member already.
    pub fn add_member_locked(&mut self, user_id: &str, room_id: &str) -> Option<Value> {
        if self.users.get(user_id)?.joined.contains(room_id) {
            return None;
        }
        self.rooms
            .get_mut(room_id)?
            .members
            .insert(user_id.to_owned());
        let u = self.users.get_mut(user_id)?;
        u.joined.insert(room_id.to_owned());
        u.left_at.remove(room_id);
        self.touch_room(room_id);
        self.touch_user(user_id);
        let membership = self.log_membership_locked(user_id, room_id, true);
        if let Some(r) = self.rooms.get_mut(room_id) {
            let latest = r.latest_id;
            r.active.insert(user_id.to_owned(), latest);
        }
        self.deliver_membership_locked(&membership, room_id, user_id);
        self.announce_join_status_locked(user_id, room_id);
        self.unread_changed_locked(user_id, room_id);
        Some(membership)
    }

    /// Joins a new identity to the default room, so its room list is not
    /// empty.
    pub fn join_default_room_locked(&mut self, user_id: &str) {
        self.join_locked(user_id, DEFAULT_ROOM_ID);
    }

    /// Joins u to r: the room's other members receive the membership, and
    /// u's connections one room_update with the room, its members, and the
    /// membership (§4.2.2). Reports whether u was not a member before.
    pub fn join_locked(&mut self, user_id: &str, room_id: &str) -> bool {
        let Some(membership) = self.add_member_locked(user_id, room_id) else {
            return false;
        };
        let frame = self.joined_update_locked(room_id, Some(&membership));
        self.send_to_user(user_id, &frame);
        true
    }

    /// Renders room_update joined for r: its record with its members, as bare
    /// user objects with their status, their complete objects in `users`,
    /// and the membership that joined the user, if any (§4.2.3).
    pub fn joined_update_locked(&self, room_id: &str, membership: Option<&Value>) -> Frame {
        let r = &self.rooms[room_id];
        let mut record = r.params(self.history_floor);
        let listed = self.add_members_locked(&mut record, r);
        let mut params =
            obj! {"joined" => vec![Json::from(record)], "users" => profiles(self, &listed)};
        if let Some(membership) = membership {
            params.insert(
                "memberships".into(),
                vec![Json::from(membership.clone())].into(),
            );
        }
        Frame::from(notification("room_update", params))
    }

    /// Adds a room's members to its record as bare user objects, ordered by
    /// user_id, and returns them. A room with more than
    /// Config.max_listed_members lists only its most recently active members
    /// and adds member_count, the total (§4.2.1).
    pub fn add_members_locked(&self, record: &mut Object, r: &RoomState) -> BTreeSet<String> {
        let (ids, truncated) = self.listed_member_ids_locked(r);
        if truncated {
            record.insert("member_count".into(), r.members.len().into());
        }
        let refs: Vec<Json> = ids
            .iter()
            .filter_map(|id| self.users.get(id))
            .map(|u| u.shown_object().into())
            .collect();
        record.insert("members".into(), refs.into());
        ids.into_iter().collect()
    }

    /// The user_ids of the members that r lists (§4.2.1), ordered by
    /// user_id: all of them, or, past Config.max_listed_members, the most
    /// recently active, and then truncated is set.
    pub fn listed_member_ids_locked(&self, r: &RoomState) -> (Vec<String>, bool) {
        let mut ids: Vec<String> = r.members.iter().cloned().collect();
        let limit = self.config.max_listed_members;
        let mut truncated = false;
        if limit > 0 && ids.len() > limit {
            ids.sort_by(|a, b| {
                let (aa, bb) = (
                    r.active.get(a).copied().unwrap_or(0),
                    r.active.get(b).copied().unwrap_or(0),
                );
                bb.cmp(&aa).then_with(|| a.cmp(b))
            });
            ids.truncate(limit);
            truncated = true;
        }
        ids.sort();
        (ids, truncated)
    }

    /// Removes u from r (§4.2.2): the room's other members receive the
    /// logged membership, and u's connections one room_update with left and
    /// the membership. Reports whether u was a member.
    pub fn leave_locked(&mut self, user_id: &str, room_id: &str) -> bool {
        if !self
            .users
            .get(user_id)
            .is_some_and(|u| u.joined.contains(room_id))
        {
            return false;
        }
        let membership = self.log_membership_locked(user_id, room_id, false);
        self.deliver_membership_locked(&membership, room_id, user_id);
        if let Some(u) = self.users.get_mut(user_id) {
            u.joined.remove(room_id);
        }
        self.touch_room(room_id);
        self.touch_user(user_id);
        let private = match self.rooms.get_mut(room_id) {
            Some(r) => {
                r.members.remove(user_id);
                r.active.remove(user_id);
                r.private
            }
            None => false,
        };
        let frame = Frame::from(notification(
            "room_update",
            obj! {"left" => vec![Json::from(obj! {"room_id" => room_id})], "memberships" => vec![Json::from(membership)]},
        ));
        self.send_to_user(user_id, &frame);
        // The room no longer counts toward the user's unread (§4.9), and
        // neither do the threads of a private room, joined or not, which
        // the user can no longer see: their counts are all taken again.
        if private {
            self.hide_threads_locked(user_id, room_id);
            self.unread_changed_locked(user_id, "");
        } else {
            self.unread_changed_locked(user_id, room_id);
        }
        self.remove_if_empty_locked(room_id);
        true
    }

    /// Removes a thread or private room nobody is in any more, with its
    /// threads and the messages in them, as apron-server-cloudflare's
    /// removeIfEmpty does; their records stay in the log until they expire.
    /// Everyone has left it, so nobody is told; a room_list delta from
    /// before the removal is answered with a full listing.
    fn remove_if_empty_locked(&mut self, room_id: &str) {
        if !self
            .rooms
            .get(room_id)
            .is_some_and(|r| r.removable() && r.members.is_empty())
        {
            return;
        }
        let mut doomed = vec![room_id.to_owned()];
        let mut i = 0;
        while i < doomed.len() {
            doomed.extend(self.rooms[&doomed[i]].children.iter().cloned());
            i += 1;
        }
        let messages: Vec<String> = self
            .messages
            .values()
            .filter(|m| doomed.contains(&m.room_id))
            .map(|m| m.id.clone())
            .collect();
        for id in messages {
            self.remove_message_locked(&id);
        }
        // Threads first, so each parent has no children left when it goes.
        for id in doomed.iter().rev() {
            self.remove_thread_locked(id, false);
        }
        self.rooms_removed_at = self.last_id;
        for u in self.users.values_mut() {
            u.unread = None;
        }
    }

    /// Follows u leaving the private room r: u can no longer see the threads
    /// it could see there, at any depth, so u leaves those it joined, and
    /// u's connections receive room_update left for the others.
    pub fn hide_threads_locked(&mut self, user_id: &str, room_id: &str) {
        let mut hidden: Vec<Json> = Vec::new();
        self.walk_hidden_threads(user_id, room_id, &mut hidden);
        if !hidden.is_empty() {
            let frame = room_update("left", hidden);
            self.send_to_user(user_id, &frame);
        }
    }

    fn walk_hidden_threads(&mut self, user_id: &str, room_id: &str, hidden: &mut Vec<Json>) {
        let children = self
            .rooms
            .get(room_id)
            .map(|r| r.children.clone())
            .unwrap_or_default();
        for thread in children {
            let Some(t) = self.rooms.get(&thread) else {
                continue;
            };
            let (private, member) = (t.private, t.members.contains(user_id));
            if private && !member {
                continue;
            }
            if private {
                self.leave_locked(user_id, &thread);
                continue;
            }
            if !self.leave_locked(user_id, &thread) {
                hidden.push(obj! {"room_id" => thread.as_str()}.into());
            }
            self.walk_hidden_threads(user_id, &thread, hidden);
        }
    }

    /// Logs a room record holding `fields`, the client fields other than
    /// parent_room_id and private. An unknown `room_id` creates the room,
    /// private if asked; an empty one names it by its creation log_id.
    /// Returns the room's id.
    pub fn commit_room_locked(
        &mut self,
        room_id: &str,
        parent: Option<String>,
        private: bool,
        fields: Object,
    ) -> String {
        let log_id = self.next_id_locked();
        let mut room_id = room_id.to_owned();
        if !self.rooms.contains_key(&room_id) {
            if room_id.is_empty() {
                room_id = format_id(log_id);
            }
            let r = RoomState {
                id: room_id.clone(),
                parent: parent.clone(),
                private,
                created_id: log_id,
                ..RoomState::default()
            };
            self.rooms.insert(room_id.clone(), r);
            if let Some(parent) = parent.as_ref().and_then(|p| self.rooms.get_mut(p)) {
                parent.children.push(room_id.clone());
            }
        }
        let r = self.rooms.get_mut(&room_id).expect("room exists");
        let mut record = obj! {"room_id" => r.id.as_str(), "log_id" => format_id(log_id)};
        if r.record_log_id != 0 {
            record.insert("prev_log_id".into(), format_id(r.record_log_id).into());
        }
        if let Some(parent) = &r.parent {
            record.insert("parent_room_id".into(), parent.as_str().into());
        }
        if r.private {
            record.insert("private".into(), true.into());
        }
        record.extend(fields);
        r.record = record.clone();
        r.record_log_id = log_id;
        self.append_locked(
            LogRecord::new(log_id, RecordKind::Room, &record),
            &[room_id.clone()],
        );
        room_id
    }

    /// Sends a room's current record as room_update updated to its members,
    /// the parent's members for a thread that is not private, and editor, if
    /// any.
    pub fn announce_room_locked(&self, room_id: &str, editor: Option<&str>) {
        let Some(r) = self.rooms.get(room_id) else {
            return;
        };
        let mut audience = r.members.clone();
        if let Some(parent) = r
            .parent
            .as_ref()
            .filter(|_| !r.private)
            .and_then(|p| self.rooms.get(p))
        {
            audience.extend(parent.members.iter().cloned());
        }
        if let Some(editor) = editor {
            audience.insert(editor.to_owned());
        }
        let frame = room_update("updated", vec![r.params(self.history_floor).into()]);
        for member in audience {
            self.send_to_user(&member, &frame);
        }
    }

    /// Sends a read cursor to the user's other connections, within
    /// ACTIVITY_RELAYS_PER_MINUTE; one past it is kept but not relayed, and
    /// devices learn of it at their next listing.
    fn relay_read_locked(&mut self, c: &Client, user_id: &str, frame: &Object) {
        let u = self.users.get_mut(user_id).expect("user exists");
        if u.clients.len() < 2 || !u.read_relays.get_or_insert_with(activity_limiter).allow() {
            return;
        }
        let Some(frame) = super::server::render(frame) else {
            return;
        };
        for id in &self.users[user_id].clients {
            if *id != c.id {
                if let Some(conn) = self.clients.get(id) {
                    conn.client.enqueue_frame(frame.clone());
                }
            }
        }
    }

    /// Reports whether the user's typing may be relayed, within
    /// ACTIVITY_RELAYS_PER_MINUTE; past it the sender is told once a
    /// minute with a ~private notice.
    fn admit_typing_locked(&mut self, c: &Client, user_id: &str, room_id: &str) -> bool {
        let u = self.users.get_mut(user_id).expect("user exists");
        if u.typing_relays.get_or_insert_with(activity_limiter).allow() {
            return true;
        }
        let now = rust_stdlib::time::now().unix_milli();
        if now - u.typing_notice_at >= 60_000 {
            u.typing_notice_at = now;
            c.enqueue(&super::commands::private_notice(
                &self.rooms[room_id],
                &format!("Typing updates are limited to {ACTIVITY_RELAYS_PER_MINUTE} per minute, so others may not see you typing for a moment."),
            ));
        }
        false
    }

    /// Checks that u may save r's client fields: only an admin saves
    /// `general`, and only an admin or mod (ROOM_CREATOR_ROLES) a public
    /// top-level room; anyone a thread, and a private room's members theirs.
    fn may_edit_room_locked(&self, u: &UserState, r: &RoomState) -> Result<(), RpcError> {
        if r.id == DEFAULT_ROOM_ID {
            if !u.has_role(ADMIN_ROLE) {
                return Err(RpcError::new(
                    CODE_DENIED,
                    "Only an admin may edit the general room",
                ));
            }
        } else if r.parent.is_none() && !r.private && !u.has_any_role(ROOM_CREATOR_ROLES) {
            return Err(RpcError::new(
                CODE_DENIED,
                "Only an admin or mod may edit a room; anyone may edit a thread",
            ));
        }
        Ok(())
    }

    /// The rooms MAX_THREADS bounds: every room but `general` and private
    /// top-level rooms, which their own caps bound.
    fn thread_count(&self) -> usize {
        self.rooms
            .values()
            .filter(|r| r.id != DEFAULT_ROOM_ID && !(r.parent.is_none() && r.private))
            .count()
    }

    /// The threads user_id created whose history retention has not
    /// discarded entirely.
    fn live_threads_created_by(&self, user_id: &str) -> usize {
        self.rooms
            .values()
            .filter(|r| {
                r.parent.is_some()
                    && r.creator == user_id
                    && r.history_log_id(self.history_floor).is_some()
            })
            .count()
    }

    fn user_of(&self, c: &Client) -> Result<String, RpcError> {
        self.client_user(c)
            .ok_or_else(|| RpcError::new(CODE_DENIED, "Sign in before sending requests"))
    }

    /// Creates a room (no room_id) or replaces an existing room's client
    /// fields (§4.2.4). parent_room_id and private are fixed at creation and
    /// ignored on updates; a thread created without private takes its
    /// parent's.
    pub fn set_room_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let updating = req.params.contains_key("room_id");
        let mut room_id = String::new();
        let mut parent_id = String::new();
        if updating {
            room_id = parse_string(&req.params, "room_id", true)?;
        } else if req.params.contains_key("parent_room_id") {
            parent_id = parse_string(&req.params, "parent_room_id", true)?;
            if parent_id.is_empty() {
                return Err(invalid_params("parent_room_id must be a non-empty string"));
            }
        }
        let mut title = parse_string(&req.params, "title", false)?;
        let description = parse_string(&req.params, "description", false)?;
        if description.len() > MAX_DESCRIPTION_BYTES {
            return Err(RpcError::new(
                CODE_TOO_LARGE,
                format!("description is at most {MAX_DESCRIPTION_BYTES} bytes"),
            ));
        }
        let (ext_write, _) = parse_ext(&req.params, "ext")?;
        let mut private = parse_bool(&req.params, "private", false)?;

        let user_id = self.user_of(c)?;
        let mut parent: Option<String> = None;
        let mut kept_ext = ExtObject::new();
        let mut private_room = private;
        if updating {
            let Some(existing) = self.visible_room_locked(&user_id, &room_id) else {
                return Err(invalid_params(format!("Unknown room {}", quote(&room_id))));
            };
            parent = existing.parent.clone();
            private_room = existing.private;
            kept_ext = ext_of(existing.record.get("ext"));
            self.may_edit_room_locked(&self.users[&user_id], existing)?;
        } else if !parent_id.is_empty() {
            let Some(parent_room) = self.visible_room_locked(&user_id, &parent_id) else {
                return Err(invalid_params(format!(
                    "Unknown parent room {}",
                    quote(&parent_id)
                )));
            };
            if parent_room.parent.is_some() {
                return Err(RpcError::new(CODE_DENIED, "Threads cannot be nested"));
            }
            let u = &self.users[&user_id];
            if u.persists() && self.live_threads_created_by(&user_id) >= MAX_THREADS_PER_USER {
                return Err(RpcError::new(
                    CODE_DENIED,
                    format!("You can have at most {MAX_THREADS_PER_USER} threads at once; one stops counting when everyone has left it or its history expires"),
                ));
            }
            parent = Some(parent_id.clone());
        } else if !private {
            if !self.users[&user_id].has_any_role(ROOM_CREATOR_ROLES) {
                return Err(RpcError::new(
                    CODE_DENIED,
                    "Only an admin or mod may create a room; others may create threads",
                ));
            }
            let created = self
                .rooms
                .values()
                .filter(|r| r.parent.is_none() && !r.private && r.id != DEFAULT_ROOM_ID)
                .count();
            if created >= MAX_CREATED_ROOMS {
                return Err(RpcError::new(CODE_DENIED, "room_limit"));
            }
        } else if !self.users[&user_id].account() {
            return Err(RpcError::new(
                CODE_DENIED,
                "Sign in to start a private room",
            ));
        } else if self.private_rooms_full_locked(&self.users[&user_id]) {
            return Err(RpcError::new(
                CODE_DENIED,
                format!(
                    "You are in {} private rooms, the most at once; leave one to start another",
                    self.config.max_private_rooms
                ),
            ));
        }
        let counted = !(updating || private && parent.is_none());
        if counted && self.thread_count() >= MAX_THREADS {
            return Err(RpcError::new(CODE_DENIED, "thread_limit"));
        }
        // ext merges into the room's (§4.12), and the limit applies to the
        // result; other client fields are replaced (§4.2.4).
        let ext = merge_ext(&kept_ext, &ext_write);
        if encoded_size(&Json::Ext(ext.clone())) > MAX_ROOM_EXT_BYTES {
            return Err(RpcError::new(
                CODE_TOO_LARGE,
                format!("The room's ext would be over {MAX_ROOM_EXT_BYTES} bytes"),
            ));
        }
        self.charge_post_locked(c, &user_id, Some(Category::Write))?;
        let mut fields = Object::new();
        if title.is_empty() && parent.is_some() {
            // Servers title threads so clients unaware of parent_room_id
            // render them.
            title = thread_title(&description);
        } else if title.trim().is_empty() && parent.is_none() && !private_room {
            // So do public top-level rooms, as on Cloudflare; a private room
            // goes without, and clients name it after its members.
            title = if room_id == DEFAULT_ROOM_ID {
                DEFAULT_ROOM_TITLE
            } else {
                TOP_LEVEL_ROOM_TITLE
            }
            .into();
        }
        if !title.is_empty() {
            fields.insert("title".into(), title.into());
        }
        if !description.is_empty() {
            fields.insert("description".into(), description.into());
        }
        if !ext.is_empty() {
            fields.insert("ext".into(), Json::Ext(ext));
        }
        if !req.params.contains_key("private") && !updating {
            if let Some(parent) = parent.as_ref().and_then(|p| self.rooms.get(p)) {
                // A thread created without private takes its parent's
                // (§4.2.4).
                private = parent.private;
            }
        }
        // The server's description follows general's while nothing else
        // sets it (§3.1).
        let described = self.server_description();
        let room_id = self.commit_room_locked(&room_id, parent.clone(), private, fields);
        if room_id == DEFAULT_ROOM_ID && self.server_description() != described {
            self.announce_server_locked();
        }
        if !updating {
            self.rooms.get_mut(&room_id).expect("room exists").creator = user_id.clone();
        }
        self.touch_room(&room_id);
        // Room updates precede the result, so the room is known when it
        // arrives.
        if updating {
            self.announce_room_locked(&room_id, Some(&user_id));
        } else {
            // The room record and the membership are both logged before the
            // room_update, whose latest_log_id is then the membership's.
            self.users
                .get_mut(&user_id)
                .expect("user exists")
                .joined
                .insert(room_id.clone());
            self.rooms
                .get_mut(&room_id)
                .expect("room exists")
                .members
                .insert(user_id.clone());
            self.touch_user(&user_id);
            let membership = self.log_membership_locked(&user_id, &room_id, true);
            let r = self.rooms.get_mut(&room_id).expect("room exists");
            let latest = r.latest_id;
            r.active.insert(user_id.clone(), latest);
            let frame = self.joined_update_locked(&room_id, Some(&membership));
            self.send_to_user(&user_id, &frame);
            // A private thread's record goes only to its own members.
            let r = &self.rooms[&room_id];
            if let Some(parent) = parent
                .as_ref()
                .filter(|_| !r.private)
                .and_then(|p| self.rooms.get(p))
            {
                let frame = room_update("updated", vec![r.params(self.history_floor).into()]);
                for id in &parent.members {
                    if *id != user_id {
                        self.send_to_user(id, &frame);
                    }
                }
            }
        }
        let result = obj! {"room_id" => room_id};
        c.send_result(req, result.clone().into());
        Ok((result.into(), true))
    }

    /// Answers room_list (§4.2.1): the rooms matching its filters, joined
    /// ones in `joined` and visible unjoined ones in `not_joined`, each most
    /// recently active first; MAX_THREADS and MAX_CREATED_ROOMS bound both.
    /// The result is followed by the read cursors kept for the listed rooms
    /// (§4.6).
    /// Charges a `room_list` to the user's minute, except the first
    /// `joined` listing after a sign-in, which is how a client learns its
    /// rooms.
    fn charge_room_list_locked(&mut self, c: &Client, req: &Request) -> Result<(), RpcError> {
        let Some(conn) = self.clients.get_mut(&c.id) else {
            return Ok(());
        };
        let Some(user_id) = conn.user.clone() else {
            return Ok(());
        };
        let joined = parse_string(&req.params, "filter", false).is_ok_and(|f| f == "joined");
        if joined && !conn.listed_joined {
            conn.listed_joined = true;
            return Ok(());
        }
        let user = Principal::User(user_id);
        let charge = Charge {
            scope: Scope::RoomList,
            principal: &user,
            allowance: Allowance::minute(self.config.limits.room_lists_per_user_minute),
        };
        self.limits.charge(&[charge], 1).map_err(|refusal| {
            refused(
                "Room listing limited",
                refusal.retry_after(),
                Some(Category::Read),
            )
        })
    }

    pub fn list_rooms_locked(
        &self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let mut filter = parse_string(&req.params, "filter", false)?;
        match filter.as_str() {
            "" => filter = "all".into(),
            "all" | "joined" | "not_joined" => {}
            _ => return Err(invalid_params("filter must be joined, not_joined, or all")),
        }
        let (want_joined, want_others) = (filter != "not_joined", filter != "joined");
        let with_members = parse_bool(&req.params, "members", false)?;
        let parent_id = parse_string(&req.params, "parent_room_id", false)?;
        let has_parent = req.params.contains_key("parent_room_id");
        let room_id = parse_string(&req.params, "room_id", false)?;
        let has_room = req.params.contains_key("room_id");
        let only_user = parse_string(&req.params, "user_id", false)?;
        let has_user = req.params.contains_key("user_id");
        let mut since = parse_bound(&req.params, "latest_log_id")?;
        // A delta cannot name the rooms removed since then
        // (§4.2.1 asks that it list deleted rooms in left), so the listing
        // is then full, which a server may always send.
        if since.is_some_and(|since| since <= self.rooms_removed_at) {
            since = None;
        }

        let user_id = self.user_of(c)?;
        let u = &self.users[&user_id];
        let candidates: Vec<&RoomState> = if has_room {
            let Some(r) = self.visible_room_locked(&user_id, &room_id) else {
                return Err(invalid_params(format!("Unknown room {}", quote(&room_id))));
            };
            vec![r]
        } else if has_parent {
            let Some(parent) = self.visible_room_locked(&user_id, &parent_id) else {
                return Err(invalid_params(format!(
                    "Unknown parent room {}",
                    quote(&parent_id)
                )));
            };
            parent
                .children
                .iter()
                .filter_map(|id| self.rooms.get(id))
                .collect()
        } else {
            self.rooms.values().collect()
        };
        let mut joined: Vec<&RoomState> = Vec::new();
        let mut others: Vec<&RoomState> = Vec::new();
        let mut left: Vec<&RoomState> = Vec::new();
        for r in candidates {
            if since.is_some_and(|since| r.latest_id <= since) {
                continue;
            }
            if u.joined.contains(&r.id) {
                if want_joined {
                    joined.push(r);
                }
                continue;
            }
            if let Some(since) = since {
                if want_joined && u.left_at.get(&r.id).copied().unwrap_or(0) > since {
                    left.push(r);
                }
            }
            // Without parent_room_id or room_id, unjoined threads are left to
            // their parent's listing. Private rooms are listed only to their
            // members.
            if want_others
                && (has_room || has_parent || r.parent.is_none())
                && self.room_visible_to(&r.id, &user_id)
            {
                others.push(r);
            }
        }
        let by_activity = |a: &&RoomState, b: &&RoomState| {
            b.latest_id
                .cmp(&a.latest_id)
                .then_with(|| b.created_id.cmp(&a.created_id))
        };
        joined.sort_by(by_activity);
        others.sort_by(by_activity);
        left.sort_by(by_activity);

        let mut users: BTreeSet<String> = BTreeSet::new();
        let mut render_rooms = |rooms: &[&RoomState]| -> Vec<Json> {
            rooms
                .iter()
                .map(|r| {
                    let mut entry = r.params(self.history_floor);
                    if with_members && has_user {
                        let mut refs: Vec<Json> = Vec::new();
                        if r.members.contains(&only_user) {
                            if let Some(m) = self.users.get(&only_user) {
                                refs.push(m.shown_object().into());
                                users.insert(only_user.clone());
                            }
                        }
                        entry.insert("members".into(), refs.into());
                    } else if with_members {
                        users.extend(self.add_members_locked(&mut entry, r));
                    }
                    entry.into()
                })
                .collect()
        };
        let mut result = Object::new();
        if want_joined {
            result.insert("joined".into(), render_rooms(&joined).into());
        }
        if want_others {
            result.insert("not_joined".into(), render_rooms(&others).into());
        }
        if since.is_some() && want_joined {
            let gone: Vec<Json> = left
                .iter()
                .map(|r| obj! {"room_id" => r.id.as_str()}.into())
                .collect();
            result.insert("left".into(), gone.into());
        }
        if with_members {
            result.insert("users".into(), profiles(self, &users).into());
        }
        let mut frames: Vec<Frame> = Vec::new();
        if let Some(frame) = super::server::render(&response(&req.id, result.clone().into())) {
            frames.push(frame);
        }
        for r in joined.iter().chain(others.iter()) {
            frames.extend(self.cursor_frames_locked(u, r));
        }
        c.enqueue_frames(frames);
        Ok((result.into(), true))
    }

    /// Joins a visible room (§4.2.2). With the user_id of another user, a
    /// member of the room adds that user, which is how people are brought
    /// into a private room; adding a member changes nothing.
    pub fn join_room_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let (room_id, target_id, has_target) = parse_membership_params(&req.params)?;
        let user_id = self.user_of(c)?;
        let Some(r) = self.visible_room_locked(&user_id, &room_id) else {
            return Err(invalid_params(format!("Unknown room {}", quote(&room_id))));
        };
        let mut target = user_id.clone();
        if has_target && target_id != user_id {
            // An admin adds anyone, an account its own bot, and, while
            // addmember is on, any account anyone. Adding is the only way
            // into a private room, so there any member but a guest or bot
            // may.
            let u = &self.users[&user_id];
            if r.private && !u.account() {
                return Err(RpcError::new(
                    CODE_DENIED,
                    "Only a signed-in member who is not a bot can add someone to a private room",
                ));
            }
            let may_add = u.has_role(ADMIN_ROLE)
                || (u.account()
                    && (r.private
                        || self.feature_on(Feature::AddMember)
                        || owns_bot(u, &target_id)));
            if !may_add {
                return Err(RpcError::new(
                    CODE_DENIED,
                    "Only an admin, or a bot's owner, can add someone else here",
                ));
            }
            if !r.members.contains(&user_id) {
                return Err(RpcError::new(
                    CODE_DENIED,
                    format!("Join {} before adding others to it", r.title()),
                ));
            }
            let Some(t) = self.users.get(&target_id).filter(|t| t.persists()) else {
                return Err(invalid_params(format!(
                    "{target_id} is not a registered user"
                )));
            };
            // Adding someone to a thread of a private room takes adding them
            // to that room first.
            if let Some(parent) = &r.parent {
                if !self.room_visible_to(parent, &target_id) {
                    return Err(RpcError::new(
                        CODE_DENIED,
                        format!(
                            "Add {target_id} to the private room {} is in first",
                            r.title()
                        ),
                    ));
                }
            }
            if r.private
                && r.parent.is_none()
                && !r.members.contains(&t.id)
                && self.private_rooms_full_locked(t)
            {
                return Err(RpcError::new(
                    CODE_DENIED,
                    format!("{target_id} is in as many private rooms as anyone may be, so cannot be added to another"),
                ));
            }
            target = target_id;
        }
        if !r.members.contains(&target) {
            self.charge_post_locked(c, &user_id, Some(Category::Write))?;
        }
        if !self.join_locked(&target, &room_id) && target == user_id {
            let frame = self.joined_update_locked(&room_id, None);
            c.enqueue_frame(frame);
        }
        let result = Object::new();
        c.send_result(req, result.clone().into());
        Ok((result.into(), true))
    }

    /// Leaves a room (§4.2.2). With the user_id of another user, it removes
    /// that user, as `RoomState::may_remove` allows.
    pub fn leave_room_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let (room_id, target_id, has_target) = parse_membership_params(&req.params)?;
        let user_id = self.user_of(c)?;
        let Some(r) = self.visible_room_locked(&user_id, &room_id) else {
            return Err(invalid_params(format!("Unknown room {}", quote(&room_id))));
        };
        let mut target = user_id.clone();
        if has_target && target_id != user_id {
            if !r.may_remove(&self.users[&user_id], &target_id) {
                return Err(RpcError::new(
                    CODE_DENIED,
                    "Only an admin, the room's creator, or a bot's owner, can remove someone else",
                ));
            }
            if !self.users.contains_key(&target_id) {
                return Err(invalid_params(format!(
                    "No user has the user_id {target_id}"
                )));
            }
            target = target_id;
        }
        if r.members.contains(&target) {
            self.charge_post_locked(c, &user_id, Some(Category::Write))?;
        }
        self.leave_locked(&target, &room_id);
        let result = Object::new();
        c.send_result(req, result.clone().into());
        Ok((result.into(), true))
    }

    /// Returns a window of the log (§4.3): with room_id, that room's log,
    /// which needs no membership, only a room the user can see; without it,
    /// the log of every room the user joined, as one log. limit counts
    /// records of every kind; the slice is partitioned into rooms, messages,
    /// reactions, and membership, each omitted when empty.
    pub fn history_locked(&self, c: &Arc<Client>, req: &Request) -> Result<(Json, bool), RpcError> {
        let room_id = parse_string(&req.params, "room_id", false)?;
        let has_room = req.params.contains_key("room_id");
        let after = parse_bound(&req.params, "after")?;
        let before = parse_bound(&req.params, "before")?;
        let limit = parse_limit(&req.params, self.config.history_page_size)?;

        let user_id = self.user_of(c)?;
        let rooms: Vec<&RoomState> = if has_room {
            let Some(r) = self.visible_room_locked(&user_id, &room_id) else {
                return Err(invalid_params(format!("Unknown room {}", quote(&room_id))));
            };
            vec![r]
        } else {
            self.users[&user_id]
                .joined
                .iter()
                .filter(|id| self.room_visible_to(id, &user_id))
                .filter_map(|id| self.rooms.get(id))
                .collect()
        };
        // The rooms' windows merge by log_id from the end the page starts
        // at, until limit+1 records: a move snapshot in two of them is one
        // record, the same in both logs, and comes once.
        let has_after = after.is_some();
        let mut windows: Vec<&[i64]> = Vec::new();
        let mut latest = 0i64;
        for r in &rooms {
            latest = latest.max(r.latest_id);
            let records = window(&r.log, after, before);
            if !records.is_empty() {
                windows.push(records);
            }
        }
        let mut matching: Vec<i64> = Vec::new();
        while matching.len() <= limit {
            let mut next: Option<i64> = None;
            for records in &windows {
                if records.is_empty() {
                    continue;
                }
                let head = if has_after {
                    records[0]
                } else {
                    records[records.len() - 1]
                };
                next = Some(match next {
                    None => head,
                    Some(n) if (has_after && head < n) || (!has_after && head > n) => head,
                    Some(n) => n,
                });
            }
            let Some(next) = next else { break };
            matching.push(next);
            for records in windows.iter_mut() {
                if records.is_empty() {
                    continue;
                }
                if has_after && records[0] == next {
                    *records = &records[1..];
                } else if !has_after && records[records.len() - 1] == next {
                    *records = &records[..records.len() - 1];
                }
            }
        }
        if !has_after {
            matching.reverse();
        }
        // With room_id, the room's log starts at its creation. Without it,
        // the log of the joined rooms starts where the server's does, at the
        // default room's creation (§4.3.3); for a user in no rooms it is
        // empty, ending just before. Retention moves either start up to the
        // history floor, and a log retention emptied has none.
        let mut created = self
            .rooms
            .get(DEFAULT_ROOM_ID)
            .map(|r| r.created_id)
            .unwrap_or(0);
        if has_room {
            created = rooms[0].created_id;
        }
        let start = created.max(self.history_floor);
        if rooms.is_empty() {
            latest = start - 1;
        }
        let mut more = matching.len() > limit;
        if more {
            if has_after {
                matching.truncate(limit);
            } else {
                matching.remove(0);
            }
        }
        // A page also stops at MAX_HISTORY_REPLY_BYTES of records, keeping
        // at least one, so one request cannot hold the lock to render an
        // unbounded reply.
        let mut size = 0usize;
        for i in 0..matching.len() {
            let k = if has_after { i } else { matching.len() - 1 - i };
            size += self.records.get(&matching[k]).map_or(0, |r| r.raw.len());
            if size > MAX_HISTORY_REPLY_BYTES && i > 0 {
                if has_after {
                    matching.truncate(k);
                } else {
                    matching.drain(..=k);
                }
                more = true;
                break;
            }
        }
        let records: Vec<&LogRecord> = matching
            .iter()
            .filter_map(|id| self.records.get(id))
            .collect();
        let has_history = !rooms.is_empty() && start <= latest;
        let result = render_history(latest, start, has_history, &records, more, size);
        // The records are already JSON: the reply is assembled from them
        // without decoding or re-encoding.
        c.enqueue_frame(Frame::from(raw_response(&req.id, &result)));
        Ok((Json::Raw(Value::from(result)), true))
    }

    /// Applies a connection's activity (§4.6). typing is relayed to the
    /// room's other members, at most MAX_TYPING_SECONDS and within
    /// ACTIVITY_RELAYS_PER_MINUTE. A read cursor must name a message and only
    /// advances; an account's is kept, sent after the room is listed, and
    /// relayed to its other connections, or with Config.read_receipts to the
    /// room's members; a guest's is dropped.
    pub fn activity_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let mut room_id = parse_string(&req.params, "room_id", false)?;
        if !req.params.contains_key("room_id") {
            room_id = DEFAULT_ROOM_ID.into();
        }
        let mut typing: Option<i64> = None;
        if let Some(raw) = req.params.get("typing") {
            let mut value: i64 = 0;
            if rust_stdlib::encoding::json::v2::unmarshal(&raw.0, &mut value, &[]).is_err()
                || value < 0
            {
                return Err(invalid_params("typing must be a non-negative integer"));
            }
            typing = Some(value);
        }
        let read_id = parse_string(&req.params, "read_message_id", false)?;
        let has_read = req.params.contains_key("read_message_id");
        let user_id = self.user_of(c)?;
        let result = Object::new();
        // A read-only guest's typing and read cursors would reach others.
        if self.read_only_guest(&user_id) {
            return Ok((result.into(), false));
        }
        let in_room = typing.is_some() || has_read;
        let visible = self.visible_room_locked(&user_id, &room_id).is_some();
        if in_room && !visible {
            return Err(invalid_params(format!("Unknown room {}", quote(&room_id))));
        }
        if has_read && self.visible_message_locked(&user_id, &read_id).is_none() {
            return Err(invalid_params(format!(
                "Unknown read_message_id {}",
                quote(&read_id)
            )));
        }
        // The relays this request causes are queued before process_frame
        // sends its result (§1).
        if !in_room {
            return Ok((result.into(), false));
        }
        let from = self.users[&user_id].from();
        let mut params = obj! {"room_id" => room_id.as_str(), "from" => from.clone()};
        // Whether the cursor goes to the room's members, with read receipts.
        let mut read = false;
        // A guest's read cursor is dropped: guests keep nothing.
        if has_read && self.users[&user_id].persists() {
            let id: i64 = read_id.parse().unwrap_or(0);
            let joined = self.users[&user_id].joined.contains(&room_id);
            let r = self.rooms.get_mut(&room_id).expect("room exists");
            let advances = r.reads.get(&user_id).is_none_or(|cursor| id > cursor.id);
            if advances {
                r.reads.insert(
                    user_id.clone(),
                    ReadCursor {
                        from: from.clone(),
                        message_id: read_id.clone(),
                        id,
                    },
                );
                let latest = r.latest_id;
                self.touch_room(&room_id);
                if !joined && id >= latest {
                    // Read to the end: no earlier mention there counts.
                    self.users
                        .get_mut(&user_id)
                        .expect("user exists")
                        .pings
                        .remove(&room_id);
                    self.touch_user(&user_id);
                }
                let frame = obj! {"method" => "activity", "params" => obj! {
                    "room_id" => room_id.as_str(), "from" => from.clone(), "read_message_id" => read_id.as_str(),
                }};
                if !self.config.read_receipts {
                    self.relay_read_locked(c, &user_id, &frame);
                } else {
                    // Read receipts go to the room's members, and a cursor
                    // for a room the user has not joined to their own
                    // connections as well.
                    if !joined {
                        if let Some(frame) = super::server::render(&frame) {
                            self.send_to_user(&user_id, &frame);
                        }
                    }
                    params.insert("read_message_id".into(), read_id.as_str().into());
                    read = true;
                }
                // Reading lowers the unread count the user's other devices
                // show.
                self.unread_changed_locked(&user_id, &room_id);
            }
        }
        let mut typed = false;
        if let Some(typing) = typing {
            if self.admit_typing_locked(c, &user_id, &room_id) {
                params.insert("typing".into(), typing.min(MAX_TYPING_SECONDS).into());
                typed = true;
            }
        }
        // Typing goes to the room's other members only, as on Cloudflare;
        // a read receipt also to the user's own connections.
        let rooms = [room_id.clone()];
        if read && self.rooms[&room_id].members.contains(&user_id) {
            let mut own = params.clone();
            own.remove("typing");
            if let Some(frame) =
                super::server::render(&obj! {"method" => "activity", "params" => own})
            {
                self.send_to_user(&user_id, &frame);
            }
        }
        if typed || read {
            if let Some(frame) =
                super::server::render(&obj! {"method" => "activity", "params" => params})
            {
                self.deliver_except_locked(&frame, &rooms, &user_id);
            }
        }
        Ok((result.into(), false))
    }
}

/// Assembles a history result (§4.3) from a window of records, with the
/// queried log's head and the start of its history, which is null for a log
/// of no rooms or one retention emptied.
pub fn render_history(
    latest: i64,
    created: i64,
    has_history: bool,
    matching: &[&LogRecord],
    more: bool,
    size: usize,
) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(size + matching.len() + 256);
    buf.extend_from_slice(b"{\"more\":");
    buf.extend_from_slice(if more { b"true" } else { b"false" });
    for (key, kind) in [
        ("rooms", RecordKind::Room),
        ("messages", RecordKind::Message),
        ("reactions", RecordKind::Reactions),
        ("memberships", RecordKind::Membership),
    ] {
        let mut first = true;
        for record in matching {
            if record.kind != kind {
                continue;
            }
            if first {
                buf.extend_from_slice(b",\"");
                buf.extend_from_slice(key.as_bytes());
                buf.extend_from_slice(b"\":[");
                first = false;
            } else {
                buf.push(b',');
            }
            buf.extend_from_slice(&record.raw);
        }
        if !first {
            buf.push(b']');
        }
    }
    let field = |buf: &mut Vec<u8>, key: &str, id: i64| {
        buf.extend_from_slice(b",\"");
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(b"\":\"");
        buf.extend_from_slice(id.to_string().as_bytes());
        buf.push(b'"');
    };
    field(&mut buf, "latest_log_id", latest);
    if has_history {
        field(&mut buf, "history_log_id", created);
    } else {
        buf.extend_from_slice(b",\"history_log_id\":null");
    }
    if let (Some(first), Some(last)) = (matching.first(), matching.last()) {
        field(&mut buf, "first_log_id", first.id);
        field(&mut buf, "last_log_id", last.id);
    }
    buf.push(b'}');
    buf
}

impl Server {
    pub(crate) fn set_room(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        self.lock().set_room_locked(c, req)
    }
    pub(crate) fn list_rooms(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let mut st = self.lock();
        st.charge_room_list_locked(c, req)?;
        st.list_rooms_locked(c, req)
    }
    pub(crate) fn join_room(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        self.lock().join_room_locked(c, req)
    }
    pub(crate) fn leave_room(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        self.lock().leave_room_locked(c, req)
    }
    pub(crate) fn history(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        self.lock().history_locked(c, req)
    }
    pub(crate) fn activity(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        self.lock().activity_locked(c, req)
    }
}
