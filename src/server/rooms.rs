use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rust_stdlib::encoding::json::jsontext::Value;

use super::client::{Client, Frame};
use super::limits::Category;
use super::messages::MessageState;
use super::protocol::*;
use super::server::{LogRecord, RecordKind, Server, State, DEFAULT_ROOM_ID};
use super::toggles::Feature;
use super::users::{UserState, ADMIN_ROLE};
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
    pub fn may_remove(&self, u: &UserState, target: Option<&UserState>) -> bool {
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
fn owns_bot(u: &UserState, target: Option<&UserState>) -> bool {
    target.is_some_and(|t| t.owner.as_deref() == Some(u.id.as_str()))
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

    /// Reports whether the room, or a room it is a thread of, is private.
    pub fn is_private(&self, room_id: &str) -> bool {
        !self.audience(room_id).0
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
            if let Some(frame) = super::client::render(&frame) {
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
    pub(super) fn deliver_except_locked(&self, frame: &Frame, rooms: &[String], except: &str) {
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
    /// the membership. A thread or private room left empty is removed.
    /// Reports whether u was a member.
    pub fn leave_locked(&mut self, user_id: &str, room_id: &str) -> bool {
        if !self.depart_locked(user_id, room_id) {
            return false;
        }
        self.remove_if_empty_locked(room_id);
        true
    }

    /// The leave itself, without removing a room it leaves empty: for a
    /// retired guest, whose connection closed rather than left. Cloudflare's
    /// connectionGone removes nothing, so the guest's thread stays listed
    /// until someone leaves it or its log expires.
    pub fn depart_locked(&mut self, user_id: &str, room_id: &str) -> bool {
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
        true
    }

    /// Removes a thread or private room nobody is in any more, with its
    /// threads and the messages in them, as apron-server-cloudflare's
    /// removeIfEmpty does; their records stay in the log until they expire.
    /// Everyone has left it, so nobody is told; a room_list delta from
    /// before the removal is answered with a full listing.
    pub(super) fn remove_if_empty_locked(&mut self, room_id: &str) {
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

    pub(super) fn user_of(&self, c: &Client) -> Result<String, RpcError> {
        self.client_user(c)
            .ok_or_else(|| RpcError::new(CODE_DENIED, "Sign in before sending requests"))
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
                        || owns_bot(u, self.users.get(&target_id))));
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
            if !r.may_remove(&self.users[&user_id], self.users.get(&target_id)) {
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
}

impl Server {
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
}
