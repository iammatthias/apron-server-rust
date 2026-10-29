//! Status (§4.5). The chosen status is set with `me`: online (the default),
//! "" for none, dnd, or invisible; the server stores "" for any other
//! value. The presence is online while a connection is attended, idle while
//! connected with none attended, and offline without a connection. Others
//! see the shown status, which the two give (§4.5.1):
//!
//! ```text
//! chosen     presence online  presence idle  presence offline
//! online     online           idle           offline
//! dnd        dnd              dnd            offline
//! invisible  offline          offline        offline
//! ""         ""               ""             ""
//! ```
//!
//! and the user sees, in `you`, the chosen status. Others see the shown
//! status as last announced (`publish_locked`): a change held back to
//! coalesce a flapping user's changes shows nowhere until it is sent. seen
//! is when the announced shown status last became offline (§4.5.2).
//! Separately, each connection reports whether it is idle, and the user
//! mutes their notifications everywhere or in one room and its threads;
//! mutes and a dnd status silence pushes (§4.9). Both are set with the
//! `status` request. Mutes are private: each change goes to every
//! connection of the user as a `status` notification, and the mutes in
//! effect to a connection after a sign-in. A connection starts attended,
//! and only its own `idle` with the seconds since attention stopped makes
//! it idle, until its `idle: false` (§4.5.3).

use std::sync::Arc;

use rust_stdlib::time::{self, Duration, Time};

use super::client::{Client, Frame};
use super::protocol::*;
use super::server::{Server, State};
use super::toggles::Feature;
use super::users::UserState;
use super::wake::HELD_WAKE_WINDOW;
use crate::obj;

pub const STATUS_ONLINE: &str = "online";
pub const STATUS_IDLE: &str = "idle";
pub const STATUS_DND: &str = "dnd";
pub const STATUS_INVISIBLE: &str = "invisible";
pub const STATUS_OFFLINE: &str = "offline";
pub const STATUS_NONE: &str = "";
/// Caps a timed mute at a year; `true` mutes until changed.
pub const MAX_MUTE_SECONDS: i64 = 365 * 24 * 60 * 60;
/// Bounds the rooms a user mutes at once.
pub const MAX_ROOM_MUTES: usize = 100;
/// What changed a user's status, which decides when others hear of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// A connection signed in, or said it is idle or back.
    Connection,
    /// A connection closed or signed in as someone else.
    Closed,
}

/// The optional statuses the server accepts, which the server frame lists as
/// server.status (§3.1, §4.5).
pub fn optional_statuses() -> Vec<String> {
    vec![STATUS_DND.into(), STATUS_INVISIBLE.into()]
}

/// Reports whether the server supports `value` as a status a user sets
/// (§4.5); it stores "" for any other.
pub fn settable_status(value: &str) -> bool {
    value == STATUS_ONLINE || value == STATUS_NONE || optional_statuses().iter().any(|s| s == value)
}

/// A mute (§4.5): until a time, forever, or, when zero, none.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MuteState {
    pub forever: bool,
    pub until: Time,
}

impl MuteState {
    /// Reports whether the mute is in effect at `now`.
    pub fn active(&self, now: &Time) -> bool {
        self.forever || now.before(&self.until)
    }

    /// The mute as a `status` notification carries it: true, the seconds
    /// left, rounded up, or false when there is none.
    pub fn wire(&self, now: &Time) -> Json {
        if self.forever {
            return true.into();
        }
        if !self.active(now) {
            return false.into();
        }
        let left = self.until.sub(now).as_nanos() + time::SECOND.as_nanos() - 1;
        (left / time::SECOND.as_nanos()).into()
    }
}

/// Go's `retryAfter`: a retry_after error carrying `wait` rounded up to
/// seconds.
pub fn retry_after(message: &str, wait: Duration) -> RpcError {
    retry_after_seconds(message, seconds(wait))
}

pub fn retry_after_seconds(message: &str, seconds: i64) -> RpcError {
    RpcError::with_data(CODE_RETRY_AFTER, message, obj! {"retry_after" => seconds})
}

/// `wait` rounded up to whole seconds, at least one.
pub fn seconds(wait: Duration) -> i64 {
    ((wait.as_nanos() + time::SECOND.as_nanos() - 1) / time::SECOND.as_nanos()).max(1)
}

/// The `status` notification that tells the user's connections of a mute,
/// everywhere or, with `room_id`, of that room (§4.5).
pub fn mute_frame(room_id: &str, mute: &MuteState, now: &Time) -> Frame {
    let mut params = obj! {"mute" => mute.wire(now)};
    if !room_id.is_empty() {
        params.insert("room_id".into(), room_id.into());
    }
    Frame::from(notification("status", params))
}

impl UserState {
    /// Reports whether u's notifications are silenced everywhere: by the
    /// unscoped mute, or by a dnd status (§4.5).
    pub fn silenced(&self, now: &Time) -> bool {
        self.mute.active(now) || self.chosen == STATUS_DND
    }

    /// The shown status, from the chosen status and the presence (§4.5.1).
    /// `attended` is whether any connection has not said it is idle.
    pub fn shown_status(&self, attended: bool) -> String {
        match self.chosen.as_str() {
            STATUS_ONLINE => {
                if attended {
                    STATUS_ONLINE.into()
                } else if !self.clients.is_empty() {
                    STATUS_IDLE.into()
                } else {
                    STATUS_OFFLINE.into()
                }
            }
            // dnd shows only while connected, so it does not tell others
            // that the user is reachable when they are not (§4.5).
            STATUS_DND => {
                if !self.clients.is_empty() {
                    STATUS_DND.into()
                } else {
                    STATUS_OFFLINE.into()
                }
            }
            STATUS_INVISIBLE => STATUS_OFFLINE.into(),
            other => other.into(),
        }
    }

    /// The user's own current object (§3.3): its profile, with the chosen
    /// status in place of the shown one, and never seen (§4.5.2).
    pub fn you(&self) -> Object {
        let mut profile = self.profile();
        profile.insert("status".into(), self.chosen.as_str().into());
        profile.remove("seen");
        profile
    }

    /// Adds u's seen to a current object of u that carries a shown offline,
    /// if it is known (§4.5.2).
    pub fn add_seen(&self, object: &mut Object) {
        if object.get("status").and_then(Json::as_str) == Some(STATUS_OFFLINE) && self.seen > 0 {
            object.insert("seen".into(), self.seen.to_string().into());
        }
    }

    /// The bare current object of u that others see: user_id and the
    /// published shown status, with seen when it is offline (§4.5.2).
    pub fn shown_object(&self) -> Object {
        let mut object = obj! {"user_id" => self.id.as_str(), "status" => self.status.as_str()};
        self.add_seen(&mut object);
        object
    }
}

/// The `user` notification of u's published shown status: `{new: {user_id,
/// status}}`, with seen when it is offline (§4.5.2).
pub fn status_frame(u: &UserState) -> Frame {
    Frame::from(notification("user", obj! {"new" => u.shown_object()}))
}

impl State {
    /// Reports whether any connection of the user has not said it is idle
    /// (§4.5).
    pub fn attended(&self, u: &UserState) -> bool {
        u.clients.iter().any(|id| {
            self.clients
                .get(id)
                .is_some_and(|conn| conn.idle_since.is_none())
        })
    }

    /// Reports whether u's own mute of room r, or of a room r is a thread
    /// of, is in effect: it silences r, mentions too (§4.5).
    pub fn room_muted(&self, u: &UserState, room_id: &str, now: &Time) -> bool {
        let mut room = self.rooms.get(room_id);
        while let Some(r) = room {
            if u.room_mutes.get(&r.id).is_some_and(|m| m.active(now)) {
                return true;
            }
            room = r.parent.as_ref().and_then(|p| self.rooms.get(p));
        }
        false
    }

    /// Notes u's shown status after a change to its chosen status or its
    /// connections, and when it has just become offline, the time it did.
    pub fn note_shown_locked(&mut self, user_id: &str) {
        let Some(u) = self.users.get(user_id) else {
            return;
        };
        // With presence off, nobody is shown a status (`/toggle`).
        let shown = if self.feature_on(Feature::Presence) {
            u.shown_status(self.attended(u))
        } else {
            STATUS_NONE.to_owned()
        };
        let u = self.users.get_mut(user_id).expect("user exists");
        if shown == u.shown {
            return;
        }
        u.shown = shown;
        if u.shown == STATUS_OFFLINE {
            u.offline_at = time::now().unix_milli();
        }
    }

    /// Notes u's shown status and makes it the one others see (§4.5.2),
    /// reporting whether that changed; the caller sends it to those who
    /// share a room with u. Only a change to offline sets seen.
    pub fn publish_locked(&mut self, user_id: &str) -> bool {
        self.note_shown_locked(user_id);
        let Some(u) = self.users.get_mut(user_id) else {
            return false;
        };
        if u.shown == u.status {
            return false;
        }
        let was_offline = u.status == STATUS_OFFLINE;
        u.status = u.shown.clone();
        u.announced_at = time::now().unix_milli();
        if u.status == STATUS_OFFLINE {
            u.seen = u.offline_at;
            if u.seen == 0 {
                u.seen = time::now().unix_milli();
            }
            self.touch_user(user_id);
        } else if was_offline {
            self.touch_user(user_id);
        }
        true
    }

    /// Notes u's shown status, then publishes it and sends it to the
    /// connections of those who share a room with u, as `user` `new`, when
    /// it differs from the one last published: once `status_coalesce` has
    /// passed since the last change went out, with whatever the status is
    /// then, and, for a change a closed connection caused, once
    /// `offline_grace` has passed too, so a reconnect within it shows
    /// nothing. A shutdown sends nothing, but still publishes.
    pub fn announce_status_locked(&mut self, user_id: &str, cause: Cause) {
        self.note_shown_locked(user_id);
        if self.closed {
            self.publish_locked(user_id);
            return;
        }
        let (coalesce, grace) = (
            self.config.limits.status_coalesce.as_nanos() / 1_000_000,
            self.config.limits.offline_grace.as_nanos() / 1_000_000,
        );
        let Some(u) = self.users.get_mut(user_id) else {
            return;
        };
        if u.shown == u.status {
            // Back to what others were told: nothing waits.
            u.status_hold = 0;
            if let Some(timer) = u.status_timer.take() {
                timer.stop();
            }
            return;
        }
        let now = time::now().unix_milli();
        if cause == Cause::Closed {
            u.status_hold = u.status_hold.max(now + grace);
        }
        let last = if u.announced_at == 0 {
            0
        } else {
            u.announced_at + coalesce
        };
        let due = last.max(u.status_hold);
        if due > now {
            if u.status_timer.is_none() {
                let generation = u.generation;
                let server = self.server.clone();
                let id = user_id.to_owned();
                let wait = Duration::from_millis(due - now);
                u.status_timer = Some(time::after_func(wait, move || {
                    let Some(server) = server.upgrade() else {
                        return;
                    };
                    let mut st = server.lock();
                    let Some(u) = st.users.get_mut(&id) else {
                        return;
                    };
                    if u.generation != generation {
                        return;
                    }
                    u.status_timer = None;
                    st.announce_status_locked(&id, Cause::Connection);
                }));
            }
            return;
        }
        u.status_hold = 0;
        if self.publish_locked(user_id) {
            let sharers = self.sharers_locked(user_id);
            self.send_status_locked(user_id, &sharers);
        }
    }

    /// Tells the connections of `users` u's published shown status.
    pub fn send_status_locked(&self, user_id: &str, users: &[String]) {
        let Some(u) = self.users.get(user_id) else {
            return;
        };
        let frame = status_frame(u);
        for other in users {
            self.send_to_user(other, &frame);
        }
    }

    /// Tells the other members of r the published status of the user who
    /// just joined it, since its membership record carries only a recorded
    /// user object. It leaves out offline and "", which would tell who is
    /// invisible or opted out.
    pub fn announce_join_status_locked(&self, user_id: &str, room_id: &str) {
        let Some(u) = self.users.get(user_id) else {
            return;
        };
        if u.status == STATUS_OFFLINE || u.status == STATUS_NONE {
            return;
        }
        let Some(r) = self.rooms.get(room_id) else {
            return;
        };
        let users: Vec<String> = r
            .members
            .iter()
            .filter(|id| *id != user_id)
            .cloned()
            .collect();
        self.send_status_locked(user_id, &users);
    }

    /// Sends a connection that has just signed in, after its auth result
    /// (§4.5), one `status` for each of its user's mutes in effect, of rooms
    /// the user can see, and one `user` with the shown status of each user
    /// who shares a room with it. offline and "" are left out. In a room of
    /// more than max_listed_members, only the members the room lists count.
    pub fn send_after_auth_locked(&self, c: &Arc<Client>) {
        let Some(user_id) = self.client_user(c) else {
            return;
        };
        let u = &self.users[&user_id];
        let now = time::now();
        let mut frames: Vec<Frame> = Vec::new();
        if u.mute.active(&now) {
            frames.push(mute_frame("", &u.mute, &now));
        }
        for (id, mute) in &u.room_mutes {
            if mute.active(&now) && self.visible_room_locked(&user_id, id).is_some() {
                frames.push(mute_frame(id, mute, &now));
            }
        }
        let mut listed = std::collections::BTreeSet::new();
        for room_id in &u.joined {
            if let Some(r) = self.rooms.get(room_id) {
                let (ids, _) = self.listed_member_ids_locked(r);
                for id in ids {
                    if id != user_id {
                        listed.insert(id);
                    }
                }
            }
        }
        for id in listed {
            if let Some(other) = self.users.get(&id) {
                if other.status != STATUS_OFFLINE && other.status != STATUS_NONE {
                    frames.push(status_frame(other));
                }
            }
        }
        if !frames.is_empty() {
            c.enqueue_frames(frames);
        }
    }

    /// Ends u's timed mute when its time passes, telling the user's
    /// connections it is now false (§4.5).
    pub fn schedule_mute_locked(&mut self, user_id: &str) {
        let closed = self.closed;
        let server = self.server.clone();
        let Some(u) = self.users.get_mut(user_id) else {
            return;
        };
        if let Some(timer) = u.mute_timer.take() {
            timer.stop();
        }
        if closed || u.mute.forever || u.mute.until.is_zero() {
            return;
        }
        let until = u.mute.until.clone();
        let generation = u.generation;
        let id = user_id.to_owned();
        u.mute_timer = Some(time::after_func(time::until(&until), move || {
            let Some(server) = server.upgrade() else {
                return;
            };
            let mut st = server.lock();
            if st.closed {
                return;
            }
            let Some(u) = st.users.get_mut(&id) else {
                return;
            };
            if u.generation != generation || u.mute.forever || !u.mute.until.equal(&until) {
                return;
            }
            u.mute = MuteState::default();
            u.mute_timer = None;
            let frame = mute_frame("", &MuteState::default(), &time::now());
            st.touch_user(&id);
            st.send_to_user(&id, &frame);
        }));
    }

    /// Ends u's timed mute of room `room_id` when its time passes. Its end
    /// is sent like the unscoped mute's, and the unread counts are taken
    /// again (§4.9).
    pub fn schedule_room_mute_locked(&mut self, user_id: &str, room_id: &str) {
        let closed = self.closed;
        let server = self.server.clone();
        let Some(u) = self.users.get_mut(user_id) else {
            return;
        };
        if let Some(timer) = u.room_mute_timers.remove(room_id) {
            timer.stop();
        }
        let Some(mute) = u.room_mutes.get(room_id) else {
            return;
        };
        if closed || mute.forever || mute.until.is_zero() {
            return;
        }
        let until = mute.until.clone();
        let generation = u.generation;
        let id = user_id.to_owned();
        let room = room_id.to_owned();
        u.room_mute_timers.insert(
            room_id.to_owned(),
            time::after_func(time::until(&until), move || {
                let Some(server) = server.upgrade() else {
                    return;
                };
                let mut st = server.lock();
                if st.closed {
                    return;
                }
                let Some(u) = st.users.get(&id) else { return };
                if u.generation != generation {
                    return;
                }
                let Some(mute) = u.room_mutes.get(&room) else {
                    return;
                };
                if mute.forever || !mute.until.equal(&until) {
                    return;
                }
                st.end_room_mute_locked(&id, &room);
                st.unread_changed_locked(&id, "");
            }),
        );
    }

    /// Forgets u's mute of a room, which has run out, and tells the user's
    /// connections it is now false (§4.5). The caller takes the unread
    /// counts again.
    pub fn end_room_mute_locked(&mut self, user_id: &str, room_id: &str) {
        let Some(u) = self.users.get_mut(user_id) else {
            return;
        };
        if let Some(timer) = u.room_mute_timers.remove(room_id) {
            timer.stop();
        }
        u.room_mutes.remove(room_id);
        self.touch_user(user_id);
        let frame = mute_frame(room_id, &MuteState::default(), &time::now());
        self.send_to_user(user_id, &frame);
    }
}

/// A connection's report of attention (§4.5.3): `idle: false`, or the
/// whole seconds since attention stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Idle {
    Back,
    For(i64),
}

/// One parsed `status` request. `None` fields were absent.
#[derive(Debug, Default, PartialEq)]
pub struct StatusUpdate {
    /// The room the mute is of, when scoped.
    pub room_id: String,
    pub scoped: bool,
    pub idle: Option<Idle>,
    /// Present when `has_mute`: forever, a positive number of seconds, or,
    /// when neither, false, which ends it.
    pub has_mute: bool,
    pub mute_forever: bool,
    pub mute_seconds: i64,
}

impl StatusUpdate {
    /// The mute the update sets, starting at `now`.
    pub fn mute(&self, now: &Time) -> MuteState {
        if self.mute_forever {
            return MuteState {
                forever: true,
                until: Time::default(),
            };
        }
        if self.mute_seconds == 0 {
            return MuteState::default();
        }
        MuteState {
            forever: false,
            until: now.add(Duration::from_secs(self.mute_seconds)),
        }
    }
}

fn parse_i64(raw: &[u8]) -> Option<i64> {
    let mut value: i64 = 0;
    rust_stdlib::encoding::json::v2::unmarshal(raw, &mut value, &[])
        .ok()
        .map(|_| value)
}

/// Reads a status request's params (§4.5). Any field of the wrong type is
/// invalid_params, and then nothing changes: room_id a string, idle false or
/// a non-negative whole number of seconds, and mute true, false, or a
/// positive whole number of seconds, a longer one shortened to
/// MAX_MUTE_SECONDS. room_id scopes only the mute, so room_id without mute
/// is invalid_params: idle is about the connection either way.
pub fn parse_status(params: &Params) -> Result<StatusUpdate, RpcError> {
    let mut update = StatusUpdate::default();
    if params.contains_key("room_id") {
        update.room_id = parse_string(params, "room_id", true)?;
        update.scoped = true;
    }
    if let Some(raw) = params.get("idle") {
        // idle is false, or the seconds since attention stopped; this
        // server takes the connection as idle from the report on.
        let raw = raw.0.trim_ascii();
        update.idle = Some(match raw {
            b"false" => Idle::Back,
            b"null" => {
                return Err(invalid_params(
                    "idle must be false or a non-negative whole number of seconds",
                ))
            }
            _ => match parse_i64(raw) {
                Some(seconds) if seconds >= 0 => Idle::For(seconds),
                _ => {
                    return Err(invalid_params(
                        "idle must be false or a non-negative whole number of seconds",
                    ))
                }
            },
        });
    }
    if let Some(raw) = params.get("mute") {
        match raw.0.trim_ascii() {
            b"true" => {
                update.has_mute = true;
                update.mute_forever = true;
            }
            b"false" => update.has_mute = true,
            b"null" => {
                return Err(invalid_params(
                    "mute must be true, false, or a positive whole number of seconds",
                ))
            }
            raw => match parse_i64(raw) {
                Some(seconds) if seconds > 0 => {
                    update.has_mute = true;
                    update.mute_seconds = seconds.min(MAX_MUTE_SECONDS);
                }
                _ => {
                    return Err(invalid_params(
                        "mute must be true, false, or a positive whole number of seconds",
                    ))
                }
            },
        }
    }
    if update.scoped && !update.has_mute {
        return Err(invalid_params("room_id scopes a mute; send it with mute"));
    }
    Ok(update)
}

impl State {
    /// Applies a `status` request (§4.5) and answers {} once it has: the
    /// mute's echo to the user's connections, the sender's included,
    /// precedes the result. On an error nothing changes: invalid params, a
    /// mute of a room the user cannot see, going idle more often than the
    /// connection's limit, a mute past the user's limit (shared with `me`
    /// status changes), or a mute of another room beyond MAX_ROOM_MUTES.
    /// Only an applied change counts against a limit, and coming back from
    /// idle never does, as on Cloudflare.
    pub fn status_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let update = parse_status(&req.params)?;
        let Some(user_id) = self.client_user(c) else {
            return Err(RpcError::new(
                CODE_DENIED,
                "Sign in before sending requests",
            ));
        };
        if update.has_mute
            && update.scoped
            && self
                .visible_room_locked(&user_id, &update.room_id)
                .is_none()
        {
            return Err(invalid_params(format!(
                "Unknown room {}",
                quote(&update.room_id)
            )));
        }
        let now = time::now();
        let ms = now.unix_milli();
        let limits = &self.config.limits;
        let (idle_limit, status_limit) = (
            limits.idle_changes_per_connection_minute,
            limits.status_changes_per_user_minute,
        );
        let idle_changes = match self.clients.get_mut(&c.id) {
            Some(conn)
                if matches!(update.idle, Some(Idle::For(_))) && conn.idle_since.is_none() =>
            {
                Some(&mut conn.idle_changes)
            }
            _ => None,
        };
        let going_idle = idle_changes.is_some();
        if let Some(wait) = idle_changes.and_then(|w| w.wait(ms, idle_limit)) {
            return Err(retry_after_seconds("Idle changes limited", wait));
        }
        if update.has_mute {
            let u = self.users.get_mut(&user_id).expect("user exists");
            if let Some(wait) = u.status_changes.wait(ms, status_limit) {
                return Err(retry_after_seconds("Mute changes limited", wait));
            }
            if update.scoped
                && update.mute(&now).active(&now)
                && !u.room_mutes.contains_key(&update.room_id)
                && u.room_mutes.len() >= MAX_ROOM_MUTES
            {
                return Err(RpcError::new(
                    CODE_DENIED,
                    format!("At most {MAX_ROOM_MUTES} rooms can be muted; unmute one first"),
                ));
            }
            u.status_changes.note(ms);
        }
        if let Some(conn) = self.clients.get_mut(&c.id).filter(|_| going_idle) {
            conn.idle_changes.note(ms);
        }
        self.apply_status_locked(c, &user_id, &update);
        Ok((Object::new().into(), false))
    }

    /// Applies an update for the user from connection c, then announces
    /// what changed. A scoped mute's room is visible to the user.
    pub fn apply_status_locked(&mut self, c: &Arc<Client>, user_id: &str, update: &StatusUpdate) {
        if let Some(idle) = update.idle {
            let now = time::now();
            let changed = match (self.clients.get_mut(&c.id), idle) {
                (Some(conn), Idle::Back) if conn.idle_since.is_some() => {
                    conn.idle_since = None;
                    true
                }
                (Some(conn), Idle::For(seconds)) if conn.idle_since.is_none() => {
                    let back = Duration::from_secs(seconds.min(HELD_WAKE_WINDOW.seconds() as i64));
                    conn.idle_since = Some(now.add(-back));
                    true
                }
                _ => false,
            };
            if changed {
                // Back: a push still waiting for them is not needed. Gone:
                // what they were passed over for since is pushed.
                match idle {
                    Idle::Back => self.drop_wakes_locked(user_id, super::wake::Seen::All),
                    Idle::For(_) => self.release_held_locked(user_id, &now),
                }
                self.announce_status_locked(user_id, Cause::Connection);
            }
        }
        if !update.has_mute {
            return;
        }
        let now = time::now();
        let mute = update.mute(&now);
        if !update.scoped {
            if let Some(u) = self.users.get_mut(user_id) {
                u.mute = mute.clone();
            }
            self.touch_user(user_id);
            self.schedule_mute_locked(user_id);
            self.send_to_user(user_id, &mute_frame("", &mute, &now));
            return;
        }
        let room_id = update.room_id.clone();
        if let Some(u) = self.users.get_mut(user_id) {
            if mute.active(&now) {
                u.room_mutes.insert(room_id.clone(), mute.clone());
            } else {
                u.room_mutes.remove(&room_id);
            }
        }
        self.touch_user(user_id);
        self.schedule_room_mute_locked(user_id, &room_id);
        self.send_to_user(user_id, &mute_frame(&room_id, &mute, &now));
        // What counts toward unread changes with a room's mute, in the room
        // and its threads, at any depth (unread.rs), so every count is taken
        // again, as when the mute runs out.
        self.unread_changed_locked(user_id, "");
    }
}

impl Server {
    pub(crate) fn status(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        self.lock().status_locked(c, req)
    }
}
