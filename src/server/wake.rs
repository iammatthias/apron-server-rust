//! Whom a message wakes, and when (§4.9), as apron-server-cloudflare does
//! it: a wake waits `--push.delay` and goes only to those still away, wakes
//! one user at most once a coalescing window per room, wakes at most
//! WAKES_PER_MESSAGE users, and what came while a user was attended is held
//! and pushed if they go idle without having been back since.

use rust_stdlib::time::{self, Duration, Time, Timer};

use super::messages::mentions;
use super::protocol::*;
use super::push::{push_payload, WakeScope};
use super::server::State;

/// Users one message may wake, counting only those pushed to.
pub const WAKES_PER_MESSAGE: usize = 10;
/// Users one message considers, and holds wakes for.
pub const MAX_WAKE_CANDIDATES: usize = 32;
/// Wakes waiting out the delay at once; past it, a wake goes at once.
pub const MAX_PENDING_WAKES: usize = 256;
/// Held wakes one user keeps; the oldest go first.
pub const MAX_HELD_WAKES: usize = 8;
/// How far back a held wake may be pushed when its user goes idle: twice
/// the five minutes clients wait without input before they report it.
pub const HELD_WAKE_WINDOW: Duration = Duration::from_secs(10 * 60);
/// The default `--push.delay`: a user back at their screen by then is not
/// pushed.
pub const PUSH_DELAY: Duration = Duration::from_secs(30);
/// The longest `--push.delay`.
pub const MAX_PUSH_DELAY: Duration = Duration::from_secs(60);
/// How often a busy room may wake one user, and how often one pushed only
/// for `joined` may.
pub const PUSH_COALESCE: Duration = Duration::from_secs(60);
pub const JOINED_COALESCE: Duration = Duration::from_secs(5 * 60);

/// The users a wake considers, in the order they were found (a reply's
/// author, then mentions, private members, and `joined` last, so it crowds
/// out nothing), each with the scopes they qualify under.
pub type Reasons = Vec<(String, WakeScope)>;

/// A message's wake waiting `--push.delay`.
pub struct PendingWake {
    message_id: String,
    room_id: String,
    /// The snapshot as it was scheduled, and its record, so an edit during
    /// the wait narrows the reasons (keep_reasons).
    record: Option<i64>,
    snapshot: Object,
    reasons: Reasons,
    /// For held wakes released together: older messages, newest first, to
    /// push instead when this one wakes no one.
    others: Vec<String>,
    timer: Option<Timer>,
}

/// A wake passed over because its user was attended.
#[derive(Clone, Debug)]
pub struct HeldWake {
    pub message_id: String,
    pub room_id: String,
    pub reasons: WakeScope,
    pub at: Time,
}

fn add_reason(reasons: &mut Reasons, user_id: &str, reason: WakeScope) -> bool {
    match reasons.iter_mut().find(|(id, _)| id == user_id) {
        Some((_, why)) => {
            *why |= reason;
            true
        }
        None => false,
    }
}

impl State {
    /// Wakes the users a message concerns (§4.9). previous is the snapshot
    /// the save replaced, `None` for a new message.
    ///
    /// A new message concerns the author of the message it replies to
    /// (scope replies), the users its body.mentions lists (mentions), in
    /// any room they can see, in a private room or a thread of one the
    /// users who joined every private room on the way up (private), and
    /// the room's members who hold admin or mod (joined). An edit concerns
    /// only the users it adds to body.mentions. Nobody is woken by their own
    /// message, and a guest's wake no one. Only accounts and bots with a
    /// registration are considered, at most MAX_WAKE_CANDIDATES.
    ///
    /// A new message shows its author saw its room: their waiting and held
    /// wakes for it go. Those attended now are held (hold_wake), but for
    /// `joined`; the rest wait `--push.delay` (schedule_wake).
    pub fn wake_locked(&mut self, message_id: &str, snapshot: &Object, previous: Option<&Object>) {
        let Some(m) = self.messages.get(message_id) else {
            return;
        };
        let (room_id, owner) = (m.room_id.clone(), m.owner.clone());
        if previous.is_none() {
            self.drop_wakes_locked(&owner, Some(&room_id));
            self.drop_held_locked(&owner, Some(&room_id));
        }
        // Transient notices, which have no message_id, are never pushed
        // (§4.9).
        if self.config.disable_push
            || self.pushes.is_empty()
            || snapshot.get("deleted").is_some_and(Json::is_true)
            || snapshot
                .get("message_id")
                .is_none_or(|id| matches!(id, Json::Null))
            || !self.users.get(&owner).is_some_and(|u| u.persists())
        {
            return;
        }
        let mut found: Reasons = Vec::new();
        let mut consider = |st: &State, user_id: &str, reason: WakeScope| {
            if user_id == owner
                || add_reason(&mut found, user_id, reason)
                || found.len() >= MAX_WAKE_CANDIDATES
                || !st.users.get(user_id).is_some_and(|u| u.persists())
                || !st.user_has_pushes(user_id)
            {
                return;
            }
            found.push((user_id.to_owned(), reason));
        };
        let body = snapshot.get("body").and_then(Json::as_object);
        match previous {
            None => {
                if let Some(target) = snapshot
                    .get("reply_to")
                    .and_then(Json::as_object)
                    .and_then(|r| r.get("message_id"))
                    .and_then(Json::as_str)
                    .and_then(|id| self.messages.get(id))
                {
                    consider(self, &target.owner.clone(), WakeScope::REPLIES);
                }
                for id in mentions(body) {
                    consider(self, &id, WakeScope::MENTIONS);
                }
                // private selects messages in the private rooms the user
                // joined and in their threads (§4.9): those who can see a
                // private room's thread joined every private room above it.
                let (everyone, audience) = self.audience(&room_id);
                if !everyone {
                    for id in audience {
                        consider(self, &id, WakeScope::PRIVATE);
                    }
                }
                let members: Vec<String> = self.rooms[&room_id].members.iter().cloned().collect();
                for id in members {
                    if self.wakes_joined(&id) {
                        consider(self, &id, WakeScope::JOINED);
                    }
                }
            }
            Some(previous) => {
                let before = mentions(previous.get("body").and_then(Json::as_object));
                for id in mentions(body) {
                    if !before.contains(&id) {
                        consider(self, &id, WakeScope::MENTIONS);
                    }
                }
            }
        }
        let now = time::now();
        let mut away = Vec::new();
        for (user_id, why) in found {
            if !self.attended(&self.users[&user_id]) {
                away.push((user_id, why));
                continue;
            }
            // joined is not held: what came while a moderator was there,
            // they could see, and a busy room would otherwise crowd their
            // mentions out of what is held.
            let held = WakeScope(why.0 & !WakeScope::JOINED.0);
            if !held.is_empty() {
                self.hold_wake_locked(&user_id, message_id, &room_id, held, &now);
            }
        }
        if !away.is_empty() {
            self.schedule_wake_locked(message_id, away, Vec::new());
        }
    }

    /// Pushes a message's wake for `reasons` once `--push.delay` is over,
    /// with the message as it is then, or at once without a delay or past
    /// MAX_PENDING_WAKES. Nothing is pushed once the server is shutting
    /// down.
    fn schedule_wake_locked(&mut self, message_id: &str, reasons: Reasons, others: Vec<String>) {
        // A wake lost with the server is not pushed.
        if self.closed {
            return;
        }
        let delay = self.config.push_delay;
        if delay.as_nanos() <= 0 || self.pending_wakes.len() >= MAX_PENDING_WAKES {
            self.send_wake_locked(message_id, &reasons, others);
            return;
        }
        let Some(m) = self.messages.get(message_id) else {
            return;
        };
        let id = self.next_wake;
        self.next_wake += 1;
        let server = self.server.clone();
        let wake = PendingWake {
            message_id: message_id.to_owned(),
            room_id: m.room_id.clone(),
            record: m.records.last().copied(),
            snapshot: self.snapshot(message_id),
            reasons,
            others,
            timer: Some(time::after_func(delay, move || {
                if let Some(server) = server.upgrade() {
                    server.lock().fire_wake_locked(id);
                }
            })),
        };
        self.pending_wakes.insert(id, wake);
    }

    /// Ends a wake's wait: the message is pushed as it is now, to those
    /// still away (push_wake). One deleted or gone during the wait is not
    /// pushed, and an edit narrows the reasons (keep_reasons).
    fn fire_wake_locked(&mut self, id: u64) {
        let Some(mut wake) = self.pending_wakes.remove(&id) else {
            return;
        };
        if self.closed {
            return;
        }
        let Some(current) = self.wake_snapshot(&wake.message_id) else {
            return;
        };
        let record = self.messages[&wake.message_id].records.last().copied();
        if record != wake.record && wake.others.is_empty() {
            keep_reasons(&mut wake.reasons, &wake.snapshot, &current);
        }
        if !wake.reasons.is_empty() {
            self.send_wake_locked(&wake.message_id, &wake.reasons, wake.others);
        }
    }

    /// The current snapshot of a message a wake may push: not deleted, and
    /// still there.
    fn wake_snapshot(&self, message_id: &str) -> Option<Object> {
        self.messages.get(message_id)?;
        let snapshot = self.snapshot(message_id);
        (!snapshot.get("deleted").is_some_and(Json::is_true)).then_some(snapshot)
    }

    /// Pushes a wake; for held wakes released together, one whose message
    /// wakes no one falls back to the next of `others` that still exists.
    fn send_wake_locked(&mut self, message_id: &str, reasons: &Reasons, others: Vec<String>) {
        let mut next = Some(message_id.to_owned());
        let mut others = others.into_iter();
        while let Some(id) = next {
            if let Some(snapshot) = self.wake_snapshot(&id) {
                if self.push_wake_locked(&id, &snapshot, reasons) {
                    return;
                }
            }
            next = others.next();
        }
    }

    /// Wakes up to WAKES_PER_MESSAGE of `reasons`' users for a message, and
    /// reports whether it woke anyone. A user is passed over without taking
    /// a wake when attended (§4.5), when their unscoped mute or a dnd status
    /// silences them, when they mute the room or a room it is a thread of,
    /// when they were woken for the room within PUSH_COALESCE (one pushed
    /// only for `joined`, within JOINED_COALESCE), or when none of their
    /// live registrations wakes for why they qualify and is on a host
    /// `--push.hosts` allows; `joined` counts only while they hold admin or
    /// mod and are in the room. What is silenced reaches them only as a
    /// badge push (badge_locked). Each registration that wakes gets the
    /// payload with its push_id and the user's unread count, with Urgency
    /// high for mentions, replies and private, and normal for joined alone.
    fn push_wake_locked(&mut self, message_id: &str, snapshot: &Object, reasons: &Reasons) -> bool {
        let room_id = self.messages[message_id].room_id.clone();
        let now = time::now();
        let mut woken = 0;
        for (user_id, why) in reasons {
            if woken >= WAKES_PER_MESSAGE {
                break;
            }
            let Some(u) = self.users.get(user_id) else {
                continue;
            };
            let mut why = *why;
            let in_room = self
                .rooms
                .get(&room_id)
                .is_some_and(|r| r.members.contains(user_id));
            if !(why & WakeScope::JOINED).is_empty() && !(self.wakes_joined(user_id) && in_room) {
                why = WakeScope(why.0 & !WakeScope::JOINED.0);
            }
            if why.is_empty()
                || !self.room_visible_to(&room_id, user_id)
                || self.attended(u)
                || u.silenced(&now)
                || self.room_muted(u, &room_id, &now)
            {
                continue;
            }
            self.expire_pushes_locked(user_id, &now);
            let woken_by: Vec<(String, WakeScope)> = self
                .sorted_pushes(user_id)
                .into_iter()
                .filter_map(|key| {
                    let p = &self.pushes[&key];
                    let scopes = why & p.wake;
                    (!scopes.is_empty() && self.config.push_hosts.allows_url(&p.url))
                        .then_some((key, scopes))
                })
                .collect();
            if woken_by.is_empty() {
                continue;
            }
            let joined_only = woken_by
                .iter()
                .all(|(_, scopes)| *scopes == WakeScope::JOINED);
            let window = if joined_only {
                self.joined_coalesce
            } else {
                self.push_coalesce
            };
            let key = (user_id.clone(), room_id.clone());
            if self
                .push_woken
                .get(&key)
                .is_some_and(|last| now.sub(last) < window)
            {
                continue;
            }
            self.push_woken.insert(key, now.clone());
            woken += 1;
            let unread = self.unread_locked(user_id, &now);
            for (key, scopes) in woken_by {
                let push_id = self.pushes[&key].push_id.clone();
                let urgency = if (scopes & WakeScope::URGENT).is_empty() {
                    "normal"
                } else {
                    "high"
                };
                self.deliver_push_locked(
                    &key,
                    unread,
                    push_payload(&push_id, unread, snapshot),
                    urgency,
                    false,
                );
            }
        }
        woken > 0
    }

    /// Drops a user from the wakes waiting to push: from all of them when
    /// they come back (`idle: false`), or from `room_id`'s when they post
    /// there.
    pub fn drop_wakes_locked(&mut self, user_id: &str, room_id: Option<&str>) {
        let mut emptied = Vec::new();
        for (id, wake) in &mut self.pending_wakes {
            if room_id.is_some_and(|room_id| room_id != wake.room_id) {
                continue;
            }
            wake.reasons.retain(|(id, _)| id != user_id);
            if wake.reasons.is_empty() {
                emptied.push(*id);
            }
        }
        for id in emptied {
            if let Some(timer) = self.pending_wakes.remove(&id).and_then(|w| w.timer) {
                timer.stop();
            }
        }
    }

    /// Stops every waiting wake, at shutdown: a wake lost with the server
    /// is not pushed.
    pub fn stop_wakes_locked(&mut self) {
        for (_, wake) in std::mem::take(&mut self.pending_wakes) {
            if let Some(timer) = wake.timer {
                timer.stop();
            }
        }
    }

    /// Keeps a wake an attended user was passed over for, so that if they
    /// go idle without having been back since it came, it is pushed then
    /// (release_held), as chat apps push what arrived after you left.
    fn hold_wake_locked(
        &mut self,
        user_id: &str,
        message_id: &str,
        room_id: &str,
        reasons: WakeScope,
        now: &Time,
    ) {
        let Some(u) = self.users.get_mut(user_id) else {
            return;
        };
        let oldest = now.add(-HELD_WAKE_WINDOW);
        u.held
            .retain(|held| held.message_id != message_id && held.at.after(&oldest));
        u.held.push(HeldWake {
            message_id: message_id.to_owned(),
            room_id: room_id.to_owned(),
            reasons,
            at: now.clone(),
        });
        let excess = u.held.len().saturating_sub(MAX_HELD_WAKES);
        u.held.drain(..excess);
    }

    /// Forgets a user's held wakes: `room_id`'s when they post there, which
    /// shows they saw it, or all of them.
    pub fn drop_held_locked(&mut self, user_id: &str, room_id: Option<&str>) {
        if let Some(u) = self.users.get_mut(user_id) {
            u.held
                .retain(|held| room_id.is_some_and(|room_id| room_id != held.room_id));
        }
    }

    /// When a user's last attended connection goes idle, pushes the wakes
    /// they were held for that came after they were last attended: the
    /// latest time their connections went idle, which `idle` dates back
    /// (§4.5.3), and no further back than HELD_WAKE_WINDOW. An `idle: 0`
    /// dates it to now, so it pushes none of them. They go as one push, the
    /// newest that still wakes them, through the usual wait
    /// (schedule_wake), with the message as it is then; their held wakes
    /// are then forgotten.
    pub fn release_held_locked(&mut self, user_id: &str, now: &Time) {
        let Some(u) = self.users.get(user_id) else {
            return;
        };
        if u.held.is_empty() || self.attended(u) {
            return;
        }
        let mut attended_until = now.add(-HELD_WAKE_WINDOW);
        for id in &u.clients {
            if let Some(since) = self
                .clients
                .get(id)
                .and_then(|conn| conn.idle_since.as_ref())
            {
                if since.after(&attended_until) {
                    attended_until = since.clone();
                }
            }
        }
        let mut due: Vec<HeldWake> = u
            .held
            .iter()
            .filter(|held| held.at.after(&attended_until))
            .cloned()
            .collect();
        self.drop_held_locked(user_id, None);
        due.sort_by(|a, b| b.at.compare(&a.at).cmp(&0));
        let reasons = due
            .iter()
            .fold(WakeScope::NONE, |all, held| all | held.reasons);
        let mut ids: Vec<String> = due.into_iter().map(|held| held.message_id).collect();
        ids.dedup();
        ids.truncate(MAX_HELD_WAKES);
        while !ids.is_empty() {
            let id = ids.remove(0);
            if self.wake_snapshot(&id).is_some() {
                self.schedule_wake_locked(&id, vec![(user_id.to_owned(), reasons)], ids);
                return;
            }
        }
    }
}

/// Narrows a wake's reasons to what an edit made during the wait left: a
/// mention only for a user it still mentions, a reply only while it still
/// replies to the same message; private and joined stay, as the room does.
/// Users left with no reason are dropped.
fn keep_reasons(reasons: &mut Reasons, before: &Object, after: &Object) {
    let mentioned = mentions(after.get("body").and_then(Json::as_object));
    let reply = |snapshot: &Object| {
        snapshot
            .get("reply_to")
            .and_then(Json::as_object)
            .and_then(|r| r.get("message_id"))
            .cloned()
    };
    let same_reply = reply(before) == reply(after);
    reasons.retain_mut(|(user_id, why)| {
        let mut kept = WakeScope(why.0 & (WakeScope::PRIVATE.0 | WakeScope::JOINED.0));
        if mentioned.contains(user_id) {
            kept |= *why & WakeScope::MENTIONS;
        }
        if same_reply {
            kept |= *why & WakeScope::REPLIES;
        }
        *why = kept;
        !kept.is_empty()
    });
}
