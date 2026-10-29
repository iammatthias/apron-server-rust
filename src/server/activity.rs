//! activity (§4.6): typing, read cursors and attention, relayed to a room's
//! other connections within their limits.

use std::sync::Arc;

use super::client::Client;
use super::protocol::*;
use super::rooms::ReadCursor;
use super::server::{Server, State, DEFAULT_ROOM_ID};
use super::wake::Seen;
use crate::obj;

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

impl State {
    /// Sends a read cursor to the user's other connections, within
    /// ACTIVITY_RELAYS_PER_MINUTE; one past it is kept but not relayed, and
    /// devices learn of it at their next listing.
    fn relay_read_locked(&mut self, c: &Client, user_id: &str, frame: &Object) {
        let u = self.users.get_mut(user_id).expect("user exists");
        if u.clients.len() < 2 || !u.read_relays.get_or_insert_with(activity_limiter).allow() {
            return;
        }
        let Some(frame) = super::client::render(frame) else {
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
}

impl State {
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
}

/// The largest id a read cursor may name: JavaScript's
/// Number.MAX_SAFE_INTEGER, as Cloudflare's asDecimalId allows.
const MAX_READ_ID: i64 = (1 << 53) - 1;

/// Reads read_message_id as Cloudflare's asDecimalId does: a decimal string
/// of a positive safe integer, returned in its canonical spelling with its
/// value. It need not name a message: a cursor only marks how far its user
/// read.
fn parse_read_id(params: &Params) -> Result<Option<(String, i64)>, RpcError> {
    if !params.contains_key("read_message_id") {
        return Ok(None);
    }
    let text = parse_string(params, "read_message_id", false)
        .ok()
        .filter(|text| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| invalid_params("read_message_id must be a decimal string"))?;
    match text.parse::<i64>() {
        Ok(id) if (1..=MAX_READ_ID).contains(&id) => Ok(Some((id.to_string(), id))),
        _ => Err(invalid_params(
            "read_message_id is outside the supported range",
        )),
    }
}

impl State {
    /// Applies a connection's activity (§4.6). typing is relayed to the
    /// room's other connections, at most MAX_TYPING_SECONDS and within
    /// ACTIVITY_RELAYS_PER_MINUTE. A read cursor only advances; an account's is kept, sent after the room is listed, and
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
            let mut value: f64 = 0.0;
            if rust_stdlib::encoding::json::v2::unmarshal(&raw.0, &mut value, &[]).is_err()
                || !value.is_finite()
                || value < 0.0
            {
                return Err(invalid_params(
                    "typing must be a non-negative number of seconds",
                ));
            }
            // Fractional seconds round down, as on Cloudflare.
            typing = Some(value.min(MAX_TYPING_SECONDS as f64).floor() as i64);
        }
        let read = parse_read_id(&req.params)?;
        let has_read = read.is_some();
        let (read_id, id) = read.unwrap_or_default();
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
                        if let Some(frame) = super::client::render(&frame) {
                            self.send_to_user(&user_id, &frame);
                        }
                    }
                    params.insert("read_message_id".into(), read_id.as_str().into());
                    read = true;
                }
                // Reading lowers the unread count the user's other devices
                // show, and what waits or is held to push for the room up to
                // the cursor is not needed (§4.9.4).
                self.unread_changed_locked(&user_id, &room_id);
                let seen = Seen::Through(&room_id, id);
                self.drop_wakes_locked(&user_id, seen);
                self.drop_held_locked(&user_id, seen);
            }
        }
        let mut typed = false;
        if let Some(typing) = typing {
            if self.admit_typing_locked(c, &user_id, &room_id) {
                params.insert("typing".into(), typing.into());
                typed = true;
            }
        }
        // The relay goes to every connection in the room but this one, the
        // user's other devices included, as on Cloudflare; a read receipt
        // also comes back to this connection.
        let rooms = [room_id.clone()];
        if read && self.rooms[&room_id].members.contains(&user_id) {
            let mut own = params.clone();
            own.remove("typing");
            if let Some(frame) =
                super::client::render(&obj! {"method" => "activity", "params" => own})
            {
                c.enqueue_frame(frame);
            }
        }
        if typed || read {
            if let Some(frame) =
                super::client::render(&obj! {"method" => "activity", "params" => params})
            {
                self.deliver_except_locked(&frame, &rooms, Some(c.id));
            }
        }
        Ok((result.into(), false))
    }
}

impl Server {
    pub(crate) fn activity(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        self.lock().activity_locked(c, req)
    }
}
