//! room_set (§4.2.2): creating and editing rooms and threads, within the room
//! and thread limits.

use std::sync::Arc;

use super::client::Client;
use super::limits::Category;
use super::protocol::*;
use super::rooms::{
    room_update, RoomState, DEFAULT_ROOM_TITLE, DEFAULT_THREAD_TITLE, MAX_CREATED_ROOMS,
    MAX_DESCRIPTION_BYTES, MAX_PRIVATE_ROOMS, MAX_PRIVATE_ROOMS_PER_USER, MAX_ROOM_EXT_BYTES,
    MAX_THREADS, MAX_THREADS_PER_USER, MAX_THREAD_TITLE_RUNES, TOP_LEVEL_ROOM_TITLE,
};
use super::server::{Server, State, DEFAULT_ROOM_ID};
use super::users::{UserState, ADMIN_ROLE, ROOM_CREATOR_ROLES};
use crate::obj;

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

impl State {
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
}

impl State {
    /// The rooms MAX_THREADS bounds: every room but `general` and private
    /// top-level rooms, which their own caps bound.
    fn thread_count(&self) -> usize {
        self.rooms
            .values()
            .filter(|r| r.id != DEFAULT_ROOM_ID && !(r.parent.is_none() && r.private))
            .count()
    }
}

impl State {
    /// The threads user_id created whose history retention has not
    /// discarded entirely.
    fn live_threads_created_by(&self, user_id: &str) -> usize {
        self.live_rooms_created_by(user_id, |r| r.parent.is_some())
    }

    /// The top-level private rooms user_id started that retention has not
    /// discarded entirely.
    fn live_private_rooms_created_by(&self, user_id: &str) -> usize {
        self.live_rooms_created_by(user_id, |r| r.parent.is_none() && r.private)
    }

    fn live_rooms_created_by(&self, user_id: &str, kind: impl Fn(&RoomState) -> bool) -> usize {
        self.rooms
            .values()
            .filter(|r| {
                kind(r) && r.creator == user_id && r.history_log_id(self.history_floor).is_some()
            })
            .count()
    }
}

impl State {
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
        } else if self.live_private_rooms_created_by(&user_id) >= MAX_PRIVATE_ROOMS_PER_USER {
            // So one account cannot take every slot by starting rooms and
            // leaving them to others.
            return Err(RpcError::new(
                CODE_DENIED,
                format!("You can have started at most {MAX_PRIVATE_ROOMS_PER_USER} private rooms at once; one stops counting when everyone has left it or its history expires"),
            ));
        } else if self
            .rooms
            .values()
            .filter(|r| r.parent.is_none() && r.private)
            .count()
            >= MAX_PRIVATE_ROOMS
        {
            return Err(RpcError::new(
                CODE_DENIED,
                "The server holds as many private rooms as it can; one frees up when everyone has left it or its history expires",
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
}

impl Server {
    pub(crate) fn set_room(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        self.lock().set_room_locked(c, req)
    }
}
