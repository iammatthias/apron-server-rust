//! room_list (§4.2.1): the rooms a user may see, joined and not.

use std::collections::BTreeSet;
use std::sync::Arc;

use super::client::{Client, Frame};
use super::protocol::*;
use super::rooms::{parse_bound, profiles, RoomState};
use super::server::{Server, State};
use crate::obj;

impl State {
    /// Answers room_list (§4.2.1): the rooms matching its filters, joined
    /// ones in `joined` and visible unjoined ones in `not_joined`, each most
    /// recently active first; MAX_THREADS and MAX_CREATED_ROOMS bound both.
    /// The result is followed by the read cursors kept for the listed rooms
    /// (§4.6).
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
        if let Some(frame) = super::client::render(&response(&req.id, result.clone().into())) {
            frames.push(frame);
        }
        for r in joined.iter().chain(others.iter()) {
            frames.extend(self.cursor_frames_locked(u, r));
        }
        c.enqueue_frames(frames);
        Ok((result.into(), true))
    }
}

impl Server {
    pub(crate) fn list_rooms(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let mut st = self.lock();
        st.charge_room_list_locked(c, req)?;
        st.list_rooms_locked(c, req)
    }
}
