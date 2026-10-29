//! `/rename <old_user_id> <new_user_id>`, an extension Go lacks
//! (docs/DEVIATIONS.md), following apron-server-cloudflare's `/rename` (its
//! SPEC.md, section 5, Admins, and store.ts `renameIdentity`).

use std::collections::BTreeSet;
use std::sync::Arc;

use super::admin::ADMIN_USER_ID;
use super::client::{Client, Frame};
use super::commands::private_notice;
use super::invites::{issuable, NOT_ISSUABLE};
use super::protocol::*;
use super::purge::truncate_chars;
use super::remap::Remap;
use super::server::State;
use crate::obj;

impl State {
    /// `/rename <old_user_id> <new_user_id>` (a leading `@` is allowed on
    /// either) gives an account a new user_id. Everything kept under the old
    /// one moves, and what they left in the log is rewritten to the new one
    /// without notifications, so it stays theirs. The old user_id stays used,
    /// never reissued. Their sessions go, so a client resuming one signs in
    /// with its passkey again; their bot keeps its user_id. Their
    /// connections get `user` `you`, and those who share a room with them
    /// `user` `new` with `old` (§3.3). The sender gets a ~private notice
    /// before the result (§1).
    pub(super) fn rename_command(
        &mut self,
        c: &Arc<Client>,
        room_id: &str,
        _body: &Object,
        args: &str,
    ) -> Result<Object, RpcError> {
        let words: Vec<&str> = args.split_whitespace().collect();
        let [from, to] = words.as_slice() else {
            return Err(invalid_params("Usage: /rename <old_user_id> <new_user_id>"));
        };
        let from = from.strip_prefix('@').unwrap_or(from);
        let to = to.strip_prefix('@').unwrap_or(to);
        if from == ADMIN_USER_ID {
            return Err(RpcError::new(
                CODE_DENIED,
                "The admin user's user_id is fixed",
            ));
        }
        let taken = invalid_params(format!("The user_id {to} is taken"));
        if to.eq_ignore_ascii_case(ADMIN_USER_ID) {
            return Err(taken);
        }
        if !issuable(to) {
            return Err(invalid_params(NOT_ISSUABLE));
        }
        let Some(u) = self.users.get(from).filter(|u| u.persists()) else {
            let mut message = format!("No registered user has the user_id {from}");
            truncate_chars(&mut message, 200);
            return Err(invalid_params(message));
        };
        if u.bot() {
            return Err(RpcError::new(CODE_DENIED, "A bot's user_id is fixed"));
        }
        // A user_id --role grants is free for an admin to give, as for
        // /invite-token.
        if self.used_ids.contains(&to.to_lowercase()) || self.room_named_locked(to) {
            return Err(taken);
        }
        let old = self.users[from].from();
        self.move_user_locked(from, to);
        self.grant_roles_locked(to);
        let u = &self.users[to];
        let you = Frame::from(notification("user", obj! {"you" => self.you_locked(u)}));
        for id in &u.clients {
            if let Some(conn) = self.clients.get(id) {
                conn.client.enqueue_frame(you.clone());
            }
        }
        self.notify_user_id_change_locked(to, old);
        c.enqueue(&private_notice(
            &self.rooms[room_id],
            &format!("Renamed `{from}` to `{to}`."),
        ));
        Ok(Object::new())
    }

    /// Moves everything kept under `from` to `to` (`remap_users_locked`)
    /// and marks `to` used.
    fn move_user_locked(&mut self, from: &str, to: &str) {
        let lower = to.to_lowercase();
        self.used_ids.insert(lower.clone());
        self.touch_used_id(&lower);
        self.remap_users_locked(&Remap::Rename { from, to }, &BTreeSet::new());
    }
}
