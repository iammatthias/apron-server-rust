//! `/purge <user_id>`, an extension Go lacks (docs/DEVIATIONS.md), following
//! apron-server-cloudflare's `/purge` (its SPEC.md, section 5, Admins, and
//! store.ts `purgeUsers`).

use std::collections::BTreeSet;

use super::admin::ADMIN_USER_ID;
use super::commands::{no_user, private_notice, user_id_args, CommandCtx};
use super::embeds::{EmbedPurpose, EmbedState};
use super::protocol::*;
use super::remap::Remap;
use super::server::State;

/// Why the connections of a purged user close.
pub(super) const PURGED: &str = "Removed by an admin";

/// What a purge removed, for the sender's notice.
struct Purged {
    messages: usize,
    reactions: usize,
    uploads: usize,
}

fn plural(n: usize, one: &str) -> String {
    format!("{n} {one}{}", if n == 1 { "" } else { "s" })
}

impl State {
    /// `/purge <user_id>` (a leading `@` is allowed): closes the connections
    /// of a user and the bots they own, then deletes them and
    /// everything they posted, reacted or uploaded, silently: no record
    /// announces it. Threads it leaves empty are removed. The user_id stays
    /// used, so it is never issued again. The sender gets a ~private notice
    /// with the counts before the result (§1).
    pub(super) fn purge_command(&mut self, cx: &CommandCtx) -> Result<Object, RpcError> {
        let CommandCtx {
            client: c,
            room_id,
            args,
            ..
        } = *cx;
        let [user_id] = user_id_args(args, "Usage: /purge <user_id>")?;
        if cx.user_id == user_id {
            return Err(RpcError::new(CODE_DENIED, "You can't purge yourself"));
        }
        if user_id == ADMIN_USER_ID {
            return Err(RpcError::new(CODE_DENIED, "The admin user can't be purged"));
        }
        if !self.users.contains_key(user_id) {
            return Err(no_user("user", user_id));
        }
        let mut ids = BTreeSet::from([user_id.to_owned()]);
        ids.extend(self.bots_of(user_id));
        let rooms: BTreeSet<String> = ids
            .iter()
            .flat_map(|id| self.users[id].joined.iter().cloned())
            .collect();
        let purged = self.erase_users_locked(&ids);
        for room in rooms {
            self.remove_if_empty_locked(&room);
        }
        let text = format!(
            "Purged `{user_id}`: {}, {}, {}.",
            plural(purged.messages, "message"),
            plural(purged.reactions, "reaction set"),
            plural(purged.uploads, "upload"),
        );
        c.enqueue(&private_notice(&self.rooms[room_id], &text));
        Ok(Object::new())
    }

    /// Deletes users and what they left (`remap_users_locked`), and
    /// counts it.
    fn erase_users_locked(&mut self, ids: &BTreeSet<String>) -> Purged {
        let gone: BTreeSet<String> = self
            .messages
            .values()
            .filter(|m| ids.contains(&m.owner))
            .map(|m| m.id.clone())
            .collect();
        let hosted = |e: &EmbedState| !e.is_link() && e.stream.is_none();
        let purged = Purged {
            messages: gone.len(),
            reactions: self
                .messages
                .values()
                .map(|m| m.reactions.keys().filter(|id| ids.contains(*id)).count())
                .sum(),
            uploads: self
                .embeds
                .values()
                .filter(|e| match &e.purpose {
                    EmbedPurpose::Message => gone.contains(&e.message_id) && hosted(e),
                    EmbedPurpose::Avatar(id) => ids.contains(id),
                    _ => false,
                })
                .count(),
        };
        self.remap_users_locked(&Remap::Drop(ids), &gone);
        // Unread counts read the log, which changed under them.
        for u in self.users.values_mut() {
            u.unread = None;
        }
        purged
    }
}
