//! The admin token and the user it signs in as, an extension Go lacks
//! (docs/DEVIATIONS.md), following apron-server-cloudflare's
//! `APRON_ADMIN_TOKEN` (its SPEC.md, section 5, Admins).

use std::sync::Arc;

use rust_stdlib_crypto::{sha256, subtle};

use super::bots::BOT_ROLE;
use super::client::Client;
use super::commands::{private_notice, target, CommandCtx};
use super::protocol::*;
use super::server::State;
use super::users::{valid_role, ADMIN_ROLE, INVALID_ROLE, MAX_ROLES};

/// The account the admin token signs in as. No one else may take its
/// user_id (`user_id_taken_locked`).
pub const ADMIN_USER_ID: &str = "admin";
pub const ADMIN_USER_NAME: &str = "Admin";
/// Refuses a passkey or a device token for the admin user, either of which
/// would outlive the admin token.
pub const ADMIN_SIGNS_IN_WITH_TOKEN: &str =
    "The admin user signs in with APRON_ADMIN_TOKEN only; make your own account an admin with /admin";

impl State {
    /// Reports whether `token` is the configured admin token.
    pub(super) fn is_admin_token(&self, token: &str) -> bool {
        self.config.admin_token.is_some_and(|want| {
            subtle::constant_time_compare(&sha256::sum256(token.as_bytes()), &want) == 1
        })
    }

    /// Signs the connection in as the user `admin`, from any origin, making
    /// it on first use: an account that signs in with the token alone, holds
    /// the `admin` role and joins the default room after the result, as a new
    /// account does. The result carries no session token.
    pub(super) fn authenticate_admin_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<Json, RpcError> {
        self.check_token_switch(c, ADMIN_USER_ID)?;
        let created = match self.users.get(ADMIN_USER_ID) {
            Some(u) if u.invited && u.has_role(ADMIN_ROLE) => false,
            Some(_) => {
                return Err(RpcError::new(
                    CODE_INTERNAL_ERROR,
                    "The user_id admin belongs to another user",
                ))
            }
            None => {
                self.used_ids.insert(ADMIN_USER_ID.to_owned());
                self.touch_used_id(ADMIN_USER_ID);
                let mut admin = self.new_user_locked(ADMIN_USER_ID, ADMIN_USER_NAME);
                admin.invited = true;
                admin.roles = vec![ADMIN_ROLE.to_owned()];
                self.users.insert(ADMIN_USER_ID.to_owned(), admin);
                self.touch_user(ADMIN_USER_ID);
                true
            }
        };
        self.sign_in_keyless_locked(c, req, ADMIN_USER_ID, created)
    }
}

/// What `change_role_locked` did: whether the user now has the role, and
/// whether that changed.
struct RoleChange {
    on: bool,
    changed: bool,
    who: String,
}

impl State {
    /// `/admin <user_id>` gives an account the admin role, and
    /// `/admin remove <user_id>` takes it away. The sender gets a ~private
    /// notice before the result (§1).
    pub(super) fn admin_command(&mut self, cx: &CommandCtx) -> Result<Object, RpcError> {
        let CommandCtx {
            client: c,
            room_id,
            args,
            ..
        } = *cx;
        let words: Vec<&str> = args.split_whitespace().collect();
        let (remove, user_id) = match words.as_slice() {
            ["remove", user_id] => (true, target(user_id)),
            [user_id] if *user_id != "remove" => (false, target(user_id)),
            _ => return Err(invalid_params("Usage: /admin [remove] <user_id>")),
        };
        if user_id.is_empty() {
            return Err(invalid_params("Usage: /admin [remove] <user_id>"));
        }
        let change = self.change_role_locked(user_id, ADMIN_ROLE, Some(!remove))?;
        let who = change.who;
        let text = match (remove, change.changed) {
            (true, true) => format!("{who} is no longer an admin."),
            (true, false) => format!("{who} was not an admin."),
            (false, true) => format!("{who} is now an admin."),
            (false, false) => format!("{who} is already an admin."),
        };
        c.enqueue(&private_notice(&self.rooms[room_id], &text));
        Ok(Object::new())
    }

    /// `/role <user_id>` tells the sender a user's roles; `/role <user_id>
    /// <role>` gives them the role, or takes it away when they have it. Any
    /// name is a label shown in `roles` (§3.3); `admin` also runs the admin
    /// commands, `admin` and `mod` remove others from rooms, and `bot` makes
    /// the user a bot. The sender gets a ~private notice before the result.
    pub(super) fn role_command(&mut self, cx: &CommandCtx) -> Result<Object, RpcError> {
        let CommandCtx {
            client: c,
            room_id,
            args,
            ..
        } = *cx;
        let words: Vec<&str> = args.split_whitespace().collect();
        let text = match words.as_slice() {
            [user_id] => {
                let user_id = target(user_id);
                let Some(u) = self.users.get(user_id).filter(|u| u.persists()) else {
                    return Err(invalid_params(format!(
                        "No registered user has the user_id {user_id}"
                    )));
                };
                let who = who(&u.name, user_id);
                if u.roles.is_empty() {
                    format!("{who} has no roles.")
                } else {
                    let roles: Vec<String> = u.roles.iter().map(|r| format!("`{r}`")).collect();
                    format!("{who} has the roles {}.", roles.join(", "))
                }
            }
            [user_id, role] => {
                let role = role.to_lowercase();
                let change = self.change_role_locked(target(user_id), &role, None)?;
                let who = change.who;
                match (change.on, change.changed) {
                    (true, true) => format!("{who} now has the role `{role}`."),
                    (true, false) => format!("{who} already has the role `{role}`."),
                    (false, true) => format!("{who} no longer has the role `{role}`."),
                    (false, false) => format!("{who} did not have the role `{role}`."),
                }
            }
            _ => return Err(invalid_params("Usage: /role <user_id> [<role>]")),
        };
        c.enqueue(&private_notice(&self.rooms[room_id], &text));
        Ok(Object::new())
    }

    /// Gives an account or bot a role (`on`), takes it away, or with no `on`
    /// toggles it, at most MAX_ROLES, and announces a change as a profile
    /// change (§3.3): `user` `you` to the user's connections and `new` to
    /// those who share a room with them. A bot is never an admin, and `bot`
    /// goes to no admin and no user with a passkey or an address, since a
    /// bot signs in with a token only; the roles a user has by what it is,
    /// `admin` for the user admin and `bot` for an account's bot, stay.
    fn change_role_locked(
        &mut self,
        user_id: &str,
        role: &str,
        on: Option<bool>,
    ) -> Result<RoleChange, RpcError> {
        if !valid_role(role) {
            return Err(invalid_params(INVALID_ROLE));
        }
        let Some(u) = self.users.get(user_id).filter(|u| u.persists()) else {
            return Err(invalid_params("No registered user has that user_id"));
        };
        let held = u.has_role(role);
        let on = on.unwrap_or(!held);
        let mut change = RoleChange {
            on,
            changed: false,
            who: who(&u.name, user_id),
        };
        if on == held {
            return Ok(change);
        }
        let refusal = if !on {
            if role == ADMIN_ROLE && user_id == ADMIN_USER_ID {
                Some("The admin user is always an admin".to_owned())
            } else if role == BOT_ROLE && u.owner.is_some() {
                Some("An owner's bot is always a bot".to_owned())
            } else {
                None
            }
        } else if role == ADMIN_ROLE && u.bot() {
            Some("A bot can't be an admin".to_owned())
        } else if role == BOT_ROLE && u.has_role(ADMIN_ROLE) {
            Some("An admin can't be a bot; take away admin first".to_owned())
        } else if role == BOT_ROLE && u.passkey.is_some() {
            Some("A bot signs in with a token and holds no passkey; this user has one".to_owned())
        } else if role == BOT_ROLE && !u.email.is_empty() {
            Some(
                "A bot signs in with a token and holds no email address; this user has one"
                    .to_owned(),
            )
        } else if u.roles.len() >= MAX_ROLES {
            Some(format!("A user has at most {MAX_ROLES} roles"))
        } else {
            None
        };
        if let Some(message) = refusal {
            return Err(RpcError::new(CODE_DENIED, message));
        }
        let u = self.users.get_mut(user_id).expect("checked above");
        if on {
            u.roles.push(role.to_owned());
        } else {
            u.roles.retain(|r| r != role);
        }
        // A user just made a bot is not idle (bots.rs).
        u.active = rust_stdlib::time::now().unix_milli();
        self.touch_user(user_id);
        self.notify_profile_locked(user_id, None, &ExtObject::new(), &[]);
        let clients: Vec<_> = self.users[user_id]
            .clients
            .iter()
            .filter_map(|id| self.clients.get(id).map(|conn| conn.client.clone()))
            .collect();
        for client in clients {
            self.sync_server_locked(&client);
        }
        change.changed = true;
        Ok(change)
    }
}

/// A user as an admin command's notice names them.
fn who(name: &str, user_id: &str) -> String {
    let name = if name.is_empty() { user_id } else { name };
    format!("**{name}** (`{user_id}`)")
}
