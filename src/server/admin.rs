//! The admin token and the user it signs in as, an extension Go lacks
//! (docs/DEVIATIONS.md), following apron-server-cloudflare's
//! `APRON_ADMIN_TOKEN` (its SPEC.md, section 5, Admins).

use std::sync::Arc;

use rust_stdlib_crypto::{sha256, subtle};

use super::protocol::*;
use super::server::{Client, State};
use super::users::ADMIN_ROLE;

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
        let current = self.client_user(c);
        if current.as_deref() == Some(ADMIN_USER_ID) {
            return Ok(self
                .switch_user_locked(c, req, ADMIN_USER_ID, Object::new(), false, false)
                .into());
        }
        if current.is_some_and(|id| self.users[&id].persists()) {
            return Err(RpcError::new(
                CODE_DENIED,
                "Identity switching requires reconnect",
            ));
        }
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
        Ok(self
            .switch_user_locked(c, req, ADMIN_USER_ID, Object::new(), true, created)
            .into())
    }
}
