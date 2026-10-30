//! Accounts an admin makes without a passkey, following
//! apron-server-cloudflare's `/invite-token` and `/invite-code` (its SPEC.md,
//! section 5, Admins): the account signs in with a bearer token through the
//! `token` scheme (§3.2), from any origin, and a sign-up invite makes one
//! such account per use (Appendix B).

use std::sync::Arc;

use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::time::{self, Time};
use rust_stdlib_crypto::{rand, sha256};

use super::admin::ADMIN_USER_ID;
use super::client::Client;
use super::commands::{private_notice, user_id_args, CommandCtx};
use super::devices::apron_link;
use super::email::web_socket_url;
use super::protocol::*;
use super::server::State;
use super::tokens::{Held, TokenTable};
use super::user_ids::{candidate_user_id, normalize_name};
use super::webauthn::SessionKey;
use crate::obj;

pub const INVITE_TOKEN_PREFIX: &str = "apron_invite_";
pub const JOIN_TOKEN_PREFIX: &str = "apron_join_";
/// Sign-ups one `/invite-code` may allow, and how long it lasts.
pub const MAX_JOIN_USES: i64 = 50;
pub const JOIN_INVITE_TTL: time::Duration = time::Duration::from_hours(7 * 24);
/// The name of a user who signs up with an invite and asks for none: not
/// "Guest", which names guests.
pub const JOIN_DEFAULT_NAME: &str = "Member";

/// The one live sign-up invite (`/invite-code`): the SHA-256 of its token, the
/// sign-ups it has left, and when it expires, in Unix milliseconds.
#[derive(Clone, Debug)]
pub struct JoinInvite {
    pub key: SessionKey,
    pub remaining: i64,
    pub expires_ms: i64,
}

/// An account token, kept by the SHA-256 of the token.
#[derive(Clone, Debug)]
pub struct InviteToken {
    pub user: String,
    pub created: Time,
}

/// The account tokens, one an account.
pub type InviteTokens = TokenTable<InviteToken>;

impl Held for InviteToken {
    const ONE_PER_HOLDER: bool = true;
    fn holder(&self) -> &str {
        &self.user
    }
    fn set_holder(&mut self, to: &str) {
        self.user = to.to_owned();
    }
}

/// Why an admin may not give out a user_id (`issuable`).
pub(super) const NOT_ISSUABLE: &str = "A user_id is 1 to 64 letters, digits, _ or -, starting with a letter or digit, ending with a letter, digit or _, and not guest_ or bot_";

/// Reports whether an admin may give out `user_id`: 1 to 64 letters,
/// digits, `_` or `-`, starting with a letter or digit and ending with a
/// letter, digit or `_`, so that `@` and the whole ID make a mention in text
/// (Appendix A.3), and not a guest's or bot's.
pub(super) fn issuable(user_id: &str) -> bool {
    let bytes = user_id.as_bytes();
    let inner = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-');
    let lower = user_id.to_ascii_lowercase();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(inner)
        && (bytes[bytes.len() - 1].is_ascii_alphanumeric() || bytes[bytes.len() - 1] == b'_')
        && !["guest", "bot"]
            .iter()
            .any(|p| lower == *p || lower.starts_with(&format!("{p}_")))
}

/// A new token: `prefix` and 32 random bytes as unpadded base64url, and the
/// SHA-256 it is kept by.
pub fn new_token(prefix: &str) -> (String, SessionKey) {
    let mut secret = [0u8; 32];
    rand::read(&mut secret);
    let token = format!("{prefix}{}", URL_SAFE_NO_PAD.encode(secret));
    let key = sha256::sum256(token.as_bytes());
    (token, key)
}

impl State {
    pub fn touch_invite(&mut self, key: SessionKey) {
        self.dirty.invites.insert(key);
    }

    /// Makes an account that signs in with a token alone, named `name`, and
    /// mints its token. The caller has checked that `user_id` is free.
    pub(super) fn create_invited_locked(&mut self, user_id: &str, name: &str) -> String {
        let key = user_id.to_lowercase();
        self.used_ids.insert(key.clone());
        self.touch_used_id(&key);
        let mut u = self.new_user_locked(user_id, name);
        u.invited = true;
        self.users.insert(user_id.to_owned(), u);
        self.touch_user(user_id);
        self.grant_roles_locked(user_id);
        let (token, key) = new_token(INVITE_TOKEN_PREFIX);
        self.invites.insert(
            key,
            InviteToken {
                user: user_id.to_owned(),
                created: time::now(),
            },
        );
        self.touch_invite(key);
        token
    }

    /// `/invite-token <user_id>` (a leading `@` is allowed): makes an account
    /// with that user_id and no passkey, named after it, in the default room,
    /// and sends the sender its bearer token in a ~private notice before the
    /// result (§1), as is and in a link any Apron app opens (Appendix A.4).
    pub(super) fn invite_token_command(&mut self, cx: &CommandCtx) -> Result<Object, RpcError> {
        let CommandCtx {
            client: c,
            room_id,
            args,
            ..
        } = *cx;
        let [user_id] = user_id_args(args, "Usage: /invite-token <user_id>")?;
        let taken = invalid_params(format!("The user_id {user_id} is taken"));
        if user_id.eq_ignore_ascii_case(ADMIN_USER_ID) {
            return Err(taken);
        }
        if !issuable(user_id) {
            return Err(invalid_params(NOT_ISSUABLE));
        }
        // A user_id --role grants is free for an admin to make.
        if self.used_ids.contains(&user_id.to_lowercase()) || self.room_named_locked(user_id) {
            return Err(taken);
        }
        self.charge_registration_locked(c, true)?;
        let token = self.create_invited_locked(user_id, user_id);
        self.join_default_room_locked(user_id);
        let mut parts = vec![
            format!("Created `{user_id}`, who signs in with this token instead of a passkey. It does not expire, and anyone who has it signs in as `{user_id}`, so hand it over privately."),
            format!("```\n{token}\n```"),
        ];
        let server = web_socket_url(&self.config.public_url);
        if !server.is_empty() {
            parts.push(format!(
                "Or send them this link, which signs them in with any Apron app: <{}>",
                apron_link(&server, &token)
            ));
        }
        parts.push(format!("To sign in, authenticate with the token scheme: `{{\"method\": \"auth\", \"params\": {{\"scheme\": \"token\", \"token\": \"{token}\"}}}}`"));
        c.enqueue(&private_notice(&self.rooms[room_id], &parts.join("\n\n")));
        Ok(Object::new())
    }

    /// Signs the connection in with an account token, from any origin. The
    /// result carries no session token: the client keeps this one.
    pub(super) fn authenticate_invite_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
        token: &str,
    ) -> Result<Json, RpcError> {
        let key = sha256::sum256(token.as_bytes());
        let Some(user_id) = self.invites.get(&key).map(|t| t.user.clone()) else {
            return Err(RpcError::new(
                CODE_DENIED,
                "This invite token is not valid; ask an admin for a new one",
            ));
        };
        self.check_token_switch(c, &user_id)?;
        self.sign_in_keyless_locked(c, req, &user_id, false)
    }

    /// `/invite-code <uses>`: mints the sign-up invite (Appendix B), a token that
    /// signs up to `uses` new accounts within a week, and revokes the last
    /// one; `/invite-code 0` only revokes. The token goes to this connection only,
    /// in a ~private notice before the result (§1).
    pub(super) fn invite_command(&mut self, cx: &CommandCtx) -> Result<Object, RpcError> {
        let CommandCtx {
            client: c,
            room_id,
            args,
            ..
        } = *cx;
        let digits = (1..=3).contains(&args.len()) && args.bytes().all(|b| b.is_ascii_digit());
        let Some(uses) = digits.then(|| args.parse::<i64>().ok()).flatten() else {
            return Err(invalid_params(format!(
                "Usage: /invite-code <uses>, 0 to {MAX_JOIN_USES}"
            )));
        };
        // More uses than the server allows is a count limit (§1.1).
        if uses > MAX_JOIN_USES {
            return Err(RpcError::new(
                CODE_DENIED,
                format!("An invite signs up at most {MAX_JOIN_USES} users"),
            ));
        }
        if uses == 0 {
            self.join_invite = None;
            c.enqueue(&private_notice(
                &self.rooms[room_id],
                "The sign-up invite is revoked.",
            ));
            return Ok(Object::new());
        }
        let (token, key) = new_token(JOIN_TOKEN_PREFIX);
        let expires = time::now().add(JOIN_INVITE_TTL);
        self.join_invite = Some(JoinInvite {
            key,
            remaining: uses,
            expires_ms: expires.unix_milli(),
        });
        let plural = if uses == 1 { "" } else { "s" };
        let mut parts = vec![
            format!(
                "This invite signs up {uses} new user{plural} until {} UTC, and replaces any earlier one. Each gets their own token to sign in again with, and can add a passkey after.",
                expires.utc().format("2006-01-02 15:04")
            ),
            format!("```\n{token}\n```"),
        ];
        let server = web_socket_url(&self.config.public_url);
        if !server.is_empty() {
            parts.push(format!(
                "Or send this link, which signs each of them up with any Apron app: <{}>",
                apron_link(&server, &token)
            ));
        }
        parts.push(format!("To sign up, authenticate with the token scheme and a name: `{{\"method\": \"auth\", \"params\": {{\"scheme\": \"token\", \"token\": \"{token}\", \"name\": \"Ada\"}}}}`"));
        c.enqueue(&private_notice(&self.rooms[room_id], &parts.join("\n\n")));
        Ok(Object::new())
    }

    /// Signs up a new account with the live sign-up invite (Appendix B),
    /// named as `auth`'s `name` asks, else "Member", with a user_id picked
    /// from the name as a passkey registration's is. The result carries the
    /// account's own `apron_invite_` token, so the shared invite is not
    /// needed again, and the account joins the default room after it. A
    /// used-up, expired or revoked invite is denied, and a used-up or
    /// expired one is dropped.
    pub(super) fn authenticate_join_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
        token: &str,
    ) -> Result<Json, RpcError> {
        if self
            .client_user(c)
            .is_some_and(|id| self.users[&id].persists())
        {
            return Err(RpcError::new(
                CODE_DENIED,
                "Identity switching requires reconnect",
            ));
        }
        let mut name = normalize_name(&parse_string(&req.params, "name", false)?);
        if name.is_empty() {
            name = JOIN_DEFAULT_NAME.to_owned();
        }
        let key = sha256::sum256(token.as_bytes());
        let now = time::now().unix_milli();
        let live = match &self.join_invite {
            Some(invite) if invite.key == key => {
                if invite.remaining > 0 && invite.expires_ms > now {
                    true
                } else {
                    self.join_invite = None;
                    false
                }
            }
            _ => false,
        };
        if !live {
            return Err(RpcError::new(
                CODE_DENIED,
                "This invite is used up or has expired; ask an admin for a new one",
            ));
        }
        self.charge_registration_locked(c, true)?;
        if let Some(invite) = &mut self.join_invite {
            invite.remaining -= 1;
        }
        let user_id = candidate_user_id(&name, |id| self.user_id_taken_locked(id));
        let own = self.create_invited_locked(&user_id, &name);
        Ok(self
            .switch_user_locked(c, req, &user_id, obj! {"token" => own}, true, true)?
            .into())
    }

    /// Refuses a token sign-in as `user_id` on a connection signed in as
    /// another account or bot: switching identities takes a reconnect, as
    /// apron-server-cloudflare has it. A guest may sign in.
    pub(super) fn check_token_switch(&self, c: &Client, user_id: &str) -> Result<(), RpcError> {
        match self.client_user(c) {
            Some(id) if id != user_id && self.users[&id].persists() => Err(RpcError::new(
                CODE_DENIED,
                "Identity switching requires reconnect",
            )),
            _ => Ok(()),
        }
    }

    /// Signs the connection in as `user_id` with a token that has no session
    /// behind it, joining the default room after the result when `created`.
    pub(super) fn sign_in_keyless_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
        user_id: &str,
        created: bool,
    ) -> Result<Json, RpcError> {
        let sign_in = self.client_user(c).as_deref() != Some(user_id);
        Ok(self
            .switch_user_locked(c, req, user_id, Object::new(), sign_in, created)?
            .into())
    }
}
