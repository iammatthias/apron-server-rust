//! Accounts an admin makes without a passkey, an extension Go lacks
//! (docs/DEVIATIONS.md), following apron-server-cloudflare's `/invite-token`
//! (its SPEC.md, section 5, Admins): the account signs in with a bearer
//! token through the `token` scheme (§3.2), from any origin.

use std::collections::BTreeMap;
use std::sync::Arc;

use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::time::{self, Time};
use rust_stdlib_crypto::{rand, sha256};

use super::admin::ADMIN_USER_ID;
use super::commands::private_notice;
use super::devices::apron_link;
use super::email::web_socket_url;
use super::protocol::*;
use super::server::{Client, State};
use super::webauthn::SessionKey;

pub const INVITE_TOKEN_PREFIX: &str = "apron_invite_";

/// An account token, kept by the SHA-256 of the token.
#[derive(Clone, Debug)]
pub struct InviteToken {
    pub user: String,
    pub created: Time,
}

/// The account tokens by key, and each account's one key.
#[derive(Default)]
pub struct InviteTokens {
    by_key: BTreeMap<SessionKey, InviteToken>,
    by_user: BTreeMap<String, SessionKey>,
}

impl InviteTokens {
    pub fn get(&self, key: &SessionKey) -> Option<&InviteToken> {
        self.by_key.get(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &SessionKey> {
        self.by_key.keys()
    }

    pub fn of_user(&self, user_id: &str) -> Option<SessionKey> {
        self.by_user.get(user_id).copied()
    }

    pub fn insert(&mut self, key: SessionKey, token: InviteToken) {
        self.by_user.insert(token.user.clone(), key);
        self.by_key.insert(key, token);
    }

    pub fn remove(&mut self, key: &SessionKey) -> Option<InviteToken> {
        let token = self.by_key.remove(key)?;
        if self.by_user.get(&token.user) == Some(key) {
            self.by_user.remove(&token.user);
        }
        Some(token)
    }
}

/// Reports whether an admin may give out `user_id`: 1 to 64 letters,
/// digits, `_` or `-`, starting with a letter or digit and ending with a
/// letter, digit or `_`, so that `@` and the whole ID make a mention in text
/// (Appendix A.3), and not a guest's or bot's.
fn issuable(user_id: &str) -> bool {
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
    pub(super) fn invite_token_command(
        &mut self,
        c: &Arc<Client>,
        room_id: &str,
        _body: &Object,
        args: &str,
    ) -> Result<Object, RpcError> {
        let mut words = args.split_whitespace();
        let (Some(word), None) = (words.next(), words.next()) else {
            return Err(invalid_params("Usage: /invite-token <user_id>"));
        };
        let user_id = word.strip_prefix('@').unwrap_or(word);
        let taken = invalid_params(format!("The user_id {user_id} is taken"));
        if user_id.eq_ignore_ascii_case(ADMIN_USER_ID) {
            return Err(taken);
        }
        if !issuable(user_id) {
            return Err(invalid_params(
                "A user_id is 1 to 64 letters, digits, _ or -, starting with a letter or digit, ending with a letter, digit or _, and not guest_ or bot_",
            ));
        }
        // A user_id --role grants is free for an admin to make.
        if self.used_ids.contains(&user_id.to_lowercase()) || self.room_named_locked(user_id) {
            return Err(taken);
        }
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
            .switch_user_locked(c, req, user_id, Object::new(), sign_in, created)
            .into())
    }
}
