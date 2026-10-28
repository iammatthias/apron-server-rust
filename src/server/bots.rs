//! `/invite-bot`, an extension Go lacks (docs/DEVIATIONS.md): an account
//! gets one bot of its own, `bot_<user_id>`, named after it, and a bearer
//! token that signs in as the bot through the `token` scheme (§3.2), from any
//! origin, until `/invite-bot` again mints a new one. It follows
//! apron-server-cloudflare's `/invite-bot`.
//!
//! A bot is a user with an owner and no credential: it persists as an
//! account does, but `account()` is false for it, so it gets no account
//! commands, and it can never add a passkey or an email address.

use std::collections::BTreeMap;
use std::sync::Arc;

use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::time::{self, Time};
use rust_stdlib_crypto::{rand, sha256};

use super::email::web_socket_url;
use super::protocol::*;
use super::server::{Client, ClientId, State};
use super::users::{normalize_name, UserState};
use super::webauthn::SessionKey;

/// Starts every bot's user_id, followed by its owner's. No other user may
/// have one (`users::requestable`).
pub const BOT_ID_PREFIX: &str = "bot_";
pub const BOT_TOKEN_PREFIX: &str = "apron_bot_";
/// The one server role (§3.3) a bot holds.
pub const BOT_ROLE: &str = "bot";
/// Refuses a bot's request to add a passkey or an email address.
pub const BOT_SIGNS_IN_WITH_TOKEN: &str =
    "A bot signs in only with its token; it cannot add a passkey or an email address";

/// A bot token, kept by the SHA-256 of the token: the bot it signs in as and
/// the account that minted it.
#[derive(Clone, Debug)]
pub struct BotToken {
    pub bot: String,
    pub owner: String,
    pub created: Time,
}

/// The bot tokens by key, and each bot's one key.
#[derive(Default)]
pub struct BotTokens {
    by_key: BTreeMap<SessionKey, BotToken>,
    by_bot: BTreeMap<String, SessionKey>,
}

impl BotTokens {
    pub fn get(&self, key: &SessionKey) -> Option<&BotToken> {
        self.by_key.get(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &SessionKey> {
        self.by_key.keys()
    }

    /// The key of the bot's token, if it has one.
    pub fn of_bot(&self, bot_id: &str) -> Option<SessionKey> {
        self.by_bot.get(bot_id).copied()
    }

    /// Adds a token, whose bot must hold no other.
    pub fn insert(&mut self, key: SessionKey, token: BotToken) {
        self.by_bot.insert(token.bot.clone(), key);
        self.by_key.insert(key, token);
    }

    pub fn remove(&mut self, key: &SessionKey) -> Option<BotToken> {
        let token = self.by_key.remove(key)?;
        if self.by_bot.get(&token.bot) == Some(key) {
            self.by_bot.remove(&token.bot);
        }
        Some(token)
    }
}

/// The name of an account's bot: "Bot of" and the account's name, or its
/// user_id when it has none, within the name limits.
fn bot_name(owner: &UserState) -> String {
    let of = if owner.name.is_empty() {
        &owner.id
    } else {
        &owner.name
    };
    normalize_name(&format!("Bot of {of}"))
}

impl State {
    pub fn touch_bot(&mut self, key: SessionKey) {
        self.dirty.bots.insert(key);
    }

    /// Makes the sender's bot, or renames it after the sender's current
    /// name, and mints its token, replacing the last one: the bot's
    /// connections that signed in with it close. A new bot joins the default
    /// room, as a new guest does. The token goes to this connection only, in
    /// a ~private notice before the result (§1).
    pub(super) fn invite_bot_command(
        &mut self,
        c: &Arc<Client>,
        room_id: &str,
        _body: &Object,
        args: &str,
    ) -> Result<Object, RpcError> {
        let owner_id = self.client_user(c).unwrap_or_default();
        let owner = &self.users[&owner_id];
        if !owner.account() {
            return Err(RpcError::new(
                CODE_DENIED,
                "Sign in with a passkey or email to use /invite-bot",
            ));
        }
        if !args.is_empty() {
            return Err(invalid_params("Usage: /invite-bot"));
        }
        let bot_id = format!("{BOT_ID_PREFIX}{owner_id}");
        let name = bot_name(owner);
        let exists = match self.users.get(&bot_id) {
            Some(bot) if bot.owner.as_deref() == Some(owner_id.as_str()) => true,
            Some(_) => {
                return Err(RpcError::new(
                    CODE_DENIED,
                    format!(
                        "The user_id {bot_id} belongs to someone else, so you cannot have a bot"
                    ),
                ))
            }
            None => false,
        };
        // A user_id is never reissued (§3.3): one a user held before the
        // bot_ prefix was reserved stays theirs.
        if !exists && !self.claim_user_id_locked(&bot_id) {
            return Err(RpcError::new(
                CODE_DENIED,
                format!("The user_id {bot_id} was taken, so you cannot have a bot"),
            ));
        }

        // The old token goes before the new one is minted, so the bot never
        // has two.
        let previous = self.bots.of_bot(&bot_id);
        if let Some(old) = previous {
            self.bots.remove(&old);
            self.touch_bot(old);
            self.revoke_bot_locked(&bot_id, &old);
        }

        if !exists {
            let mut bot = self.new_user_locked(&bot_id, &name);
            bot.owner = Some(owner_id.clone());
            self.users.insert(bot_id.clone(), bot);
            self.touch_user(&bot_id);
            self.grant_roles_locked(&bot_id);
            self.join_default_room_locked(&bot_id);
        } else if self.users[&bot_id].name != name {
            self.users.get_mut(&bot_id).expect("bot exists").name = name.clone();
            self.touch_user(&bot_id);
            self.notify_profile_locked(&bot_id, None, &ExtObject::new(), &[]);
        }

        let mut secret = [0u8; 32];
        rand::read(&mut secret);
        let token = format!("{BOT_TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(secret));
        let key = sha256::sum256(token.as_bytes());
        self.bots.insert(
            key,
            BotToken {
                bot: bot_id.clone(),
                owner: owner_id,
                created: time::now(),
            },
        );
        self.touch_bot(key);

        let server = web_socket_url(&self.config.public_url);
        let server = if server.is_empty() {
            "this server's WebSocket URL".to_owned()
        } else {
            server
        };
        let text = format!(
            "This token signs in as your bot **{name}** (`{bot_id}`) and replaces any earlier one. Anyone who has it can post as the bot, so keep it secret.\n\n```\n{token}\n```\n\nIf you're using an LLM, you can give it these instructions:\n\n```\nRead https://github.com/shazow/apron/blob/main/PROTOCOL.md\nConnect to {server}\nAuth using token scheme with this token: \"{token}\"\n```"
        );
        c.enqueue(&super::commands::private_notice(
            &self.rooms[room_id],
            &text,
        ));
        Ok(Object::new())
    }

    /// Closes and signs out the bot's connections that signed in with the
    /// replaced token, then forgets the bot's push registrations, as a replaced device token
    /// does.
    fn revoke_bot_locked(&mut self, bot_id: &str, old: &SessionKey) {
        let revoked: Vec<ClientId> = self
            .users
            .get(bot_id)
            .map(|u| &u.clients)
            .into_iter()
            .flatten()
            .filter(|id| self.clients[*id].token == *old)
            .copied()
            .collect();
        for id in revoked {
            self.revoke_connection_locked(
                id,
                RpcError::new(CODE_DENIED, "Bot token replaced; sign in with the new one"),
            );
        }
        for key in self.sorted_pushes(bot_id) {
            self.remove_push_locked(&key);
        }
    }

    /// Signs the connection in as a bot with its token, from any origin. The
    /// result carries no session token: the bot keeps its own.
    pub(super) fn authenticate_bot_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
        token: &str,
    ) -> Result<Json, RpcError> {
        let key = sha256::sum256(token.as_bytes());
        let Some(bot_id) = self
            .bots
            .get(&key)
            .map(|b| b.bot.clone())
            .filter(|id| self.users.contains_key(id))
        else {
            return Err(RpcError::new(
                CODE_DENIED,
                "Bot token is not valid; its owner can get a new one with /invite-bot",
            ));
        };
        self.set_conn_token(c, key);
        let sign_in = self.client_user(c).as_deref() != Some(&bot_id);
        Ok(self
            .switch_user_locked(c, req, &bot_id, Object::new(), sign_in, false)
            .into())
    }
}
