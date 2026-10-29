//! `/invite-bot`, an extension Go lacks (docs/DEVIATIONS.md): an account
//! gets one bot of its own, made as `bot_<user_id>` and keeping that
//! user_id when its owner is renamed, named after it, and a bearer
//! token that signs in as the bot through the `token` scheme (§3.2), from any
//! origin, until `/invite-bot` again mints a new one. It follows
//! apron-server-cloudflare's `/invite-bot`.
//!
//! A bot is a user with an owner and no credential: it persists as an
//! account does, but `account()` is false for it, so it gets no account
//! commands, and it can never add a passkey or an email address.

use std::collections::BTreeMap;
use std::sync::Arc;

use rust_stdlib::time::{self, Duration, Time};
use rust_stdlib_crypto::sha256;

use super::client::{Client, ClientId};
use super::commands::CommandCtx;
use super::email::web_socket_url;
use super::protocol::*;
use super::remap::{Fate, Remap};
use super::server::State;
use super::user_ids::normalize_name;
use super::users::UserState;
use super::webauthn::SessionKey;

/// Starts every bot's user_id, followed by its owner's. No other user may
/// have one (`user_ids::requestable`).
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

    /// The keys of the tokens `owner` minted.
    pub fn owned_by(&self, owner: &str) -> Vec<SessionKey> {
        self.by_key
            .iter()
            .filter(|(_, token)| token.owner == owner)
            .map(|(key, _)| *key)
            .collect()
    }

    /// Removes the tokens of the bots `remap` drops and the tokens their
    /// owners minted, or gives the tokens the renamed owner minted to the
    /// new user_id, and returns their keys.
    pub(super) fn remap(&mut self, remap: &Remap) -> Vec<SessionKey> {
        let mut changed = Vec::new();
        for from in remap.sources() {
            match remap.fate(from) {
                Fate::Rename(to) => {
                    for key in self.owned_by(from) {
                        self.by_key.get_mut(&key).expect("listed").owner = to.to_owned();
                        changed.push(key);
                    }
                }
                _ => {
                    for key in self.of_bot(from).into_iter().chain(self.owned_by(from)) {
                        self.remove(&key);
                        changed.push(key);
                    }
                }
            }
        }
        changed
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

    /// The user_ids of the bots `owner` owns. A bot keeps its user_id when
    /// its owner is renamed, so this, not the `bot_` prefix, finds them.
    pub fn bots_of(&self, owner: &str) -> Vec<String> {
        self.users
            .values()
            .filter(|u| u.owner.as_deref() == Some(owner))
            .map(|u| u.id.clone())
            .collect()
    }

    /// Makes the sender's bot, or renames it after the sender's current
    /// name, and mints its token, replacing the last one: the bot's
    /// connections that signed in with it close. A new bot joins the default
    /// room, as a new guest does. The token goes to this connection only, in
    /// a ~private notice before the result (§1).
    pub(super) fn invite_bot_command(&mut self, cx: &CommandCtx) -> Result<Object, RpcError> {
        let CommandCtx {
            client: c,
            room_id,
            args,
            ..
        } = *cx;
        let owner_id = cx.user_id.to_owned();
        let owner = &self.users[&owner_id];
        if !args.is_empty() {
            return Err(invalid_params("Usage: /invite-bot"));
        }
        let bot_id = self
            .bots_of(&owner_id)
            .into_iter()
            .next()
            .unwrap_or_else(|| format!("{BOT_ID_PREFIX}{owner_id}"));
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

        let (token, key) = super::invites::new_token(BOT_TOKEN_PREFIX);
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
    /// replaced token, then forgets the bot's push registrations.
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
            .switch_user_locked(c, req, &bot_id, Object::new(), sign_in, false)?
            .into())
    }
}

/// How long a bot may go without signing in, posting or reacting before
/// the idle bot sweep signs it out, and how often the sweep runs.
pub const BOT_IDLE: Duration = Duration::from_hours(7 * 24);
pub const BOT_SWEEP_INTERVAL: Duration = Duration::from_hours(24);
/// Bots one sweep signs out; a full batch makes the next sweep due at once.
pub const BOT_SWEEP_BATCH: usize = 4;
/// A bot's activity is noted at most this often.
const BOT_ACTIVE_WRITE: Duration = Duration::from_hours(1);

impl State {
    /// Notes that a user whose only role is `bot` signed in, posted or
    /// reacted, for the idle bot sweep; at most hourly. Anyone else is left
    /// as is.
    pub fn note_bot_active_locked(&mut self, user_id: &str) {
        let now = time::now().unix_milli();
        let Some(u) = self.users.get_mut(user_id) else {
            return;
        };
        if u.roles != [BOT_ROLE] || now - u.active < BOT_ACTIVE_WRITE.milliseconds() {
            return;
        }
        u.active = now;
        self.touch_user(user_id);
    }

    /// The idle bot sweep, apron-server-cloudflare's: once due, signs out up
    /// to BOT_SWEEP_BATCH users whose only role is `bot` and that have been
    /// inactive for BOT_IDLE, oldest first. Each is closed, leaves its rooms
    /// with logged leaves, and loses its tokens; its account and what it
    /// posted stay, and its owner's next `/invite-bot` brings it back. The
    /// first sweep after a start with none due only sets one a week out, so
    /// bots active before are not taken for idle.
    pub fn sweep_idle_bots_locked(&mut self, now: &Time) {
        let now = now.unix_milli();
        if self.bot_sweep_at == 0 {
            self.bot_sweep_at = now + BOT_IDLE.milliseconds();
            return;
        }
        if now < self.bot_sweep_at {
            return;
        }
        let before = now - BOT_IDLE.milliseconds();
        let mut idle: Vec<(i64, String)> = self
            .users
            .values()
            .filter(|u| u.roles == [BOT_ROLE] && u.active > 0 && u.active < before)
            .map(|u| (u.active, u.id.clone()))
            .collect();
        idle.sort();
        idle.truncate(BOT_SWEEP_BATCH);
        self.bot_sweep_at = if idle.len() == BOT_SWEEP_BATCH {
            now
        } else {
            now + BOT_SWEEP_INTERVAL.milliseconds()
        };
        for (_, user_id) in idle {
            self.sign_out_bot_locked(&user_id);
        }
    }

    fn sign_out_bot_locked(&mut self, user_id: &str) {
        let clients: Vec<ClientId> = self.users[user_id].clients.iter().copied().collect();
        for id in clients {
            self.revoke_connection_locked(
                id,
                RpcError::new(
                    CODE_DENIED,
                    "Signed out after a week without signing in or posting",
                ),
            );
        }
        let rooms: Vec<String> = self.users[user_id].joined.iter().cloned().collect();
        for room_id in rooms {
            self.leave_locked(user_id, &room_id);
        }
        if let Some(key) = self.bots.of_bot(user_id) {
            self.bots.remove(&key);
            self.touch_bot(key);
        }
        if let Some(key) = self.invites.of_user(user_id) {
            self.invites.remove(&key);
            self.touch_invite(key);
        }
        for key in self.sorted_pushes(user_id) {
            self.remove_push_locked(&key);
        }
        if let Some(u) = self.users.get_mut(user_id) {
            u.active = 0;
        }
        self.touch_user(user_id);
    }
}
