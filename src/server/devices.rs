//! `/invite-device <name>`: an account mints a bearer token that signs it in
//! on another device through the `token` scheme (§3.2), from any origin,
//! until the same name mints a new one. It follows apron-server-cloudflare's
//! `/invite-device`.

use std::sync::Arc;

use rust_stdlib::time::{self, Time};
use rust_stdlib_crypto::sha256;

use super::client::{Client, ClientId};
use super::commands::CommandCtx;
use super::email::web_socket_url;
use super::protocol::*;
use super::server::State;
use super::tokens::{Held, TokenTable};
use super::webauthn::SessionKey;

/// Device tokens an account may hold at once, each under its own name.
pub const MAX_DEVICE_TOKENS: usize = 3;
pub const DEVICE_TOKEN_PREFIX: &str = "apron_device_";

/// A device token, kept by the SHA-256 of the token: the account it signs in
/// as and the name it was minted under.
#[derive(Clone, Debug)]
pub struct DeviceToken {
    pub user: String,
    pub name: String,
    pub created: Time,
}

/// The device tokens, each account's oldest first, so a name again finds its
/// token and the cap names them in order.
pub type DeviceTokens = TokenTable<DeviceToken>;

impl Held for DeviceToken {
    const ONE_PER_HOLDER: bool = false;
    fn holder(&self) -> &str {
        &self.user
    }
    fn set_holder(&mut self, to: &str) {
        self.user = to.to_owned();
    }
}

/// A device name: 1 to 32 letters, digits, `_`, `.` or `-`, starting with a
/// letter or digit.
fn valid_device_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

impl State {
    pub fn touch_device(&mut self, key: SessionKey) {
        self.dirty.devices.insert(key);
    }

    /// Mints a device token for the sender's account under the one name in
    /// args. The same name again replaces its token: the old one no longer
    /// signs in, and the account's other connections that signed in with it
    /// close and its push registrations go. A passkey or session token
    /// someone got while signed in with the old token stays. The token goes
    /// to this connection only, in a ~private notice before the result (§1).
    pub(super) fn invite_device_command(&mut self, cx: &CommandCtx) -> Result<Object, RpcError> {
        let CommandCtx {
            client: c,
            room_id,
            args,
            ..
        } = *cx;
        let user_id = cx.user_id.to_owned();
        if user_id == super::admin::ADMIN_USER_ID {
            return Err(RpcError::new(
                CODE_DENIED,
                super::admin::ADMIN_SIGNS_IN_WITH_TOKEN,
            ));
        }
        let mut words = args.split_whitespace();
        let (Some(name), None) = (words.next(), words.next()) else {
            return Err(invalid_params("Usage: /invite-device <name>"));
        };
        if !valid_device_name(name) {
            return Err(invalid_params(
                "A device name is 1 to 32 letters, digits, _, . or -, starting with a letter or digit",
            ));
        }
        let held: Vec<(SessionKey, String)> = self
            .devices
            .of(&user_id)
            .map(|(key, token)| (key, token.name.clone()))
            .collect();
        let previous = held
            .iter()
            .find(|(_, held)| held == name)
            .map(|(key, _)| *key);
        if previous.is_none() && held.len() >= MAX_DEVICE_TOKENS {
            let names: Vec<String> = held.iter().map(|(_, name)| format!("`{name}`")).collect();
            return Err(RpcError::new(
                CODE_DENIED,
                format!(
                    "You have {MAX_DEVICE_TOKENS} device tokens ({}); run /invite-device with one of those names to replace its token",
                    names.join(", ")
                ),
            ));
        }
        if let Some(old) = previous {
            self.devices.remove(&old);
            self.touch_device(old);
        }
        let (token, key) = super::invites::new_token(DEVICE_TOKEN_PREFIX);
        self.devices.insert(
            key,
            DeviceToken {
                user: user_id.clone(),
                name: name.to_owned(),
                created: time::now(),
            },
        );
        self.touch_device(key);
        if let Some(old) = previous {
            self.revoke_device_locked(c, &user_id, &old, &key);
        }
        let replaced = if previous.is_some() {
            ", and replaces its earlier token"
        } else {
            ""
        };
        let server = web_socket_url(&self.config.public_url);
        let link = if server.is_empty() {
            String::new()
        } else {
            format!(
                "Or open this link on **{name}**, which signs you in there with any Apron app: <{}>\n\n",
                apron_link(&server, &token)
            )
        };
        let text = format!(
            "This token signs in as you (`{user_id}`) on your device **{name}**{replaced}. It does not expire, and anyone who has it can sign in as you, so keep it secret. `/invite-device {name}` again replaces it.\n\n```\n{token}\n```\n\n{link}To sign in, authenticate with the token scheme: `{{\"method\": \"auth\", \"params\": {{\"scheme\": \"token\", \"token\": \"{token}\"}}}}`"
        );
        c.enqueue(&super::commands::private_notice(
            &self.rooms[room_id],
            &text,
        ));
        Ok(Object::new())
    }

    /// Closes and signs out the account's connections, other than the asking
    /// one, that signed in with the replaced token; the asking connection
    /// now counts as signed in with the replacement, so a later replacement
    /// closes it. The push registrations made by connections signed in with
    /// the old token go too, the asking connection's among them.
    fn revoke_device_locked(
        &mut self,
        c: &Client,
        user_id: &str,
        old: &SessionKey,
        replacement: &SessionKey,
    ) {
        if let Some(conn) = self
            .clients
            .get_mut(&c.id)
            .filter(|conn| conn.device == *old)
        {
            conn.device = *replacement;
        }
        let revoked: Vec<ClientId> = self.users[user_id]
            .clients
            .iter()
            .filter(|id| **id != c.id && self.clients[*id].device == *old)
            .copied()
            .collect();
        for id in revoked {
            self.revoke_connection_locked(
                id,
                RpcError::new(
                    CODE_DENIED,
                    "Device token replaced; sign in with the new one",
                ),
            );
        }
        for key in self.sorted_pushes(user_id) {
            if self.pushes[&key].device == *old {
                self.remove_push_locked(&key);
            }
        }
    }

    /// Signs the connection in with a device token, from any origin. The
    /// result carries no session token: the device keeps its own.
    pub(super) fn authenticate_device_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
        token: &str,
    ) -> Result<Json, RpcError> {
        let key = sha256::sum256(token.as_bytes());
        let Some(user_id) = self.devices.get(&key).map(|d| d.user.clone()) else {
            return Err(RpcError::new(
                CODE_DENIED,
                "This device token is not valid; get a new one with /invite-device on a signed-in device",
            ));
        };
        if let Some(conn) = self.clients.get_mut(&c.id) {
            conn.device = key;
        }
        let sign_in = self.client_user(c).as_deref() != Some(&user_id);
        Ok(self
            .switch_user_locked(c, req, &user_id, Object::new(), sign_in, false)?
            .into())
    }
}

/// A link that any Apron app opens to sign in to `server` with `token`
/// (link.apron.chat SPEC.md section 2.1), spelled as apron-server-cloudflare's
/// `apronLink` spells it: the keys go in the fragment, and every byte other
/// than a letter, a digit or one of `-._~:/` is percent-encoded.
pub fn apron_link(server: &str, token: &str) -> String {
    format!(
        "https://link.apron.chat/#server={}&token={}",
        link_escape(server),
        link_escape(token)
    )
}

fn link_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~:/".contains(&byte) {
            escaped.push(byte as char);
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    escaped
}
