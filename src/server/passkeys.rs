//! `/passkeys`, an extension Go lacks (docs/DEVIATIONS.md), following
//! apron-server-cloudflare's (its SPEC.md, section 5, WebAuthn): an account
//! lists its passkeys and removes one it no longer trusts.

use std::sync::Arc;

use rust_stdlib::time;

use super::commands::{private_notice, PRIVATE_NOTICE_ID, PRIVATE_NOTICE_NAME};
use super::protocol::*;
use super::server::{Client, State};
use super::webpush::encode_base64_url;
use crate::obj;

/// The first 8 characters of a credential ID in base64url, as `/passkeys`
/// names a passkey.
fn short_id(id: &[u8]) -> String {
    format!(
        "{}…",
        encode_base64_url(id).chars().take(8).collect::<String>()
    )
}

/// A day as `/passkeys` shows it, from Unix milliseconds; "unknown" for a
/// passkey stored before its times were kept.
fn day(ms: i64) -> String {
    if ms == 0 {
        return "unknown".into();
    }
    time::unix_milli(ms).utc().format("2006-01-02")
}

impl State {
    /// Sends a ~private notice, in no room, to the user's connections other
    /// than `c`.
    pub(super) fn send_to_others_locked(&self, user_id: &str, c: &Client, text: &str) {
        let notice = obj! {"method" => "message", "params" => obj! {
            "from" => obj! {"user_id" => PRIVATE_NOTICE_ID, "name" => PRIVATE_NOTICE_NAME},
            "body" => obj! {"text" => text, "format" => "markdown"},
        }};
        let Some(frame) = super::server::render(&notice) else {
            return;
        };
        for id in &self.users[user_id].clients {
            if *id != c.id {
                if let Some(conn) = self.clients.get(id) {
                    conn.client.enqueue_frame(frame.clone());
                }
            }
        }
    }

    /// `/passkeys` lists the sender's passkeys, oldest first, numbered, with
    /// when each was added and last used; `/passkeys remove <n>` removes one,
    /// though never the last, and deletes the account's push registrations,
    /// so a device that held it stops getting its messages. Both answer with
    /// a ~private notice before the result (§1), and a removal is also told
    /// to the account's other connections. Sessions the passkey started stay
    /// valid until they expire.
    pub(super) fn passkeys_command(
        &mut self,
        c: &Arc<Client>,
        room_id: &str,
        _body: &Object,
        args: &str,
    ) -> Result<Object, RpcError> {
        let usage = || invalid_params("Usage: /passkeys, or /passkeys remove <n>");
        let words: Vec<&str> = args.split_whitespace().collect();
        let chosen = match words.as_slice() {
            [] => None,
            ["remove", n]
                if (1..=2).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()) =>
            {
                Some(n.parse::<usize>().map_err(|_| usage())?)
            }
            _ => return Err(usage()),
        };
        let user_id = self.client_user(c).unwrap_or_default();
        let passkey = self.users[&user_id].passkey.clone().unwrap_or_default();
        let count = passkey.credentials.len();
        let Some(n) = chosen else {
            let text = if count == 0 {
                "Your account has no passkey. Register one while signed in to add it.".to_owned()
            } else {
                let mut lines = vec!["Your passkeys:".to_owned()];
                for (i, credential) in passkey.credentials.iter().enumerate() {
                    let times = passkey
                        .times
                        .get(&credential.id.0)
                        .copied()
                        .unwrap_or_default();
                    lines.push(format!(
                        "{}. `{}`, added {}, last used {}",
                        i + 1,
                        short_id(&credential.id.0),
                        day(times.added),
                        day(times.used)
                    ));
                }
                lines.join("\n")
            };
            c.enqueue(&private_notice(&self.rooms[room_id], &text));
            return Ok(Object::new());
        };
        let Some(credential) = n.checked_sub(1).and_then(|i| passkey.credentials.get(i)) else {
            let plural = if count == 1 { "" } else { "s" };
            return Err(invalid_params(format!(
                "You have {count} passkey{plural}; see /passkeys"
            )));
        };
        if count <= 1 {
            return Err(RpcError::new(
                CODE_DENIED,
                "You can't remove your only passkey",
            ));
        }
        let id = credential.id.0.clone();
        let passkey = self
            .users
            .get_mut(&user_id)
            .and_then(|u| u.passkey.as_mut())
            .expect("counted above");
        passkey.credentials.retain(|cred| cred.id.0 != id);
        passkey.times.remove(&id);
        self.credentials.remove(&id);
        self.touch_user(&user_id);
        for key in self.sorted_pushes(&user_id) {
            self.remove_push_locked(&key);
        }
        let text = format!("Removed the passkey `{}` from your account.", short_id(&id));
        self.send_to_others_locked(&user_id, c, &text);
        c.enqueue(&private_notice(&self.rooms[room_id], &text));
        Ok(Object::new())
    }
}
