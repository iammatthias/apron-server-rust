//! The server frame (§3.1) and the welcome notice a connection gets.

use rust_stdlib::time::{self};

use super::client::Client;
use super::commands::{PRIVATE_NOTICE_ID, PRIVATE_NOTICE_NAME};
use super::media_types::AVATAR_TYPES;
use super::protocol::*;
use super::server::{State, DEFAULT_ROOM_ID};
use super::status::optional_statuses;
use super::toggles::Feature;
use crate::obj;

impl State {
    /// Whether `origin` is offered passkeys: it is configured for them, as
    /// apron-server-cloudflare offers them only there.
    pub fn passkeys_offered(&self, origin: &str) -> bool {
        self.config.web_authn.as_ref().is_some_and(|w| {
            crate::webauthn::protocol::is_origin_in_haystack(origin, &w.config.rp_origins)
        })
    }

    /// The `server` frame's params (§3.1) for a connection.
    pub fn server_params(&self, client: &Client) -> Object {
        let origin = client.origin.as_str();
        // signup (§3.2) lists the schemes that can create an account: a
        // token does as an admin's sign-up invite (`/invite-code`); a guest is no
        // account.
        let mut schemes: Vec<String> = Vec::new();
        if self.passkeys_offered(origin) {
            schemes.push("webauthn".into());
        }
        if self.config.email_sender.is_some() {
            schemes.push("email".into());
        }
        schemes.push("token".into());
        let signup = schemes.clone();
        // Bot, device and account tokens sign in from anywhere, so token is
        // always offered.
        let mut auth_schemes = schemes;
        auth_schemes.push("guest".into());
        let (activity, uploads) = (
            self.feature_on(Feature::Activity),
            self.feature_on(Feature::Uploads),
        );
        // A connection is offered what is on as it connects, and keeps it.
        let mut capabilities: Vec<String> = [
            ("history", true),
            ("edit", true),
            ("rooms", true),
            ("reactions", true),
            ("activity", activity),
            ("embed:upload", uploads),
            ("embed:stream", true),
            ("command", true),
            ("status", true),
            ("ext", true),
        ]
        .iter()
        .filter(|(_, on)| *on)
        .map(|(s, _)| s.to_string())
        .collect();
        let mut params = obj! {
            "apron" => 9i64,
            "agent" => "apron-rust/9",
            "auth" => auth_schemes.clone(),
            "ping" => (self.config.ping_interval.as_nanos() / time::SECOND.as_nanos()).max(1),
        };
        // The optional statuses accepted with `me` (§4.5), only while others
        // are shown them; online and "" always are, and are not listed.
        if self.feature_on(Feature::Presence) {
            params.insert("status".into(), optional_statuses().into());
        }
        if !self.config.disable_push {
            let joined = self.connection_wakes_joined(client);
            params.insert(
                "push".into(),
                super::push::server_push_params(self, joined).into(),
            );
        }
        params.insert("welcome".into(), self.welcome(origin).into());
        self.insert_server_metadata(&mut params);
        // ext:settings (EXTENSIONS.md): read cursors are kept with activity.
        // private_rooms is left out when unlimited, as an absent key says.
        // What each user may do is in `you` (ext:permissions).
        let mut settings = obj! {"read_cursors" => activity};
        if self.config.max_private_rooms > 0 {
            settings.insert("private_rooms".into(), self.config.max_private_rooms.into());
        }
        // ext:media (EXTENSIONS.md): uploads are served from this server's
        // own origin, an attachment may be one of Config.upload_types and
        // an avatar one of the image types /avatar keeps, each up to its
        // configured size.
        let sized = |max_bytes: i64| Json::from(obj! {"max_bytes" => max_bytes});
        let avatar: Object = AVATAR_TYPES
            .iter()
            .map(|t| (t.to_string(), sized(self.config.max_avatar_bytes)))
            .collect();
        let mut media = Object::new();
        if uploads {
            let upload: Object = self
                .config
                .upload_types
                .iter()
                .map(|t| (t.clone(), sized(self.config.max_upload_bytes)))
                .collect();
            media.insert("upload".into(), upload.into());
            media.insert("avatar".into(), avatar.into());
            let emoji: Object = AVATAR_TYPES
                .iter()
                .map(|t| (t.to_string(), sized(self.config.max_emoji_bytes)))
                .collect();
            media.insert("emoji".into(), emoji.into());
        }
        capabilities.extend([
            "ext:settings".into(),
            "ext:media".into(),
            "ext:permissions".into(),
            "ext:limits".into(),
        ]);
        let mut ext = obj! {"settings" => settings, "media" => media};
        // ext:emoji, once an admin has added a custom emoji.
        if let Some(url) = self.catalog_url(&client.base_url) {
            capabilities.push("ext:emoji".into());
            ext.insert("emoji".into(), obj! {"catalog_url" => url}.into());
        }
        params.insert("ext".into(), ext.into());
        params.insert("capabilities".into(), capabilities.into());
        params.insert("signup".into(), signup.into());
        params
    }

    /// `server.welcome` (§3.2): `--welcome` when set, else `general`'s
    /// description, which its members edit, as apron-server-cloudflare
    /// shows, else a summary of how guests and sign-in fit together here.
    fn welcome(&self, origin: &str) -> String {
        if !self.config.welcome.is_empty() {
            return self.config.welcome.clone();
        }
        let general = self.rooms.get(DEFAULT_ROOM_ID);
        match general
            .and_then(|r| r.record.get("description"))
            .and_then(Json::as_str)
        {
            Some(description) if !description.is_empty() => description.to_owned(),
            _ => self.sign_in_summary(origin),
        }
    }

    fn sign_in_summary(&self, origin: &str) -> String {
        let mut parts = vec![if self.config.guest_posting {
            "Guests can post under a new name each visit."
        } else {
            "Guests can read along."
        }
        .to_owned()];
        let passkeys = self.passkeys_offered(origin);
        let email = self.config.email_sender.is_some();
        if passkeys {
            parts.push(
                "**Create a passkey** to post, react, and start threads; it signs you in on your next visit too."
                    .into(),
            );
        } else if self.config.web_authn.is_some() {
            parts.push("Passkeys work on this server's own site.".into());
        }
        if email {
            parts.push(
                if passkeys {
                    "You can also sign in with an email address."
                } else {
                    "**Sign in with email** to post, react, and start threads."
                }
                .into(),
            );
        }
        if self.config.web_authn.is_some() || email {
            parts.push("Bots sign in with a token their owner gets from `/invite-bot`.".into());
        }
        if let Some(retention) = self.config.retention {
            let days = (retention.hours() / 24.0).round().max(1.0) as u64;
            parts.push(if days == 1 {
                "Messages are kept for a day.".into()
            } else {
                format!("Messages are kept for {days} days.")
            });
        }
        parts.join(" ")
    }

    /// The `~private` welcome a connection gets right after the `server`
    /// frame, before any auth (§3.5, Appendix B): with no room_id, since the
    /// client knows no rooms yet, and the server version. Where guests only
    /// read, it says how to participate.
    pub fn welcome_notice(&self, origin: &str) -> Object {
        let mut lines = vec![format!(
            "Welcome to Apron Chat. Server version: `{}`",
            env!("CARGO_PKG_VERSION")
        )];
        if !self.config.guest_posting {
            lines.push(
                if self.passkeys_offered(origin) {
                    "Guests can read. *Sign in with passkey* to participate."
                } else if self.config.email_sender.is_some() {
                    "Guests can read. *Sign in with email* to participate."
                } else {
                    "Guests can read."
                }
                .into(),
            );
        }
        obj! {"method" => "message", "params" => obj! {
            "from" => obj! {"user_id" => PRIVATE_NOTICE_ID, "name" => PRIVATE_NOTICE_NAME},
            "body" => obj! {"text" => lines.join("\n\n"), "format" => "markdown"},
        }}
    }
}
