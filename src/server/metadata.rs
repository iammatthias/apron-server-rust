//! What the `server` frame shows people about this server (§3.1): its
//! `title`, `description` and `avatar`. An admin sets each with `/server`;
//! otherwise the `--server.*` flags apply, and for the description,
//! `general`'s. apron-server-cloudflare's `SERVER_*` variables and `/server`.

use std::sync::Arc;

use rust_stdlib::net::url;
use rust_stdlib_derive::{MarshalTo, UnmarshalFrom};

use super::commands::private_notice;
use super::embeds::EmbedPurpose;
use super::protocol::*;
use super::server::{Client, State, DEFAULT_ROOM_ID};
use super::toggles::{Feature, UPLOADS_OFF};
use super::users::MAX_NAME_RUNES;
use crate::obj;

/// The longest server description, in UTF-8 bytes: a few words, sent in
/// every `server` frame.
pub const MAX_SERVER_DESCRIPTION_BYTES: usize = 500;
/// The longest `--server.avatar`, in characters: an https URL, or a small
/// `data:` image.
const MAX_SERVER_AVATAR_CHARS: usize = 8192;

/// The server's title, description and avatar URL as `--server.*` sets
/// them; empty leaves one out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerMetadata {
    pub title: String,
    pub description: String,
    pub avatar: String,
}

/// What admins set with `/server`, kept in the store as meta "server";
/// empty while the flag applies.
#[derive(Clone, Debug, Default, PartialEq, Eq, MarshalTo, UnmarshalFrom)]
pub struct StoredServer {
    #[json("title,omitzero")]
    pub title: String,
    #[json("description,omitzero")]
    pub description: String,
    /// The upload holding the avatar `/server avatar` set.
    #[json("avatar_embed,omitzero")]
    pub avatar_embed: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ServerField {
    Title,
    Description,
    Avatar,
}

impl ServerField {
    const ALL: [ServerField; 3] = [
        ServerField::Title,
        ServerField::Description,
        ServerField::Avatar,
    ];

    fn name(self) -> &'static str {
        match self {
            ServerField::Title => "title",
            ServerField::Description => "description",
            ServerField::Avatar => "avatar",
        }
    }
}

/// Where a shown field comes from.
enum Source {
    Command,
    Flag,
    General,
}

/// Whether a server `title`, trimmed, is a plain name: one line, within
/// the display-name length.
pub fn valid_server_title(title: &str) -> bool {
    !title.chars().any(|c| c.is_ascii_control()) && title.chars().count() <= MAX_NAME_RUNES
}

/// Whether a server `description`, trimmed, is short CommonMark: text
/// whose only control character is a line feed, within
/// MAX_SERVER_DESCRIPTION_BYTES.
pub fn valid_server_description(description: &str) -> bool {
    !description
        .chars()
        .any(|c| c.is_ascii_control() && c != '\n')
        && description.len() <= MAX_SERVER_DESCRIPTION_BYTES
}

/// Whether `--server.avatar` is an `https:` URL or a small
/// `data:image/{png,jpeg,gif,webp};base64,` URL (§4.8.6).
pub fn valid_server_avatar(avatar: &str) -> bool {
    if avatar.chars().count() > MAX_SERVER_AVATAR_CHARS {
        return false;
    }
    if let Some(rest) = avatar.strip_prefix("data:image/") {
        let data = ["png", "jpeg", "gif", "webp"]
            .iter()
            .find_map(|t| rest.strip_prefix(t)?.strip_prefix(";base64,"));
        return data.is_some_and(|data| {
            let digits = data.trim_end_matches('=');
            !digits.is_empty()
                && data.len() - digits.len() <= 2
                && digits
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        });
    }
    url::parse(avatar).is_ok_and(|u| u.scheme == "https" && !u.host.is_empty())
}

/// Escapes a plain name for a CommonMark notice, so it shows as written.
fn plain(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if "\\`*_{}[]()#+-.!|<>~&".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

impl State {
    pub fn touch_server(&mut self) {
        self.dirty.server = true;
    }

    /// One field as an admin set it with `/server`.
    fn stored_server_field(&self, field: ServerField) -> Option<String> {
        let value = match field {
            ServerField::Title => self.server_meta.title.clone(),
            ServerField::Description => self.server_meta.description.clone(),
            ServerField::Avatar => self
                .embeds
                .get(&self.server_meta.avatar_embed)
                .filter(|e| e.finished)
                .map(|e| e.file_url())
                .unwrap_or_default(),
        };
        (!value.is_empty()).then_some(value)
    }

    fn flag_server_field(&self, field: ServerField) -> Option<String> {
        let configured = &self.config.server;
        let value = match field {
            ServerField::Title => &configured.title,
            ServerField::Description => &configured.description,
            ServerField::Avatar => &configured.avatar,
        };
        (!value.is_empty()).then(|| value.clone())
    }

    /// `general`'s description, trimmed, when it is one a server
    /// description may be; left out rather than cut, since cut CommonMark
    /// can end mid-markup.
    fn general_server_description(&self) -> Option<String> {
        let description = self
            .rooms
            .get(DEFAULT_ROOM_ID)?
            .record
            .get("description")?
            .as_str()?
            .trim();
        (!description.is_empty() && valid_server_description(description))
            .then(|| description.to_owned())
    }

    fn shown_server_field(&self, field: ServerField) -> Option<(String, Source)> {
        if let Some(value) = self.stored_server_field(field) {
            return Some((value, Source::Command));
        }
        if let Some(value) = self.flag_server_field(field) {
            return Some((value, Source::Flag));
        }
        if field == ServerField::Description {
            return self
                .general_server_description()
                .map(|value| (value, Source::General));
        }
        None
    }

    /// The server's description as the `server` frame carries it.
    pub fn server_description(&self) -> Option<String> {
        self.shown_server_field(ServerField::Description)
            .map(|(value, _)| value)
    }

    /// Adds the server's `title`, `description` and `avatar` (§3.1) to a
    /// `server` frame's params.
    pub fn insert_server_metadata(&self, params: &mut Object) {
        for field in ServerField::ALL {
            if let Some((value, _)) = self.shown_server_field(field) {
                params.insert(field.name().into(), value.into());
            }
        }
    }

    /// Sends every connection a new `server` frame, which fully replaces
    /// the one it had (§3.1).
    pub fn announce_server_locked(&mut self) {
        let clients: Vec<_> = self
            .clients
            .values()
            .map(|conn| conn.client.clone())
            .collect();
        for client in clients {
            self.send_server_locked(&client);
        }
    }

    /// Sends a connection its `server` frame, noting whether it listed
    /// wake scope `joined`.
    pub fn send_server_locked(&mut self, client: &Client) {
        let joined = self.connection_wakes_joined(client);
        client.enqueue(&obj! {"method" => "server", "params" => self.server_params(client)});
        if let Some(conn) = self.clients.get_mut(&client.id) {
            conn.wake_joined = joined;
        }
    }

    /// After a sign-in or a role change: a new `server` frame for a
    /// connection whose wake scopes changed, so its clients offer `joined`
    /// exactly while it works. Other connections get nothing.
    pub fn sync_server_locked(&mut self, client: &Client) {
        let told = self.clients.get(&client.id).map(|conn| conn.wake_joined);
        if told.is_some_and(|told| told != self.connection_wakes_joined(client)) {
            self.send_server_locked(client);
        }
    }

    /// Whether a connection's `server` frame lists wake scope `joined`.
    pub fn connection_wakes_joined(&self, client: &Client) -> bool {
        !self.config.disable_push
            && self
                .clients
                .get(&client.id)
                .and_then(|conn| conn.user.as_deref())
                .is_some_and(|user_id| self.wakes_joined(user_id))
    }

    /// Makes an uploaded image the server's avatar, or with `None` clears
    /// it, deleting the image it replaces, and announces the change.
    pub fn set_server_avatar_locked(&mut self, embed: Option<String>) {
        let old = std::mem::take(&mut self.server_meta.avatar_embed);
        if !old.is_empty() && Some(&old) != embed.as_ref() {
            self.remove_embed_locked(&old);
        }
        self.server_meta.avatar_embed = embed.unwrap_or_default();
        self.touch_server();
        self.announce_server_locked();
    }

    /// `/server`, for admins: alone, a `~private` notice showing the
    /// server's `title`, `description` and `avatar` and where each comes
    /// from. `/server title <text>` and `/server description <text>` set
    /// one, with the rules of their flags; without the text they clear it,
    /// so the flag applies again. `/server avatar` with one `upload` embed
    /// answers with its write URL, and the image becomes the avatar when the
    /// write finishes; alone, it clears the avatar and deletes its image. A
    /// change sends every connection a new `server` frame.
    pub(super) fn server_command(
        &mut self,
        c: &Arc<Client>,
        room_id: &str,
        body: &Object,
        args: &str,
    ) -> Result<Object, RpcError> {
        let (field, rest) = args.split_once(char::is_whitespace).unwrap_or((args, ""));
        let value = rest.trim();
        let field = field.to_lowercase();
        let embeds = body.get("embeds").map(Json::as_list).unwrap_or(&[]);
        if field != "avatar" && !embeds.is_empty() {
            return Err(invalid_params("Only /server avatar takes an attachment"));
        }
        let field = match field.as_str() {
            "" => {
                c.enqueue(&private_notice(
                    &self.rooms[room_id],
                    &self.server_overview(),
                ));
                return Ok(Object::new());
            }
            "avatar" => return self.server_avatar_command(c, room_id, embeds, value),
            "title" => ServerField::Title,
            "description" => ServerField::Description,
            _ => {
                return Err(invalid_params(
                    "Usage: /server, /server title|description [<text>], or /server avatar",
                ))
            }
        };
        if field == ServerField::Title && !valid_server_title(value) {
            return Err(invalid_params(format!(
                "A server title is one line of at most {MAX_NAME_RUNES} characters"
            )));
        }
        if field == ServerField::Description && !valid_server_description(value) {
            return Err(invalid_params(format!(
                "A server description is CommonMark of at most {MAX_SERVER_DESCRIPTION_BYTES} bytes"
            )));
        }
        let name = field.name();
        let stored = match field {
            ServerField::Title => &mut self.server_meta.title,
            _ => &mut self.server_meta.description,
        };
        let before = std::mem::replace(stored, value.to_owned());
        if before != value {
            self.touch_server();
            self.announce_server_locked();
        }
        let done = if !value.is_empty() {
            format!("Set the server's {name}.")
        } else if !before.is_empty() {
            format!("Cleared the server's {name}.")
        } else {
            format!("The server's {name} was not set with `/server {name}`.")
        };
        let text = format!("{done}\n\n{}", self.server_overview());
        c.enqueue(&private_notice(&self.rooms[room_id], &text));
        Ok(Object::new())
    }

    fn server_avatar_command(
        &mut self,
        c: &Arc<Client>,
        room_id: &str,
        embeds: &[Json],
        value: &str,
    ) -> Result<Object, RpcError> {
        if !value.is_empty() {
            return Err(invalid_params(
                "Usage: /server avatar with one image attached, or alone to clear it",
            ));
        }
        if embeds.is_empty() {
            let cleared = !self.server_meta.avatar_embed.is_empty();
            if cleared {
                self.set_server_avatar_locked(None);
            }
            let done = if cleared {
                "Cleared the server's avatar."
            } else {
                "The server's avatar was not set with `/server avatar`."
            };
            let text = format!("{done}\n\n{}", self.server_overview());
            c.enqueue(&private_notice(&self.rooms[room_id], &text));
            return Ok(Object::new());
        }
        if !one_upload(embeds) {
            return Err(invalid_params(
                "Attach one image to /server avatar as an upload embed",
            ));
        }
        if !self.feature_on(Feature::Uploads) {
            return Err(RpcError::new(CODE_DENIED, UPLOADS_OFF));
        }
        let user_id = self.client_user(c).unwrap_or_default();
        self.charge_post_locked(c, &user_id)?;
        Ok(self.new_image_write_locked(c, EmbedPurpose::ServerAvatar))
    }

    /// The server's `title`, `description` and `avatar` for `/server`, each
    /// with where it comes from.
    fn server_overview(&self) -> String {
        let mut lines =
            vec!["This server's title, description and avatar, as clients show it:".to_owned()];
        for field in ServerField::ALL {
            let name = field.name();
            let Some((value, source)) = self.shown_server_field(field) else {
                let why = match field {
                    ServerField::Title => " (clients show the server's address)".to_owned(),
                    ServerField::Description if self.general_has_description() => format!(
                        " (`{DEFAULT_ROOM_ID}`'s description is longer than {MAX_SERVER_DESCRIPTION_BYTES} bytes or holds control characters, so it is left out)"
                    ),
                    _ => String::new(),
                };
                lines.push(format!("- **{name}**: none{why}"));
                continue;
            };
            let source = match source {
                Source::Command => format!("set with `/server {name}`"),
                Source::Flag => format!("from `--server.{name}`"),
                Source::General => {
                    format!("from the default room `{DEFAULT_ROOM_ID}`'s description")
                }
            };
            let shown = match field {
                // CommonMark, quoted in the list item as clients show it.
                ServerField::Description => value
                    .split('\n')
                    .map(|line| format!("\n  > {line}"))
                    .collect(),
                ServerField::Avatar if value.starts_with("data:") => {
                    format!(" a `data:` image of {} characters", value.chars().count())
                }
                ServerField::Avatar => format!(" <{value}>"),
                ServerField::Title => format!(" {}", plain(&value)),
            };
            lines.push(format!("- **{name}** ({source}):{shown}"));
        }
        lines.join("\n")
    }

    fn general_has_description(&self) -> bool {
        self.rooms
            .get(DEFAULT_ROOM_ID)
            .and_then(|r| r.record.get("description"))
            .and_then(Json::as_str)
            .is_some_and(|d| !d.trim().is_empty())
    }

    /// Registers an image upload kept apart from any message, the server's
    /// avatar or a custom emoji's, and returns the command result that
    /// carries its write URL.
    pub(super) fn new_image_write_locked(
        &mut self,
        c: &Arc<Client>,
        purpose: EmbedPurpose,
    ) -> Object {
        let id = self.next_embed_id();
        self.new_write_locked(c, &id, "upload", "");
        let e = self.embeds.get_mut(&id).expect("just registered");
        e.purpose = purpose;
        obj! {
            "embeds" => vec![Json::from(obj! {"embed_id" => id.as_str(), "kind" => "upload", "write_url" => e.write_url()})],
        }
    }
}

/// Whether a command's embeds are exactly one `upload` embed.
pub(super) fn one_upload(embeds: &[Json]) -> bool {
    embeds.len() == 1
        && embeds[0]
            .as_object()
            .and_then(|e| e.get("kind"))
            .and_then(Json::as_str)
            == Some("upload")
}
