//! Custom emoji (EXTENSIONS.md, `ext:emoji`): the catalog an admin keeps
//! with `/emoji add` and `/emoji remove`, published as JSON at a URL named
//! by its SHA-256, as apron-server-cloudflare keeps it.

use std::collections::BTreeMap;
use std::sync::Arc;

use rust_stdlib::encoding::hex;
use rust_stdlib::net::http::{self, Request as HttpRequest, ResponseWriter};
use rust_stdlib_crypto::sha256;
use rust_stdlib_derive::{MarshalTo, UnmarshalFrom};

use super::commands::private_notice;
use super::embeds::EmbedPurpose;
use super::emoji::is_emoji_key;
use super::metadata::one_upload;
use super::protocol::*;
use super::server::{Client, Server, State};
use super::toggles::{Feature, UPLOADS_OFF};
use crate::obj;

/// Where aprond serves catalogs: `/emoji/<SHA-256 of the JSON>.json`.
pub const CATALOG_PATH: &str = "/emoji/";
/// The longest name `/emoji add` takes, so a key stays well within a
/// reaction entry's 64 bytes.
pub const MAX_EMOJI_NAME_CHARS: usize = 32;
/// Cloudflare's maxEmoji and maxEmojiBytes.
pub const DEFAULT_MAX_EMOJI: usize = 500;
pub const DEFAULT_MAX_EMOJI_BYTES: i64 = 256 << 10;

/// One custom emoji: the upload holding its image, and the image's size.
#[derive(Clone, Debug, Default, PartialEq, Eq, MarshalTo, UnmarshalFrom)]
pub struct EmojiImage {
    #[json("embed")]
    pub embed: String,
    #[json("width,omitzero")]
    pub width: i64,
    #[json("height,omitzero")]
    pub height: i64,
}

/// A catalog as published: its JSON and the hex SHA-256 that names it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Published {
    pub json: Arc<Vec<u8>>,
    pub hash: String,
}

impl Published {
    fn of(json: Vec<u8>) -> Published {
        Published {
            hash: hex::encode(sha256::sum256(&json)),
            json: Arc::new(json),
        }
    }
}

/// The custom emoji catalog. The catalog a change replaced stays published,
/// with the images only it refers to, until the next change, so a client
/// that just read the old `catalog_url` can still fetch it.
#[derive(Debug, Default)]
pub struct EmojiCatalog {
    pub entries: BTreeMap<String, EmojiImage>,
    /// The current catalog, `None` while it is empty.
    pub current: Option<Published>,
    pub previous: Option<Published>,
    /// The images a change replaced or removed, which only `previous`
    /// refers to.
    pub superseded: Vec<String>,
}

/// The catalog as the store keeps it, as meta "emoji".
#[derive(Clone, Debug, Default, PartialEq, Eq, MarshalTo, UnmarshalFrom)]
pub struct StoredEmoji {
    #[json("entries,omitzero")]
    pub entries: BTreeMap<String, EmojiImage>,
    #[json("previous,omitzero")]
    pub previous: String,
    #[json("superseded,omitzero")]
    pub superseded: Vec<String>,
}

impl State {
    /// The catalog's JSON, an object that maps each key to its image's
    /// `url` and, where the write showed them, `width` and `height`.
    fn catalog_json(&self) -> Option<Vec<u8>> {
        let mut catalog = Object::new();
        for (key, image) in &self.emoji.entries {
            let Some(e) = self.embeds.get(&image.embed) else {
                continue;
            };
            let mut entry = obj! {"url" => e.file_url()};
            if image.width > 0 && image.height > 0 {
                entry.insert("width".into(), image.width.into());
                entry.insert("height".into(), image.height.into());
            }
            catalog.insert(key.clone(), entry.into());
        }
        (!catalog.is_empty()).then(|| encode_json(&catalog).expect("a catalog encodes"))
    }

    /// The `catalog_url` a connection is offered, while the catalog has an
    /// emoji.
    pub fn catalog_url(&self, base_url: &str) -> Option<String> {
        let current = self.emoji.current.as_ref()?;
        Some(format!("{base_url}{CATALOG_PATH}{}.json", current.hash))
    }

    /// Makes a change to the entries current: the catalog before it stays
    /// published, with the images it alone refers to (`replaced`), and the
    /// one before that goes, with its images. Every connection gets a new
    /// `server` frame with the new `catalog_url`.
    fn publish_emoji_locked(&mut self, replaced: Option<String>) {
        for id in std::mem::take(&mut self.emoji.superseded) {
            self.remove_embed_locked(&id);
        }
        self.emoji.superseded.extend(replaced);
        self.emoji.previous = self.emoji.current.take();
        self.emoji.current = self.catalog_json().map(Published::of);
        self.dirty.emoji = true;
        self.announce_server_locked();
    }

    /// Whether the catalog has room for `key`: it holds it already, or
    /// fewer than `Config.max_emoji`.
    pub fn emoji_fits(&self, key: &str) -> bool {
        self.emoji.entries.contains_key(key) || self.emoji.entries.len() < self.config.max_emoji
    }

    /// A finished `/emoji add` write that fits (emoji_fits): the image
    /// becomes the key's, replacing the one it had.
    pub fn add_emoji_locked(&mut self, key: &str, embed: &str, width: i64, height: i64) {
        let image = EmojiImage {
            embed: embed.to_owned(),
            width,
            height,
        };
        let replaced = self.emoji.entries.insert(key.to_owned(), image);
        self.publish_emoji_locked(replaced.map(|old| old.embed));
    }

    pub fn has_custom_emoji(&self, key: &str) -> bool {
        self.emoji.entries.contains_key(key)
    }

    /// `/emoji add :name:` with one `upload` embed, and `/emoji remove
    /// :name:`, for admins. An add's result carries the embed's write URL,
    /// and the image becomes the key's when the write finishes. A removal
    /// answers with a `~private` notice.
    pub(super) fn emoji_command(
        &mut self,
        c: &Arc<Client>,
        room_id: &str,
        body: &Object,
        args: &str,
    ) -> Result<Object, RpcError> {
        let words: Vec<&str> = args.split_whitespace().collect();
        let (action, key) = match words[..] {
            [action @ ("add" | "remove"), key] => (action, key),
            _ => {
                return Err(invalid_params(
                    "Usage: /emoji add :name: with one image attached, or /emoji remove :name:",
                ))
            }
        };
        if !is_emoji_key(key) || key.len() - 2 > MAX_EMOJI_NAME_CHARS {
            return Err(invalid_params(format!(
                "A custom emoji is written :name:, with a name of 1 to {MAX_EMOJI_NAME_CHARS} letters, digits, _, + or -"
            )));
        }
        if action == "remove" {
            let Some(image) = self.emoji.entries.remove(key) else {
                return Err(invalid_params(format!("{key} is not a custom emoji here")));
            };
            self.publish_emoji_locked(Some(image.embed));
            c.enqueue(&private_notice(
                &self.rooms[room_id],
                &format!("Removed the custom emoji `{key}`."),
            ));
            return Ok(Object::new());
        }
        let embeds = body.get("embeds").map(Json::as_list).unwrap_or(&[]);
        if !one_upload(embeds) {
            return Err(invalid_params(format!(
                "Attach one image to /emoji add {key} as an upload embed"
            )));
        }
        if !self.feature_on(Feature::Uploads) {
            return Err(RpcError::new(CODE_DENIED, UPLOADS_OFF));
        }
        let most = self.config.max_emoji;
        if !self.emoji_fits(key) {
            return Err(RpcError::new(
                CODE_DENIED,
                format!("This server keeps at most {most} custom emoji; remove one first"),
            ));
        }
        let user_id = self.client_user(c).unwrap_or_default();
        self.charge_uploads_locked(&user_id, 1)?;
        Ok(self.new_image_write_locked(c, EmbedPurpose::Emoji(key.to_owned())))
    }

    pub fn stored_emoji(&self) -> StoredEmoji {
        StoredEmoji {
            entries: self.emoji.entries.clone(),
            previous: self
                .emoji
                .previous
                .as_ref()
                .map(|p| String::from_utf8_lossy(&p.json).into_owned())
                .unwrap_or_default(),
            superseded: self.emoji.superseded.clone(),
        }
    }

    /// Restores the catalog, leaving out images whose upload is gone.
    pub fn restore_emoji(&mut self, stored: StoredEmoji) {
        self.emoji.entries = stored.entries;
        let embeds = &self.embeds;
        self.emoji
            .entries
            .retain(|_, image| embeds.contains_key(&image.embed));
        self.emoji.superseded = stored.superseded;
        self.emoji.superseded.retain(|id| embeds.contains_key(id));
        self.emoji.previous =
            (!stored.previous.is_empty()).then(|| Published::of(stored.previous.into_bytes()));
        self.emoji.current = self.catalog_json().map(Published::of);
    }
}

impl Server {
    /// Serves a published catalog, current or previous, readable from any
    /// origin. A catalog never changes under its URL.
    pub(crate) fn handle_catalog(&self, w: &mut dyn ResponseWriter, r: &mut HttpRequest) {
        w.header().set("Access-Control-Allow-Origin", "*");
        if r.method != http::METHOD_GET && r.method != http::METHOD_HEAD {
            http::http_error(w, "Read with GET", http::STATUS_METHOD_NOT_ALLOWED);
            return;
        }
        let hash = r
            .url
            .path
            .strip_prefix(CATALOG_PATH)
            .and_then(|name| name.strip_suffix(".json"))
            .unwrap_or("");
        let st = self.lock();
        let json = [&st.emoji.current, &st.emoji.previous]
            .into_iter()
            .flatten()
            .find(|p| p.hash == hash)
            .map(|p| p.json.clone());
        drop(st);
        let Some(json) = json else {
            http::not_found(w, r);
            return;
        };
        let header = w.header();
        header.set("Content-Type", "application/json");
        header.set("X-Content-Type-Options", "nosniff");
        header.set("Cache-Control", "public, max-age=31536000, immutable");
        header.set("Content-Length", &json.len().to_string());
        if r.method == http::METHOD_HEAD {
            return;
        }
        let _ = w.write_all(&json);
    }
}
