//! Embeds (§4.8): uploads and streams the server hosts, their write URLs,
//! and the /write/, /files/, and /streams/ endpoints.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rust_stdlib::os::{self};
use rust_stdlib::path;
use rust_stdlib::time::{self, Duration, Timer};
use rust_stdlib_crypto::{rand, subtle};

use super::client::Client;
use super::protocol::*;
use super::server::State;
use super::streams::StreamBuffer;
use super::toggles::{Feature, UPLOADS_OFF};
use super::unfurl::Preview;
use crate::obj;

/// HTTP paths for embed content (§4.8.3, §4.8.5). Write URLs carry a
/// one-time token; file and stream URLs carry the embed_id and an
/// unguessable secret, since HTTP requests are not authenticated.
pub const WRITE_PATH: &str = "/write/";
pub const FILE_PATH: &str = "/files/";
pub const STREAM_PATH: &str = "/streams/";

/// Bounds body.embeds.
pub const MAX_EMBEDS_PER_MESSAGE: usize = 32;

/// Bounds how long one upload body may take to arrive.
pub const UPLOAD_READ_TIMEOUT: Duration = Duration::from_mins(15);

pub const LINK_KIND: &str = "link";

/// Names upload files, so stale ones can be told apart from anything else in
/// the directory.
pub const UPLOAD_SUFFIX: &str = ".upload";

/// What a hosted upload is for. It decides the upload's size limit and
/// types, whether eviction and retention may remove it, and how long
/// clients may cache it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum EmbedPurpose {
    /// An embed of `EmbedState.message_id`.
    #[default]
    Message,
    /// The `/avatar` of this user (§4.8.6).
    Avatar(String),
    /// The server's avatar, from `/server avatar` (§3.1).
    ServerAvatar,
    /// The image of this custom emoji key, from `/emoji add` (ext:emoji).
    Emoji(String),
}

impl EmbedPurpose {
    /// Whether the upload is an image the server keeps apart from any
    /// message: one of AVATAR_TYPES, never evicted or expired.
    pub fn image(&self) -> bool {
        *self != EmbedPurpose::Message
    }

    /// Whether the server keeps the upload's file URL for good, so clients
    /// may cache it as long as they like.
    pub(super) fn immutable(&self) -> bool {
        matches!(self, EmbedPurpose::ServerAvatar | EmbedPurpose::Emoji(_))
    }
}

/// A server-hosted embed: an upload, a stream, or a link preview
/// (`unfurl`). Other embed kinds are body content with only an embed_id.
/// An embed that is no longer in `State.embeds` was removed; its write,
/// file, and stream URLs are dead.
#[derive(Debug, Default)]
pub struct EmbedState {
    pub id: String,
    pub kind: String,
    /// The message the embed belongs to, for `EmbedPurpose::Message`.
    pub message_id: String,
    pub purpose: EmbedPurpose,
    /// The user who asked for an image write (`/avatar`, `/emoji`,
    /// `/server`), in memory only: a custom emoji needs them to hold an
    /// EMOJI_ROLES role still when the write finishes.
    pub uploader: String,
    pub base_url: String,
    pub secret: String,
    pub token: String,
    pub title: String,
    /// The sender's og.image.alt, kept in the server's og.
    pub alt: String,
    /// Expires an unused write URL, then bounds a stream's duration.
    pub timer: Option<Timer>,
    pub started: bool,
    pub finished: bool,
    /// The server fields restored on every save: an upload's url and og, a
    /// live stream's url, a finished stream's text.
    pub owned: Object,
    /// The file holding a finished upload's content, `size` its length, and
    /// `seq` its place in `State.uploads`, oldest first.
    pub path: String,
    pub size: i64,
    pub seq: i64,
    pub content_type: String,
    pub stream: Option<Arc<StreamBuffer>>,
}

impl EmbedState {
    /// A link preview, whose image is hosted like an upload.
    pub fn is_link(&self) -> bool {
        self.kind == LINK_KIND
    }

    pub fn end_stream(&self) {
        if let Some(stream) = &self.stream {
            stream.end();
        }
    }

    pub fn file_url(&self) -> String {
        format!("{}{FILE_PATH}{}/{}", self.base_url, self.id, self.secret)
    }

    pub fn stream_url(&self) -> String {
        format!("{}{STREAM_PATH}{}/{}", self.base_url, self.id, self.secret)
    }

    pub fn write_url(&self) -> String {
        format!("{}{WRITE_PATH}{}", self.base_url, self.token)
    }
}

fn embed_list(value: Option<&Json>) -> &[Json] {
    value.map(Json::as_list).unwrap_or(&[])
}

fn embed_id(embed: &Json) -> Option<&str> {
    embed.as_object()?.get("embed_id")?.as_str()
}

fn og_image_alt(og: Option<&Json>) -> String {
    og.and_then(Json::as_object)
        .and_then(|og| og.get("image"))
        .and_then(Json::as_object)
        .and_then(|image| image.get("alt"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

/// The fields of a sender's `og` this server keeps, as single lines of at
/// most this many code points (apron-server-cloudflare's OG_TEXT_FIELDS).
const OG_TEXT_FIELDS: [(&str, usize); 3] =
    [("title", 256), ("description", 512), ("site_name", 128)];

/// Reduces a sender's `og` to its text fields, each one plain line, so a
/// client never loads media a sender named; drops `og` when nothing is
/// left. The server's own og, of a link preview or upload, replaces it.
fn clean_og(embed: &mut Object) {
    let Some(og) = embed.remove("og") else {
        return;
    };
    let Some(og) = og.as_object() else {
        return;
    };
    let mut clean = Object::new();
    for (field, max) in OG_TEXT_FIELDS {
        if let Some(line) = og
            .get(field)
            .and_then(Json::as_str)
            .and_then(|v| og_line(v, max))
        {
            clean.insert(field.into(), line.into());
        }
    }
    if !clean.is_empty() {
        embed.insert("og".into(), clean.into());
    }
}

/// `value` as one line: controls and bidirectional overrides become spaces,
/// runs of whitespace one space, trimmed, and cut to `max` code points with
/// an ellipsis; `None` when nothing is left.
fn og_line(value: &str, max: usize) -> Option<String> {
    let unsafe_char = |c: char| {
        c.is_control()
            || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    };
    let spaced: String = value
        .chars()
        .map(|c| if unsafe_char(c) { ' ' } else { c })
        .collect();
    let line = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.is_empty() {
        return None;
    }
    if line.chars().count() <= max {
        return Some(line);
    }
    let cut: String = line.chars().take(max - 1).collect();
    Some(format!("{}…", cut.trim_end()))
}

/// Drops an embed's `og.image`, and its `og` when nothing else is left.
fn without_image(embed: &mut Object) {
    let Some(og) = embed.get_mut("og").and_then(Json::as_object_mut) else {
        return;
    };
    og.remove("image");
    if og.is_empty() {
        embed.remove("og");
    }
}

/// Swaps one embed in a body for `update`, or removes it when `update` is
/// `None`. Reports whether the embed was present.
pub fn replace_embed(body: &mut Object, id: &str, update: Option<&dyn Fn(&mut Object)>) -> bool {
    let Some(Json::Array(embeds)) = body.get_mut("embeds") else {
        return false;
    };
    let Some(i) = embeds.iter().position(|e| embed_id(e) == Some(id)) else {
        return false;
    };
    match update {
        None => {
            embeds.remove(i);
            if embeds.is_empty() {
                body.remove("embeds");
            }
        }
        Some(update) => {
            if let Some(embed) = embeds[i].as_object_mut() {
                update(embed);
            }
        }
    }
    true
}

impl State {
    pub fn next_embed_id(&mut self) -> String {
        self.embed_number += 1;
        format!("embed_{}", self.embed_number)
    }

    /// Records `path`, of `size` bytes, as the finished file of hosted embed
    /// `id`, newest in the eviction order, and returns its file URL.
    pub fn host_file_locked(&mut self, id: &str, path: String, size: i64) -> String {
        self.upload_seq += 1;
        let seq = self.upload_seq;
        let e = self.embeds.get_mut(id).expect("a registered embed");
        e.finished = true;
        e.path = path;
        e.size = size;
        e.seq = seq;
        let url = e.file_url();
        self.uploads.insert((seq, id.to_owned()));
        self.upload_bytes += size;
        self.touch_embed(id);
        url
    }

    /// Registers a link preview of `url` as a hosted embed of a message,
    /// with `file` holding the preview's image, and returns the embed to
    /// append to the message's body.
    pub fn add_link_embed_locked(
        &mut self,
        message_id: &str,
        base_url: &str,
        url: &str,
        preview: &Preview,
        file: Option<String>,
    ) -> Object {
        let id = self.next_embed_id();
        self.embeds.insert(
            id.clone(),
            EmbedState {
                id: id.clone(),
                kind: LINK_KIND.into(),
                message_id: message_id.to_owned(),
                base_url: base_url.to_owned(),
                secret: rand::text(),
                started: true,
                finished: true,
                ..EmbedState::default()
            },
        );
        let image_url = match (file, &preview.image) {
            (Some(path), Some(image)) => {
                let e = self.embeds.get_mut(&id).expect("just registered");
                e.content_type = image.content_type.clone();
                Some(self.host_file_locked(&id, path, image.bytes.len() as i64))
            }
            _ => None,
        };
        let owned = obj! {"url" => url, "og" => preview.og(image_url.as_deref())};
        self.embeds.get_mut(&id).expect("just registered").owned = owned.clone();
        self.touch_embed(&id);
        let mut embed = obj! {"embed_id" => id.as_str(), "kind" => LINK_KIND};
        embed.extend(owned);
        embed
    }

    /// Applies embed identity (§4.8.2) to a submitted body. An embed with
    /// embed_id keeps that embed of the current snapshot, with its kind and
    /// server-owned fields restored from the server's records; one without
    /// is new and gets an embed_id, and a new upload or stream embed gets a
    /// write URL, listed in the second result. Senders' og is dropped: the
    /// server only describes media it hosts.
    pub fn resolve_embeds_locked(
        &mut self,
        c: &Arc<Client>,
        message_id: &str,
        current: Option<&Object>,
        body: &mut Object,
    ) -> Result<(Vec<Json>, Vec<Json>), RpcError> {
        let submitted: Vec<Json> = embed_list(body.get("embeds")).to_vec();
        let mut previous: BTreeMap<String, Object> = BTreeMap::new();
        if let Some(current_body) = current
            .and_then(|c| c.get("body"))
            .and_then(Json::as_object)
        {
            for value in embed_list(current_body.get("embeds")) {
                if let (Some(embed), Some(id)) = (value.as_object(), embed_id(value)) {
                    previous.insert(id.to_owned(), embed.clone());
                }
            }
        }
        let mut kept = BTreeSet::new();
        for (i, value) in submitted.iter().enumerate() {
            let Some(raw) = value.as_object().and_then(|e| e.get("embed_id")) else {
                continue;
            };
            let id = raw.as_str().unwrap_or("");
            if !previous.contains_key(id) || !kept.insert(id.to_owned()) {
                let shown = encode_json(raw)
                    .map(|v| String::from_utf8_lossy(&v).into_owned())
                    .unwrap_or_default();
                return Err(invalid_params(format!(
                    "body.embeds[{i}]: unknown embed_id {shown}"
                )));
            }
        }

        let new_uploads = submitted
            .iter()
            .filter(|value| {
                embed_id(value).is_none()
                    && value
                        .as_object()
                        .and_then(|e| e.get("kind"))
                        .and_then(Json::as_str)
                        == Some("upload")
            })
            .count();
        if new_uploads > 0 {
            if !self.feature_on(Feature::Uploads) {
                return Err(RpcError::new(CODE_DENIED, UPLOADS_OFF));
            }
            let user_id = self.client_user(c).unwrap_or_default();
            self.charge_uploads_locked(&user_id, new_uploads as u32)?;
        }
        let mut embeds: Vec<Json> = Vec::with_capacity(submitted.len());
        let mut written: Vec<Json> = Vec::new();
        for value in submitted {
            let mut embed = value.as_object().cloned().unwrap_or_default();
            if let Some(id) = embed_id(&value).map(str::to_owned) {
                if let Some(kind) = previous[&id].get("kind").cloned() {
                    embed.insert("kind".into(), kind);
                }
                clean_og(&mut embed);
                embed.remove("write_url");
                if let Some(e) = self.embeds.get(&id) {
                    embed.remove("url");
                    embed.remove("text");
                    embed.extend(e.owned.clone());
                }
                embeds.push(embed.into());
                continue;
            }
            let kind = embed
                .get("kind")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned();
            let id = self.next_embed_id();
            let alt = og_image_alt(embed.get("og"));
            clean_og(&mut embed);
            embed.remove("write_url");
            embed.insert("embed_id".into(), id.as_str().into());
            if kind == "upload" || kind == "stream" {
                embed.remove("url");
                embed.remove("text");
                let title = embed
                    .get("title")
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .to_owned();
                self.new_write_locked(c, &id, &kind, message_id);
                let e = self.embeds.get_mut(&id).expect("just registered");
                e.alt = alt;
                e.title = title;
                if kind == "stream" {
                    e.stream = Some(Arc::new(StreamBuffer::new(
                        self.config.stream_keep_bytes,
                        self.config.stream_max_bytes,
                    )));
                    let url = e.stream_url();
                    e.owned = obj! {"url" => url.as_str()};
                    embed.insert("url".into(), url.into());
                }
                written.push(
                    obj! {"embed_id" => id.as_str(), "kind" => kind.as_str(), "write_url" => e.write_url()}
                        .into(),
                );
            }
            embeds.push(embed.into());
        }
        Ok((embeds, written))
    }

    /// Registers a hosted embed awaiting its write. An unused write URL
    /// expires, and the embed is dropped.
    pub fn new_write_locked(&mut self, c: &Arc<Client>, id: &str, kind: &str, message_id: &str) {
        let token = rand::text();
        let server = self.server.clone();
        let expired = id.to_owned();
        let timer = time::after_func(self.config.upload_start_timeout, move || {
            let Some(server) = server.upgrade() else {
                return;
            };
            let mut st = server.lock();
            if st.embeds.get(&expired).is_some_and(|e| !e.started) {
                st.fail_write_locked(&expired);
            }
        });
        self.embeds.insert(
            id.to_owned(),
            EmbedState {
                id: id.to_owned(),
                kind: kind.to_owned(),
                message_id: message_id.to_owned(),
                base_url: c.base_url.clone(),
                secret: rand::text(),
                token: token.clone(),
                timer: Some(timer),
                ..EmbedState::default()
            },
        );
        self.touch_embed(id);
        self.writes.insert(token, id.to_owned());
    }

    /// Deletes the hosted content of embeds a save removed from the current
    /// snapshot (§4.8.2); a `None` body, as for a tombstone, removes every
    /// embed.
    pub fn release_embeds_locked(&mut self, current: Option<&Object>, body: Option<&Object>) {
        let Some(current) = current else {
            return;
        };
        let remaining: BTreeSet<&str> = body
            .map(|b| embed_list(b.get("embeds")))
            .unwrap_or(&[])
            .iter()
            .filter_map(embed_id)
            .collect();
        let removed: Vec<String> = current
            .get("body")
            .and_then(Json::as_object)
            .map(|b| embed_list(b.get("embeds")))
            .unwrap_or(&[])
            .iter()
            .filter_map(embed_id)
            .filter(|id| !remaining.contains(id))
            .map(str::to_owned)
            .collect();
        for id in removed {
            self.remove_embed_locked(&id);
        }
    }

    /// Forgets a hosted embed and its content, invalidating its write, file,
    /// and stream URLs.
    pub fn remove_embed_locked(&mut self, id: &str) {
        let Some(e) = self.embeds.remove(id) else {
            return;
        };
        if let Some(timer) = &e.timer {
            timer.stop();
        }
        e.end_stream();
        if self.uploads.remove(&(e.seq, e.id.clone())) {
            self.upload_bytes -= e.size;
        }
        if !e.path.is_empty() {
            let _ = os::remove(&e.path);
        }
        self.writes.remove(&e.token);
        self.touch_embed(id);
    }

    /// Finishes a write that never started or failed: the embed is published
    /// out of its message (§4.8.3).
    pub fn fail_write_locked(&mut self, id: &str) {
        let message_id = self
            .embeds
            .get(id)
            .map(|e| e.message_id.clone())
            .unwrap_or_default();
        if self.messages.contains_key(&message_id) {
            self.republish_locked(&message_id, |body| replace_embed(body, id, None));
        }
        self.remove_embed_locked(id);
    }

    /// Records the hosted upload behind a user's avatar, deleting the content
    /// of the one it replaces.
    pub fn set_avatar_embed_locked(&mut self, user_id: &str, embed: Option<String>) {
        let Some(u) = self.users.get(user_id) else {
            return;
        };
        if let Some(old) = u.avatar_embed.clone() {
            if Some(&old) != embed.as_ref() {
                self.remove_embed_locked(&old);
            }
        }
        if let Some(u) = self.users.get_mut(user_id) {
            u.avatar_embed = embed;
        }
        self.touch_user(user_id);
    }

    /// Totals the finished uploads of one message.
    pub fn message_upload_bytes_locked(&self, message_id: &str) -> i64 {
        self.uploads
            .iter()
            .filter_map(|(_, id)| self.embeds.get(id))
            .filter(|e| {
                e.message_id == message_id && !e.is_link() && e.purpose == EmbedPurpose::Message
            })
            .map(|e| e.size)
            .sum()
    }

    /// Removes hosted files, other than `keep`, while they exceed
    /// max_upload_storage_bytes: link preview images first, then the
    /// oldest message uploads. Each affected message is republished once:
    /// a link keeps its card without `og.image`, and an upload embed leaves
    /// the message, as for a failed write (§4.8.3). Avatars and custom emoji
    /// count toward the total but are never removed.
    pub fn evict_uploads_locked(&mut self, keep: &str) {
        let (links, uploads): (Vec<String>, Vec<String>) = self
            .uploads
            .iter()
            .map(|(_, id)| id.clone())
            .partition(|id| self.embeds.get(id).is_some_and(EmbedState::is_link));
        let mut evicted: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();
        let mut order: Vec<String> = Vec::new();
        for id in links.into_iter().chain(uploads) {
            if self.upload_bytes <= self.config.max_upload_storage_bytes {
                break;
            }
            let Some(e) = self.embeds.get(&id) else {
                continue;
            };
            if id == keep || e.purpose.image() {
                continue;
            }
            let (message_id, link) = (e.message_id.clone(), e.is_link());
            if !evicted.contains_key(&message_id) {
                order.push(message_id.clone());
            }
            evicted
                .entry(message_id)
                .or_default()
                .push((id.clone(), link));
            if link {
                self.remove_link_image_locked(&id);
            } else {
                self.remove_embed_locked(&id);
            }
        }
        for message_id in order {
            if !self.messages.contains_key(&message_id) {
                continue;
            }
            let ids = &evicted[&message_id];
            self.republish_locked(&message_id, |body| {
                let mut changed = false;
                for (id, link) in ids {
                    let update: Option<&dyn Fn(&mut Object)> =
                        if *link { Some(&without_image) } else { None };
                    changed = replace_embed(body, id, update) || changed;
                }
                changed
            });
        }
    }

    /// Deletes a link preview's hosted image, keeping the preview.
    fn remove_link_image_locked(&mut self, id: &str) {
        let Some(e) = self.embeds.get_mut(id) else {
            return;
        };
        let path = std::mem::take(&mut e.path);
        let key = (e.seq, e.id.clone());
        let size = std::mem::take(&mut e.size);
        e.seq = 0;
        e.content_type.clear();
        without_image(&mut e.owned);
        if self.uploads.remove(&key) {
            self.upload_bytes -= size;
        }
        if !path.is_empty() {
            let _ = os::remove(&path);
        }
        self.touch_embed(id);
    }

    /// Resolves "embed_id/secret" from a file or stream path.
    pub fn lookup_embed_locked(&self, path: &str) -> Option<&EmbedState> {
        let (id, secret) = path.split_once('/')?;
        let e = self.embeds.get(id)?;
        if subtle::constant_time_compare(secret.as_bytes(), e.secret.as_bytes()) != 1 {
            return None;
        }
        Some(e)
    }

    /// Removes upload files in the upload directory that no restored embed
    /// holds, such as those of a run without persistence.
    pub fn remove_stale_uploads(&self, keep: &BTreeSet<String>) {
        let pattern = path::join(&[self.upload_dir.as_str(), &format!("*{UPLOAD_SUFFIX}")]);
        for name in path::filepath::glob(&pattern).unwrap_or_default() {
            if !keep.contains(&name) {
                let _ = os::remove(&name);
            }
        }
    }
}
