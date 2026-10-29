//! Embeds (§4.8): uploads and streams the server hosts, their write URLs,
//! and the /write/, /files/, and /streams/ endpoints.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use rust_stdlib::log::slog;
use rust_stdlib::net::http::{
    self, MaxBytesError, Request as HttpRequest, ResponseController, ResponseWriter,
};
use rust_stdlib::os::{self, File, FileMode};
use rust_stdlib::text::BytesExt;
use rust_stdlib::time::{self, Duration, Time, Timer};
use rust_stdlib::{image, mime, path};
use rust_stdlib_crypto::{rand, subtle};

use super::protocol::*;
use super::server::{Client, Server, State};
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
    fn immutable(&self) -> bool {
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

        let new_upload = submitted.iter().any(|value| {
            embed_id(value).is_none()
                && value
                    .as_object()
                    .and_then(|e| e.get("kind"))
                    .and_then(Json::as_str)
                    == Some("upload")
        });
        if new_upload && !self.feature_on(Feature::Uploads) {
            return Err(RpcError::new(CODE_DENIED, UPLOADS_OFF));
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

fn set_embed_cors(w: &mut dyn ResponseWriter, methods: &str) {
    let header = w.header();
    header.set("Access-Control-Allow-Origin", "*");
    header.set("Access-Control-Allow-Methods", methods);
    header.set("Access-Control-Allow-Headers", "Content-Type");
}

/// Answers a write without reading its body, and closes the connection. The
/// server would otherwise read what is left of the body before answering, to
/// reuse the connection, and wait for as long as the writer holds the body
/// open, such as a stream writer waiting for the answer.
/// Why an avatar, custom emoji or server avatar write was refused for its
/// type.
fn not_image_message(purpose: &EmbedPurpose) -> &'static str {
    match purpose {
        EmbedPurpose::Avatar(_) => "Avatars must be PNG, JPEG, GIF, or WebP images",
        _ => "Only PNG, JPEG, GIF, and WebP images can be custom emoji or the server's avatar",
    }
}

fn refuse_write(w: &mut dyn ResponseWriter, message: &str, status: u16) {
    w.header().set("Connection", "close");
    let _ = ResponseController::new(w).set_read_deadline(&time::now());
    http::http_error(w, message, status);
}

/// Prefers the sender's declared type, except for types a browser would run
/// as a document, and otherwise sniffs the content.
pub fn upload_content_type(declared: &str, head: &[u8]) -> String {
    let (media_type, params) = mime::parse_media_type(declared);
    if params.is_ok() && media_type != "application/octet-stream" && !active_type(&media_type) {
        return media_type;
    }
    let (media_type, _) = mime::parse_media_type(http::detect_content_type(head));
    if active_type(&media_type) {
        return "application/octet-stream".into();
    }
    media_type
}

/// Reports whether a browser could run or apply content of the type on this
/// origin: markup, scripts, stylesheets, and WebAssembly.
fn active_type(media_type: &str) -> bool {
    ["html", "xml", "xsl", "script", "jscript", "css", "wasm"]
        .iter()
        .any(|marker| media_type.contains(marker))
}

/// The image types `/avatar` keeps, which `ext.media.avatar` lists.
pub const AVATAR_TYPES: [&str; 4] = ["image/png", "image/jpeg", "image/gif", "image/webp"];

/// The types an attachment may be by default, the ones `sniff_upload`
/// recognizes (apron-server-cloudflare's IMAGE_TYPES and AUDIO_TYPES).
pub const UPLOAD_TYPES: [&str; 7] = [
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "audio/webm",
    "audio/ogg",
    "audio/mp4",
];

/// The image or audio type a file's first bytes show, from its signature,
/// as apron-server-cloudflare's sniffImage and sniffAudio read it: only the
/// container is checked, so a WebM or MP4 holding video counts as audio.
pub fn sniff_upload(head: &[u8]) -> Option<&'static str> {
    let at = |start: usize, text: &[u8]| head.get(start..start + text.len()) == Some(text);
    if at(0, b"\x89PNG\r\n\x1a\n") && at(12, b"IHDR") {
        return Some("image/png");
    }
    if at(0, b"GIF87a") || at(0, b"GIF89a") {
        return Some("image/gif");
    }
    if at(0, b"RIFF") && at(8, b"WEBP") {
        return Some("image/webp");
    }
    if at(0, &[0xff, 0xd8, 0xff]) {
        return Some("image/jpeg");
    }
    // EBML whose header names the DocType (element 0x4282, size 4) webm.
    if at(0, &[0x1a, 0x45, 0xdf, 0xa3]) {
        let end = head.len().min(64);
        return (4..end)
            .any(|i| at(i, &[0x42, 0x82, 0x84]) && at(i + 3, b"webm"))
            .then_some("audio/webm");
    }
    // The first Ogg page starts a stream whose first packet names its codec.
    if head.len() >= 28 && at(0, b"OggS") {
        let packet = 27 + usize::from(head[26]);
        return (at(packet, b"OpusHead") || at(packet, b"\x01vorbis") || at(packet, b"\x7fFLAC"))
            .then_some("audio/ogg");
    }
    if at(4, b"ftyp") {
        const IMAGE_BRANDS: [&[u8]; 10] = [
            b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"mif1", b"msf1", b"avif",
            b"avis",
        ];
        let brand = head.get(8..12)?;
        return (!IMAGE_BRANDS.contains(&brand)).then_some("audio/mp4");
    }
    None
}

/// Reports whether `media_type` matches one of `patterns`: a MIME type,
/// `type/*`, or `*/*`, without regard to case (EXTENSIONS.md, `ext:media`).
pub fn type_matches(patterns: &[String], media_type: &str) -> bool {
    let media_type = media_type.to_ascii_lowercase();
    let major = media_type.split('/').next().unwrap_or("");
    patterns.iter().any(|pattern| {
        let pattern = pattern.to_ascii_lowercase();
        pattern == "*/*"
            || pattern == media_type
            || pattern.strip_suffix("/*").is_some_and(|p| p == major)
    })
}

pub fn avatar_type(content_type: &str) -> bool {
    AVATAR_TYPES.contains(&content_type)
}

/// `image.DecodeConfig`, with WebP registered: an image's format and
/// dimensions, from its header.
pub(crate) fn image_config(r: impl Read) -> Option<(image::Config, String)> {
    crate::webp::register();
    image::decode_config(r).ok()
}

/// `image_config` of the file's first 1 GiB.
fn decode_image_config(file: &File) -> Option<(image::Config, String)> {
    let mut file = file;
    file.seek(SeekFrom::Start(0)).ok()?;
    image_config(file.take(1 << 30))
}

pub(crate) fn new_upload_file(dir: &str) -> io::Result<File> {
    os::create_temp(dir, &format!("*{UPLOAD_SUFFIX}"))
}

/// The width and height of an image upload, an avatar's or a custom
/// emoji's, whose content decodes as the image type it shows.
pub(crate) fn image_size(content_type: &str, file: Option<&File>) -> Option<(i64, i64)> {
    if !avatar_type(content_type) {
        return None;
    }
    let (config, format) = decode_image_config(file?)?;
    (format!("image/{format}") == content_type)
        .then(|| (i64::from(config.width), i64::from(config.height)))
}

/// Builds the og the server sets on a finished upload (§4.8.4): image for a
/// preview, or video or audio to play. Other files have none, so clients
/// show a file card.
fn describe_upload(e: &EmbedState, file: &File) -> Option<Object> {
    let mut media = obj! {"url" => e.file_url(), "type" => e.content_type.as_str()};
    let mut og = Object::new();
    if avatar_type(&e.content_type) {
        if let Some((config, _)) = decode_image_config(file) {
            media.insert("width".into(), i64::from(config.width).into());
            media.insert("height".into(), i64::from(config.height).into());
        }
        if !e.alt.is_empty() {
            media.insert("alt".into(), e.alt.as_str().into());
        }
        og.insert("image".into(), media.into());
    } else if e.content_type.starts_with("video/") {
        og.insert("video".into(), media.into());
    } else if e.content_type.starts_with("audio/") {
        og.insert("audio".into(), media.into());
    } else {
        return None;
    }
    if !e.title.is_empty() {
        og.insert("title".into(), e.title.as_str().into());
    }
    Some(og)
}

/// Reports whether a hosted file may be shown in the browser rather than
/// downloaded.
fn inline_type(content_type: &str) -> bool {
    avatar_type(content_type)
        || content_type == "text/plain"
        || content_type.starts_with("video/")
        || content_type.starts_with("audio/")
}

/// Why an upload body was not stored.
enum UploadError {
    TooLarge,
    /// An avatar or a custom emoji that is not an image of AVATAR_TYPES.
    NotImage,
    /// An attachment of a type Config.upload_types leaves out.
    NotAccepted,
    Other,
}

/// The first 512 bytes of the file, for sniffing.
fn head_of(file: &File) -> Vec<u8> {
    let mut file = file;
    let mut head = Vec::with_capacity(512);
    if file.seek(SeekFrom::Start(0)).is_ok() {
        let _ = file.take(512).read_to_end(&mut head);
    }
    head
}

impl Server {
    /// Prepares the upload directory: the configured one, or a new temporary
    /// one. Upload files no restored embed holds are removed after the state
    /// is restored.
    pub(crate) fn open_upload_dir(&self, st: &mut State) {
        let dir = &self.config.upload_dir;
        if dir.is_empty() {
            match os::mkdir_temp("", "aprond-uploads-") {
                Ok(temp) => {
                    st.upload_dir = temp;
                    st.temp_upload_dir = true;
                }
                Err(e) => slog::error(
                    "cannot create a temporary upload directory",
                    &["error".into(), slog::Value::from(e.to_string()).into()],
                ),
            }
            return;
        }
        if let Err(e) = os::mkdir_all(dir, FileMode(0o700)) {
            slog::error(
                "cannot create the upload directory",
                &[
                    "dir".into(),
                    slog::Value::from(dir.clone()).into(),
                    "error".into(),
                    slog::Value::from(e.to_string()).into(),
                ],
            );
        }
        st.upload_dir = dir.clone();
    }

    /// Accepts an upload or stream body at its write URL, once.
    pub(crate) fn handle_write(self: &Arc<Self>, w: &mut dyn ResponseWriter, r: &mut HttpRequest) {
        set_embed_cors(w, "PUT, OPTIONS");
        if r.method == http::METHOD_OPTIONS {
            w.write_header(http::STATUS_NO_CONTENT);
            return;
        }
        if r.method != http::METHOD_PUT {
            w.header().set("Allow", "PUT, OPTIONS");
            refuse_write(w, "Write with PUT", http::STATUS_METHOD_NOT_ALLOWED);
            return;
        }
        let token = r.url.path.strip_prefix(WRITE_PATH).unwrap_or("").to_owned();
        let (id, stream) = {
            let mut st = self.lock();
            let Some(id) = st.writes.get(&token).cloned() else {
                drop(st);
                refuse_write(
                    w,
                    "This write URL is unknown, used, or expired",
                    http::STATUS_NOT_FOUND,
                );
                return;
            };
            let Some(e) = st.embeds.get_mut(&id).filter(|e| !e.started) else {
                drop(st);
                refuse_write(
                    w,
                    "This write URL is unknown, used, or expired",
                    http::STATUS_NOT_FOUND,
                );
                return;
            };
            // An avatar's, a custom emoji's or the server's avatar's declared
            // type, where it has one, must be an image type it keeps: one that
            // is not is refused before the body is read, and the write stays
            // open (ext:media).
            let (declared, _) = mime::parse_media_type(r.header.get("Content-Type").unwrap_or(""));
            if e.stream.is_none()
                && e.purpose.image()
                && !declared.is_empty()
                && !AVATAR_TYPES.contains(&declared.as_str())
            {
                let message = not_image_message(&e.purpose);
                drop(st);
                refuse_write(w, message, http::STATUS_UNSUPPORTED_MEDIA_TYPE);
                return;
            }
            e.started = true;
            if let Some(timer) = e.timer.take() {
                timer.stop();
            }
            if let Some(stream) = e.stream.clone() {
                let ended = stream.clone();
                e.timer = Some(time::after_func(
                    self.config.stream_max_duration,
                    move || ended.end(),
                ));
            }
            let stream = e.stream.clone();
            st.writes.remove(&token);
            (id, stream)
        };
        match stream {
            Some(stream) => self.write_stream(w, r, &id, &stream),
            None => self.write_upload(w, r, &id),
        }
    }

    fn write_upload(self: &Arc<Self>, w: &mut dyn ResponseWriter, r: &mut HttpRequest, id: &str) {
        let (limit, purpose, message_id) = {
            let st = self.lock();
            let Some(e) = st.embeds.get(id) else {
                drop(st);
                http::http_error(
                    w,
                    "The embed was removed from its message",
                    http::STATUS_GONE,
                );
                return;
            };
            let limit = match &e.purpose {
                EmbedPurpose::Message => self.config.max_upload_bytes.min(
                    self.config.max_message_upload_bytes
                        - st.message_upload_bytes_locked(&e.message_id),
                ),
                EmbedPurpose::Emoji(_) => self.config.max_emoji_bytes,
                EmbedPurpose::Avatar(_) | EmbedPurpose::ServerAvatar => {
                    self.config.max_avatar_bytes
                }
            };
            (limit, e.purpose.clone(), e.message_id.clone())
        };
        let _ = ResponseController::new(w).set_read_deadline(&time::now().add(UPLOAD_READ_TIMEOUT));
        let (file, size, mut err) = self.receive_upload(w, r, limit);
        let head = file.as_ref().map(head_of).unwrap_or_default();
        let declared = r.header.get("Content-Type").unwrap_or("").to_owned();
        // The type comes from the bytes where they show one, so a sender
        // cannot have the server serve one it does not keep.
        let content_type = match sniff_upload(&head) {
            Some(sniffed) => sniffed.to_owned(),
            // A type the sniffer knows must show in the bytes.
            None => match upload_content_type(&declared, &head) {
                known if UPLOAD_TYPES.contains(&known.as_str()) => {
                    "application/octet-stream".into()
                }
                other => other,
            },
        };
        let mut size_px = None;
        if err.is_none() && purpose.image() {
            size_px = image_size(&content_type, file.as_ref());
            if size_px.is_none() {
                err = Some(UploadError::NotImage);
            }
        }
        let (declared_type, _) = mime::parse_media_type(&declared);
        if err.is_none()
            && purpose == EmbedPurpose::Message
            && (!type_matches(&self.config.upload_types, &content_type)
                || !(declared_type.is_empty()
                    || type_matches(&self.config.upload_types, &declared_type)))
        {
            err = Some(UploadError::NotAccepted);
        }
        let file_name = file.as_ref().map(|f| f.name().to_owned());

        let mut st = self.lock();
        let mut og: Option<Object> = None;
        if err.is_none() {
            if let (Some(e), Some(file)) = (st.embeds.get_mut(id), file.as_ref()) {
                e.content_type = content_type.clone();
                og = describe_upload(e, file);
            }
        }
        if let Some(file) = &file {
            let _ = file.close();
        }
        let fail = |st: &mut State, w: &mut dyn ResponseWriter, status: u16, message: &str| {
            if let Some(name) = &file_name {
                let _ = os::remove(name);
            }
            if st.embeds.contains_key(id) {
                st.fail_write_locked(id);
            }
            http::http_error(w, message, status);
        };
        if !st.embeds.contains_key(id) {
            fail(
                &mut st,
                w,
                http::STATUS_GONE,
                "The embed was removed from its message",
            );
            return;
        }
        match err {
            Some(UploadError::TooLarge) => {
                fail(
                    &mut st,
                    w,
                    http::STATUS_REQUEST_ENTITY_TOO_LARGE,
                    &format!("This upload is limited to {limit} bytes"),
                );
                return;
            }
            Some(UploadError::NotImage) => {
                let message = not_image_message(&purpose);
                fail(&mut st, w, http::STATUS_UNSUPPORTED_MEDIA_TYPE, message);
                return;
            }
            Some(UploadError::NotAccepted) => {
                fail(
                    &mut st,
                    w,
                    http::STATUS_UNSUPPORTED_MEDIA_TYPE,
                    &format!(
                        "Uploads here must be {}",
                        self.config.upload_types.join(", ")
                    ),
                );
                return;
            }
            Some(UploadError::Other) => {
                fail(
                    &mut st,
                    w,
                    http::STATUS_BAD_REQUEST,
                    "The upload did not finish",
                );
                return;
            }
            None => {}
        }
        if purpose == EmbedPurpose::Message
            && st.message_upload_bytes_locked(&message_id) + size
                > self.config.max_message_upload_bytes
        {
            // Another upload for the message finished while this one arrived.
            fail(
                &mut st,
                w,
                http::STATUS_REQUEST_ENTITY_TOO_LARGE,
                &format!(
                    "A message's uploads are limited to {} bytes",
                    self.config.max_message_upload_bytes
                ),
            );
            return;
        }
        if let EmbedPurpose::Emoji(key) = &purpose {
            if !st.emoji_fits(key) {
                // Another add filled the catalog while this one arrived.
                let most = self.config.max_emoji;
                fail(
                    &mut st,
                    w,
                    http::STATUS_GONE,
                    &format!("This server keeps at most {most} custom emoji; remove one first"),
                );
                return;
            }
        }
        let Some(file_name) = file_name else {
            fail(
                &mut st,
                w,
                http::STATUS_BAD_REQUEST,
                "The upload did not finish",
            );
            return;
        };
        let file_url = st.host_file_locked(id, file_name, size);
        let e = st.embeds.get_mut(id).expect("checked above");
        e.owned = obj! {"url" => file_url.as_str()};
        if let Some(og) = og {
            e.owned.insert("og".into(), og.into());
        }
        match purpose {
            EmbedPurpose::Avatar(user_id) if st.users.contains_key(&user_id) => {
                st.set_avatar_embed_locked(&user_id, Some(id.to_owned()));
                if let Some(u) = st.users.get_mut(&user_id) {
                    u.avatar = file_url.clone();
                }
                st.touch_user(&user_id);
                st.notify_profile_locked(&user_id, None, &ExtObject::new(), &[]);
            }
            EmbedPurpose::Avatar(_) => st.remove_embed_locked(id),
            EmbedPurpose::ServerAvatar => st.set_server_avatar_locked(Some(id.to_owned())),
            EmbedPurpose::Emoji(key) => {
                let (width, height) = size_px.unwrap_or_default();
                st.add_emoji_locked(&key, id, width, height);
            }
            EmbedPurpose::Message if st.messages.contains_key(&message_id) => {
                let owned = st
                    .embeds
                    .get(id)
                    .map(|e| e.owned.clone())
                    .unwrap_or_default();
                st.republish_locked(&message_id, |body| {
                    replace_embed(
                        body,
                        id,
                        Some(&|embed: &mut Object| embed.extend(owned.clone())),
                    )
                });
            }
            EmbedPurpose::Message => {}
        }
        st.evict_uploads_locked(id);
        drop(st);
        w.header().set("Content-Type", "application/json");
        w.write_header(http::STATUS_CREATED);
        let _ = io::Write::write_all(w, format!("{{\"url\":{}}}\n", quote(&file_url)).as_bytes());
    }

    /// Copies a request body of at most `limit` bytes into a new file in the
    /// upload directory. On error the file, if any, is still returned so the
    /// caller can remove it.
    fn receive_upload(
        &self,
        w: &mut dyn ResponseWriter,
        r: &mut HttpRequest,
        limit: i64,
    ) -> (Option<File>, i64, Option<UploadError>) {
        if limit <= 0 {
            return (None, 0, Some(UploadError::TooLarge));
        }
        let dir = self.lock().upload_dir.clone();
        let file = match new_upload_file(&dir) {
            Ok(file) => file,
            Err(e) => {
                slog::error(
                    "cannot store upload",
                    &["error".into(), slog::Value::from(e.to_string()).into()],
                );
                return (None, 0, Some(UploadError::Other));
            }
        };
        let Some(body) = r.body.take() else {
            return (Some(file), 0, None);
        };
        let mut body = http::max_bytes_reader(Some(w), body, limit);
        let mut out = &file;
        match io::copy(&mut body, &mut out) {
            Ok(size) => (Some(file), size as i64, None),
            Err(e) => {
                let too_large = e
                    .get_ref()
                    .is_some_and(|inner| inner.downcast_ref::<MaxBytesError>().is_some());
                let kind = if too_large {
                    UploadError::TooLarge
                } else {
                    UploadError::Other
                };
                (Some(file), 0, Some(kind))
            }
        }
    }

    /// Serves a finished upload. Hosted files never run as documents on this
    /// origin: they are sandboxed, not sniffed, and downloaded unless they are
    /// media or plain text.
    pub(crate) fn handle_file(self: &Arc<Self>, w: &mut dyn ResponseWriter, r: &mut HttpRequest) {
        w.header().set("Access-Control-Allow-Origin", "*");
        if r.method != http::METHOD_GET && r.method != http::METHOD_HEAD {
            http::http_error(w, "Read with GET", http::STATUS_METHOD_NOT_ALLOWED);
            return;
        }
        let path = r.url.path.strip_prefix(FILE_PATH).unwrap_or("").to_owned();
        let (content, content_type, title, immutable) = {
            let st = self.lock();
            let Some(e) = st
                .lookup_embed_locked(&path)
                .filter(|e| e.finished && e.stream.is_none() && !e.path.is_empty())
            else {
                drop(st);
                http::not_found(w, r);
                return;
            };
            // An upload removed after this still reads from the open file.
            (
                os::open(&e.path),
                e.content_type.clone(),
                e.title.clone(),
                e.purpose.immutable(),
            )
        };
        let Ok(mut content) = content else {
            http::not_found(w, r);
            return;
        };
        let header = w.header();
        header.set("Content-Type", &content_type);
        header.set("X-Content-Type-Options", "nosniff");
        header.set("Content-Security-Policy", "sandbox; default-src 'none'");
        // A custom emoji or the server's avatar keeps its URL until it is
        // removed or replaced, as on apron-server-cloudflare.
        header.set(
            "Cache-Control",
            if immutable {
                "public, max-age=31536000, immutable"
            } else {
                "private, max-age=3600"
            },
        );
        let mut disposition = if inline_type(&content_type) {
            "inline".to_owned()
        } else {
            "attachment".to_owned()
        };
        if !title.is_empty() {
            let mut params = BTreeMap::new();
            params.insert("filename".to_owned(), title);
            disposition = mime::format_media_type(&disposition, &params).unwrap_or_default();
        }
        header.set("Content-Disposition", &disposition);
        http::serve_content(w, r, "", &Time::default(), &mut content);
        let _ = content.close();
    }

    /// Copies the request body into a stream until it ends: the body ends, a
    /// limit is reached, or the embed is removed (§4.8.5).
    fn write_stream(
        self: &Arc<Self>,
        w: &mut dyn ResponseWriter,
        r: &mut HttpRequest,
        id: &str,
        stream: &Arc<StreamBuffer>,
    ) {
        // The reply may come before the body ends, as when the stream is
        // removed.
        let _ = ResponseController::new(w).enable_full_duplex();
        let reader = r.body.take().map(|mut body| {
            let stream = stream.clone();
            thread::spawn(move || {
                let mut buf = vec![0u8; 32 << 10];
                loop {
                    match body.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if !stream.write(&buf[..n]) {
                                break;
                            }
                        }
                    }
                }
                stream.writer_done();
            })
        });
        let body_ended = match &reader {
            Some(_) => stream.wait_writer(),
            None => true,
        };
        stream.end();
        if !body_ended {
            // Unblock a body read still waiting on the writer, and let it
            // finish. The expired deadline also cancels the connection, so
            // the connection must not serve another request.
            w.header().set("Connection", "close");
            let _ = ResponseController::new(w).set_read_deadline(&time::now());
        }
        if let Some(reader) = reader {
            let _ = reader.join();
        }
        let mut st = self.lock();
        let Some(e) = st.embeds.get_mut(id) else {
            drop(st);
            http::http_error(
                w,
                "The stream was removed from its message",
                http::STATUS_GONE,
            );
            return;
        };
        if let Some(timer) = e.timer.take() {
            timer.stop();
        }
        e.finished = true;
        let text = stream.text();
        e.owned = obj! {"text" => text.as_str()};
        let message_id = e.message_id.clone();
        st.touch_embed(id);
        if st.messages.contains_key(&message_id) {
            st.republish_locked(&message_id, |body| {
                replace_embed(
                    body,
                    id,
                    Some(&|embed: &mut Object| {
                        embed.remove("url");
                        embed.insert("text".into(), text.as_str().into());
                    }),
                )
            });
        }
        drop(st);
        if stream.limited() {
            http::http_error(
                w,
                &format!(
                    "Streams are limited to {} bytes; the stream ended",
                    self.config.stream_max_bytes
                ),
                http::STATUS_REQUEST_ENTITY_TOO_LARGE,
            );
            return;
        }
        w.write_header(http::STATUS_NO_CONTENT);
    }

    /// Serves a live stream: the kept text, then more as it arrives, until
    /// the stream ends. A finished stream's URL no longer works.
    pub(crate) fn handle_stream(self: &Arc<Self>, w: &mut dyn ResponseWriter, r: &mut HttpRequest) {
        w.header().set("Access-Control-Allow-Origin", "*");
        if r.method != http::METHOD_GET {
            http::http_error(w, "Read with GET", http::STATUS_METHOD_NOT_ALLOWED);
            return;
        }
        let path = r
            .url
            .path
            .strip_prefix(STREAM_PATH)
            .unwrap_or("")
            .to_owned();
        let stream = {
            let st = self.lock();
            let Some(stream) = st
                .lookup_embed_locked(&path)
                .filter(|e| !e.finished)
                .and_then(|e| e.stream.clone())
            else {
                drop(st);
                http::not_found(w, r);
                return;
            };
            stream
        };
        let header = w.header();
        header.set("Content-Type", "text/plain; charset=utf-8");
        header.set("X-Content-Type-Options", "nosniff");
        header.set("Cache-Control", "no-store");
        let ctx = r.context();
        let mut position: i64 = -1;
        loop {
            let (chunk, next, version, ended) = stream.read(position);
            if !chunk.is_empty() && io::Write::write_all(w, &chunk).is_err() {
                return;
            }
            let _ = ResponseController::new(w).flush();
            position = next;
            if ended {
                return;
            }
            // Go selects on the stream's change and the request's context;
            // the wait is bounded so a reader whose connection went away is
            // noticed.
            while !stream.wait_change(version, Duration::from_secs(1)) {
                if ctx.err().is_some() {
                    return;
                }
            }
        }
    }
}

/// Keeps a stream's trailing text and wakes readers as it grows.
#[derive(Debug)]
pub struct StreamBuffer {
    keep: usize,
    max_bytes: i64,
    inner: Mutex<StreamInner>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct StreamInner {
    /// The kept bytes, starting at absolute offset `start`.
    data: Vec<u8>,
    start: i64,
    total: i64,
    /// Counts changes, standing in for Go's replaced `changed` channel.
    version: u64,
    ended: bool,
    at_limit: bool,
    /// Set once the writer's body ended, for `write_stream`.
    writer_done: bool,
}

impl StreamBuffer {
    pub fn new(keep: usize, max_bytes: i64) -> StreamBuffer {
        StreamBuffer {
            keep,
            max_bytes,
            inner: Mutex::new(StreamInner::default()),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, StreamInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Appends to the stream and reports whether it still accepts more. At
    /// the size limit it keeps what fits and ends.
    pub fn write(&self, p: &[u8]) -> bool {
        let mut b = self.lock();
        if b.ended {
            return false;
        }
        let mut p = p;
        let room = self.max_bytes - b.total;
        if p.len() as i64 >= room {
            p = &p[..room.max(0) as usize];
            b.at_limit = true;
        }
        b.data.extend_from_slice(p);
        b.total += p.len() as i64;
        if b.data.len() > self.keep {
            let mut excess = b.data.len() - self.keep;
            // Trim to a rune boundary so the kept text starts with a whole
            // rune.
            while excess < b.data.len() && !rust_stdlib::unicode::rune::rune_start(b.data[excess]) {
                excess += 1;
            }
            b.data.drain(..excess);
            b.start += excess as i64;
        }
        b.version += 1;
        if b.at_limit {
            b.ended = true;
        }
        self.changed.notify_all();
        !b.ended
    }

    pub fn end(&self) {
        let mut b = self.lock();
        if !b.ended {
            b.ended = true;
            b.version += 1;
            self.changed.notify_all();
        }
    }

    pub fn limited(&self) -> bool {
        self.lock().at_limit
    }

    /// Returns the bytes from `position` on (from the start of the kept text
    /// when `position` is before it), the next position, the change version
    /// to wait past, and whether the stream has ended with nothing more to
    /// read.
    pub fn read(&self, position: i64) -> (Vec<u8>, i64, u64, bool) {
        let b = self.lock();
        let position = position.max(b.start);
        let chunk = b.data[(position - b.start) as usize..].to_vec();
        (chunk, b.start + b.data.len() as i64, b.version, b.ended)
    }

    /// Waits up to `timeout` for a change past `version`, reporting whether
    /// one happened.
    pub fn wait_change(&self, version: u64, timeout: Duration) -> bool {
        let b = self.lock();
        let timeout = std::time::Duration::from_nanos(timeout.as_nanos().max(0) as u64);
        let (b, _) = self
            .changed
            .wait_timeout_while(b, timeout, |b| b.version == version)
            .unwrap_or_else(|e| e.into_inner());
        b.version != version
    }

    /// Notes that the writer's body ended.
    fn writer_done(&self) {
        let mut b = self.lock();
        b.writer_done = true;
        b.version += 1;
        self.changed.notify_all();
    }

    /// Waits until the writer's body ends or the stream ends, reporting
    /// whether the body ended.
    fn wait_writer(&self) -> bool {
        let b = self.lock();
        let b = self
            .changed
            .wait_while(b, |b| !b.writer_done && !b.ended)
            .unwrap_or_else(|e| e.into_inner());
        b.writer_done
    }

    /// The kept text as valid UTF-8.
    pub fn text(&self) -> String {
        let b = self.lock();
        String::from_utf8(b.data.to_valid_utf8("\u{FFFD}".as_bytes())).unwrap_or_default()
    }
}
