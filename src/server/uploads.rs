//! The HTTP side of hosted embeds (§4.8): writes to /write/ and reads from
//! /files/.

use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use rust_stdlib::log::slog;
use rust_stdlib::mime;
use rust_stdlib::net::http::{
    self, MaxBytesError, Request as HttpRequest, ResponseController, ResponseWriter,
};
use rust_stdlib::os::{self, File, FileMode};
use rust_stdlib::time::{self, Time};

use super::embeds::{
    replace_embed, EmbedPurpose, EmbedState, FILE_PATH, UPLOAD_READ_TIMEOUT, UPLOAD_SUFFIX,
    WRITE_PATH,
};
use super::media_types::{
    avatar_type, decode_image_config, image_size, sniff_upload, type_matches, upload_content_type,
    AVATAR_TYPES, UPLOAD_TYPES,
};
use super::protocol::*;
use super::server::{Server, State};
use super::users::EMOJI_ROLES;
use crate::obj;

pub(super) fn set_embed_cors(w: &mut dyn ResponseWriter, methods: &str) {
    let header = w.header();
    header.set("Access-Control-Allow-Origin", "*");
    header.set("Access-Control-Allow-Methods", methods);
    header.set("Access-Control-Allow-Headers", "Content-Type");
}

/// Why an avatar, custom emoji or server avatar write was refused for its
/// type.
fn not_image_message(purpose: &EmbedPurpose) -> &'static str {
    match purpose {
        EmbedPurpose::Avatar(_) => "Avatars must be PNG, JPEG, GIF, or WebP images",
        _ => "Only PNG, JPEG, GIF, and WebP images can be custom emoji or the server's avatar",
    }
}

/// Answers a write without reading its body, and closes the connection. The
/// server would otherwise read what is left of the body before answering, to
/// reuse the connection, and wait for as long as the writer holds the body
/// open, such as a stream writer waiting for the answer.
pub(super) fn refuse_write(w: &mut dyn ResponseWriter, message: &str, status: u16) {
    w.header().set("Connection", "close");
    let _ = ResponseController::new(w).set_read_deadline(&time::now());
    http::http_error(w, message, status);
}

pub(crate) fn new_upload_file(dir: &str) -> io::Result<File> {
    os::create_temp(dir, &format!("*{UPLOAD_SUFFIX}"))
}

/// Builds the og the server sets on a finished upload (§4.8.4): image for a
/// preview, or video or audio to play. Other files have none, so clients
/// show a file card.
pub(super) fn describe_upload(e: &EmbedState, file: &File) -> Option<Object> {
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
pub(super) fn inline_type(content_type: &str) -> bool {
    avatar_type(content_type)
        || content_type == "text/plain"
        || content_type.starts_with("video/")
        || content_type.starts_with("audio/")
}

/// Why an upload body was not stored.
pub(super) enum UploadError {
    TooLarge,
    /// An avatar or a custom emoji that is not an image of AVATAR_TYPES.
    NotImage,
    /// An attachment of a type Config.upload_types leaves out.
    NotAccepted,
    Other,
}

/// The first 512 bytes of the file, for sniffing.
pub(super) fn head_of(file: &File) -> Vec<u8> {
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
        // A /rename while the body arrived moved an avatar to the new
        // user_id.
        let purpose = st.embeds[id].purpose.clone();
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
            let uploader = &st.embeds[id].uploader;
            if !st
                .users
                .get(uploader)
                .is_some_and(|u| u.has_any_role(EMOJI_ROLES))
            {
                // The sender lost the roles /emoji needs while it arrived.
                fail(
                    &mut st,
                    w,
                    http::STATUS_FORBIDDEN,
                    &format!("/emoji needs one of the roles {}", EMOJI_ROLES.join(", ")),
                );
                return;
            }
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
}
