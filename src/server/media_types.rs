//! Upload media types: what a declared type or the content's first bytes
//! make of an upload, and the image dimensions an upload reports.

use std::io::{Read, Seek, SeekFrom};

use rust_stdlib::net::http::{self};
use rust_stdlib::os::File;
use rust_stdlib::{image, mime};

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
pub(super) fn decode_image_config(file: &File) -> Option<(image::Config, String)> {
    let mut file = file;
    file.seek(SeekFrom::Start(0)).ok()?;
    image_config(file.take(1 << 30))
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
