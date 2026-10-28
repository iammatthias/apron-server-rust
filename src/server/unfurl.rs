//! Link previews, an extension Go lacks (docs/DEVIATIONS.md). With
//! `Config.unfurl`, the first http(s) URLs of a message's text are fetched in
//! the background, and the message is republished with a `link` embed for
//! each page that describes itself, carrying its OpenGraph `og` (§4.8.1). The
//! og:image is downloaded and hosted as an upload, so clients load it from
//! the server's own origin.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread;

use rust_stdlib::concurrent::WaitGroup;
use rust_stdlib::net::http::client::{CheckRedirect, Client};
use rust_stdlib::net::http::header::BoxError;
use rust_stdlib::net::http::Request as HttpRequest;
use rust_stdlib::net::{split_host_port, url};
use rust_stdlib::time::{self, Duration, Time};
use rust_stdlib::{html, image, mime, os};
use rust_stdlib_crypto::rand;

use super::embeds::EmbedState;
use super::embeds::{MAX_EMBEDS_PER_MESSAGE, UPLOAD_SUFFIX};
use super::protocol::*;
use super::push::public_address;
use super::server::{Server, State};
use crate::obj;
use crate::rate::{every, Limiter};

pub const MAX_URLS_PER_MESSAGE: usize = 3;
/// Bounds each user's unfurled URLs: a burst of this many, refilled evenly
/// over a minute.
pub const UNFURLS_PER_MINUTE: i64 = 10;
pub const MAX_REDIRECTS: usize = 3;
/// Bounds each request, the body included.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// The part of a page read for its metadata.
pub const MAX_PAGE_BYTES: u64 = 512 << 10;
pub const MAX_IMAGE_BYTES: u64 = 2 << 20;
/// Bounds the unfurls running at once; a message posted beyond it is not
/// unfurled.
pub const MAX_JOBS: usize = 16;
pub const CACHE_TTL: Duration = Duration::from_hours(1);
/// How long a page that gave no preview is not fetched again.
pub const FAILURE_TTL: Duration = Duration::from_mins(5);
pub const MAX_CACHED: usize = 256;
/// Bounds the image bytes the cache holds.
pub const MAX_CACHED_BYTES: usize = 32 << 20;
const MAX_TITLE_CHARS: usize = 300;
const MAX_DESCRIPTION_CHARS: usize = 1000;

pub const USER_AGENT: &str = concat!(
    "Mozilla/5.0 (compatible; aprond/",
    env!("CARGO_PKG_VERSION"),
    "; link preview; +https://github.com/iammatthias/apron-server-rust)"
);

/// Decides whether a dialed address, `host:port` with the host an IP
/// address, may be connected to.
pub type DialCheck = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// The dial check for the public internet only, as push's.
pub fn public_dial_check() -> DialCheck {
    Arc::new(|address: &str| split_host_port(address).is_ok_and(|(host, _)| public_address(&host)))
}

/// What a page says about itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    pub title: String,
    pub description: String,
    pub site_name: String,
    /// The og:image, resolved against the page's URL.
    pub image: String,
    pub image_alt: String,
}

/// An og:image the server hosts: a PNG, JPEG, GIF, or WebP that decodes.
#[derive(Debug, PartialEq, Eq)]
pub struct Image {
    pub bytes: Vec<u8>,
    pub content_type: String,
    pub width: i64,
    pub height: i64,
    pub alt: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Preview {
    pub title: String,
    pub description: String,
    pub site_name: String,
    pub image: Option<Image>,
}

impl Preview {
    /// The og of the preview, its image at `image_url`.
    pub fn og(&self, image_url: Option<&str>) -> Object {
        let mut og = Object::new();
        for (key, value) in [
            ("title", &self.title),
            ("description", &self.description),
            ("site_name", &self.site_name),
        ] {
            if !value.is_empty() {
                og.insert(key.into(), value.as_str().into());
            }
        }
        if let (Some(image), Some(url)) = (&self.image, image_url) {
            let mut media = obj! {
                "url" => url,
                "type" => image.content_type.as_str(),
                "width" => image.width,
                "height" => image.height,
            };
            if !image.alt.is_empty() {
                media.insert("alt".into(), image.alt.as_str().into());
            }
            og.insert("image".into(), media.into());
        }
        og
    }
}

/// The http(s) URLs in a message body's text, in order, without repeats.
/// In markdown, URLs in code spans and fenced code blocks are skipped.
pub fn message_urls(body: Option<&Object>) -> Vec<String> {
    let Some(body) = body else {
        return Vec::new();
    };
    let text = body.get("text").and_then(Json::as_str).unwrap_or("");
    let markdown = body.get("format").and_then(Json::as_str) == Some("markdown");
    let text = if markdown {
        without_code(text)
    } else {
        text.to_owned()
    };
    let mut urls: Vec<String> = Vec::new();
    for url in scan_urls(&text) {
        if !urls.contains(&url) {
            urls.push(url);
        }
    }
    urls
}

/// Replaces markdown code (fenced blocks and code spans) with spaces.
fn without_code(text: &str) -> String {
    let mut prose = String::with_capacity(text.len());
    // The fence character and length of the open fenced block.
    let mut fence: Option<(char, usize)> = None;
    for line in text.split_inclusive('\n') {
        let indent = line.len() - line.trim_start_matches(' ').len();
        let rest = &line[indent..];
        let marker = rest.chars().next().filter(|c| *c == '`' || *c == '~');
        let run = marker.map_or(0, |m| rest.len() - rest.trim_start_matches(m).len());
        match (fence, marker) {
            (None, Some(m)) if indent < 4 && run >= 3 => fence = Some((m, run)),
            (Some((open, length)), Some(m))
                if indent < 4 && m == open && run >= length && rest[run..].trim().is_empty() =>
            {
                fence = None
            }
            (None, _) => {
                prose.push_str(line);
                continue;
            }
            _ => {}
        }
        prose.push('\n');
    }
    without_code_spans(&prose)
}

/// A backtick run opens a code span that the next run of the same length
/// closes; a run that is never closed is literal text.
fn without_code_spans(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'`' {
            let next = text[i..].find('`').map_or(bytes.len(), |n| i + n);
            out.push_str(&text[i..next]);
            i = next;
            continue;
        }
        let run = text[i..].len() - text[i..].trim_start_matches('`').len();
        let mut close = None;
        let mut j = i + run;
        while let Some(n) = text[j..].find('`') {
            let start = j + n;
            let length = text[start..].len() - text[start..].trim_start_matches('`').len();
            if length == run {
                close = Some(start + length);
                break;
            }
            j = start + length;
        }
        match close {
            Some(end) => {
                out.push(' ');
                i = end;
            }
            None => {
                out.push_str(&text[i..i + run]);
                i += run;
            }
        }
    }
    out
}

/// Finds the http(s) URLs in text. A URL starts at a word boundary and ends
/// at whitespace or a delimiter; trailing punctuation, and a closing bracket
/// it did not open, are left out.
fn scan_urls(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut urls = Vec::new();
    let mut from = 0;
    while let Some(found) = ["http://", "https://"]
        .iter()
        .filter_map(|scheme| lower[from..].find(scheme))
        .min()
    {
        let start = from + found;
        let end = text[start..]
            .find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '`'))
            .map_or(text.len(), |n| start + n);
        from = end.max(start + 1);
        let boundary = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        if !boundary {
            continue;
        }
        let mut candidate = &text[start..end];
        loop {
            let trimmed =
                candidate.trim_end_matches(['.', ',', ';', ':', '!', '?', '\'', '*', '_', '~']);
            let trimmed = match trimmed.chars().last() {
                Some(close @ (')' | ']')) => {
                    let open = if close == ')' { '(' } else { '[' };
                    if trimmed.matches(close).count() > trimmed.matches(open).count() {
                        &trimmed[..trimmed.len() - 1]
                    } else {
                        trimmed
                    }
                }
                _ => trimmed,
            };
            if trimmed.len() == candidate.len() {
                break;
            }
            candidate = trimmed;
        }
        let Ok(parsed) = url::parse(candidate) else {
            continue;
        };
        if matches!(parsed.scheme.as_str(), "http" | "https") && !parsed.hostname().is_empty() {
            urls.push(candidate.to_owned());
        }
    }
    urls
}

/// Reads a page's OpenGraph metadata from its `<meta>` tags, with the
/// `<title>` and the meta description as fallbacks. Scripts, styles, and
/// comments are skipped; nothing runs.
pub fn parse_page(html_text: &str, base: &url::Url) -> Page {
    let lower = html_text.to_ascii_lowercase();
    let mut page = Page::default();
    let (mut title, mut description) = (String::new(), String::new());
    let mut i = 0;
    while let Some(n) = lower[i..].find('<') {
        let start = i + n;
        if lower[start..].starts_with("<!--") {
            i = lower[start..]
                .find("-->")
                .map_or(lower.len(), |e| start + e + 3);
            continue;
        }
        let name_end = lower[start + 1..]
            .find(|c: char| !c.is_ascii_alphanumeric())
            .map_or(lower.len(), |e| start + 1 + e);
        let name = &lower[start + 1..name_end];
        let Some(tag_end) = tag_end(html_text, name_end) else {
            break;
        };
        i = tag_end;
        match name {
            "meta" => {
                let attrs = attributes(&html_text[name_end..tag_end]);
                let key = attrs
                    .get("property")
                    .or_else(|| attrs.get("name"))
                    .map(|k| k.to_ascii_lowercase())
                    .unwrap_or_default();
                let content = clean(attrs.get("content").map_or("", String::as_str));
                let field = match key.as_str() {
                    "og:title" => &mut page.title,
                    "og:description" => &mut page.description,
                    "og:site_name" => &mut page.site_name,
                    "og:image" | "og:image:url" | "og:image:secure_url" => &mut page.image,
                    "og:image:alt" => &mut page.image_alt,
                    "description" => &mut description,
                    _ => continue,
                };
                if field.is_empty() {
                    *field = content;
                }
            }
            "title" if title.is_empty() => {
                let close = lower[i..].find("</title").map_or(lower.len(), |e| i + e);
                title = clean(&html_text[i..close]);
                i = close;
            }
            "script" | "style" => {
                i = lower[i..]
                    .find(&format!("</{name}"))
                    .map_or(lower.len(), |e| i + e);
            }
            _ => {}
        }
    }
    if page.title.is_empty() {
        page.title = title;
    }
    if page.description.is_empty() {
        page.description = description;
    }
    page.title = truncate(&page.title, MAX_TITLE_CHARS);
    page.description = truncate(&page.description, MAX_DESCRIPTION_CHARS);
    page.site_name = truncate(&page.site_name, MAX_TITLE_CHARS);
    page.image_alt = truncate(&page.image_alt, MAX_DESCRIPTION_CHARS);
    page.image = Some(page.image.as_str())
        .filter(|image| !image.is_empty())
        .and_then(|image| url::parse(image).ok())
        .map(|reference| base.resolve_reference(&reference))
        .filter(|u| matches!(u.scheme.as_str(), "http" | "https") && !u.hostname().is_empty())
        .map(|u| u.to_string())
        .unwrap_or_default();
    if page.image.is_empty() {
        page.image_alt.clear();
    }
    page
}

/// The end of the tag whose attributes start at `from`: past its `>`, which
/// a quoted attribute value does not end.
fn tag_end(text: &str, from: usize) -> Option<usize> {
    let mut quote: Option<u8> = None;
    for (i, &b) in text.as_bytes()[from..].iter().enumerate() {
        match (quote, b) {
            (Some(q), _) if b == q => quote = None,
            (Some(_), _) => {}
            (None, b'"' | b'\'') => quote = Some(b),
            (None, b'>') => return Some(from + i + 1),
            _ => {}
        }
    }
    None
}

/// A tag's attributes by lowercased name, values unescaped; the first of a
/// repeated name wins.
fn attributes(tag: &str) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    let mut rest = tag.trim_end_matches('>').trim_end_matches('/');
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '/');
        if rest.is_empty() {
            return attrs;
        }
        let name_end = rest
            .find(|c: char| c.is_whitespace() || c == '=' || c == '/')
            .unwrap_or(rest.len());
        let name = rest[..name_end].to_ascii_lowercase();
        rest = rest[name_end..].trim_start();
        let mut value = String::new();
        if let Some(after) = rest.strip_prefix('=') {
            let after = after.trim_start();
            let (raw, remaining) = match after.chars().next() {
                Some(q @ ('"' | '\'')) => {
                    let body = &after[1..];
                    let end = body.find(q).unwrap_or(body.len());
                    (&body[..end], body.get(end + 1..).unwrap_or(""))
                }
                _ => {
                    let end = after.find(char::is_whitespace).unwrap_or(after.len());
                    (&after[..end], &after[end..])
                }
            };
            value = html::unescape(raw);
            rest = remaining;
        }
        attrs.entry(name).or_insert(value);
    }
}

/// Unescapes text and collapses its whitespace.
fn clean(text: &str) -> String {
    html::unescape(text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate(text: &str, chars: usize) -> String {
    match text.char_indices().nth(chars) {
        Some((end, _)) => text[..end].to_owned(),
        None => text.to_owned(),
    }
}

/// GETs pages and images with the limits of link previews: http(s) only, at
/// most MAX_REDIRECTS redirects, a timeout over the whole exchange, and
/// every dialed address, after each redirect too, passed by the dial check.
/// The address is checked as dialed, so DNS is resolved once and cannot
/// redirect it.
pub struct Fetcher {
    client: Client,
}

impl Fetcher {
    pub fn new(check: DialCheck, timeout: Duration) -> Fetcher {
        let dialer = rust_stdlib_sys::net::Dialer {
            timeout: timeout.as_nanos(),
            control: Some(Box::new(move |_network: &str, address: &str, _raw: &_| {
                if check(address) {
                    Ok(())
                } else {
                    Err(std::io::Error::other(
                        "link preview address is not on the public internet",
                    ))
                }
            })),
            ..rust_stdlib_sys::net::Dialer::default()
        };
        let transport = rust_stdlib::net::http::transport::Transport {
            // The proxy of the environment would carry requests past the
            // check on the dialed address.
            proxy: None,
            dial_context: Some(rust_stdlib_sysnet::dial_context(dialer)),
            tls_handshake_timeout: timeout,
            ..rust_stdlib_sysnet::transport()
        };
        // The transport refuses schemes other than http and https.
        let check_redirect: CheckRedirect = Arc::new(|_: &HttpRequest, via: &[HttpRequest]| {
            if via.len() > MAX_REDIRECTS {
                return Err(format!("stopped after {MAX_REDIRECTS} redirects").into());
            }
            Ok(())
        });
        Fetcher {
            client: Client {
                timeout,
                transport: Some(Arc::new(transport)),
                check_redirect: Some(check_redirect),
                ..Client::default()
            },
        }
    }

    /// GETs url and reads at most `limit` bytes of a 200 answer, returning
    /// the URL answered after redirects, the Content-Type, the bytes, and
    /// whether the body went past the limit.
    fn get(
        &self,
        target: &str,
        accept: &str,
        limit: u64,
    ) -> Result<(url::Url, String, Vec<u8>, bool), BoxError> {
        let mut request = HttpRequest::new("GET", target)?;
        request.header.set("User-Agent", USER_AGENT);
        request.header.set("Accept", accept);
        let response = self.client.do_request(request)?;
        let Some(body) = &response.body else {
            return Err("no body".into());
        };
        let result = (|| {
            if response.status_code != 200 {
                return Err(format!("status {}", response.status_code).into());
            }
            let mut bytes = Vec::new();
            body.clone().take(limit + 1).read_to_end(&mut bytes)?;
            let over = bytes.len() as u64 > limit;
            bytes.truncate(limit as usize);
            let answered = response
                .request
                .as_ref()
                .map(|r| r.url.clone())
                .unwrap_or_default();
            let content_type = response.header.get("Content-Type").unwrap_or("").to_owned();
            Ok((answered, content_type, bytes, over))
        })();
        let _ = body.close();
        result
    }

    /// Fetches a page and its og:image. `None` when the page cannot be read,
    /// is not HTML, or gives no title, description, or usable image.
    pub fn preview(&self, target: &str) -> Option<Preview> {
        let (answered, content_type, bytes, _) = self
            .get(target, "text/html,application/xhtml+xml", MAX_PAGE_BYTES)
            .ok()?;
        let (media_type, _) = mime::parse_media_type(&content_type);
        if media_type != "text/html" && media_type != "application/xhtml+xml" {
            return None;
        }
        let page = parse_page(&String::from_utf8_lossy(&bytes), &answered);
        let image = if page.image.is_empty() {
            None
        } else {
            self.image(&page.image, &page.image_alt)
        };
        if page.title.is_empty() && page.description.is_empty() && image.is_none() {
            return None;
        }
        Some(Preview {
            title: page.title,
            description: page.description,
            site_name: page.site_name,
            image,
        })
    }

    /// Downloads an og:image of at most MAX_IMAGE_BYTES, declared as an image
    /// and decoding as a PNG, JPEG, GIF, or WebP, the only formats that
    /// decode. The decoded format is its type: sites often declare
    /// `image/jpg`, or one type for another a CDN negotiated.
    fn image(&self, target: &str, alt: &str) -> Option<Image> {
        let (_, declared, bytes, over) = self.get(target, "image/*", MAX_IMAGE_BYTES).ok()?;
        if over || !mime::parse_media_type(&declared).0.starts_with("image/") {
            return None;
        }
        crate::webp::register();
        let (config, format) = image::decode_config(&bytes[..]).ok()?;
        let content_type = format!("image/{format}");
        Some(Image {
            bytes,
            content_type,
            width: i64::from(config.width),
            height: i64::from(config.height),
            alt: alt.to_owned(),
        })
    }
}

struct Cached {
    preview: Option<Arc<Preview>>,
    expires: Time,
}

impl Cached {
    fn bytes(&self) -> usize {
        self.preview
            .as_ref()
            .and_then(|p| p.image.as_ref())
            .map_or(0, |image| image.bytes.len())
    }
}

/// Unfurl results by URL: a preview for CACHE_TTL, a failure for
/// FAILURE_TTL. Beyond MAX_CACHED entries or MAX_CACHED_BYTES of images, the
/// entries closest to expiring go first.
#[derive(Default)]
pub struct Cache {
    entries: BTreeMap<String, Cached>,
    bytes: usize,
}

impl Cache {
    /// The cached result for url: `None` when there is none, `Some(None)`
    /// for a failure.
    pub fn get(&self, target: &str, now: &Time) -> Option<Option<Arc<Preview>>> {
        self.entries
            .get(target)
            .filter(|c| now.before(&c.expires))
            .map(|c| c.preview.clone())
    }

    pub fn insert(&mut self, target: &str, preview: Option<Arc<Preview>>, now: &Time) {
        let ttl = if preview.is_some() {
            CACHE_TTL
        } else {
            FAILURE_TTL
        };
        let entry = Cached {
            preview,
            expires: now.add(ttl),
        };
        if entry.bytes() > MAX_CACHED_BYTES {
            return;
        }
        self.bytes += entry.bytes();
        if let Some(old) = self.entries.insert(target.to_owned(), entry) {
            self.bytes -= old.bytes();
        }
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, c)| !now.before(&c.expires))
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            self.remove(&key);
        }
        while self.entries.len() > MAX_CACHED || self.bytes > MAX_CACHED_BYTES {
            let Some(first) = self
                .entries
                .iter()
                .min_by(|a, b| a.1.expires.compare(&b.1.expires).cmp(&0))
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.remove(&first);
        }
    }

    fn remove(&mut self, target: &str) {
        if let Some(old) = self.entries.remove(target) {
            self.bytes -= old.bytes();
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One message's unfurl: its URLs, and where its images are hosted.
pub struct Job {
    pub message_id: String,
    pub base_url: String,
    pub upload_dir: String,
    pub urls: Vec<String>,
}

/// Runs unfurls in the background, one thread per message and one per URL
/// within it.
pub struct Unfurler {
    fetcher: Fetcher,
    cache: Mutex<Cache>,
    running: AtomicUsize,
    /// The unfurls in progress, which `shutdown` awaits.
    pub pending: WaitGroup,
}

impl Unfurler {
    pub fn new(fetcher: Fetcher) -> Arc<Unfurler> {
        Arc::new(Unfurler {
            fetcher,
            cache: Mutex::new(Cache::default()),
            running: AtomicUsize::new(0),
            pending: WaitGroup::new(),
        })
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The preview of url, from the cache or fetched.
    pub fn preview(&self, target: &str) -> Option<Arc<Preview>> {
        if let Some(cached) = self.cache().get(target, &time::now()) {
            return cached;
        }
        let preview = self.fetcher.preview(target).map(Arc::new);
        self.cache().insert(target, preview.clone(), &time::now());
        preview
    }

    /// Unfurls a message's URLs in the background, then attaches the
    /// previews to the message as it is then. Beyond MAX_JOBS the message is
    /// not unfurled.
    pub fn start(self: &Arc<Self>, server: Weak<Server>, job: Job) {
        if self.running.fetch_add(1, Ordering::SeqCst) >= MAX_JOBS {
            self.running.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        self.pending.add(1);
        let unfurler = self.clone();
        thread::spawn(move || {
            let previews: Vec<(String, Arc<Preview>)> = thread::scope(|scope| {
                let fetches: Vec<_> = job
                    .urls
                    .iter()
                    .map(|u| scope.spawn(|| (u.clone(), unfurler.preview(u))))
                    .collect();
                fetches
                    .into_iter()
                    .filter_map(|f| f.join().ok())
                    .filter_map(|(u, p)| p.map(|p| (u, p)))
                    .collect()
            });
            let hosted = previews
                .into_iter()
                .map(|(u, p)| {
                    let file = p
                        .image
                        .as_ref()
                        .and_then(|image| store_image(&job.upload_dir, &image.bytes));
                    (u, p, file)
                })
                .collect();
            if let Some(server) = server.upgrade() {
                server.lock().attach_previews_locked(&job, hosted);
            } else {
                remove_files(hosted);
            }
            unfurler.running.fetch_sub(1, Ordering::SeqCst);
            unfurler.pending.done();
        });
    }
}

/// A preview to attach, and the upload file holding its image.
type Hosted = (String, Arc<Preview>, Option<String>);

/// Writes an image to a new upload file, returning its name.
fn store_image(dir: &str, bytes: &[u8]) -> Option<String> {
    let file = os::create_temp(dir, &format!("*{UPLOAD_SUFFIX}")).ok()?;
    let name = file.name().to_owned();
    let mut out = &file;
    let written = std::io::Write::write_all(&mut out, bytes).is_ok();
    let _ = file.close();
    if !written {
        let _ = os::remove(&name);
        return None;
    }
    Some(name)
}

fn remove_files(hosted: Vec<Hosted>) {
    for (_, _, file) in hosted {
        if let Some(name) = file {
            let _ = os::remove(&name);
        }
    }
}

/// The URLs of the link embeds in a body.
fn linked_urls(body: Option<&Object>) -> Vec<String> {
    body.and_then(|b| b.get("embeds"))
        .map(Json::as_list)
        .unwrap_or(&[])
        .iter()
        .filter_map(Json::as_object)
        .filter_map(|e| e.get("url").and_then(Json::as_str))
        .map(str::to_owned)
        .collect()
}

impl State {
    /// Starts unfurling the URLs a save added to a message's text: the first
    /// MAX_URLS_PER_MESSAGE of its text that the previous snapshot's text
    /// did not have and no embed already links, within the user's
    /// UNFURLS_PER_MINUTE.
    pub fn unfurl_locked(
        &mut self,
        user_id: &str,
        base_url: &str,
        message_id: &str,
        previous: Option<&Object>,
        snapshot: &Object,
    ) {
        let Some(unfurler) = self.unfurler.clone() else {
            return;
        };
        let body = |s: &Object| s.get("body").and_then(Json::as_object).cloned();
        let before = message_urls(previous.and_then(body).as_ref());
        let body = body(snapshot);
        let linked = linked_urls(body.as_ref());
        let mut urls: Vec<String> = message_urls(body.as_ref())
            .into_iter()
            .take(MAX_URLS_PER_MESSAGE)
            .filter(|u| !before.contains(u) && !linked.contains(u))
            .collect();
        let Some(u) = self.users.get_mut(user_id) else {
            return;
        };
        let limiter = u.unfurls.get_or_insert_with(|| {
            Limiter::new(
                every(Duration::from_nanos(
                    time::MINUTE.as_nanos() / UNFURLS_PER_MINUTE,
                )),
                UNFURLS_PER_MINUTE,
            )
        });
        let now = time::now();
        urls.retain(|_| limiter.allow_n(&now, 1));
        if urls.is_empty() {
            return;
        }
        unfurler.start(
            self.server.clone(),
            Job {
                message_id: message_id.to_owned(),
                base_url: base_url.to_owned(),
                upload_dir: self.upload_dir.clone(),
                urls,
            },
        );
    }

    /// Republishes a message once with a link embed for each preview whose
    /// URL its text still has and no embed links yet. The images become
    /// hosted uploads of the message.
    pub fn attach_previews_locked(&mut self, job: &Job, hosted: Vec<Hosted>) {
        let snapshot = self.snapshot(&job.message_id);
        let body = snapshot.get("body").and_then(Json::as_object);
        if self.closed || !self.messages.contains_key(&job.message_id) || body.is_none() {
            remove_files(hosted);
            return;
        }
        let present = message_urls(body);
        let mut linked = linked_urls(body);
        let mut room = MAX_EMBEDS_PER_MESSAGE.saturating_sub(embed_count(body));
        let mut added: Vec<Json> = Vec::new();
        for (target, preview, file) in hosted {
            if room == 0 || !present.contains(&target) || linked.contains(&target) {
                if let Some(name) = file {
                    let _ = os::remove(&name);
                }
                continue;
            }
            room -= 1;
            linked.push(target.clone());
            self.embed_number += 1;
            let id = format!("embed_{}", self.embed_number);
            let mut e = EmbedState {
                id: id.clone(),
                kind: "link".into(),
                message_id: job.message_id.clone(),
                base_url: job.base_url.clone(),
                secret: rand::text(),
                started: true,
                finished: true,
                ..EmbedState::default()
            };
            let mut image_url = None;
            if let (Some(name), Some(image)) = (file, &preview.image) {
                self.upload_seq += 1;
                e.seq = self.upload_seq;
                e.path = name;
                e.size = image.bytes.len() as i64;
                e.content_type = image.content_type.clone();
                image_url = Some(e.file_url());
                self.uploads.insert((e.seq, id.clone()));
                self.upload_bytes += e.size;
            }
            e.owned = obj! {
                "url" => target.as_str(),
                "og" => preview.og(image_url.as_deref()),
            };
            let mut embed = obj! {"embed_id" => id.as_str(), "kind" => "link"};
            embed.extend(e.owned.clone());
            added.push(embed.into());
            self.embeds.insert(id.clone(), e);
            self.touch_embed(&id);
        }
        if added.is_empty() {
            return;
        }
        self.republish_locked(&job.message_id, |body| {
            match body.get_mut("embeds") {
                Some(Json::Array(embeds)) => embeds.extend(added),
                _ => {
                    body.insert("embeds".into(), added.into());
                }
            }
            true
        });
        self.evict_uploads_locked("");
    }
}

fn embed_count(body: Option<&Object>) -> usize {
    body.and_then(|b| b.get("embeds"))
        .map_or(0, |e| e.as_list().len())
}
