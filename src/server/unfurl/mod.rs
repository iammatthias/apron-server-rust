//! Link previews, an extension Go lacks (docs/DEVIATIONS.md). With
//! `Config.unfurl`, the first http(s) URLs of a message's text are fetched in
//! the background, and the message is republished with a `link` embed for
//! each page that describes itself, carrying its OpenGraph `og` (§4.8.1). The
//! og:image is downloaded and hosted as an upload, so clients load it from
//! the server's own origin.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread;

use rust_stdlib::concurrent::WaitGroup;
use rust_stdlib::os;
use rust_stdlib::time::{self, Duration};

use super::embeds::{new_upload_file, MAX_EMBEDS_PER_MESSAGE};
use super::protocol::*;
use super::server::{Server, State};
use crate::rate::{every, Limiter};

mod cache;
mod fetch;
mod page;
mod text;

pub use cache::*;
pub use fetch::*;
pub use page::*;
pub use text::*;

pub const MAX_URLS_PER_MESSAGE: usize = 3;
/// Bounds each user's unfurled URLs: a burst of this many, refilled evenly
/// over a minute.
pub const UNFURLS_PER_MINUTE: i64 = 10;
/// Bounds the unfurls running at once; a message posted beyond it is not
/// unfurled.
pub const MAX_JOBS: usize = 16;

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
        let cached = self.cache().get(target, &time::now());
        let unfurled = match cached {
            Some(cached) => cached,
            None => {
                let unfurled = match self.fetcher.preview(target) {
                    Some(preview) => Unfurled::Preview(Arc::new(preview)),
                    None => Unfurled::Nothing,
                };
                self.cache().insert(target, unfurled.clone(), &time::now());
                unfurled
            }
        };
        match unfurled {
            Unfurled::Preview(preview) => Some(preview),
            Unfurled::Nothing => None,
        }
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
            let hosted: Vec<Hosted> = previews
                .into_iter()
                .map(|(url, preview)| Hosted {
                    file: preview
                        .image
                        .as_ref()
                        .and_then(|image| UploadFile::write(&job.upload_dir, &image.bytes)),
                    url,
                    preview,
                })
                .collect();
            if let Some(server) = server.upgrade() {
                server.lock().attach_previews_locked(&job, hosted);
            }
            unfurler.running.fetch_sub(1, Ordering::SeqCst);
            unfurler.pending.done();
        });
    }
}

/// A preview to attach, and the upload file holding its image.
pub struct Hosted {
    url: String,
    preview: Arc<Preview>,
    file: Option<UploadFile>,
}

/// An upload file not yet held by an embed, removed unless kept.
struct UploadFile(String);

impl UploadFile {
    fn write(dir: &str, bytes: &[u8]) -> Option<UploadFile> {
        let file = new_upload_file(dir).ok()?;
        let upload = UploadFile(file.name().to_owned());
        let mut out = &file;
        let written = std::io::Write::write_all(&mut out, bytes).is_ok();
        let _ = file.close();
        written.then_some(upload)
    }

    fn keep(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl Drop for UploadFile {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            let _ = os::remove(&self.0);
        }
    }
}

fn body_of(snapshot: &Object) -> Option<&Object> {
    snapshot.get("body").and_then(Json::as_object)
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
        let (before, after) = (previous.and_then(body_of), body_of(snapshot));
        if text_of(before) == text_of(after) {
            return;
        }
        let old = message_urls(before);
        let linked = linked_urls(after);
        let mut urls: Vec<String> = message_urls(after)
            .into_iter()
            .filter(|u| !old.contains(u) && !linked.contains(u))
            .take(MAX_URLS_PER_MESSAGE)
            .collect();
        if urls.is_empty() {
            return;
        }
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
    /// hosted files of the message.
    pub fn attach_previews_locked(&mut self, job: &Job, hosted: Vec<Hosted>) {
        let snapshot = self.snapshot(&job.message_id);
        let body = body_of(&snapshot);
        if self.closed || !self.messages.contains_key(&job.message_id) || body.is_none() {
            return;
        }
        let present = message_urls(body);
        let linked = linked_urls(body);
        let room = MAX_EMBEDS_PER_MESSAGE.saturating_sub(embed_count(body));
        let accepted: Vec<Hosted> = hosted
            .into_iter()
            .filter(|h| present.contains(&h.url) && !linked.contains(&h.url))
            .take(room)
            .collect();
        if accepted.is_empty() {
            return;
        }
        let added: Vec<Json> = accepted
            .into_iter()
            .map(|h| {
                let file = h.file.map(UploadFile::keep);
                self.add_link_embed_locked(&job.message_id, &job.base_url, &h.url, &h.preview, file)
                    .into()
            })
            .collect();
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
