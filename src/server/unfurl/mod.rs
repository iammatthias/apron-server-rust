//! Link previews, an extension Go lacks (docs/DEVIATIONS.md). With
//! `Config.unfurl`, the first http(s) URLs of a message's text are fetched in
//! the background, and the message is republished with a `link` embed for
//! each page that describes itself, carrying its OpenGraph `og` (§4.8.1). The
//! og:image is downloaded and hosted as an upload, so clients load it from
//! the server's own origin.

use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread;

use rust_stdlib::os;
use rust_stdlib::time::{self, Duration, Time};

use super::embeds::MAX_EMBEDS_PER_MESSAGE;

use super::protocol::*;
use super::server::{Server, State};
use super::uploads::new_upload_file;
use crate::rate::{every, Limiter};

mod cache;
mod fetch;
pub(crate) mod page;
mod text;

pub use cache::*;
pub use fetch::*;
pub use text::*;

pub const MAX_URLS_PER_MESSAGE: usize = 3;
/// Bounds each user's unfurled URLs: a burst of this many, refilled evenly
/// over a minute.
pub const UNFURLS_PER_MINUTE: i64 = 10;
/// Bounds the server's unfurled URLs, across users, the same way.
pub const SERVER_UNFURLS_PER_MINUTE: i64 = 60;
/// Bounds the unfurls running at once; a message posted beyond it is not
/// unfurled.
pub const MAX_JOBS: usize = 16;

fn per_minute(n: i64) -> Limiter {
    Limiter::new(every(Duration::from_nanos(time::MINUTE.as_nanos() / n)), n)
}

/// The whole URLs a limiter allows at `now`.
fn whole_tokens(limiter: &Limiter, now: &Time) -> usize {
    limiter.tokens_at(now).max(0.0) as usize
}

/// One message's unfurl: its URLs, and where its images are hosted.
struct Job {
    message_id: String,
    base_url: String,
    upload_dir: String,
    urls: Vec<String>,
}

/// Counts the jobs running, at most MAX_JOBS.
#[derive(Default)]
struct Jobs {
    running: Mutex<usize>,
    idle: Condvar,
}

/// A running job's place in `Jobs`, given back when dropped, so a job that
/// panics or never starts frees it.
struct Slot(Arc<Unfurler>);

impl Drop for Slot {
    fn drop(&mut self) {
        let mut running = self.0.running();
        *running -= 1;
        if *running == 0 {
            self.0.jobs.idle.notify_all();
        }
    }
}

/// Runs unfurls in the background: a thread per message, which gives up on
/// the URLs not unfurled within the fetch timeout, and a thread per URL.
pub struct Unfurler {
    fetcher: Fetcher,
    /// How long a job waits for its URLs. A fetch stuck where its own
    /// timeout does not reach, as in a DNS lookup, is left to finish alone.
    timeout: Duration,
    cache: Mutex<Cache>,
    jobs: Jobs,
    limiter: Mutex<Limiter>,
}

impl Unfurler {
    pub fn new(fetcher: Fetcher, timeout: Duration) -> Arc<Unfurler> {
        Arc::new(Unfurler {
            fetcher,
            timeout,
            cache: Mutex::new(Cache::default()),
            jobs: Jobs::default(),
            limiter: Mutex::new(per_minute(SERVER_UNFURLS_PER_MINUTE)),
        })
    }

    fn cache(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn running(&self) -> MutexGuard<'_, usize> {
        self.jobs.running.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes a job's slot, unless MAX_JOBS are running.
    fn try_start(self: &Arc<Self>) -> Option<Slot> {
        let mut running = self.running();
        if *running >= MAX_JOBS {
            return None;
        }
        *running += 1;
        Some(Slot(self.clone()))
    }

    /// Waits until no job runs. Each job gives up on its fetches after the
    /// fetch timeout, so the wait is bounded.
    pub(crate) fn wait(&self) {
        let mut running = self.running();
        while *running > 0 {
            running = self
                .jobs
                .idle
                .wait(running)
                .unwrap_or_else(|e| e.into_inner());
        }
    }

    fn limiter(&self) -> MutexGuard<'_, Limiter> {
        self.limiter.lock().unwrap_or_else(|e| e.into_inner())
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

    /// The previews of urls, in their order, fetched in parallel. A URL not
    /// unfurled within the timeout is skipped; its fetch finishes in the
    /// background and fills the cache.
    pub fn previews(self: &Arc<Self>, urls: &[String]) -> Vec<(String, Arc<Preview>)> {
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_nanos(self.timeout.as_nanos().max(0) as u64);
        let (tx, rx) = mpsc::channel();
        for (i, url) in urls.iter().enumerate() {
            let (unfurler, url, tx) = (self.clone(), url.clone(), tx.clone());
            let _ = thread::Builder::new().spawn(move || {
                let preview = unfurler.preview(&url);
                let _ = tx.send((i, url, preview));
            });
        }
        drop(tx);
        let mut previews = Vec::new();
        while let Ok((i, url, preview)) =
            rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
        {
            if let Some(preview) = preview {
                previews.push((i, url, preview));
            }
        }
        previews.sort_by_key(|(i, _, _)| *i);
        previews.into_iter().map(|(_, u, p)| (u, p)).collect()
    }

    /// Unfurls a message's URLs in the background, then attaches the
    /// previews to the message as it is then.
    fn start(self: &Arc<Self>, slot: Slot, server: Weak<Server>, job: Job) {
        let unfurler = self.clone();
        let _ = thread::Builder::new().spawn(move || {
            let _slot = slot;
            let hosted: Vec<Hosted> = unfurler
                .previews(&job.urls)
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
        });
    }
}

/// A preview to attach, and the upload file holding its image.
struct Hosted {
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
    /// did not have and no embed already links, as many as the user's and
    /// the server's limiters allow. The limiters are charged only when a
    /// job slot is free.
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
        let limiter = u
            .unfurls
            .get_or_insert_with(|| per_minute(UNFURLS_PER_MINUTE));
        let now = time::now();
        let admitted = urls
            .len()
            .min(whole_tokens(limiter, &now))
            .min(whole_tokens(&unfurler.limiter(), &now));
        if admitted == 0 {
            return;
        }
        let Some(slot) = unfurler.try_start() else {
            return;
        };
        urls.truncate(admitted);
        limiter.allow_n(&now, admitted as i64);
        unfurler.limiter().allow_n(&now, admitted as i64);
        unfurler.start(
            slot,
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
    fn attach_previews_locked(&mut self, job: &Job, hosted: Vec<Hosted>) {
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
