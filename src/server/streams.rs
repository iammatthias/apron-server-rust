//! Stream embeds (§4.8.5): a stream write's body relayed to /streams/
//! readers as it arrives, through a StreamBuffer.

use std::io::{self, Read};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use rust_stdlib::net::http::{self, Request as HttpRequest, ResponseController, ResponseWriter};
use rust_stdlib::text::BytesExt;
use rust_stdlib::time::{self, Duration};

use super::embeds::{replace_embed, STREAM_PATH};
use super::protocol::*;
use super::server::Server;
use crate::obj;

impl Server {
    /// Copies the request body into a stream until it ends: the body ends, a
    /// limit is reached, or the embed is removed (§4.8.5).
    pub(super) fn write_stream(
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
