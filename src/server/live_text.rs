//! Live text (§4.8.3, §4.8.5, §4.8.6): a `terminal` or `append` embed whose
//! text its sender streams with a `PUT` to the embed's write URL while
//! readers follow it at `/live/`, as apron-server-cloudflare's live-text.ts
//! and its SPEC section 4.5 have it. The text lives in memory while it
//! streams; what its kind keeps is published once, when it ends.

use std::io::{self, Read};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;

use rust_stdlib::net::http::{self, Request as HttpRequest, ResponseController, ResponseWriter};
use rust_stdlib::net::url;
use rust_stdlib::time::{self, Duration};

use super::client::Client;
use super::commands::{private_notice, CommandCtx};
use super::embeds::{replace_embed, LivePost};
use super::limits::Category;
use super::protocol::*;
use super::server::{Server, State};
use super::uploads::refuse_write;
use crate::obj;

/// Where a live text is read: `/live/<secret>`.
pub const LIVE_PATH: &str = "/live/";

/// Apron's stand-alone terminal viewer, where a browser that opens a
/// terminal's `url` goes unless `--terminal-viewer-url` says otherwise.
pub const DEFAULT_TERMINAL_VIEWER_URL: &str = "https://terminal.apron.chat/";

/// A terminal embed's `og` (§4.8.1), for a client that doesn't render
/// terminal embeds and shows it as the card its `og` describes, which opens
/// its `url`. Titled as the embed is.
pub fn terminal_og(title: &str) -> Object {
    let title = if title.is_empty() { "Terminal" } else { title };
    obj! {"title" => title, "description" => "Terminal output. Open it to watch."}
}

/// The two kinds of live text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveKind {
    /// Program output for an 80×40 terminal, kept as `output` when it ends
    /// (§4.8.6).
    Terminal,
    /// Text appended to the message's body when it ends (§4.8.5).
    Append,
}

impl LiveKind {
    pub fn parse(kind: &str) -> Option<LiveKind> {
        match kind {
            "terminal" => Some(LiveKind::Terminal),
            "append" => Some(LiveKind::Append),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LiveKind::Terminal => "terminal",
            LiveKind::Append => "append",
        }
    }
}

/// Why a text ended, as its writer is told in the `PUT` response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveEnd {
    /// The body ended.
    Complete,
    /// The owner's time ran out.
    Time,
    /// The input cap, or an append's kept bytes, was reached.
    Size,
    /// The writer went away.
    Disconnected,
    /// A save removed the embed, or the message, or its owner was purged.
    Removed,
    /// The server is shutting down; the text is lost.
    Unavailable,
}

impl LiveEnd {
    /// The `PUT` response, once the text has ended and what was kept is
    /// published (`published`), in apron-server-cloudflare's words: an
    /// error status for a write that failed or reached a limit, and 200
    /// for any other (§4.8.3).
    pub fn response(
        self,
        published: bool,
        kind: LiveKind,
        limit: usize,
        max: Duration,
        limits: &LiveLimits,
    ) -> (u16, String) {
        let status = match self {
            LiveEnd::Complete | LiveEnd::Removed => http::STATUS_OK,
            LiveEnd::Time => http::STATUS_REQUEST_TIMEOUT,
            LiveEnd::Size => http::STATUS_REQUEST_ENTITY_TOO_LARGE,
            LiveEnd::Disconnected => http::STATUS_BAD_REQUEST,
            LiveEnd::Unavailable => {
                return (
                    http::STATUS_SERVICE_UNAVAILABLE,
                    "Server storage is unavailable; the text could not be posted.".into(),
                )
            }
        };
        if !published && self != LiveEnd::Removed {
            let (_, text) = LiveEnd::Removed.response(true, kind, limit, max, limits);
            return (status, text);
        }
        let text = match self {
            LiveEnd::Complete => "Done: the text is posted.".to_owned(),
            LiveEnd::Time => format!(
                "Stopped at the {}-second limit; what was kept is posted.",
                max.as_nanos() / time::SECOND.as_nanos()
            ),
            LiveEnd::Size => match kind {
                LiveKind::Append => format!(
                    "Stopped at the {} limit; what was kept is posted.",
                    byte_size(limit)
                ),
                LiveKind::Terminal => format!(
                    "Stopped at the {} limit; the last {} is posted.",
                    byte_size(limits.max_input_bytes),
                    byte_size(limit)
                ),
            },
            LiveEnd::Disconnected => {
                "The write was interrupted; what arrived is posted.".to_owned()
            }
            LiveEnd::Removed => "Stopped: the message or its embed was removed.".to_owned(),
            LiveEnd::Unavailable => unreachable!("answered above"),
        };
        (status, text)
    }
}

/// The limits live text is held to: apron-server-cloudflare's Workers Paid
/// `liveText` policy by default (`--limit.live-*`).
#[derive(Clone, Debug, PartialEq)]
pub struct LiveLimits {
    /// How long a text may stream from its `PUT`, and how long an admin's
    /// or mod's may.
    pub max: Duration,
    pub moderator_max: Duration,
    /// How long an unused write URL stays valid.
    pub write_window: Duration,
    /// What a terminal keeps of its output, its last part.
    pub terminal_keep_bytes: usize,
    /// The most one `PUT` may send in all.
    pub max_input_bytes: usize,
    /// The most an append adds to its message's text.
    pub append_max_bytes: usize,
    /// Starts one user (a guest: one address's guests) and one address may
    /// make at once, then this many per `start_window`; zero is no limit.
    pub starts_per_user: u32,
    pub starts_per_ip: u32,
    pub start_window: Duration,
    /// Starts one user, and everyone, may make a UTC day; zero is no limit.
    pub starts_per_user_day: u32,
    pub starts_per_day: u32,
    /// Texts open on the server at once, unused write URLs included; zero is
    /// no limit.
    pub concurrent: usize,
    /// Readers of one text at once, and reads over its life; zero is no
    /// limit.
    pub readers_per_text: usize,
    pub reads_per_text: u32,
}

impl Default for LiveLimits {
    fn default() -> LiveLimits {
        LiveLimits {
            max: Duration::from_secs(120),
            moderator_max: Duration::from_secs(300),
            write_window: Duration::from_secs(120),
            terminal_keep_bytes: 32 << 10,
            max_input_bytes: 2 << 20,
            append_max_bytes: 4096,
            starts_per_user: 3,
            starts_per_ip: 6,
            start_window: Duration::from_mins(10),
            starts_per_user_day: 20,
            starts_per_day: 100,
            concurrent: 4,
            readers_per_text: 10,
            reads_per_text: 30,
        }
    }
}

/// Refuses a new terminal or append embed, or its commands, while live text
/// is off.
pub const LIVE_TEXT_OFF: &str = "Live text is turned off here";

/// Roles whose holders stream for `moderator_max` rather than `max`.
pub const LIVE_TEXT_LONG_ROLES: &[&str] = &["admin", "mod"];

/// §4.8.6's `keep_last`, exactly: the last `limit` bytes, starting at their
/// first byte below 0x20 (a control character), or else at their first byte
/// outside 0x80–0xBF, so no partial character starts the text.
pub fn keep_last(output: &[u8], limit: usize) -> &[u8] {
    if output.len() <= limit {
        return output;
    }
    let tail = &output[output.len() - limit..];
    if let Some(at) = tail.iter().position(|&b| b < 0x20) {
        return &tail[at..];
    }
    let start = tail
        .iter()
        .position(|&b| !(0x80..=0xbf).contains(&b))
        .unwrap_or(tail.len());
    &tail[start..]
}

/// §4.8.5: the first `limit` bytes, cut back to a whole UTF-8 character.
pub fn keep_first(text: &[u8], limit: usize) -> &[u8] {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    // A continuation byte at the cut belongs to a character that starts
    // before it.
    while end > 0 && text[end] & 0xc0 == 0x80 {
        end -= 1;
    }
    &text[..end]
}

/// Kept bytes as text, with the WHATWG Encoding Standard's UTF-8 decode
/// without BOM (§4.8.3): each maximal invalid subsequence, and an incomplete
/// one at the end, is one U+FFFD, and a leading BOM is kept, as a client's
/// streaming decoder shows it. `String::from_utf8_lossy` substitutes by
/// maximal subparts, which is that rule.
pub fn live_text_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The largest finished terminal `output`, in bytes of JSON: a control
/// character escapes to six (`\u001b`), so the kept bytes are cut further
/// while escaping would pass it, and one record always fits a history
/// response.
pub const MAX_TERMINAL_OUTPUT_JSON_BYTES: usize = 128 << 10;

/// A finished terminal's `output` (§4.8.6): the kept bytes as text, cut
/// further with `keep_last` while their JSON passes
/// MAX_TERMINAL_OUTPUT_JSON_BYTES.
pub fn terminal_output(bytes: &[u8]) -> String {
    let mut kept = bytes;
    loop {
        let text = live_text_string(kept);
        if encoded_size(&Json::from(text.as_str())) <= MAX_TERMINAL_OUTPUT_JSON_BYTES {
            return text;
        }
        kept = keep_last(kept, kept.len() * 3 / 4);
    }
}

/// A byte count as people read it: 4 KB, 32 KB, 2 MB, 4,000 bytes.
pub fn byte_size(bytes: usize) -> String {
    if bytes >= 1 << 20 && bytes.is_multiple_of(1 << 20) {
        return format!("{} MB", bytes >> 20);
    }
    if bytes >= 1 << 10 && bytes.is_multiple_of(1 << 10) {
        return format!("{} KB", bytes >> 10);
    }
    let digits = bytes.to_string();
    let mut grouped = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(c);
    }
    format!("{grouped} bytes")
}

/// A duration as people read it: 2 minutes, 90 seconds.
fn duration_text(d: Duration) -> String {
    let seconds = d.as_nanos() / time::SECOND.as_nanos();
    if seconds % 60 == 0 {
        let minutes = seconds / 60;
        return format!("{minutes} minute{}", if minutes == 1 { "" } else { "s" });
    }
    format!("{seconds} seconds")
}

const LIVE_NOTICE_FOOTER: &str = "The message appears when the stream starts. At a limit the stream ends, and so does the command feeding it. The link works once, and anyone with it can stream as you, so don't share it.";

/// The `~private` notice that answers `/embed-terminal` and `/embed-append`
/// (Appendix A.1): the write URL in copy-paste recipes, with the limits that
/// apply to this user.
pub fn command_notice(
    kind: LiveKind,
    write_url: &str,
    max: Duration,
    limit: usize,
    limits: &LiveLimits,
) -> String {
    let window = duration_text(limits.write_window);
    let seconds = max.as_nanos() / time::SECOND.as_nanos();
    let url = format!("'{write_url}'");
    match kind {
        LiveKind::Terminal => [
            format!(
                "Stream a terminal into this room within {window} (80×40, up to {seconds} seconds and {}; the last {} is kept):",
                byte_size(limits.max_input_bytes),
                byte_size(limit)
            ),
            String::new(),
            "```sh".into(),
            format!("script -qfc 'stty cols 80 rows 40; YOUR_COMMAND' /dev/null | curl -sT - {url}"),
            "```".into(),
            String::new(),
            "On macOS:".into(),
            String::new(),
            "```sh".into(),
            format!("script -q /dev/null sh -c 'stty cols 80 rows 40; YOUR_COMMAND' | curl -sT - {url}"),
            "```".into(),
            String::new(),
            LIVE_NOTICE_FOOTER.into(),
        ]
        .join("\n"),
        LiveKind::Append => [
            format!(
                "Stream text into this room within {window} (up to {seconds} seconds and {}; it is appended to your message as markdown, revised by backspace and form feed):",
                byte_size(limit)
            ),
            String::new(),
            "```sh".into(),
            format!("your-llm-command | curl -sT - {url}"),
            "```".into(),
            String::new(),
            LIVE_NOTICE_FOOTER.into(),
        ]
        .join("\n"),
    }
}

/// The kept bytes of one text (apron-server-cloudflare's LiveBuffer): the
/// last part for a terminal; for an append, its text so far as decoded and
/// edited (§4.8.5), re-encoded as UTF-8, its first part.
#[derive(Debug)]
pub struct LiveBuffer {
    kind: LiveKind,
    /// The most kept: a terminal's keep bytes, or the bytes an append may
    /// add.
    limit: usize,
    /// Bytes received in all, kept or not.
    pub received: usize,
    /// An append that reached its limit keeps nothing more.
    pub full: bool,
    bytes: Vec<u8>,
    /// An append's bytes of a character split across chunks, which the next
    /// chunk completes.
    partial: Vec<u8>,
}

impl LiveBuffer {
    pub fn new(kind: LiveKind, limit: usize) -> LiveBuffer {
        LiveBuffer {
            kind,
            limit,
            received: 0,
            full: false,
            bytes: Vec::new(),
            partial: Vec::new(),
        }
    }

    /// Takes a chunk and returns the bytes readers get now: a terminal's
    /// chunk; for an append, the whole characters it decoded up to its
    /// limit, edits included (clients apply them), so a reader that
    /// connects later can follow the edited text.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.received += chunk.len();
        match self.kind {
            LiveKind::Terminal => {
                self.bytes.extend_from_slice(chunk);
                // A terminal compacts when its buffer holds twice what it
                // keeps, so each byte is copied a bounded number of times:
                // keep_last is stable, so cutting early and again later
                // keeps what one cut at the end keeps.
                if self.bytes.len() > 2 * self.limit {
                    let kept = keep_last(&self.bytes, self.limit).to_vec();
                    self.bytes = kept;
                }
                chunk.to_vec()
            }
            LiveKind::Append => {
                if self.full {
                    return Vec::new();
                }
                let mut input = std::mem::take(&mut self.partial);
                input.extend_from_slice(chunk);
                let text = self.decode_stream(&input);
                self.append(&text)
            }
        }
    }

    /// Decodes an append's bytes as WHATWG's streaming UTF-8 decode does:
    /// each maximal invalid subsequence reads as U+FFFD, and an incomplete
    /// character at the end waits for the next chunk.
    fn decode_stream(&mut self, mut input: &[u8]) -> String {
        let mut text = String::new();
        loop {
            match std::str::from_utf8(input) {
                Ok(valid) => {
                    text.push_str(valid);
                    return text;
                }
                Err(e) => {
                    let (valid, rest) = input.split_at(e.valid_up_to());
                    text.push_str(std::str::from_utf8(valid).expect("checked"));
                    match e.error_len() {
                        Some(n) => {
                            text.push('\u{FFFD}');
                            input = &rest[n..];
                        }
                        None => {
                            self.partial = rest.to_vec();
                            return text;
                        }
                    }
                }
            }
        }
    }

    /// Ends an append's text: a character left incomplete reads as U+FFFD
    /// (§4.8.3), unless the write was `cut` at its input limit, which keeps
    /// the text up to a whole character (§4.8.5). Returns what readers get
    /// of it.
    pub fn end(&mut self, cut: bool) -> Vec<u8> {
        let partial = std::mem::take(&mut self.partial);
        if self.kind != LiveKind::Append || self.full || cut || partial.is_empty() {
            return Vec::new();
        }
        self.append("\u{FFFD}")
    }

    /// Adds decoded text to an append (§4.8.5): backspace removes the code
    /// point before it, never reaching before the live text, and form feed
    /// removes all of it. The limit counts the edited text: at the first
    /// character that does not fit, the append is full.
    fn append(&mut self, text: &str) -> Vec<u8> {
        let before = self.bytes.len();
        let mut edited = false;
        let mut read = 0;
        for (at, c) in text.char_indices() {
            match c {
                '\u{0C}' => {
                    self.bytes.clear();
                    edited = true;
                }
                '\u{08}' => {
                    while let Some(b) = self.bytes.pop() {
                        if b & 0xc0 != 0x80 {
                            break;
                        }
                    }
                    edited = true;
                }
                c => {
                    if self.bytes.len() + c.len_utf8() > self.limit {
                        self.full = true;
                        break;
                    }
                    let mut buf = [0u8; 4];
                    self.bytes
                        .extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
            }
            read = at + c.len_utf8();
        }
        // Without edits, readers get what was added; with them, the text
        // that was read, edits and all.
        if edited {
            text.as_bytes()[..read].to_vec()
        } else {
            self.bytes[before..].to_vec()
        }
    }

    /// What is kept now: what a reader that connects gets first, and what
    /// the text publishes when it ends.
    pub fn kept(&self) -> &[u8] {
        match self.kind {
            LiveKind::Terminal => keep_last(&self.bytes, self.limit),
            LiveKind::Append => &self.bytes,
        }
    }
}

/// Bytes a reader may fall behind before it is dropped, so a stalled one
/// cannot grow the server's memory.
pub const MAX_READER_BACKLOG_BYTES: usize = 256 << 10;
/// How long a reader's bytes wait to go together, and how many may wait: a
/// writer in a pseudo-terminal sends a chunk per line or less.
pub const READER_FLUSH: Duration = Duration::from_millis(50);
pub const READER_FLUSH_BYTES: usize = 16 << 10;

/// One text while it streams, shared by its writer, its readers and the
/// server state: what is kept, what readers have yet to read, and how it
/// ended.
#[derive(Debug)]
pub struct LiveText {
    kind: LiveKind,
    max_input: usize,
    inner: Mutex<LiveInner>,
    changed: Condvar,
}

#[derive(Debug)]
struct LiveInner {
    buffer: LiveBuffer,
    /// Bytes readers have yet to read, from absolute offset `start`;
    /// `total` is the offset after the last.
    log: Vec<u8>,
    start: usize,
    total: usize,
    /// Counts changes, so a reader waits for one past the version it saw.
    version: u64,
    end: Option<LiveEnd>,
    /// Set once the writer's body ended.
    writer_done: bool,
    /// Readers now, and reads served over the text's life.
    readers: usize,
    served: u32,
}

/// Why a reader is refused (§4.8.3, SPEC section 4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReaderRefusal {
    TooMany,
    TooOften,
}

/// A reader's next step.
pub enum ReadStep {
    /// Nothing arrived within the wait.
    Nothing,
    /// The reader fell MAX_READER_BACKLOG_BYTES behind and is dropped.
    Behind,
    Chunk {
        bytes: Vec<u8>,
        next: usize,
        ended: bool,
    },
}

impl LiveInner {
    /// Queues bytes for the readers, dropping what the slowest may no longer
    /// catch up on.
    fn send(&mut self, bytes: &[u8]) {
        self.log.extend_from_slice(bytes);
        self.total += bytes.len();
        if self.log.len() > MAX_READER_BACKLOG_BYTES {
            let excess = self.log.len() - MAX_READER_BACKLOG_BYTES;
            self.log.drain(..excess);
            self.start += excess;
        }
    }

    /// Records why the text ended, once; an append's last incomplete
    /// character reads as U+FFFD for its readers too, unless the write was
    /// cut at its limit.
    fn finish(&mut self, why: LiveEnd) {
        if self.end.is_none() {
            let rest = self.buffer.end(why == LiveEnd::Size);
            self.send(&rest);
            self.end = Some(why);
        }
    }
}

impl LiveText {
    pub fn new(kind: LiveKind, limit: usize, max_input: usize) -> LiveText {
        LiveText {
            kind,
            max_input,
            inner: Mutex::new(LiveInner {
                buffer: LiveBuffer::new(kind, limit),
                log: Vec::new(),
                start: 0,
                total: 0,
                version: 0,
                end: None,
                writer_done: false,
                readers: 0,
                served: 0,
            }),
            changed: Condvar::new(),
        }
    }

    pub fn kind(&self) -> LiveKind {
        self.kind
    }

    fn lock(&self) -> MutexGuard<'_, LiveInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes a chunk of the writer's body: what the kind keeps goes to the
    /// buffer, what readers get to the log. Reports whether the text goes
    /// on: it ends at the input cap, at an append's limit, or when ended
    /// meanwhile.
    pub fn write(&self, chunk: &[u8]) -> bool {
        let mut b = self.lock();
        if b.end.is_some() {
            return false;
        }
        let room = self.max_input.saturating_sub(b.buffer.received);
        let chunk = &chunk[..chunk.len().min(room)];
        let send = b.buffer.push(chunk);
        b.send(&send);
        if b.buffer.full || b.buffer.received >= self.max_input {
            b.finish(LiveEnd::Size);
        }
        b.version += 1;
        self.changed.notify_all();
        b.end.is_none()
    }

    /// Ends the text, the first reason winning.
    pub fn end(&self, why: LiveEnd) {
        let mut b = self.lock();
        if b.end.is_none() {
            b.finish(why);
            b.version += 1;
            self.changed.notify_all();
        }
    }

    pub fn ended(&self) -> Option<LiveEnd> {
        self.lock().end
    }

    pub fn kept(&self) -> Vec<u8> {
        self.lock().buffer.kept().to_vec()
    }

    fn writer_done(&self) {
        let mut b = self.lock();
        b.writer_done = true;
        b.version += 1;
        self.changed.notify_all();
    }

    /// Waits until the writer's body ends or the text ends, reporting
    /// whether the body ended.
    fn wait_writer(&self) -> bool {
        let b = self.lock();
        let b = self
            .changed
            .wait_while(b, |b| !b.writer_done && b.end.is_none())
            .unwrap_or_else(|e| e.into_inner());
        b.writer_done
    }

    /// Admits a reader within `limits`: the kept bytes it starts with and
    /// the offset it reads on from.
    pub fn open_reader(&self, limits: &LiveLimits) -> Result<(Vec<u8>, usize), ReaderRefusal> {
        let mut b = self.lock();
        if limits.reads_per_text > 0 && b.served >= limits.reads_per_text {
            return Err(ReaderRefusal::TooOften);
        }
        if limits.readers_per_text > 0 && b.readers >= limits.readers_per_text {
            return Err(ReaderRefusal::TooMany);
        }
        b.served += 1;
        b.readers += 1;
        Ok((b.buffer.kept().to_vec(), b.total))
    }

    pub fn close_reader(&self) {
        self.lock().readers -= 1;
    }

    /// What a reader at `position` gets next, waiting up to `wait` for
    /// something to arrive, and then up to READER_FLUSH for more to go with
    /// it, unless READER_FLUSH_BYTES wait or the text has ended.
    pub fn read(&self, position: usize, wait: Duration) -> ReadStep {
        let std_wait = |d: Duration| std::time::Duration::from_nanos(d.as_nanos().max(0) as u64);
        let b = self.lock();
        let quiet = |b: &LiveInner| b.total == position && b.end.is_none();
        let (mut b, _) = self
            .changed
            .wait_timeout_while(b, std_wait(wait), |b| quiet(b))
            .unwrap_or_else(|e| e.into_inner());
        if quiet(&b) {
            return ReadStep::Nothing;
        }
        let small = |b: &LiveInner| b.end.is_none() && b.total - position < READER_FLUSH_BYTES;
        if small(&b) {
            (b, _) = self
                .changed
                .wait_timeout_while(b, std_wait(READER_FLUSH), |b| small(b))
                .unwrap_or_else(|e| e.into_inner());
        }
        if position < b.start {
            return ReadStep::Behind;
        }
        ReadStep::Chunk {
            bytes: b.log[position - b.start..].to_vec(),
            next: b.total,
            ended: b.end.is_some(),
        }
    }
}

/// The headers of a live text's `url` (§4.8.3), readable from any origin.
/// `no-transform` keeps a proxy from compressing it: compression buffers
/// the stream, so readers would see nothing until the end. With a terminal
/// viewer, readers that fetch it get the text, and a browser that opens it
/// as a page the viewer, so it varies with `Sec-Fetch-Mode`.
fn set_live_headers(w: &mut dyn ResponseWriter, viewer: bool) {
    let header = w.header();
    if viewer {
        header.set("Vary", "Sec-Fetch-Mode");
    }
    header.set("Content-Type", "text/plain; charset=utf-8");
    header.set("X-Content-Type-Options", "nosniff");
    header.set("Cache-Control", "no-store, no-transform");
    header.set("Access-Control-Allow-Origin", "*");
    header.set("Content-Security-Policy", "default-src 'none'");
}

/// A plain-text answer to a live text's writer or reader, readable in a
/// terminal, from any origin.
fn live_answer(w: &mut dyn ResponseWriter, status: u16, message: &str, retry_after: Option<i64>) {
    let header = w.header();
    header.set("Content-Type", "text/plain; charset=utf-8");
    header.set("X-Content-Type-Options", "nosniff");
    header.set("Cache-Control", "no-store");
    header.set("Access-Control-Allow-Origin", "*");
    header.set("Access-Control-Expose-Headers", "Retry-After");
    if let Some(seconds) = retry_after {
        header.set("Retry-After", &seconds.to_string());
    }
    w.write_header(status);
    let _ = io::Write::write_all(w, format!("{message}\n").as_bytes());
}

/// What `finish_live_locked` found: the text's kind and limits, for the
/// writer's answer, and whether anything was published.
pub struct Finished {
    pub kind: LiveKind,
    pub limit: usize,
    pub max: Duration,
    pub published: bool,
}

impl Server {
    /// Copies a live text's `PUT` body into it until the text ends: the
    /// body ends, a limit is reached, the embed is removed, or the server
    /// stops (§4.8.3). Then publishes what was kept, once, and answers the
    /// writer in plain text.
    pub(super) fn write_live(
        self: &Arc<Self>,
        w: &mut dyn ResponseWriter,
        r: &mut HttpRequest,
        id: &str,
        text: &Arc<LiveText>,
    ) {
        // The answer may come before the body ends, as at a limit.
        let _ = ResponseController::new(w).enable_full_duplex();
        let reader = r.body.take().map(|mut body| {
            let text = text.clone();
            thread::spawn(move || {
                let mut buf = vec![0u8; 32 << 10];
                let why = loop {
                    match body.read(&mut buf) {
                        Ok(0) => break LiveEnd::Complete,
                        Err(_) => break LiveEnd::Disconnected,
                        Ok(n) => {
                            if !text.write(&buf[..n]) {
                                break LiveEnd::Size;
                            }
                        }
                    }
                };
                text.writer_done();
                why
            })
        });
        let Some(reader) = reader else {
            text.end(LiveEnd::Complete);
            self.answer_live_write(w, id, text);
            return;
        };
        let body_done = text.wait_writer();
        if !body_done || text.ended() == Some(LiveEnd::Size) {
            // Unblock a body read still waiting on the writer, and let it
            // finish, or leave the rest of a body past a limit unread. The
            // expired deadline also cancels the connection, so the
            // connection must not serve another request.
            w.header().set("Connection", "close");
            let _ = ResponseController::new(w).set_read_deadline(&time::now());
        }
        let why = reader.join().unwrap_or(LiveEnd::Disconnected);
        text.end(why);
        self.answer_live_write(w, id, text);
    }

    fn answer_live_write(self: &Arc<Self>, w: &mut dyn ResponseWriter, id: &str, text: &LiveText) {
        let end = text.ended().expect("ended before it is answered");
        let finished = if end == LiveEnd::Unavailable {
            None
        } else {
            self.lock().finish_live_locked(id)
        };
        let limits = &self.config.live;
        let (status, message) = match finished {
            Some(f) => end.response(f.published, f.kind, f.limit, f.max, limits),
            None => end.response(false, text.kind(), 0, limits.max, limits),
        };
        let retry_after = (status == http::STATUS_SERVICE_UNAVAILABLE)
            .then_some(super::config::RETRY_AFTER_SECONDS);
        live_answer(w, status, &message, retry_after);
    }

    /// Serves a live text at its `url` (§4.8.3): the kept text, then more as
    /// it arrives, in batches, until the text ends. The url exists from the
    /// write's start (§4.8.5); an ended or unknown text is 404.
    pub(crate) fn handle_live(self: &Arc<Self>, w: &mut dyn ResponseWriter, r: &mut HttpRequest) {
        if r.method == http::METHOD_OPTIONS {
            let header = w.header();
            header.set("Access-Control-Allow-Origin", "*");
            header.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
            header.set("Access-Control-Max-Age", "86400");
            w.write_header(http::STATUS_NO_CONTENT);
            return;
        }
        if r.method != http::METHOD_GET && r.method != http::METHOD_HEAD {
            live_answer(
                w,
                http::STATUS_METHOD_NOT_ALLOWED,
                "Method not allowed",
                None,
            );
            return;
        }
        let secret = r.url.path.strip_prefix(LIVE_PATH).unwrap_or("").to_owned();
        let found = {
            let st = self.lock();
            st.live_ids
                .get(&secret)
                .and_then(|id| st.embeds.get(id))
                .and_then(|e| Some((e.live.as_ref()?.text.clone(), e.live_url())))
        };
        let Some((text, url)) = found else {
            live_answer(
                w,
                http::STATUS_NOT_FOUND,
                "This live text has ended, or never existed",
                None,
            );
            return;
        };
        let viewer = self.terminal_viewer(text.kind(), &url);
        if let Some(viewer) = viewer.filter(|_| {
            r.method == http::METHOD_GET && r.header.get("Sec-Fetch-Mode") == Some("navigate")
        }) {
            // The url goes in the fragment, which never reaches the
            // viewer's host (§4.8.5, §5.5); a redirect is no read.
            let header = w.header();
            header.set(
                "Location",
                &format!("{viewer}#stream={}", url::query_escape(&url)),
            );
            header.set("Cache-Control", "no-store");
            header.set("Vary", "Sec-Fetch-Mode");
            w.write_header(http::STATUS_FOUND);
            return;
        }
        if r.method == http::METHOD_HEAD {
            set_live_headers(w, viewer.is_some());
            w.write_header(http::STATUS_OK);
            return;
        }
        let (initial, mut position) = match text.open_reader(&self.config.live) {
            Ok(opened) => opened,
            Err(ReaderRefusal::TooOften) => {
                live_answer(
                    w,
                    http::STATUS_FORBIDDEN,
                    "This live text has been read as often as it may be",
                    None,
                );
                return;
            }
            Err(ReaderRefusal::TooMany) => {
                live_answer(
                    w,
                    http::STATUS_TOO_MANY_REQUESTS,
                    "This live text has as many readers as it may have",
                    Some(10),
                );
                return;
            }
        };
        set_live_headers(w, viewer.is_some());
        w.write_header(http::STATUS_OK);
        // A reader before the first bytes sees its headers now, and waits.
        if !initial.is_empty() && io::Write::write_all(w, &initial).is_err() {
            text.close_reader();
            return;
        }
        let _ = ResponseController::new(w).flush();
        let ctx = r.context();
        loop {
            match text.read(position, Duration::from_secs(1)) {
                ReadStep::Nothing => {
                    // The wait is bounded so a reader whose connection went
                    // away is noticed.
                    if ctx.err().is_some() {
                        break;
                    }
                }
                ReadStep::Behind => break,
                ReadStep::Chunk { bytes, next, ended } => {
                    if !bytes.is_empty() && io::Write::write_all(w, &bytes).is_err() {
                        break;
                    }
                    let _ = ResponseController::new(w).flush();
                    position = next;
                    if ended {
                        break;
                    }
                }
            }
        }
        text.close_reader();
    }

    /// The terminal viewer a browser that opens `url` as a page goes to, if
    /// any: only a terminal's, and none for an https viewer when `url` is
    /// http, since the viewer reads only https.
    fn terminal_viewer(&self, kind: LiveKind, url: &str) -> Option<&str> {
        let viewer = self.config.terminal_viewer_url.as_str();
        let unreadable = viewer.starts_with("https:") && !url.starts_with("https:");
        (kind == LiveKind::Terminal && !viewer.is_empty() && !unreadable).then_some(viewer)
    }

    /// A live text's write arrived (§4.8.3): its embed gets its `url`, a
    /// command's message is posted with it now and a message's is
    /// republished with it (§4.8.5), the text starts streaming, and its
    /// time limit starts.
    pub(super) fn start_live_write(
        self: &Arc<Self>,
        w: &mut dyn ResponseWriter,
        r: &mut HttpRequest,
        id: &str,
    ) {
        let text = {
            let mut st = self.lock();
            st.add_live_url_locked(id);
            if let Err(err) = st.post_live_message_locked(id) {
                st.remove_embed_locked(id);
                drop(st);
                refuse_write(
                    w,
                    &format!("This text can no longer be posted: {}", err.message),
                    http::STATUS_GONE,
                );
                return;
            }
            let server = self.clone();
            let ended = id.to_owned();
            let Some(e) = st.embeds.get_mut(id) else {
                drop(st);
                refuse_write(
                    w,
                    "Stopped: the message or its embed was removed.",
                    http::STATUS_GONE,
                );
                return;
            };
            let live = e.live.as_mut().expect("a live embed");
            live.deadline = time::now().add(live.max);
            e.timer = Some(time::after_func(live.max, move || {
                let st = server.lock();
                if let Some(live) = st.embeds.get(&ended).and_then(|e| e.live.as_ref()) {
                    live.text.end(LiveEnd::Time);
                }
            }));
            live.text.clone()
        };
        self.write_live(w, r, id, &text);
    }
}

impl State {
    /// The checks a live text's start makes before anything is charged: the
    /// feature is on, the user has none open, the server has room, and an
    /// append has text room left. Returns what the text keeps.
    pub fn live_start_room_locked(
        &self,
        user_id: &str,
        kind: LiveKind,
        text_bytes: usize,
    ) -> Result<usize, RpcError> {
        if !self.feature_on(super::toggles::Feature::LiveText) {
            return Err(RpcError::new(CODE_DENIED, LIVE_TEXT_OFF));
        }
        let open: Vec<&super::embeds::LiveEmbed> = self
            .embeds
            .values()
            .filter_map(|e| e.live.as_ref())
            .collect();
        if open.iter().any(|live| live.owner == user_id) {
            return Err(RpcError::new(
                CODE_DENIED,
                "You already have a live text open; finish it, or let its write_url expire, before you start another",
            ));
        }
        let limits = &self.config.live;
        if limits.concurrent > 0 && open.len() >= limits.concurrent {
            let soonest = open
                .iter()
                .map(|live| live.deadline.clone())
                .min_by(|a, b| a.unix_nano().cmp(&b.unix_nano()))
                .expect("some are open");
            let wait = soonest.sub(&time::now()).as_nanos() / time::SECOND.as_nanos();
            return Err(super::limits::refused(
                "Live text is busy on this server; try again shortly",
                wait.max(1),
                None,
            ));
        }
        let limit = match kind {
            LiveKind::Terminal => limits.terminal_keep_bytes,
            LiveKind::Append => limits
                .append_max_bytes
                .min(self.config.frame.max_text_bytes.saturating_sub(text_bytes)),
        };
        if limit == 0 {
            return Err(RpcError::new(
                CODE_TOO_LARGE,
                "The message text leaves no room to append to",
            ));
        }
        Ok(limit)
    }

    /// Opens a live text for `user_id` within the limits (§4.8.3, SPEC
    /// section 4.5), charging its start, and returns the embed's id. Its
    /// time limit is the owner's: `moderator_max` for an admin or mod.
    /// `message_id` is empty for a command's text, whose message is posted
    /// when the write arrives.
    pub fn open_live_locked(
        &mut self,
        c: &Arc<Client>,
        user_id: &str,
        kind: LiveKind,
        message_id: &str,
        limit: usize,
    ) -> Result<String, RpcError> {
        self.charge_live_start_locked(c, user_id)?;
        let limits = &self.config.live;
        let u = &self.users[user_id];
        let max = if u.kind() == super::users::Identity::Account
            && u.has_any_role(LIVE_TEXT_LONG_ROLES)
        {
            limits.moderator_max
        } else {
            limits.max
        };
        // An append takes no more input than it keeps, so its edits never
        // let it send more than an append without them.
        let max_input = match kind {
            LiveKind::Terminal => limits.max_input_bytes,
            LiveKind::Append => limits.max_input_bytes.min(limit),
        };
        let write_window = limits.write_window;
        let id = self.next_embed_id();
        self.new_write_locked(c, &id, kind.as_str(), message_id, write_window);
        let e = self.embeds.get_mut(&id).expect("just registered");
        e.live = Some(super::embeds::LiveEmbed {
            kind,
            owner: user_id.to_owned(),
            max,
            limit,
            deadline: time::now().add(write_window),
            post: None,
            text: Arc::new(LiveText::new(kind, limit, max_input)),
        });
        Ok(id)
    }

    /// Gives a live embed its `url` as its write starts (§4.8.5): readers
    /// find the text from then on, and a message's text is republished
    /// with the url, as an upload is with its file's.
    fn add_live_url_locked(&mut self, id: &str) {
        let Some(e) = self.embeds.get_mut(id) else {
            return;
        };
        let url = e.live_url();
        e.owned = obj! {"url" => url.as_str()};
        let (secret, message_id) = (e.secret.clone(), e.message_id.clone());
        self.live_ids.insert(secret, id.to_owned());
        self.touch_embed(id);
        if self.messages.contains_key(&message_id) {
            self.republish_locked(&message_id, |body| {
                replace_embed(
                    body,
                    id,
                    Some(&|embed: &mut Object| {
                        embed.insert("url".into(), url.as_str().into());
                    }),
                )
            });
        }
    }

    pub(super) fn embed_terminal_command(&mut self, cx: &CommandCtx) -> Result<Object, RpcError> {
        self.live_command(cx, LiveKind::Terminal)
    }

    pub(super) fn embed_append_command(&mut self, cx: &CommandCtx) -> Result<Object, RpcError> {
        self.live_command(cx, LiveKind::Append)
    }

    /// `/embed-terminal [title]` and `/embed-append [markdown]` (§4.8.3):
    /// everything is checked and charged now, the post included, and
    /// nothing is posted until the write arrives. The rest of the line is
    /// the terminal's plain title, or the append's opening markdown, which
    /// a paragraph break follows when it is not empty, so the streamed text
    /// starts a new paragraph. The result carries the write URL, after a
    /// `~private` notice with it in copy-paste recipes.
    fn live_command(&mut self, cx: &CommandCtx, kind: LiveKind) -> Result<Object, RpcError> {
        let CommandCtx {
            client: c,
            room_id,
            rest,
            ..
        } = *cx;
        let user_id = cx.user_id.to_owned();
        let (title, text) = match kind {
            LiveKind::Terminal => (rest, String::new()),
            LiveKind::Append => {
                let opening = rest.trim_end();
                let text = if opening.is_empty() {
                    String::new()
                } else {
                    format!("{opening}\n\n")
                };
                ("", text)
            }
        };
        let limit = self.live_start_room_locked(&user_id, kind, text.len())?;
        self.charge_post_locked(c, &user_id, Some(Category::Write))?;
        let id = self.open_live_locked(c, &user_id, kind, "", limit)?;
        let from = self.users[&user_id].from();
        let e = self.embeds.get_mut(&id).expect("just opened");
        e.title = super::embeds::og_line(title, 256).unwrap_or_default();
        let write_url = e.write_url();
        let live = e.live.as_mut().expect("just opened");
        live.post = Some(LivePost {
            room_id: room_id.to_owned(),
            text,
            reply_to: cx.reply_to.map(str::to_owned),
            from,
        });
        let notice = command_notice(kind, &write_url, live.max, live.limit, &self.config.live);
        let result = obj! {
            "embeds" => vec![Json::from(obj! {"embed_id" => id.as_str(), "kind" => kind.as_str(), "write_url" => write_url.as_str()})],
        };
        c.enqueue(&private_notice(&self.rooms[room_id], &notice));
        Ok(result)
    }

    /// Posts a command's message when its write arrives, from the sender,
    /// in the command's room, with the command's `reply_to`: `{text: "",
    /// embeds: [terminal]}` or `{text, format: "markdown", embeds:
    /// [append]}`, a new message that wakes as one does (§4.9), its embed
    /// with the `url` the write's start gave it. A text that was started in
    /// a message needs nothing. Fails when the room or the reply is gone.
    fn post_live_message_locked(&mut self, id: &str) -> Result<(), RpcError> {
        let Some(e) = self.embeds.get(id) else {
            return Ok(());
        };
        let Some(live) = e.live.as_ref() else {
            return Ok(());
        };
        let Some(post) = live.post.clone() else {
            return Ok(());
        };
        let (kind, owner, base_url, title) = (
            live.kind,
            live.owner.clone(),
            e.base_url.clone(),
            e.title.clone(),
        );
        if !self.rooms.contains_key(&post.room_id) {
            return Err(invalid_params(format!(
                "Unknown room {}",
                quote(&post.room_id)
            )));
        }
        if let Some(reply_to) = &post.reply_to {
            if !self.messages.contains_key(reply_to) {
                return Err(invalid_params("reply_to must name an existing message"));
            }
        }
        let log_id = self.next_id_locked();
        let message_id = format_id(log_id);
        let mut embed = obj! {"embed_id" => id, "kind" => kind.as_str()};
        if kind == LiveKind::Terminal {
            embed.insert("og".into(), terminal_og(&title).into());
        }
        if !title.is_empty() {
            embed.insert("title".into(), title.into());
        }
        embed.extend(self.embeds[id].owned.clone());
        let format = match kind {
            LiveKind::Terminal => "plain",
            LiveKind::Append => "markdown",
        };
        let body = obj! {
            "text" => post.text.as_str(),
            "format" => format,
            "embeds" => vec![Json::from(embed)],
        };
        let mut snapshot = obj! {
            "message_id" => message_id.as_str(),
            "log_id" => message_id.as_str(),
            "room_id" => post.room_id.as_str(),
            "from" => post.from.clone(),
            "body" => body,
        };
        if let Some(reply_to) = &post.reply_to {
            snapshot.insert(
                "reply_to".into(),
                obj! {"message_id" => reply_to.as_str()}.into(),
            );
        }
        self.messages.insert(
            message_id.clone(),
            super::messages::MessageState {
                id: message_id.clone(),
                from: post.from,
                owner: owner.clone(),
                ..super::messages::MessageState::default()
            },
        );
        let e = self.embeds.get_mut(id).expect("checked above");
        e.message_id = message_id.clone();
        e.live.as_mut().expect("checked above").post = None;
        self.touch_embed(id);
        self.commit_snapshot_locked(&message_id, snapshot.clone(), log_id);
        self.message_unread_locked(&message_id, None, None);
        self.unread_changed_locked(&owner, &post.room_id);
        self.wake_locked(&message_id, &snapshot, None);
        self.unfurl_locked(&owner, &base_url, &message_id, None, &snapshot);
        Ok(())
    }

    /// Ends a live text once (§4.8.3) and publishes what it kept: a
    /// terminal's message gets its embed with `output` in place of `url`
    /// (§4.8.6), an append's the kept text appended to `body.text` and its
    /// embed removed (§4.8.5); with nothing kept, the embed is removed, and
    /// a message left with neither text nor embeds becomes a tombstone. An
    /// embed that is gone publishes nothing.
    pub fn finish_live_locked(&mut self, id: &str) -> Option<Finished> {
        let e = self.embeds.get_mut(id)?;
        let live = e.live.take()?;
        if let Some(timer) = e.timer.take() {
            timer.stop();
        }
        e.finished = true;
        let (kind, limit, max) = (live.kind, live.limit, live.max);
        let message_id = e.message_id.clone();
        self.live_ids.remove(&e.secret);
        self.touch_embed(id);
        let kept = live.text.kept();
        let published = match kind {
            LiveKind::Terminal => {
                let output = terminal_output(keep_last(&kept, limit));
                if output.is_empty() {
                    self.fail_write_locked(id);
                    false
                } else {
                    self.embeds.get_mut(id).expect("checked above").owned =
                        obj! {"output" => output.as_str()};
                    if self.messages.contains_key(&message_id) {
                        self.republish_locked(&message_id, |body| {
                            replace_embed(
                                body,
                                id,
                                Some(&|embed: &mut Object| {
                                    embed.remove("url");
                                    embed.insert("output".into(), output.as_str().into());
                                }),
                            )
                        });
                    }
                    true
                }
            }
            LiveKind::Append => {
                let base = self
                    .snapshot(&message_id)
                    .get("body")
                    .and_then(Json::as_object)
                    .and_then(|b| b.get("text"))
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .to_owned();
                // A save may have lengthened the text while it streamed: the
                // body stays within the text limit, cut at a whole
                // character. The kept text is edited already (§4.8.5), and
                // never reaches into `base`.
                let room = self.config.frame.max_text_bytes.saturating_sub(base.len());
                let added = live_text_string(keep_first(&kept, limit.min(room)));
                if added.is_empty() {
                    self.fail_write_locked(id);
                    false
                } else {
                    if self.messages.contains_key(&message_id) {
                        let text = format!("{base}{added}");
                        self.republish_locked(&message_id, |body| {
                            body.insert("text".into(), text.as_str().into());
                            replace_embed(body, id, None);
                            true
                        });
                    }
                    self.remove_embed_locked(id);
                    true
                }
            }
        };
        Some(Finished {
            kind,
            limit,
            max,
            published,
        })
    }
}
