//! RFC 6455 WebSockets over a connection hijacked from rust-stdlib's
//! `net/http` server, in place of `github.com/coder/websocket`. It keeps the
//! behavior the Go server relies on: the handshake checks and origin rules
//! of `websocket.Accept`, text and binary messages with fragmentation, a
//! read limit, pings that wait for their pong, and the close status codes
//! coder/websocket sends. There is no permessage-deflate.
//!
//! `dial` is the client side, which the tests use.

use std::fmt;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use rust_stdlib::encoding::base64;
use rust_stdlib::net::http::{self, Request, ResponseWriter};
use rust_stdlib::net::{self, url};
use rust_stdlib::time::{self, Duration, Time};
use rust_stdlib_crypto::sha1;

pub const STATUS_NORMAL_CLOSURE: u16 = 1000;
pub const STATUS_GOING_AWAY: u16 = 1001;
pub const STATUS_PROTOCOL_ERROR: u16 = 1002;
pub const STATUS_UNSUPPORTED_DATA: u16 = 1003;
pub const STATUS_NO_STATUS_RCVD: u16 = 1005;
pub const STATUS_ABNORMAL_CLOSURE: u16 = 1006;
pub const STATUS_INVALID_FRAME_PAYLOAD_DATA: u16 = 1007;
pub const STATUS_POLICY_VIOLATION: u16 = 1008;
pub const STATUS_MESSAGE_TOO_BIG: u16 = 1009;
pub const STATUS_INTERNAL_ERROR: u16 = 1011;

const DEFAULT_READ_LIMIT: i64 = 32768;
/// Bounds the write of a pong or a close frame, as coder/websocket's
/// `handleControl` and `writeClose` do.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const OP_CONTINUATION: u8 = 0;
const OP_TEXT: u8 = 1;
const OP_BINARY: u8 = 2;
const OP_CLOSE: u8 = 8;
const OP_PING: u8 = 9;
const OP_PONG: u8 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    Text,
    Binary,
}

/// Why a read or write failed. `Closed` carries the status code and reason
/// of the close frame that ended the connection, ours or the peer's.
#[derive(Debug)]
pub enum Error {
    Closed { code: u16, reason: String },
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Closed { code, reason } => {
                write!(f, "WebSocket closed: status = {code}, reason = {reason:?}")
            }
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<net::NetError> for Error {
    fn from(e: net::NetError) -> Error {
        Error::Io(e.into())
    }
}

/// `websocket.AcceptOptions`, without subprotocols and compression.
#[derive(Clone, Debug, Default)]
pub struct AcceptOptions {
    /// Disables origin verification.
    pub insecure_skip_verify: bool,
    /// Host patterns of authorized origins, matched case-insensitively with
    /// `path.Match`; a pattern with `://` matches `scheme://host`. The
    /// request host is always authorized.
    pub origin_patterns: Vec<String>,
}

/// One WebSocket connection. Reads happen on one thread; writes may come
/// from several, each frame written whole under a lock. Every write takes
/// its own timeout, which bounds that frame alone, as coder/websocket's
/// per-call contexts do: the connection's write deadline is set for the
/// frame and cleared after it.
pub struct Conn {
    raw: Arc<dyn net::Conn>,
    reader: Mutex<Box<dyn Read + Send>>,
    writer: Mutex<()>,
    client: bool,
    read_limit: AtomicI64,
    closed: AtomicBool,
    pongs: Mutex<Vec<(Vec<u8>, Sender<()>)>>,
    ping_counter: AtomicI64,
    partial: Mutex<Option<(u8, Vec<u8>)>>,
}

struct RawWrite(Arc<dyn net::Conn>);

impl Write for RawWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf).map_err(io::Error::from)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct RawRead(Arc<dyn net::Conn>);

impl Read for RawRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(io::Error::from)
    }
}

impl Conn {
    fn new(raw: Arc<dyn net::Conn>, reader: Box<dyn Read + Send>, client: bool) -> Conn {
        Conn {
            raw,
            reader: Mutex::new(reader),
            writer: Mutex::new(()),
            client,
            read_limit: AtomicI64::new(DEFAULT_READ_LIMIT),
            closed: AtomicBool::new(false),
            pongs: Mutex::new(Vec::new()),
            ping_counter: AtomicI64::new(0),
            partial: Mutex::new(None),
        }
    }

    /// Sets the largest message `read` accepts; past it the connection is
    /// closed with `STATUS_MESSAGE_TOO_BIG`. -1 disables the limit.
    pub fn set_read_limit(&self, n: i64) {
        self.read_limit.store(n, Ordering::Relaxed);
    }

    pub fn set_read_deadline(&self, t: &Time) -> Result<(), Error> {
        Ok(self.raw.set_read_deadline(t)?)
    }

    /// Reads the next data message, answering pings and closes on the way.
    pub fn read(&self) -> Result<(MessageType, Vec<u8>), Error> {
        let mut reader = self.reader.lock().unwrap();
        loop {
            let frame = match self.read_frame(&mut **reader) {
                Ok(frame) => frame,
                Err(ReadError::Protocol(reason)) => {
                    return Err(self.fail(STATUS_PROTOCOL_ERROR, &reason))
                }
                Err(ReadError::Io(e)) => {
                    if self.closed.load(Ordering::Relaxed) {
                        return Err(Error::Closed {
                            code: STATUS_ABNORMAL_CLOSURE,
                            reason: String::new(),
                        });
                    }
                    return Err(Error::Io(e));
                }
            };
            match frame.opcode {
                OP_PING => {
                    self.write_frame(OP_PONG, &frame.payload, CONTROL_TIMEOUT)?;
                }
                OP_PONG => {
                    let mut pongs = self.pongs.lock().unwrap();
                    if let Some(i) = pongs.iter().position(|(p, _)| *p == frame.payload) {
                        let (_, tx) = pongs.remove(i);
                        let _ = tx.send(());
                    }
                }
                OP_CLOSE => {
                    let (code, reason) = match parse_close(&frame.payload) {
                        Ok(close) => close,
                        Err(reason) => return Err(self.fail(STATUS_PROTOCOL_ERROR, &reason)),
                    };
                    // The peer's close is echoed with its own code and
                    // reason, as coder/websocket does, then the connection
                    // ends.
                    let _ =
                        self.write_frame(OP_CLOSE, &close_payload(code, &reason), CONTROL_TIMEOUT);
                    self.close_now();
                    return Err(Error::Closed { code, reason });
                }
                OP_TEXT | OP_BINARY | OP_CONTINUATION => {
                    let mut partial = self.partial.lock().unwrap();
                    let message = match (frame.opcode, partial.take()) {
                        (OP_CONTINUATION, None) => {
                            return Err(self.fail(
                                STATUS_PROTOCOL_ERROR,
                                "received continuation frame without text or binary frame",
                            ))
                        }
                        (OP_CONTINUATION, Some((op, mut buf))) => {
                            buf.extend_from_slice(&frame.payload);
                            (op, buf)
                        }
                        (op, Some(_)) => {
                            let _ = op;
                            return Err(self.fail(
                                STATUS_PROTOCOL_ERROR,
                                "received new data frame without finishing the previous frame",
                            ));
                        }
                        (op, None) => (op, frame.payload),
                    };
                    let limit = self.read_limit.load(Ordering::Relaxed);
                    if limit >= 0 && message.1.len() as i64 > limit {
                        return Err(self.fail(
                            STATUS_MESSAGE_TOO_BIG,
                            &format!("read limited at {} bytes", limit + 1),
                        ));
                    }
                    if !frame.fin {
                        *partial = Some(message);
                        continue;
                    }
                    let (op, payload) = message;
                    if op == OP_TEXT {
                        if std::str::from_utf8(&payload).is_err() {
                            return Err(self.fail(
                                STATUS_INVALID_FRAME_PAYLOAD_DATA,
                                "invalid UTF-8 received",
                            ));
                        }
                        return Ok((MessageType::Text, payload));
                    }
                    return Ok((MessageType::Binary, payload));
                }
                op => {
                    return Err(self.fail(
                        STATUS_PROTOCOL_ERROR,
                        &format!("received unknown opcode {op}"),
                    ))
                }
            }
        }
    }

    fn read_frame(&self, reader: &mut dyn Read) -> Result<Frame, ReadError> {
        let mut head = [0u8; 2];
        reader.read_exact(&mut head)?;
        let fin = head[0] & 0x80 != 0;
        if head[0] & 0x70 != 0 {
            return Err(ReadError::Protocol(
                "received header with unexpected rsv bits set".into(),
            ));
        }
        let opcode = head[0] & 0x0f;
        let masked = head[1] & 0x80 != 0;
        let mut len = (head[1] & 0x7f) as u64;
        if len == 126 {
            let mut b = [0u8; 2];
            reader.read_exact(&mut b)?;
            len = u16::from_be_bytes(b) as u64;
        } else if len == 127 {
            let mut b = [0u8; 8];
            reader.read_exact(&mut b)?;
            len = u64::from_be_bytes(b);
        }
        if masked == self.client {
            return Err(ReadError::Protocol(if masked {
                "client got masked frame".into()
            } else {
                "server got unmasked frame".into()
            }));
        }
        let control = opcode >= OP_CLOSE;
        if control && (len > 125 || !fin) {
            return Err(ReadError::Protocol(
                "received control frame with invalid length or fragmentation".into(),
            ));
        }
        let limit = self.read_limit.load(Ordering::Relaxed);
        if !control && limit >= 0 && len > (limit as u64).saturating_add(1) {
            // A frame far past the limit is refused before it is read.
            return Err(ReadError::Protocol(format!(
                "read limited at {} bytes",
                limit + 1
            )));
        }
        let mut mask = [0u8; 4];
        if masked {
            reader.read_exact(&mut mask)?;
        }
        let mut payload = vec![0u8; len as usize];
        reader.read_exact(&mut payload)?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        Ok(Frame {
            fin,
            opcode,
            payload,
        })
    }

    /// Sends a close frame with `code` and `reason`, then closes the
    /// connection, and reports the failure to the reader.
    fn fail(&self, code: u16, reason: &str) -> Error {
        let _ = self.write_frame(OP_CLOSE, &close_payload(code, reason), CONTROL_TIMEOUT);
        self.close_now();
        Error::Closed {
            code,
            reason: reason.to_owned(),
        }
    }

    /// Writes one data message, failing if it takes longer than `timeout`.
    pub fn write(&self, typ: MessageType, payload: &[u8], timeout: Duration) -> Result<(), Error> {
        let op = match typ {
            MessageType::Text => OP_TEXT,
            MessageType::Binary => OP_BINARY,
        };
        self.write_frame(op, payload, timeout)
    }

    fn write_frame(&self, opcode: u8, payload: &[u8], timeout: Duration) -> Result<(), Error> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed {
                code: STATUS_ABNORMAL_CLOSURE,
                reason: String::new(),
            });
        }
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | opcode);
        let mask_bit = if self.client { 0x80 } else { 0 };
        if payload.len() < 126 {
            frame.push(mask_bit | payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            frame.push(mask_bit | 126);
            frame.extend((payload.len() as u16).to_be_bytes());
        } else {
            frame.push(mask_bit | 127);
            frame.extend((payload.len() as u64).to_be_bytes());
        }
        if self.client {
            let mut mask = [0u8; 4];
            rust_stdlib_crypto::rand::read(&mut mask);
            frame.extend(mask);
            frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        } else {
            frame.extend_from_slice(payload);
        }
        // The deadline is set and cleared under the lock, so it never
        // outlives this frame or bounds another writer's.
        let _guard = self.writer.lock().unwrap();
        self.raw.set_write_deadline(&time::now().add(timeout))?;
        let written = RawWrite(self.raw.clone()).write_all(&frame);
        let _ = self.raw.set_write_deadline(&Time::default());
        Ok(written?)
    }

    /// Sends a ping and waits for its pong, which `read` on another thread
    /// receives. `timeout` bounds the write and the wait together, as the
    /// context of coder/websocket's `Ping` does.
    pub fn ping(&self, timeout: Duration) -> Result<(), Error> {
        let deadline = time::now().add(timeout);
        let n = self.ping_counter.fetch_add(1, Ordering::Relaxed);
        let payload = n.to_string().into_bytes();
        let (tx, rx): (Sender<()>, Receiver<()>) = mpsc::channel();
        self.pongs.lock().unwrap().push((payload.clone(), tx));
        if let Err(e) = self.write_frame(OP_PING, &payload, timeout) {
            self.pongs.lock().unwrap().retain(|(p, _)| *p != payload);
            return Err(e);
        }
        let left = time::until(&deadline).as_nanos().max(0) as u64;
        let waited = rx.recv_timeout(std::time::Duration::from_nanos(left));
        if waited.is_ok() {
            return Ok(());
        }
        self.pongs.lock().unwrap().retain(|(p, _)| *p != payload);
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed {
                code: STATUS_ABNORMAL_CLOSURE,
                reason: String::new(),
            });
        }
        Err(Error::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "ping timed out waiting for pong",
        )))
    }

    /// Sends a close frame, then closes the connection without waiting for
    /// the peer's close.
    pub fn close(&self, code: u16, reason: &str) -> Result<(), Error> {
        let written = self.write_frame(OP_CLOSE, &close_payload(code, reason), CONTROL_TIMEOUT);
        self.close_now();
        written
    }

    /// Closes the connection at once, without a close frame. A blocked read
    /// on another thread fails.
    pub fn close_now(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self.raw.close();
        }
    }
}

struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

enum ReadError {
    Protocol(String),
    Io(io::Error),
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> ReadError {
        ReadError::Io(e)
    }
}

/// The payload of a close frame. 1005 says no status was received and must
/// not be sent (RFC 6455 §7.4.1), so it is an empty payload, as in
/// coder/websocket's `writeClose`.
fn close_payload(code: u16, reason: &str) -> Vec<u8> {
    if code == STATUS_NO_STATUS_RCVD {
        return Vec::new();
    }
    let mut payload = Vec::with_capacity(2 + reason.len());
    payload.extend(code.to_be_bytes());
    payload.extend_from_slice(reason.as_bytes());
    payload.truncate(125);
    payload
}

fn parse_close(payload: &[u8]) -> Result<(u16, String), String> {
    match payload.len() {
        0 => Ok((STATUS_NO_STATUS_RCVD, String::new())),
        1 => Err("close payload too small, need at least 2 bytes".into()),
        _ => {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            if !valid_close_code(code) {
                return Err(format!("received invalid status code {code}"));
            }
            let reason = std::str::from_utf8(&payload[2..])
                .map_err(|_| "invalid UTF-8 in close reason".to_owned())?;
            Ok((code, reason.to_owned()))
        }
    }
}

fn valid_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1011 | 3000..=4999)
}

fn accept_key(key: &str) -> String {
    base64::STANDARD.encode(sha1::sum(format!("{key}{GUID}").as_bytes()))
}

fn header_contains_token_ignore_case(r: &Request, name: &str, token: &str) -> bool {
    r.header
        .values(name)
        .iter()
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

/// The handshake checks of coder/websocket's `verifyClientRequest`, with the
/// HTTP status each failure answers with.
fn verify_client_request(w: &mut dyn ResponseWriter, r: &Request) -> Result<String, (u16, String)> {
    if !r.proto_at_least(1, 1) {
        return Err((
            http::STATUS_UPGRADE_REQUIRED,
            format!(
                "WebSocket protocol violation: handshake request must be at least HTTP/1.1: {:?}",
                r.proto
            ),
        ));
    }
    if !header_contains_token_ignore_case(r, "Connection", "Upgrade") {
        w.header().set("Connection", "Upgrade");
        w.header().set("Upgrade", "websocket");
        return Err((
            http::STATUS_UPGRADE_REQUIRED,
            format!(
                "WebSocket protocol violation: Connection header {:?} does not contain Upgrade",
                r.header.get("Connection").unwrap_or("")
            ),
        ));
    }
    if !header_contains_token_ignore_case(r, "Upgrade", "websocket") {
        w.header().set("Connection", "Upgrade");
        w.header().set("Upgrade", "websocket");
        return Err((
            http::STATUS_UPGRADE_REQUIRED,
            format!(
                "WebSocket protocol violation: Upgrade header {:?} does not contain websocket",
                r.header.get("Upgrade").unwrap_or("")
            ),
        ));
    }
    if r.method != "GET" {
        return Err((
            http::STATUS_METHOD_NOT_ALLOWED,
            format!(
                "WebSocket protocol violation: handshake request method is not GET but {:?}",
                r.method
            ),
        ));
    }
    if r.header.get("Sec-WebSocket-Version") != Some("13") {
        w.header().set("Sec-WebSocket-Version", "13");
        return Err((
            http::STATUS_BAD_REQUEST,
            format!(
                "unsupported WebSocket protocol version (only 13 is supported): {:?}",
                r.header.get("Sec-WebSocket-Version").unwrap_or("")
            ),
        ));
    }
    let keys = r.header.values("Sec-WebSocket-Key");
    if keys.is_empty() {
        return Err((
            http::STATUS_BAD_REQUEST,
            "WebSocket protocol violation: missing Sec-WebSocket-Key".into(),
        ));
    }
    if keys.len() > 1 {
        return Err((
            http::STATUS_BAD_REQUEST,
            "WebSocket protocol violation: multiple Sec-WebSocket-Key headers".into(),
        ));
    }
    let key = keys[0].trim();
    match base64::STANDARD.decode(key) {
        Ok(v) if v.len() == 16 => Ok(key.to_owned()),
        _ => Err((
            http::STATUS_BAD_REQUEST,
            format!("WebSocket protocol violation: invalid Sec-WebSocket-Key {key:?}, must be a 16 byte base64 encoded string"),
        )),
    }
}

/// coder/websocket's `authenticateOrigin`: an absent Origin passes, the
/// request's own host passes, and otherwise a pattern must match.
pub fn authenticate_origin(r: &Request, origin_patterns: &[String]) -> Result<(), String> {
    let origin = r.header.get("Origin").unwrap_or("");
    if origin.is_empty() {
        return Ok(());
    }
    let u =
        url::parse(origin).map_err(|e| format!("failed to parse Origin header {origin:?}: {e}"))?;
    if r.host.eq_ignore_ascii_case(&u.host) {
        return Ok(());
    }
    for pattern in origin_patterns {
        let target = if pattern.contains("://") {
            format!("{}://{}", u.scheme, u.host)
        } else {
            u.host.clone()
        };
        let matched = rust_stdlib::path::matches(&pattern.to_lowercase(), &target.to_lowercase())
            .map_err(|e| format!("failed to parse path pattern {pattern:?}: {e}"))?;
        if matched {
            return Ok(());
        }
    }
    if u.host.is_empty() {
        return Err(format!(
            "request Origin {origin:?} is not a valid URL with a host"
        ));
    }
    Err(format!(
        "request Origin {:?} is not authorized for Host {:?}",
        u.host, r.host
    ))
}

/// `websocket.Accept`: completes the handshake over the hijacked connection
/// or answers the request with the matching HTTP error.
pub fn accept(
    w: &mut dyn ResponseWriter,
    r: &Request,
    opts: &AcceptOptions,
) -> Result<Conn, String> {
    let key = match verify_client_request(w, r) {
        Ok(key) => key,
        Err((code, message)) => {
            http::util::error(w, &message, code);
            return Err(message);
        }
    };
    if !opts.insecure_skip_verify {
        if let Err(message) = authenticate_origin(r, &opts.origin_patterns) {
            http::util::error(w, &message, http::STATUS_FORBIDDEN);
            return Err(message);
        }
    }
    let Some(hijacker) = w.hijacker() else {
        let message = "http.ResponseWriter does not implement http.Hijacker".to_owned();
        http::util::error(w, &message, http::STATUS_INTERNAL_SERVER_ERROR);
        return Err(message);
    };
    let mut hj = match hijacker.hijack() {
        Ok(hj) => hj,
        Err(e) => return Err(format!("failed to hijack connection: {e}")),
    };
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(&key)
    );
    if let Err(e) = hj
        .writer
        .write_all(response.as_bytes())
        .and_then(|()| hj.writer.flush())
    {
        return Err(format!("failed to write handshake response: {e}"));
    }
    let raw: Arc<dyn net::Conn> = Arc::from(hj.conn);
    Ok(Conn::new(raw, Box::new(hj.reader), false))
}

/// Why `dial` failed; `response` is the server's answer when the handshake
/// was refused with an HTTP status.
#[derive(Debug)]
pub struct DialError {
    pub message: String,
    pub response: Option<Box<http::Response>>,
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DialError {}

fn dial_error(message: impl Into<String>) -> DialError {
    DialError {
        message: message.into(),
        response: None,
    }
}

/// The client side of the handshake, for `ws://` URLs. `headers` are added
/// to the request, such as an Origin.
pub fn dial(raw_url: &str, headers: &[(&str, &str)], timeout: Duration) -> Result<Conn, DialError> {
    let u = url::parse(raw_url).map_err(|e| dial_error(format!("failed to parse url: {e}")))?;
    if u.scheme != "ws" {
        return Err(dial_error(format!("unexpected url scheme: {:?}", u.scheme)));
    }
    let addr = if u.port().is_empty() {
        format!("{}:80", u.host)
    } else {
        u.host.clone()
    };
    let conn = net::dial_timeout("tcp", &addr, timeout)
        .map_err(|e| dial_error(format!("failed to dial: {e}")))?;
    let raw: Arc<dyn net::Conn> = Arc::from(conn);
    let _ = raw.set_deadline(&time::now().add(timeout));
    let mut key_bytes = [0u8; 16];
    rust_stdlib_crypto::rand::read(&mut key_bytes);
    let key = base64::STANDARD.encode(key_bytes);
    let path = if u.path.is_empty() {
        "/".to_owned()
    } else {
        u.escaped_path()
    };
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n",
        u.host
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    RawWrite(raw.clone())
        .write_all(request.as_bytes())
        .map_err(|e| dial_error(format!("failed to write handshake request: {e}")))?;
    let reader = http::BufioReader::new(RawRead(raw.clone()));
    let response = http::response::read_response(&reader, None)
        .map_err(|e| dial_error(format!("failed to read handshake response: {e}")))?;
    if response.status_code != http::STATUS_SWITCHING_PROTOCOLS {
        let _ = raw.close();
        return Err(DialError {
            message: format!(
                "expected handshake response status code {} but got {}",
                http::STATUS_SWITCHING_PROTOCOLS,
                response.status_code
            ),
            response: Some(Box::new(response)),
        });
    }
    if response.header.get("Sec-WebSocket-Accept") != Some(accept_key(&key).as_str()) {
        let _ = raw.close();
        return Err(DialError {
            message: "WebSocket protocol violation: invalid Sec-WebSocket-Accept".into(),
            response: Some(Box::new(response)),
        });
    }
    let _ = raw.set_deadline(&Time::default());
    Ok(Conn::new(raw, Box::new(reader), true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_stdlib::net::http::httptest;
    use rust_stdlib::net::http::ServeMux;
    use std::sync::Arc;

    fn ws_url(server: &httptest::Server) -> String {
        format!("ws{}/ws", &server.url["http".len()..])
    }

    fn echo_server(opts: AcceptOptions) -> httptest::Server {
        let mux = Arc::new(ServeMux::new());
        mux.handle_func("/ws", move |w, r| {
            let Ok(conn) = accept(w, r, &opts) else {
                return;
            };
            conn.set_read_limit(64);
            loop {
                match conn.read() {
                    Ok((MessageType::Text, payload)) => {
                        conn.write(MessageType::Text, &payload, second()).unwrap()
                    }
                    Ok((MessageType::Binary, _)) => {
                        let _ = conn.close(STATUS_UNSUPPORTED_DATA, "text frames required");
                        return;
                    }
                    Err(_) => return,
                }
            }
        })
        .unwrap();
        httptest::Server::new(mux).unwrap()
    }

    fn second() -> Duration {
        time::SECOND
    }

    #[test]
    fn echoes_text_and_pongs_pings() {
        let server = echo_server(AcceptOptions::default());
        let conn = Arc::new(dial(&ws_url(&server), &[], second()).unwrap());
        conn.set_read_deadline(&time::now().add(second())).unwrap();
        conn.write(MessageType::Text, b"hello", second()).unwrap();
        assert_eq!(conn.read().unwrap(), (MessageType::Text, b"hello".to_vec()));
        // A ping waits for its pong, which a concurrent read receives.
        let reader = std::thread::spawn({
            let c = conn.clone();
            move || c.read()
        });
        conn.ping(second()).unwrap();
        conn.close(STATUS_NORMAL_CLOSURE, "done").unwrap();
        assert!(reader.join().unwrap().is_err());
    }

    #[test]
    fn fragments_assemble_and_limits_close_with_1009() {
        let server = echo_server(AcceptOptions::default());
        let conn = dial(&ws_url(&server), &[], second()).unwrap();
        conn.set_read_deadline(&time::now().add(second())).unwrap();
        // A text frame without fin, then a continuation with fin.
        let mut mask = [0u8; 4];
        rust_stdlib_crypto::rand::read(&mut mask);
        let masked =
            |b: &[u8]| -> Vec<u8> { b.iter().enumerate().map(|(i, x)| x ^ mask[i % 4]).collect() };
        let mut frames = vec![0x01, 0x80 | 3];
        frames.extend(mask);
        frames.extend(masked(b"abc"));
        frames.extend([0x80, 0x80 | 3]);
        frames.extend(mask);
        frames.extend(masked(b"def"));
        RawWrite(conn.raw.clone()).write_all(&frames).unwrap();
        assert_eq!(
            conn.read().unwrap(),
            (MessageType::Text, b"abcdef".to_vec())
        );
        conn.write(MessageType::Text, &[b'x'; 65], second())
            .unwrap();
        match conn.read() {
            Err(Error::Closed { code, .. }) => assert_eq!(code, STATUS_MESSAGE_TOO_BIG),
            other => panic!("read after an oversized message: {other:?}"),
        }
    }

    /// A close without a status is echoed without one: 1005 must not
    /// appear on the wire (RFC 6455 §7.4.1), and coder/websocket sends an
    /// empty payload for StatusNoStatusRcvd.
    #[test]
    fn empty_close_is_echoed_empty() {
        let server = echo_server(AcceptOptions::default());
        let conn = dial(&ws_url(&server), &[], second()).unwrap();
        conn.set_read_deadline(&time::now().add(second())).unwrap();
        let mut mask = [0u8; 4];
        rust_stdlib_crypto::rand::read(&mut mask);
        let mut frame = vec![0x80 | OP_CLOSE, 0x80];
        frame.extend(mask);
        RawWrite(conn.raw.clone()).write_all(&frame).unwrap();
        match conn.read() {
            Err(Error::Closed { code, reason }) => {
                assert_eq!((code, reason.as_str()), (STATUS_NO_STATUS_RCVD, ""))
            }
            other => panic!("read after an empty close: {other:?}"),
        }
    }

    #[test]
    fn binary_is_refused_with_1003() {
        let server = echo_server(AcceptOptions::default());
        let conn = dial(&ws_url(&server), &[], second()).unwrap();
        conn.set_read_deadline(&time::now().add(second())).unwrap();
        conn.write(MessageType::Binary, b"\x00", second()).unwrap();
        match conn.read() {
            Err(Error::Closed { code, reason }) => {
                assert_eq!(
                    (code, reason.as_str()),
                    (STATUS_UNSUPPORTED_DATA, "text frames required")
                )
            }
            other => panic!("read after a binary message: {other:?}"),
        }
    }

    #[test]
    fn origins_follow_coder_websocket() {
        let server = echo_server(AcceptOptions {
            origin_patterns: vec!["http://localhost:*".into(), "chat.example".into()],
            ..AcceptOptions::default()
        });
        for (origin, ok) in [
            ("", true),
            ("http://localhost:3000", true),
            ("HTTP://LOCALHOST:3000", true),
            ("https://chat.example", true),
            ("https://evil.example", false),
            ("http://localhost", false),
            (&format!("http://{}", &server.url["http://".len()..]), true),
        ] {
            let headers: Vec<(&str, &str)> = if origin.is_empty() {
                vec![]
            } else {
                vec![("Origin", origin)]
            };
            let result = dial(&ws_url(&server), &headers, second());
            assert_eq!(result.is_ok(), ok, "origin {origin:?}");
            if let Err(e) = result {
                assert_eq!(
                    e.response.map(|r| r.status_code),
                    Some(http::STATUS_FORBIDDEN),
                    "origin {origin:?}"
                );
            }
        }
        let any = echo_server(AcceptOptions {
            insecure_skip_verify: true,
            ..AcceptOptions::default()
        });
        assert!(dial(
            &ws_url(&any),
            &[("Origin", "https://evil.example")],
            second()
        )
        .is_ok());
    }
}
