//! A WebSocket connection: its outgoing queue, writer and pinger threads, and
//! the per-connection state the server keeps under the lock (Conn).

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};

use rust_stdlib::encoding::json::v2::MarshalTo;
use rust_stdlib::time::{self, Duration, Time};

use super::email::ProposalId;
use super::limits::{IpKey, Window};
use super::protocol::*;
use super::webauthn::PasskeyCeremony;
use crate::rate::Limiter;
use crate::ws;

/// A rendered frame, shared by every connection it goes to.
pub type Frame = Arc<[u8]>;

/// Renders a frame once, for sending to many connections.
pub fn render<T: MarshalTo>(value: &T) -> Option<Frame> {
    encode_json(value).map(Frame::from)
}

/// The exact client liveness ping (§1); `pong_frame` answers it.
pub const PING_FRAME: &[u8] = br#"{"method":"ping"}"#;
pub fn pong_frame() -> Frame {
    Frame::from(br#"{"method":"pong"}"#.as_slice())
}

/// Keeps a sequence of protocol frames together in the writer's queue while
/// each frame is still written as its own WebSocket message, such as a
/// room_list result and the read cursors that follow it. A batch with
/// `close_reason` is the connection's last: the writer closes the connection
/// after writing it.
pub struct OutboundBatch {
    pub frames: Vec<Frame>,
    pub close_reason: String,
    stop: bool,
}

/// Go's closed `done` channel: set once, waited on with a timeout.
#[derive(Default)]
pub struct Done {
    flag: Mutex<bool>,
    cv: Condvar,
}

impl Done {
    pub fn set(&self) {
        *self.flag.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.cv.notify_all();
    }

    pub fn is_done(&self) -> bool {
        *self.flag.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Waits up to `d` and reports whether done was set.
    pub fn wait_timeout(&self, d: Duration) -> bool {
        let timeout = std::time::Duration::from_nanos(d.as_nanos().max(0) as u64);
        let guard = self.flag.lock().unwrap_or_else(|e| e.into_inner());
        let (guard, _) = self
            .cv
            .wait_timeout_while(guard, timeout, |done| !*done)
            .unwrap_or_else(|e| e.into_inner());
        *guard
    }

    pub fn wait(&self) {
        let guard = self.flag.lock().unwrap_or_else(|e| e.into_inner());
        let _unused = self
            .cv
            .wait_while(guard, |done| !*done)
            .unwrap_or_else(|e| e.into_inner());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientId(pub u64);

static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);

impl ClientId {
    /// A ClientId no other connection of this process has.
    pub fn next() -> ClientId {
        ClientId(NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

/// One WebSocket connection: what its threads read without the lock. The
/// identity and idle flag that Go guards with `s.mu` live in `State.clients`.
pub struct Client {
    pub id: ClientId,
    pub ws: ws::Conn,
    pub(super) out: SyncSender<OutboundBatch>,
    pub done: Done,
    /// Prefixes the write, file, and stream URLs this connection mints.
    pub base_url: String,
    pub origin: String,
    /// Names the client address for the limits of all its connections.
    pub ip_key: IpKey,
    pub(super) write_timeout: Duration,
    pub(super) ping_interval: Duration,
    pub(super) ping_timeout: Duration,
    /// Set once the final batch is queued; later frames are dropped.
    pub(super) closing: AtomicBool,
    /// Set by the first liveness ping (§1); `last_frame` is when the latest
    /// frame arrived, in Unix nanoseconds.
    pub(super) pinged: AtomicBool,
    pub(super) last_frame: AtomicI64,
    /// The connection's recent policy violations, and how many in a minute
    /// close it (Limits.policy_violations).
    pub(super) violations: Mutex<Window>,
    pub(super) max_violations: usize,
}

/// The lock-guarded half of a connection.
pub struct Conn {
    pub client: Arc<Client>,
    /// The connection's identity, `None` before authentication.
    pub user: Option<String>,
    /// When nobody has attended the connection since (§4.5.3), as its
    /// `idle` dated it; `None` while attended, which it is until it says
    /// otherwise.
    pub idle_since: Option<Time>,
    /// The pending passkey ceremony, if any (§4.10).
    pub ceremony: Option<PasskeyCeremony>,
    /// The SHA-256 of the session or bot token the connection last signed
    /// in or resumed with, which a later sign-in forgets; zero without one.
    pub token: [u8; 32],
    /// The SHA-256 of the /invite-device token the connection signed in
    /// with, zero for none. A later session token leaves it, so replacing
    /// the device token still closes the connection.
    pub device: [u8; 32],
    /// Limits the email proposals made on the connection (email.rs).
    pub email_sends: Option<Limiter>,
    /// The connection's latest proposal, which may have been dropped since.
    pub proposal: Option<ProposalId>,
    /// Whether the connection has listed its joined rooms since it signed
    /// in, which the first time costs no room listing.
    pub listed_joined: bool,
    /// Whether the last `server` frame it got listed wake scope `joined`
    /// (push.rs, `wakes_joined`).
    pub wake_joined: bool,
}

impl Client {
    pub(super) fn write_loop(self: Arc<Self>, out: Receiver<OutboundBatch>) {
        loop {
            let Ok(batch) = out.recv() else { return };
            if self.done.is_done() || batch.stop {
                return;
            }
            for payload in &batch.frames {
                if self.done.is_done() {
                    return;
                }
                if self
                    .ws
                    .write(ws::MessageType::Text, payload, self.write_timeout)
                    .is_err()
                {
                    self.stop_connection();
                    return;
                }
            }
            if !batch.close_reason.is_empty() {
                // The error frame explains the close; a close handshake would
                // wait on a peer that may not be reading.
                self.stop_connection();
                return;
            }
        }
    }

    /// Pings at the WebSocket level, which finds dead transports, and closes
    /// a connection whose client sent liveness pings (§1) and then fell
    /// silent for three intervals: its page is frozen or gone even if the
    /// socket is not. Three intervals leave room for background timer
    /// throttling.
    pub(super) fn ping_loop(self: Arc<Self>) {
        let silence = self
            .ping_interval
            .mul(3)
            .checked_add(self.ping_timeout)
            .unwrap_or(self.ping_interval);
        loop {
            if self.done.wait_timeout(self.ping_interval) {
                return;
            }
            if self.pinged.load(Ordering::Relaxed) {
                let last = time::unix(0, self.last_frame.load(Ordering::Relaxed));
                if time::since(&last).as_nanos() > silence.as_nanos() {
                    self.stop_connection();
                    return;
                }
            }
            if self.ws.ping(self.ping_timeout).is_err() {
                self.stop_connection();
                return;
            }
        }
    }

    /// Answers a liveness ping, before authentication too (§1).
    pub fn pong(&self) {
        self.pinged.store(true, Ordering::Relaxed);
        self.enqueue_frame(pong_frame());
    }

    pub fn stop_connection(&self) {
        if !self.done.is_done() {
            self.done.set();
            self.ws.close_now();
            let _ = self.out.try_send(OutboundBatch {
                frames: Vec::new(),
                close_reason: String::new(),
                stop: true,
            });
        }
    }

    /// Sends an error about the connection as a whole, without id
    /// (PROTOCOL.md §1.1), after the frames already queued, then closes the
    /// connection.
    pub fn close_with_error(&self, e: RpcError) {
        let Some(payload) = render(&error_response(None, e.clone())) else {
            return;
        };
        if self.closing.swap(true, Ordering::SeqCst) {
            return;
        }
        let batch = OutboundBatch {
            frames: vec![payload],
            close_reason: e.message,
            stop: false,
        };
        if self.out.try_send(batch).is_err() {
            self.stop_connection();
        }
    }

    /// Closes with a WebSocket close code and reason (RFC 6455 §7.4), for a
    /// connection that broke a policy.
    pub fn close_with_code(&self, code: u16, reason: &str) {
        if self.closing.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.ws.close(code, reason);
        self.stop_connection();
    }

    /// Reports whether a connection-level error is queued, after which the
    /// connection sends nothing more and runs none of its frames.
    pub fn is_closing(&self) -> bool {
        self.closing.load(Ordering::SeqCst)
    }

    pub fn enqueue<T: MarshalTo>(&self, value: &T) -> bool {
        match render(value) {
            Some(frame) => self.enqueue_frames(vec![frame]),
            None => {
                self.stop_connection();
                false
            }
        }
    }

    pub fn enqueue_frame(&self, frame: Frame) -> bool {
        self.enqueue_frames(vec![frame])
    }

    /// Queues frames as one batch. A frame rendered once for many
    /// connections is shared as is; the writer never modifies it.
    pub fn enqueue_frames(&self, frames: Vec<Frame>) -> bool {
        if frames.is_empty() {
            return true;
        }
        if self.closing.load(Ordering::Relaxed) || self.done.is_done() {
            return false;
        }
        match self.out.try_send(OutboundBatch {
            frames,
            close_reason: String::new(),
            stop: false,
        }) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                // A slow client cannot hold the room lock or the server's
                // broadcast path.
                self.stop_connection();
                false
            }
        }
    }

    pub fn send_result(&self, req: &Request, result: Json) {
        self.enqueue(&response(&req.id, result));
    }

    pub fn send_error(&self, req: &Request, err: RpcError) {
        let (code, forgiven) = (err.code, err.forgiven);
        self.enqueue(&error_response(Some(&req.id), err));
        if !forgiven {
            self.note_violation(code);
        }
    }

    /// Counts an error of `code` against the connection when it is a
    /// policy violation, closing the connection with 1008 when there were
    /// too many in a minute. A denial is not one.
    pub fn note_violation(&self, code: i64) {
        if !matches!(
            code,
            CODE_PARSE_ERROR | CODE_INVALID_REQUEST | CODE_INVALID_PARAMS | CODE_TOO_LARGE
        ) {
            return;
        }
        let now = time::now().unix_milli();
        let recent = self
            .violations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .note(now);
        if self.max_violations > 0 && recent >= self.max_violations {
            self.close_with_code(ws::STATUS_POLICY_VIOLATION, "Repeated policy violations");
        }
    }
}
