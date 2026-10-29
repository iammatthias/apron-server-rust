//! The WebSocket test client and the ways a test dials and signs in.

use std::sync::Arc;

use rust_stdlib::encoding::json::v2 as json;
use rust_stdlib::time::{self, Duration};

use crate::obj;
use crate::server::protocol::*;
use crate::server::status::STATUS_OFFLINE;
use crate::ws;

use super::*;

pub struct TestClient {
    pub ws: ws::Conn,
    /// Numbers the request IDs the helpers generate.
    requests: usize,
    /// The identity the guest was assigned at auth.
    pub user_id: String,
    /// Keeps the bare status announcements of others (§4.5), which `read`
    /// otherwise skips.
    pub statuses: bool,
    /// The challenge_id of the latest passkey begin, which `passkey_call`
    /// sends with a finish.
    pub passkey_challenge: String,
}

impl Drop for TestClient {
    fn drop(&mut self) {
        let _ = self.ws.close(ws::STATUS_NORMAL_CLOSURE, "test finished");
    }
}

fn second() -> Duration {
    time::SECOND
}

impl TestClient {
    /// A request ID not used before by this test process, so a client
    /// signing in again after a restart is not deduplicated against its
    /// earlier requests (§1.2).
    pub fn next_id(&mut self, prefix: &str) -> String {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        self.requests += 1;
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{prefix}-{n}")
    }

    pub fn write(&self, value: &Object) {
        let payload = json::marshal(value, &[]).expect("marshal frame");
        self.ws
            .write(ws::MessageType::Text, &payload, second())
            .expect("write frame");
    }

    pub fn write_raw(&self, raw: &str) {
        self.ws
            .write(ws::MessageType::Text, raw.as_bytes(), second())
            .expect("write frame");
    }

    pub fn read(&self) -> Object {
        loop {
            self.ws
                .set_read_deadline(&time::now().add(second()))
                .unwrap();
            let (_, payload) = match self.ws.read() {
                Ok(message) => message,
                Err(e) => panic!("read frame: {e}"),
            };
            let frame = decode_frame(&payload);
            if !self.statuses && is_status_announcement(&frame) {
                continue;
            }
            return frame;
        }
    }

    /// Reads the next raw message, for checks on the connection itself.
    pub fn read_raw(&self, timeout: Duration) -> Result<Vec<u8>, ws::Error> {
        self.ws
            .set_read_deadline(&time::now().add(timeout))
            .unwrap();
        self.ws.read().map(|(_, payload)| payload)
    }

    /// Returns every frame queued before a fence request's reply.
    pub fn drain(&mut self) -> Vec<Object> {
        let id = self.next_id("fence");
        self.write(&obj! {"method" => "fence", "id" => id.as_str()});
        let mut frames = Vec::new();
        loop {
            let frame = self.read();
            if frame.get("id").and_then(Json::as_str) == Some(&id) {
                return frames;
            }
            frames.push(frame);
        }
    }

    pub fn expect_quiet(&mut self) {
        let frames = self.drain();
        assert!(frames.is_empty(), "unexpected frames: {frames:?}");
    }

    /// Sends a request and returns its reply frame, which must come next.
    pub fn call(&mut self, method: &str, id: &str, params: Object) -> Object {
        self.write(&obj! {"method" => method, "id" => id, "params" => params});
        let frame = self.read();
        assert_eq!(
            frame.get("id").and_then(Json::as_str),
            Some(id),
            "{method} reply = {frame:?}, want id {id:?}"
        );
        frame
    }

    /// Sends a request and returns the notifications that precede its
    /// reply, then its result.
    pub fn request(&mut self, method: &str, id: &str, params: Object) -> (Vec<Object>, Object) {
        self.write(&obj! {"method" => method, "id" => id, "params" => params});
        let mut before = Vec::new();
        loop {
            let frame = self.read();
            if !frame.contains_key("id") {
                before.push(frame);
                continue;
            }
            let result = frame.get("result").and_then(Json::as_object).cloned();
            match result {
                Some(result) if frame.get("id").and_then(Json::as_str) == Some(id) => {
                    return (before, result)
                }
                _ => {
                    panic!("{method} reply = {frame:?} after {before:?}, want a result for {id:?}")
                }
            }
        }
    }

    pub fn result(&mut self, method: &str, id: &str, params: Object) -> Object {
        let frame = self.call(method, id, params);
        match frame.get("result").and_then(Json::as_object) {
            Some(result) => result.clone(),
            None => panic!("{method} failed: {frame:?}"),
        }
    }

    pub fn expect_error(&mut self, method: &str, id: &str, params: Object, code: i64) {
        let frame = self.call(method, id, params);
        let failure = frame.get("error").and_then(Json::as_object);
        let got = failure.and_then(|f| f.get("code")).cloned();
        assert_eq!(
            got,
            Some(Json::from(code)),
            "{method} {id}: {frame:?}, want error {code}"
        );
    }

    /// Reads the next frame and requires it to be the named notification.
    pub fn notification(&self, method: &str) -> Object {
        let frame = self.read();
        notification_params(&frame, method)
    }
}

pub fn decode_frame(payload: &[u8]) -> Object {
    let mut frame = Json::Null;
    json::unmarshal(payload, &mut frame, &[])
        .unwrap_or_else(|e| panic!("decode frame {:?}: {e}", String::from_utf8_lossy(payload)));
    match frame {
        Json::Object(frame) => frame,
        other => panic!("frame is not an object: {other:?}"),
    }
}

/// Reports whether frame is a bare announcement of another user's status:
/// `user` with only `new`, which has only user_id and status, and seen only
/// with offline (§4.5.2).
pub fn is_status_announcement(frame: &Object) -> bool {
    let params = frame.get("params").and_then(Json::as_object);
    let object = params.and_then(|p| p.get("new")).and_then(Json::as_object);
    if frame.get("method").and_then(Json::as_str) != Some("user")
        || params.is_none_or(|p| p.len() != 1)
    {
        return false;
    }
    let Some(object) = object else { return false };
    if !object.contains_key("user_id") || !object.contains_key("status") {
        return false;
    }
    if object.contains_key("seen") {
        return object.len() == 3
            && object.get("status").and_then(Json::as_str) == Some(STATUS_OFFLINE);
    }
    object.len() == 2
}

/// Connects without signing in and returns the server frame.
pub fn dial_raw(server: &TestServer) -> (TestClient, Object) {
    dial_origin(server, "")
}

/// Connects as a page on origin, if given, and returns the server frame.
pub fn dial_origin(server: &TestServer, origin: &str) -> (TestClient, Object) {
    if origin.is_empty() {
        dial_headers(server, &[])
    } else {
        dial_headers(server, &[("Origin", origin)])
    }
}

/// Connects with the given request headers and returns the server frame,
/// after reading the welcome that follows it.
pub fn dial_headers(server: &TestServer, headers: &[(&str, &str)]) -> (TestClient, Object) {
    let (c, server_frame) = dial_server_frame(server, headers);
    welcome_text(&c.read());
    (c, server_frame)
}

/// Connects and returns the server frame, leaving what follows it unread.
pub fn dial_server_frame(server: &TestServer, headers: &[(&str, &str)]) -> (TestClient, Object) {
    let conn = match ws::dial(&ws_url(server), headers, second()) {
        Ok(conn) => conn,
        Err(e) => panic!("dial: {e}"),
    };
    conn.set_read_limit(1 << 24);
    let c = TestClient {
        ws: conn,
        requests: 0,
        user_id: String::new(),
        statuses: false,
        passkey_challenge: String::new(),
    };
    let server_frame = c.read();
    assert_eq!(
        server_frame.get("method").and_then(Json::as_str),
        Some("server"),
        "first frame = {server_frame:?}, want server announcement"
    );
    (c, server_frame)
}

/// Signs c in as a guest and returns the auth result. Every notification the
/// sign-in causes follows the result (§3.2): first room_update joined for the
/// guest's join to general.
pub fn guest_auth(c: &mut TestClient) -> Object {
    let id = c.next_id("auth");
    let (before, result) = c.request("auth", &id, obj! {"scheme" => "guest"});
    c.user_id = you_of(&result)["user_id"].as_str().unwrap().to_owned();
    assert!(
        before.is_empty(),
        "frames before the guest auth result: {before:?}"
    );
    expect_joined_default(c, &c.user_id.clone());
    result
}

/// Signs in a new guest. The guest's join to general is delivered to its
/// connection after the auth result (§3.2).
pub fn dial_test_client(server: &TestServer) -> TestClient {
    let (mut c, _) = dial_raw(server);
    guest_auth(&mut c);
    c.expect_quiet();
    c
}

/// Signs in n guests, in order. New guests join general, so each earlier
/// guest reads the later ones' memberships.
pub fn dial_group(server: &TestServer, n: usize) -> Vec<TestClient> {
    let mut clients: Vec<TestClient> = Vec::with_capacity(n);
    for i in 0..n {
        let c = dial_test_client(server);
        assert_eq!(
            c.user_id,
            format!("guest_{}", i + 1),
            "guest {} was assigned {:?}",
            i + 1,
            c.user_id
        );
        for earlier in &clients {
            expect_membership(earlier, "general", &c.user_id, true);
        }
        clients.push(c);
    }
    clients
}

/// The connection signed in as user_id that holds or, with `is` false, does
/// not hold token as its session, bot or device token, from the server's
/// state, for checks on a connection the test client cannot reach.
pub fn token_connection(
    server: &TestServer,
    user_id: &str,
    token: &str,
    is: bool,
) -> Arc<crate::server::client::Client> {
    let key = rust_stdlib_crypto::sha256::sum256(token.as_bytes());
    let st = server.app.lock();
    st.clients
        .values()
        .find(|conn| {
            conn.user.as_deref() == Some(user_id) && (conn.token == key || conn.device == key) == is
        })
        .map(|conn| conn.client.clone())
        .unwrap_or_else(|| panic!("no such connection of {user_id}"))
}

/// Waits up to five seconds for `done`, as a closed connection's handler
/// detaches it after the test drops its end.
pub fn wait_for(mut done: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !done() {
        assert!(std::time::Instant::now() < deadline, "timed out waiting");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
