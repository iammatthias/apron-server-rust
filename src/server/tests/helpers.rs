//! The test client and the checks of helpers_test.go, with the same names.
//! A failed check panics, as `t.Fatalf` does.

use std::sync::Arc;

use rust_stdlib::context::Context;
use rust_stdlib::encoding::json::v2 as json;
use rust_stdlib::net::http::httptest;
use rust_stdlib::time::{self, Duration};

use crate::obj;
use crate::server::protocol::*;
use crate::server::status::STATUS_OFFLINE;
use crate::server::{open, Config, Server};
use crate::ws;

pub struct TestServer {
    pub app: Arc<Server>,
    pub http: httptest::Server,
    stopped: bool,
    /// The upload directory `open` made when the config named none, which a
    /// shutdown removes; a failed test skips the shutdown and removes it here.
    temp_upload_dir: Option<String>,
}

impl TestServer {
    /// Shuts the server down, closing the store, once.
    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        let (ctx, cancel) =
            Context::background().with_timeout(rust_stdlib::time::Duration::from_secs(10));
        if let Err(e) = self.app.shutdown(&ctx) {
            panic!("shutdown: {e}");
        }
        cancel();
        self.http.close();
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.stop();
        } else if let Some(dir) = &self.temp_upload_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// A temporary directory removed on drop, even when the test fails, as Go's
/// `t.TempDir()` is.
pub struct TempDir(String);

impl TempDir {
    pub fn new(prefix: &str) -> TempDir {
        TempDir(rust_stdlib::os::mkdir_temp("", prefix).unwrap())
    }
}

impl std::ops::Deref for TempDir {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TempDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The server's defaults with guest posting on: the tests ported from Go sign
/// in as guests to post, and `guest_posting_test` covers the read-only
/// default.
pub fn default_config() -> Config {
    Config {
        guest_posting: true,
        ..crate::server::default_config()
    }
}

/// `default_config` with frames and texts large enough to reach the
/// server's limits on ext, descriptions and history pages.
pub fn large_frames_config() -> Config {
    let mut config = default_config();
    config.frame.max_bytes = 1 << 20;
    config.frame.max_text_bytes = 1 << 20;
    config
}

pub fn new_test_server(config: Config) -> TestServer {
    let app = open(config).expect("open");
    let http = httptest::Server::new(app.handler()).expect("httptest server");
    let temp_upload_dir = {
        let st = app.lock();
        st.temp_upload_dir.then(|| st.upload_dir.clone())
    };
    TestServer {
        app,
        http,
        stopped: false,
        temp_upload_dir,
    }
}

/// The WebSocket endpoint of a test server.
pub fn ws_url(server: &TestServer) -> String {
    format!("ws{}/ws", &server.http.url["http".len()..])
}

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
    /// A request ID not used before on this client.
    pub fn next_id(&mut self, prefix: &str) -> String {
        self.requests += 1;
        format!("{prefix}-{}", self.requests)
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

/// The text of the `~private` welcome that follows the server frame, after
/// checking that it is one, in no room.
pub fn welcome_text(frame: &Object) -> String {
    let notice = notification_params(frame, "message");
    assert!(
        !notice.contains_key("room_id")
            && !notice.contains_key("message_id")
            && notice["from"]
                == Json::from(obj! {"user_id" => "~private", "name" => "System message to you"}),
        "welcome notice = {frame:?}"
    );
    notice["body"].as_object().unwrap()["text"]
        .as_str()
        .unwrap()
        .to_owned()
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

/// A JSON array of strings.
pub fn strings(values: &[&str]) -> Json {
    Json::Array(values.iter().map(|v| Json::from(*v)).collect())
}

pub fn you_of(result: &Object) -> Object {
    result["you"].as_object().cloned().unwrap()
}

/// Reads the room_update that tells user_id's connection of its join to
/// general at sign-in.
pub fn expect_joined_default(c: &TestClient, user_id: &str) -> Object {
    check_joined_default(&c.read(), user_id)
}

/// Checks a room_update joined for user_id's join to general and returns its
/// membership record.
pub fn check_joined_default(frame: &Object, user_id: &str) -> Object {
    let record = joined_record(frame, user_id);
    assert_eq!(
        record.get("room_id"),
        Some(&Json::from("general")),
        "joined {record:?}, want general"
    );
    let membership = membership_of(frame);
    check_membership(&membership, "general", user_id, true);
    membership
}

/// The one membership record of a room_update frame (§4.2.3).
pub fn membership_of(frame: &Object) -> Object {
    let update = notification_params(frame, "room_update");
    let records = update.get("memberships").map(Json::as_list).unwrap_or(&[]);
    assert!(
        records.len() == 1,
        "room_update = {update:?}, want one membership record"
    );
    records[0].as_object().cloned().unwrap()
}

/// The membership record of a room_update that carries nothing else, as the
/// room's other members receive it.
pub fn membership_only(frame: &Object) -> Object {
    let update = notification_params(frame, "room_update");
    assert!(
        update.len() == 1,
        "room_update = {update:?}, want its membership alone"
    );
    membership_of(frame)
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

/// Reads a room_update carrying only a membership record: one entry, for
/// user_id in room_id, as the room's other members receive it.
pub fn expect_membership(c: &TestClient, room_id: &str, user_id: &str, joined: bool) -> Object {
    let params = membership_only(&c.read());
    check_membership(&params, room_id, user_id, joined);
    params
}

/// Reads the room_update that tells a user's connection it left or was
/// removed from room_id: left and the membership.
pub fn expect_left(c: &TestClient, room_id: &str, user_id: &str) -> Object {
    check_left(&c.read(), room_id, user_id)
}

pub fn check_left(frame: &Object, room_id: &str, user_id: &str) -> Object {
    let update = notification_params(frame, "room_update");
    let want_left: Json = vec![Json::from(obj! {"room_id" => room_id})].into();
    assert!(
        update.len() == 2 && update.get("left") == Some(&want_left),
        "room_update = {update:?}, want left {room_id} and its membership"
    );
    let membership = membership_of(frame);
    check_membership(&membership, room_id, user_id, false);
    membership
}

/// Checks a live membership record's shape.
pub fn check_membership(params: &Object, room_id: &str, user_id: &str, joined: bool) {
    let members = params.get("members").map(Json::as_list).unwrap_or(&[]);
    assert!(
        members.len() == 1
            && params.len() == 3
            && params.get("room_id") == Some(&Json::from(room_id)),
        "membership = {params:?}, want one entry in {room_id}"
    );
    parse_id(params.get("log_id"));
    let entry = members[0].as_object().unwrap();
    let user = entry
        .get("user")
        .and_then(Json::as_object)
        .cloned()
        .unwrap_or_default();
    assert!(
        entry.len() == 2
            && user.get("user_id") == Some(&Json::from(user_id))
            && entry.get("joined") == Some(&Json::from(joined)),
        "membership entry = {entry:?}, want {user_id} joined={joined}"
    );
}

/// Sends room_list and returns its result.
pub fn list_rooms(c: &mut TestClient, params: Object) -> Object {
    let id = c.next_id("list");
    c.result("room_list", &id, params)
}

/// Lists the room_id of each room record in a room_list array.
pub fn room_ids(value: Option<&Json>) -> Vec<String> {
    let Some(Json::Array(list)) = value else {
        panic!("room list {value:?} is not an array")
    };
    list.iter()
        .map(|entry| {
            entry.as_object().unwrap()["room_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// Requires a frame to be the named notification and returns its params.
pub fn notification_params(frame: &Object, method: &str) -> Object {
    let params = frame.get("params").and_then(Json::as_object);
    assert!(
        frame.get("method").and_then(Json::as_str) == Some(method)
            && params.is_some()
            && frame.get("id").is_none(),
        "frame = {frame:?}, want {method} notification"
    );
    params.cloned().unwrap()
}

/// Names each frame's method, or "reply" for a reply.
pub fn methods(frames: &[Object]) -> Vec<String> {
    frames
        .iter()
        .map(|frame| match frame.get("method").and_then(Json::as_str) {
            Some(method) if !method.is_empty() => method.to_owned(),
            _ => "reply".to_owned(),
        })
        .collect()
}

/// Sends a message request and returns the result ID and the sender's copy
/// of the broadcast snapshot, which precedes the result (§1).
pub fn save(c: &mut TestClient, request_id: &str, mut params: Object) -> (String, Object) {
    if !params.contains_key("room_id") {
        params.insert("room_id".into(), "general".into());
    }
    let room_id = params["room_id"].clone();
    let (before, result) = c.request("message", request_id, params);
    let id = result
        .get("message_id")
        .and_then(Json::as_str)
        .map(str::to_owned);
    assert!(
        id.is_some() && before.len() == 1,
        "message result {result:?} after {before:?}, want one broadcast first"
    );
    let id = id.unwrap();
    let snapshot = notification_params(&before[0], "message");
    assert!(
        snapshot.get("message_id") == Some(&Json::from(id.as_str()))
            && snapshot.get("room_id") == Some(&room_id),
        "result and snapshot disagree: {result:?} vs {snapshot:?}"
    );
    assert!(
        !snapshot.contains_key("message"),
        "snapshot is not flat: {snapshot:?}"
    );
    assert!(result.len() == 1, "message result: {result:?}");
    (id, snapshot)
}

/// Sends room_set and returns the room ID and the record of the room_update
/// that precedes the result: joined for a new room, followed by the
/// creator's membership, or updated for an edit. The joined record's members
/// are checked and removed, so it compares with updated records.
pub fn save_room(c: &mut TestClient, request_id: &str, params: Object) -> (String, Object) {
    let editing = params.contains_key("room_id");
    let (before, result) = c.request("room_set", request_id, params);
    assert_eq!(
        methods(&before),
        vec!["room_update"],
        "room_set frames = {before:?}, want one room_update"
    );
    let mut record;
    if editing {
        record = update_record(&before[0], "updated");
    } else {
        // The creator receives the room with its members and the creator's
        // membership in one room_update (§4.2.4).
        record = joined_record(&before[0], &c.user_id);
        let membership = membership_of(&before[0]);
        check_membership(
            &membership,
            record["room_id"].as_str().unwrap(),
            &c.user_id,
            true,
        );
        assert!(
            membership.get("log_id") == record.get("latest_log_id")
                && parse_id(membership.get("log_id")) > parse_id(record.get("log_id")),
            "creator membership {membership:?} does not follow the room record {record:?}"
        );
        assert_eq!(
            member_ids(&record),
            vec![c.user_id.clone()],
            "new room members"
        );
        record.remove("members");
    }
    assert!(
        result.len() == 1 && result.get("room_id") == record.get("room_id"),
        "room_set result {result:?} disagrees with {record:?}"
    );
    (record["room_id"].as_str().unwrap().to_owned(), record)
}

/// Sends room_join and returns the room record of the room_update joined
/// that follows the membership and precedes the result. The record keeps its
/// members.
pub fn join_room(c: &mut TestClient, room_id: &str) -> Object {
    let id = c.next_id("join");
    let (before, result) = c.request("room_join", &id, obj! {"room_id" => room_id});
    assert!(
        methods(&before) == vec!["room_update"] && result.is_empty(),
        "room_join {room_id}: {before:?} then {result:?}"
    );
    let membership = membership_of(&before[0]);
    check_membership(&membership, room_id, &c.user_id, true);
    let record = joined_record(&before[0], &c.user_id);
    assert!(
        record.get("room_id") == Some(&Json::from(room_id))
            && record.get("latest_log_id") == membership.get("log_id"),
        "room_join {room_id} record: {record:?}"
    );
    record
}

/// Sends room_leave and checks the membership and room_update left that
/// precede its result.
pub fn leave_room(c: &mut TestClient, room_id: &str) {
    let id = c.next_id("leave");
    let (before, result) = c.request("room_leave", &id, obj! {"room_id" => room_id});
    assert!(
        methods(&before) == vec!["room_update"] && result.is_empty(),
        "room_leave {room_id}: {before:?} then {result:?}"
    );
    check_left(&before[0], room_id, &c.user_id);
}

/// Reads a room_update notification and returns its one record in field.
pub fn room_updated(c: &TestClient, field: &str) -> Object {
    update_record(&c.read(), field)
}

/// Requires a room_update carrying one record in field alone.
pub fn update_record(frame: &Object, field: &str) -> Object {
    let update = notification_params(frame, "room_update");
    let records = update.get(field).map(Json::as_list).unwrap_or(&[]);
    assert!(
        records.len() == 1 && update.len() == 1,
        "room_update = {update:?}, want one {field} record"
    );
    records[0].as_object().cloned().unwrap()
}

/// Requires a room_update joined carrying one record with its members, and
/// users holding each member's current object once. A non-empty member must
/// be among them.
pub fn joined_record(frame: &Object, member: &str) -> Object {
    let update = notification_params(frame, "room_update");
    let records = update.get("joined").map(Json::as_list).unwrap_or(&[]);
    let with_membership = update.contains_key("memberships");
    assert!(
        records.len() == 1 && (update.len() == 2 || (with_membership && update.len() == 3)),
        "room_update = {update:?}, want one joined record and users"
    );
    let record = records[0].as_object().cloned().unwrap();
    let members = member_ids(&record);
    let users: Vec<String> = update
        .get("users")
        .map(Json::as_list)
        .unwrap_or(&[])
        .iter()
        .map(|u| {
            u.as_object().unwrap()["user_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert!(
        members == users && (member.is_empty() || members.iter().any(|m| m == member)),
        "joined members {members:?} with users {users:?}, want {member:?} among them"
    );
    record
}

/// Lists the user_ids of a room record's members.
pub fn member_ids(entry: &Object) -> Vec<String> {
    entry
        .get("members")
        .map(Json::as_list)
        .unwrap_or(&[])
        .iter()
        .map(|m| {
            m.as_object().unwrap()["user_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// Sets reactions and returns the broadcast that precedes the result.
pub fn react(c: &mut TestClient, request_id: &str, message_id: &str, emojis: &[&str]) -> Object {
    let list: Vec<Json> = emojis.iter().map(|e| Json::from(*e)).collect();
    let (before, result) = c.request(
        "reactions",
        request_id,
        obj! {"message_id" => message_id, "emojis" => list},
    );
    assert!(
        result.is_empty() && before.len() == 1,
        "reactions result {result:?} after {before:?}, want one broadcast first"
    );
    notification_params(&before[0], "reactions")
}

pub fn history_page(c: &mut TestClient, room_id: &str, mut params: Object) -> Object {
    params.insert("room_id".into(), room_id.into());
    let id = c.next_id("history");
    c.result("history", &id, params)
}

/// Lists the log_ids of a history array, empty when it is omitted.
pub fn log_ids(page: &Object, key: &str) -> Vec<String> {
    let Some(raw) = page.get(key) else {
        return vec![];
    };
    let Json::Array(list) = raw else {
        panic!("history {key} is not a non-empty array: {page:?}")
    };
    assert!(
        !list.is_empty(),
        "history {key} is not a non-empty array: {page:?}"
    );
    list.iter()
        .map(|v| {
            v.as_object().unwrap()["log_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// Returns a history array, empty when it is omitted.
pub fn records(page: &Object, key: &str) -> Vec<Object> {
    log_ids(page, key);
    page.get(key)
        .map(Json::as_list)
        .unwrap_or(&[])
        .iter()
        .map(|v| v.as_object().cloned().unwrap())
        .collect()
}

pub fn parse_id(value: Option<&Json>) -> i64 {
    let Some(Json::String(text)) = value else {
        panic!("log id {value:?} is not a string")
    };
    match text.parse::<i64>() {
        Ok(id) if id > 0 => id,
        _ => panic!("log id {text:?} is not a positive integer"),
    }
}

/// Sends one HTTP GET and returns the status and body.
pub fn http_get(url: &str) -> (u16, Vec<u8>) {
    let response =
        rust_stdlib::net::http::client::get(url).unwrap_or_else(|e| panic!("GET {url}: {e}"));
    let body = response
        .body
        .as_ref()
        .map(|b| b.read_all().unwrap())
        .unwrap_or_default();
    (response.status_code, body)
}

/// Makes the clients keep the bare status announcements of others (§4.5).
pub fn watching(clients: &mut [&mut TestClient]) {
    for c in clients {
        c.statuses = true;
    }
}

/// Checks a bare announcement of user_id's status, `user` `{new: {user_id,
/// status}}`, with seen when status is offline, and returns the seen.
pub fn check_status(frame: &Object, user_id: &str, status: &str) -> String {
    let params = notification_params(frame, "user");
    let mut want = obj! {"new" => obj! {"user_id" => user_id, "status" => status}};
    let seen = params
        .get("new")
        .and_then(Json::as_object)
        .and_then(|n| n.get("seen"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    if status == STATUS_OFFLINE {
        assert!(seen.parse::<i64>().is_ok_and(|s| s > 0), "seen {seen:?}");
        want.get_mut("new")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("seen".into(), seen.as_str().into());
    }
    assert_eq!(params, want, "user notification");
    seen
}

/// Sends one HTTP request and returns the status, headers, and body.
pub fn http_do(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    content_type: &str,
) -> (u16, rust_stdlib::net::http::Header, Vec<u8>) {
    let mut request =
        rust_stdlib::net::http::Request::new(method, url).unwrap_or_else(|e| panic!("{url}: {e}"));
    if let Some(body) = body {
        request = request.with_body(body.to_vec());
    }
    if !content_type.is_empty() {
        request.header.set("Content-Type", content_type);
    }
    let response = rust_stdlib::net::http::client::DEFAULT_CLIENT
        .do_request(request)
        .unwrap_or_else(|e| panic!("{method} {url}: {e}"));
    let data = response
        .body
        .as_ref()
        .map(|b| b.read_all().unwrap())
        .unwrap_or_default();
    (response.status_code, response.header, data)
}

/// A 3x2 PNG.
pub fn test_png() -> Vec<u8> {
    use rust_stdlib::image;
    let mut buf = Vec::new();
    image::png::encode(&mut buf, &image::Rgba::new(image::rect(0, 0, 3, 2))).expect("encode png");
    buf
}

pub fn embeds_of(snapshot: &Object) -> Vec<Object> {
    snapshot
        .get("body")
        .and_then(Json::as_object)
        .and_then(|body| body.get("embeds"))
        .map(Json::as_list)
        .unwrap_or(&[])
        .iter()
        .map(|value| value.as_object().cloned().unwrap())
        .collect()
}

/// Posts a message with new upload or stream embeds and returns its result,
/// which must follow the sender's copy of the pending snapshot (§1); the
/// snapshot is added to the result as "snapshot".
pub fn post_embeds(c: &mut TestClient, id: &str, params: Object) -> Object {
    let (before, mut result) = c.request("message", id, params);
    assert!(
        before.len() == 1
            && !result
                .get("embeds")
                .map(Json::as_list)
                .unwrap_or(&[])
                .is_empty(),
        "message with embeds: {before:?} then {result:?}"
    );
    result.insert(
        "snapshot".into(),
        notification_params(&before[0], "message").into(),
    );
    result
}

/// The connection signed in as user_id that holds or, with `is` false, does
/// not hold token as its session, bot or device token, from the server's
/// state, for checks on a connection the test client cannot reach.
pub fn token_connection(
    server: &TestServer,
    user_id: &str,
    token: &str,
    is: bool,
) -> Arc<crate::server::server::Client> {
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

const LATE_POST: &[u8] =
    br#"{"method":"message","id":"late","params":{"room_id":"general","body":{"text":"still here"}}}"#;

/// Runs the command `text` on asker, whose connection in the server is
/// asker_conn, while holding the state lock, and checks before releasing it
/// that the command revoked `revoked`, a connection of user_id: it is still
/// connected, as its writer has not drained, but closing and signed out, so
/// a request already past the read loop is denied when it resolves its
/// identity. Returns the frames asker receives before the result.
pub fn command_revoking(
    server: &TestServer,
    asker: &mut TestClient,
    asker_conn: &Arc<crate::server::server::Client>,
    text: &str,
    revoked: &Arc<crate::server::server::Client>,
    user_id: &str,
) -> Vec<Object> {
    let command = encode_json(&obj! {
        "method" => "command", "id" => "reissue", "params" => obj! {"body" => obj! {"text" => text}},
    })
    .unwrap();
    let (command, _) = parse_request(&command, &FrameLimits::default());
    let (late, _) = parse_request(LATE_POST, &FrameLimits::default());
    {
        let mut st = server.app.lock();
        st.command_locked(asker_conn, &command)
            .unwrap_or_else(|e| panic!("{text}: {e:?}"));
        assert!(
            st.clients.contains_key(&revoked.id) && revoked.is_closing(),
            "the revoked connection is not closing"
        );
        assert!(
            st.client_user(revoked).is_none(),
            "the revoked connection is signed in"
        );
        assert!(
            !st.users[user_id].clients.contains(&revoked.id),
            "{user_id} keeps the revoked connection"
        );
        let messages = st.messages.len();
        let err = st.save_message_locked(revoked, &late).unwrap_err();
        assert_eq!(
            (err.code, err.message.as_str(), st.messages.len()),
            (CODE_DENIED, "Sign in before sending requests", messages),
            "in-flight message on the revoked connection"
        );
    }
    let mut before = Vec::new();
    loop {
        let frame = asker.read();
        if frame.get("id") == Some(&Json::from("reissue")) {
            assert!(frame.contains_key("result"), "{text}: {frame:?}");
            return before;
        }
        before.push(frame);
    }
}

/// Checks that frames the revoked connection c sends from now on are
/// ignored, a sign-in included, and that no message reached watcher.
pub fn assert_revoked_runs_nothing(
    server: &TestServer,
    c: &Arc<crate::server::server::Client>,
    watcher: &mut TestClient,
) {
    let (messages, users) = {
        let st = server.app.lock();
        (st.messages.len(), st.users.len())
    };
    server.app.process_frame(c, LATE_POST);
    server.app.process_frame(
        c,
        br#"{"method":"auth","id":"again","params":{"scheme":"guest"}}"#,
    );
    let st = server.app.lock();
    assert_eq!(
        (st.messages.len(), st.users.len(), st.client_user(c)),
        (messages, users, None),
        "the revoked connection posted or signed in"
    );
    drop(st);
    let frames = watcher.drain();
    assert!(
        frames
            .iter()
            .all(|f| f.get("method") != Some(&Json::from("message"))),
        "a message reached a member: {frames:?}"
    );
}

/// Gives user_id `role` in memory only, so a test guest can do what the
/// role allows (guests never hold roles otherwise).
pub fn grant_role(server: &TestServer, user_id: &str, role: &str) {
    let mut st = server.app.lock();
    let u = st.users.get_mut(user_id).expect("user exists");
    if !u.has_role(role) {
        u.roles.push(role.into());
    }
}

pub fn revoke_role(server: &TestServer, user_id: &str, role: &str) {
    let mut st = server.app.lock();
    st.users
        .get_mut(user_id)
        .expect("user exists")
        .roles
        .retain(|r| r != role);
}

/// Makes the guest user_id an account in memory only, one that signs in
/// with a token it was never given, so a test guest can do what only
/// accounts may.
pub fn make_account(server: &TestServer, user_id: &str) {
    server
        .app
        .lock()
        .users
        .get_mut(user_id)
        .expect("user exists")
        .invited = true;
}

/// The wake scopes of a `server` frame's push, failing on any other frame.
pub fn server_wake(frame: &Object) -> Vec<String> {
    assert_eq!(
        frame.get("method"),
        Some(&Json::from("server")),
        "want server: {frame:?}"
    );
    frame["params"].as_object().unwrap()["push"]
        .as_object()
        .unwrap()["wake"]
        .as_list()
        .iter()
        .map(|scope| scope.as_str().unwrap().to_owned())
        .collect()
}

/// Reads the `server` frame a moderator's sign-in sends after its result,
/// which lists wake scope `joined`.
pub fn expect_joined_wake(c: &TestClient) {
    let wake = server_wake(&c.read());
    assert!(wake.iter().any(|s| s == "joined"), "wake scopes {wake:?}");
}

/// Lifts user_id's limit on push_register requests, for tests that make
/// more than a minute's.
pub fn unlimit_push_registers(server: &TestServer, user_id: &str) {
    server
        .app
        .lock()
        .users
        .get_mut(user_id)
        .expect("user exists")
        .push_registers = Some(crate::rate::Limiter::new(crate::rate::INF, 1));
}

/// Sends a request and returns its reply, result or error, skipping the
/// notifications before it.
pub fn reply(c: &mut TestClient, method: &str, id: &str, params: Object) -> Object {
    c.write(&obj! {"method" => method, "id" => id, "params" => params});
    loop {
        let frame = c.read();
        if frame.contains_key("id") {
            return frame;
        }
    }
}

/// The error code of a reply, if it is an error.
pub fn error_code(frame: &Object) -> Option<i64> {
    match frame.get("error")?.as_object()?.get("code")? {
        Json::Number(code) => Some(*code as i64),
        _ => None,
    }
}

/// A body of `size` bytes, at least 16, that starts with a PNG signature,
/// so uploads that only need some image take it.
pub fn png_of_size(size: usize) -> Vec<u8> {
    let mut body = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    body.resize(size.max(body.len()), 0);
    body
}
