//! The relay fixture and the tests of whom a push wakes, from push_test.go,
//! test by test. The rest of push_test.go lives in push_scopes_test.rs,
//! push_registration_test.rs, push_hosts_test.rs, push_badge_test.rs and
//! push_delivery_test.rs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use rust_stdlib::net::http::{handler_func, httptest, Header, ResponseWriter};
use rust_stdlib::time::Duration;

use super::helpers::*;
use super::status_test::{add_account, check_mute, expect_echo};
use crate::obj;
use crate::server::messages::MessageState;
use crate::server::protocol::*;
use crate::server::push::*;

pub(super) struct RelayRequest {
    pub(super) path: String,
    pub(super) header: Header,
    pub(super) body: Vec<u8>,
    pub(super) payload: Option<Object>,
}

impl RelayRequest {
    pub(super) fn header(&self, name: &str) -> &str {
        self.header.get(name).unwrap_or("")
    }

    pub(super) fn payload(&self) -> &Object {
        self.payload.as_ref().expect("a JSON payload")
    }

    pub(super) fn message(&self) -> &Object {
        self.payload()["message"].as_object().expect("message")
    }
}

/// Records the push deliveries it receives. A path ending in /gone answers
/// 410, one ending in /missing 404 and one ending in /forbidden 403; while
/// failing is set, one ending in
/// /flaky answers 500.
pub(super) struct TestRelay {
    http: httptest::Server,
    pub(super) url: String,
    received: Mutex<Receiver<RelayRequest>>,
    pub(super) failing: Arc<AtomicBool>,
}

pub(super) fn new_test_relay() -> TestRelay {
    let (tx, rx): (Sender<RelayRequest>, Receiver<RelayRequest>) = channel();
    let tx = Mutex::new(tx);
    let failing = Arc::new(AtomicBool::new(false));
    let flaky = failing.clone();
    let http = httptest::Server::new(handler_func(move |w: &mut dyn ResponseWriter, r| {
        let body = r
            .body
            .as_ref()
            .map(|b| b.read_all().unwrap())
            .unwrap_or_default();
        let path = r.url.path.clone();
        let payload = if r.header.get("Content-Encoding").unwrap_or("").is_empty() {
            decode_object(&body)
        } else {
            None
        };
        let request = RelayRequest {
            path: path.clone(),
            header: r.header.clone(),
            body,
            payload,
        };
        let _ = tx.lock().unwrap().send(request);
        let status = if path.ends_with("/gone") {
            410
        } else if path.ends_with("/missing") {
            404
        } else if path.ends_with("/forbidden") {
            403
        } else if path.ends_with("/flaky") && flaky.load(Ordering::SeqCst) {
            500
        } else {
            201
        };
        w.write_header(status);
    }))
    .unwrap();
    let url = http.url.clone();
    TestRelay {
        http,
        url,
        received: Mutex::new(rx),
        failing,
    }
}

impl TestRelay {
    /// The deliveries made so far, sorted by path, after the requests c sent
    /// before have finished waking users and their badge pushes have gone
    /// out.
    pub(super) fn pushes(&self, server: &TestServer, c: &mut TestClient) -> Vec<RelayRequest> {
        c.drain();
        server.app.badges.wait();
        server.app.push.wait();
        let mut requests: Vec<RelayRequest> = self.received.lock().unwrap().try_iter().collect();
        requests.sort_by(|a, b| a.path.cmp(&b.path));
        requests
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        self.http.close();
    }
}

pub(super) fn paths(requests: &[RelayRequest]) -> Vec<String> {
    requests.iter().map(|r| r.path.clone()).collect()
}

/// Accepts internal push endpoints and sends badge pushes without waiting
/// to coalesce them.
pub(super) fn push_test_server() -> TestServer {
    let mut config = default_config();
    config.allow_insecure_push = true;
    config.push_hosts = PushHosts::Any;
    config.push_delay = Duration::from_secs(0);
    let server = new_test_server(config);
    server.app.lock().badge_delay = Duration::from_secs(0);
    without_coalescing(&server);
    server
}

/// Lets one user be woken for one room again at once.
pub(super) fn without_coalescing(server: &TestServer) {
    let mut st = server.app.lock();
    st.push_coalesce = Duration::from_secs(0);
    st.joined_coalesce = Duration::from_secs(0);
}

/// Registers an endpoint for a user without a connection.
pub(super) fn add_push(server: &TestServer, user_id: &str, p: PushRegistration) -> String {
    let key = push_key(user_id, &p.url);
    server.app.lock().add_push_locked(PushRegistration {
        user_id: user_id.to_owned(),
        last_unread: -1,
        ..p
    });
    key
}

pub(super) fn relay_push(url: String, wake: WakeScope) -> PushRegistration {
    PushRegistration {
        url,
        wake,
        ..PushRegistration::default()
    }
}

pub(super) fn has_push(server: &TestServer, user_id: &str, url: &str) -> bool {
    server
        .app
        .lock()
        .pushes
        .contains_key(&push_key(user_id, url))
}

/// Signs in n guests and makes each an account, as only accounts register
/// and wake anyone.
pub(super) fn push_group(server: &TestServer, n: usize) -> Vec<TestClient> {
    let clients = dial_group(server, n);
    for c in &clients {
        make_account(server, &c.user_id);
    }
    clients
}

pub(super) fn push_client(server: &TestServer) -> TestClient {
    let c = dial_test_client(server);
    make_account(server, &c.user_id);
    c
}

/// Tells the server nobody attends c, which tells c nothing.
pub(super) fn go_idle(c: &mut TestClient) {
    let frames = c.status(obj! {"idle" => 300i64});
    assert!(frames.is_empty(), "frames after idle: {frames:?}");
}

pub(super) fn strs(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

pub(super) fn list(items: &[&str]) -> Json {
    Json::from(strs(items))
}

#[test]
fn test_push_wakes_mentions_and_replies_of_idle_users() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut clients = push_group(&server, 2);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    add_account(&server, "alice", &[&a, &b]);
    add_push(
        &server,
        "alice",
        PushRegistration {
            token: "tok".into(),
            push_id: "alice-phone".into(),
            ..relay_push(format!("{}/alice", relay.url), WakeScope::DEFAULT)
        },
    );
    add_push(
        &server,
        "alice",
        relay_push(format!("{}/alice/gone", relay.url), WakeScope::DEFAULT),
    );
    let post = |a: &mut TestClient, b: &TestClient, id: &str, params: Object| -> String {
        let (message_id, _) = save(a, id, params);
        b.notification("message");
        message_id
    };

    // Only body.mentions decides who is mentioned; text is never parsed.
    let text = "@alice: the deploy is done";
    let id = post(
        &mut a,
        &b,
        "text",
        obj! {"body" => obj! {"text" => text, "format" => "markdown"}},
    );
    assert!(
        relay.pushes(&server, &mut a).is_empty(),
        "text mention woke"
    );
    // An edit wakes the users it adds to mentions, on every registration.
    post(
        &mut a,
        &b,
        "add-mention",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => text, "format" => "markdown", "mentions" => list(&["alice"])}},
    );
    let got = relay.pushes(&server, &mut a);
    assert_eq!(paths(&got), strs(&["/alice", "/alice/gone"]), "deliveries");
    // The payload is the envelope (§4.9): push_id, unread, and the message
    // without log_id, format, or embeds; the token is the bearer.
    let message = obj! {
        "message_id" => id.as_str(),
        "room_id" => "general",
        "from" => obj! {"user_id" => "guest_1", "name" => "Guest 1"},
        "body" => obj! {"text" => text, "mentions" => list(&["alice"])},
    };
    assert_eq!(
        got[0].payload(),
        &obj! {"push_id" => "alice-phone", "unread" => 1i64, "message" => message.clone()},
        "payload"
    );
    assert!(
        got[0].header("Authorization") == "Bearer tok"
            && got[0].header("Content-Type") == "application/json"
            && got[0].header("Content-Encoding").is_empty(),
        "relay headers: {:?}",
        got[0].header
    );
    assert!(
        got[1].payload() == &obj! {"unread" => 1i64, "message" => message}
            && got[1].header("Authorization").is_empty(),
        "payload without push_id or token: {:?}",
        got[1].payload
    );
    // An endpoint that answers 410 loses its registration.
    assert!(
        !has_push(&server, "alice", &format!("{}/alice/gone", relay.url)),
        "gone registration was kept"
    );
    post(
        &mut a,
        &b,
        "same-mention",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => "edited", "mentions" => list(&["alice"])}},
    );
    assert!(
        relay.pushes(&server, &mut a).is_empty(),
        "an edit re-mentioned"
    );

    // A connected user is woken only when no connection of theirs is
    // attended (§4.5).
    b.result(
        "push_register",
        "b",
        obj! {"kind" => "relay", "url" => format!("{}/b", relay.url)},
    );
    let mention_b =
        || obj! {"body" => obj! {"text" => "@guest_2 ping", "mentions" => list(&["guest_2"])}};
    let held = post(&mut a, &b, "attended", mention_b());
    assert!(
        relay.pushes(&server, &mut a).is_empty(),
        "attended user woken"
    );
    // Going idle pushes what came after attention stopped, which `idle`
    // dates back: 300 seconds, so the mention it was held for.
    go_idle(&mut b);
    let got = relay.pushes(&server, &mut a);
    assert_eq!(paths(&got), strs(&["/b"]), "held wake");
    assert_eq!(got[0].message()["message_id"], Json::from(held.as_str()));
    post(&mut a, &b, "idle", mention_b());
    let got = relay.pushes(&server, &mut a);
    assert!(
        paths(&got) == strs(&["/b"]) && got[0].header("Authorization").is_empty(),
        "idle user: {:?}",
        paths(&got)
    );
    // Neither typing nor a message from the connection ends idle; only
    // idle: false does (§4.5).
    b.write(
        &obj! {"method" => "activity", "params" => obj! {"room_id" => "general", "typing" => 3i64}},
    );
    // Typing reaches the others only.
    a.notification("activity");
    let (own, _) = save(&mut b, "own", obj! {"body" => obj! {"text" => "mine"}});
    a.notification("message");
    post(&mut a, &b, "still-idle", mention_b());
    assert_eq!(
        relay.pushes(&server, &mut a).len(),
        1,
        "typing or a message ended idle"
    );
    let frames = b.status(obj! {"idle" => false});
    assert!(frames.is_empty(), "frames after idle: false: {frames:?}");
    post(&mut a, &b, "back", mention_b());
    assert!(
        relay.pushes(&server, &mut a).is_empty(),
        "user back from idle woken"
    );
    // A reply wakes the author of the message it replies to. `idle: 0`
    // dates the idle to now, so the mention held while they were back is
    // not pushed.
    let frames = b.status(obj! {"idle" => 0i64});
    assert!(frames.is_empty(), "frames after idle: 0: {frames:?}");
    post(
        &mut a,
        &b,
        "reply",
        obj! {"body" => obj! {"text" => "a reply"}, "reply_to" => obj! {"message_id" => own.as_str()}},
    );
    let got = relay.pushes(&server, &mut a);
    assert!(
        got.len() == 1 && got[0].message().contains_key("reply_to"),
        "reply: {:?}",
        paths(&got)
    );
    // Mentions and replies wake a user in any room they can see, joined or
    // not. Mentions in commands notify no one.
    grant_role(&server, &a.user_id, "mod");
    let (ops, _) = save_room(&mut a, "ops", obj! {"title" => "Ops"});
    save(
        &mut a,
        "elsewhere",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "@guest_2", "mentions" => list(&["guest_2"])}},
    );
    let got = relay.pushes(&server, &mut a);
    assert!(
        got.len() == 1 && got[0].message()["room_id"] == Json::from(ops.as_str()),
        "mention in an unjoined room: {:?}",
        paths(&got)
    );
    save(
        &mut a,
        "reply-elsewhere",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "a reply"}, "reply_to" => obj! {"message_id" => own.as_str()}},
    );
    assert_eq!(
        relay.pushes(&server, &mut a).len(),
        1,
        "reply in an unjoined room"
    );
    // A mention in a private room wakes only its members (§4.2.4).
    let (hidden, _) = save_room(
        &mut a,
        "hidden",
        obj! {"title" => "Hidden", "private" => true},
    );
    save(
        &mut a,
        "hidden-mention",
        obj! {"room_id" => hidden.as_str(), "body" => obj! {"text" => "@guest_2", "mentions" => list(&["guest_2"])}},
    );
    assert!(
        relay.pushes(&server, &mut a).is_empty(),
        "mention in a private room woke a non-member"
    );
    let (before, _) = a.request(
        "command",
        "help",
        obj! {"body" => obj! {"text" => "/help", "mentions" => list(&["guest_2"])}},
    );
    assert_eq!(before.len(), 1, "help frames: {before:?}");
    assert!(relay.pushes(&server, &mut a).is_empty(), "command woke");
}

/// Muted users, and those whose status is dnd, get no pushes; nor does a
/// muted room, mentions included (§4.9, §4.5).
#[test]
fn test_push_respects_mutes() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut clients = push_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    grant_role(&server, &b.user_id, "mod");
    b.result(
        "push_register",
        "all",
        obj! {"kind" => "relay", "url" => format!("{}/b", relay.url), "wake" => list(&["joined", "mentions"])},
    );
    go_idle(&mut b);
    let post = |a: &mut TestClient, b: &TestClient, params: Object| {
        let id = a.next_id("post");
        save(a, &id, params);
        b.notification("message");
    };
    let mention = || obj! {"body" => obj! {"text" => "@guest_2", "mentions" => list(&["guest_2"])}};
    let chatter = || obj! {"body" => obj! {"text" => "chatter"}};

    // A muted room wakes for nothing, mentions included.
    expect_echo(
        &mut b,
        obj! {"room_id" => "general", "mute" => true},
        "general",
        Json::from(true),
        &[],
    );
    post(&mut a, &b, chatter());
    post(&mut a, &b, mention());
    assert!(relay.pushes(&server, &mut a).is_empty(), "muted room woke");
    expect_echo(
        &mut b,
        obj! {"room_id" => "general", "mute" => false},
        "general",
        Json::from(false),
        &[],
    );
    post(&mut a, &b, chatter());
    assert_eq!(relay.pushes(&server, &mut a).len(), 1, "unmuted room");
    // A muted user gets no pushes at all, mentions included.
    expect_echo(
        &mut b,
        obj! {"mute" => 3600i64},
        "",
        Json::from(3600i64),
        &[],
    );
    post(&mut a, &b, mention());
    assert!(relay.pushes(&server, &mut a).is_empty(), "muted user woken");
    expect_echo(&mut b, obj! {"mute" => false}, "", Json::from(false), &[]);
    post(&mut a, &b, mention());
    assert_eq!(relay.pushes(&server, &mut a).len(), 1, "unmuted user");
    // A dnd status silences like the mute.
    let you = b.result("me", "dnd", obj! {"status" => "dnd"});
    assert_eq!(you_of(&you)["status"], Json::from("dnd"), "you after dnd");
    // The change reaches a as a named user object, not a bare status.
    a.notification("user");
    post(&mut a, &b, mention());
    assert!(relay.pushes(&server, &mut a).is_empty(), "dnd user woken");
    b.result("me", "online", obj! {"status" => "online"});
    a.notification("user");
    post(&mut a, &b, mention());
    assert_eq!(relay.pushes(&server, &mut a).len(), 1, "online user");

    // A room's mute covers its threads, and applies to a room the user has
    // not joined, mentions and replies alike.
    let (thread, _) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => "general", "title" => "Thread"},
    );
    b.notification("room_update");
    join_room(&mut b, &thread);
    expect_membership(&a, &thread, &b.user_id, true);
    b.status(obj! {"room_id" => "general", "mute" => true});
    save(
        &mut a,
        "in-thread",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "@guest_2", "mentions" => list(&["guest_2"])}},
    );
    b.notification("message");
    assert!(
        relay.pushes(&server, &mut a).is_empty(),
        "thread of a muted room woke"
    );
    b.status(obj! {"room_id" => "general", "mute" => false});
    grant_role(&server, &a.user_id, "mod");
    let (ops, _) = save_room(&mut a, "ops", obj! {"title" => "Ops"});
    let frames = b.status(obj! {"room_id" => ops.as_str(), "mute" => true});
    assert_eq!(
        frames.len(),
        1,
        "frames after muting an unjoined room: {frames:?}"
    );
    check_mute(&frames[0], &ops, &Json::from(true));
    let theirs = format_id(server_message(&server, &b.user_id, "theirs"));
    a.notification("message");
    b.notification("message");
    save(
        &mut a,
        "ops-reply",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "re"}, "reply_to" => obj! {"message_id" => theirs.as_str()}},
    );
    save(
        &mut a,
        "ops-mention",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "@guest_2", "mentions" => list(&["guest_2"])}},
    );
    assert!(
        relay.pushes(&server, &mut a).is_empty(),
        "muted unjoined room woke"
    );
    b.status(obj! {"room_id" => ops.as_str(), "mute" => false});
    save(
        &mut a,
        "ops-mention-again",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "@guest_2", "mentions" => list(&["guest_2"])}},
    );
    let got = relay.pushes(&server, &mut a);
    assert!(
        got.len() == 1 && got[0].header("Urgency") == "high",
        "mention in an unmuted unjoined room: {:?}",
        paths(&got)
    );
}

/// A message by user_id, made in general, as the server would log it; its
/// log_id.
pub(super) fn server_message(server: &TestServer, user_id: &str, text: &str) -> i64 {
    let mut st = server.app.lock();
    let from = st.users[user_id].from();
    let log_id = st.next_id_locked();
    let id = format_id(log_id);
    st.messages.insert(
        id.clone(),
        MessageState {
            id: id.clone(),
            from: from.clone(),
            owner: user_id.to_owned(),
            ..MessageState::default()
        },
    );
    st.commit_snapshot_locked(
        &id,
        obj! {"message_id" => id.as_str(), "log_id" => id.as_str(), "room_id" => "general", "from" => from, "body" => obj! {"text" => text}},
        log_id,
    );
    log_id
}

/// Guests cannot register, so they are never woken; nor do their messages
/// wake anyone (apron-server-cloudflare).
#[test]
fn test_guests_neither_register_nor_wake() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut clients = dial_group(&server, 2);
    let mut guest = clients.pop().unwrap();
    let mut b = clients.pop().unwrap();
    let frame = reply(
        &mut guest,
        "push_register",
        "phone",
        obj! {"kind" => "relay", "url" => format!("{}/phone", relay.url)},
    );
    assert_eq!(
        frame["error"],
        Json::from(
            obj! {"code" => CODE_DENIED, "message" => "Sign in to receive push notifications"}
        ),
        "a guest's push_register"
    );
    guest.expect_error(
        "push_unregister",
        "off",
        obj! {"url" => format!("{}/phone", relay.url)},
        CODE_DENIED,
    );
    make_account(&server, &b.user_id);
    b.result(
        "push_register",
        "b",
        obj! {"kind" => "relay", "url" => format!("{}/b", relay.url)},
    );
    go_idle(&mut b);
    let mention =
        obj! {"body" => obj! {"text" => "hey", "mentions" => list(&[b.user_id.as_str()])}};
    save(&mut guest, "guest-mention", mention);
    b.notification("message");
    assert!(
        relay.pushes(&server, &mut guest).is_empty(),
        "a guest's mention pushed"
    );
}
