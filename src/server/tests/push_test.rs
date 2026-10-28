//! push_test.go, test by test.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use rust_stdlib::context::Context;
use rust_stdlib::net::http::{handler_func, httptest, Header, ResponseWriter};
use rust_stdlib::time::{self, Duration, Time};

use super::helpers::*;
use super::persist_test::{start_with, start_with_store};
use super::status_test::{add_account, check_mute, expect_echo, expect_mute};
use super::webpush_test::{check_vapid, decode, must_decode, test_subscription};
use crate::obj;
use crate::rate::{every, Limiter};
use crate::server::messages::MessageState;
use crate::server::persist::{ENTRY_PUSH, ENTRY_USER};
use crate::server::protocol::*;
use crate::server::push::*;
use crate::server::status::{
    MuteState, StatusUpdate, STATUS_DND, STATUS_INVISIBLE, STATUS_NONE, STATUS_ONLINE,
};
use crate::server::webpush::{decrypt_push, encode_base64_url, parse_push_keys, VapidKey};
use crate::server::{default_config, open, Config};
use crate::store::{self, Entry, Store};
use crate::ws;

struct RelayRequest {
    path: String,
    header: Header,
    body: Vec<u8>,
    payload: Option<Object>,
}

impl RelayRequest {
    fn header(&self, name: &str) -> &str {
        self.header.get(name).unwrap_or("")
    }

    fn payload(&self) -> &Object {
        self.payload.as_ref().expect("a JSON payload")
    }

    fn message(&self) -> &Object {
        self.payload()["message"].as_object().expect("message")
    }
}

/// Records the push deliveries it receives. A path ending in /gone answers
/// 410 and one ending in /missing 404; while failing is set, one ending in
/// /flaky answers 500.
struct TestRelay {
    http: httptest::Server,
    url: String,
    received: Mutex<Receiver<RelayRequest>>,
    failing: Arc<AtomicBool>,
}

fn new_test_relay() -> TestRelay {
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
    fn pushes(&self, server: &TestServer, c: &mut TestClient) -> Vec<RelayRequest> {
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

fn paths(requests: &[RelayRequest]) -> Vec<String> {
    requests.iter().map(|r| r.path.clone()).collect()
}

/// Accepts internal push endpoints and sends badge pushes without waiting
/// to coalesce them.
fn push_test_server() -> TestServer {
    let mut config = default_config();
    config.allow_insecure_push = true;
    let server = new_test_server(config);
    server.app.lock().badge_delay = Duration::from_secs(0);
    server
}

/// Registers an endpoint for a user without a connection.
fn add_push(server: &TestServer, user_id: &str, p: PushRegistration) -> String {
    let key = push_key(user_id, &p.url);
    server.app.lock().add_push_locked(PushRegistration {
        user_id: user_id.to_owned(),
        last_unread: -1,
        ..p
    });
    key
}

fn relay_push(url: String, wake: WakeScope) -> PushRegistration {
    PushRegistration {
        url,
        wake,
        ..PushRegistration::default()
    }
}

fn has_push(server: &TestServer, user_id: &str, url: &str) -> bool {
    server
        .app
        .lock()
        .pushes
        .contains_key(&push_key(user_id, url))
}

/// Tells the server nobody attends c, which tells c nothing.
fn go_idle(c: &mut TestClient) {
    let frames = c.status(obj! {"idle" => 300i64});
    assert!(frames.is_empty(), "frames after idle: {frames:?}");
}

fn strs(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn list(items: &[&str]) -> Json {
    Json::from(strs(items))
}

#[test]
fn test_push_wakes_mentions_and_replies_of_idle_users() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut clients = dial_group(&server, 2);
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
        "from" => obj! {"user_id" => "guest_1"},
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
    post(&mut a, &b, "attended", mention_b());
    assert!(
        relay.pushes(&server, &mut a).is_empty(),
        "attended user woken"
    );
    go_idle(&mut b);
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
    a.notification("activity");
    b.notification("activity");
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
    // A reply wakes the author of the message it replies to.
    go_idle(&mut b);
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

#[test]
fn test_push_registration() {
    let server = push_test_server();
    let mut clients = dial_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    let (_, keys) = test_subscription();
    let endpoint = "https://push.example.net/s/abc";
    let cases: Vec<Object> = vec![
        obj! {"kind" => "ext:other", "url" => endpoint},
        obj! {"kind" => "relay"},
        obj! {"kind" => "relay", "url" => "ftp://relay.example/a"},
        obj! {"kind" => "relay", "url" => "/relative"},
        obj! {"kind" => "relay", "url" => "https://user:pass@relay.example/a"},
        obj! {"kind" => "relay", "url" => "https://relay.example/a b"},
        obj! {"kind" => "relay", "url" => endpoint, "token" => 5i64},
        obj! {"kind" => "relay", "url" => endpoint, "push_id" => ""},
        obj! {"kind" => "relay", "url" => endpoint, "push_id" => "has space"},
        obj! {"kind" => "relay", "url" => endpoint, "push_id" => "dot.ted"},
        obj! {"kind" => "relay", "url" => endpoint, "push_id" => "a".repeat(65)},
        obj! {"kind" => "relay", "url" => endpoint, "push_id" => 7i64},
        obj! {"kind" => "relay", "url" => endpoint, "keys" => "abc"},
        obj! {"kind" => "relay", "url" => endpoint, "keys" => obj! {"p256dh" => keys["p256dh"].clone()}},
        obj! {"kind" => "relay", "url" => endpoint, "keys" => obj! {"p256dh" => "AAAA", "auth" => keys["auth"].clone()}},
        obj! {"kind" => "webpush", "url" => endpoint},
        obj! {"kind" => "webpush", "url" => endpoint, "keys" => obj! {"p256dh" => keys["p256dh"].clone(), "auth" => "AAAA"}},
        obj! {"kind" => "relay", "url" => endpoint, "wake" => "mentions"},
        obj! {"kind" => "relay", "url" => endpoint, "wake" => Json::from(vec![Json::from("mentions"), Json::from(5i64)])},
        obj! {"kind" => "relay", "url" => endpoint, "wake" => Json::Null},
    ];
    for (i, params) in cases.into_iter().enumerate() {
        a.expect_error(
            "push_register",
            &format!("bad-{i}"),
            params,
            CODE_INVALID_PARAMS,
        );
    }
    // A url rejected for its size is too_large (§1.1).
    a.expect_error(
        "push_register",
        "long-url",
        obj! {"kind" => "relay", "url" => format!("https://relay.example/{}", "a".repeat(MAX_PUSH_URL_BYTES))},
        CODE_TOO_LARGE,
    );
    let registration = |user: &str| {
        server
            .app
            .lock()
            .pushes
            .get(&push_key(user, endpoint))
            .cloned()
    };
    // A registration belongs to its user and url: another user's of the
    // same url is their own, and re-registering replaces only the caller's.
    // Scopes the server does not implement are ignored.
    a.result(
        "push_register",
        "webpush",
        obj! {
            "kind" => "webpush", "url" => endpoint, "keys" => keys.clone(), "push_id" => "t65S5XBst9bSDpjJ",
            "wake" => list(&["mentions", "private", "ext:later", "unknown"]), "token" => "ignored",
        },
    );
    b.result(
        "push_register",
        "relay",
        obj! {"kind" => "relay", "url" => endpoint, "token" => "tok"},
    );
    let first = registration(&a.user_id).expect("webpush registration");
    assert!(
        first.kind == "webpush"
            && first.token.is_empty()
            && first.push_id == "t65S5XBst9bSDpjJ"
            && first.wake == WakeScope::MENTIONS | WakeScope::PRIVATE
            && first.keys.is_some(),
        "webpush registration: {first:?}"
    );
    let other = registration(&b.user_id).expect("relay registration");
    assert!(
        other.kind == "relay"
            && other.token == "tok"
            && other.wake == WakeScope::DEFAULT
            && other.keys.is_none(),
        "relay registration: {other:?}"
    );
    a.result(
        "push_register",
        "again",
        obj! {"kind" => "relay", "url" => endpoint, "keys" => keys.clone(), "wake" => Json::from(Vec::<Json>::new())},
    );
    let again = registration(&a.user_id).expect("re-registration");
    assert!(
        again.generation != first.generation
            && again.kind == "relay"
            && again.keys.is_some()
            && again.push_id.is_empty()
            && again.wake.is_empty()
            && !again.renewed.before(&first.renewed),
        "re-registration: {again:?}"
    );
    // Another spelling of the same endpoint is the same registration.
    a.result(
        "push_register",
        "spelling",
        obj! {"kind" => "relay", "url" => "HTTPS://Push.Example.NET:443/s/abc", "keys" => keys.clone(), "wake" => Json::from(Vec::<Json>::new())},
    );
    let spellings = server.app.lock().sorted_pushes(&a.user_id).len();
    assert_eq!(
        spellings, 1,
        "registrations of one endpoint under two spellings"
    );
    a.expect_error(
        "push_register",
        "long",
        obj! {"kind" => "relay", "url" => format!("https://push.example.net/{}", "a".repeat(MAX_PUSH_URL_BYTES - "https://push.example.net/".len() + 1))},
        CODE_TOO_LARGE,
    );
    // Unregistering removes only the caller's; an unknown url succeeds.
    a.result(
        "push_unregister",
        "unregister",
        obj! {"url" => "https://PUSH.example.net/s/abc"},
    );
    a.result(
        "push_unregister",
        "unknown",
        obj! {"url" => "https://push.example.net/never"},
    );
    assert!(
        registration(&a.user_id).is_none() && registration(&b.user_id).is_some(),
        "unregister removed the wrong registration"
    );
    a.expect_error(
        "push_unregister",
        "no-url",
        Object::new(),
        CODE_INVALID_PARAMS,
    );

    // A user holds at most ten; another replaces the least recently
    // registered, and registering a url again renews it.
    for i in 0..MAX_PUSHES_PER_USER {
        a.result(
            "push_register",
            &format!("many-{i}"),
            obj! {"kind" => "relay", "url" => format!("{endpoint}{i}")},
        );
        time::sleep(time::MILLISECOND);
    }
    a.result(
        "push_register",
        "renew",
        obj! {"kind" => "relay", "url" => format!("{endpoint}0")},
    );
    a.result(
        "push_register",
        "eleventh",
        obj! {"kind" => "relay", "url" => format!("{endpoint}new")},
    );
    let prefix = format!("{} {endpoint}", a.user_id);
    let urls: Vec<String> = server
        .app
        .lock()
        .sorted_pushes(&a.user_id)
        .iter()
        .map(|k| k.trim_start_matches(&prefix).to_owned())
        .collect();
    assert!(
        urls.len() == MAX_PUSHES_PER_USER
            && !urls.contains(&"1".to_owned())
            && urls.contains(&"0".to_owned())
            && urls.contains(&"new".to_owned()),
        "registrations after the eleventh: {urls:?}"
    );
    a.expect_quiet();
    b.expect_quiet();
}

/// Wake scopes (§4.9): mentions, replies, private, joined; [] wakes for
/// nothing, and without wake the default is mentions and replies.
#[test]
fn test_push_wake_scopes() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = dial_test_client(&server);
    add_account(&server, "carol", &[&a]);
    for (name, wake) in [
        ("default", WakeScope::DEFAULT),
        ("joined", WakeScope::JOINED),
        ("private", WakeScope::PRIVATE),
        ("replies", WakeScope::REPLIES),
        ("mentions", WakeScope::MENTIONS),
        ("nothing", WakeScope::NONE),
    ] {
        add_push(
            &server,
            "carol",
            relay_push(format!("{}/{name}", relay.url), wake),
        );
    }
    let post = |a: &mut TestClient, params: Object| -> String {
        let id = a.next_id("post");
        save(a, &id, params).0
    };

    // A message in a joined room wakes only joined.
    post(&mut a, obj! {"body" => obj! {"text" => "chatter"}});
    assert_eq!(
        paths(&relay.pushes(&server, &mut a)),
        strs(&["/joined"]),
        "joined room message"
    );
    // A mention wakes mentions and the default, and joined in a joined room.
    post(
        &mut a,
        obj! {"body" => obj! {"text" => "@carol", "mentions" => list(&["carol"])}},
    );
    assert_eq!(
        paths(&relay.pushes(&server, &mut a)),
        strs(&["/default", "/joined", "/mentions"]),
        "mention"
    );
    // A reply to carol's message wakes replies and the default.
    let own = format_id(server_message(&server, "carol", "carol's"));
    a.notification("message");
    post(
        &mut a,
        obj! {"body" => obj! {"text" => "re"}, "reply_to" => obj! {"message_id" => own.as_str()}},
    );
    assert_eq!(
        paths(&relay.pushes(&server, &mut a)),
        strs(&["/default", "/joined", "/replies"]),
        "reply"
    );
    // A message in a private room carol joined wakes private and joined,
    // and so does one in a thread of it.
    let (secret, _) = save_room(
        &mut a,
        "secret",
        obj! {"title" => "Secret", "private" => true},
    );
    a.request(
        "room_join",
        "add-carol",
        obj! {"room_id" => secret.as_str(), "user_id" => "carol"},
    );
    post(
        &mut a,
        obj! {"room_id" => secret.as_str(), "body" => obj! {"text" => "psst"}},
    );
    assert_eq!(
        paths(&relay.pushes(&server, &mut a)),
        strs(&["/joined", "/private"]),
        "private room message"
    );
    let (thread, _) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => secret.as_str(), "private" => false},
    );
    a.request(
        "room_join",
        "add-carol-thread",
        obj! {"room_id" => thread.as_str(), "user_id" => "carol"},
    );
    post(
        &mut a,
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "in the thread"}},
    );
    assert_eq!(
        paths(&relay.pushes(&server, &mut a)),
        strs(&["/joined", "/private"]),
        "private thread message"
    );
    // A room carol has not joined wakes neither joined nor private.
    let (open_room, _) = save_room(&mut a, "open", obj! {"title" => "Open"});
    post(
        &mut a,
        obj! {"room_id" => open_room.as_str(), "body" => obj! {"text" => "elsewhere"}},
    );
    assert!(
        relay.pushes(&server, &mut a).is_empty(),
        "unjoined room message woke"
    );
}

/// Muted users, and those whose status is dnd, get no pushes; nor does a
/// muted room, mentions included (§4.9, §4.5).
#[test]
fn test_push_respects_mutes() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut clients = dial_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
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
    post(&mut a, &b, mention());
    assert!(relay.pushes(&server, &mut a).is_empty(), "dnd user woken");
    b.result("me", "online", obj! {"status" => "online"});
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
fn server_message(server: &TestServer, user_id: &str, text: &str) -> i64 {
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

/// Badge pushes wait badge_delay, so one push carries the count after a
/// burst of changes; a guest's retirement sends none.
#[test]
fn test_badge_pushes_coalesce() {
    let relay = new_test_relay();
    let server = push_test_server();
    server.app.lock().badge_delay = Duration::from_millis(300);
    let mut clients = dial_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    b.result(
        "push_register",
        "phone",
        obj! {"kind" => "relay", "url" => format!("{}/phone", relay.url), "wake" => list(&["badge"])},
    );
    let mut ids = Vec::new();
    for i in 0..3 {
        let request = a.next_id("post");
        let (id, _) = save(
            &mut a,
            &request,
            obj! {"body" => obj! {"text" => i.to_string()}},
        );
        b.notification("message");
        ids.push(id);
    }
    for id in &ids[..2] {
        b.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => "general", "read_message_id" => id.as_str()}});
        a.notification("activity");
        b.notification("activity");
    }
    let got = relay.pushes(&server, &mut a);
    assert!(
        got.len() == 1 && got[0].payload()["unread"] == Json::from(1i64),
        "coalesced badge pushes: {:?}",
        paths(&got)
    );
    // A guest that leaves takes its registrations with it: its leaves send
    // nothing.
    save(&mut a, "more", obj! {"body" => obj! {"text" => "more"}});
    b.notification("message");
    let b_id = b.user_id.clone();
    let _ = b.ws.close(ws::STATUS_NORMAL_CLOSURE, "bye");
    expect_membership(&a, "general", &b_id, false);
    assert!(
        relay.pushes(&server, &mut a).is_empty(),
        "pushes after a guest left"
    );
}

/// Shutdown cancels pending badge pushes rather than waiting out
/// badge_delay.
#[test]
fn test_shutdown_cancels_pending_badges() {
    let relay = new_test_relay();
    let server = push_test_server();
    server.app.lock().badge_delay = time::HOUR;
    let mut a = dial_test_client(&server);
    add_account(&server, "dora", &[&a]);
    add_push(
        &server,
        "dora",
        relay_push(format!("{}/dora", relay.url), WakeScope::BADGE),
    );
    save(&mut a, "post", obj! {"body" => obj! {"text" => "hi"}});
    let pending = server.app.lock().users["dora"].badge_timer.is_some();
    assert!(pending, "no badge push pending");
    let (ctx, cancel) = Context::background().with_timeout(Duration::from_secs(5));
    server
        .app
        .shutdown(&ctx)
        .expect("shutdown with a pending badge");
    cancel();
}

/// webpush deliveries are RFC 8291 ciphertext signed with VAPID (RFC 8292),
/// and so are relay deliveries with keys, with the relay's token.
#[test]
fn test_web_push_delivery() {
    let relay = new_test_relay();
    let mut config = default_config();
    config.allow_insecure_push = true;
    config.public_url = "https://chat.example".into();
    let server = new_test_server(config);
    let (mut c, frame) = dial_raw(&server);
    guest_auth(&mut c);
    let key = frame["params"].as_object().unwrap()["push"]
        .as_object()
        .unwrap()["webpush"]
        .as_object()
        .unwrap()["key"]
        .as_str()
        .unwrap()
        .to_owned();
    let (browser, keys) = test_subscription();
    let auth = must_decode(keys["auth"].as_str().unwrap());
    c.result(
        "push_register",
        "web",
        obj! {"kind" => "webpush", "url" => format!("{}/web", relay.url), "keys" => keys.clone(), "push_id" => "web-1"},
    );
    c.result(
        "push_register",
        "relay",
        obj! {"kind" => "relay", "url" => format!("{}/relay", relay.url), "keys" => keys.clone(), "token" => "tok", "push_id" => "relay-1"},
    );
    go_idle(&mut c);
    let mut poster = dial_test_client(&server);
    expect_membership(&c, "general", &poster.user_id, true);
    save(
        &mut poster,
        "mention",
        obj! {"body" => obj! {"text" => "hi @guest_1", "format" => "markdown", "mentions" => list(&["guest_1"])}},
    );
    c.notification("message");
    let got = relay.pushes(&server, &mut poster);
    assert_eq!(paths(&got), strs(&["/relay", "/web"]), "deliveries");
    for request in &got {
        assert!(
            request.header("Content-Encoding") == "aes128gcm"
                && request.header("Content-Type") == "application/octet-stream",
            "{} headers: {:?}",
            request.path,
            request.header
        );
        let payload = decode(&decrypt_push(&request.body, &browser, &auth).expect("decrypt"));
        let message_id = payload["message"].as_object().unwrap()["message_id"].clone();
        let want = obj! {
            "push_id" => format!("{}-1", request.path.trim_start_matches('/')),
            "unread" => 1i64,
            "message" => obj! {
                "message_id" => message_id, "room_id" => "general", "from" => obj! {"user_id" => "guest_2"},
                "body" => obj! {"text" => "hi @guest_1", "mentions" => list(&["guest_1"])},
            },
        };
        assert_eq!(payload, want, "{} payload", request.path);
    }
    // Relays get TTL and Urgency too (§4.9).
    assert!(
        got[0].header("Authorization") == "Bearer tok"
            && got[0].header("TTL") == "86400"
            && got[0].header("Urgency") == "high",
        "relay headers: {:?}",
        got[0].header
    );
    assert!(
        got[1].header("TTL") == "86400" && got[1].header("Urgency") == "high",
        "webpush headers: {:?}",
        got[1].header
    );
    // The VAPID token is for the endpoint's origin, signed with the key the
    // server frame advertises, with the public URL as its contact.
    let claims = check_vapid(got[1].header("Authorization"), &key);
    assert!(
        claims["aud"] == Json::from(relay.url.as_str())
            && claims["sub"] == Json::from("https://chat.example"),
        "claims: {claims:?}"
    );
    // A subscription that answers 404 is removed, for any kind.
    c.result(
        "push_register",
        "missing",
        obj! {"kind" => "webpush", "url" => format!("{}/web/missing", relay.url), "keys" => keys.clone()},
    );
    save(
        &mut poster,
        "again",
        obj! {"body" => obj! {"text" => "again", "mentions" => list(&["guest_1"])}},
    );
    c.notification("message");
    assert_eq!(
        paths(&relay.pushes(&server, &mut poster)),
        strs(&["/relay", "/web", "/web/missing"]),
        "deliveries"
    );
    assert!(
        !has_push(&server, &c.user_id, &format!("{}/web/missing", relay.url)),
        "a webpush subscription answering 404 was kept"
    );
}

#[test]
fn test_push_payload_fits_in_limit() {
    let mut snapshot = obj! {
        "message_id" => "1724803200042", "log_id" => "1724803200043", "room_id" => "general",
        "from" => obj! {"user_id" => "alice", "name" => "Alice"},
        "reply_to" => obj! {"message_id" => "1724803200001"},
        "body" => obj! {"text" => "short", "format" => "markdown", "embeds" => Json::from(vec![Json::from(obj! {"kind" => "upload"})])},
        "ext" => obj! {"x" => 1i64},
    };
    let decode_payload = |payload: Vec<u8>| -> Object {
        assert!(
            payload.len() <= MAX_PUSH_PAYLOAD_BYTES,
            "payload of {} bytes",
            payload.len()
        );
        decode(&payload)
    };
    let body_of = |value: &Object| {
        value["message"].as_object().unwrap()["body"]
            .as_object()
            .unwrap()
            .clone()
    };
    let got = decode_payload(push_payload("p", 3, &snapshot));
    let want = obj! {"push_id" => "p", "unread" => 3i64, "message" => obj! {
        "message_id" => "1724803200042", "room_id" => "general", "from" => obj! {"user_id" => "alice", "name" => "Alice"},
        "reply_to" => obj! {"message_id" => "1724803200001"}, "body" => obj! {"text" => "short"},
    }};
    assert_eq!(got, want, "payload");
    // Text is truncated to MAX_PUSH_TEXT_RUNES.
    snapshot.insert(
        "body".into(),
        obj! {"text" => "e".repeat(MAX_PUSH_TEXT_RUNES + 500)}.into(),
    );
    let text = body_of(&decode_payload(push_payload("", 0, &snapshot)))["text"]
        .as_str()
        .unwrap()
        .to_owned();
    let runes: Vec<char> = text.chars().collect();
    assert!(
        runes.len() == MAX_PUSH_TEXT_RUNES && runes.last() == Some(&'…'),
        "truncated text: {} runes",
        runes.len()
    );
    // Mentions go first.
    let many: Vec<String> = (0..200)
        .map(|i| format!("a_rather_long_user_id_{i}"))
        .collect();
    snapshot.insert(
        "body".into(),
        obj! {"text" => "hi", "mentions" => many}.into(),
    );
    assert_eq!(
        body_of(&decode_payload(push_payload("", 0, &snapshot))),
        obj! {"text" => "hi"},
        "body without mentions"
    );
    // Then text is shortened to fit.
    snapshot.insert(
        "body".into(),
        obj! {"text" => "\u{2028}".repeat(MAX_PUSH_TEXT_RUNES)}.into(),
    );
    let payload = push_payload("", 0, &snapshot);
    let size = payload.len();
    let text = body_of(&decode_payload(payload))["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        text.ends_with('…') && size >= MAX_PUSH_PAYLOAD_BYTES - 16,
        "shortened text: {size} bytes of payload"
    );
    // Then body goes, from keeps only user_id, and reply_to goes.
    snapshot.insert("body".into(), obj! {"text" => "hi"}.into());
    snapshot.insert(
        "from".into(),
        obj! {"user_id" => "alice", "name" => "\\".repeat(3000)}.into(),
    );
    let value = decode_payload(push_payload("", 0, &snapshot));
    let message = value["message"].as_object().unwrap();
    assert!(
        !message.contains_key("body")
            && message["from"] == Json::from(obj! {"user_id" => "alice"})
            && message.contains_key("reply_to"),
        "message without body and name: {message:?}"
    );
}

#[test]
fn test_push_registrations_expire() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = dial_test_client(&server);
    add_account(&server, "dora", &[&a]);
    let stale = add_push(
        &server,
        "dora",
        PushRegistration {
            renewed: time::now().add(-PUSH_EXPIRY - time::MINUTE),
            ..relay_push(format!("{}/stale", relay.url), WakeScope::DEFAULT)
        },
    );
    add_push(
        &server,
        "dora",
        PushRegistration {
            renewed: time::now().add(-PUSH_EXPIRY + time::HOUR),
            ..relay_push(format!("{}/fresh", relay.url), WakeScope::DEFAULT)
        },
    );
    save(
        &mut a,
        "mention",
        obj! {"body" => obj! {"text" => "@dora", "mentions" => list(&["dora"])}},
    );
    assert_eq!(
        paths(&relay.pushes(&server, &mut a)),
        strs(&["/fresh"]),
        "deliveries"
    );
    assert!(
        !server.app.lock().pushes.contains_key(&stale),
        "an expired registration was kept"
    );
}

/// unread is the user's one count of messages after their read positions,
/// the same in every registration's pushes, and badge pushes, without a
/// message and with Urgency low, send each change of it to the relay
/// registrations with scope badge (§4.9).
#[test]
fn test_push_unread_and_badge() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut clients = dial_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    b.result(
        "push_register",
        "phone",
        obj! {"kind" => "relay", "url" => format!("{}/phone", relay.url), "push_id" => "phone", "wake" => list(&["joined", "badge"])},
    );
    b.result(
        "push_register",
        "web",
        obj! {"kind" => "relay", "url" => format!("{}/mentions", relay.url), "wake" => list(&["mentions", "badge"])},
    );
    let (_, keys) = test_subscription();
    b.result(
        "push_register",
        "browser",
        obj! {"kind" => "webpush", "url" => format!("{}/browser", relay.url), "keys" => keys, "wake" => list(&["joined", "badge"])},
    );
    go_idle(&mut b);
    /// Each delivery's path, unread, Urgency, and whether it carries a
    /// message.
    #[derive(Debug, PartialEq)]
    struct Delivery(String, Json, String, bool);
    let d = |path: &str, unread: i64, urgency: &str, message: bool| {
        Delivery(path.into(), Json::from(unread), urgency.into(), message)
    };
    let browser = || {
        Delivery(
            "/browser".into(),
            Json::from("encrypted"),
            "normal".into(),
            true,
        )
    };
    let expect = |a: &mut TestClient, want: Vec<Delivery>| {
        let got: Vec<Delivery> = relay
            .pushes(&server, a)
            .iter()
            .map(|r| match &r.payload {
                Some(payload) => Delivery(
                    r.path.clone(),
                    payload.get("unread").cloned().unwrap_or_default(),
                    r.header("Urgency").into(),
                    payload.contains_key("message"),
                ),
                None => Delivery(
                    r.path.clone(),
                    Json::from("encrypted"),
                    r.header("Urgency").into(),
                    true,
                ),
            })
            .collect();
        assert_eq!(got, want, "deliveries");
    };
    let post = |a: &mut TestClient, b: &TestClient, params: Object| -> String {
        let id = a.next_id("post");
        let (message_id, _) = save(a, &id, params);
        b.notification("message");
        message_id
    };
    let read = |b: &mut TestClient, others: &[&TestClient], room_id: &str, message_id: &str| {
        b.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => room_id, "read_message_id" => message_id}});
        for c in others {
            c.notification("activity");
        }
        b.notification("activity");
    };
    // A message no scope of /mentions selects still changes the count it
    // shows: it gets a badge push.
    let first = post(&mut a, &b, obj! {"body" => obj! {"text" => "one"}});
    expect(
        &mut a,
        vec![
            browser(),
            d("/mentions", 1, "low", false),
            d("/phone", 1, "normal", true),
        ],
    );
    let second = post(
        &mut a,
        &b,
        obj! {"body" => obj! {"text" => "@guest_2", "mentions" => list(&["guest_2"])}},
    );
    expect(
        &mut a,
        vec![
            browser(),
            d("/mentions", 2, "high", true),
            d("/phone", 2, "normal", true),
        ],
    );
    // Reading on another connection sends badge pushes to relay
    // registrations whose count changed; webpush ignores badge.
    read(&mut b, &[&a], "general", &first);
    expect(
        &mut a,
        vec![
            d("/mentions", 1, "low", false),
            d("/phone", 1, "low", false),
        ],
    );
    read(&mut b, &[&a], "general", &second);
    expect(
        &mut a,
        vec![
            d("/mentions", 0, "low", false),
            d("/phone", 0, "low", false),
        ],
    );
    // Deleting a counted message lowers the count.
    let third = post(&mut a, &b, obj! {"body" => obj! {"text" => "three"}});
    expect(
        &mut a,
        vec![
            browser(),
            d("/mentions", 1, "low", false),
            d("/phone", 1, "normal", true),
        ],
    );
    a.request(
        "message",
        "delete",
        obj! {"room_id" => "general", "message_id" => third.as_str(), "deleted" => true},
    );
    b.notification("message");
    expect(
        &mut a,
        vec![
            d("/mentions", 0, "low", false),
            d("/phone", 0, "low", false),
        ],
    );
    // The user's own message moves their read position.
    post(&mut a, &b, obj! {"body" => obj! {"text" => "four"}});
    expect(
        &mut a,
        vec![
            browser(),
            d("/mentions", 1, "low", false),
            d("/phone", 1, "normal", true),
        ],
    );
    save(&mut b, "own", obj! {"body" => obj! {"text" => "mine"}});
    a.notification("message");
    expect(
        &mut a,
        vec![
            d("/mentions", 0, "low", false),
            d("/phone", 0, "low", false),
        ],
    );
    // A mention in a room the user has not joined counts until read there.
    let (ops, _) = save_room(&mut a, "ops", obj! {"title" => "Ops"});
    let (elsewhere, _) = save(
        &mut a,
        "elsewhere",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "@guest_2", "mentions" => list(&["guest_2"])}},
    );
    expect(
        &mut a,
        vec![
            d("/mentions", 1, "high", true),
            d("/phone", 1, "low", false),
        ],
    );
    read(&mut b, &[], &ops, &elsewhere);
    expect(
        &mut a,
        vec![
            d("/mentions", 0, "low", false),
            d("/phone", 0, "low", false),
        ],
    );
    // A message moved into a joined room counts there from its move.
    let (moved, _) = save(
        &mut a,
        "to-move",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "moving"}},
    );
    expect(&mut a, vec![]);
    let (before, _) = a.request(
        "message",
        "move",
        obj! {"message_id" => moved.as_str(), "room_id" => "general", "body" => obj! {"text" => "moving"}},
    );
    assert_eq!(before.len(), 1, "frames before the move result: {before:?}");
    b.notification("message");
    expect(
        &mut a,
        vec![
            d("/mentions", 1, "low", false),
            d("/phone", 1, "low", false),
        ],
    );
    read(&mut b, &[&a], "general", &moved);
    expect(
        &mut a,
        vec![
            d("/mentions", 0, "low", false),
            d("/phone", 0, "low", false),
        ],
    );
    // What a mute silences reaches only registrations with scope badge,
    // without a message.
    b.status(obj! {"mute" => true});
    post(
        &mut a,
        &b,
        obj! {"body" => obj! {"text" => "@guest_2", "mentions" => list(&["guest_2"])}},
    );
    expect(
        &mut a,
        vec![
            d("/mentions", 1, "low", false),
            d("/phone", 1, "low", false),
        ],
    );
    // So does what a dnd status silences.
    b.status(obj! {"mute" => false});
    b.result("me", "dnd", obj! {"status" => "dnd"});
    post(
        &mut a,
        &b,
        obj! {"body" => obj! {"text" => "@guest_2", "mentions" => list(&["guest_2"])}},
    );
    expect(
        &mut a,
        vec![
            d("/mentions", 2, "low", false),
            d("/phone", 2, "low", false),
        ],
    );
    // A room's mute leaves what it silences out of unread, mentions too.
    b.result("me", "online", obj! {"status" => "online"});
    b.status(obj! {"room_id" => "general", "mute" => true});
    expect(
        &mut a,
        vec![
            d("/mentions", 0, "low", false),
            d("/phone", 0, "low", false),
        ],
    );
    post(
        &mut a,
        &b,
        obj! {"body" => obj! {"text" => "@guest_2", "mentions" => list(&["guest_2"])}},
    );
    expect(&mut a, vec![]);
}

/// Registrations, with their keys, push_id, and scopes, survive a restart,
/// and so do the VAPID key and the status and mutes the user set (§4.5). A
/// stored status the server does not support loads as "".
#[test]
fn test_push_and_status_survive_restart() {
    let memory: Arc<dyn Store> = Arc::new(store::Memory::new());
    let (_, keys) = test_subscription();
    let relay_url = "https://relay.example/erin";
    let stored = crate::server::persist::StoredPush {
        user: "erin".into(),
        kind: "relay".into(),
        url: relay_url.into(),
        token: "tok".into(),
        wake: WakeScope::DEFAULT.names(),
        renewed: time::now(),
        ..Default::default()
    };
    memory
        .apply(&[
            Entry::put(
                ENTRY_USER,
                "erin",
                br#"{"name":"Erin","passkey":{"handle":"aA=="}}"#.to_vec(),
            ),
            Entry::put(
                ENTRY_USER,
                "finn",
                br#"{"name":"Finn","passkey":{"handle":"aA=="},"status":"invisible"}"#.to_vec(),
            ),
            Entry::put(
                ENTRY_USER,
                "gail",
                br#"{"name":"Gail","passkey":{"handle":"aQ=="},"status":"away"}"#.to_vec(),
            ),
            Entry::put(
                ENTRY_PUSH,
                &push_key("erin", relay_url),
                encode_json(&stored).unwrap(),
            ),
        ])
        .unwrap();
    let dir = TempDir::new("apron-push-");
    let mut server = start_with_store(memory.clone(), &dir);
    let (_, frame) = dial_raw(&server);
    let key = frame["params"].as_object().unwrap()["push"]
        .as_object()
        .unwrap()["webpush"]
        .as_object()
        .unwrap()["key"]
        .clone();
    {
        let mut st = server.app.lock();
        let relay = st.pushes.get(&push_key("erin", relay_url)).cloned();
        assert!(
            relay.as_ref().is_some_and(|r| r.token == "tok"
                && r.wake == WakeScope::DEFAULT
                && r.live(&time::now())),
            "relay registration: {relay:?}"
        );
        let subscription = parse_push_keys(
            keys["p256dh"].as_str().unwrap(),
            keys["auth"].as_str().unwrap(),
        )
        .unwrap();
        st.add_push_locked(PushRegistration {
            user_id: "erin".into(),
            kind: "webpush".into(),
            url: "https://push.example/s".into(),
            push_id: "p1".into(),
            keys: Some(subscription),
            wake: WakeScope::JOINED | WakeScope::BADGE,
            ..PushRegistration::default()
        });
        let (erin, finn, gail) = (
            &st.users["erin"].chosen,
            &st.users["finn"].chosen,
            &st.users["gail"].chosen,
        );
        assert!(
            finn == STATUS_INVISIBLE && gail == STATUS_NONE && erin == STATUS_ONLINE,
            "loaded statuses: erin {erin:?} finn {finn:?} gail {gail:?}"
        );
        let erin = st.users.get_mut("erin").unwrap();
        erin.chosen = STATUS_DND.into();
        erin.mute = MuteState {
            forever: false,
            until: time::now().add(time::HOUR),
        };
        erin.room_mutes.insert(
            "general".into(),
            MuteState {
                forever: true,
                until: Time::default(),
            },
        );
        st.users.get_mut("finn").unwrap().chosen = STATUS_NONE.into();
        st.touch_user("erin");
        st.touch_user("finn");
    }
    server.stop();

    let dir2 = TempDir::new("apron-push-");
    let server = start_with_store(memory.clone(), &dir2);
    let (_, frame) = dial_raw(&server);
    let again = frame["params"].as_object().unwrap()["push"]
        .as_object()
        .unwrap()["webpush"]
        .as_object()
        .unwrap()["key"]
        .clone();
    assert_eq!(again, key, "VAPID key changed across a restart");
    {
        let st = server.app.lock();
        let web = st.pushes.get(&push_key("erin", "https://push.example/s"));
        assert!(
            web.is_some_and(|w| w.kind == "webpush"
                && w.push_id == "p1"
                && w.wake == WakeScope::JOINED | WakeScope::BADGE
                && w.keys
                    .as_ref()
                    .is_some_and(|k| encode_base64_url(&k.auth) == keys["auth"].as_str().unwrap())),
            "webpush registration after restart: {web:?}"
        );
        assert!(
            st.pushes.contains_key(&push_key("erin", relay_url)) && st.pushes.len() == 2,
            "registrations after restart: {:?}",
            st.pushes.keys()
        );
        let erin = &st.users["erin"];
        assert!(
            erin.chosen == STATUS_DND
                && st.users["finn"].chosen == STATUS_NONE
                && erin.mute.active(&time::now())
                && erin.room_mutes["general"].forever,
            "status after restart: {:?} {:?}",
            erin.chosen,
            st.users["finn"].chosen
        );
    }
    let mut stored = Vec::new();
    memory
        .load(&mut |e| {
            if e.kind == ENTRY_PUSH {
                stored.push(e.id);
            }
            Ok(())
        })
        .unwrap();
    stored.sort();
    assert_eq!(
        stored,
        strs(&[
            "erin https://push.example/s",
            "erin https://relay.example/erin"
        ]),
        "stored registrations"
    );
    // A configured VAPID key replaces the stored one, and a malformed one
    // stops the server from starting.
    let configured = VapidKey::generate().unwrap();
    let mut config = default_config();
    config.vapid_private_key = configured.encoded();
    let configured_server = new_test_server(config.clone());
    let public = configured_server
        .app
        .lock()
        .vapid
        .as_ref()
        .unwrap()
        .public
        .clone();
    assert_eq!(
        public, configured.public,
        "the configured VAPID key is not used"
    );
    config.vapid_private_key = "nope".into();
    assert!(open(config).is_err(), "a malformed VAPID key was accepted");
}

/// A user gets at most MAX_PUSHES_PER_USER_DAY pushes a day, counting only
/// those their endpoints accepted.
#[test]
fn test_pushes_per_user_day() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = dial_test_client(&server);
    add_account(&server, "dora", &[&a]);
    add_push(
        &server,
        "dora",
        relay_push(format!("{}/broken/missing", relay.url), WakeScope::DEFAULT),
    );
    let mention = |a: &mut TestClient| -> usize {
        let id = a.next_id("mention");
        save(
            a,
            &id,
            obj! {"body" => obj! {"text" => "@dora", "mentions" => list(&["dora"])}},
        );
        relay.pushes(&server, a).len()
    };
    let today = || {
        let mut st = server.app.lock();
        st.users
            .get_mut("dora")
            .unwrap()
            .pushes_today_locked(&time::now())
    };
    // Refused deliveries count nothing (and 404 forgets the registration).
    assert_eq!(mention(&mut a), 1, "deliveries");
    assert_eq!(today(), 0, "a refused push counted");
    add_push(
        &server,
        "dora",
        relay_push(format!("{}/dora", relay.url), WakeScope::DEFAULT),
    );
    assert_eq!(mention(&mut a), 1, "deliveries");
    assert_eq!(today(), 1, "an accepted push counted");
    server
        .app
        .lock()
        .users
        .get_mut("dora")
        .unwrap()
        .pushes_today = MAX_PUSHES_PER_USER_DAY;
    assert_eq!(mention(&mut a), 0, "deliveries past the daily cap");
    // A new day starts over.
    server.app.lock().users.get_mut("dora").unwrap().push_day = "2000-01-01".into();
    assert_eq!(mention(&mut a), 1, "deliveries on a new day");
}

#[test]
fn test_push_refuses_internal_addresses() {
    let hits = Arc::new(AtomicI32::new(0));
    let counter = hits.clone();
    let mut relay = httptest::Server::new(handler_func(move |_w: &mut dyn ResponseWriter, _r| {
        counter.fetch_add(1, Ordering::SeqCst);
    }))
    .unwrap();
    let deliverer = PushDeliverer::new(false, String::new());
    let called = Arc::new(AtomicBool::new(false));
    let flag = called.clone();
    deliverer.deliver(
        PushRegistration {
            url: relay.url.clone(),
            ..PushRegistration::default()
        },
        b"{}".to_vec(),
        "normal",
        String::new(),
        Box::new(move |status| flag.store(status != 0, Ordering::SeqCst)),
    );
    deliverer.wait();
    relay.close();
    assert!(
        hits.load(Ordering::SeqCst) == 0 && !called.load(Ordering::SeqCst),
        "delivered to a loopback address: hits={} called={}",
        hits.load(Ordering::SeqCst),
        called.load(Ordering::SeqCst)
    );
    assert!(
        check_push_url("http://relay.example/p", false).is_err(),
        "http push URL accepted without allow_insecure_push"
    );
    // Internal address literals, localhost, and hosts ending in a dot are
    // refused at registration.
    for endpoint in [
        "https://10.0.0.1/p",
        "https://[::1]/p",
        "https://[fd00::1]:8443/p",
        "https://169.254.169.254/p",
        "https://localhost/p",
        "https://push.localhost/p",
        "https://192.0.2.1/p",
        "https://push.example.net./p",
        "mailto:a@b.example",
    ] {
        assert!(
            check_push_url(endpoint, false).is_err(),
            "{endpoint} accepted"
        );
    }
    // Endpoints are kept in one form: scheme and host lowercased, no
    // default port.
    for (endpoint, want) in [
        ("https://93.184.215.14/p", "https://93.184.215.14/p"),
        (
            "https://fcm.googleapis.com/fcm/send/x",
            "https://fcm.googleapis.com/fcm/send/x",
        ),
        (
            "HTTPS://FCM.GoogleAPIs.com:443/fcm/send/x",
            "https://fcm.googleapis.com/fcm/send/x",
        ),
        (
            "https://push.example.net:8443/A?b=C",
            "https://push.example.net:8443/A?b=C",
        ),
        (
            "https://[2606:4700::1111]:443/p",
            "https://[2606:4700::1111]/p",
        ),
    ] {
        assert_eq!(
            check_push_url(endpoint, false),
            Ok(want.to_owned()),
            "{endpoint}"
        );
    }
}

/// Fills the host's lane of deliverer with deliveries to busy_url that the
/// relay holds until released, and waits until it has them all.
fn fill_lane(deliverer: &Arc<PushDeliverer>, busy_url: &str, started: impl Fn() -> bool) {
    for _ in 0..MAX_PUSH_PER_HOST {
        deliverer.deliver(
            PushRegistration {
                user_id: "filler".into(),
                url: busy_url.to_owned(),
                ..PushRegistration::default()
            },
            b"{}".to_vec(),
            "normal",
            String::new(),
            Box::new(|_| {}),
        );
    }
    let deadline = time::now().add(time::SECOND * 2);
    while time::now().before(&deadline) && !started() {
        time::sleep(time::MILLISECOND * 5);
    }
}

/// A gate the test relays hold requests at until it opens.
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    cv: std::sync::Condvar,
}

impl Gate {
    fn wait(&self) {
        let open = self.open.lock().unwrap();
        let _unused = self
            .cv
            .wait_timeout_while(open, std::time::Duration::from_secs(15), |open| !*open)
            .unwrap();
    }

    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.cv.notify_all();
    }
}

/// Badge deliveries for one registration that have not started give way to
/// the latest; lanes are per host, ignoring case.
#[test]
fn test_push_deliveries_coalesce_badges() {
    let release = Arc::new(Gate::default());
    let bodies = Arc::new(Mutex::new(Vec::<String>::new()));
    let (gate, seen) = (release.clone(), bodies.clone());
    let mut relay = httptest::Server::new(handler_func(move |_w: &mut dyn ResponseWriter, r| {
        let body = r
            .body
            .as_ref()
            .map(|b| b.read_all().unwrap())
            .unwrap_or_default();
        seen.lock().unwrap().push(String::from_utf8(body).unwrap());
        gate.wait();
    }))
    .unwrap();
    let deliverer = PushDeliverer::new(true, String::new());
    // Fill the host's lane so later deliveries wait.
    let local = relay.url.replace("127.0.0.1", "localhost");
    fill_lane(&deliverer, &format!("{local}/busy"), || {
        bodies.lock().unwrap().len() == MAX_PUSH_PER_HOST
    });
    let upper = relay.url.replace("127.0.0.1", "LocalHost");
    for i in 0..3 {
        deliverer.deliver(
            PushRegistration {
                user_id: "u".into(),
                url: format!("{upper}/badge"),
                ..PushRegistration::default()
            },
            i.to_string().into_bytes(),
            "low",
            format!("u {upper}/badge"),
            Box::new(|_| {}),
        );
    }
    let (lanes, queued) = (deliverer.lanes(), deliverer.queued_for("u"));
    release.release();
    deliverer.wait();
    relay.close();
    assert!(
        lanes == 1 && queued == 1,
        "lanes {lanes}, queued badge deliveries {queued}"
    );
    let bodies = bodies.lock().unwrap();
    assert!(
        bodies.contains(&"2".to_owned())
            && !bodies.contains(&"0".to_owned())
            && !bodies.contains(&"1".to_owned()),
        "delivered bodies: {bodies:?}"
    );
}

#[test]
fn test_push_lanes_isolate_stalled_relays() {
    let release = Arc::new(Gate::default());
    let stalled = Arc::new(AtomicI32::new(0));
    let (gate, count) = (release.clone(), stalled.clone());
    let mut slow = httptest::Server::new(handler_func(move |_w: &mut dyn ResponseWriter, _r| {
        count.fetch_add(1, Ordering::SeqCst);
        gate.wait();
    }))
    .unwrap();
    let (tx, delivered) = channel::<()>();
    let tx = Mutex::new(tx);
    let mut fast = httptest::Server::new(handler_func(move |w: &mut dyn ResponseWriter, _r| {
        let _ = tx.lock().unwrap().send(());
        w.write_header(204);
    }))
    .unwrap();
    let deliverer = PushDeliverer::new(true, String::new());
    let finish = |slow: &mut httptest::Server, fast: &mut httptest::Server| {
        release.release();
        deliverer.wait();
        slow.close();
        fast.close();
    };
    let deliver = |user: &str, url: String| {
        deliverer.deliver(
            PushRegistration {
                user_id: user.into(),
                url,
                ..PushRegistration::default()
            },
            b"{}".to_vec(),
            "normal",
            String::new(),
            Box::new(|_| {}),
        );
    };

    // One user queues at most MAX_PUSH_QUEUED_PER_USER deliveries.
    for _ in 0..MAX_PUSH_QUEUED_PER_USER + 5 {
        deliver("spammer", format!("{}/slow", slow.url));
    }
    let queued = deliverer.queued_for("spammer");
    for i in 0..MAX_CONCURRENT_PUSH_POST {
        deliver(&format!("user{i}"), format!("{}/slow", slow.url));
    }
    let deadline = time::now().add(time::SECOND);
    while (stalled.load(Ordering::SeqCst) as usize) < MAX_PUSH_PER_HOST
        && time::now().before(&deadline)
    {
        time::sleep(time::MILLISECOND * 10);
    }
    let concurrent = stalled.load(Ordering::SeqCst) as usize;
    // Another push host has its own lane.
    deliver("victim", format!("{}/fast", fast.url));
    let reached = delivered
        .recv_timeout(std::time::Duration::from_secs(2))
        .is_ok();
    finish(&mut slow, &mut fast);
    assert_eq!(
        queued, MAX_PUSH_QUEUED_PER_USER,
        "queued deliveries for one user"
    );
    assert_eq!(
        concurrent, MAX_PUSH_PER_HOST,
        "concurrent deliveries to one host"
    );
    assert!(
        reached,
        "a stalled push host blocked delivery to another host"
    );
}

/// With push disabled, stored registrations are kept but not loaded;
/// enabled again, they apply.
#[test]
fn test_disabled_push_ignores_stored_registrations() {
    let memory: Arc<dyn Store> = Arc::new(store::Memory::new());
    let url = "https://relay.example/erin";
    let stored = crate::server::persist::StoredPush {
        user: "erin".into(),
        kind: "relay".into(),
        url: url.into(),
        renewed: time::now(),
        ..Default::default()
    };
    memory
        .apply(&[
            Entry::put(
                ENTRY_USER,
                "erin",
                br#"{"name":"Erin","passkey":{"handle":"aA=="}}"#.to_vec(),
            ),
            Entry::put(
                ENTRY_PUSH,
                &push_key("erin", url),
                encode_json(&stored).unwrap(),
            ),
        ])
        .unwrap();
    let dir = TempDir::new("apron-push-");
    let mut server = start_with(memory.clone(), &dir, |c: &mut Config| c.disable_push = true);
    assert_eq!(server.app.lock().pushes.len(), 0, "with push disabled");
    server.stop();
    let server = start_with_store(memory, &dir);
    assert_eq!(server.app.lock().pushes.len(), 1, "with push enabled again");
    drop(server);
}

/// A count is recorded as an endpoint's only once it accepts the push with
/// a 2xx: a badge push that failed is sent again at the next change, even
/// one that leaves the count where it was (§4.9).
#[test]
fn test_badge_count_recorded_only_when_accepted() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = dial_test_client(&server);
    add_account(&server, "alice", &[&a]);
    add_push(
        &server,
        "alice",
        relay_push(format!("{}/flaky", relay.url), WakeScope::BADGE),
    );
    relay.failing.store(true, Ordering::SeqCst);
    save(&mut a, "post", obj! {"body" => obj! {"text" => "hi"}});
    let got = relay.pushes(&server, &mut a);
    assert!(
        got.len() == 1 && got[0].payload()["unread"] == Json::from(1i64),
        "first badge: {:?}",
        paths(&got)
    );
    relay.failing.store(false, Ordering::SeqCst);
    let recount = || server.app.lock().unread_changed_locked("alice", "");
    recount();
    let got = relay.pushes(&server, &mut a);
    assert!(
        got.len() == 1 && got[0].payload()["unread"] == Json::from(1i64),
        "badge after a failed one: {:?}",
        paths(&got)
    );
    // Accepted, the same count is not sent again.
    recount();
    assert!(
        relay.pushes(&server, &mut a).is_empty(),
        "badge of an accepted count"
    );
}

/// A timed room mute that runs out changes what counts, so the count is
/// taken again and a badge push sent (§4.9, §4.5).
#[test]
fn test_room_mute_expiry_updates_badge() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut clients = dial_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    b.result(
        "push_register",
        "badge",
        obj! {"kind" => "relay", "url" => format!("{}/b", relay.url), "wake" => list(&["badge"])},
    );
    let frames = b.status(obj! {"room_id" => "general", "mute" => 1i64});
    assert_eq!(frames.len(), 1, "room mute echo: {frames:?}");
    save(&mut a, "post", obj! {"body" => obj! {"text" => "hi"}});
    b.notification("message");
    for got in relay.pushes(&server, &mut a) {
        assert_eq!(
            got.payload()["unread"],
            Json::from(0i64),
            "badge while the room is muted"
        );
    }
    time::sleep(time::MILLISECOND * 1200);
    let got = relay.pushes(&server, &mut a);
    assert!(
        got.len() == 1 && got[0].payload()["unread"] == Json::from(1i64),
        "badge after the room mute ran out: {:?}",
        paths(&got)
    );
    // Its end is sent to the user's connections (§4.5).
    expect_mute(&b, "general", &Json::from(false));
    b.expect_quiet();
}

/// A wake list's names past the first MAX_WAKE_SCOPES, and names longer
/// than MAX_WAKE_SCOPE_BYTES, are ignored rather than refused (§4.9).
#[test]
fn test_wake_names_past_the_bounds_are_ignored() {
    let server = push_test_server();
    let mut a = dial_test_client(&server);
    let endpoint = "http://127.0.0.1:1/p";
    let mut wake_of = |id: &str, wake: Vec<String>| -> WakeScope {
        a.result(
            "push_register",
            id,
            obj! {"kind" => "relay", "url" => endpoint, "wake" => wake},
        );
        server.app.lock().pushes[&push_key(&a.user_id, endpoint)].wake
    };
    let mut many = vec!["ext:filler".to_owned(); MAX_WAKE_SCOPES + 4];
    many[0] = "replies".into();
    many[MAX_WAKE_SCOPES] = "mentions".into();
    assert_eq!(
        wake_of("many", many),
        WakeScope::REPLIES,
        "wake of {} names",
        MAX_WAKE_SCOPES + 4
    );
    assert_eq!(
        wake_of(
            "long",
            vec![
                format!("mentions{}", " ".repeat(MAX_WAKE_SCOPE_BYTES)),
                "private".into()
            ]
        ),
        WakeScope::PRIVATE,
        "wake with a long name"
    );
}

/// private wakes the members of a private room for messages in its
/// threads, joined or not (§4.9).
#[test]
fn test_private_wakes_for_threads_of_joined_rooms() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = dial_test_client(&server);
    add_account(&server, "carol", &[&a]);
    add_push(
        &server,
        "carol",
        relay_push(format!("{}/private", relay.url), WakeScope::PRIVATE),
    );
    add_account(&server, "dave", &[&a]);
    add_push(
        &server,
        "dave",
        relay_push(
            format!("{}/dave", relay.url),
            WakeScope::PRIVATE | WakeScope::JOINED,
        ),
    );
    let (secret, _) = save_room(
        &mut a,
        "secret",
        obj! {"title" => "Secret", "private" => true},
    );
    a.request(
        "room_join",
        "add-carol",
        obj! {"room_id" => secret.as_str(), "user_id" => "carol"},
    );
    let (thread, _) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => secret.as_str(), "private" => false},
    );
    let (nested, _) = save_room(&mut a, "nested", obj! {"parent_room_id" => thread.as_str()});
    relay.pushes(&server, &mut a);
    for (i, room) in [thread, nested].iter().enumerate() {
        save(
            &mut a,
            &format!("post-{i}"),
            obj! {"room_id" => room.as_str(), "body" => obj! {"text" => "in a thread"}},
        );
        let got = relay.pushes(&server, &mut a);
        assert!(
            paths(&got) == strs(&["/private"]) && got[0].header("Urgency") == "high",
            "a message in a thread of a private room carol joined woke {:?}",
            paths(&got)
        );
    }
    // A public room's thread wakes no one for private.
    let (public, _) = save_room(
        &mut a,
        "public-thread",
        obj! {"parent_room_id" => "general"},
    );
    save(
        &mut a,
        "post-public",
        obj! {"room_id" => public.as_str(), "body" => obj! {"text" => "public"}},
    );
    let got = relay.pushes(&server, &mut a);
    assert!(got.is_empty(), "a public thread woke {:?}", paths(&got));
}

/// A mention in a private room wakes a member who wakes for mentions alone,
/// and never someone outside it, mentioned or not (§4.9, §4.2.4).
#[test]
fn test_mentions_wake_in_private_rooms() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = dial_test_client(&server);
    add_account(&server, "carol", &[&a]);
    add_push(
        &server,
        "carol",
        relay_push(format!("{}/carol", relay.url), WakeScope::MENTIONS),
    );
    add_account(&server, "dave", &[&a]);
    add_push(
        &server,
        "dave",
        relay_push(format!("{}/dave", relay.url), WakeScope::MENTIONS),
    );
    let (dm, _) = save_room(&mut a, "dm", obj! {"private" => true});
    a.request(
        "room_join",
        "add-carol",
        obj! {"room_id" => dm.as_str(), "user_id" => "carol"},
    );
    relay.pushes(&server, &mut a);
    save(
        &mut a,
        "plain",
        obj! {"room_id" => dm.as_str(), "body" => obj! {"text" => "no mention"}},
    );
    let got = relay.pushes(&server, &mut a);
    assert!(
        got.is_empty(),
        "a message without a mention woke {:?}",
        paths(&got)
    );
    save(
        &mut a,
        "mention",
        obj! {"room_id" => dm.as_str(), "body" => obj! {"text" => "@carol @dave look", "mentions" => list(&["carol", "dave"])}},
    );
    let got = relay.pushes(&server, &mut a);
    assert!(
        paths(&got) == strs(&["/carol"]) && got[0].header("Urgency") == "high",
        "a mention in a private room woke {:?}",
        paths(&got)
    );
    assert_eq!(
        got[0].message()["room_id"],
        Json::from(dm.as_str()),
        "pushed"
    );
}

/// The user's unread count as kept, and as counted again from the log.
fn unread_state(server: &TestServer, user_id: &str) -> (i64, i64) {
    let mut st = server.app.lock();
    let now = time::now();
    let kept = st.unread_locked(user_id, &now);
    st.users.get_mut(user_id).unwrap().unread = None;
    (kept, st.unread_locked(user_id, &now))
}

/// Muting or unmuting a room takes the unread counts of its threads again,
/// which the mute silences too (§4.9, §4.5).
#[test]
fn test_room_mute_recounts_threads() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = dial_test_client(&server);
    add_account(&server, "carol", &[&a]);
    add_push(
        &server,
        "carol",
        relay_push(format!("{}/badge", relay.url), WakeScope::BADGE),
    );
    let (thread, _) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => "general", "title" => "T"},
    );
    a.request(
        "room_join",
        "add-carol",
        obj! {"room_id" => thread.as_str(), "user_id" => "carol"},
    );
    save(
        &mut a,
        "p1",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "one"}},
    );
    save(
        &mut a,
        "p2",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "two"}},
    );
    relay.pushes(&server, &mut a);
    assert_eq!(
        unread_state(&server, "carol"),
        (2, 2),
        "before the mute: kept, counted"
    );
    for mute in [true, false] {
        {
            let mut st = server.app.lock();
            let c = st.clients.values().next().unwrap().client.clone();
            st.apply_status_locked(
                &c,
                "carol",
                &StatusUpdate {
                    room_id: "general".into(),
                    scoped: true,
                    has_mute: true,
                    mute_forever: mute,
                    ..StatusUpdate::default()
                },
            );
        }
        let want = if mute { 0 } else { 2 };
        let got = relay.pushes(&server, &mut a);
        assert!(
            got.len() == 1 && got[0].payload()["unread"] == Json::from(want),
            "badge after mute {mute}: {:?}",
            paths(&got)
        );
        assert_eq!(
            unread_state(&server, "carol"),
            (want, want),
            "after mute {mute}: kept, counted"
        );
    }
}

/// Leaving a private room takes the unread counts of its threads again: a
/// thread the user could see there, and was mentioned in without joining,
/// no longer counts (§4.9).
#[test]
fn test_leaving_private_room_recounts_threads() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = dial_test_client(&server);
    add_account(&server, "carol", &[&a]);
    add_push(
        &server,
        "carol",
        relay_push(format!("{}/badge", relay.url), WakeScope::BADGE),
    );
    let (secret, _) = save_room(
        &mut a,
        "secret",
        obj! {"title" => "Secret", "private" => true},
    );
    a.request(
        "room_join",
        "add-carol",
        obj! {"room_id" => secret.as_str(), "user_id" => "carol"},
    );
    let (thread, _) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => secret.as_str(), "private" => false},
    );
    save(
        &mut a,
        "ping",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "@carol", "mentions" => list(&["carol"])}},
    );
    relay.pushes(&server, &mut a);
    assert_eq!(
        unread_state(&server, "carol"),
        (1, 1),
        "before leaving: kept, counted"
    );
    a.request(
        "room_leave",
        "remove-carol",
        obj! {"room_id" => secret.as_str(), "user_id" => "carol"},
    );
    let got = relay.pushes(&server, &mut a);
    assert!(
        got.len() == 1 && got[0].payload()["unread"] == Json::from(0i64),
        "badge after leaving: {:?}",
        paths(&got)
    );
    assert_eq!(
        unread_state(&server, "carol"),
        (0, 0),
        "after leaving: kept, counted"
    );
}

/// A badge delivery that replaces one still queued goes with the
/// registration as it is now, its token included, not as it was when the
/// first was queued.
#[test]
fn test_coalesced_badge_uses_latest_registration() {
    let release = Arc::new(Gate::default());
    let tokens = Arc::new(Mutex::new(BTreeMap::<String, String>::new()));
    let (gate, seen) = (release.clone(), tokens.clone());
    let mut relay = httptest::Server::new(handler_func(move |_w: &mut dyn ResponseWriter, r| {
        let body = r
            .body
            .as_ref()
            .map(|b| b.read_all().unwrap())
            .unwrap_or_default();
        let authorization = r.header.get("Authorization").unwrap_or("").to_owned();
        seen.lock()
            .unwrap()
            .insert(String::from_utf8(body).unwrap(), authorization);
        gate.wait();
    }))
    .unwrap();
    let deliverer = PushDeliverer::new(true, String::new());
    fill_lane(&deliverer, &format!("{}/busy", relay.url), || {
        !tokens.lock().unwrap().is_empty()
    });
    let key = format!("u {}/badge", relay.url);
    for (token, body) in [("old", "1"), ("new", "2")] {
        deliverer.deliver(
            PushRegistration {
                user_id: "u".into(),
                url: format!("{}/badge", relay.url),
                token: token.into(),
                ..PushRegistration::default()
            },
            body.as_bytes().to_vec(),
            "low",
            key.clone(),
            Box::new(|_| {}),
        );
    }
    release.release();
    deliverer.wait();
    relay.close();
    let tokens = tokens.lock().unwrap();
    assert!(
        !tokens.contains_key("1") && tokens.get("2").map(String::as_str) == Some("Bearer new"),
        "badge deliveries: {tokens:?}"
    );
}

/// Shutdown stops the timers that end timed mutes and send coalesced
/// statuses, and no badge push is scheduled after it.
#[test]
fn test_shutdown_stops_timers() {
    let relay = new_test_relay();
    let server = push_test_server();
    server.app.lock().badge_delay = time::HOUR;
    let a = dial_test_client(&server);
    add_account(&server, "dora", &[&a]);
    add_push(
        &server,
        "dora",
        relay_push(format!("{}/dora", relay.url), WakeScope::BADGE),
    );
    {
        let mut st = server.app.lock();
        let now = time::now();
        let dora = st.users.get_mut("dora").unwrap();
        dora.mute = MuteState {
            forever: false,
            until: now.add(time::HOUR),
        };
        st.schedule_mute_locked("dora");
        st.users.get_mut("dora").unwrap().room_mutes.insert(
            "general".into(),
            MuteState {
                forever: false,
                until: now.add(time::HOUR),
            },
        );
        st.schedule_room_mute_locked("dora", "general");
        let dora = st.users.get_mut("dora").unwrap();
        dora.status_limit = Some(Limiter::new(every(time::HOUR), 0));
        dora.chosen = STATUS_NONE.into();
        st.announce_status_locked("dora");
        let dora = &st.users["dora"];
        let pending = dora.mute_timer.is_some()
            && dora.room_mute_timers.contains_key("general")
            && dora.status_timer.is_some();
        assert!(pending, "timers not pending");
    }
    let (ctx, cancel) = Context::background().with_timeout(Duration::from_secs(5));
    server
        .app
        .shutdown(&ctx)
        .expect("shutdown with pending timers");
    cancel();
    let mut st = server.app.lock();
    st.schedule_badge_locked("dora");
    st.schedule_mute_locked("dora");
    let dora = &st.users["dora"];
    assert!(
        dora.mute_timer.is_none()
            && dora.room_mute_timers.is_empty()
            && dora.status_timer.is_none()
            && dora.badge_timer.is_none(),
        "timers after shutdown"
    );
}
