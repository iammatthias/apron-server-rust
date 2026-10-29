//! How pushes are delivered, ported from push_test.go. These cover Web Push
//! encryption, payload size, the daily limit, and the per-host lanes. The
//! relay fixture lives in push_test.rs.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

use rust_stdlib::net::http::{handler_func, httptest, ResponseWriter};
use rust_stdlib::time::{self, Duration};

use super::helpers::*;
use super::push_test::{
    add_push, go_idle, has_push, list, new_test_relay, paths, push_client, push_test_server,
    relay_push, strs, without_coalescing,
};
use super::status_test::add_account;
use super::webpush_test::{check_vapid, decode, must_decode, test_subscription};
use crate::obj;
use crate::server::protocol::*;
use crate::server::push::*;
use crate::server::push_delivery::PushDeliverer;
use crate::server::webpush::decrypt_push;

/// webpush deliveries are RFC 8291 ciphertext signed with VAPID (RFC 8292),
/// and so are relay deliveries with keys, with the relay's token.
#[test]
fn test_web_push_delivery() {
    let relay = new_test_relay();
    let mut config = default_config();
    config.allow_insecure_push = true;
    config.push_hosts = PushHosts::Any;
    config.public_url = "https://chat.example".into();
    config.push_delay = Duration::from_secs(0);
    let server = new_test_server(config);
    without_coalescing(&server);
    let (mut c, frame) = dial_raw(&server);
    guest_auth(&mut c);
    make_account(&server, &c.user_id);
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
    let mut poster = push_client(&server);
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
                "message_id" => message_id, "room_id" => "general", "from" => obj! {"user_id" => "guest_2", "name" => "Guest 2"},
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
    // So is one that refuses the server's VAPID key with 403, as after a
    // key change.
    c.result(
        "push_register",
        "forbidden",
        obj! {"kind" => "webpush", "url" => format!("{}/web/forbidden", relay.url), "keys" => keys.clone()},
    );
    save(
        &mut poster,
        "third",
        obj! {"body" => obj! {"text" => "third", "mentions" => list(&["guest_1"])}},
    );
    c.notification("message");
    assert_eq!(
        paths(&relay.pushes(&server, &mut poster)),
        strs(&["/relay", "/web", "/web/forbidden"]),
        "deliveries"
    );
    assert!(
        !has_push(&server, &c.user_id, &format!("{}/web/forbidden", relay.url)),
        "a webpush subscription answering 403 was kept"
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
    // Text is cut to 200 code points, the last of them `…`.
    snapshot.insert("body".into(), obj! {"text" => "e".repeat(700)}.into());
    let text = body_of(&decode_payload(push_payload("", 0, &snapshot)))["text"]
        .as_str()
        .unwrap()
        .to_owned();
    let runes: Vec<char> = text.chars().collect();
    assert!(
        runes.len() == 200 && runes.last() == Some(&'…'),
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
    // Then text is shortened to fit, which takes a long name besides: 200
    // code points of text alone always fit.
    snapshot.insert(
        "body".into(),
        obj! {"text" => "\u{2028}".repeat(MAX_PUSH_TEXT_RUNES)}.into(),
    );
    snapshot.insert(
        "from".into(),
        obj! {"user_id" => "alice", "name" => "\\".repeat(900)}.into(),
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

/// A user gets at most MAX_PUSHES_PER_USER_DAY pushes a day, counting only
/// those their endpoints accepted.
#[test]
fn test_pushes_per_user_day() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = push_client(&server);
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
