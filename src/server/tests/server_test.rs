//! server_test.go, test by test. Each keeps the Go test's name, tables, and
//! literal expectations.

use rust_stdlib::context::Context;
use rust_stdlib::net::http;
use rust_stdlib::time::{self, Duration};

use super::helpers::*;
use crate::obj;
use crate::server::messages::{MAX_DISTINCT_EMOJI, MAX_EMOJI_BYTES};
use crate::server::protocol::*;
use crate::server::rooms::MAX_DESCRIPTION_BYTES;
use crate::ws;

fn f(n: i64) -> Json {
    Json::from(n)
}

fn sorted_keys(o: &Object) -> Vec<String> {
    o.keys().cloned().collect()
}

#[test]
fn test_shutdown_closes_connections() {
    let mut server = new_test_server(default_config());
    let closed = dial_test_client(&server);
    let active = dial_test_client(&server);
    let closed_id = closed.user_id.clone();
    drop(closed);
    // The closed guest's leave is logged in general.
    expect_membership(&active, "general", &closed_id, false);

    let (ctx, _cancel) = Context::background().with_timeout(Duration::from_secs(1));
    server
        .app
        .shutdown(&ctx)
        .expect("shutdown with accepted connections");
    // The connection is told to retry later (an error without id), then
    // closed.
    let failure = active.read();
    assert!(
        !failure.contains_key("id")
            && failure["error"].as_object().unwrap()["code"] == f(CODE_RETRY_AFTER),
        "shutdown frame = {failure:?}"
    );
    assert!(
        active.read_raw(time::SECOND).is_err(),
        "active connection remained open after shutdown"
    );
    server.app.shutdown(&ctx).expect("repeated shutdown");
    match ws::dial(&ws_url(&server), &[], time::SECOND) {
        Err(e) => assert_eq!(
            e.response.map(|r| r.status_code),
            Some(http::STATUS_SERVICE_UNAVAILABLE),
            "connection after shutdown"
        ),
        Ok(_) => panic!("connection after shutdown succeeded"),
    }
    server.stop();
}

#[test]
fn test_server_frame() {
    let server = new_test_server(default_config());
    let (_, frame) = dial_raw(&server);
    let params = frame["params"].as_object().unwrap();
    assert!(
        params["apron"] == f(9)
            && params["agent"] == Json::from("apron-rust/9")
            && params["ping"] == f(30),
        "version, agent, and ping: {params:?}"
    );
    assert_eq!(
        params["capabilities"],
        strings(&[
            "history",
            "edit",
            "rooms",
            "reactions",
            "activity",
            "embed:upload",
            "embed:stream",
            "command",
            "status",
            "ext",
            "ext:settings",
            "ext:media"
        ]),
        "capabilities"
    );
    // With capability status, server.status lists the optional statuses
    // accepted (§4.5).
    assert_eq!(params["status"], strings(&["dnd", "invisible"]), "status");
    assert!(
        params["auth"] == strings(&["token", "guest"]) && params["signup"] == strings(&["token"]),
        "auth: {:?}, signup: {:?}",
        params["auth"],
        params.get("signup")
    );
    // push offers relay and webpush, with the server's VAPID key, and the
    // wake scopes it implements (§4.9).
    let push = params["push"].as_object().expect("push");
    let webpush = push["webpush"].as_object().expect("push.webpush");
    let point = webpush["key"]
        .as_str()
        .and_then(crate::server::webpush::decode_base64_url);
    assert!(
        point.is_some_and(|p| p.len() == crate::server::webpush::P256_POINT_BYTES)
            && webpush.len() == 1,
        "push.webpush: {webpush:?}"
    );
    assert!(
        push["relay"] == Json::from(Object::new())
            && push["wake"] == strings(&["mentions", "replies", "private", "joined", "badge"])
            && push.len() == 3,
        "push: {push:?}"
    );
    // ext:settings always carries every key apron-server-cloudflare sends;
    // the default config keeps guests read-only and bounds private rooms at
    // 20, and this one lets guests post.
    assert_eq!(
        params["ext"].as_object().unwrap()["settings"],
        Json::from(obj! {
            "guest_posting" => true, "read_cursors" => true, "add_members" => true,
            "private_rooms" => f(20),
        }),
        "server.ext.settings"
    );
    // Without a bound, private_rooms is absent, as no stated limit is.
    let mut unbounded = default_config();
    unbounded.max_private_rooms = 0;
    let unbounded_server = new_test_server(unbounded);
    let (_, frame) = dial_raw(&unbounded_server);
    let params = frame["params"].as_object().unwrap();
    assert_eq!(
        params["ext"].as_object().unwrap()["settings"],
        Json::from(obj! {
            "guest_posting" => true, "read_cursors" => true, "add_members" => true,
        }),
        "unbounded private rooms"
    );

    // A token only signs in, so signup lists the other schemes.
    let mut config = default_config();
    config.web_authn = Some(super::webauthn_test::test_web_authn());
    let passkeys = new_test_server(config);
    let (_, frame) = dial_origin(&passkeys, super::webauthn_test::TEST_PASSKEY_ORIGIN);
    let params = frame["params"].as_object().unwrap();
    assert!(
        params["auth"] == strings(&["webauthn", "token", "guest"])
            && params["signup"] == strings(&["webauthn", "token"]),
        "passkey schemes: {params:?}"
    );

    let mut config = default_config();
    config.disable_push = true;
    let quiet = new_test_server(config);
    let (mut c, frame) = dial_raw(&quiet);
    assert!(
        !frame["params"].as_object().unwrap().contains_key("push"),
        "push advertised while disabled"
    );
    guest_auth(&mut c);
    c.expect_error(
        "push_register",
        "p",
        obj! {"kind" => "relay", "url" => "https://relay.example/p"},
        CODE_UNSUPPORTED,
    );
}

#[test]
fn test_guest_auth() {
    let server = new_test_server(default_config());
    let (mut c, _) = dial_raw(&server);
    c.expect_error(
        "message",
        "early",
        obj! {"room_id" => "general", "body" => Object::new()},
        CODE_DENIED,
    );
    // An unknown scheme is a name the server does not know (§1).
    c.expect_error(
        "auth",
        "bad-scheme",
        obj! {"scheme" => "password"},
        CODE_INVALID_PARAMS,
    );
    // A request method without an id is ignored, guest auth included.
    c.write(&obj! {"method" => "auth", "params" => obj! {"scheme" => "guest"}});
    c.expect_quiet();
    // The new guest's join to general is room_update joined, as any join
    // sends (§4.2.3), delivered to its connection after the auth result
    // (§3.2).
    let (before, result) = c.request(
        "auth",
        "auth",
        obj! {"scheme" => "guest", "name" => "Ada", "agent" => "apron-test/1"},
    );
    let you = you_of(&result);
    // A requested name is not honored: the guest is named after its number.
    assert!(
        you["user_id"] == Json::from("guest_1")
            && you["name"] == Json::from("Guest 1")
            && before.is_empty(),
        "guest identity {you:?} after {before:?}"
    );
    let membership = check_joined_default(&c.read(), "guest_1");
    let want_membership = obj! {
        "log_id" => membership["log_id"].clone(), "room_id" => "general",
        "members" => vec![Json::from(obj! {"user" => obj! {"user_id" => "guest_1", "name" => "Guest 1"}, "joined" => true})],
    };
    assert_eq!(membership, want_membership, "membership");
    // No room_update follows auth; the client lists the rooms it has joined.
    c.expect_quiet();
    let listed = list_rooms(&mut c, obj! {"filter" => "joined", "members" => true});
    assert!(
        !listed.contains_key("not_joined") && listed["joined"].as_list().len() == 1,
        "joined rooms: {listed:?}"
    );
    let general = listed["joined"].as_list()[0].as_object().unwrap().clone();
    let log_id = general["log_id"].clone();
    parse_id(Some(&log_id));
    let want = obj! {
        "room_id" => "general", "title" => "General", "log_id" => log_id.clone(), "latest_log_id" => membership["log_id"].clone(), "history_log_id" => log_id,
        "members" => vec![Json::from(obj! {"user_id" => "guest_1", "status" => "online"})],
    };
    assert!(
        general == want && listed["users"] == Json::Array(vec![you.into()]),
        "general = {general:?} with users {:?}, want {want:?}",
        listed["users"]
    );
    c.expect_quiet();
}

/// ext.media (apron-web EXT.md §6) states the configured sizes: an
/// attachment of any type, and an avatar of the image types /avatar keeps.
#[test]
fn test_server_frame_media() {
    let mut config = default_config();
    config.max_upload_bytes = 5_242_880;
    config.max_avatar_bytes = 262_144;
    let server = new_test_server(config);
    let (_, frame) = dial_raw(&server);
    let avatar = obj! {"max_bytes" => f(262_144)};
    assert_eq!(
        frame["params"].as_object().unwrap()["ext"]
            .as_object()
            .unwrap()["media"],
        Json::from(obj! {
            "upload" => obj! {"*/*" => obj! {"max_bytes" => f(5_242_880)}},
            "avatar" => obj! {
                "image/png" => avatar.clone(), "image/jpeg" => avatar.clone(),
                "image/gif" => avatar.clone(), "image/webp" => avatar,
            },
        }),
    );
}

#[test]
fn test_guest_auth_ignores_requested_identity() {
    let server = new_test_server(default_config());
    let mut held: Vec<TestClient> = Vec::new();
    let mut auth = |id: &str, mut params: Object| -> String {
        let (mut c, _) = dial_raw(&server);
        params.insert("scheme".into(), "guest".into());
        let (_, result) = c.request("auth", id, params);
        held.push(c);
        let you = you_of(&result);
        let user_id = you["user_id"].as_str().unwrap().to_owned();
        assert_eq!(
            you["name"],
            Json::from(format!("Guest {}", &user_id["guest_".len()..])),
            "{id}: {you:?}"
        );
        user_id
    };
    // A requested user_id or name is not honored, as apron-server-cloudflare
    // does not: every guest takes the next guest number, and its name.
    for (i, requested) in ["ada", "guest_7", "guest_1", "user_1", "guest"]
        .iter()
        .enumerate()
    {
        assert_eq!(
            auth(
                &format!("r{i}"),
                obj! {"user_id" => *requested, "name" => "Ada"}
            ),
            format!("guest_{}", i + 1),
            "requested {requested:?}"
        );
    }
    // A user_id is never empty and has no whitespace or control characters
    // (§2.4): requesting one that could be no user_id is invalid_params,
    // with any scheme the server offers, and takes no guest number. A
    // scheme it does not offer is unsupported first.
    let (mut c, _) = dial_raw(&server);
    for (i, requested) in [
        f(5),
        Json::Null,
        "".into(),
        "bad id".into(),
        "tab\tid".into(),
        "line\n".into(),
        "nbsp\u{a0}id".into(),
        "bell\u{7}".into(),
    ]
    .into_iter()
    .enumerate()
    {
        c.expect_error(
            "auth",
            &format!("bad{i}"),
            obj! {"scheme" => "guest", "user_id" => requested},
            CODE_INVALID_PARAMS,
        );
    }
    c.expect_error(
        "auth",
        "bad-token",
        obj! {"scheme" => "token", "token" => "x", "user_id" => "a b"},
        CODE_INVALID_PARAMS,
    );
    assert_eq!(
        auth("after", Object::new()),
        "guest_6",
        "counter after invalid requests"
    );
}

#[test]
fn test_guest_numbers_are_sequential_and_never_reused() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 3);
    // Retire guest_1: its last connection closes, and guest_2 sees the leave.
    let first = clients.remove(0);
    first
        .ws
        .close(ws::STATUS_NORMAL_CLOSURE, "bye")
        .expect("close");
    drop(first);
    for observer in &clients {
        expect_membership(observer, "general", "guest_1", false);
    }
    // Neither a new guest nor a request for the retired ID gets guest_1.
    let d = dial_test_client(&server);
    assert_eq!(d.user_id, "guest_4", "guest after a retirement");
    let (mut e, _) = dial_raw(&server);
    let (_, result) = e.request(
        "auth",
        "e",
        obj! {"scheme" => "guest", "user_id" => "guest_1"},
    );
    assert_eq!(
        you_of(&result)["user_id"],
        Json::from("guest_5"),
        "request for a retired guest ID"
    );
}

#[test]
fn test_liveness_ping() {
    let mut config = default_config();
    config.ping_interval = Duration::from_millis(20);
    config.ping_timeout = Duration::from_millis(200);
    let server = new_test_server(config);
    let (mut c, frame) = dial_raw(&server);
    assert_eq!(
        frame["params"].as_object().unwrap()["ping"],
        f(1),
        "ping interval rounds up to one second: {frame:?}"
    );
    // Pings are answered before authentication too, exact bytes or not.
    let ping = |c: &TestClient, raw: &str| {
        c.write_raw(raw);
        let pong = c.read();
        assert_eq!(pong, obj! {"method" => "pong"}, "{raw} answered");
    };
    ping(&c, r#"{"method":"ping"}"#);
    ping(&c, r#"{ "method": "ping", "params": {} }"#);
    // A ping with an id is a ping, answered with pong and nothing else: a
    // server may ignore the id of a notification method, and handle the
    // frame as a notification (§1.1).
    ping(&c, r#"{"method":"ping","id":"p1"}"#);
    guest_auth(&mut c);
    ping(&c, r#"{"method":"ping"}"#);

    // A connection that pinged and then fell silent is closed.
    let deadline = time::now().add(Duration::from_secs(2));
    loop {
        if c.read_raw(Duration::from_secs(2)).is_err() {
            assert!(
                time::now().before(&deadline),
                "a silent connection stayed open"
            );
            break;
        }
    }
    // One that never pinged stays open while it answers WebSocket pings.
    let mut quiet = dial_test_client(&server);
    let deadline = time::now().add(Duration::from_millis(500));
    while time::now().before(&deadline) {
        quiet.expect_quiet();
    }
}

/// A write deadline covers one frame: a connection idle past write_timeout
/// keeps answering the server's pings, which coder/websocket bounds by the
/// ping's own context.
#[test]
fn test_idle_connection_outlives_write_timeout() {
    let mut config = default_config();
    config.write_timeout = Duration::from_millis(50);
    config.ping_interval = Duration::from_millis(100);
    config.ping_timeout = Duration::from_secs(1);
    let server = new_test_server(config);
    let mut c = dial_test_client(&server);
    // Several pings arrive while this read waits; ws.rs answers each.
    match c.read_raw(Duration::from_millis(650)) {
        Err(ws::Error::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => {}
        other => panic!("idle read past several pings: {other:?}"),
    }
    c.expect_quiet();
}

/// The pong to a client's ping is a frame of its own, written after
/// write_timeout has passed since the last data frame.
#[test]
fn test_client_ping_after_write_timeout_gets_pong() {
    let mut config = default_config();
    config.write_timeout = Duration::from_millis(50);
    config.ping_interval = Duration::from_secs(10);
    let server = new_test_server(config);
    let mut c = dial_test_client(&server);
    std::thread::sleep(std::time::Duration::from_millis(150));
    let fence = c.next_id("fence");
    let pinged = std::thread::scope(|scope| {
        let pinger = scope.spawn(|| {
            let pinged = c.ws.ping(Duration::from_secs(1));
            // Ends the read below.
            c.write(&obj! {"method" => "fence", "id" => fence.as_str()});
            pinged
        });
        let reply = c.read_raw(Duration::from_secs(2));
        assert!(reply.is_ok(), "fence after the ping: {reply:?}");
        pinger.join().unwrap()
    });
    assert!(pinged.is_ok(), "ping: {pinged:?}");
}

/// An operation that panics ends only its own connection: the connection
/// leaves the server's state, and a duplicate waiting on it (§1.2) gets an
/// error rather than waiting forever.
#[test]
fn test_panicking_operation_cleans_up() {
    let server = super::webauthn_test::passkey_test_server();
    let origin = super::webauthn_test::TEST_PASSKEY_ORIGIN;
    let (mut a, _) = dial_origin(&server, origin);
    let registered = super::webauthn_test::register_test_passkey(
        &mut a,
        &mut super::webauthn_test::new_test_authenticator(),
    );
    let user_id = you_of(&registered)["user_id"].as_str().unwrap().to_owned();
    let token = registered["token"].as_str().unwrap().to_owned();
    a.drain();
    let (mut b, _) = dial_origin(&server, origin);
    super::webauthn_test::passkey_result(&super::webauthn_test::passkey_call(
        &mut b,
        "resume",
        "token",
        "",
        obj! {"token" => token.as_str()},
    ));
    b.drain();
    let connections = || {
        let st = server.app.lock();
        (st.clients.len(), st.users[&user_id].clients.len())
    };
    assert_eq!(connections(), (2, 2), "before the panic");

    a.write(&obj! {"method" => "test_panic", "id" => "boom", "params" => Object::new()});
    std::thread::sleep(std::time::Duration::from_millis(100));
    b.write(&obj! {"method" => "test_panic", "id" => "boom", "params" => Object::new()});
    let reply = b.read();
    assert_eq!(
        reply["error"].as_object().unwrap()["code"],
        Json::from(CODE_INTERNAL_ERROR),
        "duplicate of a panicked request: {reply:?}"
    );
    assert!(
        a.read_raw(Duration::from_secs(1)).is_err(),
        "panicked connection"
    );
    assert_eq!(connections(), (1, 1), "after the panic");
    b.expect_quiet();
}

/// auth is a barrier (§3.2): requests pipelined behind it run after it, as
/// the authenticated user, and are denied when it fails.
#[test]
fn test_auth_is_a_barrier() {
    let server = new_test_server(default_config());
    let (c, _) = dial_raw(&server);
    c.write(&obj! {"method" => "auth", "id" => "auth", "params" => obj! {"scheme" => "guest", "name" => "Ada"}});
    c.write(&obj! {"method" => "room_list", "id" => "list", "params" => obj! {"filter" => "joined", "members" => true}});
    c.write(&obj! {"method" => "history", "id" => "history", "params" => Object::new()});
    c.write(&obj! {"method" => "message", "id" => "post", "params" => obj! {"body" => obj! {"text" => "hi"}}});
    let mut frames: Vec<Object> = Vec::new();
    while frames.len() < 6 {
        frames.push(c.read());
    }
    // The sign-in's join follows its result (§3.2).
    assert_eq!(
        methods(&frames),
        vec!["reply", "room_update", "reply", "reply", "message", "reply"],
        "pipelined frames"
    );
    let membership = check_joined_default(&frames[1], "guest_1");
    for (i, id) in ["auth", "", "list", "history"].iter().enumerate() {
        if !id.is_empty() {
            assert!(
                frames[i].get("id") == Some(&Json::from(*id)) && frames[i].contains_key("result"),
                "reply {i} = {:?}, want a result for {id}",
                frames[i]
            );
        }
    }
    let listed = frames[2]["result"].as_object().unwrap().clone();
    let joined_entry = listed["joined"].as_list()[0].as_object().unwrap().clone();
    assert!(
        room_ids(listed.get("joined")) == vec!["general"]
            && member_ids(&joined_entry) == vec!["guest_1"],
        "room_list behind auth: {listed:?}"
    );
    // The joined record repeats what room_list says of the room (§4.2.3).
    let joined = frames[1]["params"].as_object().unwrap()["joined"].as_list()[0].clone();
    assert_eq!(joined, listed["joined"].as_list()[0], "joined vs room_list");
    let page = frames[3]["result"].as_object().unwrap().clone();
    assert!(
        log_ids(&page, "memberships") == vec![membership["log_id"].as_str().unwrap()]
            && page["latest_log_id"] == membership["log_id"],
        "history behind auth: {page:?}"
    );
    assert!(
        frames[5]["id"] == Json::from("post")
            && frames[4]["params"].as_object().unwrap()["message_id"]
                == frames[5]["result"].as_object().unwrap()["message_id"],
        "message behind auth: {:?}",
        &frames[4..]
    );

    // Requests behind a failed auth are denied; notifications are ignored.
    for (i, auth) in [
        obj! {"scheme" => "password"},
        obj! {"scheme" => "guest", "user_id" => f(5)},
    ]
    .into_iter()
    .enumerate()
    {
        let (c, _) = dial_raw(&server);
        c.write(&obj! {"method" => "auth", "id" => "auth", "params" => auth});
        c.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => "general", "typing" => f(3)}});
        c.write(&obj! {"method" => "room_list", "id" => "list", "params" => obj! {"filter" => "joined"}});
        c.write(&obj! {"method" => "history", "id" => "history", "params" => Object::new()});
        let failed = c.read();
        assert!(
            failed["id"] == Json::from("auth") && failed.contains_key("error"),
            "auth {i}: {failed:?}"
        );
        for id in ["list", "history"] {
            let denied = c.read();
            assert!(
                denied["id"] == Json::from(id)
                    && denied["error"].as_object().unwrap()["code"] == f(CODE_DENIED),
                "auth {i}: {id} behind a failed auth: {denied:?}"
            );
        }
    }
}

#[test]
fn test_unimplemented_and_unknown_methods_are_unsupported() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    for method in ["frobnicate", "room_teleport"] {
        c.expect_error(
            method,
            method,
            obj! {"room_id" => "general"},
            CODE_UNSUPPORTED,
        );
    }
    c.expect_quiet();
}

#[test]
fn test_message_snapshots_replace_editable_state() {
    let server = new_test_server(default_config());
    let mut owner = dial_test_client(&server);
    let observer = dial_test_client(&server);
    expect_membership(&owner, "general", &observer.user_id, true);
    owner.result("me", "name", obj! {"name" => "Alice"});
    let renamed = observer.notification("user");
    assert_eq!(
        renamed,
        obj! {"new" => obj! {"user_id" => "guest_1", "name" => "Alice", "status" => "online"}},
        "rename notification"
    );
    let ext = obj! {"irc" => obj! {"nick" => "ada_"}};
    let (id, creation) = save(
        &mut owner,
        "create",
        obj! {
            "from" => obj! {"user_id" => "forged"},
            "log_id" => "123",
            "body" => obj! {"text" => "hello", "format" => "plain", "embeds" => vec![Json::from(obj! {"kind" => "ext:file"})]},
            "ext" => ext.clone(),
            "custom" => true,
            "deleted" => false,
        },
    );
    let first = observer.notification("message");
    assert_eq!(first, creation, "observer snapshot differs");
    let want_keys = ["body", "ext", "from", "log_id", "message_id", "room_id"];
    assert!(
        creation["log_id"] == Json::from(id.as_str()) && sorted_keys(&creation) == want_keys,
        "creation snapshot: {creation:?}"
    );
    let from = creation["from"].as_object().unwrap();
    assert!(
        from["user_id"] == Json::from("guest_1")
            && from["name"] == Json::from("Alice")
            && creation["ext"] == Json::from(ext.clone()),
        "creation fields: {creation:?}"
    );

    owner.result("me", "rename", obj! {"name" => "Later"});
    observer.notification("user");
    let (stable, edit) = save(
        &mut owner,
        "edit",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => "edited"}, "from" => Json::Null},
    );
    observer.notification("message");
    assert!(
        stable == id && parse_id(edit.get("log_id")) > parse_id(Some(&Json::from(id.as_str()))),
        "edit snapshot: {edit:?}"
    );
    // A save replaces every client field but ext, which merges (§4.4): the
    // edit that leaves ext out keeps it.
    assert!(
        edit["ext"] == Json::from(ext.clone())
            && edit["body"].as_object().unwrap().len() == 1
            && edit["from"].as_object().unwrap()["name"] == Json::from("Alice"),
        "replacement merged editable fields, lost ext, or changed author: {edit:?}"
    );

    // A tombstone carries neither body nor ext (§4.4).
    let (_, deleted) = save(
        &mut owner,
        "delete",
        obj! {"message_id" => id.as_str(), "deleted" => true, "body" => "discard even invalid body", "ext" => obj! {"irc" => obj! {"nick" => "x"}}},
    );
    observer.notification("message");
    assert!(
        !deleted.contains_key("body")
            && !deleted.contains_key("ext")
            && deleted["deleted"] == Json::from(true),
        "tombstone: {deleted:?}"
    );

    let page = history_page(&mut owner, "general", obj! {"after" => "0"});
    let entries = records(&page, "messages");
    assert_eq!(entries.len(), 3, "history: {page:?}");
    // Deletion redacts earlier snapshots into tombstones at their log_ids.
    let redacted = |snapshot: &Object| {
        let mut value = snapshot.clone();
        value.remove("body");
        value.remove("ext");
        value.insert("deleted".into(), true.into());
        value
    };
    for (i, expected) in [redacted(&creation), redacted(&edit), deleted]
        .iter()
        .enumerate()
    {
        assert_eq!(&entries[i], expected, "history entry {i}");
    }
    let mut observer = observer;
    observer.expect_error("message", "forged", obj! {"room_id" => "general", "message_id" => id.as_str(), "body" => obj! {"text" => "forged"}}, CODE_DENIED);
}

#[test]
fn test_log_ids_form_one_sequence_across_rooms_and_kinds() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let listed = list_rooms(&mut c, obj! {"room_id" => "general"});
    let mut last = parse_id(
        listed["joined"].as_list()[0]
            .as_object()
            .unwrap()
            .get("log_id"),
    );
    let mut check = |label: &str, value: Option<&Json>| {
        let id = parse_id(value);
        assert!(id > last, "{label} log_id {id} does not follow {last}");
        last = id;
    };
    let (id, message) = save(&mut c, "m1", obj! {"body" => obj! {"text" => "a"}});
    check("message", message.get("log_id"));
    grant_role(&server, &c.user_id, "mod");
    let (room, record) = save_room(&mut c, "r1", obj! {"title" => "Ops"});
    check("room", record.get("log_id"));
    assert_eq!(
        Json::from(room.as_str()),
        record["log_id"],
        "room_id should be its creation log_id"
    );
    check("reactions", react(&mut c, "x1", &id, &["👍"]).get("log_id"));
    let (_, other) = save(
        &mut c,
        "m2",
        obj! {"room_id" => room.as_str(), "body" => obj! {"text" => "b"}},
    );
    check("message in other room", other.get("log_id"));
}

#[test]
fn test_replies_may_cross_rooms() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let body = obj! {"text" => "hello"};
    let (root, _) = save(&mut c, "root", obj! {"body" => body.clone()});
    grant_role(&server, &c.user_id, "mod");
    let (ops, _) = save_room(&mut c, "ops", obj! {"title" => "Ops"});

    let (reply, created) = save(
        &mut c,
        "reply",
        obj! {"room_id" => ops.as_str(), "body" => body.clone(), "reply_to" => obj! {"message_id" => root.as_str()}},
    );
    assert_eq!(
        created["reply_to"],
        Json::from(obj! {"message_id" => root.as_str()}),
        "cross-room reply_to"
    );
    // A client may pass back a snapshot; only its message_id is used.
    let (_, echoed) = save(
        &mut c,
        "reply-snapshot",
        obj! {"body" => body.clone(), "reply_to" => obj! {"message_id" => reply.as_str(), "room_id" => ops.as_str(), "body" => body.clone()}},
    );
    assert_eq!(
        echoed["reply_to"],
        Json::from(obj! {"message_id" => reply.as_str()}),
        "reply_to not bare"
    );

    let before = history_page(&mut c, "general", Object::new());
    for (i, mut params) in [
        obj! {"reply_to" => Json::Null},
        obj! {"reply_to" => f(123)},
        obj! {"reply_to" => root.as_str()},
        obj! {"reply_to" => Object::new()},
        obj! {"reply_to" => obj! {"message_id" => ""}},
        obj! {"reply_to" => obj! {"message_id" => "0"}},
        obj! {"reply_to" => obj! {"message_id" => "bad"}},
        obj! {"reply_to" => obj! {"message_id" => "999"}},
        obj! {"message_id" => root.as_str(), "reply_to" => obj! {"message_id" => root.as_str()}},
        obj! {"reply_to" => obj! {"message_id" => root.as_str()}, "room_id" => "missing-room"},
    ]
    .into_iter()
    .enumerate()
    {
        if !params.contains_key("room_id") {
            params.insert("room_id".into(), "general".into());
        }
        params.insert("body".into(), body.clone().into());
        c.expect_error(
            "message",
            &format!("bad-reply-{i}"),
            params,
            CODE_INVALID_PARAMS,
        );
    }
    let after = history_page(&mut c, "general", Object::new());
    assert_eq!(
        before["last_log_id"], after["last_log_id"],
        "rejected reply changed history"
    );

    // Replies to tombstones remain valid, and omitting reply_to on a save
    // removes it.
    save(
        &mut c,
        "delete-root",
        obj! {"message_id" => root.as_str(), "deleted" => true},
    );
    save(
        &mut c,
        "reply-to-tombstone",
        obj! {"body" => body.clone(), "reply_to" => obj! {"message_id" => root.as_str()}},
    );
    let (_, removed) = save(
        &mut c,
        "remove-reply",
        obj! {"message_id" => reply.as_str(), "room_id" => ops.as_str(), "body" => body},
    );
    assert!(
        !removed.contains_key("reply_to"),
        "omitted reply_to was retained"
    );
}

#[test]
fn test_room_set_creates_and_edits_rooms_and_threads() {
    let server = new_test_server(large_frames_config());
    let mut clients = dial_group(&server, 2);
    let mut observer = clients.remove(1);
    let mut c = clients.remove(0);
    let description = "Deploy status\n*second* line";

    // A new thread joins its creator, logging the creator's membership; the
    // parent's other members learn of it as updated, without joining. A
    // thread without a title gets one from its description.
    let (thread, record) = save_room(
        &mut c,
        "thread",
        obj! {"parent_room_id" => "general", "description" => description},
    );
    assert_eq!(
        room_updated(&observer, "updated"),
        record,
        "observer room differs"
    );
    let want = obj! {
        "room_id" => thread.as_str(), "log_id" => thread.as_str(), "parent_room_id" => "general", "title" => "Deploy status",
        "description" => description, "latest_log_id" => record["latest_log_id"].clone(), "history_log_id" => thread.as_str(),
    };
    assert_eq!(record, want, "thread record");
    let (_, untitled) = save_room(&mut c, "untitled", obj! {"parent_room_id" => "general"});
    assert!(
        untitled["title"] == Json::from("Thread"),
        "untitled thread: {untitled:?}"
    );
    room_updated(&observer, "updated");

    // Edits replace every client field except parent_room_id, and reach the
    // room's members and, for a thread, the parent's.
    let ext = obj! {"app" => obj! {"pinned" => true}};
    let (same_id, updated) = save_room(
        &mut c,
        "update",
        obj! {"room_id" => thread.as_str(), "parent_room_id" => "ignored", "title" => "Renamed", "ext" => ext.clone()},
    );
    assert_eq!(
        room_updated(&observer, "updated"),
        updated,
        "observer update differs"
    );
    assert!(
        same_id == thread
            && updated["parent_room_id"] == Json::from("general")
            && updated["title"] == Json::from("Renamed")
            && updated["ext"] == Json::from(ext),
        "thread update: {updated:?}"
    );
    assert!(
        !updated.contains_key("description")
            && updated["history_log_id"] == Json::from(thread.as_str())
            && updated["latest_log_id"] == updated["log_id"],
        "thread update fields: {updated:?}"
    );
    // A new top-level room joins only its creator.
    grant_role(&server, &observer.user_id, "mod");
    let (top, top_record) = save_room(&mut observer, "top", obj! {"title" => "Ops"});
    c.expect_quiet();
    assert!(
        !top_record.contains_key("parent_room_id") && top_record["title"] == Json::from("Ops"),
        "top-level room: {top_record:?}"
    );
    let (_, cleared) = save_room(&mut observer, "clear", obj! {"room_id" => top.as_str()});
    assert!(
        !cleared.contains_key("title"),
        "omitted title was retained on a top-level room: {cleared:?}"
    );
    // An editor who has not joined the room still receives the update.
    grant_role(&server, &c.user_id, "mod");
    let (_, renamed) = save_room(
        &mut c,
        "rename-top",
        obj! {"room_id" => top.as_str(), "title" => "Ops 2"},
    );
    assert_eq!(
        room_updated(&observer, "updated"),
        renamed,
        "member's update differs"
    );

    // Room records and memberships are part of the room's own log.
    let page = history_page(&mut c, &thread, Object::new());
    assert_eq!(
        log_ids(&page, "rooms"),
        vec![
            thread.clone(),
            updated["log_id"].as_str().unwrap().to_owned()
        ],
        "thread room records: {page:?}"
    );
    assert_eq!(
        log_ids(&page, "memberships"),
        vec![record["latest_log_id"].as_str().unwrap().to_owned()],
        "thread memberships: {page:?}"
    );
    assert!(
        !page.contains_key("messages")
            && page["history_log_id"] == Json::from(thread.as_str())
            && page["latest_log_id"] == updated["log_id"],
        "thread history: {page:?}"
    );
    let general = history_page(&mut c, "general", Object::new());
    assert!(
        records(&general, "rooms").len() == 1 && records(&general, "memberships").len() == 2,
        "thread records leaked into the parent log: {general:?}"
    );

    for (i, params) in [
        obj! {"room_id" => "missing", "title" => "x"},
        obj! {"room_id" => Json::Null},
        obj! {"parent_room_id" => "missing"},
        obj! {"parent_room_id" => ""},
        obj! {"parent_room_id" => f(12)},
        obj! {"title" => f(12)},
        obj! {"title" => Json::Null},
        obj! {"description" => f(12)},
        obj! {"description" => Json::Null},
        obj! {"ext" => Json::Array(vec![])},
        obj! {"ext" => Json::Null},
    ]
    .into_iter()
    .enumerate()
    {
        c.expect_error(
            "room_set",
            &format!("bad-room-{i}"),
            params,
            CODE_INVALID_PARAMS,
        );
    }
    // A value rejected for its size is too_large (§1.1).
    c.expect_error(
        "room_set",
        "long-description",
        obj! {"description" => "x".repeat(MAX_DESCRIPTION_BYTES + 1)},
        CODE_TOO_LARGE,
    );
    c.expect_quiet();
    observer.expect_quiet();

    // A description is set with room_set like any client field, such as by
    // a bot keeping a thread's summary current, and listed rooms carry it.
    let summary = "Root cause: **expired cert**.";
    let (_, described) = save_room(
        &mut c,
        "describe",
        obj! {"room_id" => thread.as_str(), "title" => "Renamed", "description" => summary},
    );
    let observed = room_updated(&observer, "updated");
    assert!(
        observed == described && described["description"] == Json::from(summary),
        "description update {described:?}, observed {observed:?}"
    );
    let listed = list_rooms(&mut observer, obj! {"room_id" => thread.as_str()});
    assert!(
        listed.contains_key("joined") && listed["joined"].as_list().is_empty(),
        "observer has not joined the thread: {listed:?}"
    );
    let entry = listed["not_joined"].as_list()[0].as_object().unwrap();
    assert!(
        entry["description"] == Json::from(summary) && entry["title"] == Json::from("Renamed"),
        "listed room: {entry:?}"
    );
}

/// A thread's description is independent of any message: deleting the
/// message a thread was started from changes none of its room records.
#[test]
fn test_deleting_a_threads_first_message_keeps_its_record() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let mut b = clients.remove(1);
    let mut a = clients.remove(0);
    let (id, _) = save(
        &mut a,
        "root",
        obj! {"body" => obj! {"text" => "Secret line\nmore"}},
    );
    b.notification("message");
    let (thread, record) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => "general", "description" => "Why the deploy failed"},
    );
    room_updated(&b, "updated");
    assert_eq!(
        record["title"],
        Json::from("Why the deploy failed"),
        "derived title: {record:?}"
    );
    let (before, _) = a.request(
        "message",
        "delete",
        obj! {"room_id" => "general", "message_id" => id.as_str(), "deleted" => true},
    );
    assert_eq!(
        methods(&before),
        vec!["message"],
        "frames before the delete result"
    );
    b.notification("message");
    let rooms = records(&history_page(&mut b, &thread, Object::new()), "rooms");
    assert!(
        rooms.len() == 1 && rooms[0]["description"] == Json::from("Why the deploy failed"),
        "thread room records: {rooms:?}"
    );
}

#[test]
fn test_move_appears_in_both_rooms_and_carries_reactions() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let mut reactor = clients.remove(1);
    let mut author = clients.remove(0);
    let body = obj! {"text" => "move me"};
    let (id, created) = save(&mut author, "create", obj! {"body" => body.clone()});
    reactor.notification("message");
    let (thread, _) = save_room(
        &mut author,
        "thread",
        obj! {"parent_room_id" => "general", "description" => "move me"},
    );
    room_updated(&reactor, "updated");
    join_room(&mut reactor, &thread);
    expect_membership(&author, &thread, &reactor.user_id, true);
    let first = react(&mut author, "react-a", &id, &["👍"]);
    reactor.notification("reactions");
    react(&mut reactor, "react-b", &id, &["🎉", "👍"]);
    author.notification("reactions");
    react(&mut reactor, "react-b-clear", &id, &[]);
    author.notification("reactions");
    react(&mut reactor, "react-b-again", &id, &["🚀"]);
    author.notification("reactions");

    reactor.expect_error(
        "message",
        "not-owner",
        obj! {"message_id" => id.as_str(), "room_id" => thread.as_str(), "body" => body.clone()},
        CODE_DENIED,
    );
    author.expect_error(
        "message",
        "missing-room",
        obj! {"message_id" => id.as_str(), "room_id" => "missing", "body" => body.clone()},
        CODE_INVALID_PARAMS,
    );

    // The move snapshot and the reactions record it carries both precede
    // the result (§1).
    let (before, result) = author.request(
        "message",
        "move",
        obj! {"message_id" => id.as_str(), "room_id" => thread.as_str(), "body" => body.clone()},
    );
    assert!(
        methods(&before) == vec!["message", "reactions"]
            && result["message_id"] == Json::from(id.as_str()),
        "move frames: {before:?} then {result:?}"
    );
    let moved = notification_params(&before[0], "message");
    let carried = notification_params(&before[1], "reactions");
    // The move snapshot names the room holding its previous snapshot.
    assert!(
        moved["room_id"] == Json::from(thread.as_str())
            && moved["prev_log_id"] == Json::from(id.as_str())
            && moved["prev_room_id"] == Json::from("general"),
        "move snapshot: {moved:?}"
    );
    assert_eq!(
        reactor.notification("message"),
        moved,
        "move broadcast differs"
    );
    assert_eq!(
        reactor.notification("reactions"),
        carried,
        "carried reactions broadcast differs"
    );
    assert!(
        carried["room_id"] == Json::from(thread.as_str())
            && carried["message_id"] == Json::from(id.as_str())
            && parse_id(carried.get("log_id")) > parse_id(moved.get("log_id")),
        "carried reactions record: {carried:?}"
    );
    let want_sets = Json::Array(vec![
        obj! {"from" => obj! {"user_id" => "guest_1", "name" => "Guest 1"}, "emojis" => strings(&["👍"])}.into(),
        obj! {"from" => obj! {"user_id" => "guest_2", "name" => "Guest 2"}, "emojis" => strings(&["🚀"])}.into(),
    ]);
    assert_eq!(carried["reactions"], want_sets, "carried sets");

    let general = history_page(&mut author, "general", Object::new());
    assert_eq!(
        log_ids(&general, "messages"),
        vec![id.clone(), moved["log_id"].as_str().unwrap().to_owned()],
        "source history entries"
    );
    let got = log_ids(&general, "reactions");
    assert!(
        got.len() == 4 && got[0] == first["log_id"].as_str().unwrap(),
        "source history keeps earlier reaction records: {got:?}"
    );
    assert_eq!(
        general["latest_log_id"], moved["log_id"],
        "source latest_log_id"
    );
    let thread_page = history_page(&mut author, &thread, Object::new());
    assert_eq!(
        log_ids(&thread_page, "messages"),
        vec![moved["log_id"].as_str().unwrap().to_owned()],
        "destination history entries"
    );
    assert_eq!(
        log_ids(&thread_page, "reactions"),
        vec![carried["log_id"].as_str().unwrap().to_owned()],
        "destination history reactions"
    );
    assert!(
        thread_page["latest_log_id"] == carried["log_id"]
            && thread_page["history_log_id"] == Json::from(thread.as_str()),
        "destination bounds: {thread_page:?}"
    );
    assert_eq!(
        general["messages"].as_list()[0],
        Json::from(created),
        "earlier snapshot changed"
    );

    // Later reactions are logged in the message's current room; edits in
    // place stay in one room.
    let later = react(&mut author, "react-later", &id, &["✅"]);
    assert_eq!(
        later["room_id"],
        Json::from(thread.as_str()),
        "reaction after move"
    );
    let (_, edited) = save(
        &mut author,
        "edit-in-thread",
        obj! {"message_id" => id.as_str(), "room_id" => thread.as_str(), "body" => obj! {"text" => "edited"}},
    );
    assert!(
        !edited.contains_key("prev_room_id") && edited["prev_log_id"] == moved["log_id"],
        "edit after a move: {edited:?}"
    );
    let after = history_page(&mut author, "general", Object::new());
    assert_eq!(
        after["latest_log_id"], moved["log_id"],
        "in-place edit leaked into source room"
    );

    // A move without reactions logs no reactions record.
    let (plain, _) = save(&mut author, "plain", obj! {"body" => body.clone()});
    save(
        &mut author,
        "plain-move",
        obj! {"message_id" => plain.as_str(), "room_id" => thread.as_str(), "body" => body},
    );
    author.expect_quiet();
}

#[test]
fn test_reactions() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let (id, _) = save(
        &mut c,
        "create",
        obj! {"body" => obj! {"text" => "react to me"}},
    );

    let set = react(&mut c, "set", &id, &["👍", "🎉", "👍"]);
    let want = obj! {
        "log_id" => set["log_id"].clone(), "message_id" => id.as_str(), "room_id" => "general",
        "reactions" => vec![Json::from(obj! {"from" => obj! {"user_id" => "guest_1", "name" => "Guest 1"}, "emojis" => strings(&["👍", "🎉"])})],
    };
    assert_eq!(set, want, "reactions broadcast");
    // An unchanged set, in any order, logs nothing.
    let result = c.result(
        "reactions",
        "same",
        obj! {"message_id" => id.as_str(), "emojis" => strings(&["🎉", "👍"])},
    );
    assert!(result.is_empty(), "unchanged result: {result:?}");
    c.expect_quiet();
    // Request deduplication returns the original result without
    // rebroadcasting.
    c.result(
        "reactions",
        "set",
        obj! {"message_id" => id.as_str(), "emojis" => strings(&["👍", "🎉", "👍"])},
    );
    c.expect_quiet();
    c.expect_error(
        "reactions",
        "set",
        obj! {"message_id" => id.as_str(), "emojis" => strings(&["👎"])},
        CODE_INVALID_PARAMS,
    );

    let cleared = react(&mut c, "clear", &id, &[]);
    let sets = cleared["reactions"].as_list();
    assert!(
        sets.len() == 1 && sets[0].as_object().unwrap()["emojis"].as_list().is_empty(),
        "clear broadcast: {cleared:?}"
    );
    c.result(
        "reactions",
        "clear-again",
        obj! {"message_id" => id.as_str(), "emojis" => Json::Array(vec![])},
    );
    c.expect_quiet();

    let too_many: Vec<Json> = (0..=MAX_DISTINCT_EMOJI)
        .map(|i| Json::from(i.to_string()))
        .collect();
    for (i, params) in [
        obj! {"message_id" => "999", "emojis" => strings(&["👍"])},
        obj! {"message_id" => id.as_str()},
        obj! {"message_id" => id.as_str(), "emojis" => Json::Null},
        obj! {"message_id" => id.as_str(), "emojis" => "👍"},
        obj! {"message_id" => id.as_str(), "emojis" => Json::Array(vec![f(12)])},
        obj! {"message_id" => id.as_str(), "emojis" => strings(&[""])},
        obj! {"emojis" => strings(&["👍"])},
    ]
    .into_iter()
    .enumerate()
    {
        c.expect_error(
            "reactions",
            &format!("bad-{i}"),
            params,
            CODE_INVALID_PARAMS,
        );
    }
    // A count limit the server sets is denied, and an emoji over its size
    // is too_large (§1.1).
    c.expect_error(
        "reactions",
        "too-many",
        obj! {"message_id" => id.as_str(), "emojis" => Json::Array(too_many)},
        CODE_DENIED,
    );
    c.expect_error("reactions", "too-long", obj! {"message_id" => id.as_str(), "emojis" => Json::Array(vec!["x".repeat(MAX_EMOJI_BYTES + 1).into()])}, CODE_TOO_LARGE);
    c.expect_quiet();

    let page = history_page(&mut c, "general", Object::new());
    assert_eq!(
        log_ids(&page, "reactions"),
        vec![
            set["log_id"].as_str().unwrap().to_owned(),
            cleared["log_id"].as_str().unwrap().to_owned()
        ],
        "history reactions: {page:?}"
    );
}

#[test]
fn test_history_paginates_across_record_kinds() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let listed = list_rooms(&mut c, obj! {"filter" => "joined"})["joined"].as_list()[0]
        .as_object()
        .unwrap()
        .clone();
    let (general_id, join_id) = (
        listed["log_id"].as_str().unwrap().to_owned(),
        listed["latest_log_id"].as_str().unwrap().to_owned(),
    );
    let (id, message) = save(&mut c, "m1", obj! {"body" => obj! {"text" => "one"}});
    let reaction = react(&mut c, "x1", &id, &["👍"]);
    grant_role(&server, &c.user_id, "admin");
    let (_, updated) = save_room(
        &mut c,
        "r1",
        obj! {"room_id" => "general", "title" => "Lobby"},
    );
    let (_, second) = save(&mut c, "m2", obj! {"body" => obj! {"text" => "two"}});
    let s = |o: &Object| o["log_id"].as_str().unwrap().to_owned();
    let all = vec![
        general_id.clone(),
        join_id,
        s(&message),
        s(&reaction),
        s(&updated),
        s(&second),
    ];

    let full = history_page(&mut c, "general", Object::new());
    assert!(
        full["first_log_id"] == Json::from(all[0].as_str())
            && full["last_log_id"] == Json::from(all[5].as_str())
            && full["more"] == Json::from(false),
        "full page: {full:?}"
    );
    assert!(
        full["history_log_id"] == Json::from(general_id.as_str())
            && full["latest_log_id"] == Json::from(all[5].as_str()),
        "full page bounds: {full:?}"
    );
    assert!(
        log_ids(&full, "rooms") == vec![all[0].clone(), all[4].clone()]
            && log_ids(&full, "memberships") == vec![all[1].clone()]
            && log_ids(&full, "messages") == vec![all[2].clone(), all[5].clone()]
            && log_ids(&full, "reactions") == vec![all[3].clone()],
        "partitioned page: {full:?}"
    );
    let lobby = full["rooms"].as_list()[1].as_object().unwrap();
    assert!(
        lobby["title"] == Json::from("Lobby") && !lobby.contains_key("latest_log_id"),
        "logged room record carries delivery fields: {lobby:?}"
    );
    // Records keep the user objects they were logged with; without room_id,
    // history pages the log of the rooms the user joined, here only
    // general.
    c.result("me", "rename", obj! {"name" => "Ada"});
    let defaulted = c.result("history", "default", Object::new());
    assert_eq!(
        defaulted["last_log_id"],
        Json::from(all[5].as_str()),
        "default room page: {defaulted:?}"
    );
    let from = &defaulted["messages"].as_list()[0].as_object().unwrap()["from"];
    assert_eq!(
        *from,
        Json::from(obj! {"user_id" => "guest_1", "name" => "Guest 1"}),
        "logged from changed"
    );

    // Forward paging over every record kind, continuing from last_log_id + 1.
    let mut collected: Vec<String> = Vec::new();
    let mut after = "0".to_owned();
    let mut pages = 0;
    loop {
        let page = history_page(
            &mut c,
            "general",
            obj! {"after" => after.as_str(), "limit" => f(2)},
        );
        let mut ids: Vec<String> = Vec::new();
        for key in ["rooms", "memberships", "messages", "reactions"] {
            ids.extend(log_ids(&page, key));
        }
        assert!(
            !ids.is_empty()
                && ids.len() <= 2
                && page["latest_log_id"] == Json::from(all[5].as_str()),
            "forward page: {page:?}"
        );
        collected.extend(ids);
        if page["more"] == Json::from(false) {
            assert!(
                pages == 2 && page["last_log_id"] == Json::from(all[5].as_str()),
                "final forward page: {page:?}"
            );
            break;
        }
        after = (parse_id(page.get("last_log_id")) + 1).to_string();
        pages += 1;
    }
    collected.sort();
    assert_eq!(collected, all, "forward paging collected");

    // Backward paging selects the newest matches first.
    let page = history_page(&mut c, "general", obj! {"limit" => f(2)});
    assert!(
        page["first_log_id"] == Json::from(all[4].as_str())
            && page["last_log_id"] == Json::from(all[5].as_str())
            && page["more"] == Json::from(true),
        "newest page: {page:?}"
    );
    let page = history_page(
        &mut c,
        "general",
        obj! {"before" => (parse_id(page.get("first_log_id")) - 1).to_string(), "limit" => f(2)},
    );
    assert!(
        page["first_log_id"] == Json::from(all[2].as_str())
            && page["last_log_id"] == Json::from(all[3].as_str())
            && page["more"] == Json::from(true),
        "backward continuation: {page:?}"
    );
    // Inclusive bounds on both sides.
    let page = history_page(
        &mut c,
        "general",
        obj! {"after" => all[3].as_str(), "before" => all[4].as_str()},
    );
    assert!(
        page["first_log_id"] == Json::from(all[3].as_str())
            && page["last_log_id"] == Json::from(all[4].as_str())
            && page["more"] == Json::from(false),
        "inclusive window: {page:?}"
    );
    // Empty arrays are omitted.
    let page = history_page(
        &mut c,
        "general",
        obj! {"after" => all[2].as_str(), "before" => all[2].as_str()},
    );
    assert_eq!(
        sorted_keys(&page),
        [
            "first_log_id",
            "history_log_id",
            "last_log_id",
            "latest_log_id",
            "messages",
            "more"
        ],
        "one-message page: {page:?}"
    );
    // An empty window has no arrays and neither bound, but keeps the room's
    // latest_log_id and history_log_id.
    let empty = history_page(
        &mut c,
        "general",
        obj! {"after" => (parse_id(Some(&Json::from(all[5].as_str()))) + 1).to_string()},
    );
    let want = obj! {"more" => false, "latest_log_id" => all[5].as_str(), "history_log_id" => general_id.as_str()};
    assert_eq!(empty, want, "empty page");
    // Invalid parameters are rejected.
    for (i, params) in [
        obj! {"room_id" => "missing"},
        obj! {"room_id" => "general", "limit" => f(0)},
        obj! {"room_id" => "general", "after" => f(5)},
        obj! {"room_id" => "general", "before" => "-1"},
    ]
    .into_iter()
    .enumerate()
    {
        c.expect_error("history", &format!("bad-{i}"), params, CODE_INVALID_PARAMS);
    }
}

/// A window bounded to one log_id returns exactly that record, so a client
/// walks prev_log_id back through a message's edits. A move snapshot names
/// the source room in prev_room_id, whose log holds the earlier snapshots.
#[test]
fn test_history_single_record_walks_prev_log_id() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let (id, created) = save(&mut c, "create", obj! {"body" => obj! {"text" => "one"}});
    let (_, edited) = save(
        &mut c,
        "edit",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => "two"}},
    );
    save(
        &mut c,
        "other",
        obj! {"body" => obj! {"text" => "unrelated"}},
    );
    let (thread, _) = save_room(
        &mut c,
        "thread",
        obj! {"parent_room_id" => "general", "title" => "Moved"},
    );
    let (_, moved) = save(
        &mut c,
        "move",
        obj! {"message_id" => id.as_str(), "room_id" => thread.as_str(), "body" => obj! {"text" => "three"}},
    );
    let (_, latest) = save(
        &mut c,
        "edit-again",
        obj! {"message_id" => id.as_str(), "room_id" => thread.as_str(), "body" => obj! {"text" => "four"}},
    );

    let mut walked: Vec<Object> = Vec::new();
    let mut rooms: Vec<String> = Vec::new();
    let mut record = latest.clone();
    loop {
        walked.push(record.clone());
        let Some(prev) = record
            .get("prev_log_id")
            .and_then(Json::as_str)
            .map(str::to_owned)
        else {
            break;
        };
        let mut room = record["room_id"].as_str().unwrap().to_owned();
        if let Some(previous) = record.get("prev_room_id").and_then(Json::as_str) {
            room = previous.to_owned();
        }
        rooms.push(room.clone());
        let page = history_page(
            &mut c,
            &room,
            obj! {"after" => prev.as_str(), "before" => prev.as_str()},
        );
        let entries = records(&page, "messages");
        assert!(
            entries.len() == 1
                && page["first_log_id"] == Json::from(prev.as_str())
                && page["last_log_id"] == Json::from(prev.as_str())
                && page["more"] == Json::from(false),
            "single-record page for {prev} in {room}: {page:?}"
        );
        record = entries[0].clone();
    }
    assert!(
        walked == vec![latest, moved, edited.clone(), created]
            && rooms == vec![thread.clone(), "general".to_owned(), "general".to_owned()],
        "walked {walked:?} through {rooms:?}"
    );
    // The destination's log does not hold the earlier snapshots.
    let page = history_page(
        &mut c,
        &thread,
        obj! {"after" => edited["log_id"].clone(), "before" => edited["log_id"].clone()},
    );
    assert!(
        !page.contains_key("messages") && !page.contains_key("first_log_id"),
        "earlier snapshot in the destination: {page:?}"
    );
}

#[test]
fn test_invalid_saves_leave_state_unchanged() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let (id, _) = save(&mut c, "create", obj! {"body" => obj! {"text" => "hello"}});
    for (i, mut params) in [
        obj! {"body" => Object::new(), "deleted" => true},
        obj! {"message_id" => "999", "body" => Object::new()},
        obj! {"message_id" => Json::Null, "body" => Object::new()},
        obj! {"message_id" => id.as_str()},
        obj! {"message_id" => id.as_str(), "body" => Json::Null},
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => Json::Null}},
        obj! {"message_id" => id.as_str(), "body" => obj! {"format" => "html"}},
        obj! {"message_id" => id.as_str(), "body" => obj! {"embeds" => Json::Null}},
        obj! {"message_id" => id.as_str(), "body" => Object::new(), "ext" => Json::Null},
        obj! {"message_id" => id.as_str(), "body" => Object::new(), "ext" => "text"},
        obj! {"body" => Object::new(), "deleted" => Json::Null},
        obj! {"body" => Object::new(), "room_id" => Json::Null},
        obj! {"body" => Object::new(), "room_id" => "missing"},
        obj! {"body" => obj! {"text" => "x", "mentions" => "guest_1"}},
        obj! {"body" => obj! {"text" => "x", "mentions" => Json::Array(vec![f(7)])}},
        obj! {"body" => obj! {"text" => "x", "mentions" => strings(&[""])}},
        // A user_id has no whitespace or control characters (§2.4).
        obj! {"body" => obj! {"text" => "x", "mentions" => strings(&["guest 1"])}},
        obj! {"body" => obj! {"text" => "x", "mentions" => strings(&["guest_1\n"])}},
    ]
    .into_iter()
    .enumerate()
    {
        if !params.contains_key("room_id") {
            params.insert("room_id".into(), "general".into());
        }
        c.expect_error("message", &format!("bad-{i}"), params, CODE_INVALID_PARAMS);
    }
    c.expect_quiet();
    let page = history_page(&mut c, "general", Object::new());
    assert!(
        records(&page, "messages").len() == 1 && page["latest_log_id"] == Json::from(id.as_str()),
        "invalid operations appended history: {page:?}"
    );
}

/// A message without room_id goes to the default room; a new message with
/// no text and no embeds is neither logged nor broadcast.
#[test]
fn test_default_room_and_empty_messages() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let (before, result) = c.request("message", "default", obj! {"body" => obj! {"text" => "hi"}});
    let snapshot = notification_params(&before[0], "message");
    assert!(
        before.len() == 1
            && snapshot["room_id"] == Json::from("general")
            && snapshot["message_id"] == result["message_id"],
        "default room snapshot: {snapshot:?}"
    );
    for (i, body) in [
        Object::new(),
        obj! {"text" => ""},
        obj! {"text" => "", "embeds" => Json::Array(vec![]), "mentions" => strings(&["guest_1"])},
    ]
    .into_iter()
    .enumerate()
    {
        let result = c.result("message", &format!("empty-{i}"), obj! {"body" => body});
        assert!(result.is_empty(), "empty message result: {result:?}");
    }
    c.expect_quiet();
    let page = history_page(&mut c, "general", Object::new());
    assert_eq!(
        records(&page, "messages").len(),
        1,
        "empty messages were logged: {page:?}"
    );
    // An empty edit is an ordinary save.
    let (_, edited) = save(
        &mut c,
        "edit",
        obj! {"message_id" => result["message_id"].clone(), "body" => Object::new()},
    );
    assert_eq!(
        edited["body"],
        Json::from(Object::new()),
        "empty edit: {edited:?}"
    );
}

#[test]
fn test_request_deduplication() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let (thread, _) = save_room(
        &mut c,
        "thread",
        obj! {"parent_room_id" => "general", "title" => "Deploy"},
    );
    c.write(&obj! {"method" => "room_set", "id" => "thread", "params" => obj! {"title" => "Deploy", "parent_room_id" => "general"}});
    assert_eq!(
        c.read()["result"].as_object().unwrap()["room_id"],
        Json::from(thread.as_str()),
        "room retry minted another ID"
    );
    c.expect_quiet();

    let (id, _) = save(
        &mut c,
        "create",
        obj! {"body" => obj! {"text" => "initial"}},
    );
    let mut params = obj! {"room_id" => thread.as_str(), "message_id" => id.as_str(), "body" => obj! {"text" => "edited"}};
    let (_, moved) = save(&mut c, "edit", params.clone());
    assert_eq!(
        c.result("message", "edit", params.clone())["message_id"],
        Json::from(id.as_str()),
        "replacement retry changed message ID"
    );
    c.expect_quiet();
    params.insert("body".into(), obj! {"text" => "conflicting retry"}.into());
    c.expect_error("message", "edit", params, CODE_INVALID_PARAMS);
    c.expect_error(
        "history",
        "edit",
        obj! {"room_id" => thread.as_str()},
        CODE_INVALID_PARAMS,
    );
    let page = history_page(&mut c, &thread, Object::new());
    assert!(
        records(&page, "messages").len() == 1 && page["last_log_id"] == moved["log_id"],
        "retry appended log entries: {page:?}"
    );

    // A duplicate is not run again, and its result reflects the current
    // state (§1.2): a retried rename answers with the name set since.
    c.result("me", "rename", obj! {"name" => "First"});
    c.result("me", "rename-again", obj! {"name" => "Second"});
    let you = you_of(&c.result("me", "rename", obj! {"name" => "First"}));
    assert_eq!(you["name"], Json::from("Second"), "retried me: {you:?}");
    c.expect_quiet();

    // Reads are not kept: a finished history runs again under the same ID.
    let first = c.result("history", "read", obj! {"room_id" => thread.as_str()});
    save(
        &mut c,
        "post",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "new"}},
    );
    let second = c.result("history", "read", obj! {"room_id" => thread.as_str()});
    assert_eq!(
        log_ids(&second, "messages").len(),
        log_ids(&first, "messages").len() + 1,
        "a finished read was answered from the cache: {second:?}"
    );
    // The server forgets a read just after sending its result, so the
    // result can arrive first.
    let kept = |id: &str| -> bool { server.app.lock().users[&c.user_id].dedup.get(id).is_some() };
    let deadline = time::now().add(time::SECOND);
    while kept("read") && time::now().before(&deadline) {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(!kept("read"), "history result kept for deduplication");
    assert!(kept("post"), "message result not kept for deduplication");
}

#[test]
fn test_notifications_get_no_replies() {
    let server = new_test_server(default_config());
    let c = dial_test_client(&server);
    c.write(&obj! {"method" => "unknown_notification"});
    c.write(&obj! {"method" => "message", "params" => Json::Array(vec![])});
    c.write(&obj! {"method" => "me", "params" => obj! {"name" => Json::Null}});
    c.write(&obj! {"method" => "reactions", "params" => obj! {"message_id" => "999", "emojis" => Json::Array(vec![])}});
    c.write(&obj! {"method" => "auth"});
    // Errors not tied to a request omit id (PROTOCOL.md §1.1).
    for raw in [r#"{"#, r#"{"method":"me","id":1}"#] {
        c.write_raw(raw);
        let failure = c.read();
        assert!(
            !failure.contains_key("id") && failure.contains_key("error"),
            "{raw}: error frame = {failure:?}, want an error without id"
        );
    }
    c.write(&obj! {"method" => "me", "id" => "n1", "params" => obj! {"name" => "A"}});
    let response = c.read();
    assert_eq!(
        response["id"],
        Json::from("n1"),
        "notification produced a response before me: {response:?}"
    );
}

#[test]
fn test_http_endpoints() {
    let dir = TempDir::new("apron-static-");
    for (name, content) in [
        ("index.html", "app"),
        (".env", "SECRET=1"),
        ("assets/app.js", "js"),
    ] {
        let path = format!("{dir}/{name}");
        std::fs::create_dir_all(std::path::Path::new(&path).parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
    }
    let mut config = default_config();
    config.static_dir = dir.to_string();
    let server = new_test_server(config);
    // The static directory serves files, but not dotfiles or listings.
    for (path, want) in [
        ("/healthz", 200u16),
        ("/", 200),
        ("/assets/app.js", 200),
        ("/.env", 404),
        ("/assets/", 404),
    ] {
        let (status, _) = http_get(&format!("{}{path}", server.http.url));
        assert_eq!(status, want, "GET {path}");
    }
    // The HTTP request host is authorized by the origin check; a configured
    // origin outside the allowlist is rejected during the WebSocket
    // handshake.
    assert!(
        ws::dial(
            &ws_url(&server),
            &[("Origin", "https://untrusted.example")],
            time::SECOND
        )
        .is_err(),
        "untrusted origin unexpectedly connected"
    );
}

#[test]
fn test_activity_relays_typing_with_inline_identity() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let (thread, _) = save_room(&mut c, "thread", obj! {"parent_room_id" => "general"});
    c.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => thread.as_str(), "typing" => f(8), "from" => obj! {"user_id" => "forged"}}});
    let params = c.notification("activity");
    let want = obj! {"room_id" => thread.as_str(), "from" => obj! {"user_id" => "guest_1", "name" => "Guest 1"}, "typing" => f(8)};
    assert_eq!(params, want, "activity");
    c.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => thread.as_str(), "typing" => f(0)}});
    let stop = c.notification("activity");
    assert_eq!(stop["typing"], f(0), "stop: {stop:?}");
    // Invalid activity changes nothing, and, as a notification, is not
    // answered even when sent with an id (§1).
    c.write(&obj! {"method" => "activity", "id" => "missing", "params" => obj! {"room_id" => "missing", "typing" => f(8)}});
    c.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => thread.as_str(), "typing" => f(-1)}});
    c.write(&obj! {"method" => "activity", "id" => "typing", "params" => obj! {"room_id" => thread.as_str(), "typing" => f(1)}});
    let typing = c.notification("activity");
    assert_eq!(typing["typing"], f(1), "typing sent with an id: {typing:?}");
    c.expect_quiet();
}

/// A notification-only method is never answered, whatever its id and even
/// with invalid or malformed params (§1). A ping is still answered with
/// pong.
#[test]
fn test_notification_only_with_id_never_answered() {
    let server = new_test_server(default_config());
    let (mut c, _) = dial_raw(&server);
    let frames = [
        r#"{"method":"activity","id":"a1","params":[]}"#,
        r#"{"method":"activity","id":7,"params":{"typing":-1}}"#,
        r#"{"method":"activity","id":"a2","params":{"room_id":"missing","typing":3}}"#,
        r#"{"method":"activity","id":"a3","params":{"read_message_id":5}}"#,
    ];
    let check = |c: &mut TestClient| {
        for frame in frames {
            c.write_raw(frame);
        }
        c.expect_quiet();
        for frame in [
            r#"{"method":"ping","id":5}"#,
            r#"{"method":"ping","id":"p","params":[]}"#,
        ] {
            c.write_raw(frame);
            let pong = c.read();
            assert_eq!(pong, obj! {"method" => "pong"}, "{frame} answered");
        }
        c.expect_quiet();
    };
    check(&mut c);
    guest_auth(&mut c);
    c.drain();
    check(&mut c);
    // Other methods still reply to a bad id or bad params.
    c.write_raw(r#"{"method":"room_list","id":5}"#);
    let reply = c.read();
    assert_eq!(
        reply["error"].as_object().unwrap()["code"],
        f(CODE_INVALID_REQUEST),
        "bad id on a request: {reply:?}"
    );
    c.write_raw(r#"{"method":"room_list","id":"r1","params":[]}"#);
    let reply = c.read();
    assert!(
        reply["id"] == Json::from("r1")
            && reply["error"].as_object().unwrap()["code"] == f(CODE_INVALID_PARAMS),
        "bad params on a request: {reply:?}"
    );
}

/// Clients send every request with an id, and a server may ignore a request
/// method sent without one (§1.1): this one does, before sign-in and after,
/// whatever it is.
#[test]
fn test_requests_without_an_id_are_ignored() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let mut b = clients.remove(1);
    let mut a = clients.remove(0);
    for frame in [
        obj! {"method" => "me", "params" => obj! {"name" => "Nobody"}},
        obj! {"method" => "message", "params" => obj! {"room_id" => "general", "body" => obj! {"text" => "hi"}}},
        obj! {"method" => "room_set", "params" => obj! {"title" => "Nothing"}},
        obj! {"method" => "room_join", "params" => obj! {"room_id" => "general"}},
        obj! {"method" => "status", "params" => obj! {"mute" => true}},
        obj! {"method" => "auth", "params" => obj! {"scheme" => "guest"}},
    ] {
        a.write(&frame);
    }
    a.expect_quiet();
    b.expect_quiet();
    let rooms = room_ids(list_rooms(&mut a, Object::new()).get("joined"));
    assert_eq!(rooms.len(), 1, "rooms after ignored requests: {rooms:?}");
}

/// Every notification a sign-in causes on its connection comes after the
/// auth result (§3.2): the new guest's join, then the statuses of those who
/// share a room (§4.5).
#[test]
fn test_sign_in_notifications_follow_the_result() {
    let server = new_test_server(default_config());
    let a = dial_test_client(&server);
    let (mut b, _) = dial_raw(&server);
    watching(&mut [&mut b]);
    b.write(&obj! {"method" => "auth", "id" => "auth", "params" => obj! {"scheme" => "guest"}});
    let frames = vec![b.read(), b.read(), b.read()];
    assert_eq!(
        methods(&frames),
        vec!["reply", "room_update", "user"],
        "sign-in frames"
    );
    b.user_id = you_of(frames[0]["result"].as_object().unwrap())["user_id"]
        .as_str()
        .unwrap()
        .to_owned();
    check_joined_default(&frames[1], &b.user_id);
    check_status(&frames[2], &a.user_id, "online");
    b.expect_quiet();
}
