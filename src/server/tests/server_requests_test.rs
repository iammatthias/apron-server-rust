//! The request, notification, and HTTP endpoint tests of server_test.go,
//! test by test. Each keeps the Go test's name, tables, and literal
//! expectations.

use rust_stdlib::time::{self};

use super::helpers::*;
use super::server_test::f;
use crate::obj;
use crate::server::protocol::*;
use crate::ws;

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
fn test_request_deduplication() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    make_account(&server, &c.user_id);
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
    let mut d = dial_test_client(&server);
    c.drain();
    let (thread, _) = save_room(&mut c, "thread", obj! {"parent_room_id" => "general"});
    d.notification("room_update");
    join_room(&mut d, &thread);
    c.drain();
    d.drain();
    // Typing reaches the room's other members, not the typist's own
    // connections.
    c.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => thread.as_str(), "typing" => f(8), "from" => obj! {"user_id" => "forged"}}});
    let params = d.notification("activity");
    let want = obj! {"room_id" => thread.as_str(), "from" => obj! {"user_id" => "guest_1", "name" => "Guest 1"}, "typing" => f(8)};
    assert_eq!(params, want, "activity");
    c.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => thread.as_str(), "typing" => f(0)}});
    let stop = d.notification("activity");
    assert_eq!(stop["typing"], f(0), "stop: {stop:?}");
    // Invalid activity changes nothing, and, as a notification, is not
    // answered even when sent with an id (§1).
    c.write(&obj! {"method" => "activity", "id" => "missing", "params" => obj! {"room_id" => "missing", "typing" => f(8)}});
    c.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => thread.as_str(), "typing" => f(-1)}});
    c.write(&obj! {"method" => "activity", "id" => "typing", "params" => obj! {"room_id" => thread.as_str(), "typing" => f(1)}});
    let typing = d.notification("activity");
    assert_eq!(typing["typing"], f(1), "typing sent with an id: {typing:?}");
    c.expect_quiet();
    d.expect_quiet();
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
