//! The connection, server frame, guest sign-in, and upload sniffing tests of
//! server_test.go, test by test, with the helpers the other server_*_test.rs
//! files share. Each keeps the Go test's name, tables, and literal
//! expectations.

use rust_stdlib::context::Context;
use rust_stdlib::net::http;
use rust_stdlib::time::{self, Duration};

use super::helpers::*;
use crate::obj;
use crate::server::protocol::*;
use crate::ws;

pub(super) fn f(n: i64) -> Json {
    Json::from(n)
}

pub(super) fn sorted_keys(o: &Object) -> Vec<String> {
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
            "ext:media",
            "ext:permissions",
            "ext:limits"
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
    // wake scopes it implements (§4.9): before sign-in, without joined,
    // which only admins and mods wake for.
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
            && push["wake"] == strings(&["mentions", "replies", "private", "badge"])
            && push.len() == 3,
        "push: {push:?}"
    );
    // ext:settings keeps read_cursors and private_rooms (EXTENSIONS.md).
    assert_eq!(
        params["ext"].as_object().unwrap()["settings"],
        Json::from(obj! {"read_cursors" => true, "private_rooms" => f(20)}),
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
        Json::from(obj! {"read_cursors" => true}),
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
    // Others see the guest without the permissions only its `you` carries.
    let mut shown = you.clone();
    shown.remove("ext");
    let general = listed["joined"].as_list()[0].as_object().unwrap().clone();
    let log_id = general["log_id"].clone();
    parse_id(Some(&log_id));
    let want = obj! {
        "room_id" => "general", "title" => "General", "log_id" => log_id.clone(), "latest_log_id" => membership["log_id"].clone(), "history_log_id" => log_id,
        "members" => vec![Json::from(obj! {"user_id" => "guest_1", "status" => "online"})],
    };
    assert!(
        general == want && listed["users"] == Json::Array(vec![shown.into()]),
        "general = {general:?} with users {:?}, want {want:?}",
        listed["users"]
    );
    c.expect_quiet();
}

/// ext.media (EXTENSIONS.md) states Cloudflare's defaults: attachments of
/// its seven image and audio types up to 5 MiB, and avatars and custom
/// emoji of the four image types up to 256 KiB.
#[test]
fn test_server_frame_media() {
    let server = new_test_server(default_config());
    let (_, frame) = dial_raw(&server);
    let file = obj! {"max_bytes" => f(5_242_880)};
    let avatar = obj! {"max_bytes" => f(262_144)};
    assert_eq!(
        frame["params"].as_object().unwrap()["ext"]
            .as_object()
            .unwrap()["media"],
        Json::from(obj! {
            "upload" => obj! {
                "image/png" => file.clone(), "image/jpeg" => file.clone(),
                "image/gif" => file.clone(), "image/webp" => file.clone(),
                "audio/webm" => file.clone(), "audio/ogg" => file.clone(), "audio/mp4" => file,
            },
            "avatar" => obj! {
                "image/png" => avatar.clone(), "image/jpeg" => avatar.clone(),
                "image/gif" => avatar.clone(), "image/webp" => avatar.clone(),
            },
            // This server's own: images for /emoji add (ext:emoji).
            "emoji" => obj! {
                "image/png" => avatar.clone(), "image/jpeg" => avatar.clone(),
                "image/gif" => avatar.clone(), "image/webp" => avatar,
            },
        }),
    );
    // Configured types and sizes are what it lists.
    let mut config = default_config();
    config.upload_types = vec!["image/*".into(), "*/*".into()];
    config.max_upload_bytes = 1000;
    let server = new_test_server(config);
    let (_, frame) = dial_raw(&server);
    let media = frame["params"].as_object().unwrap()["ext"]
        .as_object()
        .unwrap()["media"]
        .as_object()
        .unwrap()
        .clone();
    assert_eq!(
        media["upload"],
        Json::from(
            obj! {"image/*" => obj! {"max_bytes" => f(1000)}, "*/*" => obj! {"max_bytes" => f(1000)}}
        )
    );
}

/// An attachment is kept only when its bytes show one of the configured
/// types, whatever it declares: a PDF or text is 415 and a PNG is kept; a
/// declared type the server does not take is 415 too. With `*/*`, any file
/// is kept (apron-server-cloudflare's "a PDF write is 415").
#[test]
fn test_upload_types_are_sniffed() {
    let upload = |c: &mut TestClient, id: &str, body: &[u8], declared: &str| {
        c.drain();
        let result = post_embeds(
            c,
            id,
            obj! {"body" => obj! {"embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
        );
        let write_url = result["embeds"].as_list()[0].as_object().unwrap()["write_url"]
            .as_str()
            .unwrap()
            .to_owned();
        http_do("PUT", &write_url, Some(body), declared).0
    };
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let pdf = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n";
    assert_eq!(upload(&mut c, "pdf", pdf, "application/pdf"), 415);
    assert_eq!(upload(&mut c, "disguised", pdf, "image/png"), 415);
    assert_eq!(upload(&mut c, "text", b"hello", ""), 415);
    assert_eq!(upload(&mut c, "png", &test_png(), "image/png"), 201);
    assert_eq!(
        upload(&mut c, "png-as-text", &test_png(), "text/plain"),
        415
    );
    let ogg = {
        let mut page = b"OggS".to_vec();
        page.resize(26, 0);
        page.push(1);
        page.push(19);
        page.extend_from_slice(b"OpusHead");
        page.resize(64, 0);
        page
    };
    assert_eq!(upload(&mut c, "ogg", &ogg, "audio/ogg"), 201);
    let large = png_of_size(5 * 1024 * 1024 + 1);
    assert_eq!(upload(&mut c, "large", &large, "image/png"), 413);

    let mut config = default_config();
    config.upload_types = vec!["*/*".into()];
    let server = new_test_server(config);
    let mut c = dial_test_client(&server);
    assert_eq!(upload(&mut c, "any", pdf, "application/pdf"), 201);
}

/// The sniffer reads each type from its signature, never from a sender.
#[test]
fn test_sniff_upload() {
    use crate::server::media_types::sniff_upload;
    let mut webm = vec![0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x86, 0x81, 0x01];
    webm.extend_from_slice(&[0x42, 0x82, 0x84]);
    webm.extend_from_slice(b"webm");
    let mut mp4 = vec![0, 0, 0, 0x20];
    mp4.extend_from_slice(b"ftypM4A ");
    let mut heic = vec![0, 0, 0, 0x20];
    heic.extend_from_slice(b"ftypheic");
    for (body, want) in [
        (test_png(), Some("image/png")),
        (b"GIF89a\x01\0\x01\0".to_vec(), Some("image/gif")),
        (b"RIFF\0\0\0\0WEBPVP8 ".to_vec(), Some("image/webp")),
        (vec![0xff, 0xd8, 0xff, 0xe0], Some("image/jpeg")),
        (webm, Some("audio/webm")),
        (mp4, Some("audio/mp4")),
        (heic, None),
        (b"<html><script>".to_vec(), None),
    ] {
        assert_eq!(sniff_upload(&body), want, "{body:?}");
    }
    let mut ogg = b"OggS".to_vec();
    ogg.resize(26, 0);
    ogg.extend_from_slice(&[1, 19]);
    ogg.extend_from_slice(b"OpusHead");
    assert_eq!(sniff_upload(&ogg), Some("audio/ogg"));

    use crate::server::media_types::type_matches;
    let patterns = vec!["image/*".to_owned(), "Audio/Ogg".to_owned()];
    assert!(type_matches(&patterns, "image/png") && type_matches(&patterns, "audio/ogg"));
    assert!(!type_matches(&patterns, "audio/mp4") && !type_matches(&patterns, "imagex/png"));
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
