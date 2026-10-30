//! Frame rate limits and repeated policy violations, apron-server-
//! cloudflare's (its SPEC.md, sections 4 and 6).

use rust_stdlib::time;

use super::helpers::*;
use crate::obj;
use crate::server::config::Config;
use crate::server::limits::Limits;
use crate::server::protocol::*;
use crate::ws;

fn server(limits: Limits) -> TestServer {
    new_test_server(Config {
        limits,
        client_ip_header: "Cf-Connecting-IP".into(),
        ..default_config()
    })
}

fn guest_from(server: &TestServer, ip: &str) -> TestClient {
    let (mut c, _) = dial_headers(server, &[("Cf-Connecting-IP", ip)]);
    guest_auth(&mut c);
    c.drain();
    c
}

/// The close code the connection ends with, skipping frames before it.
fn close_code(c: &TestClient) -> u16 {
    loop {
        match c.read_raw(time::SECOND * 2) {
            Ok(_) => continue,
            Err(ws::Error::Closed { code, .. }) => return code,
            Err(e) => panic!("want a close, got {e}"),
        }
    }
}

fn list(c: &mut TestClient, id: &str) -> Object {
    reply(c, "room_list", id, obj! {"filter" => "joined"})
}

#[test]
fn test_a_connection_flood_closes_with_1008() {
    let server = server(Limits {
        frames_per_connection_minute: 5,
        ..Limits::unlimited()
    });
    let mut c = guest_from(&server, "198.51.100.1");
    // The guest's auth was its first frame; pings are not frames.
    for _ in 0..10 {
        c.write_raw(r#"{"method":"ping"}"#);
    }
    c.drain();
    let mut flood = guest_from(&server, "198.51.100.2");
    // Its auth and the helper's fence were two.
    for i in 0..3 {
        assert!(list(&mut flood, &format!("l{i}")).contains_key("result"));
    }
    flood.write_raw(r#"{"method":"room_list","id":"over","params":{}}"#);
    assert_eq!(close_code(&flood), ws::STATUS_POLICY_VIOLATION);
}

#[test]
fn test_an_address_flood_closes_with_1013() {
    let server = server(Limits {
        frames_per_ip_minute: 6,
        ..Limits::unlimited()
    });
    let mut a = guest_from(&server, "203.0.113.1");
    let mut b = guest_from(&server, "203.0.113.1");
    // Each sign-in and its fence were two.
    assert!(list(&mut a, "a").contains_key("result"));
    assert!(list(&mut b, "b").contains_key("result"));
    b.write_raw(r#"{"method":"room_list","id":"over","params":{}}"#);
    assert_eq!(close_code(&b), ws::STATUS_TRY_AGAIN_LATER);
    let mut other = guest_from(&server, "203.0.113.2");
    assert!(list(&mut other, "c").contains_key("result"));
}

/// Past the server's minute a request is refused for a while and a
/// notification dropped, and the connection stays open.
#[test]
fn test_a_busy_server_refuses_requests_and_keeps_connections() {
    let server = server(Limits {
        server_frames_per_minute: 5,
        ..Limits::unlimited()
    });
    let mut a = guest_from(&server, "192.0.2.1");
    let mut b = guest_from(&server, "192.0.2.2");
    assert!(list(&mut a, "a").contains_key("result"));
    let frame = list(&mut b, "busy");
    let (message, data) = retry_after_of(&frame);
    assert_eq!(message, "Server is busy with too many requests");
    let Json::Number(wait) = data["retry_after"] else {
        panic!("{data:?}")
    };
    assert!((11.0..=12.0).contains(&wait), "retry_after {wait}");
    assert!(!data.contains_key("ext"), "{data:?}");
    b.write_raw(r#"{"method":"activity","params":{"room_id":"general","typing":1}}"#);
    b.expect_quiet();
    a.expect_quiet();
}

#[test]
fn test_three_violations_in_a_minute_close_with_1008() {
    let server = server(Limits {
        policy_violations: 3,
        ..Limits::unlimited()
    });
    let mut c = guest_from(&server, "198.51.100.7");
    // A denial is no violation.
    for i in 0..3 {
        let frame = reply(
            &mut c,
            "room_set",
            &format!("d{i}"),
            obj! {"room_id" => "general", "description" => "x"},
        );
        assert_eq!(
            frame["error"].as_object().unwrap()["code"],
            Json::from(CODE_DENIED)
        );
    }
    c.write_raw("not json");
    c.write_raw(r#"{"method":"history","id":"h","params":{"room_id":7}}"#);
    let frames = c.drain();
    assert_eq!(frames.len(), 2, "{frames:?}");
    c.write_raw(r#"{"method":"history","id":"h2","params":{"limit":"x"}}"#);
    assert_eq!(close_code(&c), ws::STATUS_POLICY_VIOLATION);
}

/// A command's `invalid_params` are errors to show, not policy violations
/// (apron-server-cloudflare's handleCommand): an unknown command and a
/// command's usage or user_id error. Errors before the command runs count.
#[test]
fn test_mistyped_commands_are_not_violations() {
    let server = new_test_server(Config {
        limits: Limits {
            policy_violations: 3,
            ..Limits::unlimited()
        },
        ..super::helpers::admin_config()
    });
    let mut admin = super::helpers::account(&server);
    grant_role(&server, &admin.user_id.clone(), "admin");
    for (i, text) in [
        "/nope",
        "hello",
        "/rename x",
        "/purge",
        "/kick",
        "/role",
        "/toggle nothing",
        "/passkeys remove x",
        "/invite-device",
        "/server avatar x",
        "/emoji",
        "/invite-code lots",
    ]
    .into_iter()
    .enumerate()
    {
        let frame = reply(
            &mut admin,
            "command",
            &format!("c{i}"),
            obj! {"body" => obj! {"text" => text}},
        );
        assert_eq!(
            frame["error"].as_object().unwrap()["code"],
            Json::from(CODE_INVALID_PARAMS),
            "{text}: {frame:?}"
        );
    }
    // Counted: a command with no body, an unknown room, and /avatar's usage.
    for (i, params) in [
        obj! {"room_id" => "general"},
        obj! {"room_id" => "nowhere", "body" => obj! {"text" => "/help"}},
    ]
    .into_iter()
    .enumerate()
    {
        let frame = reply(&mut admin, "command", &format!("v{i}"), params);
        assert!(frame.contains_key("error"), "{frame:?}");
    }
    admin.write_raw(r#"{"method":"command","id":"v2","params":{"body":{"text":"/avatar"}}}"#);
    assert_eq!(close_code(&admin), ws::STATUS_POLICY_VIOLATION);
}
