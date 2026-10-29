//! The mute tests of status_test.go, test by test. Each keeps the Go test's
//! name, tables, and literal expectations.

use rust_stdlib::time::{self};

use super::helpers::*;
use crate::obj;
use crate::server::protocol::*;
use crate::server::status::*;

use super::status_test::{check_mute, expect_echo, expect_status};
use super::webauthn_test::*;

/// mute is cleared or ends (§4.5). Others never see a mute.
#[test]
fn test_mute_echo_to_all_connections() {
    let server = passkey_test_server();
    let mut observer = dial_test_client(&server);
    let (mut first, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut first, &mut new_test_authenticator());
    let (mut second, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    second.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => registered["token"].clone()},
    );
    second.user_id = first.user_id.clone();
    expect_registered(&observer, &first.user_id);
    watching(&mut [&mut observer]);
    first.drain();
    second.drain();
    observer.drain();
    let steps: Vec<(Object, &str, Json)> = vec![
        (obj! {"mute" => 60i64}, "", Json::from(60i64)),
        (obj! {"mute" => true}, "", Json::from(true)),
        (obj! {"mute" => false}, "", Json::from(false)),
        (
            obj! {"mute" => 10 * MAX_MUTE_SECONDS},
            "",
            Json::from(MAX_MUTE_SECONDS),
        ),
        (
            obj! {"room_id" => "general", "mute" => true},
            "general",
            Json::from(true),
        ),
        (
            obj! {"room_id" => "general", "mute" => false},
            "general",
            Json::from(false),
        ),
    ];
    for (params, room_id, mute) in steps {
        expect_echo(&mut first, params, room_id, mute, &[&second]);
    }
    // Invalid values, and a room the user cannot see, are invalid_params
    // and change nothing, the valid fields beside them included.
    for params in [
        // mute seconds are a positive integer: 0 is not false (§4.5).
        obj! {"mute" => -1i64},
        obj! {"mute" => 0i64},
        obj! {"room_id" => "general", "mute" => 0i64},
        obj! {"mute" => Json::Number(1.5)},
        obj! {"mute" => "60"},
        obj! {"mute" => Json::Null},
        obj! {"room_id" => "general"},
        obj! {"room_id" => "general", "idle" => false},
        obj! {"room_id" => "missing", "mute" => true},
        obj! {"room_id" => 5i64, "mute" => true},
        obj! {"mute" => true, "idle" => "yes"},
        obj! {"mute" => true, "room_id" => Json::Null},
        // idle is false or seconds since attention stopped (§4.5.3).
        obj! {"mute" => true, "idle" => true},
        obj! {"mute" => true, "idle" => -1i64},
        obj! {"mute" => true, "idle" => Json::Number(1.5)},
        obj! {"mute" => true, "idle" => Json::Null},
    ] {
        second.status_error(params, CODE_INVALID_PARAMS);
    }
    first.expect_quiet();
    second.expect_quiet();

    // Timed mutes end by themselves, sent as false to every connection.
    expect_echo(
        &mut second,
        obj! {"mute" => 1i64},
        "",
        Json::from(1i64),
        &[&first],
    );
    expect_echo(
        &mut second,
        obj! {"room_id" => "general", "mute" => 1i64},
        "general",
        Json::from(1i64),
        &[&first],
    );
    time::sleep(time::MILLISECOND * 1200);
    for c in [&mut first, &mut second] {
        let mut frames = c.drain();
        assert!(
            frames.len() == 2,
            "frames after the mutes ran out: {frames:?}"
        );
        // The two timers run in either order.
        let scoped = frames[0]
            .get("params")
            .and_then(Json::as_object)
            .is_some_and(|p| p.contains_key("room_id"));
        if scoped {
            frames.swap(0, 1);
        }
        check_mute(&frames[0], "", &Json::from(false));
        check_mute(&frames[1], "general", &Json::from(false));
    }
    observer.expect_quiet();
    let listed = list_rooms(
        &mut observer,
        obj! {"room_id" => "general", "members" => true},
    );
    for user in listed["users"].as_list() {
        assert!(
            !user.as_object().unwrap().contains_key("mute"),
            "mute shown to others: {user:?}"
        );
    }
    let own = list_rooms(&mut second, obj! {"room_id" => "general"});
    for room in own["joined"].as_list() {
        assert!(
            !room.as_object().unwrap().contains_key("mute"),
            "mute in a room record: {room:?}"
        );
    }
}

/// room_id scopes only mute (§4.5): idle is the sending connection's with
/// any room_id, and the unscoped mute is untouched by a scoped one. A mute
/// of a room the user cannot see is invalid_params, and then the idle
/// beside it does not apply either.
#[test]
fn test_room_id_scopes_only_mute() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    watching(&mut [&mut a]);
    a.drain();

    // A mute of a room the user cannot see changes nothing.
    b.status_error(
        obj! {"room_id" => "missing", "idle" => 300i64, "mute" => true},
        CODE_INVALID_PARAMS,
    );
    a.expect_quiet();
    // Without a mute, room_id is invalid_params (§4.5), and the idle beside
    // it does not apply either.
    b.status_error(
        obj! {"room_id" => "missing", "idle" => 300i64},
        CODE_INVALID_PARAMS,
    );
    a.expect_quiet();
    let frames = b.status(obj! {"idle" => 300i64});
    assert!(frames.is_empty(), "frames after an idle: {frames:?}");
    expect_status(&a, &b.user_id, "idle");
    // A visible room: idle applies to the connection, the mute to the room.
    let frames = b.status(obj! {"room_id" => "general", "idle" => false, "mute" => true});
    assert!(
        frames.len() == 1,
        "frames after a mute of general: {frames:?}"
    );
    check_mute(&frames[0], "general", &Json::from(true));
    expect_status(&a, &b.user_id, "online");
    a.expect_quiet();
    let st = server.app.lock();
    let u = &st.users[&b.user_id];
    let now = time::now();
    assert!(
        !u.mute.active(&now) && st.room_muted(u, "general", &now),
        "mutes: unscoped {:?}, rooms {:?}",
        u.mute,
        u.room_mutes
    );
}
