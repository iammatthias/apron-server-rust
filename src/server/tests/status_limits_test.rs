//! The rate limit and bound tests of status_test.go, test by test. Each
//! keeps the Go test's name, tables, and literal expectations.

use rust_stdlib::time::{self, Time};

use super::helpers::*;
use crate::obj;
use crate::rate::{every, Limiter};
use crate::server::protocol::*;
use crate::server::status::*;

use super::status_test::{
    expect_echo, expect_profile_status, expect_status, set_status, status_id,
};

/// The server limits each user's `status` requests (§4.5): beyond the limit
/// a request is retry_after, with the seconds to wait, and changes nothing,
/// neither idle nor mute.
#[test]
fn test_status_rate_limit() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    watching(&mut [&mut a]);
    a.drain();

    // The default: a burst of STATUS_REQUEST_BURST, refilled one a second,
    // so a quick run of more is refused.
    for i in 0..STATUS_REQUEST_BURST + 2 {
        b.write(&obj! {
            "method" => "status",
            "id" => status_id(),
            "params" => obj! {"idle" => false, "seq" => i},
        });
    }
    let mut limited = 0;
    for _ in 0..STATUS_REQUEST_BURST + 2 {
        let frame = b.read();
        if let Some(failure) = frame.get("error").and_then(Json::as_object) {
            assert_eq!(
                failure.get("code"),
                Some(&Json::from(CODE_RETRY_AFTER)),
                "status beyond the burst: {frame:?}"
            );
            limited += 1;
        }
    }
    assert!(
        limited > 0,
        "no status of {} was limited",
        STATUS_REQUEST_BURST + 2
    );

    // A limit of two, refilled hourly.
    server
        .app
        .lock()
        .users
        .get_mut(&b.user_id)
        .unwrap()
        .status_requests = Some(Limiter::new(every(time::HOUR), 2));
    b.status(obj! {"idle" => 300i64});
    expect_status(&a, &b.user_id, "idle");
    expect_echo(&mut b, obj! {"mute" => true}, "", Json::from(true), &[]);
    for params in [
        obj! {"idle" => false},
        obj! {"mute" => false},
        obj! {"room_id" => "general", "mute" => true},
    ] {
        let failure = b.status_error(params.clone(), CODE_RETRY_AFTER);
        assert_eq!(
            failure.get("message"),
            Some(&Json::from("Status changes limited")),
            "the refusal names the limit, not its rate"
        );
        let wait = failure
            .get("data")
            .and_then(Json::as_object)
            .and_then(|d| d.get("retry_after"));
        assert!(
            matches!(wait, Some(Json::Number(n)) if *n >= 1.0),
            "retry_after of {params:?}: {failure:?}"
        );
    }
    b.expect_quiet();
    a.expect_quiet();
    let st = server.app.lock();
    let u = &st.users[&b.user_id];
    let now = time::now();
    let status = u.shown_status(st.attended(u));
    assert!(
        u.mute.forever && !st.room_muted(u, "general", &now) && status == STATUS_IDLE,
        "after limited requests: mute {:?}, room mutes {:?}, status {status}",
        u.mute,
        u.room_mutes
    );
}

/// The statuses sent after a sign-in are only of the users that the user's
/// rooms list in members (§4.5): past max_listed_members, a room lists its
/// most recently active members (§4.2.1), the user who just joined
/// included.
#[test]
fn test_after_auth_statuses_are_bounded() {
    let mut config = default_config();
    config.max_listed_members = 2;
    let server = new_test_server(config);
    let mut clients = dial_group(&server, 4);
    save(
        &mut clients[0],
        "post",
        obj! {"body" => obj! {"text" => "hi"}},
    );
    for c in &mut clients {
        c.drain();
    }
    let (mut g, _) = dial_raw(&server);
    watching(&mut [&mut g]);
    guest_auth(&mut g);
    let got: Vec<String> = g
        .drain()
        .iter()
        .map(|frame| {
            notification_params(frame, "user")["new"]
                .as_object()
                .unwrap()["user_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    // general lists g, who joined last, and clients[0], who posted.
    assert_eq!(
        got,
        vec![clients[0].user_id.clone()],
        "statuses after sign-in, want the listed members"
    );
}

/// A `me` that changes the status counts against the user's limit on status
/// changes, as a status request does (§4.5): beyond it the `me` is
/// retry_after and changes nothing, while one that leaves the status as it
/// is passes.
#[test]
fn test_me_status_changes_are_limited() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    watching(&mut [&mut a]);
    a.drain();
    server
        .app
        .lock()
        .users
        .get_mut(&b.user_id)
        .unwrap()
        .status_requests = Some(Limiter::new(every(time::HOUR), 1));
    assert_eq!(set_status(&mut b, "dnd"), Json::from("dnd"), "status");
    expect_profile_status(&a, &b.user_id, "dnd");
    let frame = b.call(
        "me",
        &status_id(),
        obj! {"status" => "online", "name" => "Bea"},
    );
    let failure = frame.get("error").and_then(Json::as_object);
    assert!(
        failure.is_some_and(|f| f.get("code") == Some(&Json::from(CODE_RETRY_AFTER))),
        "me beyond the limit: {frame:?}"
    );
    // `me` is no request of ext:limits' rows, so its refusal names no
    // category: data holds retry_after alone (Cloudflare b97f119).
    let data = failure.unwrap()["data"].as_object().expect("data");
    assert_eq!(data.keys().collect::<Vec<_>>(), ["retry_after"], "{data:?}");
    assert_eq!(
        set_status(&mut b, "dnd"),
        Json::from("dnd"),
        "unchanged status"
    );
    b.expect_quiet();
    a.expect_quiet();
    let st = server.app.lock();
    let u = &st.users[&b.user_id];
    assert!(
        u.chosen == STATUS_DND && u.name != "Bea",
        "after a limited me: status {:?} name {:?}",
        u.chosen,
        u.name
    );
}

/// A user mutes at most MAX_ROOM_MUTES rooms at once: muting another is
/// denied, while changing or removing a room's mute is not.
#[test]
fn test_room_mutes_are_bounded() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    grant_role(&server, &c.user_id, "mod");
    let (room, _) = save_room(&mut c, "room", obj! {"title" => "Room"});
    expect_echo(
        &mut c,
        obj! {"room_id" => room.as_str(), "mute" => true},
        &room,
        Json::from(true),
        &[],
    );
    {
        let mut st = server.app.lock();
        let u = st.users.get_mut(&c.user_id).unwrap();
        for i in 0..MAX_ROOM_MUTES - 1 {
            u.room_mutes.insert(
                format!("gone-{i}"),
                MuteState {
                    forever: true,
                    until: Time::default(),
                },
            );
        }
    }
    c.status_error(obj! {"room_id" => "general", "mute" => 60i64}, CODE_DENIED);
    expect_echo(
        &mut c,
        obj! {"room_id" => room.as_str(), "mute" => 60i64},
        &room,
        Json::from(60i64),
        &[],
    );
    expect_echo(
        &mut c,
        obj! {"room_id" => "general", "mute" => false},
        "general",
        Json::from(false),
        &[],
    );
    expect_echo(
        &mut c,
        obj! {"room_id" => room.as_str(), "mute" => false},
        &room,
        Json::from(false),
        &[],
    );
    expect_echo(
        &mut c,
        obj! {"room_id" => "general", "mute" => true},
        "general",
        Json::from(true),
        &[],
    );
}
