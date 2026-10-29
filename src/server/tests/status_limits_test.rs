//! The rate limit and bound tests of status_test.go, test by test. Each
//! keeps the Go test's name, tables, and literal expectations.

use rust_stdlib::time::{self, Time};

use super::helpers::*;
use crate::obj;
use crate::server::protocol::*;
use crate::server::status::*;

use super::status_test::{expect_echo, expect_profile_status, set_status, status_id};

/// The refusal's retry_after, which must be whole seconds within a minute.
fn wait_of(failure: &Object) -> i64 {
    match failure["data"].as_object().expect("data")["retry_after"] {
        Json::Number(n) if (1.0..=60.0).contains(&n) => n as i64,
        ref other => panic!("retry_after {other:?}: {failure:?}"),
    }
}

/// A connection goes idle at most `idle_changes_per_connection_minute`
/// times a rolling minute, as on Cloudflare: beyond it a request going idle
/// is retry_after "Idle changes limited" and changes nothing, while coming
/// back, or a report that leaves it idle, is never refused.
#[test]
fn test_idle_changes_are_limited() {
    let mut config = default_config();
    config.limits.idle_changes_per_connection_minute = 2;
    let server = new_test_server(config);
    let mut clients = dial_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    watching(&mut [&mut a]);
    a.drain();
    for _ in 0..2 {
        b.status(obj! {"idle" => 300i64});
        b.status(obj! {"idle" => 600i64});
        b.status(obj! {"idle" => false});
    }
    a.drain();
    let failure = b.status_error(obj! {"idle" => 300i64}, CODE_RETRY_AFTER);
    assert_eq!(failure["message"], Json::from("Idle changes limited"));
    wait_of(&failure);
    b.status(obj! {"idle" => false});
    b.expect_quiet();
    a.expect_quiet();
    let st = server.app.lock();
    let u = &st.users[&b.user_id];
    assert_eq!(u.shown_status(st.attended(u)), STATUS_ONLINE);
}

/// A user's mute changes and `me` status changes share one limit,
/// `status_changes_per_user_minute` a rolling minute, as on Cloudflare:
/// beyond it a mute is retry_after "Mute changes limited" and a status
/// change "Status changes limited", and either changes nothing, while
/// going idle and a `me` that leaves the status as it is pass.
#[test]
fn test_mute_and_status_changes_share_a_limit() {
    let mut config = default_config();
    config.limits.status_changes_per_user_minute = 2;
    let server = new_test_server(config);
    let mut clients = dial_group(&server, 2);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    watching(&mut [&mut a]);
    a.drain();
    expect_echo(&mut b, obj! {"mute" => true}, "", Json::from(true), &[]);
    assert_eq!(set_status(&mut b, "dnd"), Json::from("dnd"), "status");
    expect_profile_status(&a, &b.user_id, "dnd");
    let failure = b.status_error(
        obj! {"room_id" => "general", "mute" => true},
        CODE_RETRY_AFTER,
    );
    assert_eq!(failure["message"], Json::from("Mute changes limited"));
    wait_of(&failure);
    let frame = b.call(
        "me",
        &status_id(),
        obj! {"status" => "online", "name" => "Bea"},
    );
    let failure = frame["error"].as_object().expect("error");
    assert_eq!(failure["code"], Json::from(CODE_RETRY_AFTER), "{frame:?}");
    assert_eq!(failure["message"], Json::from("Status changes limited"));
    // `me` is no request of ext:limits' rows, so its refusal names no
    // category: data holds retry_after alone (Cloudflare b97f119).
    let data = failure["data"].as_object().expect("data");
    assert_eq!(data.keys().collect::<Vec<_>>(), ["retry_after"], "{data:?}");
    assert_eq!(
        set_status(&mut b, "dnd"),
        Json::from("dnd"),
        "unchanged status"
    );
    // Going idle has its own limit, and dnd shows over idle.
    b.status(obj! {"idle" => 300i64});
    b.expect_quiet();
    a.expect_quiet();
    let st = server.app.lock();
    let u = &st.users[&b.user_id];
    let now = time::now();
    assert!(
        u.mute.forever
            && !st.room_muted(u, "general", &now)
            && u.chosen == STATUS_DND
            && u.name != "Bea",
        "after limited requests: mute {:?}, room mutes {:?}, status {:?}, name {:?}",
        u.mute,
        u.room_mutes,
        u.chosen,
        u.name
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

/// A user mutes at most 100 rooms at once, as on Cloudflare: muting
/// another is denied, while changing or removing a room's mute is not.
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
        for i in 0..99 {
            u.room_mutes.insert(
                format!("gone-{i}"),
                MuteState {
                    forever: true,
                    until: Time::default(),
                },
            );
        }
    }
    let refused = c.status_error(obj! {"room_id" => "general", "mute" => 60i64}, CODE_DENIED);
    assert_eq!(
        refused["message"],
        Json::from("At most 100 rooms can be muted; unmute one first")
    );
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
