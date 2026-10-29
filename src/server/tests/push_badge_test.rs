//! Unread counts and badge pushes, ported from push_test.go. The relay
//! fixture lives in push_test.rs.

use std::sync::atomic::Ordering;

use rust_stdlib::context::Context;
use rust_stdlib::time::{self, Duration};

use super::helpers::*;
use super::push_test::{
    add_push, go_idle, list, new_test_relay, paths, push_client, push_group, push_test_server,
    relay_push,
};
use super::status_test::{add_account, expect_mute};
use super::webpush_test::test_subscription;
use crate::obj;
use crate::server::protocol::*;
use crate::server::push::*;
use crate::server::status::{MuteState, StatusUpdate, STATUS_NONE};

/// Badge pushes wait badge_delay, so one push carries the count after a
/// burst of changes.
#[test]
fn test_badge_pushes_coalesce() {
    let relay = new_test_relay();
    let server = push_test_server();
    server.app.lock().badge_delay = Duration::from_millis(300);
    let mut clients = push_group(&server, 2);
    let mut b = clients.pop().unwrap();
    make_account(&server, &b.user_id);
    grant_role(&server, &b.user_id, "mod");
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
        // A reply on the same connection follows the cursor's handling.
        b.result("me", &format!("after-{id}"), Object::new());
    }
    let got = relay.pushes(&server, &mut a);
    assert!(
        got.len() == 1 && got[0].payload()["unread"] == Json::from(1i64),
        "coalesced badge pushes: {:?}",
        paths(&got)
    );
}

/// Shutdown cancels pending badge pushes rather than waiting out
/// badge_delay.
#[test]
fn test_shutdown_cancels_pending_badges() {
    let relay = new_test_relay();
    let server = push_test_server();
    server.app.lock().badge_delay = time::HOUR;
    let mut a = push_client(&server);
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

/// unread is the user's one count of messages after their read positions,
/// the same in every registration's pushes, and badge pushes, without a
/// message and with Urgency low, send each change of it to the relay
/// registrations with scope badge (§4.9).
#[test]
fn test_push_unread_and_badge() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut clients = push_group(&server, 2);
    let mut b = clients.pop().unwrap();
    make_account(&server, &b.user_id);
    grant_role(&server, &b.user_id, "mod");
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
    let read = |b: &mut TestClient, room_id: &str, message_id: &str| {
        b.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => room_id, "read_message_id" => message_id}});
        // A reply on the same connection follows the cursor's handling.
        let id = b.next_id("after-read");
        reply(
            b,
            "history",
            &id,
            obj! {"room_id" => "general", "limit" => 1i64},
        );
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
    read(&mut b, "general", &first);
    expect(
        &mut a,
        vec![
            d("/mentions", 1, "low", false),
            d("/phone", 1, "low", false),
        ],
    );
    read(&mut b, "general", &second);
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
    grant_role(&server, &a.user_id, "mod");
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
    read(&mut b, &ops, &elsewhere);
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
    read(&mut b, "general", &moved);
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
    a.notification("user");
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

/// A count is recorded as an endpoint's only once it accepts the push with
/// a 2xx: a badge push that failed is sent again at the next change, even
/// one that leaves the count where it was (§4.9).
#[test]
fn test_badge_count_recorded_only_when_accepted() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = push_client(&server);
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
    let mut clients = push_group(&server, 2);
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
    let mut a = push_client(&server);
    make_account(&server, &a.user_id);
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
    let mut a = push_client(&server);
    make_account(&server, &a.user_id);
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

/// Shutdown stops the timers that end timed mutes and send coalesced
/// statuses, and no badge push is scheduled after it.
#[test]
fn test_shutdown_stops_timers() {
    let relay = new_test_relay();
    let server = push_test_server();
    server.app.lock().badge_delay = time::HOUR;
    let a = push_client(&server);
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
        dora.status_hold = time::now().unix_milli() + 3_600_000;
        dora.chosen = STATUS_NONE.into();
        st.announce_status_locked("dora", crate::server::status::Cause::Connection);
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
