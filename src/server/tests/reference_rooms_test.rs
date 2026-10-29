//! The room settings, membership, delivery, and read cursor tests of
//! reference_test.go, test by test. Each keeps the Go test's name, tables,
//! and literal expectations.

use super::helpers::*;
use super::reference_test::{absent, ids, nth};
use crate::obj;
use crate::server::config::Config;
use crate::server::protocol::*;
use crate::server::rooms::{MAX_CREATED_ROOMS, MAX_THREADS, MAX_THREADS_PER_USER};
use crate::ws;

/// Only an admin or mod creates and edits top-level rooms, and only an
/// admin `general`; anyone creates and edits threads, which cannot nest. An
/// account has at most MAX_THREADS_PER_USER threads, the server
/// MAX_CREATED_ROOMS top-level rooms besides `general` and MAX_THREADS rooms
/// besides it and private rooms (apron-server-cloudflare's commitRoom).
#[test]
fn test_room_set_permissions_and_caps() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let (mut guest, mut mod_) = (clients.remove(0), clients.remove(0));
    let denied = |c: &mut TestClient, id: &str, params: Object, message: &str| {
        let frame = c.call("room_set", id, params);
        assert_eq!(
            frame["error"]
                .as_object()
                .map(|e| (e["code"].clone(), e["message"].clone())),
            Some((Json::from(CODE_DENIED), Json::from(message))),
            "{id}: {frame:?}"
        );
    };
    denied(
        &mut guest,
        "top",
        obj! {"title" => "Ops"},
        "Only an admin or mod may create a room; others may create threads",
    );
    denied(
        &mut guest,
        "general",
        obj! {"room_id" => "general", "title" => "Mine"},
        "Only an admin may edit the general room",
    );
    grant_role(&server, &mod_.user_id, "mod");
    denied(
        &mut mod_,
        "general",
        obj! {"room_id" => "general", "title" => "Mine"},
        "Only an admin may edit the general room",
    );
    let (ops, _) = save_room(&mut mod_, "ops", obj! {"title" => "Ops"});
    denied(
        &mut guest,
        "edit-ops",
        obj! {"room_id" => ops.as_str(), "title" => "Mine"},
        "Only an admin or mod may edit a room; anyone may edit a thread",
    );
    save_room(
        &mut mod_,
        "mod-edits-ops",
        obj! {"room_id" => ops.as_str(), "title" => "Ops 2"},
    );
    let (thread, _) = save_room(
        &mut guest,
        "thread",
        obj! {"parent_room_id" => ops.as_str()},
    );
    mod_.drain();
    save_room(
        &mut mod_,
        "edit-thread",
        obj! {"room_id" => thread.as_str(), "title" => "Renamed"},
    );
    guest.drain();
    denied(
        &mut guest,
        "nested",
        obj! {"parent_room_id" => thread.as_str()},
        "Threads cannot be nested",
    );
    revoke_role(&server, &mod_.user_id, "mod");
    grant_role(&server, &mod_.user_id, "admin");
    save_room(
        &mut mod_,
        "edit-general",
        obj! {"room_id" => "general", "title" => "General"},
    );
    for i in 1..MAX_CREATED_ROOMS {
        save_room(&mut mod_, &format!("top-{i}"), obj! {"title" => "Top"});
    }
    denied(&mut mod_, "top-full", obj! {"title" => "Top"}, "room_limit");
    guest.drain();

    // An account's live threads are capped; a guest's are not.
    server
        .app
        .lock()
        .users
        .get_mut(&mod_.user_id)
        .unwrap()
        .invited = true;
    for i in 0..MAX_THREADS_PER_USER {
        save_room(
            &mut mod_,
            &format!("mine-{i}"),
            obj! {"parent_room_id" => "general"},
        );
        guest.drain();
    }
    denied(
        &mut mod_,
        "mine-full",
        obj! {"parent_room_id" => "general"},
        &format!("You can have at most {MAX_THREADS_PER_USER} threads at once; one stops counting when everyone has left it or its history expires"),
    );
    let made = MAX_CREATED_ROOMS + 1 + MAX_THREADS_PER_USER;
    for i in made..MAX_THREADS {
        save_room(
            &mut guest,
            &format!("theirs-{i}"),
            obj! {"parent_room_id" => "general"},
        );
        mod_.drain();
    }
    denied(
        &mut guest,
        "theirs-full",
        obj! {"parent_room_id" => "general"},
        "thread_limit",
    );
    // Private rooms count against their own caps, and their members edit
    // them.
    let (private, _) = save_room(&mut mod_, "private", obj! {"private" => true});
    save_room(
        &mut mod_,
        "edit-private",
        obj! {"room_id" => private.as_str(), "title" => "Ours"},
    );
}

/// Every join and leave is a logged membership, delivered to the room's
/// members before and after the change and ordered before the room_update
/// and the result on the requesting connection (§4.2.2).
#[test]
fn test_join_leave_and_deliveries() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 3);
    let (mut a, mut b, mut c) = (clients.remove(0), clients.remove(0), clients.remove(0));
    grant_role(&server, &a.user_id, "mod");
    let (ops, ops_record) = save_room(&mut a, "ops", obj! {"title" => "Ops"});

    // A member receives the room's records; a poster who has not joined gets
    // only the result.
    b.write(&obj! {"method" => "message", "id" => "outside", "params" => obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "from outside"}}});
    let frames = b.drain();
    assert_eq!(
        methods(&frames),
        vec!["reply"],
        "non-member post: {frames:?}"
    );
    let outside = a.notification("message");
    assert_eq!(
        outside["from"].as_object().unwrap().get("user_id"),
        Some(&Json::from("guest_2")),
        "non-member post broadcast: {outside:?}"
    );
    // Reactions and typing in a room not joined reach only its members.
    react(
        &mut a,
        "react",
        outside["message_id"].as_str().unwrap(),
        &["👍"],
    );
    b.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => ops.as_str(), "typing" => 5i64}});
    a.notification("activity");
    b.expect_quiet();

    // Joining: the membership goes to the members and the joiner, then the
    // joiner gets room_update joined with the members, then the result.
    let record = join_room(&mut b, &ops);
    assert!(
        record["title"] == Json::from("Ops")
            && record.get("log_id") == ops_record.get("log_id")
            && member_ids(&record) == ids(&["guest_1", "guest_2"]),
        "joined record: {record:?}"
    );
    let joined = expect_membership(&a, &ops, "guest_2", true);
    assert_eq!(
        joined.get("log_id"),
        record.get("latest_log_id"),
        "member's copy {joined:?} disagrees with {record:?}"
    );
    c.expect_quiet();
    save(
        &mut a,
        "inside",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "welcome"}},
    );
    b.notification("message");
    // Joining again logs nothing and re-sends the room to the calling
    // connection only.
    let (before, _) = b.request("room_join", "again", obj! {"room_id" => ops.as_str()});
    assert!(
        before.len() == 1
            && member_ids(&joined_record(&before[0], "guest_2")) == ids(&["guest_1", "guest_2"]),
        "second join: {before:?}"
    );
    a.expect_quiet();
    b.expect_error(
        "room_join",
        "missing",
        obj! {"room_id" => "missing"},
        CODE_INVALID_PARAMS,
    );

    // Leaving: the leaver's connections get room_update with left and the
    // membership, the other members the membership alone, then the result;
    // a result sent after the leave reflects it.
    b.write(&obj! {"method" => "room_leave", "id" => "leave", "params" => obj! {"room_id" => ops.as_str()}});
    b.write(&obj! {"method" => "room_list", "id" => "after-leave", "params" => obj! {"filter" => "joined"}});
    let frames = b.drain();
    assert_eq!(
        methods(&frames),
        vec!["room_update", "reply", "reply"],
        "leave frames: {frames:?}"
    );
    let leave = check_left(&frames[0], &ops, "guest_2");
    assert_eq!(
        room_ids(frames[2]["result"].as_object().unwrap().get("joined")),
        ids(&["general"]),
        "joined after leave"
    );
    let left = expect_membership(&a, &ops, "guest_2", false);
    assert_eq!(left, leave, "member's copy of the leave");
    save(
        &mut a,
        "after",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "gone"}},
    );
    b.expect_quiet();
    // Leaving a room not joined changes nothing.
    b.result(
        "room_leave",
        "leave-again",
        obj! {"room_id" => ops.as_str()},
    );
    b.expect_error(
        "room_leave",
        "missing",
        obj! {"room_id" => "missing"},
        CODE_INVALID_PARAMS,
    );
    a.expect_quiet();

    // Leaves are memberships only, never user notifications (§3.3), even from
    // the last shared room.
    leave_room(&mut b, "general");
    expect_membership(&a, "general", "guest_2", false);
    expect_membership(&c, "general", "guest_2", false);
    a.expect_quiet();
    join_room(&mut b, &ops);
    expect_membership(&a, &ops, "guest_2", true);

    // A guest whose last connection closes is retired: it leaves every room
    // it joined, each a logged membership for the remaining members.
    let _ = b.ws.close(ws::STATUS_NORMAL_CLOSURE, "done");
    expect_membership(&a, &ops, "guest_2", false);
    a.expect_quiet();
    c.expect_quiet();
    let entry = nth(
        &list_rooms(&mut a, obj! {"room_id" => ops.as_str(), "members" => true}),
        "joined",
        0,
    );
    assert_eq!(
        member_ids(&entry),
        ids(&["guest_1"]),
        "retired guest is still a member: {entry:?}"
    );
    // history returns the room's memberships in log order.
    let changes: Vec<String> = records(&history_page(&mut a, &ops, Object::new()), "memberships")
        .iter()
        .map(|value| {
            let entry = value["members"].as_list()[0].as_object().unwrap();
            let user_id = entry["user"].as_object().unwrap()["user_id"]
                .as_str()
                .unwrap();
            format!("{user_id} {}", entry["joined"].is_true())
        })
        .collect();
    assert_eq!(
        changes,
        vec![
            "guest_1 true",
            "guest_2 true",
            "guest_2 false",
            "guest_2 true",
            "guest_2 false"
        ],
        "ops memberships"
    );
}

/// A thread's messages go only to its members; the parent's members get only
/// its room record changes, as room_update updated (§4.2, §4.2.3).
#[test]
fn test_thread_messages_reach_only_thread_members() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 3);
    let (mut a, mut b, mut c) = (clients.remove(0), clients.remove(0), clients.remove(0));
    save(&mut a, "root", obj! {"body" => obj! {"text" => "Deploy"}});
    b.notification("message");
    c.notification("message");
    let (thread, record) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => "general", "description" => "Deploy"},
    );
    for member in [&b, &c] {
        let observed = room_updated(member, "updated");
        assert_eq!(observed, record, "parent member's new thread");
    }
    join_room(&mut b, &thread);
    expect_membership(&a, &thread, "guest_2", true);
    c.expect_quiet();

    let (id, _) = save(
        &mut a,
        "in-thread",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "rolling out"}},
    );
    b.notification("message");
    react(&mut b, "react", &id, &["👍"]);
    a.notification("reactions");
    a.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => thread.as_str(), "typing" => 3i64}});
    b.notification("activity");
    a.expect_quiet();
    c.expect_quiet();

    // An edited thread record reaches the parent's members too.
    let (_, edited) = save_room(
        &mut b,
        "rename",
        obj! {"room_id" => thread.as_str(), "title" => "Rollout"},
    );
    for member in [&a, &c] {
        let observed = room_updated(member, "updated");
        assert_eq!(observed, edited, "thread edit");
    }
    for client in [&mut a, &mut b, &mut c] {
        client.expect_quiet();
    }
}

#[test]
fn test_prev_log_id_links_records() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let (id, creation) = save(&mut c, "create", obj! {"body" => obj! {"text" => "one"}});
    assert!(
        !creation.contains_key("prev_log_id"),
        "creation has prev_log_id: {creation:?}"
    );
    let (_, edit) = save(
        &mut c,
        "edit",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => "two"}},
    );
    assert_eq!(
        edit.get("prev_log_id"),
        Some(&Json::from(id.as_str())),
        "edit prev_log_id: {edit:?}"
    );
    grant_role(&server, &c.user_id, "mod");
    let (room, record) = save_room(&mut c, "room", obj! {"title" => "A"});
    let (_, updated) = save_room(
        &mut c,
        "update",
        obj! {"room_id" => room.as_str(), "title" => "B"},
    );
    assert!(
        !record.contains_key("prev_log_id") && updated.get("prev_log_id") == record.get("log_id"),
        "room prev_log_id: {record:?} then {updated:?}"
    );
    // Only room records and message snapshots carry prev_log_id (§4.3.1).
    let first = react(&mut c, "r1", &id, &["👍"]);
    let second = react(&mut c, "r2", &id, &["🎉"]);
    assert!(
        absent(&first, "prev_log_id") && absent(&second, "prev_log_id"),
        "reactions prev_log_id: {first:?} then {second:?}"
    );
    leave_room(&mut c, &room);
    for value in records(&history_page(&mut c, &room, Object::new()), "memberships") {
        assert!(
            !value.contains_key("prev_log_id"),
            "membership with prev_log_id: {value:?}"
        );
    }
}

#[test]
fn test_read_cursors() {
    let server = new_test_server(Config {
        read_receipts: true,
        ..default_config()
    });
    let mut clients = dial_group(&server, 2);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));
    let (first, _) = save(&mut a, "one", obj! {"body" => obj! {"text" => "one"}});
    b.notification("message");
    let (second, _) = save(&mut a, "two", obj! {"body" => obj! {"text" => "two"}});
    b.notification("message");

    a.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => "general", "read_message_id" => second.as_str()}});
    let want = obj! {"room_id" => "general", "from" => obj! {"user_id" => "guest_1", "name" => "Guest 1"}, "read_message_id" => second.as_str()};
    for c in [&a, &b] {
        assert_eq!(c.notification("activity"), want, "read cursor");
    }
    // A cursor that moves back is ignored.
    a.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => "general", "read_message_id" => first.as_str()}});
    b.expect_quiet();
    a.expect_quiet();
    // activity is a notification: one sent with an id is processed as one,
    // unanswered, and an unknown cursor changes nothing (§1).
    a.write(&obj! {"method" => "activity", "id" => "unknown", "params" => obj! {"room_id" => "general", "read_message_id" => "999"}});
    a.expect_quiet();
    b.expect_quiet();

    // Kept cursors follow a room_list result that lists the room: every
    // member's for a joined room, only the user's own for another.
    let mut c = dial_test_client(&server);
    make_account(&server, &c.user_id);
    expect_membership(&a, "general", &c.user_id, true);
    expect_membership(&b, "general", &c.user_id, true);
    c.write(
        &obj! {"method" => "room_list", "id" => "list", "params" => obj! {"filter" => "joined"}},
    );
    let frames = c.drain();
    assert!(
        methods(&frames) == vec!["reply", "activity"]
            && frames[1].get("params") == Some(&Json::from(want.clone())),
        "room_list frames: {frames:?}"
    );
    let (thread, _) = save_room(&mut b, "thread", obj! {"parent_room_id" => "general"});
    room_updated(&a, "updated");
    room_updated(&c, "updated");
    b.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => thread.as_str(), "read_message_id" => second.as_str()}});
    b.notification("activity");
    a.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => thread.as_str(), "read_message_id" => first.as_str()}});
    a.notification("activity");
    b.notification("activity");
    a.write(&obj! {"method" => "room_list", "id" => "threads", "params" => obj! {"parent_room_id" => "general"}});
    let frames = a.drain();
    assert!(
        methods(&frames) == vec!["reply", "activity"]
            && frames[1]["params"].as_object().unwrap()["from"]
                .as_object()
                .unwrap()
                .get("user_id")
                == Some(&Json::from("guest_1")),
        "unjoined room cursors: {frames:?}"
    );
}
