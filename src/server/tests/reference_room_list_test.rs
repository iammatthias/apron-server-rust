//! The room list and joined-room history tests of reference_test.go, test by
//! test. Each keeps the Go test's name, tables, and literal expectations.

use super::helpers::*;
use super::reference_test::{absent, empty, ids, nth};
use crate::obj;
use crate::server::protocol::*;

/// After a guest joins general and posts one message, room_list reports the
/// message's log_id as general's latest_log_id, not the earlier membership's.
/// Phase 1a's smoke diff masked ids, which could not tell the two apart.
#[test]
fn test_room_list_latest_log_id_is_the_last_record() {
    let server = new_test_server(default_config());
    let mut a = dial_test_client(&server);
    let (message_id, _) = save(&mut a, "m1", obj! {"body" => obj! {"text" => "hello"}});
    let listed = list_rooms(&mut a, obj! {"members" => true});
    let general = listed["joined"].as_list()[0].as_object().unwrap();
    assert_eq!(
        general["latest_log_id"],
        Json::from(message_id.as_str()),
        "general after one message: {general:?}"
    );
    let page = history_page(&mut a, "general", Object::new());
    let memberships = log_ids(&page, "memberships");
    assert!(
        memberships.len() == 1 && memberships[0].as_str() < message_id.as_str(),
        "the join precedes the message: {memberships:?} vs {message_id}"
    );
    assert_eq!(page["latest_log_id"], Json::from(message_id.as_str()));
}

/// A room_list `left` array naming one room.
fn left_list(room_id: &str) -> Json {
    Json::Array(vec![Json::from(obj! {"room_id" => room_id})])
}

#[test]
fn test_room_list_filters_and_order() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));
    grant_role(&server, &a.user_id, "mod");
    let (ops, _) = save_room(&mut a, "ops", obj! {"title" => "Ops"});
    let (deploy, _) = save_room(
        &mut a,
        "deploy",
        obj! {"parent_room_id" => ops.as_str(), "title" => "Deploy"},
    );
    grant_role(&server, &b.user_id, "mod");
    let (random, _) = save_room(&mut b, "random", obj! {"title" => "Random"});
    let (idle, _) = save_room(
        &mut b,
        "idle",
        obj! {"parent_room_id" => "general", "title" => "Idle"},
    );
    room_updated(&a, "updated");
    save(
        &mut a,
        "post",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "most recent"}},
    );

    // joined holds joined rooms at every depth, most recently active first;
    // not_joined holds visible unjoined top-level rooms. Without members,
    // neither members nor users is sent.
    let listed = list_rooms(&mut a, Object::new());
    assert_eq!(
        room_ids(listed.get("joined")),
        vec![ops.clone(), deploy.clone(), "general".into()],
        "joined"
    );
    assert_eq!(
        room_ids(listed.get("not_joined")),
        vec![random.clone()],
        "not_joined"
    );
    assert_eq!(
        listed.keys().collect::<Vec<_>>(),
        vec!["joined", "not_joined"],
        "listing without members: {listed:?}"
    );
    for entry in listed["joined"]
        .as_list()
        .iter()
        .chain(listed["not_joined"].as_list())
    {
        assert!(
            !entry.as_object().unwrap().contains_key("members"),
            "members without members: true: {entry:?}"
        );
    }
    let ops_entry = nth(&listed, "joined", 0);
    assert!(
        ops_entry["title"] == Json::from("Ops") && !absent(&ops_entry, "latest_log_id"),
        "ops entry: {ops_entry:?}"
    );

    // members: true lists every member of every room, joined or not, with
    // each user's current object once in users.
    let with_members = list_rooms(&mut a, obj! {"members" => true});
    let general = nth(&with_members, "joined", 2);
    assert!(
        member_ids(&general) == ids(&["guest_1", "guest_2"])
            && general["members"].as_list()[0]
                == Json::from(obj! {"user_id" => "guest_1", "status" => "online"}),
        "general members: {general:?}"
    );
    let random_entry = nth(&with_members, "not_joined", 0);
    assert_eq!(
        member_ids(&random_entry),
        ids(&["guest_2"]),
        "unjoined room members: {random_entry:?}"
    );
    let want_users = vec![
        Json::from(obj! {"user_id" => "guest_1", "name" => "Guest 1", "status" => "online"}),
        Json::from(obj! {"user_id" => "guest_2", "name" => "Guest 2", "status" => "online"}),
    ];
    assert_eq!(
        with_members.get("users"),
        Some(&Json::from(want_users.clone())),
        "users"
    );

    // filter leaves out the other array; an array it asks for is present
    // even when empty.
    let only = list_rooms(&mut a, obj! {"filter" => "joined"});
    assert!(
        absent(&only, "not_joined") && only["joined"].as_list().len() == 3,
        "filter joined: {only:?}"
    );
    let not = list_rooms(&mut a, obj! {"filter" => "not_joined"});
    assert!(
        absent(&not, "joined") && room_ids(not.get("not_joined")) == vec![random.clone()],
        "filter not_joined: {not:?}"
    );
    let all = list_rooms(&mut a, obj! {"filter" => "all"});
    assert!(
        all["joined"].as_list().len() == 3 && all["not_joined"].as_list().len() == 1,
        "filter all: {all:?}"
    );
    let none = list_rooms(
        &mut a,
        obj! {"parent_room_id" => "general", "filter" => "joined"},
    );
    assert_eq!(none, obj! {"joined" => empty()}, "empty joined threads");
    // parent_room_id lists that room's threads, joined or not.
    let threads = list_rooms(&mut a, obj! {"parent_room_id" => "general"});
    assert!(
        threads["joined"].as_list().is_empty()
            && room_ids(threads.get("not_joined")) == vec![idle.clone()],
        "general's threads: {threads:?}"
    );
    let threads = list_rooms(&mut b, obj! {"parent_room_id" => ops.as_str()});
    assert_eq!(
        room_ids(threads.get("not_joined")),
        vec![deploy.clone()],
        "ops threads for a non-member: {threads:?}"
    );
    // room_id lists one room and overrides parent_room_id.
    let one = list_rooms(
        &mut b,
        obj! {"room_id" => ops.as_str(), "parent_room_id" => "general", "members" => true},
    );
    assert!(
        room_ids(one.get("not_joined")) == vec![ops.clone()]
            && one["joined"].as_list().is_empty()
            && one.get("users") == Some(&Json::from(want_users[..1].to_vec())),
        "one room: {one:?}"
    );
    for (i, params) in [
        obj! {"parent_room_id" => "missing"},
        obj! {"room_id" => "missing"},
        obj! {"filter" => "mine"},
        obj! {"filter" => 5i64},
        obj! {"members" => "yes"},
        obj! {"latest_log_id" => 5i64},
        obj! {"parent_room_id" => 5i64},
    ]
    .into_iter()
    .enumerate()
    {
        a.expect_error(
            "room_list",
            &format!("bad-{i}"),
            params,
            CODE_INVALID_PARAMS,
        );
    }
    a.expect_quiet();
    b.expect_quiet();
}

/// With latest_log_id, room_list lists only rooms changed since, and `left`
/// the rooms the user left since (§4.2.1).
#[test]
fn test_room_list_latest_log_id_delta() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));
    grant_role(&server, &a.user_id, "mod");
    let (ops, _) = save_room(&mut a, "ops", obj! {"title" => "Ops"});
    join_room(&mut b, &ops);
    let since = expect_membership(&a, &ops, &b.user_id, true)["log_id"]
        .as_str()
        .unwrap()
        .to_owned();

    leave_room(&mut b, &ops);
    expect_membership(&a, &ops, &b.user_id, false);
    let (news, _) = save_room(&mut a, "news", obj! {"title" => "News"});
    grant_role(&server, &b.user_id, "mod");
    let (mine, _) = save_room(&mut b, "mine", obj! {"title" => "Mine"});

    // Joined since then in joined, left since then in left; general has not
    // changed since, so it is not listed.
    let delta = list_rooms(
        &mut b,
        obj! {"filter" => "joined", "latest_log_id" => since.as_str()},
    );
    let want = obj! {"joined" => delta["joined"].clone(), "left" => left_list(&ops)};
    assert!(
        delta == want && room_ids(delta.get("joined")) == vec![mine.clone()],
        "joined delta: {delta:?}"
    );
    // With not_joined too, a room left since then is also a visible unjoined
    // room that changed.
    let delta = list_rooms(
        &mut b,
        obj! {"latest_log_id" => since.as_str(), "members" => true},
    );
    assert!(
        room_ids(delta.get("not_joined")) == vec![news.clone(), ops.clone()]
            && delta.get("left") == Some(&left_list(&ops)),
        "full delta: {delta:?}"
    );
    assert_eq!(
        member_ids(&nth(&delta, "not_joined", 1)),
        ids(&["guest_1"]),
        "members in a delta: {delta:?}"
    );
    // left accompanies joined only.
    let delta = list_rooms(
        &mut b,
        obj! {"filter" => "not_joined", "latest_log_id" => since.as_str()},
    );
    assert!(absent(&delta, "left"), "not_joined delta: {delta:?}");
    // left is present even when empty.
    let latest = nth(
        &list_rooms(&mut b, obj! {"filter" => "joined"}),
        "joined",
        0,
    )["latest_log_id"]
        .clone();
    let nothing = list_rooms(
        &mut b,
        obj! {"filter" => "joined", "latest_log_id" => latest.clone()},
    );
    assert_eq!(
        nothing,
        obj! {"joined" => empty(), "left" => empty()},
        "empty delta"
    );
    // A room left before the position is not in left, even when it changed.
    save(
        &mut a,
        "later",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "later"}},
    );
    let delta = list_rooms(&mut b, obj! {"latest_log_id" => latest});
    assert!(
        delta.get("left") == Some(&empty())
            && room_ids(delta.get("not_joined")) == vec![ops.clone()],
        "delta after an old leave: {delta:?}"
    );
    // A room rejoined since the position is in joined, not left.
    join_room(&mut b, &ops);
    expect_membership(&a, &ops, &b.user_id, true);
    let delta = list_rooms(
        &mut b,
        obj! {"filter" => "joined", "latest_log_id" => since.as_str()},
    );
    assert!(
        room_ids(delta.get("joined")) == vec![ops.clone(), mine.clone()]
            && delta.get("left") == Some(&empty()),
        "delta after rejoining: {delta:?}"
    );
    // A room the user was removed from is left too.
    a.request(
        "room_leave",
        "remove",
        obj! {"room_id" => ops.as_str(), "user_id" => "guest_2"},
    );
    b.drain();
    let delta = list_rooms(
        &mut b,
        obj! {"filter" => "joined", "latest_log_id" => since.as_str()},
    );
    assert!(
        room_ids(delta.get("joined")) == vec![mine.clone()]
            && delta.get("left") == Some(&left_list(&ops)),
        "delta after removal: {delta:?}"
    );
}

/// A delta listing (§4.2.1) carries the private rooms and threads the user
/// was added to since the position, at their latest activity, and the ones
/// they left; it never carries one they are not in.
#[test]
fn test_room_list_latest_log_id_delta_private_rooms() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 3);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let (mut a, mut b, mut c) = (clients.remove(0), clients.remove(0), clients.remove(0));
    let since = nth(
        &list_rooms(&mut b, obj! {"filter" => "joined"}),
        "joined",
        0,
    )["latest_log_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (dm, _) = save_room(&mut a, "dm", obj! {"private" => true});
    a.request(
        "room_join",
        "add",
        obj! {"room_id" => dm.as_str(), "user_id" => b.user_id.as_str()},
    );
    let (thread, _) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => dm.as_str(), "title" => "Plans"},
    );
    a.request(
        "room_join",
        "add-thread",
        obj! {"room_id" => thread.as_str(), "user_id" => b.user_id.as_str()},
    );
    a.drain();
    save(
        &mut a,
        "in-thread",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "in the thread"}},
    );
    let (_, last) = save(
        &mut a,
        "in-dm",
        obj! {"room_id" => dm.as_str(), "body" => obj! {"text" => "just us"}},
    );
    let (other, _) = save_room(&mut c, "other", obj! {"private" => true});
    b.drain();

    let delta = list_rooms(
        &mut b,
        obj! {"filter" => "joined", "latest_log_id" => since.as_str()},
    );
    assert!(
        room_ids(delta.get("joined")) == vec![dm.clone(), thread.clone()]
            && delta.get("left") == Some(&empty()),
        "delta after being added: {delta:?}"
    );
    let head = nth(&delta, "joined", 0).get("latest_log_id").cloned();
    assert_eq!(
        head.as_ref(),
        last.get("log_id"),
        "private room's latest_log_id, want its last message's"
    );
    let unjoined =
        room_ids(list_rooms(&mut b, obj! {"latest_log_id" => since.as_str()}).get("not_joined"));
    assert!(
        !unjoined.contains(&other),
        "someone else's private room in a delta: {unjoined:?}"
    );

    // Removed from the room, its thread goes too.
    a.request(
        "room_leave",
        "remove",
        obj! {"room_id" => dm.as_str(), "user_id" => b.user_id.as_str()},
    );
    b.drain();
    let delta = list_rooms(
        &mut b,
        obj! {"filter" => "joined", "latest_log_id" => since.as_str()},
    );
    assert!(
        room_ids(delta.get("joined")).is_empty() && !delta["left"].as_list().is_empty(),
        "delta after removal: {delta:?}"
    );
    c.drain();
}

/// Without room_id, history pages the log of every room the user joined as
/// one log (§4.3): private rooms included, nothing of rooms not joined or not
/// visible, a moved message once, in log_id order both ways.
#[test]
fn test_history_without_room_id_pages_joined_rooms() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 3);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let (mut a, mut b, mut c) = (clients.remove(0), clients.remove(0), clients.remove(0));
    let since = nth(
        &list_rooms(&mut b, obj! {"filter" => "joined"}),
        "joined",
        0,
    )["latest_log_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (dm, _) = save_room(&mut a, "dm", obj! {"private" => true});
    a.request(
        "room_join",
        "add",
        obj! {"room_id" => dm.as_str(), "user_id" => b.user_id.as_str()},
    );
    let (theirs, _) = save_room(&mut c, "theirs", obj! {"private" => true});
    let (aside, _) = save_room(
        &mut c,
        "aside",
        obj! {"parent_room_id" => "general", "title" => "Aside"},
    );
    a.drain();
    grant_role(&server, &a.user_id, "mod");
    let (ops, _) = save_room(&mut a, "ops", obj! {"title" => "Ops"});
    b.drain();
    join_room(&mut b, &ops);
    a.drain();
    c.drain();
    let mut mine = Vec::new();
    let mut post = |cl: &mut TestClient, id: &str, room: &str, keep: bool| -> String {
        cl.drain();
        let (message, _) = save(
            cl,
            id,
            obj! {"room_id" => room, "body" => obj! {"text" => id}},
        );
        if keep {
            mine.push(message.clone());
        }
        message
    };
    post(&mut a, "dm-1", &dm, true);
    let moved = post(&mut a, "general-1", "general", true);
    post(&mut c, "theirs-1", &theirs, false);
    post(&mut c, "aside-1", &aside, false);
    post(&mut a, "dm-2", &dm, true);
    // Moved from general into ops, both joined: its move snapshot is in both
    // logs, and comes once.
    a.drain();
    a.request(
        "message",
        "move",
        obj! {"message_id" => moved.as_str(), "room_id" => ops.as_str(), "body" => obj! {"text" => "general-1"}},
    );
    b.drain();

    let page = b.result(
        "history",
        "all",
        obj! {"after" => since.as_str(), "limit" => 50i64},
    );
    let ids = log_ids(&page, "messages");
    assert!(
        ids.len() == 4
            && ids[0] == mine[0]
            && ids[1] == mine[1]
            && ids[2] == mine[2]
            && page.get("more") == Some(&Json::from(false)),
        "joined rooms' log: {ids:?}, want {mine:?} and the move"
    );
    for key in ["rooms", "memberships", "messages"] {
        let records = page.get(key).map(Json::as_list).unwrap_or(&[]);
        assert!(!records.is_empty(), "no {key} in {page:?}");
        for record in records {
            let room = record.as_object().unwrap().get("room_id").cloned();
            assert!(
                [
                    Json::from("general"),
                    Json::from(dm.as_str()),
                    Json::from(ops.as_str())
                ]
                .iter()
                .any(|r| Some(r) == room.as_ref()),
                "a record of {room:?}, which bob did not join: {record:?}"
            );
        }
    }
    assert_eq!(
        page.get("latest_log_id"),
        Some(&Json::from(ids[3].as_str())),
        "latest_log_id, want the move"
    );

    // One record at a time forward, and the newest backward.
    let mut forward = Vec::new();
    let mut after = since.clone();
    for _ in 0..50 {
        let id = b.next_id("forward");
        let next = b.result(
            "history",
            &id,
            obj! {"after" => after.as_str(), "limit" => 1i64},
        );
        forward.extend(log_ids(&next, "messages"));
        if next.get("more") == Some(&Json::from(false)) {
            break;
        }
        let last: i64 = next["last_log_id"].as_str().unwrap().parse().unwrap();
        after = (last + 1).to_string();
    }
    assert_eq!(forward, ids, "forward pages");
    let newest = b.result("history", "newest", obj! {"limit" => 1i64});
    assert!(
        log_ids(&newest, "messages") == ids[3..] && newest.get("more") == Some(&Json::from(true)),
        "newest page: {newest:?}"
    );
    // Bounded on both sides, across rooms; and the move snapshot alone.
    let middle = b.result(
        "history",
        "middle",
        obj! {"after" => ids[0].as_str(), "before" => ids[2].as_str()},
    );
    assert_eq!(
        log_ids(&middle, "messages"),
        ids[..3].to_vec(),
        "bounded page: {middle:?}"
    );
    let one = b.result(
        "history",
        "one",
        obj! {"after" => ids[3].as_str(), "before" => ids[3].as_str()},
    );
    assert!(
        log_ids(&one, "messages") == ids[3..] && one.get("more") == Some(&Json::from(false)),
        "the move snapshot alone: {one:?}"
    );

    // The log's lower bound is the server's, whatever rooms the user is in,
    // so it never moves (§4.3.3); in no rooms, the log is empty and ends
    // just before it.
    let start = page.get("history_log_id").cloned();
    let general = history_page(&mut b, "general", Object::new());
    assert_eq!(
        start.as_ref(),
        general.get("history_log_id"),
        "history_log_id, want general's"
    );
    for room in ["general", ops.as_str(), dm.as_str()] {
        leave_room(&mut b, room);
        b.drain();
        let id = b.next_id("left");
        let bound = b
            .result("history", &id, obj! {"limit" => 1i64})
            .get("history_log_id")
            .cloned();
        assert!(
            bound == start || room == dm,
            "history_log_id after leaving {room}: {bound:?}, want {start:?}"
        );
    }
    let none = b.result("history", "none", Object::new());
    let first: i64 = start
        .as_ref()
        .and_then(Json::as_str)
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        absent(&none, "history_log_id")
            && none.get("latest_log_id") == Some(&Json::from((first - 1).to_string()))
            && none.get("more") == Some(&Json::from(false))
            && absent(&none, "messages"),
        "history in no rooms: {none:?}"
    );
    join_room(&mut b, "general");
    let bound = b
        .result("history", "rejoined", obj! {"limit" => 1i64})
        .get("history_log_id")
        .cloned();
    assert_eq!(bound, start, "history_log_id after rejoining");
}
