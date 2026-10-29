//! The private room tests of reference_test.go, test by test. Each keeps
//! the Go test's name, tables, and literal expectations.

use super::helpers::*;
use super::reference_test::{ids, nth};
use crate::obj;
use crate::server::protocol::*;

fn strs(values: &[&str]) -> Json {
    Json::Array(values.iter().map(|v| Json::from(*v)).collect())
}

/// Config.max_private_rooms bounds the top-level private rooms one user is
/// in, created or added to: past it, creating one or being added to one is
/// denied. Public rooms and threads are not counted, and leaving a private
/// room makes room for another.
#[test]
fn test_private_rooms_per_user_bound() {
    let mut config = default_config();
    config.max_private_rooms = 2;
    let server = new_test_server(config);
    let mut clients = dial_group(&server, 2);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));

    let (first, _) = save_room(&mut a, "first", obj! {"private" => true});
    save_room(&mut a, "second", obj! {"private" => true});
    a.expect_error("room_set", "third", obj! {"private" => true}, CODE_DENIED);
    // Not counted: a public room, a private thread of a public room, and a
    // thread of a private room, whose members alone can be added to it.
    grant_role(&server, &a.user_id, "mod");
    save_room(&mut a, "open", obj! {"title" => "Open"});
    save_room(
        &mut a,
        "aside",
        obj! {"parent_room_id" => "general", "private" => true},
    );
    save_room(&mut a, "side", obj! {"parent_room_id" => first.as_str()});

    // b is in two private rooms of its own, so nobody can add b to another.
    let (full, _) = save_room(&mut b, "b1", obj! {"private" => true});
    save_room(&mut b, "b2", obj! {"private" => true});
    a.expect_error(
        "room_join",
        "full",
        obj! {"room_id" => first.as_str(), "user_id" => b.user_id.as_str()},
        CODE_DENIED,
    );
    b.expect_quiet();
    // Leaving one makes room for the next.
    leave_room(&mut b, &full);
    let (_, result) = a.request(
        "room_join",
        "added",
        obj! {"room_id" => first.as_str(), "user_id" => b.user_id.as_str()},
    );
    assert!(result.is_empty(), "adding b: {result:?}");
    let joined = joined_record(&b.read(), &b.user_id);
    assert!(
        joined["room_id"] == Json::from(first.as_str())
            && joined.get("private") == Some(&Json::from(true)),
        "b's room_update: {joined:?}"
    );
    b.expect_error("room_set", "b3", obj! {"private" => true}, CODE_DENIED);
    // Adding someone already in the room changes nothing, bound or not.
    a.result(
        "room_join",
        "again",
        obj! {"room_id" => first.as_str(), "user_id" => b.user_id.as_str()},
    );
}

/// A private room and its threads are invisible to non-members, who get
/// invalid_params as for an unknown room; members bring others in with
/// room_join's user_id, and the room's creator removes them with
/// room_leave's (§4.2.2, §4.2.4).
#[test]
fn test_private_rooms_and_membership_by_user_id() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 3);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let (mut a, mut b, mut c) = (clients.remove(0), clients.remove(0), clients.remove(0));

    let (room, record) = save_room(&mut a, "private", obj! {"title" => "DM", "private" => true});
    assert_eq!(
        record.get("private"),
        Some(&Json::from(true)),
        "private room record: {record:?}"
    );
    let (secret, _) = save(
        &mut a,
        "secret",
        obj! {"room_id" => room.as_str(), "body" => obj! {"text" => "just us"}},
    );
    let (thread, _) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => room.as_str(), "description" => "Plans", "private" => false},
    );
    // A thread created without private takes its parent's (§4.2.4).
    let (_, inherited) = save_room(&mut a, "inherits", obj! {"parent_room_id" => room.as_str()});
    assert_eq!(
        inherited.get("private"),
        Some(&Json::from(true)),
        "thread of a private room: {inherited:?}"
    );
    // A private thread in a public room: its record does not reach the
    // parent's members.
    let (aside, aside_record) = save_room(
        &mut a,
        "aside",
        obj! {"parent_room_id" => "general", "private" => true},
    );
    assert!(
        aside_record.get("private") == Some(&Json::from(true))
            && aside_record.get("parent_room_id") == Some(&Json::from("general")),
        "private thread record: {aside_record:?}"
    );
    b.expect_quiet();
    c.expect_quiet();

    // To anyone else these rooms, their threads, and their messages are unknown.
    for room_id in [&room, &thread, &aside] {
        let room_id = room_id.as_str();
        let id = b.next_id("history");
        b.expect_error(
            "history",
            &id,
            obj! {"room_id" => room_id},
            CODE_INVALID_PARAMS,
        );
        let id = b.next_id("join");
        b.expect_error(
            "room_join",
            &id,
            obj! {"room_id" => room_id},
            CODE_INVALID_PARAMS,
        );
        let id = b.next_id("list");
        b.expect_error(
            "room_list",
            &id,
            obj! {"room_id" => room_id},
            CODE_INVALID_PARAMS,
        );
        let id = b.next_id("post");
        b.expect_error(
            "message",
            &id,
            obj! {"room_id" => room_id, "body" => obj! {"text" => "hi"}},
            CODE_INVALID_PARAMS,
        );
        let id = b.next_id("set");
        b.expect_error(
            "room_set",
            &id,
            obj! {"room_id" => room_id, "title" => "Mine"},
            CODE_INVALID_PARAMS,
        );
        let id = b.next_id("help");
        b.expect_error(
            "command",
            &id,
            obj! {"room_id" => room_id, "body" => obj! {"text" => "/help"}},
            CODE_INVALID_PARAMS,
        );
    }
    b.expect_error(
        "room_list",
        "threads",
        obj! {"parent_room_id" => room.as_str()},
        CODE_INVALID_PARAMS,
    );
    b.expect_error(
        "room_set",
        "nested",
        obj! {"parent_room_id" => room.as_str()},
        CODE_INVALID_PARAMS,
    );
    b.expect_error(
        "reactions",
        "react",
        obj! {"message_id" => secret.as_str(), "emojis" => strs(&["👀"])},
        CODE_INVALID_PARAMS,
    );
    b.expect_error(
        "message",
        "reply",
        obj! {"body" => obj! {"text" => "re"}, "reply_to" => obj! {"message_id" => secret.as_str()}},
        CODE_INVALID_PARAMS,
    );
    let listed = list_rooms(&mut b, Object::new());
    let unjoined = room_ids(listed.get("not_joined"));
    assert!(
        !unjoined.contains(&room),
        "private room listed to a non-member: {unjoined:?}"
    );
    let unjoined =
        room_ids(list_rooms(&mut b, obj! {"parent_room_id" => "general"}).get("not_joined"));
    assert!(
        !unjoined.contains(&aside),
        "private thread listed to a non-member: {unjoined:?}"
    );

    // Only members may add others; adding someone gives them the room.
    grant_role(&server, &a.user_id, "mod");
    let (open, _) = save_room(&mut a, "open", obj! {"title" => "Open"});
    b.expect_error(
        "room_join",
        "not-a-member",
        obj! {"room_id" => open.as_str(), "user_id" => "guest_3"},
        CODE_DENIED,
    );
    for (id, user_id) in [
        ("unknown-user", "nobody"),
        ("empty-user", ""),
        ("spaced-user", "guest 2"),
    ] {
        a.expect_error(
            "room_join",
            id,
            obj! {"room_id" => room.as_str(), "user_id" => user_id},
            CODE_INVALID_PARAMS,
        );
    }
    let (before, result) = a.request(
        "room_join",
        "add",
        obj! {"room_id" => room.as_str(), "user_id" => "guest_2"},
    );
    assert!(
        result.is_empty() && methods(&before) == vec!["room_update"],
        "adding a member: {before:?} then {result:?}"
    );
    check_membership(&membership_only(&before[0]), &room, "guest_2", true);
    let added = b.read();
    check_membership(&membership_of(&added), &room, "guest_2", true);
    let joined = joined_record(&added, "guest_2");
    assert!(
        joined["room_id"] == Json::from(room.as_str())
            && joined.get("private") == Some(&Json::from(true)),
        "added member's room_update: {joined:?}"
    );
    let messages = records(&history_page(&mut b, &room, Object::new()), "messages");
    assert_eq!(messages.len(), 1, "added member's history: {messages:?}");
    // Its public thread is visible to the new member, who is not in it.
    let unjoined =
        room_ids(list_rooms(&mut b, obj! {"parent_room_id" => room.as_str()}).get("not_joined"));
    assert_eq!(
        unjoined,
        vec![thread.clone()],
        "threads of the private room"
    );
    // Adding a member again changes nothing.
    a.result(
        "room_join",
        "again",
        obj! {"room_id" => room.as_str(), "user_id" => "guest_2"},
    );
    b.expect_quiet();
    // Its threads are for its members: someone outside it cannot be added
    // to one.
    a.expect_error(
        "room_join",
        "outsider",
        obj! {"room_id" => thread.as_str(), "user_id" => "guest_3"},
        CODE_DENIED,
    );
    join_room(&mut b, &thread);
    expect_membership(&a, &thread, "guest_2", true);
    let (other, _) = save_room(
        &mut a,
        "other-thread",
        obj! {"parent_room_id" => room.as_str(), "title" => "Other", "private" => false},
    );
    let update = room_updated(&b, "updated");
    assert_eq!(
        update.get("room_id"),
        Some(&Json::from(other.as_str())),
        "new thread for a member of its private room: {update:?}"
    );

    // A message may not move into or out of a private room, nor between
    // it and its threads, as on Cloudflare.
    let (public, _) = save(
        &mut a,
        "public",
        obj! {"body" => obj! {"text" => "in general"}},
    );
    b.notification("message");
    c.notification("message");
    for (id, message_id, room_id) in [
        ("into-private", &public, &room),
        ("into-thread", &secret, &thread),
        ("into-aside", &secret, &aside),
    ] {
        let frame = a.call(
            "message",
            id,
            obj! {"message_id" => message_id.as_str(), "room_id" => room_id.as_str(), "body" => obj! {"text" => "moved"}},
        );
        assert_eq!(
            frame.get("error"),
            Some(&Json::from(obj! {
                "code" => CODE_DENIED,
                "message" => "Messages cannot be moved into or out of a private room",
            })),
            "{id}: {frame:?}"
        );
    }
    // private is fixed at creation.
    let (_, edited) = save_room(
        &mut b,
        "edit",
        obj! {"room_id" => room.as_str(), "title" => "DM", "private" => false},
    );
    assert_eq!(
        edited.get("private"),
        Some(&Json::from(true)),
        "private changed on edit: {edited:?}"
    );
    room_updated(&a, "updated");

    // Removing someone else is for the room's creator and moderators.
    b.expect_error(
        "room_leave",
        "remove-creator",
        obj! {"room_id" => room.as_str(), "user_id" => "guest_1"},
        CODE_DENIED,
    );
    let (before, result) = a.request(
        "room_leave",
        "remove",
        obj! {"room_id" => room.as_str(), "user_id" => "guest_2"},
    );
    assert!(
        result.is_empty() && methods(&before) == vec!["room_update", "room_update"],
        "removing a member: {before:?} then {result:?}"
    );
    // Losing the private room loses its threads: the removed member leaves
    // the one they joined, and is told of it.
    check_membership(&membership_only(&before[1]), &thread, "guest_2", false);
    expect_left(&b, &room, "guest_2");
    expect_left(&b, &thread, "guest_2");
    let left = room_updated(&b, "left");
    assert_eq!(
        left,
        obj! {"room_id" => other.as_str()},
        "removed member's update for a thread they had not joined"
    );
    for room_id in [&room, &thread] {
        let id = b.next_id("after-removal");
        b.expect_error(
            "history",
            &id,
            obj! {"room_id" => room_id.as_str()},
            CODE_INVALID_PARAMS,
        );
    }
    save(
        &mut a,
        "after",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "without b"}},
    );
    b.expect_quiet();
    // Removing someone not in the room changes nothing.
    a.result(
        "room_leave",
        "remove-again",
        obj! {"room_id" => room.as_str(), "user_id" => "guest_2"},
    );
    for client in [&mut a, &mut b, &mut c] {
        client.expect_quiet();
    }
}

/// A room with more members than max_listed_members lists its most recently
/// active members and member_count, the total (§4.2.1).
#[test]
fn test_member_lists_are_truncated_with_member_count() {
    let mut config = default_config();
    config.max_listed_members = 2;
    let server = new_test_server(config);
    let mut clients = dial_group(&server, 3);
    // guest_1 posts last, so guest_1 and guest_3, who joined last, are the
    // most recently active.
    save(
        &mut clients[0],
        "post",
        obj! {"body" => obj! {"text" => "hi"}},
    );
    for other in &clients[1..] {
        other.notification("message");
    }
    let listed = list_rooms(
        &mut clients[1],
        obj! {"room_id" => "general", "members" => true},
    );
    let mut entry = listed["not_joined"].as_list();
    if entry.is_empty() {
        entry = listed["joined"].as_list();
    }
    let general = entry[0].as_object().unwrap();
    assert!(
        general.get("member_count") == Some(&Json::from(3i64))
            && member_ids(general) == ids(&["guest_1", "guest_3"])
            && listed["users"].as_list().len() == 2,
        "truncated listing: {listed:?}"
    );
    // user_id lists only that member, also one the truncated listing leaves
    // out, and no one for a user who isn't a member.
    for (id, want) in [("guest_2", vec!["guest_2"]), ("nobody", vec![])] {
        let one = list_rooms(
            &mut clients[1],
            obj! {"room_id" => "general", "members" => true, "user_id" => id},
        );
        let mut rooms = one["not_joined"].as_list();
        if rooms.is_empty() {
            rooms = one["joined"].as_list();
        }
        let room = rooms[0].as_object().unwrap();
        assert!(
            !room.contains_key("member_count")
                && member_ids(room) == want
                && one["users"].as_list().len() == want.len(),
            "listing of {id}: {one:?}"
        );
    }
    // 0 lists every member.
    let mut unlimited = default_config();
    unlimited.max_listed_members = 0;
    let other = new_test_server(unlimited);
    let mut everyone = dial_group(&other, 3);
    let all = nth(
        &list_rooms(
            &mut everyone[0],
            obj! {"room_id" => "general", "members" => true},
        ),
        "joined",
        0,
    );
    assert!(
        !all.contains_key("member_count") && member_ids(&all).len() == 3,
        "unlimited listing: {all:?}"
    );
    // A room within the bound carries no member_count.
    grant_role(&server, &clients[0].user_id, "mod");
    let (ops, _) = save_room(&mut clients[0], "ops", obj! {"title" => "Ops"});
    let ops_entry = nth(
        &list_rooms(
            &mut clients[0],
            obj! {"room_id" => ops.as_str(), "members" => true},
        ),
        "joined",
        0,
    );
    assert!(
        !ops_entry.contains_key("member_count"),
        "untruncated listing: {ops_entry:?}"
    );
}

/// Leaving a private room sends room_update left once for each thread the
/// user could see there, and nothing about private threads they were never
/// in, whose room_ids stay unknown to them.
#[test]
fn test_leaving_a_private_room_hides_only_what_was_visible() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));
    let (room, _) = save_room(&mut a, "room", obj! {"title" => "P", "private" => true});
    a.request(
        "room_join",
        "add",
        obj! {"room_id" => room.as_str(), "user_id" => b.user_id.as_str()},
    );
    b.drain();
    let (public, _) = save_room(
        &mut a,
        "public",
        obj! {"parent_room_id" => room.as_str(), "title" => "Public", "private" => false},
    );
    let (aside, _) = save_room(
        &mut a,
        "aside",
        obj! {"parent_room_id" => room.as_str(), "title" => "Aside", "private" => true},
    );
    let (shared, _) = save_room(
        &mut a,
        "shared",
        obj! {"parent_room_id" => room.as_str(), "title" => "Shared", "private" => true},
    );
    a.request(
        "room_join",
        "add-shared",
        obj! {"room_id" => shared.as_str(), "user_id" => b.user_id.as_str()},
    );
    b.drain();
    a.drain();

    let (before, _) = b.request("room_leave", "leave", obj! {"room_id" => room.as_str()});
    let mut left: Vec<String> = before
        .iter()
        .filter(|frame| frame.get("method") == Some(&Json::from("room_update")))
        .flat_map(|frame| {
            frame["params"].as_object().unwrap()["left"]
                .as_list()
                .iter()
                .map(|entry| {
                    entry.as_object().unwrap()["room_id"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect::<Vec<_>>()
        })
        .collect();
    left.sort();
    let mut want = vec![room, public, shared];
    want.sort();
    assert_eq!(left, want, "left (not {aside})");
}

/// A message cannot move out of a private room, even its author's own, and
/// a reply cannot quote a message that some who see the reply cannot see.
#[test]
fn test_moves_and_replies_out_of_private_rooms() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));
    let (room, _) = save_room(&mut a, "room", obj! {"title" => "P", "private" => true});
    let (id, _) = save(
        &mut a,
        "secret",
        obj! {"room_id" => room.as_str(), "body" => obj! {"text" => "still private"}},
    );
    a.expect_error(
        "message",
        "reply",
        obj! {"body" => obj! {"text" => "re"}, "reply_to" => obj! {"message_id" => id.as_str()}},
        CODE_DENIED,
    );
    let frame = a.call(
        "message",
        "move",
        obj! {"message_id" => id.as_str(), "room_id" => "general", "body" => obj! {"text" => "still private"}},
    );
    assert_eq!(
        frame.get("error"),
        Some(&Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "Messages cannot be moved into or out of a private room",
        })),
        "move out of a private room: {frame:?}"
    );
    b.expect_quiet();
    // Nor may a moderator in the room move it out.
    grant_role(&server, &b.user_id, "mod");
    a.request(
        "room_join",
        "add",
        obj! {"room_id" => room.as_str(), "user_id" => b.user_id.as_str()},
    );
    b.drain();
    let frame = b.call(
        "message",
        "moderate",
        obj! {"message_id" => id.as_str(), "room_id" => "general", "body" => obj! {"text" => "still private"}},
    );
    assert_eq!(
        frame.get("error"),
        Some(&Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "Messages cannot be moved into or out of a private room",
        })),
        "moderator's move out of a private room: {frame:?}"
    );
    // Within the same audience a reply may quote it.
    save(
        &mut a,
        "inner",
        obj! {"room_id" => room.as_str(), "body" => obj! {"text" => "inner"}},
    );
    let (inner, _) = save(
        &mut a,
        "inner-2",
        obj! {"room_id" => room.as_str(), "body" => obj! {"text" => "inner"}},
    );
    save(
        &mut a,
        "quote",
        obj! {"room_id" => room.as_str(), "body" => obj! {"text" => "re"}, "reply_to" => obj! {"message_id" => inner.as_str()}},
    );
}

/// The denial of a room_set, its message.
fn denial(c: &mut TestClient, id: &str, params: Object) -> Json {
    let frame = c.call("room_set", id, params);
    let error = frame["error"].as_object().expect("error");
    assert_eq!(error["code"], Json::from(CODE_DENIED), "{frame:?}");
    error["message"].clone()
}

/// An account may have started at most 5 private rooms still live, as on
/// Cloudflare, even after leaving them to others; one stops counting when
/// everyone has left it.
#[test]
fn test_private_rooms_started_per_user_bound() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));
    let mut started = Vec::new();
    for i in 0..5 {
        let (room, _) = save_room(&mut a, &format!("p{i}"), obj! {"private" => true});
        a.request(
            "room_join",
            &format!("add{i}"),
            obj! {"room_id" => room.as_str(), "user_id" => b.user_id.as_str()},
        );
        leave_room(&mut a, &room);
        started.push(room);
    }
    a.drain();
    b.drain();
    assert_eq!(
        denial(&mut a, "sixth", obj! {"private" => true}),
        Json::from("You can have started at most 5 private rooms at once; one stops counting when everyone has left it or its history expires")
    );
    leave_room(&mut b, &started[0]);
    a.drain();
    save_room(&mut a, "again", obj! {"private" => true});
}

/// The server holds at most 100 private rooms, as Cloudflare's demo does.
#[test]
fn test_private_rooms_server_bound() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 21);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let mut last = clients.pop().unwrap();
    for (n, c) in clients.iter_mut().enumerate() {
        for i in 0..5 {
            save_room(c, &format!("p{n}-{i}"), obj! {"private" => true});
        }
    }
    last.drain();
    assert_eq!(
        denial(&mut last, "full", obj! {"private" => true}),
        Json::from("The server holds as many private rooms as it can; one frees up when everyone has left it or its history expires")
    );
}
