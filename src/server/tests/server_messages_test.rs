//! The message, room, and thread tests of server_test.go, test by test.
//! Each keeps the Go test's name, tables, and literal expectations.

use super::helpers::*;
use super::server_test::{f, sorted_keys};
use crate::obj;
use crate::server::protocol::*;
use crate::server::rooms::MAX_DESCRIPTION_BYTES;

#[test]
fn test_message_snapshots_replace_editable_state() {
    let server = new_test_server(default_config());
    let mut owner = dial_test_client(&server);
    make_account(&server, &owner.user_id);
    let observer = dial_test_client(&server);
    make_account(&server, &observer.user_id);
    expect_membership(&owner, "general", &observer.user_id, true);
    owner.result("me", "name", obj! {"name" => "Alice"});
    let renamed = observer.notification("user");
    assert_eq!(
        renamed,
        obj! {"new" => obj! {"user_id" => "guest_1", "name" => "Alice", "status" => "online", "roles" => strings(&[])}},
        "rename notification"
    );
    let ext = obj! {"irc" => obj! {"nick" => "ada_"}};
    let (id, creation) = save(
        &mut owner,
        "create",
        obj! {
            "from" => obj! {"user_id" => "forged"},
            "log_id" => "123",
            "body" => obj! {"text" => "hello", "format" => "plain", "embeds" => vec![Json::from(obj! {"kind" => "ext:file"})]},
            "ext" => ext.clone(),
            "custom" => true,
            "deleted" => false,
        },
    );
    let first = observer.notification("message");
    assert_eq!(first, creation, "observer snapshot differs");
    let want_keys = ["body", "ext", "from", "log_id", "message_id", "room_id"];
    assert!(
        creation["log_id"] == Json::from(id.as_str()) && sorted_keys(&creation) == want_keys,
        "creation snapshot: {creation:?}"
    );
    let from = creation["from"].as_object().unwrap();
    assert!(
        from["user_id"] == Json::from("guest_1")
            && from["name"] == Json::from("Alice")
            && creation["ext"] == Json::from(ext.clone()),
        "creation fields: {creation:?}"
    );

    owner.result("me", "rename", obj! {"name" => "Later"});
    observer.notification("user");
    let (stable, edit) = save(
        &mut owner,
        "edit",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => "edited"}, "from" => Json::Null},
    );
    observer.notification("message");
    assert!(
        stable == id && parse_id(edit.get("log_id")) > parse_id(Some(&Json::from(id.as_str()))),
        "edit snapshot: {edit:?}"
    );
    // A save replaces every client field but ext, which merges (§4.4): the
    // edit that leaves ext out keeps it.
    assert!(
        edit["ext"] == Json::from(ext.clone())
            && edit["body"].as_object().unwrap().len() == 1
            && edit["from"].as_object().unwrap()["name"] == Json::from("Alice"),
        "replacement merged editable fields, lost ext, or changed author: {edit:?}"
    );

    // A tombstone carries neither body nor ext (§4.4).
    let (_, deleted) = save(
        &mut owner,
        "delete",
        obj! {"message_id" => id.as_str(), "deleted" => true, "body" => "discard even invalid body", "ext" => obj! {"irc" => obj! {"nick" => "x"}}},
    );
    observer.notification("message");
    assert!(
        !deleted.contains_key("body")
            && !deleted.contains_key("ext")
            && deleted["deleted"] == Json::from(true),
        "tombstone: {deleted:?}"
    );

    let page = history_page(&mut owner, "general", obj! {"after" => "0"});
    let entries = records(&page, "messages");
    assert_eq!(entries.len(), 3, "history: {page:?}");
    // Deletion redacts earlier snapshots into tombstones at their log_ids.
    let redacted = |snapshot: &Object| {
        let mut value = snapshot.clone();
        value.remove("body");
        value.remove("ext");
        value.insert("deleted".into(), true.into());
        value
    };
    for (i, expected) in [redacted(&creation), redacted(&edit), deleted]
        .iter()
        .enumerate()
    {
        assert_eq!(&entries[i], expected, "history entry {i}");
    }
    let mut observer = observer;
    observer.expect_error("message", "forged", obj! {"room_id" => "general", "message_id" => id.as_str(), "body" => obj! {"text" => "forged"}}, CODE_DENIED);
}

#[test]
fn test_log_ids_form_one_sequence_across_rooms_and_kinds() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let listed = list_rooms(&mut c, obj! {"room_id" => "general"});
    let mut last = parse_id(
        listed["joined"].as_list()[0]
            .as_object()
            .unwrap()
            .get("log_id"),
    );
    let mut check = |label: &str, value: Option<&Json>| {
        let id = parse_id(value);
        assert!(id > last, "{label} log_id {id} does not follow {last}");
        last = id;
    };
    let (id, message) = save(&mut c, "m1", obj! {"body" => obj! {"text" => "a"}});
    check("message", message.get("log_id"));
    grant_role(&server, &c.user_id, "mod");
    let (room, record) = save_room(&mut c, "r1", obj! {"title" => "Ops"});
    check("room", record.get("log_id"));
    assert_eq!(
        Json::from(room.as_str()),
        record["log_id"],
        "room_id should be its creation log_id"
    );
    check("reactions", react(&mut c, "x1", &id, &["👍"]).get("log_id"));
    let (_, other) = save(
        &mut c,
        "m2",
        obj! {"room_id" => room.as_str(), "body" => obj! {"text" => "b"}},
    );
    check("message in other room", other.get("log_id"));
}

#[test]
fn test_replies_may_cross_rooms() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let body = obj! {"text" => "hello"};
    let (root, _) = save(&mut c, "root", obj! {"body" => body.clone()});
    grant_role(&server, &c.user_id, "mod");
    let (ops, _) = save_room(&mut c, "ops", obj! {"title" => "Ops"});

    let (reply, created) = save(
        &mut c,
        "reply",
        obj! {"room_id" => ops.as_str(), "body" => body.clone(), "reply_to" => obj! {"message_id" => root.as_str()}},
    );
    assert_eq!(
        created["reply_to"],
        Json::from(obj! {"message_id" => root.as_str()}),
        "cross-room reply_to"
    );
    // A client may pass back a snapshot; only its message_id is used.
    let (_, echoed) = save(
        &mut c,
        "reply-snapshot",
        obj! {"body" => body.clone(), "reply_to" => obj! {"message_id" => reply.as_str(), "room_id" => ops.as_str(), "body" => body.clone()}},
    );
    assert_eq!(
        echoed["reply_to"],
        Json::from(obj! {"message_id" => reply.as_str()}),
        "reply_to not bare"
    );

    let before = history_page(&mut c, "general", Object::new());
    for (i, mut params) in [
        obj! {"reply_to" => Json::Null},
        obj! {"reply_to" => f(123)},
        obj! {"reply_to" => root.as_str()},
        obj! {"reply_to" => Object::new()},
        obj! {"reply_to" => obj! {"message_id" => ""}},
        obj! {"reply_to" => obj! {"message_id" => "0"}},
        obj! {"reply_to" => obj! {"message_id" => "bad"}},
        obj! {"reply_to" => obj! {"message_id" => "999"}},
        obj! {"message_id" => root.as_str(), "reply_to" => obj! {"message_id" => root.as_str()}},
        obj! {"reply_to" => obj! {"message_id" => root.as_str()}, "room_id" => "missing-room"},
    ]
    .into_iter()
    .enumerate()
    {
        if !params.contains_key("room_id") {
            params.insert("room_id".into(), "general".into());
        }
        params.insert("body".into(), body.clone().into());
        c.expect_error(
            "message",
            &format!("bad-reply-{i}"),
            params,
            CODE_INVALID_PARAMS,
        );
    }
    let after = history_page(&mut c, "general", Object::new());
    assert_eq!(
        before["last_log_id"], after["last_log_id"],
        "rejected reply changed history"
    );

    // Replies to tombstones remain valid, and omitting reply_to on a save
    // removes it.
    save(
        &mut c,
        "delete-root",
        obj! {"message_id" => root.as_str(), "deleted" => true},
    );
    save(
        &mut c,
        "reply-to-tombstone",
        obj! {"body" => body.clone(), "reply_to" => obj! {"message_id" => root.as_str()}},
    );
    let (_, removed) = save(
        &mut c,
        "remove-reply",
        obj! {"message_id" => reply.as_str(), "room_id" => ops.as_str(), "body" => body},
    );
    assert!(
        !removed.contains_key("reply_to"),
        "omitted reply_to was retained"
    );
}

#[test]
fn test_room_set_creates_and_edits_rooms_and_threads() {
    let server = new_test_server(large_frames_config());
    let mut clients = dial_group(&server, 2);
    let mut observer = clients.remove(1);
    let mut c = clients.remove(0);
    let description = "Deploy status\n*second* line";

    // A new thread joins its creator, logging the creator's membership; the
    // parent's other members learn of it as updated, without joining. A
    // thread without a title gets one from its description.
    let (thread, record) = save_room(
        &mut c,
        "thread",
        obj! {"parent_room_id" => "general", "description" => description},
    );
    assert_eq!(
        room_updated(&observer, "updated"),
        record,
        "observer room differs"
    );
    let want = obj! {
        "room_id" => thread.as_str(), "log_id" => thread.as_str(), "parent_room_id" => "general", "title" => "Deploy status",
        "description" => description, "latest_log_id" => record["latest_log_id"].clone(), "history_log_id" => thread.as_str(),
    };
    assert_eq!(record, want, "thread record");
    let (_, untitled) = save_room(&mut c, "untitled", obj! {"parent_room_id" => "general"});
    assert!(
        untitled["title"] == Json::from("Thread"),
        "untitled thread: {untitled:?}"
    );
    room_updated(&observer, "updated");

    // Edits replace every client field except parent_room_id, and reach the
    // room's members and, for a thread, the parent's.
    let ext = obj! {"app" => obj! {"pinned" => true}};
    let (same_id, updated) = save_room(
        &mut c,
        "update",
        obj! {"room_id" => thread.as_str(), "parent_room_id" => "ignored", "title" => "Renamed", "ext" => ext.clone()},
    );
    assert_eq!(
        room_updated(&observer, "updated"),
        updated,
        "observer update differs"
    );
    assert!(
        same_id == thread
            && updated["parent_room_id"] == Json::from("general")
            && updated["title"] == Json::from("Renamed")
            && updated["ext"] == Json::from(ext),
        "thread update: {updated:?}"
    );
    assert!(
        !updated.contains_key("description")
            && updated["history_log_id"] == Json::from(thread.as_str())
            && updated["latest_log_id"] == updated["log_id"],
        "thread update fields: {updated:?}"
    );
    // A new top-level room joins only its creator.
    grant_role(&server, &observer.user_id, "mod");
    let (top, top_record) = save_room(&mut observer, "top", obj! {"title" => "Ops"});
    c.expect_quiet();
    assert!(
        !top_record.contains_key("parent_room_id") && top_record["title"] == Json::from("Ops"),
        "top-level room: {top_record:?}"
    );
    let (_, cleared) = save_room(&mut observer, "clear", obj! {"room_id" => top.as_str()});
    assert_eq!(
        cleared["title"],
        Json::from("Room"),
        "an omitted title on a top-level room is the default"
    );
    // An editor who has not joined the room still receives the update.
    grant_role(&server, &c.user_id, "mod");
    let (_, renamed) = save_room(
        &mut c,
        "rename-top",
        obj! {"room_id" => top.as_str(), "title" => "Ops 2"},
    );
    assert_eq!(
        room_updated(&observer, "updated"),
        renamed,
        "member's update differs"
    );

    // Room records and memberships are part of the room's own log.
    let page = history_page(&mut c, &thread, Object::new());
    assert_eq!(
        log_ids(&page, "rooms"),
        vec![
            thread.clone(),
            updated["log_id"].as_str().unwrap().to_owned()
        ],
        "thread room records: {page:?}"
    );
    assert_eq!(
        log_ids(&page, "memberships"),
        vec![record["latest_log_id"].as_str().unwrap().to_owned()],
        "thread memberships: {page:?}"
    );
    assert!(
        !page.contains_key("messages")
            && page["history_log_id"] == Json::from(thread.as_str())
            && page["latest_log_id"] == updated["log_id"],
        "thread history: {page:?}"
    );
    let general = history_page(&mut c, "general", Object::new());
    assert!(
        records(&general, "rooms").len() == 1 && records(&general, "memberships").len() == 2,
        "thread records leaked into the parent log: {general:?}"
    );

    for (i, params) in [
        obj! {"room_id" => "missing", "title" => "x"},
        obj! {"room_id" => Json::Null},
        obj! {"parent_room_id" => "missing"},
        obj! {"parent_room_id" => ""},
        obj! {"parent_room_id" => f(12)},
        obj! {"title" => f(12)},
        obj! {"title" => Json::Null},
        obj! {"description" => f(12)},
        obj! {"description" => Json::Null},
        obj! {"ext" => Json::Array(vec![])},
        obj! {"ext" => Json::Null},
    ]
    .into_iter()
    .enumerate()
    {
        c.expect_error(
            "room_set",
            &format!("bad-room-{i}"),
            params,
            CODE_INVALID_PARAMS,
        );
    }
    // A value rejected for its size is too_large (§1.1).
    c.expect_error(
        "room_set",
        "long-description",
        obj! {"description" => "x".repeat(MAX_DESCRIPTION_BYTES + 1)},
        CODE_TOO_LARGE,
    );
    c.expect_quiet();
    observer.expect_quiet();

    // A description is set with room_set like any client field, such as by
    // a bot keeping a thread's summary current, and listed rooms carry it.
    let summary = "Root cause: **expired cert**.";
    let (_, described) = save_room(
        &mut c,
        "describe",
        obj! {"room_id" => thread.as_str(), "title" => "Renamed", "description" => summary},
    );
    let observed = room_updated(&observer, "updated");
    assert!(
        observed == described && described["description"] == Json::from(summary),
        "description update {described:?}, observed {observed:?}"
    );
    let listed = list_rooms(&mut observer, obj! {"room_id" => thread.as_str()});
    assert!(
        listed.contains_key("joined") && listed["joined"].as_list().is_empty(),
        "observer has not joined the thread: {listed:?}"
    );
    let entry = listed["not_joined"].as_list()[0].as_object().unwrap();
    assert!(
        entry["description"] == Json::from(summary) && entry["title"] == Json::from("Renamed"),
        "listed room: {entry:?}"
    );
}

/// A thread's description is independent of any message: deleting the
/// message a thread was started from changes none of its room records.
#[test]
fn test_deleting_a_threads_first_message_keeps_its_record() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let mut b = clients.remove(1);
    let mut a = clients.remove(0);
    let (id, _) = save(
        &mut a,
        "root",
        obj! {"body" => obj! {"text" => "Secret line\nmore"}},
    );
    b.notification("message");
    let (thread, record) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => "general", "description" => "Why the deploy failed"},
    );
    room_updated(&b, "updated");
    assert_eq!(
        record["title"],
        Json::from("Why the deploy failed"),
        "derived title: {record:?}"
    );
    let (before, _) = a.request(
        "message",
        "delete",
        obj! {"room_id" => "general", "message_id" => id.as_str(), "deleted" => true},
    );
    assert_eq!(
        methods(&before),
        vec!["message"],
        "frames before the delete result"
    );
    b.notification("message");
    let rooms = records(&history_page(&mut b, &thread, Object::new()), "rooms");
    assert!(
        rooms.len() == 1 && rooms[0]["description"] == Json::from("Why the deploy failed"),
        "thread room records: {rooms:?}"
    );
}

#[test]
fn test_move_appears_in_both_rooms_and_carries_reactions() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let mut reactor = clients.remove(1);
    let mut author = clients.remove(0);
    let body = obj! {"text" => "move me"};
    let (id, created) = save(&mut author, "create", obj! {"body" => body.clone()});
    reactor.notification("message");
    let (thread, _) = save_room(
        &mut author,
        "thread",
        obj! {"parent_room_id" => "general", "description" => "move me"},
    );
    room_updated(&reactor, "updated");
    join_room(&mut reactor, &thread);
    expect_membership(&author, &thread, &reactor.user_id, true);
    let first = react(&mut author, "react-a", &id, &["👍"]);
    reactor.notification("reactions");
    react(&mut reactor, "react-b", &id, &["🎉", "👍"]);
    author.notification("reactions");
    react(&mut reactor, "react-b-clear", &id, &[]);
    author.notification("reactions");
    react(&mut reactor, "react-b-again", &id, &["🚀"]);
    author.notification("reactions");

    reactor.expect_error(
        "message",
        "not-owner",
        obj! {"message_id" => id.as_str(), "room_id" => thread.as_str(), "body" => body.clone()},
        CODE_DENIED,
    );
    author.expect_error(
        "message",
        "missing-room",
        obj! {"message_id" => id.as_str(), "room_id" => "missing", "body" => body.clone()},
        CODE_INVALID_PARAMS,
    );

    // The move snapshot and the reactions record it carries both precede
    // the result (§1).
    let (before, result) = author.request(
        "message",
        "move",
        obj! {"message_id" => id.as_str(), "room_id" => thread.as_str(), "body" => body.clone()},
    );
    assert!(
        methods(&before) == vec!["message", "reactions"]
            && result["message_id"] == Json::from(id.as_str()),
        "move frames: {before:?} then {result:?}"
    );
    let moved = notification_params(&before[0], "message");
    let carried = notification_params(&before[1], "reactions");
    // The move snapshot names the room holding its previous snapshot.
    assert!(
        moved["room_id"] == Json::from(thread.as_str())
            && moved["prev_log_id"] == Json::from(id.as_str())
            && moved["prev_room_id"] == Json::from("general"),
        "move snapshot: {moved:?}"
    );
    assert_eq!(
        reactor.notification("message"),
        moved,
        "move broadcast differs"
    );
    assert_eq!(
        reactor.notification("reactions"),
        carried,
        "carried reactions broadcast differs"
    );
    assert!(
        carried["room_id"] == Json::from(thread.as_str())
            && carried["message_id"] == Json::from(id.as_str())
            && parse_id(carried.get("log_id")) > parse_id(moved.get("log_id")),
        "carried reactions record: {carried:?}"
    );
    let want_sets = Json::Array(vec![
        obj! {"from" => obj! {"user_id" => "guest_1", "name" => "Guest 1"}, "emojis" => strings(&["👍"])}.into(),
        obj! {"from" => obj! {"user_id" => "guest_2", "name" => "Guest 2"}, "emojis" => strings(&["🚀"])}.into(),
    ]);
    assert_eq!(carried["reactions"], want_sets, "carried sets");

    let general = history_page(&mut author, "general", Object::new());
    assert_eq!(
        log_ids(&general, "messages"),
        vec![id.clone(), moved["log_id"].as_str().unwrap().to_owned()],
        "source history entries"
    );
    let got = log_ids(&general, "reactions");
    assert!(
        got.len() == 4 && got[0] == first["log_id"].as_str().unwrap(),
        "source history keeps earlier reaction records: {got:?}"
    );
    assert_eq!(
        general["latest_log_id"], moved["log_id"],
        "source latest_log_id"
    );
    let thread_page = history_page(&mut author, &thread, Object::new());
    assert_eq!(
        log_ids(&thread_page, "messages"),
        vec![moved["log_id"].as_str().unwrap().to_owned()],
        "destination history entries"
    );
    assert_eq!(
        log_ids(&thread_page, "reactions"),
        vec![carried["log_id"].as_str().unwrap().to_owned()],
        "destination history reactions"
    );
    assert!(
        thread_page["latest_log_id"] == carried["log_id"]
            && thread_page["history_log_id"] == Json::from(thread.as_str()),
        "destination bounds: {thread_page:?}"
    );
    assert_eq!(
        general["messages"].as_list()[0],
        Json::from(created),
        "earlier snapshot changed"
    );

    // Later reactions are logged in the message's current room; edits in
    // place stay in one room.
    let later = react(&mut author, "react-later", &id, &["✅"]);
    assert_eq!(
        later["room_id"],
        Json::from(thread.as_str()),
        "reaction after move"
    );
    let (_, edited) = save(
        &mut author,
        "edit-in-thread",
        obj! {"message_id" => id.as_str(), "room_id" => thread.as_str(), "body" => obj! {"text" => "edited"}},
    );
    assert!(
        !edited.contains_key("prev_room_id") && edited["prev_log_id"] == moved["log_id"],
        "edit after a move: {edited:?}"
    );
    let after = history_page(&mut author, "general", Object::new());
    assert_eq!(
        after["latest_log_id"], moved["log_id"],
        "in-place edit leaked into source room"
    );

    // A move without reactions logs no reactions record.
    let (plain, _) = save(&mut author, "plain", obj! {"body" => body.clone()});
    save(
        &mut author,
        "plain-move",
        obj! {"message_id" => plain.as_str(), "room_id" => thread.as_str(), "body" => body},
    );
    author.expect_quiet();
}

#[test]
fn test_invalid_saves_leave_state_unchanged() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let (id, _) = save(&mut c, "create", obj! {"body" => obj! {"text" => "hello"}});
    for (i, mut params) in [
        obj! {"body" => Object::new(), "deleted" => true},
        obj! {"message_id" => "999", "body" => Object::new()},
        obj! {"message_id" => Json::Null, "body" => Object::new()},
        obj! {"message_id" => id.as_str()},
        obj! {"message_id" => id.as_str(), "body" => Json::Null},
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => Json::Null}},
        obj! {"message_id" => id.as_str(), "body" => obj! {"format" => "html"}},
        obj! {"message_id" => id.as_str(), "body" => obj! {"embeds" => Json::Null}},
        obj! {"message_id" => id.as_str(), "body" => Object::new(), "ext" => Json::Null},
        obj! {"message_id" => id.as_str(), "body" => Object::new(), "ext" => "text"},
        obj! {"body" => Object::new(), "deleted" => Json::Null},
        obj! {"body" => Object::new(), "room_id" => Json::Null},
        obj! {"body" => Object::new(), "room_id" => "missing"},
        obj! {"body" => obj! {"text" => "x", "mentions" => "guest_1"}},
        obj! {"body" => obj! {"text" => "x", "mentions" => Json::Array(vec![f(7)])}},
        obj! {"body" => obj! {"text" => "x", "mentions" => strings(&[""])}},
        // A user_id has no whitespace or control characters (§2.4).
        obj! {"body" => obj! {"text" => "x", "mentions" => strings(&["guest 1"])}},
        obj! {"body" => obj! {"text" => "x", "mentions" => strings(&["guest_1\n"])}},
    ]
    .into_iter()
    .enumerate()
    {
        if !params.contains_key("room_id") {
            params.insert("room_id".into(), "general".into());
        }
        c.expect_error("message", &format!("bad-{i}"), params, CODE_INVALID_PARAMS);
    }
    c.expect_quiet();
    let page = history_page(&mut c, "general", Object::new());
    assert!(
        records(&page, "messages").len() == 1 && page["latest_log_id"] == Json::from(id.as_str()),
        "invalid operations appended history: {page:?}"
    );
}

/// A message without room_id goes to the default room; a new message with
/// no text and no embeds is neither logged nor broadcast.
#[test]
fn test_default_room_and_empty_messages() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let (before, result) = c.request("message", "default", obj! {"body" => obj! {"text" => "hi"}});
    let snapshot = notification_params(&before[0], "message");
    assert!(
        before.len() == 1
            && snapshot["room_id"] == Json::from("general")
            && snapshot["message_id"] == result["message_id"],
        "default room snapshot: {snapshot:?}"
    );
    for (i, body) in [
        Object::new(),
        obj! {"text" => ""},
        obj! {"text" => "", "embeds" => Json::Array(vec![]), "mentions" => strings(&["guest_1"])},
    ]
    .into_iter()
    .enumerate()
    {
        let result = c.result("message", &format!("empty-{i}"), obj! {"body" => body});
        assert!(result.is_empty(), "empty message result: {result:?}");
    }
    c.expect_quiet();
    let page = history_page(&mut c, "general", Object::new());
    assert_eq!(
        records(&page, "messages").len(),
        1,
        "empty messages were logged: {page:?}"
    );
    // An empty edit is an ordinary save.
    let (_, edited) = save(
        &mut c,
        "edit",
        obj! {"message_id" => result["message_id"].clone(), "body" => Object::new()},
    );
    assert_eq!(
        edited["body"],
        Json::from(Object::new()),
        "empty edit: {edited:?}"
    );
}

/// body.mentions keeps the user_ids as sent, once each, each at most 256
/// bytes (apron-server-cloudflare's "stores body.mentions as sent").
#[test]
fn test_mentions_are_user_ids() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let me = c.user_id.clone();
    let (_, plain) = save(
        &mut c,
        "plain",
        obj! {"body" => obj! {"text" => format!("@{me} hello")}},
    );
    assert!(
        !plain["body"].as_object().unwrap().contains_key("mentions"),
        "{plain:?}"
    );
    let (_, listed) = save(
        &mut c,
        "listed",
        obj! {"body" => obj! {"text" => "no at signs", "mentions" => strings(&[&me, "bob", &me])}},
    );
    assert_eq!(
        listed["body"].as_object().unwrap()["mentions"],
        strings(&[&me, "bob"])
    );
    let long = "b".repeat(257);
    let frame = reply(
        &mut c,
        "message",
        "long",
        obj! {"body" => obj! {"text" => "x", "mentions" => strings(&[&long])}},
    );
    assert_eq!(error_code(&frame), Some(CODE_TOO_LARGE), "{frame:?}");
    let (_, fits) = save(
        &mut c,
        "fits",
        obj! {"body" => obj! {"text" => "x", "mentions" => strings(&[&"b".repeat(256)])}},
    );
    assert!(fits.contains_key("body"));
}

/// A sender's `og` keeps only its title, description and site_name, each
/// one plain line within its length; media go (apron-server-cloudflare's
/// withCleanOg).
#[test]
fn test_client_og_is_kept_as_text() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let og = obj! {
        "title" => "  Release\u{7}notes\u{202e}\n",
        "description" => "d".repeat(600),
        "site_name" => 7i64,
        "image" => obj! {"url" => "https://tracker.example/pixel.png"},
    };
    let (id, snapshot) = save(
        &mut c,
        "card",
        obj! {"body" => obj! {"text" => "see", "embeds" => vec![Json::from(obj! {"kind" => "link", "url" => "https://example.com/", "og" => og})]}},
    );
    let want = obj! {"title" => "Release notes", "description" => format!("{}…", "d".repeat(511))};
    let embed = embeds_of(&snapshot)[0].clone();
    assert_eq!(embed["og"], Json::from(want.clone()), "{embed:?}");
    // An edit that resubmits it keeps it; one with nothing left drops it.
    let (_, edited) = save(
        &mut c,
        "edit",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => "see", "embeds" => vec![Json::from(embed.clone())]}},
    );
    assert_eq!(embeds_of(&edited)[0]["og"], Json::from(want));
    let mut bare = embed;
    bare.insert(
        "og".into(),
        obj! {"image" => obj! {"url" => "https://x.example/"}}.into(),
    );
    let (_, dropped) = save(
        &mut c,
        "drop",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => "see", "embeds" => vec![Json::from(bare)]}},
    );
    assert!(!embeds_of(&dropped)[0].contains_key("og"));
}

/// A public top-level room saved without a title is titled `Room`, and
/// `general` `General`; a private room goes without (apron-server-cloudflare's
/// ROOM_TITLE and DEFAULT_ROOM_TITLE).
#[test]
fn test_default_room_titles() {
    let server = super::helpers::admin_test_server();
    let mut ada = super::helpers::admin(&server);
    let (room_id, created) = save_room(&mut ada, "create", obj! {"title" => "  "});
    assert_eq!(created["title"], Json::from("Room"));
    let (_, saved) = save_room(&mut ada, "save", obj! {"room_id" => room_id.as_str()});
    assert_eq!(saved["title"], Json::from("Room"));
    let (_, general) = save_room(
        &mut ada,
        "general",
        obj! {"room_id" => "general", "title" => ""},
    );
    assert_eq!(general["title"], Json::from("General"));
    let (_, private) = save_room(&mut ada, "private", obj! {"private" => true});
    assert!(!private.contains_key("title"), "{private:?}");
}
