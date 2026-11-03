//! The history tests of server_test.go, test by test. Each keeps the Go
//! test's name, tables, and literal expectations.

use super::helpers::*;
use super::server_test::{f, sorted_keys};
use crate::obj;
use crate::server::protocol::*;

#[test]
fn test_history_paginates_across_record_kinds() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    make_account(&server, &c.user_id);
    let listed = list_rooms(&mut c, obj! {"filter" => "joined"})["joined"].as_list()[0]
        .as_object()
        .unwrap()
        .clone();
    let (general_id, join_id) = (
        listed["log_id"].as_str().unwrap().to_owned(),
        listed["latest_log_id"].as_str().unwrap().to_owned(),
    );
    let (id, message) = save(&mut c, "m1", obj! {"body" => obj! {"text" => "one"}});
    let reaction = react(&mut c, "x1", &id, &["👍"]);
    grant_role(&server, &c.user_id, "admin");
    let (_, updated) = save_room(
        &mut c,
        "r1",
        obj! {"room_id" => "general", "title" => "Lobby"},
    );
    let (_, second) = save(&mut c, "m2", obj! {"body" => obj! {"text" => "two"}});
    let s = |o: &Object| o["log_id"].as_str().unwrap().to_owned();
    let all = vec![
        general_id.clone(),
        join_id,
        s(&message),
        s(&reaction),
        s(&updated),
        s(&second),
    ];

    let full = history_page(&mut c, "general", Object::new());
    assert!(
        full["first_log_id"] == Json::from(all[0].as_str())
            && full["last_log_id"] == Json::from(all[5].as_str())
            && full["more"] == Json::from(false),
        "full page: {full:?}"
    );
    assert!(
        full["history_log_id"] == Json::from(general_id.as_str())
            && full["latest_log_id"] == Json::from(all[5].as_str()),
        "full page bounds: {full:?}"
    );
    assert!(
        log_ids(&full, "rooms") == vec![all[0].clone(), all[4].clone()]
            && log_ids(&full, "memberships") == vec![all[1].clone()]
            && log_ids(&full, "messages") == vec![all[2].clone(), all[5].clone()]
            && log_ids(&full, "reactions") == vec![all[3].clone()],
        "partitioned page: {full:?}"
    );
    let lobby = full["rooms"].as_list()[1].as_object().unwrap();
    assert!(
        lobby["title"] == Json::from("Lobby") && !lobby.contains_key("latest_log_id"),
        "logged room record carries delivery fields: {lobby:?}"
    );
    // Records keep the user objects they were logged with; without room_id,
    // history pages the log of the rooms the user joined, here only
    // general.
    c.result("me", "rename", obj! {"name" => "Ada"});
    let defaulted = c.result("history", "default", Object::new());
    assert_eq!(
        defaulted["last_log_id"],
        Json::from(all[5].as_str()),
        "default room page: {defaulted:?}"
    );
    let from = &defaulted["messages"].as_list()[0].as_object().unwrap()["from"];
    assert_eq!(
        *from,
        Json::from(obj! {"user_id" => "guest_1", "name" => "Guest 1"}),
        "logged from changed"
    );

    // Forward paging over every record kind, continuing from last_log_id + 1.
    let mut collected: Vec<String> = Vec::new();
    let mut after = "0".to_owned();
    let mut pages = 0;
    loop {
        let page = history_page(
            &mut c,
            "general",
            obj! {"after" => after.as_str(), "limit" => f(2)},
        );
        let mut ids: Vec<String> = Vec::new();
        for key in ["rooms", "memberships", "messages", "reactions"] {
            ids.extend(log_ids(&page, key));
        }
        assert!(
            !ids.is_empty()
                && ids.len() <= 2
                && page["latest_log_id"] == Json::from(all[5].as_str()),
            "forward page: {page:?}"
        );
        collected.extend(ids);
        if page["more"] == Json::from(false) {
            assert!(
                pages == 2 && page["last_log_id"] == Json::from(all[5].as_str()),
                "final forward page: {page:?}"
            );
            break;
        }
        after = (parse_id(page.get("last_log_id")) + 1).to_string();
        pages += 1;
    }
    collected.sort();
    assert_eq!(collected, all, "forward paging collected");

    // Backward paging selects the newest matches first.
    let page = history_page(&mut c, "general", obj! {"limit" => f(2)});
    assert!(
        page["first_log_id"] == Json::from(all[4].as_str())
            && page["last_log_id"] == Json::from(all[5].as_str())
            && page["more"] == Json::from(true),
        "newest page: {page:?}"
    );
    let page = history_page(
        &mut c,
        "general",
        obj! {"before" => (parse_id(page.get("first_log_id")) - 1).to_string(), "limit" => f(2)},
    );
    assert!(
        page["first_log_id"] == Json::from(all[2].as_str())
            && page["last_log_id"] == Json::from(all[3].as_str())
            && page["more"] == Json::from(true),
        "backward continuation: {page:?}"
    );
    // Inclusive bounds on both sides.
    let page = history_page(
        &mut c,
        "general",
        obj! {"after" => all[3].as_str(), "before" => all[4].as_str()},
    );
    assert!(
        page["first_log_id"] == Json::from(all[3].as_str())
            && page["last_log_id"] == Json::from(all[4].as_str())
            && page["more"] == Json::from(false),
        "inclusive window: {page:?}"
    );
    // Empty arrays are omitted.
    let page = history_page(
        &mut c,
        "general",
        obj! {"after" => all[2].as_str(), "before" => all[2].as_str()},
    );
    assert_eq!(
        sorted_keys(&page),
        [
            "first_log_id",
            "history_log_id",
            "last_log_id",
            "latest_log_id",
            "messages",
            "more"
        ],
        "one-message page: {page:?}"
    );
    // An empty window has no arrays and neither bound, but keeps the room's
    // latest_log_id and history_log_id.
    let empty = history_page(
        &mut c,
        "general",
        obj! {"after" => (parse_id(Some(&Json::from(all[5].as_str()))) + 1).to_string()},
    );
    let want = obj! {"more" => false, "latest_log_id" => all[5].as_str(), "history_log_id" => general_id.as_str()};
    assert_eq!(empty, want, "empty page");
    // Invalid parameters are rejected.
    for (i, params) in [
        obj! {"room_id" => "missing"},
        obj! {"room_id" => "general", "limit" => f(0)},
        obj! {"room_id" => "general", "after" => f(5)},
        obj! {"room_id" => "general", "before" => "-1"},
    ]
    .into_iter()
    .enumerate()
    {
        c.expect_error("history", &format!("bad-{i}"), params, CODE_INVALID_PARAMS);
    }
}

/// A window bounded to one log_id returns exactly that record, so a client
/// walks prev_log_id back through a message's edits. A move snapshot names
/// the source room in prev_room_id, whose log holds the earlier snapshots.
#[test]
fn test_history_single_record_walks_prev_log_id() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let (id, created) = save(&mut c, "create", obj! {"body" => obj! {"text" => "one"}});
    let (_, edited) = save(
        &mut c,
        "edit",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => "two"}},
    );
    save(
        &mut c,
        "other",
        obj! {"body" => obj! {"text" => "unrelated"}},
    );
    let (thread, _) = save_room(
        &mut c,
        "thread",
        obj! {"parent_room_id" => "general", "title" => "Moved"},
    );
    let (_, moved) = save(
        &mut c,
        "move",
        obj! {"message_id" => id.as_str(), "room_id" => thread.as_str(), "body" => obj! {"text" => "three"}},
    );
    let (_, latest) = save(
        &mut c,
        "edit-again",
        obj! {"message_id" => id.as_str(), "room_id" => thread.as_str(), "body" => obj! {"text" => "four"}},
    );

    let mut walked: Vec<Object> = Vec::new();
    let mut rooms: Vec<String> = Vec::new();
    let mut record = latest.clone();
    loop {
        walked.push(record.clone());
        let Some(prev) = record
            .get("prev_log_id")
            .and_then(Json::as_str)
            .map(str::to_owned)
        else {
            break;
        };
        let mut room = record["room_id"].as_str().unwrap().to_owned();
        if let Some(previous) = record.get("prev_room_id").and_then(Json::as_str) {
            room = previous.to_owned();
        }
        rooms.push(room.clone());
        let page = history_page(
            &mut c,
            &room,
            obj! {"after" => prev.as_str(), "before" => prev.as_str()},
        );
        let entries = records(&page, "messages");
        assert!(
            entries.len() == 1
                && page["first_log_id"] == Json::from(prev.as_str())
                && page["last_log_id"] == Json::from(prev.as_str())
                && page["more"] == Json::from(false),
            "single-record page for {prev} in {room}: {page:?}"
        );
        record = entries[0].clone();
    }
    assert!(
        walked == vec![latest, moved, edited.clone(), created]
            && rooms == vec![thread.clone(), "general".to_owned(), "general".to_owned()],
        "walked {walked:?} through {rooms:?}"
    );
    // The destination's log does not hold the earlier snapshots.
    let page = history_page(
        &mut c,
        &thread,
        obj! {"after" => edited["log_id"].clone(), "before" => edited["log_id"].clone()},
    );
    assert!(
        !page.contains_key("messages") && !page.contains_key("first_log_id"),
        "earlier snapshot in the destination: {page:?}"
    );
}

/// A guest pages back `guest_history_depth` records from each room's
/// newest, and no further; the newest page, `before` the head, a window
/// bounded by both and catching up with `after` stay open (Cloudflare's
/// "lets a guest page back guestHistoryDepth records from each room's
/// head, and no further").
#[test]
fn test_guest_history_depth() {
    let mut config = default_config();
    config.limits.guest_history_depth = 4;
    let server = new_test_server(config);
    let mut ada = dial_test_client(&server);
    make_account(&server, &ada.user_id);
    let (thread, _) = save_room(
        &mut ada,
        "thread",
        obj! {"parent_room_id" => "general", "title" => "Look around"},
    );
    let mut guest = dial_test_client(&server);
    ada.drain();
    let logs: Vec<String> = (0..8)
        .map(|i| {
            let (_, m) = save(
                &mut ada,
                &format!("m{i}"),
                obj! {"body" => obj! {"text" => format!("entry-{i}")}},
            );
            m["log_id"].as_str().unwrap().to_owned()
        })
        .collect();
    save(
        &mut ada,
        "in-thread",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "in the thread"}},
    );
    guest.drain();
    let page = |c: &mut TestClient, room: &str, mut params: Object| {
        params.insert("room_id".into(), room.into());
        params.insert("limit".into(), 2i64.into());
        let id = c.next_id("history");
        c.call("history", &id, params)
    };
    let messages = |frame: &Object| log_ids(frame["result"].as_object().unwrap(), "messages");

    // The newest page, as a client without a checkpoint asks for it, and
    // one from a head captured a little earlier.
    let newest = page(&mut guest, "general", obj! {"before" => logs[7].as_str()});
    assert_eq!(messages(&newest), logs[6..8].to_vec());
    let earlier = page(&mut guest, "general", obj! {"before" => logs[6].as_str()});
    assert_eq!(messages(&earlier), logs[5..7].to_vec());
    // Scrolling back while fewer than four records lie past `before`.
    let back = page(&mut guest, "general", obj! {"before" => logs[4].as_str()});
    assert_eq!(messages(&back), logs[3..5].to_vec());
    // Four past it is as far as a guest goes: older pages are for accounts.
    let denied = page(&mut guest, "general", obj! {"before" => logs[3].as_str()});
    assert_eq!(
        denied.get("error"),
        Some(&Json::from(
            obj! {"code" => CODE_DENIED, "message" => "Sign in to load older history"}
        ))
    );
    let account = page(&mut ada, "general", obj! {"before" => logs[3].as_str()});
    assert_eq!(messages(&account), logs[2..4].to_vec());
    // A window bounded by both, and catching up with `after`, stay open.
    let window = page(
        &mut guest,
        "general",
        obj! {"after" => logs[0].as_str(), "before" => logs[1].as_str()},
    );
    assert_eq!(messages(&window), logs[0..2].to_vec());
    let caught_up = page(&mut guest, "general", obj! {"after" => logs[0].as_str()});
    assert_eq!(messages(&caught_up), logs[0..2].to_vec());
    // Every room is measured from its own newest: a quiet thread opens
    // however busy general is.
    let quiet = page(&mut guest, &thread, obj! {"before" => logs[0].as_str()});
    let quiet = quiet["result"].as_object().unwrap();
    assert_eq!(log_ids(quiet, "messages"), Vec::<String>::new());
    assert_eq!(log_ids(quiet, "rooms").len(), 1, "{quiet:?}");
}

/// A refused guest page is charged as a served one (Cloudflare's "keeps a
/// refused guest page charged to its address").
#[test]
fn test_refused_guest_page_is_charged() {
    let mut config = default_config();
    config.limits.guest_history_depth = 1;
    config.limits.server_history_day = 1;
    let server = new_test_server(config);
    let mut ada = dial_test_client(&server);
    make_account(&server, &ada.user_id);
    let mut guest = dial_test_client(&server);
    ada.drain();
    let (_, first) = save(&mut ada, "m0", obj! {"body" => obj! {"text" => "one"}});
    save(&mut ada, "m1", obj! {"body" => obj! {"text" => "two"}});
    guest.drain();
    let first = first["log_id"].as_str().unwrap();
    let refused = guest.call(
        "history",
        "older",
        obj! {"room_id" => "general", "before" => first, "limit" => 1i64},
    );
    assert_eq!(error_code(&refused), Some(CODE_DENIED), "{refused:?}");
    let next = guest.call("history", "newest", obj! {"room_id" => "general"});
    assert_eq!(
        next["error"].as_object().unwrap()["message"],
        Json::from("Daily history limit reached for the server"),
        "{next:?}"
    );
}
