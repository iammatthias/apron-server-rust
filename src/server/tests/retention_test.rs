//! History retention (`Config.retention`), an extension Go lacks that
//! follows apron-server-cloudflare's rolling history (docs/DEVIATIONS.md).
//! The tests move the clock by calling `expire_history_locked` with a time
//! past the window.

use std::collections::BTreeMap;
use std::sync::Arc;

use rust_stdlib::path::filepath;
use rust_stdlib::time::{self, Duration};

use super::helpers::*;
use super::persist_test::start_with;
use crate::obj;
use crate::server::embeds::UPLOAD_SUFFIX;
use crate::server::protocol::*;
use crate::server::Config;
use crate::store::{self, Store};

const RETENTION: Duration = Duration::from_hours(1);

fn retention_config() -> Config {
    let mut config = default_config();
    config.retention = Some(RETENTION);
    config
}

/// Runs retention as if it were the window after `log_id`, so every record
/// before `log_id` expires and `log_id` itself stays.
fn expire_before(server: &TestServer, log_id: &str) {
    let cutoff: i64 = log_id.parse().unwrap();
    server
        .app
        .lock()
        .expire_history_locked(&time::unix_milli(cutoff + RETENTION.milliseconds()));
}

fn floor(server: &TestServer) -> String {
    format_id(server.app.lock().history_floor)
}

fn message_ids(page: &Object) -> Vec<String> {
    page.get("messages")
        .map(Json::as_list)
        .unwrap_or(&[])
        .iter()
        .map(|m| {
            m.as_object().unwrap()["message_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

fn general_entry(c: &mut TestClient) -> Object {
    let listed = list_rooms(c, obj! {"room_id" => "general"});
    listed["joined"].as_list()[0].as_object().cloned().unwrap()
}

fn error_code(c: &mut TestClient, method: &str, id: &str, params: Object) -> Json {
    let frame = c.call(method, id, params);
    frame["error"].as_object().unwrap()["code"].clone()
}

/// Messages, reactions, threads, and uploads older than the window go and
/// then behave as if they never existed; general stays, its history starting
/// at the floor, and its members hear of both.
#[test]
fn test_retention_expires_old_history() {
    let dir = TempDir::new("retention-uploads-");
    let mut config = retention_config();
    config.upload_dir = dir.to_string();
    let server = new_test_server(config);
    let mut a = dial_test_client(&server);

    let (old, _) = save(&mut a, "old", obj! {"body" => obj! {"text" => "old"}});
    react(&mut a, "react", &old, &["👍"]);
    let upload = post_embeds(
        &mut a,
        "upload",
        obj! {"room_id" => "general", "body" => obj! {"embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
    );
    let write_url = upload["embeds"].as_list()[0].as_object().unwrap()["write_url"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        http_do("PUT", &write_url, Some(b"hello"), "text/plain").0,
        201
    );
    a.drain();
    let (thread, _) = save_room(&mut a, "thread", obj! {"parent_room_id" => "general"});
    save(
        &mut a,
        "in-thread",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "in the thread"}},
    );
    a.drain();
    assert_eq!(
        filepath::glob(&format!("{dir}/*{UPLOAD_SUFFIX}"))
            .unwrap()
            .len(),
        1
    );
    let (new, _) = save(&mut a, "new", obj! {"body" => obj! {"text" => "new"}});

    expire_before(&server, &new);
    let frames = a.drain();
    assert_eq!(
        frames
            .iter()
            .map(|f| notification_params(f, "room_update"))
            .collect::<Vec<_>>(),
        vec![
            obj! {"left" => vec![Json::from(obj! {"room_id" => thread.as_str()})]},
            obj! {"updated" => vec![Json::from(general_entry(&mut a))]},
        ],
    );
    let page = history_page(&mut a, "general", Object::new());
    assert_eq!(message_ids(&page), vec![new.clone()]);
    assert_eq!(page["history_log_id"], Json::from(floor(&server)));
    assert_eq!(page["latest_log_id"], Json::from(new.as_str()));
    assert!(floor(&server) <= new, "floor past the kept message");
    assert_eq!(
        general_entry(&mut a)["history_log_id"],
        Json::from(floor(&server))
    );

    let edit = obj! {"message_id" => old.as_str(), "body" => obj! {"text" => "edited"}};
    let reaction = obj! {"message_id" => old.as_str(), "emojis" => vec!["🎉".to_owned()]};
    let reply =
        obj! {"reply_to" => obj! {"message_id" => old.as_str()}, "body" => obj! {"text" => "re"}};
    for (method, params) in [
        ("message", edit),
        ("reactions", reaction),
        ("message", reply),
        ("history", obj! {"room_id" => thread.as_str()}),
        ("room_join", obj! {"room_id" => thread.as_str()}),
    ] {
        assert_eq!(
            error_code(&mut a, method, &format!("{method}-expired"), params.clone()),
            Json::from(CODE_INVALID_PARAMS),
            "{method} {params:?}"
        );
    }
    let listed = list_rooms(&mut a, Object::new());
    assert_eq!(room_ids(listed.get("joined")), vec!["general".to_owned()]);
    // A delta from before the removal cannot name the thread, so it is a
    // full listing, without left; one from after it is a delta again.
    let delta = list_rooms(
        &mut a,
        obj! {"filter" => "joined", "latest_log_id" => new.as_str()},
    );
    assert_eq!(
        (room_ids(delta.get("joined")), delta.get("left")),
        (vec!["general".to_owned()], None)
    );
    let (newer, _) = save(&mut a, "newer", obj! {"body" => obj! {"text" => "newer"}});
    let delta = list_rooms(
        &mut a,
        obj! {"filter" => "joined", "latest_log_id" => newer.as_str()},
    );
    assert_eq!(
        (room_ids(delta.get("joined")), delta.get("left")),
        (vec![], Some(&Json::from(Vec::<Json>::new())))
    );
    assert!(
        filepath::glob(&format!("{dir}/*{UPLOAD_SUFFIX}"))
            .unwrap()
            .is_empty(),
        "the expired message's upload is still on disk"
    );
    let st = server.app.lock();
    assert!(st.embeds.is_empty(), "embeds: {:?}", st.embeds.keys());
    assert_eq!(st.upload_bytes, 0);
}

/// A message an edit kept inside the window stays, without the reaction set
/// logged before the window: reacting with it again logs it anew.
#[test]
fn test_retention_drops_expired_reaction_sets() {
    let server = new_test_server(retention_config());
    let mut a = dial_test_client(&server);
    let (kept, _) = save(&mut a, "post", obj! {"body" => obj! {"text" => "v1"}});
    react(&mut a, "react", &kept, &["👍"]);
    let (_, edited) = save(
        &mut a,
        "edit",
        obj! {"message_id" => kept.as_str(), "body" => obj! {"text" => "v2"}},
    );

    expire_before(&server, edited["log_id"].as_str().unwrap());
    a.drain();
    let page = history_page(&mut a, "general", Object::new());
    assert_eq!(message_ids(&page), vec![kept.clone()]);
    assert_eq!(page.get("reactions"), None, "{page:?}");
    let logged = react(&mut a, "again", &kept, &["👍"]);
    assert_eq!(
        logged["reactions"],
        Json::from(vec![Json::from(
            obj! {"from" => obj! {"user_id" => a.user_id.as_str(), "name" => "Guest 1"}, "emojis" => vec!["👍".to_owned()]}
        )])
    );
}

/// After the whole log expires, rooms report history_log_id null and keep
/// latest_log_id, and new log_ids still grow past every one issued.
#[test]
fn test_log_ids_stay_monotonic_after_full_expiry() {
    let server = new_test_server(retention_config());
    let mut a = dial_test_client(&server);
    let (old, _) = save(&mut a, "old", obj! {"body" => obj! {"text" => "old"}});
    let last = server.app.lock().last_id;

    expire_before(&server, &format_id(last + 1));
    a.drain();
    let latest = format_id(last);
    let entry = general_entry(&mut a);
    assert_eq!(
        (&entry["latest_log_id"], &entry["history_log_id"]),
        (&Json::from(latest.as_str()), &Json::Null)
    );
    for params in [obj! {"room_id" => "general"}, Object::new()] {
        let page = a.result("history", "history", params.clone());
        assert_eq!(
            (&page["latest_log_id"], &page["history_log_id"]),
            (&Json::from(latest.as_str()), &Json::Null),
            "{params:?}"
        );
    }
    assert_eq!(floor(&server), format_id(last + 1));

    let (new, _) = save(&mut a, "new", obj! {"body" => obj! {"text" => "new"}});
    let new_id: i64 = new.parse().unwrap();
    assert!(new_id > last && new != old, "{new} after {last}");
    let page = history_page(&mut a, "general", Object::new());
    assert_eq!(message_ids(&page), vec![new.clone()]);
    assert_eq!(page["history_log_id"], Json::from(floor(&server)));
}

/// A save may keep a reply_to whose target expired, so old replies stay
/// editable; a new reply to it, or a save that changes reply_to to it, is
/// invalid_params.
#[test]
fn test_expired_reply_to_kept_only_unchanged() {
    let server = new_test_server(retention_config());
    let mut a = dial_test_client(&server);
    let (target, _) = save(&mut a, "target", obj! {"body" => obj! {"text" => "target"}});
    let (other, _) = save(&mut a, "other", obj! {"body" => obj! {"text" => "other"}});
    let (reply, _) = save(
        &mut a,
        "reply",
        obj! {"reply_to" => obj! {"message_id" => target.as_str()}, "body" => obj! {"text" => "re"}},
    );
    let (plain, _) = save(&mut a, "plain", obj! {"body" => obj! {"text" => "plain"}});

    expire_before(&server, &reply);
    a.drain();
    let (_, saved) = save(
        &mut a,
        "keep",
        obj! {"message_id" => reply.as_str(), "reply_to" => obj! {"message_id" => target.as_str()}, "body" => obj! {"text" => "re, edited"}},
    );
    assert_eq!(
        saved["reply_to"],
        Json::from(obj! {"message_id" => target.as_str()})
    );
    for (id, params) in [
        (
            "new-reply",
            obj! {"reply_to" => obj! {"message_id" => target.as_str()}, "body" => obj! {"text" => "re"}},
        ),
        (
            "changed",
            obj! {"message_id" => reply.as_str(), "reply_to" => obj! {"message_id" => other.as_str()}, "body" => obj! {"text" => "re"}},
        ),
        (
            "added",
            obj! {"message_id" => plain.as_str(), "reply_to" => obj! {"message_id" => target.as_str()}, "body" => obj! {"text" => "plain"}},
        ),
    ] {
        assert_eq!(
            error_code(&mut a, "message", id, params),
            Json::from(CODE_INVALID_PARAMS),
            "{id}"
        );
    }
}

/// The floor and the discarded state survive a restart, and a restart after
/// the window passed discards what expired before anyone reads it.
#[test]
fn test_retention_survives_restart() {
    let dir = TempDir::new("retention-restart-");
    let path = format!("{dir}/aprond.db");
    let open = || -> Arc<dyn Store> { Arc::new(store::SQLite::open(&path).unwrap()) };
    let upload_dir = format!("{dir}/uploads");
    let with_retention = |retention: Duration| move |c: &mut Config| c.retention = Some(retention);

    let mut server = start_with(open(), &upload_dir, with_retention(RETENTION));
    let mut a = dial_test_client(&server);
    let (old, _) = save(&mut a, "old", obj! {"body" => obj! {"text" => "old"}});
    let (thread, _) = save_room(&mut a, "thread", obj! {"parent_room_id" => "general"});
    let (new, _) = save(&mut a, "new", obj! {"body" => obj! {"text" => "new"}});
    expire_before(&server, &new);
    let kept_floor = server.app.lock().history_floor;
    drop(a);
    server.stop();

    let s = open();
    let mut entries: BTreeMap<String, Vec<String>> = BTreeMap::new();
    s.load(&mut |e| {
        entries.entry(e.kind).or_default().push(e.id);
        Ok(())
    })
    .unwrap();
    s.close().unwrap();
    let records: Vec<i64> = entries["record"]
        .iter()
        .map(|id| id.parse().unwrap())
        .collect();
    assert!(
        records.iter().all(|id| *id >= kept_floor),
        "expired records stored: {records:?} below {kept_floor}"
    );
    assert_eq!(entries["message"], vec![new.clone()]);
    assert_eq!(entries["room"], vec!["general".to_owned()]);

    let mut server = start_with(open(), &upload_dir, with_retention(RETENTION));
    let mut a = dial_test_client(&server);
    let page = history_page(&mut a, "general", Object::new());
    assert_eq!(message_ids(&page), vec![new.clone()]);
    assert_eq!(page["history_log_id"], Json::from(format_id(kept_floor)));
    let edit = obj! {"message_id" => old.as_str(), "body" => obj! {"text" => "edited"}};
    assert_eq!(
        error_code(&mut a, "message", "edit-old", edit),
        Json::from(CODE_INVALID_PARAMS)
    );
    assert_eq!(
        error_code(
            &mut a,
            "history",
            "thread",
            obj! {"room_id" => thread.as_str()}
        ),
        Json::from(CODE_INVALID_PARAMS)
    );
    drop(a);
    server.stop();
    let last = server.app.lock().last_id;

    // Every record is older than a millisecond by the time it reopens.
    while time::now().unix_milli() <= last + 1 {
        std::thread::yield_now();
    }
    let mut server = start_with(
        open(),
        &upload_dir,
        with_retention(Duration::from_millis(1)),
    );
    let st = server.app.lock();
    assert!(
        st.records.is_empty(),
        "records kept: {:?}",
        st.records.keys()
    );
    assert!(st.messages.is_empty());
    assert_eq!(st.history_floor, last + 1);
    assert_eq!(st.rooms["general"].history_log_id(st.history_floor), None);
    assert_eq!(st.rooms["general"].latest_id, last);
    drop(st);
    let mut a = dial_test_client(&server);
    let (next, _) = save(&mut a, "next", obj! {"body" => obj! {"text" => "next"}});
    assert!(next.parse::<i64>().unwrap() > last);
    drop(a);
    server.stop();
}

/// A private room whose whole log expired goes like a thread, its members
/// told it left; a top-level room an admin made stays.
#[test]
fn test_retention_removes_expired_private_rooms() {
    let server = new_test_server(retention_config());
    let mut a = dial_test_client(&server);
    make_account(&server, &a.user_id);
    grant_role(&server, &a.user_id, "mod");
    let (private, _) = save_room(&mut a, "private", obj! {"private" => true});
    let (top, _) = save_room(&mut a, "top", obj! {"title" => "Top"});
    let (new, _) = save(&mut a, "new", obj! {"body" => obj! {"text" => "new"}});
    a.drain();
    expire_before(&server, &new);
    let left: Vec<Object> = a
        .drain()
        .iter()
        .map(|f| notification_params(f, "room_update"))
        .filter(|p| p.contains_key("left"))
        .collect();
    assert_eq!(
        left,
        vec![obj! {"left" => vec![Json::from(obj! {"room_id" => private.as_str()})]}]
    );
    let st = server.app.lock();
    assert!(!st.rooms.contains_key(&private) && st.rooms.contains_key(&top));
}
