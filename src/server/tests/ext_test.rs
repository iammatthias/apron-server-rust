//! ext_test.go, test by test. Each keeps the Go test's name, tables, and
//! literal expectations.

use rust_stdlib::encoding::json::jsontext::Value;

use super::helpers::*;
use super::webauthn_test::*;
use crate::obj;
use crate::server::messages::MAX_MESSAGE_EXT_BYTES;
use crate::server::protocol::*;
use crate::server::rooms::MAX_ROOM_EXT_BYTES;
use crate::server::users::MAX_PROFILE_EXT_BYTES;

/// Above 2^53, so a float64 cannot hold it exactly.
const BIG_NUMBER: &str = "12345678901234567891";

/// BIG_NUMBER as it arrives on the wire, unquoted (Go's
/// `jsontext.Value(bigNumber)`).
fn big_value() -> Json {
    Json::from(Value::from(BIG_NUMBER))
}

/// BIG_NUMBER as a decoded frame holds it, Go's `12345678901234567891.0`.
fn big_float() -> Json {
    Json::Number(BIG_NUMBER.parse().unwrap())
}

/// Writes merge ext one level deep (§4.12): each key a write carries replaces
/// the kept value whole, an empty value ("", [], {}) removes the key, keys it
/// leaves out stay, null is an ordinary value, and "ext": {} changes nothing.
/// A message save leaves ext out to keep it.
#[test]
fn test_message_saves_merge_ext() {
    let server = new_test_server(large_frames_config());
    let mut a = dial_test_client(&server);

    let (id, created) = save(
        &mut a,
        "create",
        obj! {
            "body" => obj! {"text" => "hi"},
            "ext" => obj! {"irc" => obj! {"nick" => "ada_"}, "big" => big_value(), "gone" => ""},
        },
    );
    assert_eq!(
        created.get("ext"),
        Some(&Json::from(
            obj! {"irc" => obj! {"nick" => "ada_"}, "big" => big_float()}
        )),
        "created ext"
    );
    // ext None: the save leaves ext out.
    let steps: Vec<(Option<Object>, Option<Object>)> = vec![
        (
            None,
            Some(obj! {"irc" => obj! {"nick" => "ada_"}, "big" => big_float()}),
        ),
        (
            Some(Object::new()),
            Some(obj! {"irc" => obj! {"nick" => "ada_"}, "big" => big_float()}),
        ),
        (
            Some(obj! {"irc" => obj! {"msgid" => "a1"}, "matrix" => Json::Null}),
            Some(
                obj! {"irc" => obj! {"msgid" => "a1"}, "big" => big_float(), "matrix" => Json::Null},
            ),
        ),
        (
            Some(obj! {"irc" => "", "matrix" => Json::Array(vec![]), "never" => Object::new()}),
            Some(obj! {"big" => big_float()}),
        ),
        (Some(obj! {"big" => Object::new()}), None),
    ];
    for (i, (ext, want)) in steps.into_iter().enumerate() {
        let mut params =
            obj! {"message_id" => id.as_str(), "body" => obj! {"text" => format!("edit {i}")}};
        if let Some(ext) = ext {
            params.insert("ext".into(), ext.into());
        }
        let (_, snapshot) = save(&mut a, &format!("edit-{i}"), params);
        let got = snapshot.get("ext");
        let Some(want) = want else {
            assert!(got.is_none(), "step {i}: ext {got:?}, want none");
            continue;
        };
        assert_eq!(got, Some(&Json::from(want)), "step {i}: ext");
        // Values are kept as they arrived, integers past 2^53 included.
        let raw = {
            let st = server.app.lock();
            let last = *st.messages[&id].records.last().unwrap();
            String::from_utf8_lossy(&st.records[&last].raw).into_owned()
        };
        assert!(
            raw.contains(&format!("\"big\":{BIG_NUMBER}")),
            "step {i}: stored snapshot lost the exact number: {raw}"
        );
    }

    // The limit applies to the merged ext: keys that fit one at a time are
    // too_large together, and the refused save changes nothing.
    let half = "x".repeat(MAX_MESSAGE_EXT_BYTES / 2);
    save(
        &mut a,
        "first-half",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => "x"}, "ext" => obj! {"a" => half.as_str()}},
    );
    a.expect_error(
        "message",
        "second-half",
        obj! {"message_id" => id.as_str(), "room_id" => "general", "body" => obj! {"text" => "x"}, "ext" => obj! {"b" => half.as_str()}},
        CODE_TOO_LARGE,
    );
    let (_, kept) = save(
        &mut a,
        "after",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => "x"}},
    );
    let ext = kept["ext"].as_object().unwrap();
    assert!(
        ext.len() == 1 && ext.get("a") == Some(&Json::from(half.as_str())),
        "a refused save changed ext: {} keys",
        ext.len()
    );
    a.expect_error(
        "message",
        "new-too-large",
        obj! {"room_id" => "general", "body" => obj! {"text" => "x"}, "ext" => obj! {"a" => half.as_str(), "b" => half.as_str()}},
        CODE_TOO_LARGE,
    );
    a.expect_error(
        "message",
        "bad-ext",
        obj! {"room_id" => "general", "body" => obj! {"text" => "x"}, "ext" => Json::Array(vec![])},
        CODE_INVALID_PARAMS,
    );
    a.expect_quiet();

    // A tombstone carries no ext, and a save of a tombstone merges into an
    // empty ext (§4.12).
    let (_, tombstone) = save(
        &mut a,
        "delete",
        obj! {"message_id" => id.as_str(), "deleted" => true, "ext" => obj! {"irc" => "x"}},
    );
    assert!(!tombstone.contains_key("ext"), "tombstone: {tombstone:?}");
    let (_, restored) = save(
        &mut a,
        "restore",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => "back"}, "ext" => obj! {"irc" => "x"}},
    );
    assert_eq!(
        restored.get("ext"),
        Some(&Json::from(obj! {"irc" => "x"})),
        "a save of a tombstone merged into another ext, want an empty ext"
    );
}

/// Concurrent saves of different ext keys of one message, from two
/// connections of its author, both survive: each merges into the snapshot
/// current when the server applies it (§4.4).
#[test]
fn test_concurrent_saves_of_different_ext_keys_both_survive() {
    let server = passkey_test_server();
    let (mut first, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut first, &mut new_test_authenticator());
    let (mut second, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    second.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => registered["token"].clone()},
    );
    first.drain();
    second.drain();
    let (id, _) = save(&mut first, "create", obj! {"body" => obj! {"text" => "hi"}});
    second.notification("message");

    const ROUNDS: i64 = 20;
    let clients = [("left", &first), ("right", &second)];
    for i in 0..ROUNDS {
        for (key, c) in clients {
            c.write(&obj! {"method" => "message", "id" => format!("{key}{i}"), "params" => obj! {
                "message_id" => id.as_str(), "room_id" => "general", "body" => obj! {"text" => "hi"},
                "ext" => obj! {key => i},
            }});
        }
    }
    // Each connection receives every snapshot, then its own replies; the
    // last snapshot either receives carries both keys at their last values.
    let want = Json::from(obj! {"left" => ROUNDS - 1, "right" => ROUNDS - 1});
    for (_, c) in clients {
        let mut last = Object::new();
        let (mut snapshots, mut replies) = (0, 0);
        while snapshots < 2 * ROUNDS || replies < ROUNDS {
            let frame = c.read();
            if frame.get("method") == Some(&Json::from("message")) {
                last = frame["params"].as_object().unwrap().clone();
                snapshots += 1;
            } else if frame.contains_key("result") {
                replies += 1;
            } else {
                panic!("unexpected frame: {frame:?}");
            }
        }
        assert_eq!(last.get("ext"), Some(&want), "last snapshot's ext");
    }
}

/// room_set replaces the client fields of a room, but merges ext (§4.2.4,
/// §4.12); the limit applies to the merged ext.
#[test]
fn test_room_set_merges_ext() {
    let server = new_test_server(default_config());
    let mut a = dial_test_client(&server);
    grant_role(&server, &a.user_id, "mod");
    let (room_id, created) = save_room(
        &mut a,
        "create",
        obj! {"title" => "Ops", "ext" => obj! {"irc" => obj! {"channel" => "#ops"}, "none" => Json::Array(vec![])}},
    );
    let channel = || obj! {"irc" => obj! {"channel" => "#ops"}};
    assert_eq!(
        created.get("ext"),
        Some(&Json::from(channel())),
        "created ext"
    );
    let (_, kept) = save_room(
        &mut a,
        "rename",
        obj! {"room_id" => room_id.as_str(), "title" => "Ops 2"},
    );
    assert!(
        kept.get("ext") == Some(&Json::from(channel()))
            && kept.get("title") == Some(&Json::from("Ops 2")),
        "an edit without ext: {kept:?}"
    );
    let (_, merged) = save_room(
        &mut a,
        "merge",
        obj! {"room_id" => room_id.as_str(), "title" => "Ops 2", "ext" => obj! {"matrix" => Json::Null}},
    );
    let mut want = channel();
    want.insert("matrix".into(), Json::Null);
    assert_eq!(merged.get("ext"), Some(&Json::from(want)), "merged ext");
    let (_, cleared) = save_room(
        &mut a,
        "clear",
        obj! {"room_id" => room_id.as_str(), "ext" => obj! {"irc" => "", "matrix" => Object::new()}},
    );
    assert!(
        !cleared.contains_key("ext") && cleared.get("title") == Some(&Json::from("Room")),
        "cleared: {cleared:?}"
    );
    let half = "x".repeat(MAX_ROOM_EXT_BYTES / 2);
    save_room(
        &mut a,
        "half",
        obj! {"room_id" => room_id.as_str(), "ext" => obj! {"a" => half.as_str()}},
    );
    a.expect_error(
        "room_set",
        "over",
        obj! {"room_id" => room_id.as_str(), "ext" => obj! {"b" => half.as_str()}},
        CODE_TOO_LARGE,
    );
    a.expect_quiet();
}

/// A profile's ext limit applies to the merged ext, and a refused `me`
/// changes nothing.
#[test]
fn test_profile_ext_limit_applies_to_the_merged_ext() {
    let server = new_test_server(default_config());
    let mut a = dial_test_client(&server);
    make_account(&server, &a.user_id);
    let half = "x".repeat(MAX_PROFILE_EXT_BYTES / 2);
    a.result(
        "me",
        "a",
        obj! {"ext" => obj! {"a" => half.as_str(), "big" => big_value()}},
    );
    a.expect_error(
        "me",
        "b",
        obj! {"name" => "Ada", "ext" => obj! {"b" => half.as_str()}},
        CODE_TOO_LARGE,
    );
    let you = a.result("me", "same", Object::new())["you"]
        .as_object()
        .cloned()
        .unwrap();
    let ext = you["ext"].as_object().unwrap();
    assert!(
        ext.contains_key("a")
            && ext.contains_key("big")
            && !ext.contains_key("b")
            && you["name"] == Json::from("Guest 1"),
        "a refused me changed the profile: {you:?}"
    );
    let raw = {
        let st = server.app.lock();
        String::from_utf8_lossy(&st.users[&a.user_id].ext["big"].0).into_owned()
    };
    assert_eq!(raw, BIG_NUMBER, "stored ext value");
}
