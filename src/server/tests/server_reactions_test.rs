//! The reaction tests of server_test.go, test by test. Each keeps the Go
//! test's name, tables, and literal expectations.

use super::helpers::*;
use super::server_test::f;
use crate::obj;
use crate::server::messages::{MAX_DISTINCT_EMOJI, MAX_EMOJI_BYTES};
use crate::server::protocol::*;

#[test]
fn test_reactions() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let (id, _) = save(
        &mut c,
        "create",
        obj! {"body" => obj! {"text" => "react to me"}},
    );

    let set = react(&mut c, "set", &id, &["👍", "🎉", "👍"]);
    let want = obj! {
        "log_id" => set["log_id"].clone(), "message_id" => id.as_str(), "room_id" => "general",
        "reactions" => vec![Json::from(obj! {"from" => obj! {"user_id" => "guest_1", "name" => "Guest 1"}, "emojis" => strings(&["👍", "🎉"])})],
    };
    assert_eq!(set, want, "reactions broadcast");
    // An unchanged set, in any order, logs nothing.
    let result = c.result(
        "reactions",
        "same",
        obj! {"message_id" => id.as_str(), "emojis" => strings(&["🎉", "👍"])},
    );
    assert!(result.is_empty(), "unchanged result: {result:?}");
    c.expect_quiet();
    // Request deduplication returns the original result without
    // rebroadcasting.
    c.result(
        "reactions",
        "set",
        obj! {"message_id" => id.as_str(), "emojis" => strings(&["👍", "🎉", "👍"])},
    );
    c.expect_quiet();
    c.expect_error(
        "reactions",
        "set",
        obj! {"message_id" => id.as_str(), "emojis" => strings(&["👎"])},
        CODE_INVALID_PARAMS,
    );

    let cleared = react(&mut c, "clear", &id, &[]);
    let sets = cleared["reactions"].as_list();
    assert!(
        sets.len() == 1 && sets[0].as_object().unwrap()["emojis"].as_list().is_empty(),
        "clear broadcast: {cleared:?}"
    );
    c.result(
        "reactions",
        "clear-again",
        obj! {"message_id" => id.as_str(), "emojis" => Json::Array(vec![])},
    );
    c.expect_quiet();

    let too_many: Vec<Json> = (0..=MAX_DISTINCT_EMOJI)
        .map(|i| Json::from(i.to_string()))
        .collect();
    for (i, params) in [
        obj! {"message_id" => "999", "emojis" => strings(&["👍"])},
        obj! {"message_id" => id.as_str()},
        obj! {"message_id" => id.as_str(), "emojis" => Json::Null},
        obj! {"message_id" => id.as_str(), "emojis" => "👍"},
        obj! {"message_id" => id.as_str(), "emojis" => Json::Array(vec![f(12)])},
        obj! {"message_id" => id.as_str(), "emojis" => strings(&[""])},
        obj! {"emojis" => strings(&["👍"])},
    ]
    .into_iter()
    .enumerate()
    {
        c.expect_error(
            "reactions",
            &format!("bad-{i}"),
            params,
            CODE_INVALID_PARAMS,
        );
    }
    // A count limit the server sets is denied, and an emoji over its size
    // is too_large (§1.1).
    c.expect_error(
        "reactions",
        "too-many",
        obj! {"message_id" => id.as_str(), "emojis" => Json::Array(too_many)},
        CODE_DENIED,
    );
    c.expect_error("reactions", "too-long", obj! {"message_id" => id.as_str(), "emojis" => Json::Array(vec!["x".repeat(MAX_EMOJI_BYTES + 1).into()])}, CODE_TOO_LARGE);
    c.expect_quiet();

    let page = history_page(&mut c, "general", Object::new());
    assert_eq!(
        log_ids(&page, "reactions"),
        vec![
            set["log_id"].as_str().unwrap().to_owned(),
            cleared["log_id"].as_str().unwrap().to_owned()
        ],
        "history reactions: {page:?}"
    );
}

/// A reaction set holds at most MAX_DISTINCT_EMOJI emoji, a message takes
/// sets from at most MAX_REACTING_USERS users, and a tombstone takes none,
/// though a set on it may still be cleared (apron-server-cloudflare's
/// "rejects new reactions on tombstones and caps reacting users per
/// message").
#[test]
fn test_reaction_caps_and_tombstones() {
    use crate::server::messages::MAX_REACTING_USERS;
    assert_eq!(
        (MAX_DISTINCT_EMOJI, MAX_REACTING_USERS),
        (8, 32),
        "Cloudflare's reaction limits"
    );
    let server = new_test_server(default_config());
    let mut author = dial_test_client(&server);
    let (id, _) = save(
        &mut author,
        "post",
        obj! {"body" => obj! {"text" => "popular"}},
    );
    let eight: Vec<String> = (0..MAX_DISTINCT_EMOJI).map(|i| format!("e{i}")).collect();
    let eight: Vec<&str> = eight.iter().map(String::as_str).collect();
    react(&mut author, "eight", &id, &eight);
    let mut reactors = vec![author];
    while reactors.len() < MAX_REACTING_USERS {
        let mut c = dial_test_client(&server);
        let frame = reply(
            &mut c,
            "reactions",
            "one",
            obj! {"message_id" => id.as_str(), "emojis" => strings(&["👍"])},
        );
        assert!(frame.contains_key("result"), "{frame:?}");
        reactors.push(c);
    }
    let mut late = dial_test_client(&server);
    let denied = |c: &mut TestClient, request: &str, emojis: &[&str], message: &str| {
        let frame = reply(
            c,
            "reactions",
            request,
            obj! {"message_id" => id.as_str(), "emojis" => strings(emojis)},
        );
        assert_eq!(
            frame["error"]
                .as_object()
                .map(|e| (e["code"].clone(), e["message"].clone())),
            Some((Json::from(CODE_DENIED), Json::from(message))),
            "{request}"
        );
    };
    denied(
        &mut late,
        "late",
        &["👍"],
        "reaction limit reached for this message",
    );
    // Those who reacted may still change their set.
    let frame = reply(
        &mut reactors[1],
        "reactions",
        "change",
        obj! {"message_id" => id.as_str(), "emojis" => strings(&["🎉"])},
    );
    assert!(frame.contains_key("result"), "{frame:?}");

    let author = &mut reactors[0];
    let frame = reply(
        author,
        "message",
        "delete",
        obj! {"message_id" => id.as_str(), "deleted" => true},
    );
    assert!(frame.contains_key("result"), "{frame:?}");
    denied(
        &mut reactors[1],
        "on-tombstone",
        &["👀"],
        "cannot react to a deleted message",
    );
    let frame = reply(
        &mut reactors[1],
        "reactions",
        "clear",
        obj! {"message_id" => id.as_str(), "emojis" => strings(&[])},
    );
    assert!(frame.contains_key("result"), "{frame:?}");
}
