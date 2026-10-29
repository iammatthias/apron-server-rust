//! The profile, name, avatar, and command tests of reference_test.go, test
//! by test. Each keeps the Go test's name, tables, and literal expectations.

use super::helpers::*;
use super::reference_test::{absent, empty, nth, write_urls};
use crate::obj;
use crate::server::embeds::{FILE_PATH, WRITE_PATH};
use crate::server::protocol::*;
use crate::server::user_ids::normalize_name;
use crate::server::users::MAX_NAME_RUNES;

#[test]
fn test_profiles_and_user_notifications() {
    // An account's own `you` also carries its permissions.
    let yours = |profile: &Object| {
        let mut you = profile.clone();
        let mut ext = you
            .get("ext")
            .and_then(Json::as_object)
            .cloned()
            .unwrap_or_default();
        ext.insert("permissions".into(), obj! {"add_members" => true}.into());
        you.insert("ext".into(), ext.into());
        you
    };
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));
    let ext = obj! {"example.org" => obj! {"pronouns" => "she/her"}};
    let you = a.result(
        "me",
        "profile",
        obj! {"name" => "  Ada  ", "avatar" => "data:image/png;base64,iVBORw0KGgo=", "ext" => ext.clone()},
    )["you"]
        .clone();
    // An avatar comes only from /avatar: `me` ignores any but "".
    let want = obj! {"user_id" => "guest_1", "name" => "Ada", "ext" => ext.clone(), "status" => "online", "roles" => strings(&[])};
    assert_eq!(you, Json::from(yours(&want)), "you");
    assert_eq!(
        b.notification("user"),
        obj! {"new" => want.clone()},
        "user notification"
    );
    // Avatars and ext travel in profiles, not in every from.
    let (_, snapshot) = save(&mut a, "post", obj! {"body" => obj! {"text" => "hi"}});
    b.notification("message");
    assert_eq!(
        snapshot.get("from"),
        Some(&Json::from(obj! {"user_id" => "guest_1", "name" => "Ada"})),
        "from"
    );
    // room_list with members: true sends members bare but for their status
    // (§4.5), with complete objects in users.
    let listed = list_rooms(&mut b, obj! {"filter" => "joined"});
    assert!(
        absent(&listed, "users"),
        "users without members: true: {listed:?}"
    );
    let listed = list_rooms(&mut b, obj! {"filter" => "joined", "members" => true});
    let members = nth(&listed, "joined", 0)["members"].as_list().to_vec();
    assert_eq!(
        members[0],
        Json::from(obj! {"user_id" => "guest_1", "status" => "online"}),
        "members"
    );
    assert_eq!(
        listed["users"].as_list()[0],
        Json::from(want.clone()),
        "users"
    );
    // An unchanged profile sends no notification; omitted fields stay.
    a.result("me", "same", obj! {"name" => "Ada"});
    let kept = a.result("me", "keep", Object::new())["you"].clone();
    assert_eq!(
        kept,
        Json::from(yours(&want)),
        "empty me changed the profile"
    );
    b.expect_quiet();
    // "ext": {} changes nothing (§4.12).
    let kept = a.result("me", "empty-ext", obj! {"ext" => Object::new()})["you"].clone();
    assert_eq!(
        kept,
        Json::from(yours(&want)),
        "ext {{}} changed the profile"
    );
    b.expect_quiet();
    // ext merges one level deep: a key the write carries replaces the kept
    // value whole, null included, and keys it leaves out stay.
    let you = a.result(
        "me",
        "merge",
        obj! {"ext" => obj! {"example.net" => Json::Null}},
    )["you"]
        .clone();
    let mut merged = want.clone();
    merged.insert(
        "ext".into(),
        obj! {"example.org" => obj! {"pronouns" => "she/her"}, "example.net" => Json::Null}.into(),
    );
    assert_eq!(you, Json::from(yours(&merged)), "merge result");
    assert_eq!(
        b.notification("user"),
        obj! {"new" => merged},
        "merge notification"
    );
    // An empty value removes a field or an ext key. The result is complete,
    // and the notification, which clients merge, carries what it removed as
    // those empty values.
    let you = a.result(
        "me",
        "clear",
        obj! {"ext" => obj! {"example.org" => "", "example.net" => empty(), "absent.example" => Object::new()}, "avatar" => ""},
    )["you"]
        .clone();
    let cleared = obj! {"user_id" => "guest_1", "name" => "Ada", "avatar" => "", "status" => "online", "roles" => strings(&[])};
    assert_eq!(you, Json::from(yours(&cleared)), "removal result");
    let mut announced = cleared.clone();
    announced.insert(
        "ext".into(),
        obj! {"example.org" => "", "example.net" => empty()}.into(),
    );
    assert_eq!(
        b.notification("user"),
        obj! {"new" => announced},
        "removal notification"
    );
    let users = list_rooms(&mut b, obj! {"room_id" => "general", "members" => true})["users"]
        .as_list()
        .to_vec();
    assert_eq!(
        users[0],
        Json::from(
            obj! {"user_id" => "guest_1", "name" => "Ada", "status" => "online", "roles" => strings(&[])}
        ),
        "profile after removal"
    );
    let you = a.result("me", "clear-name", obj! {"name" => ""})["you"].clone();
    assert_eq!(
        you,
        Json::from(yours(
            &obj! {"user_id" => "guest_1", "name" => "", "status" => "online", "roles" => strings(&[])}
        )),
        "clearing the name"
    );
    b.notification("user");
    let you = you_of(&a.result(
        "me",
        "other-avatar",
        obj! {"avatar" => "https://example.com/a.png"},
    ));
    assert!(
        !you.contains_key("avatar"),
        "an https: avatar was kept: {you:?}"
    );
    a.expect_error("me", "bad-name", obj! {"name" => 7i64}, CODE_INVALID_PARAMS);
    b.expect_quiet();
}

/// The Go table's fullwidth row needs NFKC, which the port does not apply
/// (the "Display names" row of docs/DEVIATIONS.md);
/// `test_names_are_normalized_without_nfkc` checks the other rows.
#[test]
#[ignore = "deviation: normalize_name has no NFKC (docs/DEVIATIONS.md, Display names)"]
fn test_names_are_normalized() {
    test_names_are_normalized_without_nfkc();
    assert_eq!(
        normalize_name("Ａｄａ"),
        "Ada",
        "normalize_name(\"Ａｄａ\")"
    );
}

#[test]
fn test_names_are_normalized_without_nfkc() {
    for (input, want) in [
        ("  Ada   Lovelace ".to_owned(), "Ada Lovelace".to_owned()),
        ("Ada\u{202e}ecalevoL".to_owned(), "AdaecalevoL".to_owned()),
        ("Bob\x00\x07".to_owned(), "Bob".to_owned()),
        ("\u{200b}\u{200b}".to_owned(), String::new()),
        ("é".repeat(80), "é".repeat(MAX_NAME_RUNES)),
    ] {
        assert_eq!(normalize_name(&input), want, "normalize_name({input:?})");
    }
}

#[test]
fn test_avatar_command() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));
    for (i, embeds) in [
        None,
        Some(vec![]),
        Some(vec![Json::from(obj! {"kind" => "stream"})]),
        Some(vec![
            Json::from(obj! {"kind" => "upload"}),
            Json::from(obj! {"kind" => "upload"}),
        ]),
    ]
    .into_iter()
    .enumerate()
    {
        let mut body = obj! {"text" => "/avatar"};
        if let Some(embeds) = embeds {
            body.insert("embeds".into(), Json::from(embeds));
        }
        a.expect_error(
            "command",
            &format!("shape-{i}"),
            obj! {"body" => body},
            CODE_INVALID_PARAMS,
        );
    }
    let result = a.result(
        "command",
        "avatar",
        obj! {"body" => obj! {"text" => "/avatar", "embeds" => vec![Json::from(obj! {"kind" => "upload", "title" => "me.png"})]}},
    );
    let written = result["embeds"].as_list();
    assert!(
        result.len() == 1 && written.len() == 1,
        "avatar result: {result:?}"
    );
    let write = written[0].as_object().unwrap();
    let write_url = write["write_url"].as_str().unwrap().to_owned();
    assert!(
        write["kind"] == Json::from("upload")
            && !absent(write, "embed_id")
            && write_url.starts_with(&format!("{}{WRITE_PATH}", server.http.url)),
        "avatar write: {write:?}"
    );
    // A command is never logged or broadcast.
    a.expect_quiet();
    b.expect_quiet();
    assert_eq!(
        http_do("PUT", &write_url, Some(&test_png()), "").0,
        201,
        "avatar upload"
    );
    let you = a.notification("user")["you"].as_object().cloned().unwrap();
    let avatar = you
        .get("avatar")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    assert!(
        avatar.starts_with(&format!("{}{FILE_PATH}", server.http.url)),
        "avatar: {you:?}"
    );
    let notice = b.notification("user")["new"].as_object().cloned().unwrap();
    assert_eq!(
        notice.get("avatar"),
        Some(&Json::from(avatar.as_str())),
        "others' notification: {notice:?}"
    );
    assert_eq!(http_do("GET", &avatar, None, "").0, 200, "avatar file");
    let page = history_page(&mut a, "general", Object::new());
    assert!(absent(&page, "messages"), "command was logged: {page:?}");

    // Only images become avatars; replacing the avatar deletes the upload.
    let result = a.result(
        "command",
        "text",
        obj! {"body" => obj! {"text" => "/avatar", "embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
    );
    let write_url = write_urls(&result).remove(0);
    assert_eq!(
        http_do("PUT", &write_url, Some(b"plain text"), "text/plain").0,
        415,
        "text avatar"
    );
    a.result("me", "clear", obj! {"avatar" => ""});
    b.notification("user");
    assert_eq!(
        http_do("GET", &avatar, None, "").0,
        404,
        "replaced avatar file"
    );
}

/// /help replies with a ~private notice to the sender's connection, in the
/// command's room, listing what the sender may use there.
fn help(client: &mut TestClient, room_id: &str) -> String {
    let mut params = obj! {"body" => obj! {"text" => "/help"}};
    let room_id = if room_id.is_empty() {
        "general"
    } else {
        params.insert("room_id".into(), room_id.into());
        room_id
    };
    // The ~private reply precedes the result (§1).
    let id = client.next_id("help");
    let (before, result) = client.request("command", &id, params);
    assert!(
        result.is_empty() && before.len() == 1,
        "help result {result:?} after {before:?}"
    );
    let notice = notification_params(&before[0], "message");
    let body = notice["body"].as_object().unwrap();
    assert!(
        !notice.contains_key("message_id")
            && absent(&notice, "log_id")
            && notice.get("room_id") == Some(&Json::from(room_id))
            && body.get("format") == Some(&Json::from("markdown"))
            && notice.get("from")
                == Some(&Json::from(
                    obj! {"user_id" => "~private", "name" => "System message to you"}
                )),
        "help notice: {notice:?}"
    );
    body["text"].as_str().unwrap().to_owned()
}

#[test]
fn test_commands() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 3);
    let (mut a, mut b, mut c) = (clients.remove(0), clients.remove(0), clients.remove(0));
    grant_role(&server, &a.user_id, "mod");
    let (ops, _) = save_room(&mut a, "ops", obj! {"title" => "Ops"});
    revoke_role(&server, &a.user_id, "mod");
    join_room(&mut b, &ops);
    expect_membership(&a, &ops, "guest_2", true);
    join_room(&mut c, &ops);
    expect_membership(&a, &ops, "guest_3", true);
    expect_membership(&b, &ops, "guest_3", true);

    let text = help(&mut a, &ops);
    assert!(
        text.contains("`/help`") && !text.contains("/avatar") && !text.contains("/kick"),
        "guest's help: {text:?}"
    );
    for client in [&mut a, &mut b, &mut c] {
        client.expect_quiet();
    }

    // Invalid commands are errors whose message the client shows.
    let unknown = b.call(
        "command",
        "unknown",
        obj! {"body" => obj! {"text" => "/Frobnicate now"}},
    );
    let failure = unknown["error"].as_object().unwrap();
    assert!(
        failure.get("code") == Some(&Json::from(CODE_INVALID_PARAMS))
            && failure.get("message")
                == Some(&Json::from("Unknown command /Frobnicate; try /help")),
        "unknown command: {unknown:?}"
    );
    for (i, params) in [
        obj! {"body" => obj! {"text" => "hello"}},
        obj! {"body" => obj! {"text" => ""}},
        obj! {"message_id" => "1", "body" => obj! {"text" => "/help"}},
        obj! {"deleted" => false, "body" => obj! {"text" => "/help"}},
        obj! {"room_id" => "missing", "body" => obj! {"text" => "/help"}},
        obj! {"body" => obj! {"text" => "/help"}, "reply_to" => obj! {"message_id" => "999"}},
        obj! {"body" => obj! {"text" => "/help", "mentions" => "x"}},
        Object::new(),
    ]
    .into_iter()
    .enumerate()
    {
        b.expect_error("command", &format!("bad-{i}"), params, CODE_INVALID_PARAMS);
    }

    for client in [&mut a, &mut b, &mut c] {
        client.expect_quiet();
    }
}
