//! Read-only guests (`Config.guest_posting` false), an extension Go lacks
//! that matches apron-server-cloudflare's `GUEST_POSTING` (docs/DEVIATIONS.md).

use super::helpers::*;
use super::invite_bot_test::account;
use super::webauthn_test::*;
use crate::obj;
use crate::server::protocol::*;
use crate::server::users::GUEST_READ_ONLY;
use crate::server::Config;

fn read_only_server() -> TestServer {
    let mut config = default_config();
    config.web_authn = Some(test_web_authn());
    config.guest_posting = false;
    new_test_server(config)
}

fn settings_of(server_frame: &Object) -> (Vec<String>, Option<Json>) {
    let params = notification_params(server_frame, "server");
    let capabilities = params["capabilities"]
        .as_list()
        .iter()
        .filter_map(Json::as_str)
        .filter(|c| c.starts_with("ext:"))
        .map(str::to_owned)
        .collect();
    let settings = params
        .get("ext")
        .and_then(Json::as_object)
        .and_then(|ext| ext.get("settings"))
        .cloned();
    (capabilities, settings)
}

/// Every write a read-only guest sends is denied, with the same message,
/// and reaches no one.
#[test]
fn test_read_only_guest_writes_are_denied() {
    let server = read_only_server();
    let (mut a, _) = account(&server, "Ada");
    let (message_id, _) = save(&mut a, "post", obj! {"body" => obj! {"text" => "hi"}});
    grant_role(&server, &a.user_id, "mod");
    let (room_id, _) = save_room(&mut a, "room", obj! {"title" => "Ops"});
    a.drain();
    let (mut g, _) = dial_raw(&server);
    guest_auth(&mut g);
    a.drain();

    let writes: Vec<(&str, Object)> = vec![
        ("message", obj! {"body" => obj! {"text" => "hello"}}),
        (
            "message",
            obj! {"message_id" => message_id.as_str(), "body" => obj! {"text" => "edited"}},
        ),
        (
            "reactions",
            obj! {"message_id" => message_id.as_str(), "emojis" => vec!["👍".to_owned()]},
        ),
        ("room_set", obj! {"parent_room_id" => "general"}),
        ("room_set", obj! {"title" => "Mine"}),
        (
            "room_set",
            obj! {"room_id" => room_id.as_str(), "title" => "Renamed"},
        ),
        ("room_join", obj! {"room_id" => room_id.as_str()}),
        ("room_leave", obj! {"room_id" => "general"}),
        (
            "push_register",
            obj! {"kind" => "relay", "url" => "https://push.example/x"},
        ),
        ("push_unregister", obj! {"url" => "https://push.example/x"}),
        ("command", obj! {"body" => obj! {"text" => "/avatar"}}),
        (
            "command",
            obj! {"body" => obj! {"text" => "/kick @guest_9"}},
        ),
    ];
    for (i, (method, params)) in writes.into_iter().enumerate() {
        let id = format!("write-{i}");
        let frame = g.call(method, &id, params.clone());
        let error = frame.get("error").and_then(Json::as_object);
        assert_eq!(
            error.map(|e| (e["code"].clone(), e["message"].clone())),
            Some((Json::from(CODE_DENIED), Json::from(GUEST_READ_ONLY))),
            "{method} {params:?}: {frame:?}"
        );
    }
    g.write(
        &obj! {"method" => "activity", "params" => obj! {"room_id" => "general", "typing" => 1i64}},
    );
    g.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => "general", "read_message_id" => message_id.as_str()}});
    g.expect_quiet();
    a.expect_quiet();

    // Accounts still post.
    save(
        &mut a,
        "again",
        obj! {"body" => obj! {"text" => "still here"}},
    );
}

/// A read-only guest still signs in, lists rooms, reads any room's history,
/// sets its status, and runs /help, which lists only /help.
#[test]
fn test_read_only_guest_reads() {
    let server = read_only_server();
    let (mut a, _) = account(&server, "Ada");
    let (message_id, _) = save(&mut a, "post", obj! {"body" => obj! {"text" => "hi"}});
    grant_role(&server, &a.user_id, "mod");
    let (room_id, _) = save_room(&mut a, "room", obj! {"title" => "Ops"});
    save(
        &mut a,
        "ops",
        obj! {"room_id" => room_id.as_str(), "body" => obj! {"text" => "in ops"}},
    );
    let (mut g, _) = dial_raw(&server);
    guest_auth(&mut g);

    let listed = list_rooms(&mut g, Object::new());
    assert_eq!(room_ids(listed.get("joined")), vec!["general".to_owned()]);
    assert_eq!(room_ids(listed.get("not_joined")), vec![room_id.clone()]);
    let page = history_page(&mut g, "general", Object::new());
    assert_eq!(
        page["messages"].as_list()[0].as_object().unwrap()["message_id"],
        Json::from(message_id.as_str())
    );
    let page = history_page(&mut g, &room_id, Object::new());
    assert_eq!(page["messages"].as_list().len(), 1, "{page:?}");
    g.result("me", "status", obj! {"status" => "dnd"});
    g.drain();

    let (before, result) = g.request("command", "help", obj! {"body" => obj! {"text" => "/help"}});
    assert!(result.is_empty(), "{result:?}");
    let notice = notification_params(&before[0], "message");
    assert_eq!(
        notice["body"].as_object().unwrap()["text"],
        Json::from("- `/help`: list the commands you can use here")
    );
}

/// ext:settings keeps only read_cursors and private_rooms; whether a guest
/// may post is in its `you` (EXTENSIONS.md).
#[test]
fn test_server_frame_advertises_guest_posting() {
    let settings = |_guest_posting: bool| {
        Some(Json::from(
            obj! {"read_cursors" => true, "private_rooms" => 20i64},
        ))
    };
    type Case = (&'static str, Config, Option<Json>);
    let cases: Vec<Case> = vec![
        ("default", crate::server::default_config(), settings(false)),
        (
            "guest posting",
            Config {
                guest_posting: true,
                ..crate::server::default_config()
            },
            settings(true),
        ),
    ];
    for (name, config, want) in cases {
        let server = new_test_server(config);
        let (_, frame) = dial_raw(&server);
        assert_eq!(
            settings_of(&frame),
            (
                vec![
                    "ext:settings".to_owned(),
                    "ext:media".to_owned(),
                    "ext:permissions".to_owned()
                ],
                want
            ),
            "{name}"
        );
    }
}

/// A guest keeps its assigned name, its own included, sets no profile
/// `ext`, and may not start a
/// top-level room, whether or not guests post (apron-server-cloudflare's
/// "rejects operations guests may not perform").
#[test]
fn test_guests_keep_their_name() {
    let server = new_test_server(default_config());
    let mut guest = dial_test_client(&server);
    for (id, name) in [("rename", "Ada"), ("same", "Guest 1"), ("clear", "")] {
        let frame = reply(&mut guest, "me", id, obj! {"name" => name});
        assert_eq!(
            frame["error"]
                .as_object()
                .map(|e| (e["code"].clone(), e["message"].clone())),
            Some((
                Json::from(CODE_DENIED),
                Json::from("Only registered users may change their name")
            )),
            "{id}"
        );
    }
    let frame = reply(
        &mut guest,
        "room_set",
        "top-level",
        obj! {"title" => "Top level"},
    );
    assert_eq!(error_code(&frame), Some(CODE_DENIED));
    let frame = reply(
        &mut guest,
        "command",
        "avatar",
        obj! {"body" => obj! {"text" => "/avatar", "embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
    );
    assert_eq!(error_code(&frame), Some(CODE_DENIED), "a guest's /avatar");
    // Nor does a guest keep a profile `ext`.
    for (id, ext) in [
        ("bio", obj! {"bio" => "Counts things."}),
        ("none", Object::new()),
    ] {
        let frame = reply(&mut guest, "me", id, obj! {"ext" => ext});
        assert_eq!(
            frame["error"]
                .as_object()
                .map(|e| (e["code"].clone(), e["message"].clone())),
            Some((
                Json::from(CODE_DENIED),
                Json::from("Only registered users may change their profile")
            )),
            "{id}"
        );
    }
    let you = you_of(&guest.result("me", "status", obj! {"status" => "dnd"}));
    assert_eq!(you["name"], Json::from("Guest 1"));
}
