//! The server frame's `title`, `description` and `avatar` (§3.1) and
//! `/server`, ported from apron-server-cloudflare's
//! test/uploads.integration.test.ts, test/admin.integration.test.ts and
//! test/config-ip-frame.test.ts.

use std::sync::Arc;

use super::admin_test::*;
use super::helpers::*;
use super::persist_test::start_with;
use crate::obj;
use crate::server::config::Config;
use crate::server::metadata::ServerMetadata;
use crate::server::protocol::*;
use crate::store::{self, Store};

/// Reads until the next `server` frame and returns its params.
pub fn next_server(c: &TestClient) -> Object {
    loop {
        let frame = c.read();
        if frame.get("method") == Some(&Json::from("server")) {
            return notification_params(&frame, "server");
        }
    }
}

/// Runs a command with embeds and returns the frames before its result
/// and the result.
pub fn command_with(c: &mut TestClient, text: &str, embeds: Vec<Json>) -> (Vec<Object>, Object) {
    let id = c.next_id("command");
    c.request(
        "command",
        &id,
        obj! {"body" => obj! {"text" => text, "embeds" => embeds}},
    )
}

pub fn upload_embed() -> Vec<Json> {
    vec![Json::from(obj! {"kind" => "upload"})]
}

pub fn write_url(result: &Object) -> String {
    result["embeds"].as_list()[0].as_object().unwrap()["write_url"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn metadata_config(server: ServerMetadata) -> Config {
    Config {
        server,
        ..admin_config()
    }
}

/// Nothing set: no title, description or avatar; with `--server.*`, each.
#[test]
fn test_server_frame_carries_the_flags() {
    let server = admin_test_server();
    let (_, frame) = dial_raw(&server);
    let params = notification_params(&frame, "server");
    for field in ["title", "description", "avatar"] {
        assert!(!params.contains_key(field), "{field}: {params:?}");
    }
    let server = new_test_server(metadata_config(ServerMetadata {
        title: "Chat Club".into(),
        description: "Talk about *clubs*.".into(),
        avatar: "https://chat.example/icon.png".into(),
    }));
    let (_, frame) = dial_raw(&server);
    let params = notification_params(&frame, "server");
    assert_eq!(params["title"], Json::from("Chat Club"));
    assert_eq!(params["description"], Json::from("Talk about *clubs*."));
    assert_eq!(
        params["avatar"],
        Json::from("https://chat.example/icon.png")
    );
}

/// `/server` shows, sets and clears the server's title, description and
/// avatar for admins, over the flags; each change sends every connection a
/// new server frame.
#[test]
fn test_server_command_sets_and_clears() {
    let server = new_test_server(metadata_config(ServerMetadata {
        title: "From Flag".into(),
        description: "Flag *description*.".into(),
        avatar: "https://example.com/icon.png".into(),
    }));
    let bare = admin_test_server();
    let mut lone = admin(&bare);
    assert_eq!(
        private_reply(&mut lone, "/server"),
        [
            "This server's title, description and avatar, as clients show it:",
            "- **title**: none (clients show the server's address)",
            "- **description**: none",
            "- **avatar**: none",
        ]
        .join("\n")
    );

    let mut ada = admin(&server);
    let (watcher, _) = dial_raw(&server);
    let mut member = account(&server);
    assert!(private_reply(&mut ada, "/help")
        .contains("`/server [title|description [<text>] | avatar]`"));
    for text in ["/server title Mine", "/server"] {
        assert_eq!(command_error(&mut member, text).0, CODE_DENIED, "{text}");
    }
    let long_title = format!("/server title {}", "x".repeat(65));
    let long_description = format!("/server description {}", "x".repeat(501));
    for text in [
        long_title.as_str(),
        "/server title two\nlines",
        long_description.as_str(),
        "/server description a\u{7}b",
        "/server colour blue",
        "/server avatar https://example.com/a.png",
    ] {
        assert_eq!(
            command_error(&mut ada, text).0,
            CODE_INVALID_PARAMS,
            "{text}"
        );
    }
    let id = ada.next_id("stray");
    let stray = obj! {"body" => obj! {"text" => "/server title Club", "embeds" => upload_embed()}};
    ada.expect_error("command", &id, stray, CODE_INVALID_PARAMS);
    let id = ada.next_id("two");
    let two = vec![upload_embed()[0].clone(), upload_embed()[0].clone()];
    let two = obj! {"body" => obj! {"text" => "/server avatar", "embeds" => two}};
    ada.expect_error("command", &id, two, CODE_INVALID_PARAMS);
    assert!(
        private_reply(&mut ada, &format!("/server title {}", "x".repeat(64)))
            .starts_with("Set the server's title.")
    );
    next_server(&watcher);
    next_server(&member);

    let titled = private_reply(&mut ada, "/server title  Chat Club ");
    assert!(
        titled.contains("Set the server's title.\n\nThis server's title, description and avatar, as clients show it:\n- **title** (set with `/server title`): Chat Club\n"),
        "{titled}"
    );
    assert_eq!(next_server(&watcher)["title"], Json::from("Chat Club"));
    assert_eq!(next_server(&member)["title"], Json::from("Chat Club"));
    private_reply(
        &mut ada,
        "/server description Talk about *clubs*.\nAll welcome.",
    );
    let described = next_server(&watcher);
    assert_eq!(
        described["description"],
        Json::from("Talk about *clubs*.\nAll welcome.")
    );
    assert!(described["capabilities"]
        .as_list()
        .contains(&Json::from("command")));
    assert!(private_reply(&mut ada, "/server").contains(
        "- **description** (set with `/server description`):\n  > Talk about *clubs*.\n  > All welcome."
    ));
    assert!(private_reply(&mut ada, "/server")
        .contains("- **avatar** (from `--server.avatar`): <https://example.com/icon.png>"));

    // An image becomes the avatar when its write finishes, served for good.
    let (_, audio) = command_with(&mut ada, "/server avatar", upload_embed());
    let refused = http_do(
        "PUT",
        &write_url(&audio),
        Some(b"OggS not an image"),
        "audio/ogg",
    );
    assert_eq!(refused.0, 415);
    let (_, started) = command_with(&mut ada, "/server avatar", upload_embed());
    let (status, _, _) = http_do("PUT", &write_url(&started), Some(&test_png()), "image/png");
    assert_eq!(status, 201);
    let avatar = next_server(&watcher)["avatar"].as_str().unwrap().to_owned();
    assert!(avatar.contains("/files/embed_"), "{avatar}");
    let (status, header, _) = http_do("GET", &avatar, None, "");
    assert_eq!(status, 200);
    assert_eq!(
        header.get("Cache-Control"),
        Some("public, max-age=31536000, immutable")
    );
    let (_, late) = dial_raw(&server);
    let late = notification_params(&late, "server");
    assert_eq!(late["title"], Json::from("Chat Club"));
    assert_eq!(late["avatar"], Json::from(avatar.as_str()));

    // Cleared, each falls back to its flag.
    let cleared = private_reply(&mut ada, "/server title");
    assert!(
        cleared.contains("Cleared the server's title.\n\nThis server's title, description and avatar, as clients show it:\n- **title** (from `--server.title`): From Flag\n"),
        "{cleared}"
    );
    assert_eq!(next_server(&watcher)["title"], Json::from("From Flag"));
    private_reply(&mut ada, "/server description");
    assert_eq!(
        next_server(&watcher)["description"],
        Json::from("Flag *description*.")
    );
    assert!(private_reply(&mut ada, "/server title")
        .contains("The server's title was not set with `/server title`."));
    let removed = private_reply(&mut ada, "/server avatar");
    assert!(
        removed.contains("Cleared the server's avatar."),
        "{removed}"
    );
    assert!(
        removed.contains("- **avatar** (from `--server.avatar`): <https://example.com/icon.png>")
    );
    assert_eq!(
        next_server(&watcher)["avatar"],
        Json::from("https://example.com/icon.png")
    );
    assert_eq!(
        http_do("GET", &avatar, None, "").0,
        404,
        "the image is deleted"
    );
    assert_eq!(server.app.lock().server_meta, Default::default());
}

/// Without `/server description` or `--server.description`, the server's
/// description is general's, re-announced when it changes; past 500 bytes
/// it is left out, not cut.
#[test]
fn test_general_description_is_the_fallback() {
    let server = admin_test_server();
    let mut ada = admin(&server);
    let (watcher, _) = dial_raw(&server);
    let describe = |c: &mut TestClient, description: Option<&str>| {
        let id = c.next_id("describe");
        let mut params = obj! {"room_id" => "general", "title" => "General"};
        if let Some(description) = description {
            params.insert("description".into(), description.into());
        }
        let (before, result) = c.request("room_set", &id, params);
        assert!(!result.contains_key("error"), "{result:?}");
        before
            .into_iter()
            .filter(|frame| frame.get("method") == Some(&Json::from("server")))
            .map(|frame| {
                notification_params(&frame, "server")
                    .get("description")
                    .cloned()
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        describe(&mut ada, Some("  Say hi in **general**. ")),
        vec![Some(Json::from("Say hi in **general**."))]
    );
    assert_eq!(
        next_server(&watcher)["description"],
        Json::from("Say hi in **general**.")
    );
    let (_, fresh) = dial_raw(&server);
    let fresh = notification_params(&fresh, "server");
    assert_eq!(fresh["description"], Json::from("Say hi in **general**."));
    assert_eq!(fresh["welcome"], Json::from("  Say hi in **general**. "));
    assert!(private_reply(&mut ada, "/server").contains(
        "- **description** (from the default room `general`'s description):\n  > Say hi in **general**."
    ));
    assert_eq!(describe(&mut ada, Some(&"x".repeat(501))), vec![None]);
    assert!(private_reply(&mut ada, "/server").contains(
        "- **description**: none (`general`'s description is longer than 500 bytes or holds control characters, so it is left out)"
    ));
    assert_eq!(
        describe(&mut ada, Some("Say hi.")),
        vec![Some(Json::from("Say hi."))]
    );
    assert_eq!(describe(&mut ada, None), vec![None]);
    assert_eq!(
        describe(&mut ada, None),
        Vec::<Option<Json>>::new(),
        "unchanged"
    );

    // /server description comes first: general's changes then send nothing.
    private_reply(&mut ada, "/server description Our own.");
    assert_eq!(
        describe(&mut ada, Some("Say hey.")),
        Vec::<Option<Json>>::new()
    );
    let (before, _) = {
        let id = ada.next_id("command");
        ada.request(
            "command",
            &id,
            obj! {"body" => obj! {"text" => "/server description"}},
        )
    };
    let frames: Vec<Object> = before
        .iter()
        .filter(|frame| frame.get("method") == Some(&Json::from("server")))
        .map(|frame| notification_params(frame, "server"))
        .collect();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0]["description"], Json::from("Say hey."));
}

/// What `/server` sets survives a restart and overrides the flags.
#[test]
fn test_server_metadata_persists() {
    let dir = TempDir::new("apron-server-meta-");
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let admin_token = |config: &mut Config| {
        *config = Config {
            store: config.store.take(),
            upload_dir: config.upload_dir.clone(),
            server: ServerMetadata {
                title: "From Flag".into(),
                ..ServerMetadata::default()
            },
            ..admin_config()
        };
    };
    let mut server = start_with(kept.clone(), &format!("{dir}/a"), admin_token);
    let mut ada = admin(&server);
    private_reply(&mut ada, "/server title Chat Club");
    let (_, started) = command_with(&mut ada, "/server avatar", upload_embed());
    let (status, _, _) = http_do("PUT", &write_url(&started), Some(&test_png()), "image/png");
    assert_eq!(status, 201);
    let avatar = next_server(&ada)["avatar"].clone();
    drop(ada);
    server.stop();

    let server = start_with(kept, &format!("{dir}/a"), admin_token);
    let (_, frame) = dial_raw(&server);
    let params = notification_params(&frame, "server");
    assert_eq!(params["title"], Json::from("Chat Club"));
    assert_eq!(params["avatar"], avatar);
}
