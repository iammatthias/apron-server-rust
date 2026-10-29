//! Custom emoji (EXTENSIONS.md, `ext:emoji`) and `/emoji`, ported from
//! apron-server-cloudflare's test/uploads.integration.test.ts.

use std::sync::Arc;

use super::helpers::*;
use super::metadata_test::{command_with, next_server, upload_embed, write_url};
use super::persist_test::start_with;
use crate::obj;
use crate::server::config::Config;
use crate::server::protocol::*;
use crate::store::{self, Store};

/// A PNG of `width` by `height` pixels.
fn png(width: i32, height: i32) -> Vec<u8> {
    use rust_stdlib::image;
    let mut buf = Vec::new();
    image::png::encode(
        &mut buf,
        &image::Rgba::new(image::rect(0, 0, width, height)),
    )
    .expect("encode png");
    buf
}

/// Starts `/emoji add <key>` and writes `image`, returning the write's
/// status, after reading the `server` frame a stored image sends `c`.
fn add(c: &mut TestClient, key: &str, image: &[u8], content_type: &str) -> u16 {
    let (_, started) = command_with(c, &format!("/emoji add {key}"), upload_embed());
    let status = http_do("PUT", &write_url(&started), Some(image), content_type).0;
    if status == 201 {
        next_server(c);
    }
    status
}

fn get(url: &str) -> (u16, Option<String>, Vec<u8>) {
    let (status, header, body) = http_do("GET", url, None, "");
    (status, header.get("Cache-Control").map(str::to_owned), body)
}

/// Sends reactions that are refused as invalid_params, skipping the
/// notifications before the error.
fn react_error(c: &mut TestClient, id: &str, message_id: &str, emojis: &[&str]) {
    let rid = c.next_id(id);
    c.write(&obj! {"method" => "reactions", "id" => rid.as_str(), "params" => obj! {"message_id" => message_id, "emojis" => strings(emojis)}});
    let reply = loop {
        let frame = c.read();
        if frame.contains_key("id") {
            break frame;
        }
    };
    assert_eq!(
        reply["error"].as_object().unwrap()["code"],
        Json::from(CODE_INVALID_PARAMS),
        "{reply:?}"
    );
}

fn reacted(c: &mut TestClient, id: &str, message_id: &str, emojis: &[&str]) -> Json {
    let rid = c.next_id(id);
    let set = react(c, &rid, message_id, emojis);
    set["reactions"].as_list()[0].as_object().unwrap()["emojis"].clone()
}

fn catalog_url(frame: &Object) -> Option<String> {
    let url = frame["ext"].as_object()?.get("emoji")?.as_object()?["catalog_url"].as_str()?;
    Some(url.to_owned())
}

fn capabilities(frame: &Object) -> Vec<Json> {
    frame["capabilities"].as_list().to_vec()
}

/// Adds, replaces and removes custom emoji with `/emoji`, publishing each
/// catalog at a new catalog_url.
#[test]
fn test_emoji_command_publishes_catalogs() {
    let server = admin_test_server();
    let mut ada = admin(&server);
    let (watcher, first_frame) = dial_raw(&server);
    let mut user = account(&server);
    let before = notification_params(&first_frame, "server");
    assert!(!capabilities(&before).contains(&Json::from("ext:emoji")));
    assert_eq!(catalog_url(&before), None);
    let limit = Json::from(obj! {"max_bytes" => 256i64 << 10});
    let emoji = before["ext"].as_object().unwrap()["media"]
        .as_object()
        .unwrap()["emoji"]
        .clone();
    assert_eq!(
        emoji,
        Json::from(
            obj! {"image/png" => limit.clone(), "image/jpeg" => limit.clone(), "image/gif" => limit.clone(), "image/webp" => limit}
        )
    );

    assert!(private_reply(&mut ada, "/help").contains("`/emoji add|remove :name:`"));
    let id = user.next_id("not-admin");
    user.expect_error(
        "command",
        &id,
        obj! {"body" => obj! {"text" => "/emoji add :mine:", "embeds" => upload_embed()}},
        CODE_DENIED,
    );
    let long = format!("/emoji add :{}:", "x".repeat(33));
    for text in [
        "/emoji add partyparrot",
        "/emoji add :partyparrot:",
        "/emoji remove :partyparrot:",
        "/emoji",
        long.as_str(),
    ] {
        let id = ada.next_id("bad");
        let embeds = if text.ends_with("partyparrot") || text.ends_with("x:") {
            upload_embed()
        } else {
            Vec::new()
        };
        ada.expect_error(
            "command",
            &id,
            obj! {"body" => obj! {"text" => text, "embeds" => embeds}},
            CODE_INVALID_PARAMS,
        );
    }
    // Not an image: refused, and nothing changes.
    assert_eq!(
        add(&mut ada, ":partyparrot:", b"OggS not an image", "audio/ogg"),
        415
    );

    // An image becomes the key's, and every connection gets a new frame.
    assert_eq!(
        add(&mut ada, ":partyparrot:", &png(64, 32), "image/png"),
        201
    );
    let first = next_server(&watcher);
    assert!(capabilities(&first).contains(&Json::from("ext:emoji")));
    let first_url = catalog_url(&first).unwrap();
    let hash = first_url
        .strip_prefix(&format!("{}/emoji/", server.http.url))
        .and_then(|name| name.strip_suffix(".json"))
        .unwrap_or_else(|| panic!("{first_url}"));
    assert!(
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "{hash}"
    );
    assert_eq!(
        catalog_url(&next_server(&user)).as_deref(),
        Some(first_url.as_str())
    );
    let (status, cache, body) = get(&first_url);
    assert_eq!(status, 200);
    assert_eq!(
        cache.as_deref(),
        Some("public, max-age=31536000, immutable")
    );
    let catalog = decode_frame(&body);
    let entry = catalog[":partyparrot:"].as_object().unwrap().clone();
    assert_eq!(entry["width"], Json::from(64i64));
    assert_eq!(entry["height"], Json::from(32i64));
    assert_eq!(catalog.len(), 1);
    let first_image = entry["url"].as_str().unwrap().to_owned();
    assert!(
        first_image.starts_with(&format!("{}/files/", server.http.url)),
        "{first_image}"
    );
    let (status, cache, _) = get(&first_image);
    assert_eq!(status, 200);
    assert_eq!(
        cache.as_deref(),
        Some("public, max-age=31536000, immutable")
    );
    let (_, late) = dial_raw(&server);
    assert_eq!(
        catalog_url(&notification_params(&late, "server")),
        Some(first_url.clone())
    );

    // Reactions take keys the catalog has, beside emoji sequences.
    let (posted, _) = save(&mut user, "post", obj! {"body" => obj! {"text" => "party"}});
    assert_eq!(
        reacted(&mut user, "react", &posted, &[":partyparrot:", "\u{2764}"]),
        strings(&[":partyparrot:", "\u{2764}\u{FE0F}"])
    );
    react_error(&mut user, "unknown", &posted, &[":nope:"]);
    react_error(&mut user, "case", &posted, &[":PartyParrot:"]);

    // A new image replaces the old; the catalog before, and the old image it
    // refers to, stay until the next change.
    assert_eq!(
        add(&mut ada, ":partyparrot:", &png(16, 16), "image/png"),
        201
    );
    let second_url = catalog_url(&next_server(&watcher)).unwrap();
    next_server(&user);
    assert_ne!(second_url, first_url);
    let replaced = decode_frame(&get(&second_url).2);
    let replaced_entry = replaced[":partyparrot:"].as_object().unwrap();
    assert_eq!(replaced_entry["width"], Json::from(16i64));
    let replaced_image = replaced_entry["url"].as_str().unwrap().to_owned();
    assert_eq!(get(&first_image).0, 200);
    assert_eq!(get(&first_url).0, 200);

    // Removing the last one withdraws the extension, and deletes the catalog
    // two back with the image only it had.
    assert_eq!(
        private_reply(&mut ada, "/emoji remove :partyparrot:"),
        "Removed the custom emoji `:partyparrot:`."
    );
    let after = next_server(&watcher);
    next_server(&user);
    assert!(!capabilities(&after).contains(&Json::from("ext:emoji")));
    assert_eq!(catalog_url(&after), None);
    assert_eq!(get(&first_image).0, 404);
    assert_eq!(get(&first_url).0, 404);
    assert_eq!(get(&second_url).0, 200);
    assert_eq!(get(&replaced_image).0, 200);
    // A removed key stays in a set that has it; nobody takes it up.
    assert_eq!(
        reacted(&mut user, "kept", &posted, &[":partyparrot:"]),
        strings(&[":partyparrot:"])
    );
    react_error(&mut ada, "taken-up", &posted, &[":partyparrot:"]);
    reacted(&mut user, "cleared", &posted, &[]);
    react_error(&mut user, "gone", &posted, &[":partyparrot:"]);

    // The next change deletes them.
    assert_eq!(add(&mut ada, ":confetti:", &png(8, 8), "image/png"), 201);
    assert!(capabilities(&next_server(&watcher)).contains(&Json::from("ext:emoji")));
    assert_eq!(get(&replaced_image).0, 404);
    assert_eq!(get(&second_url).0, 404);
    private_reply(&mut ada, "/emoji remove :confetti:");
    assert!(!capabilities(&next_server(&watcher)).contains(&Json::from("ext:emoji")));
}

/// Mods and friends run `/emoji` as admins do, and no other role does
/// (apron-server-cloudflare's EMOJI_ROLES; its uploads integration test).
#[test]
fn test_mods_and_friends_use_emoji() {
    let server = admin_test_server();
    let mut user = account(&server);
    let id = user.user_id.clone();
    let denied = |c: &mut TestClient, text: &str| {
        let request_id = c.next_id("denied");
        let frame = reply(
            c,
            "command",
            &request_id,
            obj! {"body" => obj! {"text" => text}},
        );
        let error = frame["error"]
            .as_object()
            .unwrap_or_else(|| panic!("{frame:?}"));
        assert_eq!(error["code"], Json::from(CODE_DENIED), "{frame:?}");
        error["message"].as_str().unwrap().to_owned()
    };

    grant_role(&server, &id, "helper");
    assert!(!private_reply(&mut user, "/help").contains("/emoji"));
    assert_eq!(
        denied(&mut user, "/emoji remove :mine:"),
        "/emoji needs one of the roles admin, mod, friend"
    );

    grant_role(&server, &id, "friend");
    assert!(private_reply(&mut user, "/help").contains("`/emoji add|remove :name:`"));
    assert_eq!(add(&mut user, ":mine:", &png(8, 8), "image/png"), 201);
    assert_eq!(
        private_reply(&mut user, "/emoji remove :mine:"),
        "Removed the custom emoji `:mine:`."
    );

    revoke_role(&server, &id, "friend");
    grant_role(&server, &id, "mod");
    assert_eq!(add(&mut user, ":ours:", &png(8, 8), "image/png"), 201);
    private_reply(&mut user, "/emoji remove :ours:");
    // Neither role runs an admin command.
    assert_eq!(
        denied(&mut user, "/server"),
        "Only an admin can use /server"
    );
}

/// At the cap a new key is denied and a known one may still be replaced; a
/// name of 32 characters is the longest; uploads off refuse an add.
#[test]
fn test_emoji_limits() {
    let server = new_test_server(Config {
        max_emoji: 2,
        ..admin_config()
    });
    let mut ada = admin(&server);
    let longest = format!(":{}:", "x".repeat(32));
    assert_eq!(add(&mut ada, &longest, &png(1, 1), "image/png"), 201);
    assert_eq!(add(&mut ada, ":b:", &png(1, 1), "image/png"), 201);
    let id = ada.next_id("third");
    ada.expect_error(
        "command",
        &id,
        obj! {"body" => obj! {"text" => "/emoji add :c:", "embeds" => upload_embed()}},
        CODE_DENIED,
    );
    assert_eq!(add(&mut ada, ":b:", &png(2, 2), "image/png"), 201);
    let too_big = vec![0u8; (256 << 10) + 1];
    assert_eq!(add(&mut ada, ":b:", &too_big, "image/png"), 413);
    private_reply(&mut ada, "/toggle uploads");
    let id = ada.next_id("off");
    ada.expect_error(
        "command",
        &id,
        obj! {"body" => obj! {"text" => "/emoji add :b:", "embeds" => upload_embed()}},
        CODE_DENIED,
    );
    let st = server.app.lock();
    let keys: Vec<&String> = st.emoji.entries.keys().collect();
    assert_eq!(keys, [&":b:".to_owned(), &longest]);
    assert_eq!(st.emoji.entries[":b:"].width, 2);
}

/// A new key's write that finishes after another add filled the catalog
/// fails, as on Cloudflare, rather than succeeding and dropping the image.
#[test]
fn test_emoji_add_that_no_longer_fits_fails() {
    let server = new_test_server(Config {
        max_emoji: 1,
        ..admin_config()
    });
    let mut ada = admin(&server);
    let (_, first) = command_with(&mut ada, "/emoji add :one:", upload_embed());
    let (_, second) = command_with(&mut ada, "/emoji add :two:", upload_embed());
    assert_eq!(
        http_do("PUT", &write_url(&first), Some(&png(1, 1)), "image/png").0,
        201
    );
    next_server(&ada);
    let (status, _, body) = http_do("PUT", &write_url(&second), Some(&png(1, 1)), "image/png");
    assert_eq!(status, 410, "{}", String::from_utf8_lossy(&body));
    assert!(
        String::from_utf8_lossy(&body).contains("at most 1 custom emoji"),
        "{}",
        String::from_utf8_lossy(&body)
    );
    let st = server.app.lock();
    assert_eq!(st.emoji.entries.keys().collect::<Vec<_>>(), [":one:"]);
    assert_eq!(st.embeds.len(), 1, "the refused image was kept");
}

/// The catalog, its URL and the previous catalog survive a restart.
#[test]
fn test_emoji_catalog_persists() {
    let dir = TempDir::new("apron-emoji-");
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let configure = |config: &mut Config| {
        *config = Config {
            store: config.store.take(),
            upload_dir: config.upload_dir.clone(),
            ..admin_config()
        };
    };
    let mut server = start_with(kept.clone(), &format!("{dir}/a"), configure);
    let mut ada = admin(&server);
    let (watcher, _) = dial_raw(&server);
    assert_eq!(add(&mut ada, ":a:", &png(4, 4), "image/png"), 201);
    let first = catalog_url(&next_server(&watcher)).unwrap();
    assert_eq!(add(&mut ada, ":b:", &png(4, 4), "image/png"), 201);
    let second = catalog_url(&next_server(&watcher)).unwrap();
    let (previous, current) = {
        let st = server.app.lock();
        (
            st.emoji.previous.clone().unwrap(),
            st.emoji.current.clone().unwrap(),
        )
    };
    drop(ada);
    server.stop();

    let server = start_with(kept, &format!("{dir}/a"), configure);
    let (_, frame) = dial_raw(&server);
    let url = catalog_url(&notification_params(&frame, "server")).unwrap();
    assert_eq!(
        url.rsplit('/').next(),
        second.rsplit('/').next(),
        "the same catalog"
    );
    let st = server.app.lock();
    assert_eq!(st.emoji.current.as_ref(), Some(&current));
    assert_eq!(st.emoji.previous.as_ref(), Some(&previous));
    assert!(first.ends_with(&format!("{}.json", previous.hash)));
}

/// An avatar's, a custom emoji's or the server's avatar's write whose
/// declared type is not an image type it keeps is 415 before the body is
/// read, and stays open; parameters are ignored (Cloudflare's "refuses
/// what is not an image").
#[test]
fn test_declared_non_image_types_are_refused_before_the_body() {
    let server = admin_test_server();
    let mut ada = admin(&server);
    for command in ["/avatar", "/emoji add :late:", "/server avatar"] {
        let (_, started) = command_with(&mut ada, command, upload_embed());
        let url = write_url(&started);
        for declared in ["text/plain", "image/svg+xml", "audio/ogg; codecs=opus"] {
            let (status, _, body) = http_do("PUT", &url, Some(&png(8, 8)), declared);
            assert_eq!(status, 415, "{command} declared {declared}");
            assert!(
                String::from_utf8_lossy(&body).contains("PNG, JPEG, GIF, or WebP")
                    || String::from_utf8_lossy(&body).contains("PNG, JPEG, GIF, and WebP"),
                "{command}: {}",
                String::from_utf8_lossy(&body)
            );
        }
        let declared = "Image/PNG; charset=binary";
        assert_eq!(
            http_do("PUT", &url, Some(&png(8, 8)), declared).0,
            201,
            "{command} after the refusals"
        );
        ada.drain();
    }
}

/// An add whose key is removed while its image is on the way is dropped,
/// and the key stays removed.
#[test]
fn test_emoji_add_dropped_when_its_key_is_removed() {
    let server = admin_test_server();
    let mut ada = admin(&server);
    assert_eq!(add(&mut ada, ":x:", &png(1, 1), "image/png"), 201);
    let (_, replacing) = command_with(&mut ada, "/emoji add :x:", upload_embed());
    private_reply(&mut ada, "/emoji remove :x:");
    let status = http_do("PUT", &write_url(&replacing), Some(&png(1, 1)), "image/png").0;
    assert_eq!(status, 404, "the write after the removal");
    let st = server.app.lock();
    assert!(st.emoji.entries.is_empty(), "the removed key came back");
}

/// An add whose sender lost every emoji role while its image was on the
/// way is dropped.
#[test]
fn test_emoji_add_dropped_when_the_sender_loses_the_role() {
    let server = admin_test_server();
    let mut user = account(&server);
    let id = user.user_id.clone();
    grant_role(&server, &id, "friend");
    let (_, started) = command_with(&mut user, "/emoji add :mine:", upload_embed());
    revoke_role(&server, &id, "friend");
    let (status, _, body) = http_do("PUT", &write_url(&started), Some(&png(1, 1)), "image/png");
    assert_eq!(status, 403, "{}", String::from_utf8_lossy(&body));
    let st = server.app.lock();
    assert!(st.emoji.entries.is_empty(), "the image became an emoji");
    assert!(st.embeds.is_empty(), "the refused image was kept");
    drop(st);

    // A rename keeps the sender's add, as they keep their roles.
    grant_role(&server, &id, "friend");
    let mut ada = admin(&server);
    let (_, started) = command_with(&mut user, "/emoji add :mine:", upload_embed());
    private_reply(&mut ada, &format!("/rename {id} renamed"));
    let status = http_do("PUT", &write_url(&started), Some(&png(1, 1)), "image/png").0;
    assert_eq!(status, 201, "an add across a rename");
    assert!(server.app.lock().emoji.entries.contains_key(":mine:"));
}
