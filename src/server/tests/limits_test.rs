//! limits_test.go, test by test. Each keeps the Go test's name, tables, and
//! literal expectations.

use rust_stdlib::os::{self, FileMode};
use rust_stdlib::path::filepath;

use super::helpers::*;
use crate::obj;
use crate::server::embeds::{MAX_EMBEDS_PER_MESSAGE, UPLOAD_SUFFIX};
use crate::server::limits::Posts;
use crate::server::messages::MAX_MENTIONS;
use crate::server::protocol::*;
use crate::server::push::MAX_PUSH_URL_BYTES;
use crate::server::server::RETRY_AFTER_SECONDS;
use crate::server::users::MAX_PROFILE_EXT_BYTES;

fn write_urls(result: &Object) -> Vec<String> {
    result["embeds"]
        .as_list()
        .iter()
        .map(|value| {
            value.as_object().unwrap()["write_url"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

fn put(write_url: &str, size: usize) -> u16 {
    http_do("PUT", write_url, Some(&png_of_size(size)), "image/png").0
}

fn upload_files(dir: &str) -> Vec<String> {
    filepath::glob(&format!("{dir}/*{UPLOAD_SUFFIX}")).unwrap()
}

#[test]
fn test_uploads_are_stored_on_disk_within_limits() {
    let dir = TempDir::new("uploads-test-");
    let stale = format!("{dir}/left-by-an-earlier-run{UPLOAD_SUFFIX}");
    let other = format!("{dir}/notes.txt");
    for name in [&stale, &other] {
        os::write_file(name, b"x", FileMode(0o600)).unwrap();
    }
    let mut config = default_config();
    config.upload_dir = dir.to_string();
    config.max_upload_bytes = 100;
    config.max_message_upload_bytes = 150;
    config.max_upload_storage_bytes = 250;
    let server = new_test_server(config);
    match os::stat(&stale) {
        Err(e) if os::is_not_exist(&e) => {}
        kept => panic!("stale upload file kept: {:?}", kept.map(|_| ())),
    }
    if let Err(e) = os::stat(&other) {
        panic!("unrelated file removed: {e}");
    }
    let mut a = dial_test_client(&server);

    // One message's uploads share max_message_upload_bytes.
    let first = post_embeds(
        &mut a,
        "first",
        obj! {"room_id" => "general", "body" => obj! {
            "embeds" => vec![Json::from(obj! {"kind" => "upload"}), Json::from(obj! {"kind" => "upload"})],
        }},
    );
    let urls = write_urls(&first);
    assert_eq!(put(&urls[0], 100), 201, "first upload");
    let first_file = embeds_of(&a.notification("message")).remove(0)["url"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        put(&urls[1], 100),
        413,
        "upload beyond the message's budget"
    );
    let left = embeds_of(&a.notification("message"));
    assert_eq!(left.len(), 1, "after the refused upload: {left:?}");

    let second = post_embeds(
        &mut a,
        "second",
        obj! {"room_id" => "general", "body" => obj! {"embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
    );
    assert_eq!(put(&write_urls(&second)[0], 100), 201, "second upload");
    let second_file = embeds_of(&a.notification("message")).remove(0)["url"]
        .as_str()
        .unwrap()
        .to_owned();
    let files = upload_files(&dir);
    assert_eq!(files.len(), 2, "upload files: {files:?}");

    // Past max_upload_storage_bytes the oldest upload leaves its message.
    let third = post_embeds(
        &mut a,
        "third",
        obj! {"room_id" => "general", "body" => obj! {"embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
    );
    assert_eq!(put(&write_urls(&third)[0], 100), 201, "third upload");
    let completed = a.notification("message");
    assert_eq!(
        completed.get("message_id"),
        third.get("message_id"),
        "expected the third upload to complete first: {completed:?}"
    );
    let evicted = a.notification("message");
    assert!(
        evicted.get("message_id") == first.get("message_id") && embeds_of(&evicted).is_empty(),
        "eviction: {evicted:?}"
    );
    assert_eq!(http_do("GET", &first_file, None, "").0, 404, "evicted file");
    assert_eq!(http_do("GET", &second_file, None, "").0, 200, "kept file");
    let files = upload_files(&dir);
    assert_eq!(files.len(), 2, "upload files after eviction: {files:?}");
    drop(a);
    drop(server);
}

#[test]
fn test_messages_are_limited_to_max_embeds() {
    let server = new_test_server(default_config());
    let mut a = dial_test_client(&server);
    let embeds: Vec<Json> = (0..=MAX_EMBEDS_PER_MESSAGE)
        .map(|_| Json::from(obj! {"kind" => "upload"}))
        .collect();
    // A count limit the server sets is denied (§1.1).
    a.expect_error(
        "message",
        "many",
        obj! {"room_id" => "general", "body" => obj! {"embeds" => embeds}},
        CODE_DENIED,
    );
    let mentions: Vec<Json> = (0..=MAX_MENTIONS)
        .map(|i| Json::from(format!("user{i}")))
        .collect();
    a.expect_error(
        "message",
        "mentions",
        obj! {"room_id" => "general", "body" => obj! {"text" => "hi", "mentions" => mentions.clone()}},
        CODE_DENIED,
    );
    a.expect_error(
        "command",
        "command-mentions",
        obj! {"room_id" => "general", "body" => obj! {"text" => "/help", "mentions" => mentions}},
        CODE_DENIED,
    );
    // A malformed value stays invalid_params.
    a.expect_error(
        "message",
        "bad-mentions",
        obj! {"room_id" => "general", "body" => obj! {"text" => "hi", "mentions" => vec![Json::from("")]}},
        CODE_INVALID_PARAMS,
    );
    a.expect_quiet();
}

#[test]
fn test_room_set_counts_toward_posts_per_minute() {
    let mut config = default_config();
    config.limits.guest_posts = Posts { minute: 1, day: 0 };
    let server = new_test_server(config);
    let mut a = dial_test_client(&server);
    grant_role(&server, &a.user_id, "mod");
    save_room(&mut a, "create", obj! {"title" => "Ops"});
    let frame = a.call("room_set", "again", obj! {"title" => "More"});
    assert_eq!(
        error_code(&frame),
        Some(Json::from(CODE_RETRY_AFTER)),
        "second room_set: {frame:?}"
    );
    let frame = a.call(
        "message",
        "post",
        obj! {"room_id" => "general", "body" => obj! {"text" => "hi"}},
    );
    assert_eq!(
        error_code(&frame),
        Some(Json::from(CODE_RETRY_AFTER)),
        "message after room_set: {frame:?}"
    );
}

fn error_code(frame: &Object) -> Option<Json> {
    frame
        .get("error")
        .and_then(Json::as_object)
        .and_then(|failure| failure.get("code"))
        .cloned()
}

#[test]
fn test_history_pages_are_bounded_and_records_unescaped() {
    let server = new_test_server(large_frames_config());
    let mut a = dial_test_client(&server);
    save(
        &mut a,
        "markup",
        obj! {"body" => obj! {"text" => "<a & b>"}},
    );
    let raw = {
        let st = server.app.lock();
        let last = *st.rooms["general"].log.last().unwrap();
        String::from_utf8_lossy(&st.records[&last].raw).into_owned()
    };
    assert!(
        raw.contains("<a & b>"),
        "stored record escapes markup: {raw}"
    );

    // 100 KiB texts: two fit the 256 KiB reply, three do not.
    let large = "x".repeat(100 << 10);
    const POSTS: u8 = 6;
    for i in 0..POSTS {
        save(
            &mut a,
            &format!("large-{}", (b'a' + i) as char),
            obj! {"body" => obj! {"text" => large.as_str()}},
        );
    }
    let page = history_page(&mut a, "general", obj! {"limit" => 50i64});
    let newest = log_ids(&page, "messages");
    assert_eq!(
        (newest.len(), page.get("more")),
        (2, Some(&Json::from(true))),
        "first page"
    );
    assert!(
        page.get("last_log_id") == Some(&Json::from(newest.last().unwrap().as_str()))
            && page.get("first_log_id").is_some_and(|v| *v != Json::Null),
        "page bounds: {:?} {:?}",
        page.get("first_log_id"),
        page.get("last_log_id")
    );
    let before = parse_id(page.get("first_log_id")) - 1;
    let rest = history_page(
        &mut a,
        "general",
        obj! {"limit" => 50i64, "before" => format_id(before)},
    );
    assert_eq!(log_ids(&rest, "messages").len(), 2, "second page");
}

/// Pages hold 20 records by default and at most 50 (apron-server-
/// cloudflare's history_default_limit and history_max_limit).
#[test]
fn test_history_page_sizes() {
    let server = new_test_server(default_config());
    let mut a = dial_test_client(&server);
    for i in 0..60 {
        save(
            &mut a,
            &format!("m{i}"),
            obj! {"body" => obj! {"text" => "x"}},
        );
    }
    let count = |page: &Object| -> usize {
        ["rooms", "messages", "reactions", "memberships"]
            .iter()
            .map(|key| log_ids(page, key).len())
            .sum()
    };
    assert_eq!(count(&history_page(&mut a, "general", Object::new())), 20);
    assert_eq!(
        count(&history_page(&mut a, "general", obj! {"limit" => 1000i64})),
        50
    );
}

/// History pages count against the user's minute, past which a request
/// is refused with the `read` category; a request that serves no page is
/// not counted.
#[test]
fn test_history_rate_limit_names_read() {
    let mut config = default_config();
    config.limits.user_history = crate::server::limits::Rate {
        per_minute: 1,
        burst: 2,
    };
    let server = new_test_server(config);
    let mut a = dial_test_client(&server);
    a.expect_error(
        "history",
        "unknown",
        obj! {"room_id" => "nowhere"},
        CODE_INVALID_PARAMS,
    );
    history_page(&mut a, "general", Object::new());
    history_page(&mut a, "general", Object::new());
    let frame = a.call("history", "over", obj! {"room_id" => "general"});
    let (message, data) = retry_after_of(&frame);
    assert_eq!(message, "History request limit reached");
    assert_eq!(data["ext"], Json::from(obj! {"limits" => "read"}));
}

#[test]
fn test_profile_and_push_size_limits() {
    let mut config = large_frames_config();
    config.allow_insecure_push = true;
    config.web_authn = Some(super::webauthn_test::test_web_authn());
    let server = new_test_server(config);
    let mut a = super::admin_test::account(&server);
    // A value rejected for its size is too_large (§1.1).
    a.expect_error(
        "me",
        "ext",
        obj! {"ext" => obj! {"x" => "y".repeat(MAX_PROFILE_EXT_BYTES)}},
        CODE_TOO_LARGE,
    );
    a.expect_error(
        "push_register",
        "url",
        obj! {"kind" => "relay", "url" => format!("http://relay.example/{}", "p".repeat(MAX_PUSH_URL_BYTES))},
        CODE_TOO_LARGE,
    );
}

#[test]
fn test_connection_and_rate_limits() {
    let mut config = default_config();
    config.max_connections = 1;
    config.limits.guest_posts = Posts { minute: 2, day: 0 };
    let server = new_test_server(config);
    let mut a = dial_test_client(&server);

    // Over capacity: the server frame, then an error without id, then
    // close, with no welcome.
    let (b, _) = dial_server_frame(&server, &[]);
    let failure = b.read();
    let error = failure["error"].as_object().unwrap();
    assert!(
        !failure.contains_key("id")
            && error.get("code") == Some(&Json::from(CODE_RETRY_AFTER))
            && error["data"].as_object().unwrap().get("retry_after")
                == Some(&Json::from(RETRY_AFTER_SECONDS)),
        "capacity error: {failure:?}"
    );

    save(&mut a, "one", obj! {"body" => obj! {"text" => "1"}});
    save(&mut a, "two", obj! {"body" => obj! {"text" => "2"}});
    let frame = a.call(
        "message",
        "three",
        obj! {"room_id" => "general", "body" => obj! {"text" => "3"}},
    );
    let limited = frame["error"].as_object().unwrap();
    let retry_after = match limited["data"].as_object().unwrap().get("retry_after") {
        Some(Json::Number(n)) => *n,
        other => panic!("retry_after {other:?}"),
    };
    assert!(
        limited.get("code") == Some(&Json::from(CODE_RETRY_AFTER)) && retry_after >= 1.0,
        "rate limit: {frame:?}"
    );
}
