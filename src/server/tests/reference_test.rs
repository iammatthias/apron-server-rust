//! reference_test.go, test by test. Each keeps the Go test's name, tables,
//! and literal expectations.

use std::io::{Read, Write};
use std::sync::{mpsc, Arc};

use rust_stdlib::context::Context;
use rust_stdlib::io::PipeWriter;
use rust_stdlib::net::http;
use rust_stdlib::time::Duration;

use super::helpers::*;
use crate::obj;
use crate::server::default_config;
use crate::server::embeds::{
    upload_content_type, valid_avatar_image, FILE_PATH, STREAM_PATH, WRITE_PATH,
};
use crate::server::protocol::*;
use crate::server::rooms::MAX_LISTED_ROOMS;
use crate::server::users::{normalize_name, MAX_NAME_RUNES};
use crate::ws;

/// After a guest joins general and posts one message, room_list reports the
/// message's log_id as general's latest_log_id, not the earlier membership's.
/// Phase 1a's smoke diff masked ids, which could not tell the two apart.
#[test]
fn test_room_list_latest_log_id_is_the_last_record() {
    let server = new_test_server(default_config());
    let mut a = dial_test_client(&server);
    let (message_id, _) = save(&mut a, "m1", obj! {"body" => obj! {"text" => "hello"}});
    let listed = list_rooms(&mut a, obj! {"members" => true});
    let general = listed["joined"].as_list()[0].as_object().unwrap();
    assert_eq!(
        general["latest_log_id"],
        Json::from(message_id.as_str()),
        "general after one message: {general:?}"
    );
    let page = history_page(&mut a, "general", Object::new());
    let memberships = log_ids(&page, "memberships");
    assert!(
        memberships.len() == 1 && memberships[0].as_str() < message_id.as_str(),
        "the join precedes the message: {memberships:?} vs {message_id}"
    );
    assert_eq!(page["latest_log_id"], Json::from(message_id.as_str()));
}

#[test]
fn test_uploads_are_hosted_with_open_graph() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let (mut a, b) = (clients.remove(0), clients.remove(0));
    // The pending snapshot precedes the result carrying the write URL (§1).
    let (before, result) = a.request(
        "message",
        "attach",
        obj! {"room_id" => "general", "body" => obj! {
            "text" => "Before the fix:",
            "embeds" => vec![
                Json::from(obj! {"kind" => "upload", "title" => "dots.png", "url" => "https://forged.example/x", "og" => obj! {"image" => obj! {"alt" => "Three dots"}}}),
                Json::from(obj! {"kind" => "iframe", "url" => "https://backend.example/term", "height" => 300i64}),
            ],
        }},
    );
    assert!(
        before.len() == 1,
        "frames before the upload result: {before:?}"
    );
    let pending = notification_params(&before[0], "message");
    let written = result["embeds"].as_list();
    assert!(written.len() == 1, "written embeds: {result:?}");
    let write = written[0].as_object().unwrap();
    let embed_id = write["embed_id"].as_str().unwrap().to_owned();
    let write_url = write["write_url"].as_str().unwrap().to_owned();
    assert!(
        write["kind"] == Json::from("upload")
            && write_url.starts_with(&format!("{}{WRITE_PATH}", server.http.url)),
        "write: {write:?}"
    );
    b.notification("message");
    let embeds = embeds_of(&pending);
    assert!(
        embeds[0]
            == obj! {"embed_id" => embed_id.as_str(), "kind" => "upload", "title" => "dots.png"}
            && embeds[1].contains_key("embed_id")
            && embeds[1]["url"] == Json::from("https://backend.example/term"),
        "pending embeds: {embeds:?}"
    );

    let image = test_png();
    let (status, _, _) = http_do("PUT", &write_url, Some(&image), "image/png");
    assert_eq!(status, 201, "upload status");
    let completed = a.notification("message");
    b.notification("message");
    let upload = embeds_of(&completed).remove(0);
    let file_url = upload["url"].as_str().unwrap_or("").to_owned();
    let want_og = obj! {"title" => "dots.png", "image" => obj! {"url" => file_url.as_str(), "type" => "image/png", "width" => 3i64, "height" => 2i64, "alt" => "Three dots"}};
    assert!(
        file_url.starts_with(&format!("{}{FILE_PATH}{embed_id}/", server.http.url))
            && upload["og"] == Json::from(want_og.clone())
            && completed["prev_log_id"] == pending["log_id"],
        "completed upload: {completed:?}"
    );
    let (status, header, content) = http_do("GET", &file_url, None, "");
    assert!(
        status == 200
            && content == image
            && header.get("Content-Type") == Some("image/png")
            && header.get("X-Content-Type-Options") == Some("nosniff")
            && header
                .get("Content-Security-Policy")
                .is_some_and(|v| v.starts_with("sandbox"))
            && header
                .get("Content-Disposition")
                .is_some_and(|v| v.starts_with("inline")),
        "file: {status} {header:?}"
    );
    let wrong = format!("{}{FILE_PATH}{embed_id}/wrong", server.http.url);
    assert_eq!(http_do("GET", &wrong, None, "").0, 404, "wrong secret");
    assert_eq!(
        http_do("PUT", &write_url, Some(b"again"), "").0,
        404,
        "reused write URL"
    );

    // A save keeps an embed by embed_id; the server restores what it owns.
    let message_id = result["message_id"].as_str().unwrap().to_owned();
    let kept = vec![
        Json::from(
            obj! {"embed_id" => embed_id.as_str(), "kind" => "stream", "title" => "renamed.png", "url" => "https://forged.example/y"},
        ),
        Json::from(embeds[1].clone()),
    ];
    let (_, edited) = save(
        &mut a,
        "keep",
        obj! {"message_id" => message_id.as_str(), "body" => obj! {"text" => "edited", "embeds" => kept}},
    );
    b.notification("message");
    let restored = embeds_of(&edited).remove(0);
    assert!(
        restored["kind"] == Json::from("upload")
            && restored["url"] == Json::from(file_url.as_str())
            && restored["og"] == Json::from(want_og)
            && restored["title"] == Json::from("renamed.png"),
        "restored embed: {restored:?}"
    );
    a.expect_error(
        "message",
        "unknown",
        obj! {"message_id" => message_id.as_str(), "room_id" => "general", "body" => obj! {"embeds" => vec![Json::from(obj! {"embed_id" => "embed_999", "kind" => "upload"})]}},
        CODE_INVALID_PARAMS,
    );

    // Removing the embed deletes its content.
    save(
        &mut a,
        "remove",
        obj! {"message_id" => message_id.as_str(), "body" => obj! {"text" => "no file"}},
    );
    b.notification("message");
    assert_eq!(http_do("GET", &file_url, None, "").0, 404, "removed file");
}

#[test]
fn test_upload_types_that_could_run_are_served_as_downloads() {
    for (declared, want) in [
        ("image/png", "image/png"),
        ("application/pdf", "application/pdf"),
        ("text/html", "text/plain"),
        ("text/ecmascript", "text/plain"),
        ("text/css", "text/plain"),
        ("text/xsl", "text/plain"),
        ("application/wasm", "text/plain"),
    ] {
        assert_eq!(
            upload_content_type(declared, b"hello"),
            want,
            "{declared}: served as"
        );
    }
    assert_eq!(
        upload_content_type("text/css", b"<html><script>"),
        "application/octet-stream",
        "sniffed markup"
    );
}

#[test]
fn test_avatar_uploads_must_be_images() {
    let dir = TempDir::new("avatar-test-");
    let check = |content_type: &str, data: &[u8]| -> bool {
        let file = rust_stdlib::os::create_temp(&dir, "avatar").unwrap();
        std::io::Write::write_all(&mut &file, data).unwrap();
        let valid = valid_avatar_image(content_type, Some(&file));
        file.close().unwrap();
        valid
    };
    assert!(check("image/png", &test_png()), "a PNG was refused");
    let webp = rust_stdlib::encoding::base64::STANDARD
        .decode("UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA==")
        .unwrap();
    assert!(check("image/webp", &webp), "a WebP was refused");
    assert!(
        !check("image/png", b"not an image")
            && !check("image/jpeg", &test_png())
            && !check("image/webp", b"RIFF\x00\x00\x00\x00WEBPVP8 "),
        "a mismatched avatar was accepted"
    );
}

#[test]
fn test_failed_and_expired_writes_drop_the_embed() {
    let mut config = default_config();
    config.max_upload_bytes = 4;
    config.upload_start_timeout = Duration::from_millis(100);
    let server = new_test_server(config);
    let mut a = dial_test_client(&server);
    let result = post_embeds(
        &mut a,
        "two",
        obj! {"room_id" => "general", "body" => obj! {
            "embeds" => vec![Json::from(obj! {"kind" => "upload"}), Json::from(obj! {"kind" => "stream"})],
        }},
    );
    let written = result["embeds"].as_list();
    let large = written[0].as_object().unwrap()["write_url"]
        .as_str()
        .unwrap();
    assert_eq!(
        http_do("PUT", large, Some(b"too large"), "text/plain").0,
        413,
        "oversized upload"
    );
    let left = embeds_of(&a.notification("message"));
    assert!(
        left.len() == 1 && left[0]["kind"] == Json::from("stream"),
        "after failed upload: {left:?}"
    );
    // The stream's write URL is never used, so it expires.
    let expired = a.notification("message");
    assert!(embeds_of(&expired).is_empty(), "after expiry: {expired:?}");
    let late = written[1].as_object().unwrap()["write_url"]
        .as_str()
        .unwrap();
    assert_eq!(
        http_do("PUT", late, Some(b"late"), "").0,
        404,
        "expired write URL"
    );
}

/// Starts a PUT of what is written to the returned pipe, as Go's tests do
/// with an `io.Pipe` body in a goroutine; the receiver gets the status, or
/// 0 when the request failed. The status is sent before the response body
/// is closed, where Go closes it first: rust-stdlib's close waits for the
/// request body to end, which a reply that comes before the body ends
/// would otherwise wait on.
fn put_from_pipe(write_url: &str) -> (PipeWriter, mpsc::Receiver<u16>) {
    let (body, pipe) = rust_stdlib::io::pipe();
    let (done, status) = mpsc::channel();
    let request = http::Request::new("PUT", write_url)
        .unwrap()
        .with_body(http::RequestBody::reader(body));
    std::thread::spawn(
        move || match http::client::DEFAULT_CLIENT.do_request(request) {
            Ok(response) => {
                let _ = done.send(response.status_code);
                if let Some(body) = &response.body {
                    let _ = body.close();
                }
            }
            Err(_) => {
                let _ = done.send(0);
            }
        },
    );
    (pipe, status)
}

/// Waits for a writer's status, failing rather than hanging.
fn writer_status(status: &mpsc::Receiver<u16>) -> u16 {
    status
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the writer never finished")
}

fn write_urls(result: &Object) -> Vec<String> {
    result["embeds"]
        .as_list()
        .iter()
        .map(|e| {
            e.as_object().unwrap()["write_url"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[test]
fn test_streams_grow_live_then_keep_their_text() {
    let mut config = default_config();
    config.stream_keep_bytes = 16;
    config.stream_max_bytes = 64;
    let server = new_test_server(config);
    let mut a = dial_test_client(&server);
    let result = post_embeds(
        &mut a,
        "stream",
        obj! {"room_id" => "general", "body" => obj! {
            "embeds" => vec![Json::from(obj! {"kind" => "stream", "format" => "terminal", "text" => "forged"})],
        }},
    );
    let write_url = write_urls(&result).remove(0);
    let live = embeds_of(result["snapshot"].as_object().unwrap()).remove(0);
    let stream_url = live["url"].as_str().unwrap_or("").to_owned();
    assert!(
        stream_url.starts_with(&format!("{}{STREAM_PATH}", server.http.url))
            && live["format"] == Json::from("terminal")
            && !live.contains_key("text"),
        "live embed: {live:?}"
    );

    let reader = http::client::get(&stream_url).expect("stream reader");
    assert_eq!(reader.status_code, 200, "stream reader");
    let mut body = reader.body.clone().unwrap();
    let (mut pipe, writer) = put_from_pipe(&write_url);
    pipe.write_all(b"hello ").unwrap();
    let mut first = [0u8; 6];
    body.read_exact(&mut first).expect("live read");
    assert_eq!(&first, b"hello ", "live read");
    let _ = pipe.write_all(b"world, this is a long line\n");
    pipe.close();
    // The second write overflows the 16 kept bytes before the reader catches
    // up, so the reader continues from the kept text.
    let mut rest = Vec::new();
    let _ = body.read_to_end(&mut rest);
    assert_eq!(
        String::from_utf8_lossy(&rest),
        " is a long line\n",
        "reader got {first:?} then {rest:?}"
    );
    assert_eq!(writer_status(&writer), 204, "writer status");
    let finished = embeds_of(&a.notification("message")).remove(0);
    assert!(
        finished["text"] == Json::from(" is a long line\n")
            && !finished.contains_key("url")
            && finished["format"] == Json::from("terminal"),
        "finished embed: {finished:?}"
    );
    assert_eq!(
        http_do("GET", &stream_url, None, "").0,
        404,
        "finished stream URL"
    );

    // At the size limit the stream ends and keeps its trailing text.
    let result = post_embeds(
        &mut a,
        "limited",
        obj! {"room_id" => "general", "body" => obj! {"embeds" => vec![Json::from(obj! {"kind" => "stream"})]}},
    );
    let write_url = write_urls(&result).remove(0);
    let oversized = format!("{}é{}", "x".repeat(63), "y".repeat(20));
    assert_eq!(
        http_do("PUT", &write_url, Some(oversized.as_bytes()), "").0,
        413,
        "oversized stream"
    );
    let text = embeds_of(&a.notification("message")).remove(0)["text"].clone();
    assert_eq!(
        text,
        Json::from(format!("{}\u{FFFD}", "x".repeat(15))),
        "limited text"
    );
}

/// A finished stream write leaves its keep-alive connection usable: a live
/// stream read next on the same connection follows the stream.
#[test]
fn test_stream_write_connection_can_read_a_stream() {
    let server = new_test_server(default_config());
    let mut a = dial_test_client(&server);
    let result = post_embeds(
        &mut a,
        "streams",
        obj! {"room_id" => "general", "body" => obj! {
            "embeds" => vec![Json::from(obj! {"kind" => "stream"}), Json::from(obj! {"kind" => "stream"})],
        }},
    );
    let written = write_urls(&result);
    let live = embeds_of(result["snapshot"].as_object().unwrap());
    // One connection carries the finished write and then the read.
    let client = http::Client {
        transport: Some(Arc::new(http::Transport {
            max_conns_per_host: 1,
            ..http::Transport::default()
        })),
        ..http::Client::default()
    };
    let request = http::Request::new("PUT", &written[0])
        .unwrap()
        .with_body(b"done".to_vec());
    let response = client.do_request(request).expect("first stream write");
    assert_eq!(response.status_code, 204, "first stream write");
    if let Some(body) = &response.body {
        body.close().unwrap();
    }
    let reader = client
        .get(live[1]["url"].as_str().unwrap())
        .expect("stream reader");
    assert_eq!(reader.status_code, 200, "stream reader");
    assert_eq!(
        http_do("PUT", &written[1], Some(b"second"), "text/plain").0,
        204,
        "second stream write"
    );
    let got = reader.body.as_ref().unwrap().read_all().unwrap_or_default();
    assert_eq!(
        String::from_utf8_lossy(&got),
        "second",
        "reader on the write's connection"
    );
}

#[test]
fn test_saving_without_a_stream_ends_it() {
    let server = new_test_server(default_config());
    let mut a = dial_test_client(&server);
    let result = post_embeds(
        &mut a,
        "stream",
        obj! {"room_id" => "general", "body" => obj! {"embeds" => vec![Json::from(obj! {"kind" => "stream"})]}},
    );
    let write_url = write_urls(&result).remove(0);
    let (mut pipe, writer) = put_from_pipe(&write_url);
    let _ = pipe.write_all(b"partial");
    // The save must find the write started; one that arrives after it is
    // refused instead (TestRefusedWriteDoesNotWaitForItsBody).
    let token = write_url[write_url.rfind('/').unwrap() + 1..].to_owned();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while server.app.lock().writes.contains_key(&token) {
        assert!(
            std::time::Instant::now() < deadline,
            "the stream write never started"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    save(
        &mut a,
        "stop",
        obj! {"message_id" => result["message_id"].clone(), "body" => obj! {"text" => "never mind"}},
    );
    assert_eq!(writer_status(&writer), 410, "writer status");
    pipe.close();
    a.expect_quiet();
}

/// Writes use PUT (§4.8.3); another method leaves the write URL unused.
#[test]
fn test_writes_are_put() {
    let server = new_test_server(default_config());
    let mut a = dial_test_client(&server);
    let result = post_embeds(
        &mut a,
        "upload",
        obj! {"room_id" => "general", "body" => obj! {"embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
    );
    let write_url = write_urls(&result).remove(0);
    let (status, header, _) = http_do("POST", &write_url, Some(b"data"), "text/plain");
    assert!(
        status == 405 && header.get("Allow") == Some("PUT, OPTIONS"),
        "POST: {status}, Allow {:?}",
        header.get("Allow")
    );
    assert_eq!(
        http_do("PUT", &write_url, Some(b"data"), "text/plain").0,
        201,
        "PUT after POST"
    );
}

/// A write to a URL that is no longer usable is refused at once, even while
/// its body is still open: the server does not wait to read the body first.
#[test]
fn test_refused_write_does_not_wait_for_its_body() {
    let server = new_test_server(default_config());
    let mut a = dial_test_client(&server);
    let result = post_embeds(
        &mut a,
        "stream",
        obj! {"room_id" => "general", "body" => obj! {"embeds" => vec![Json::from(obj! {"kind" => "stream"})]}},
    );
    let write_url = write_urls(&result).remove(0);
    save(
        &mut a,
        "stop",
        obj! {"message_id" => result["message_id"].clone(), "body" => obj! {"text" => "never mind"}},
    );
    let (body, pipe) = rust_stdlib::io::pipe();
    let late = pipe.clone();
    std::thread::spawn(move || {
        let _ = late.write_shared(b"late");
    });
    let (ctx, cancel) = Context::background().with_timeout(Duration::from_secs(5));
    let request = http::Request::new("PUT", &write_url)
        .unwrap()
        .with_body(http::RequestBody::reader(body))
        .with_context(&ctx);
    let response = http::client::DEFAULT_CLIENT.do_request(request);
    // Go closes the response body before the pipe. rust-stdlib's close
    // waits for the request body to end, so the pipe closes first here.
    pipe.close();
    cancel();
    let response = response.unwrap_or_else(|e| panic!("a refused write with an open body: {e}"));
    if let Some(body) = &response.body {
        let _ = body.close();
    }
    assert_eq!(response.status_code, 404, "status");
}

/// The i-th room record in a room_list array.
fn nth(listed: &Object, key: &str, i: usize) -> Object {
    listed[key].as_list()[i].as_object().cloned().unwrap()
}

/// Reports whether a key is missing or null, as Go's `m[key] == nil`.
fn absent(o: &Object, key: &str) -> bool {
    o.get(key).is_none_or(|v| *v == Json::Null)
}

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}

fn strs(values: &[&str]) -> Json {
    Json::Array(values.iter().map(|v| Json::from(*v)).collect())
}

fn empty() -> Json {
    Json::Array(vec![])
}

/// A room_list `left` array naming one room.
fn left_list(room_id: &str) -> Json {
    Json::Array(vec![Json::from(obj! {"room_id" => room_id})])
}

#[test]
fn test_room_list_filters_and_order() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));
    let (ops, _) = save_room(&mut a, "ops", obj! {"title" => "Ops"});
    let (deploy, _) = save_room(
        &mut a,
        "deploy",
        obj! {"parent_room_id" => ops.as_str(), "title" => "Deploy"},
    );
    let (random, _) = save_room(&mut b, "random", obj! {"title" => "Random"});
    let (idle, _) = save_room(
        &mut b,
        "idle",
        obj! {"parent_room_id" => "general", "title" => "Idle"},
    );
    room_updated(&a, "updated");
    save(
        &mut a,
        "post",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "most recent"}},
    );

    // joined holds joined rooms at every depth, most recently active first;
    // not_joined holds visible unjoined top-level rooms. Without members,
    // neither members nor users is sent.
    let listed = list_rooms(&mut a, Object::new());
    assert_eq!(
        room_ids(listed.get("joined")),
        vec![ops.clone(), deploy.clone(), "general".into()],
        "joined"
    );
    assert_eq!(
        room_ids(listed.get("not_joined")),
        vec![random.clone()],
        "not_joined"
    );
    assert_eq!(
        listed.keys().collect::<Vec<_>>(),
        vec!["joined", "not_joined"],
        "listing without members: {listed:?}"
    );
    for entry in listed["joined"]
        .as_list()
        .iter()
        .chain(listed["not_joined"].as_list())
    {
        assert!(
            !entry.as_object().unwrap().contains_key("members"),
            "members without members: true: {entry:?}"
        );
    }
    let ops_entry = nth(&listed, "joined", 0);
    assert!(
        ops_entry["title"] == Json::from("Ops") && !absent(&ops_entry, "latest_log_id"),
        "ops entry: {ops_entry:?}"
    );

    // members: true lists every member of every room, joined or not, with
    // each user's current object once in users.
    a.result("me", "name", obj! {"name" => "Ada"});
    b.notification("user");
    let with_members = list_rooms(&mut a, obj! {"members" => true});
    let general = nth(&with_members, "joined", 2);
    assert!(
        member_ids(&general) == ids(&["guest_1", "guest_2"])
            && general["members"].as_list()[0]
                == Json::from(obj! {"user_id" => "guest_1", "status" => "online"}),
        "general members: {general:?}"
    );
    let random_entry = nth(&with_members, "not_joined", 0);
    assert_eq!(
        member_ids(&random_entry),
        ids(&["guest_2"]),
        "unjoined room members: {random_entry:?}"
    );
    let want_users = vec![
        Json::from(obj! {"user_id" => "guest_1", "name" => "Ada", "status" => "online"}),
        Json::from(obj! {"user_id" => "guest_2", "status" => "online"}),
    ];
    assert_eq!(
        with_members.get("users"),
        Some(&Json::from(want_users.clone())),
        "users"
    );

    // filter leaves out the other array; an array it asks for is present
    // even when empty.
    let only = list_rooms(&mut a, obj! {"filter" => "joined"});
    assert!(
        absent(&only, "not_joined") && only["joined"].as_list().len() == 3,
        "filter joined: {only:?}"
    );
    let not = list_rooms(&mut a, obj! {"filter" => "not_joined"});
    assert!(
        absent(&not, "joined") && room_ids(not.get("not_joined")) == vec![random.clone()],
        "filter not_joined: {not:?}"
    );
    let all = list_rooms(&mut a, obj! {"filter" => "all"});
    assert!(
        all["joined"].as_list().len() == 3 && all["not_joined"].as_list().len() == 1,
        "filter all: {all:?}"
    );
    let none = list_rooms(
        &mut a,
        obj! {"parent_room_id" => "general", "filter" => "joined"},
    );
    assert_eq!(none, obj! {"joined" => empty()}, "empty joined threads");
    // parent_room_id lists that room's threads, joined or not.
    let threads = list_rooms(&mut a, obj! {"parent_room_id" => "general"});
    assert!(
        threads["joined"].as_list().is_empty()
            && room_ids(threads.get("not_joined")) == vec![idle.clone()],
        "general's threads: {threads:?}"
    );
    let threads = list_rooms(&mut b, obj! {"parent_room_id" => ops.as_str()});
    assert_eq!(
        room_ids(threads.get("not_joined")),
        vec![deploy.clone()],
        "ops threads for a non-member: {threads:?}"
    );
    // room_id lists one room and overrides parent_room_id.
    let one = list_rooms(
        &mut b,
        obj! {"room_id" => ops.as_str(), "parent_room_id" => "general", "members" => true},
    );
    assert!(
        room_ids(one.get("not_joined")) == vec![ops.clone()]
            && one["joined"].as_list().is_empty()
            && one.get("users") == Some(&Json::from(want_users[..1].to_vec())),
        "one room: {one:?}"
    );
    for (i, params) in [
        obj! {"parent_room_id" => "missing"},
        obj! {"room_id" => "missing"},
        obj! {"filter" => "mine"},
        obj! {"filter" => 5i64},
        obj! {"members" => "yes"},
        obj! {"latest_log_id" => 5i64},
        obj! {"parent_room_id" => 5i64},
    ]
    .into_iter()
    .enumerate()
    {
        a.expect_error(
            "room_list",
            &format!("bad-{i}"),
            params,
            CODE_INVALID_PARAMS,
        );
    }
    a.expect_quiet();
    b.expect_quiet();
}

/// With latest_log_id, room_list lists only rooms changed since, and `left`
/// the rooms the user left since (§4.2.1).
#[test]
fn test_room_list_latest_log_id_delta() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));
    let (ops, _) = save_room(&mut a, "ops", obj! {"title" => "Ops"});
    join_room(&mut b, &ops);
    let since = expect_membership(&a, &ops, &b.user_id, true)["log_id"]
        .as_str()
        .unwrap()
        .to_owned();

    leave_room(&mut b, &ops);
    expect_membership(&a, &ops, &b.user_id, false);
    let (news, _) = save_room(&mut a, "news", obj! {"title" => "News"});
    let (mine, _) = save_room(&mut b, "mine", obj! {"title" => "Mine"});

    // Joined since then in joined, left since then in left; general has not
    // changed since, so it is not listed.
    let delta = list_rooms(
        &mut b,
        obj! {"filter" => "joined", "latest_log_id" => since.as_str()},
    );
    let want = obj! {"joined" => delta["joined"].clone(), "left" => left_list(&ops)};
    assert!(
        delta == want && room_ids(delta.get("joined")) == vec![mine.clone()],
        "joined delta: {delta:?}"
    );
    // With not_joined too, a room left since then is also a visible unjoined
    // room that changed.
    let delta = list_rooms(
        &mut b,
        obj! {"latest_log_id" => since.as_str(), "members" => true},
    );
    assert!(
        room_ids(delta.get("not_joined")) == vec![news.clone(), ops.clone()]
            && delta.get("left") == Some(&left_list(&ops)),
        "full delta: {delta:?}"
    );
    assert_eq!(
        member_ids(&nth(&delta, "not_joined", 1)),
        ids(&["guest_1"]),
        "members in a delta: {delta:?}"
    );
    // left accompanies joined only.
    let delta = list_rooms(
        &mut b,
        obj! {"filter" => "not_joined", "latest_log_id" => since.as_str()},
    );
    assert!(absent(&delta, "left"), "not_joined delta: {delta:?}");
    // left is present even when empty.
    let latest = nth(
        &list_rooms(&mut b, obj! {"filter" => "joined"}),
        "joined",
        0,
    )["latest_log_id"]
        .clone();
    let nothing = list_rooms(
        &mut b,
        obj! {"filter" => "joined", "latest_log_id" => latest.clone()},
    );
    assert_eq!(
        nothing,
        obj! {"joined" => empty(), "left" => empty()},
        "empty delta"
    );
    // A room left before the position is not in left, even when it changed.
    save(
        &mut a,
        "later",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "later"}},
    );
    let delta = list_rooms(&mut b, obj! {"latest_log_id" => latest});
    assert!(
        delta.get("left") == Some(&empty())
            && room_ids(delta.get("not_joined")) == vec![ops.clone()],
        "delta after an old leave: {delta:?}"
    );
    // A room rejoined since the position is in joined, not left.
    join_room(&mut b, &ops);
    expect_membership(&a, &ops, &b.user_id, true);
    let delta = list_rooms(
        &mut b,
        obj! {"filter" => "joined", "latest_log_id" => since.as_str()},
    );
    assert!(
        room_ids(delta.get("joined")) == vec![ops.clone(), mine.clone()]
            && delta.get("left") == Some(&empty()),
        "delta after rejoining: {delta:?}"
    );
    // A room the user was removed from is left too.
    let kick = obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "/kick @guest_2", "mentions" => strs(&["guest_2"])}};
    a.request("command", "kick", kick);
    b.drain();
    let delta = list_rooms(
        &mut b,
        obj! {"filter" => "joined", "latest_log_id" => since.as_str()},
    );
    assert!(
        room_ids(delta.get("joined")) == vec![mine.clone()]
            && delta.get("left") == Some(&left_list(&ops)),
        "delta after removal: {delta:?}"
    );
}

/// A delta listing (§4.2.1) carries the private rooms and threads the user
/// was added to since the position, at their latest activity, and the ones
/// they left; it never carries one they are not in.
#[test]
fn test_room_list_latest_log_id_delta_private_rooms() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 3);
    let (mut a, mut b, mut c) = (clients.remove(0), clients.remove(0), clients.remove(0));
    let since = nth(
        &list_rooms(&mut b, obj! {"filter" => "joined"}),
        "joined",
        0,
    )["latest_log_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (dm, _) = save_room(&mut a, "dm", obj! {"private" => true});
    a.request(
        "room_join",
        "add",
        obj! {"room_id" => dm.as_str(), "user_id" => b.user_id.as_str()},
    );
    let (thread, _) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => dm.as_str(), "title" => "Plans"},
    );
    a.request(
        "room_join",
        "add-thread",
        obj! {"room_id" => thread.as_str(), "user_id" => b.user_id.as_str()},
    );
    a.drain();
    save(
        &mut a,
        "in-thread",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "in the thread"}},
    );
    let (_, last) = save(
        &mut a,
        "in-dm",
        obj! {"room_id" => dm.as_str(), "body" => obj! {"text" => "just us"}},
    );
    let (other, _) = save_room(&mut c, "other", obj! {"private" => true});
    b.drain();

    let delta = list_rooms(
        &mut b,
        obj! {"filter" => "joined", "latest_log_id" => since.as_str()},
    );
    assert!(
        room_ids(delta.get("joined")) == vec![dm.clone(), thread.clone()]
            && delta.get("left") == Some(&empty()),
        "delta after being added: {delta:?}"
    );
    let head = nth(&delta, "joined", 0).get("latest_log_id").cloned();
    assert_eq!(
        head.as_ref(),
        last.get("log_id"),
        "private room's latest_log_id, want its last message's"
    );
    let unjoined =
        room_ids(list_rooms(&mut b, obj! {"latest_log_id" => since.as_str()}).get("not_joined"));
    assert!(
        !unjoined.contains(&other),
        "someone else's private room in a delta: {unjoined:?}"
    );

    // Removed from the room, its thread goes too.
    a.request(
        "room_leave",
        "remove",
        obj! {"room_id" => dm.as_str(), "user_id" => b.user_id.as_str()},
    );
    b.drain();
    let delta = list_rooms(
        &mut b,
        obj! {"filter" => "joined", "latest_log_id" => since.as_str()},
    );
    assert!(
        room_ids(delta.get("joined")).is_empty() && !delta["left"].as_list().is_empty(),
        "delta after removal: {delta:?}"
    );
    c.drain();
}

/// Without room_id, history pages the log of every room the user joined as
/// one log (§4.3): private rooms included, nothing of rooms not joined or not
/// visible, a moved message once, in log_id order both ways.
#[test]
fn test_history_without_room_id_pages_joined_rooms() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 3);
    let (mut a, mut b, mut c) = (clients.remove(0), clients.remove(0), clients.remove(0));
    let since = nth(
        &list_rooms(&mut b, obj! {"filter" => "joined"}),
        "joined",
        0,
    )["latest_log_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (dm, _) = save_room(&mut a, "dm", obj! {"private" => true});
    a.request(
        "room_join",
        "add",
        obj! {"room_id" => dm.as_str(), "user_id" => b.user_id.as_str()},
    );
    let (theirs, _) = save_room(&mut c, "theirs", obj! {"private" => true});
    let (aside, _) = save_room(
        &mut c,
        "aside",
        obj! {"parent_room_id" => "general", "title" => "Aside"},
    );
    a.drain();
    let (ops, _) = save_room(&mut a, "ops", obj! {"title" => "Ops"});
    b.drain();
    join_room(&mut b, &ops);
    a.drain();
    c.drain();
    let mut mine = Vec::new();
    let mut post = |cl: &mut TestClient, id: &str, room: &str, keep: bool| -> String {
        cl.drain();
        let (message, _) = save(
            cl,
            id,
            obj! {"room_id" => room, "body" => obj! {"text" => id}},
        );
        if keep {
            mine.push(message.clone());
        }
        message
    };
    post(&mut a, "dm-1", &dm, true);
    let moved = post(&mut a, "general-1", "general", true);
    post(&mut c, "theirs-1", &theirs, false);
    post(&mut c, "aside-1", &aside, false);
    post(&mut a, "dm-2", &dm, true);
    // Moved from general into ops, both joined: its move snapshot is in both
    // logs, and comes once.
    a.drain();
    a.request(
        "message",
        "move",
        obj! {"message_id" => moved.as_str(), "room_id" => ops.as_str(), "body" => obj! {"text" => "general-1"}},
    );
    b.drain();

    let page = b.result(
        "history",
        "all",
        obj! {"after" => since.as_str(), "limit" => 50i64},
    );
    let ids = log_ids(&page, "messages");
    assert!(
        ids.len() == 4
            && ids[0] == mine[0]
            && ids[1] == mine[1]
            && ids[2] == mine[2]
            && page.get("more") == Some(&Json::from(false)),
        "joined rooms' log: {ids:?}, want {mine:?} and the move"
    );
    for key in ["rooms", "memberships", "messages"] {
        let records = page.get(key).map(Json::as_list).unwrap_or(&[]);
        assert!(!records.is_empty(), "no {key} in {page:?}");
        for record in records {
            let room = record.as_object().unwrap().get("room_id").cloned();
            assert!(
                [
                    Json::from("general"),
                    Json::from(dm.as_str()),
                    Json::from(ops.as_str())
                ]
                .iter()
                .any(|r| Some(r) == room.as_ref()),
                "a record of {room:?}, which bob did not join: {record:?}"
            );
        }
    }
    assert_eq!(
        page.get("latest_log_id"),
        Some(&Json::from(ids[3].as_str())),
        "latest_log_id, want the move"
    );

    // One record at a time forward, and the newest backward.
    let mut forward = Vec::new();
    let mut after = since.clone();
    for _ in 0..50 {
        let id = b.next_id("forward");
        let next = b.result(
            "history",
            &id,
            obj! {"after" => after.as_str(), "limit" => 1i64},
        );
        forward.extend(log_ids(&next, "messages"));
        if next.get("more") == Some(&Json::from(false)) {
            break;
        }
        let last: i64 = next["last_log_id"].as_str().unwrap().parse().unwrap();
        after = (last + 1).to_string();
    }
    assert_eq!(forward, ids, "forward pages");
    let newest = b.result("history", "newest", obj! {"limit" => 1i64});
    assert!(
        log_ids(&newest, "messages") == ids[3..] && newest.get("more") == Some(&Json::from(true)),
        "newest page: {newest:?}"
    );
    // Bounded on both sides, across rooms; and the move snapshot alone.
    let middle = b.result(
        "history",
        "middle",
        obj! {"after" => ids[0].as_str(), "before" => ids[2].as_str()},
    );
    assert_eq!(
        log_ids(&middle, "messages"),
        ids[..3].to_vec(),
        "bounded page: {middle:?}"
    );
    let one = b.result(
        "history",
        "one",
        obj! {"after" => ids[3].as_str(), "before" => ids[3].as_str()},
    );
    assert!(
        log_ids(&one, "messages") == ids[3..] && one.get("more") == Some(&Json::from(false)),
        "the move snapshot alone: {one:?}"
    );

    // The log's lower bound is the server's, whatever rooms the user is in,
    // so it never moves (§4.3.3); in no rooms, the log is empty and ends
    // just before it.
    let start = page.get("history_log_id").cloned();
    let general = history_page(&mut b, "general", Object::new());
    assert_eq!(
        start.as_ref(),
        general.get("history_log_id"),
        "history_log_id, want general's"
    );
    for room in ["general", ops.as_str(), dm.as_str()] {
        leave_room(&mut b, room);
        b.drain();
        let id = b.next_id("left");
        let bound = b
            .result("history", &id, obj! {"limit" => 1i64})
            .get("history_log_id")
            .cloned();
        assert!(
            bound == start || room == dm,
            "history_log_id after leaving {room}: {bound:?}, want {start:?}"
        );
    }
    let none = b.result("history", "none", Object::new());
    let first: i64 = start
        .as_ref()
        .and_then(Json::as_str)
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        absent(&none, "history_log_id")
            && none.get("latest_log_id") == Some(&Json::from((first - 1).to_string()))
            && none.get("more") == Some(&Json::from(false))
            && absent(&none, "messages"),
        "history in no rooms: {none:?}"
    );
    join_room(&mut b, "general");
    let bound = b
        .result("history", "rejoined", obj! {"limit" => 1i64})
        .get("history_log_id")
        .cloned();
    assert_eq!(bound, start, "history_log_id after rejoining");
}

#[test]
fn test_room_list_truncates_only_unjoined_rooms() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let (mut owner, mut other) = (clients.remove(0), clients.remove(0));
    let mut threads = Vec::new();
    for i in 0..=MAX_LISTED_ROOMS {
        let (thread, _) = save_room(
            &mut owner,
            &format!("thread-{i}"),
            obj! {"parent_room_id" => "general"},
        );
        room_updated(&other, "updated");
        threads.push(thread);
    }
    let joined = list_rooms(&mut owner, obj! {"filter" => "joined"});
    assert_eq!(
        joined["joined"].as_list().len(),
        MAX_LISTED_ROOMS + 2,
        "owner joined rooms"
    );
    // The unjoined listing keeps the most recently active.
    let rooms =
        room_ids(list_rooms(&mut other, obj! {"parent_room_id" => "general"}).get("not_joined"));
    assert!(
        rooms.len() == MAX_LISTED_ROOMS
            && rooms[0] == *threads.last().unwrap()
            && !rooms.contains(&threads[0]),
        "unjoined threads: {}, first {:?}",
        rooms.len(),
        rooms.first()
    );
}

/// Every join and leave is a logged membership, delivered to the room's
/// members before and after the change and ordered before the room_update
/// and the result on the requesting connection (§4.2.2).
#[test]
fn test_join_leave_and_deliveries() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 3);
    let (mut a, mut b, mut c) = (clients.remove(0), clients.remove(0), clients.remove(0));
    let (ops, ops_record) = save_room(&mut a, "ops", obj! {"title" => "Ops"});

    // A member receives the room's records; a poster who has not joined gets
    // only the result.
    b.write(&obj! {"method" => "message", "id" => "outside", "params" => obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "from outside"}}});
    let frames = b.drain();
    assert_eq!(
        methods(&frames),
        vec!["reply"],
        "non-member post: {frames:?}"
    );
    let outside = a.notification("message");
    assert_eq!(
        outside["from"].as_object().unwrap().get("user_id"),
        Some(&Json::from("guest_2")),
        "non-member post broadcast: {outside:?}"
    );
    // Reactions and typing in a room not joined reach only its members.
    react(
        &mut a,
        "react",
        outside["message_id"].as_str().unwrap(),
        &["👍"],
    );
    b.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => ops.as_str(), "typing" => 5i64}});
    a.notification("activity");
    b.expect_quiet();

    // Joining: the membership goes to the members and the joiner, then the
    // joiner gets room_update joined with the members, then the result.
    let record = join_room(&mut b, &ops);
    assert!(
        record["title"] == Json::from("Ops")
            && record.get("log_id") == ops_record.get("log_id")
            && member_ids(&record) == ids(&["guest_1", "guest_2"]),
        "joined record: {record:?}"
    );
    let joined = expect_membership(&a, &ops, "guest_2", true);
    assert_eq!(
        joined.get("log_id"),
        record.get("latest_log_id"),
        "member's copy {joined:?} disagrees with {record:?}"
    );
    c.expect_quiet();
    save(
        &mut a,
        "inside",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "welcome"}},
    );
    b.notification("message");
    // Joining again logs nothing and re-sends the room to the calling
    // connection only.
    let (before, _) = b.request("room_join", "again", obj! {"room_id" => ops.as_str()});
    assert!(
        before.len() == 1
            && member_ids(&joined_record(&before[0], "guest_2")) == ids(&["guest_1", "guest_2"]),
        "second join: {before:?}"
    );
    a.expect_quiet();
    b.expect_error(
        "room_join",
        "missing",
        obj! {"room_id" => "missing"},
        CODE_INVALID_PARAMS,
    );

    // Leaving: the leaver's connections get room_update with left and the
    // membership, the other members the membership alone, then the result;
    // a result sent after the leave reflects it.
    b.write(&obj! {"method" => "room_leave", "id" => "leave", "params" => obj! {"room_id" => ops.as_str()}});
    b.write(&obj! {"method" => "room_list", "id" => "after-leave", "params" => obj! {"filter" => "joined"}});
    let frames = b.drain();
    assert_eq!(
        methods(&frames),
        vec!["room_update", "reply", "reply"],
        "leave frames: {frames:?}"
    );
    let leave = check_left(&frames[0], &ops, "guest_2");
    assert_eq!(
        room_ids(frames[2]["result"].as_object().unwrap().get("joined")),
        ids(&["general"]),
        "joined after leave"
    );
    let left = expect_membership(&a, &ops, "guest_2", false);
    assert_eq!(left, leave, "member's copy of the leave");
    save(
        &mut a,
        "after",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "gone"}},
    );
    b.expect_quiet();
    // Leaving a room not joined changes nothing.
    b.result(
        "room_leave",
        "leave-again",
        obj! {"room_id" => ops.as_str()},
    );
    b.expect_error(
        "room_leave",
        "missing",
        obj! {"room_id" => "missing"},
        CODE_INVALID_PARAMS,
    );
    a.expect_quiet();

    // Leaves are memberships only, never user notifications (§3.3), even from
    // the last shared room.
    leave_room(&mut b, "general");
    expect_membership(&a, "general", "guest_2", false);
    expect_membership(&c, "general", "guest_2", false);
    a.expect_quiet();
    join_room(&mut b, &ops);
    expect_membership(&a, &ops, "guest_2", true);

    // A guest whose last connection closes is retired: it leaves every room
    // it joined, each a logged membership for the remaining members.
    let _ = b.ws.close(ws::STATUS_NORMAL_CLOSURE, "done");
    expect_membership(&a, &ops, "guest_2", false);
    a.expect_quiet();
    c.expect_quiet();
    let entry = nth(
        &list_rooms(&mut a, obj! {"room_id" => ops.as_str(), "members" => true}),
        "joined",
        0,
    );
    assert_eq!(
        member_ids(&entry),
        ids(&["guest_1"]),
        "retired guest is still a member: {entry:?}"
    );
    // history returns the room's memberships in log order.
    let changes: Vec<String> = records(&history_page(&mut a, &ops, Object::new()), "memberships")
        .iter()
        .map(|value| {
            let entry = value["members"].as_list()[0].as_object().unwrap();
            let user_id = entry["user"].as_object().unwrap()["user_id"]
                .as_str()
                .unwrap();
            format!("{user_id} {}", entry["joined"].is_true())
        })
        .collect();
    assert_eq!(
        changes,
        vec![
            "guest_1 true",
            "guest_2 true",
            "guest_2 false",
            "guest_2 true",
            "guest_2 false"
        ],
        "ops memberships"
    );
}

/// A thread's messages go only to its members; the parent's members get only
/// its room record changes, as room_update updated (§4.2, §4.2.3).
#[test]
fn test_thread_messages_reach_only_thread_members() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 3);
    let (mut a, mut b, mut c) = (clients.remove(0), clients.remove(0), clients.remove(0));
    save(&mut a, "root", obj! {"body" => obj! {"text" => "Deploy"}});
    b.notification("message");
    c.notification("message");
    let (thread, record) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => "general", "description" => "Deploy"},
    );
    for member in [&b, &c] {
        let observed = room_updated(member, "updated");
        assert_eq!(observed, record, "parent member's new thread");
    }
    join_room(&mut b, &thread);
    expect_membership(&a, &thread, "guest_2", true);
    c.expect_quiet();

    let (id, _) = save(
        &mut a,
        "in-thread",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "rolling out"}},
    );
    b.notification("message");
    react(&mut b, "react", &id, &["👍"]);
    a.notification("reactions");
    a.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => thread.as_str(), "typing" => 3i64}});
    a.notification("activity");
    b.notification("activity");
    c.expect_quiet();

    // An edited thread record reaches the parent's members too.
    let (_, edited) = save_room(
        &mut b,
        "rename",
        obj! {"room_id" => thread.as_str(), "title" => "Rollout"},
    );
    for member in [&a, &c] {
        let observed = room_updated(member, "updated");
        assert_eq!(observed, edited, "thread edit");
    }
    for client in [&mut a, &mut b, &mut c] {
        client.expect_quiet();
    }
}

#[test]
fn test_prev_log_id_links_records() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let (id, creation) = save(&mut c, "create", obj! {"body" => obj! {"text" => "one"}});
    assert!(
        !creation.contains_key("prev_log_id"),
        "creation has prev_log_id: {creation:?}"
    );
    let (_, edit) = save(
        &mut c,
        "edit",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => "two"}},
    );
    assert_eq!(
        edit.get("prev_log_id"),
        Some(&Json::from(id.as_str())),
        "edit prev_log_id: {edit:?}"
    );
    let (room, record) = save_room(&mut c, "room", obj! {"title" => "A"});
    let (_, updated) = save_room(
        &mut c,
        "update",
        obj! {"room_id" => room.as_str(), "title" => "B"},
    );
    assert!(
        !record.contains_key("prev_log_id") && updated.get("prev_log_id") == record.get("log_id"),
        "room prev_log_id: {record:?} then {updated:?}"
    );
    // Only room records and message snapshots carry prev_log_id (§4.3.1).
    let first = react(&mut c, "r1", &id, &["👍"]);
    let second = react(&mut c, "r2", &id, &["🎉"]);
    assert!(
        absent(&first, "prev_log_id") && absent(&second, "prev_log_id"),
        "reactions prev_log_id: {first:?} then {second:?}"
    );
    leave_room(&mut c, &room);
    for value in records(&history_page(&mut c, &room, Object::new()), "memberships") {
        assert!(
            !value.contains_key("prev_log_id"),
            "membership with prev_log_id: {value:?}"
        );
    }
}

#[test]
fn test_read_cursors() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));
    let (first, _) = save(&mut a, "one", obj! {"body" => obj! {"text" => "one"}});
    b.notification("message");
    let (second, _) = save(&mut a, "two", obj! {"body" => obj! {"text" => "two"}});
    b.notification("message");

    a.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => "general", "read_message_id" => second.as_str()}});
    let want = obj! {"room_id" => "general", "from" => obj! {"user_id" => "guest_1"}, "read_message_id" => second.as_str()};
    for c in [&a, &b] {
        assert_eq!(c.notification("activity"), want, "read cursor");
    }
    // A cursor that moves back is ignored.
    a.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => "general", "read_message_id" => first.as_str()}});
    b.expect_quiet();
    a.expect_quiet();
    // activity is a notification: one sent with an id is processed as one,
    // unanswered, and an unknown cursor changes nothing (§1).
    a.write(&obj! {"method" => "activity", "id" => "unknown", "params" => obj! {"room_id" => "general", "read_message_id" => "999"}});
    a.expect_quiet();
    b.expect_quiet();

    // Kept cursors follow a room_list result that lists the room: every
    // member's for a joined room, only the user's own for another.
    let mut c = dial_test_client(&server);
    expect_membership(&a, "general", &c.user_id, true);
    expect_membership(&b, "general", &c.user_id, true);
    c.write(
        &obj! {"method" => "room_list", "id" => "list", "params" => obj! {"filter" => "joined"}},
    );
    let frames = c.drain();
    assert!(
        methods(&frames) == vec!["reply", "activity"]
            && frames[1].get("params") == Some(&Json::from(want.clone())),
        "room_list frames: {frames:?}"
    );
    let (thread, _) = save_room(&mut b, "thread", obj! {"parent_room_id" => "general"});
    room_updated(&a, "updated");
    room_updated(&c, "updated");
    b.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => thread.as_str(), "read_message_id" => second.as_str()}});
    b.notification("activity");
    a.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => thread.as_str(), "read_message_id" => first.as_str()}});
    a.notification("activity");
    b.notification("activity");
    a.write(&obj! {"method" => "room_list", "id" => "threads", "params" => obj! {"parent_room_id" => "general"}});
    let frames = a.drain();
    assert!(
        methods(&frames) == vec!["reply", "activity"]
            && frames[1]["params"].as_object().unwrap()["from"]
                .as_object()
                .unwrap()
                .get("user_id")
                == Some(&Json::from("guest_1")),
        "unjoined room cursors: {frames:?}"
    );
}

#[test]
fn test_profiles_and_user_notifications() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));
    let ext = obj! {"example.org" => obj! {"pronouns" => "she/her"}};
    let you = a.result(
        "me",
        "profile",
        obj! {"name" => "  Ada  ", "avatar" => "data:image/png;base64,iVBORw0KGgo=", "ext" => ext.clone()},
    )["you"]
        .clone();
    let want = obj! {"user_id" => "guest_1", "name" => "Ada", "avatar" => "data:image/png;base64,iVBORw0KGgo=", "ext" => ext.clone(), "status" => "online"};
    assert_eq!(you, Json::from(want.clone()), "you");
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
        Json::from(want.clone()),
        "empty me changed the profile"
    );
    b.expect_quiet();
    // "ext": {} changes nothing (§4.12).
    let kept = a.result("me", "empty-ext", obj! {"ext" => Object::new()})["you"].clone();
    assert_eq!(
        kept,
        Json::from(want.clone()),
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
    assert_eq!(you, Json::from(merged.clone()), "merge result");
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
    let cleared =
        obj! {"user_id" => "guest_1", "name" => "Ada", "avatar" => "", "status" => "online"};
    assert_eq!(you, Json::from(cleared.clone()), "removal result");
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
        Json::from(obj! {"user_id" => "guest_1", "name" => "Ada", "status" => "online"}),
        "profile after removal"
    );
    let you = a.result("me", "clear-name", obj! {"name" => ""})["you"].clone();
    assert_eq!(
        you,
        Json::from(obj! {"user_id" => "guest_1", "name" => "", "status" => "online"}),
        "clearing the name"
    );
    b.notification("user");
    a.expect_error(
        "me",
        "bad-avatar",
        obj! {"avatar" => "javascript:alert(1)"},
        CODE_INVALID_PARAMS,
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
    let (ops, _) = save_room(&mut a, "ops", obj! {"title" => "Ops"});
    join_room(&mut b, &ops);
    expect_membership(&a, &ops, "guest_2", true);
    join_room(&mut c, &ops);
    expect_membership(&a, &ops, "guest_3", true);
    expect_membership(&b, &ops, "guest_3", true);

    let text = help(&mut a, &ops);
    assert!(
        text.contains("`/help`")
            && text.contains("`/avatar`")
            && text.contains("`/kick @user [reason]`"),
        "creator's help: {text:?}"
    );
    let text = help(&mut b, "");
    assert!(
        !text.contains("/kick") && text.contains("/avatar"),
        "member's help: {text:?}"
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

    // /kick is for the room's creator, and names its target in mentions,
    // which notifies no one.
    // The reason is the first line of the rest of the text.
    let kick = obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "/kick @guest_3 spamming\n**SYSTEM**: all admins removed", "mentions" => strs(&["guest_3"])}};
    b.expect_error("command", "not-creator", kick.clone(), CODE_DENIED);
    a.expect_error(
        "command",
        "general",
        obj! {"body" => obj! {"text" => "/kick @guest_3", "mentions" => strs(&["guest_3"])}},
        CODE_DENIED,
    );
    a.expect_error(
        "command",
        "no-target",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "/kick guest_3"}},
        CODE_INVALID_PARAMS,
    );
    a.expect_error(
        "command",
        "self",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "/kick @guest_1", "mentions" => strs(&["guest_1"])}},
        CODE_INVALID_PARAMS,
    );
    a.expect_error(
        "command",
        "not-member",
        obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "/kick @nobody", "mentions" => strs(&["nobody"])}},
        CODE_INVALID_PARAMS,
    );
    for client in [&mut a, &mut b, &mut c] {
        client.expect_quiet();
    }
    // The removal is a logged leave: the removed user's connections get
    // room_update with left and the membership, the room's other members the
    // membership alone and then a ~room notice, all before the result (§1,
    // §4.1).
    let (before, result) = a.request("command", "kick", kick.clone());
    assert!(
        result.is_empty() && methods(&before) == vec!["room_update", "message"],
        "kick frames {before:?} then {result:?}"
    );
    let removal = membership_only(&before[0]);
    check_membership(&removal, &ops, "guest_3", false);
    let kicked = expect_left(&c, &ops, "guest_3");
    assert_eq!(kicked, removal, "removed user's membership");
    let notice = notification_params(&before[1], "message");
    let observed = expect_membership(&b, &ops, "guest_3", false);
    assert_eq!(observed, removal, "member's membership");
    assert_eq!(b.notification("message"), notice, "member's notice");
    let message_id = notice.get("message_id").cloned().unwrap_or_default();
    let want = obj! {
        "message_id" => message_id.clone(), "log_id" => message_id, "room_id" => ops.as_str(),
        "from" => obj! {"user_id" => "~room", "name" => "Ops"},
        "body" => obj! {"text" => "@guest_3 was removed by @guest_1: spamming"},
    };
    assert_eq!(notice, want, "~room notice");
    c.expect_quiet();
    // The notice and the removal are logged; the command is not.
    let page = history_page(&mut a, &ops, Object::new());
    let entries = records(&page, "messages");
    assert!(
        entries.len() == 1 && entries[0] == notice,
        "ops history: {entries:?}"
    );
    let memberships = records(&page, "memberships");
    assert_eq!(memberships.last(), Some(&removal), "ops memberships");
    // A retried command does not run again.
    let result = a.result("command", "kick", kick);
    assert!(result.is_empty(), "retried kick: {result:?}");
    for client in [&mut a, &mut b, &mut c] {
        client.expect_quiet();
    }
}

/// Config.max_private_rooms bounds the top-level private rooms one user is
/// in, created or added to: past it, creating one or being added to one is
/// denied. Public rooms and threads are not counted, and leaving a private
/// room makes room for another.
#[test]
fn test_private_rooms_per_user_bound() {
    let mut config = default_config();
    config.max_private_rooms = 2;
    let server = new_test_server(config);
    let mut clients = dial_group(&server, 2);
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));

    let (first, _) = save_room(&mut a, "first", obj! {"private" => true});
    save_room(&mut a, "second", obj! {"private" => true});
    a.expect_error("room_set", "third", obj! {"private" => true}, CODE_DENIED);
    // Not counted: a public room, a private thread of a public room, and a
    // thread of a private room, whose members alone can be added to it.
    save_room(&mut a, "open", obj! {"title" => "Open"});
    save_room(
        &mut a,
        "aside",
        obj! {"parent_room_id" => "general", "private" => true},
    );
    save_room(&mut a, "side", obj! {"parent_room_id" => first.as_str()});

    // b is in two private rooms of its own, so nobody can add b to another.
    let (full, _) = save_room(&mut b, "b1", obj! {"private" => true});
    save_room(&mut b, "b2", obj! {"private" => true});
    a.expect_error(
        "room_join",
        "full",
        obj! {"room_id" => first.as_str(), "user_id" => b.user_id.as_str()},
        CODE_DENIED,
    );
    b.expect_quiet();
    // Leaving one makes room for the next.
    leave_room(&mut b, &full);
    let (_, result) = a.request(
        "room_join",
        "added",
        obj! {"room_id" => first.as_str(), "user_id" => b.user_id.as_str()},
    );
    assert!(result.is_empty(), "adding b: {result:?}");
    let joined = joined_record(&b.read(), &b.user_id);
    assert!(
        joined["room_id"] == Json::from(first.as_str())
            && joined.get("private") == Some(&Json::from(true)),
        "b's room_update: {joined:?}"
    );
    b.expect_error("room_set", "b3", obj! {"private" => true}, CODE_DENIED);
    // Adding someone already in the room changes nothing, bound or not.
    a.result(
        "room_join",
        "again",
        obj! {"room_id" => first.as_str(), "user_id" => b.user_id.as_str()},
    );
}

/// A private room and its threads are invisible to non-members, who get
/// invalid_params as for an unknown room; members bring others in with
/// room_join's user_id, and the room's creator removes them with
/// room_leave's (§4.2.2, §4.2.4).
#[test]
fn test_private_rooms_and_membership_by_user_id() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 3);
    let (mut a, mut b, mut c) = (clients.remove(0), clients.remove(0), clients.remove(0));

    let (room, record) = save_room(&mut a, "private", obj! {"title" => "DM", "private" => true});
    assert_eq!(
        record.get("private"),
        Some(&Json::from(true)),
        "private room record: {record:?}"
    );
    let (secret, _) = save(
        &mut a,
        "secret",
        obj! {"room_id" => room.as_str(), "body" => obj! {"text" => "just us"}},
    );
    let (thread, _) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => room.as_str(), "description" => "Plans", "private" => false},
    );
    // A thread created without private takes its parent's (§4.2.4).
    let (_, inherited) = save_room(&mut a, "inherits", obj! {"parent_room_id" => room.as_str()});
    assert_eq!(
        inherited.get("private"),
        Some(&Json::from(true)),
        "thread of a private room: {inherited:?}"
    );
    // A private thread in a public room: its record does not reach the
    // parent's members.
    let (aside, aside_record) = save_room(
        &mut a,
        "aside",
        obj! {"parent_room_id" => "general", "private" => true},
    );
    assert!(
        aside_record.get("private") == Some(&Json::from(true))
            && aside_record.get("parent_room_id") == Some(&Json::from("general")),
        "private thread record: {aside_record:?}"
    );
    b.expect_quiet();
    c.expect_quiet();

    // To anyone else these rooms, their threads, and their messages are unknown.
    for room_id in [&room, &thread, &aside] {
        let room_id = room_id.as_str();
        let id = b.next_id("history");
        b.expect_error(
            "history",
            &id,
            obj! {"room_id" => room_id},
            CODE_INVALID_PARAMS,
        );
        let id = b.next_id("join");
        b.expect_error(
            "room_join",
            &id,
            obj! {"room_id" => room_id},
            CODE_INVALID_PARAMS,
        );
        let id = b.next_id("list");
        b.expect_error(
            "room_list",
            &id,
            obj! {"room_id" => room_id},
            CODE_INVALID_PARAMS,
        );
        let id = b.next_id("post");
        b.expect_error(
            "message",
            &id,
            obj! {"room_id" => room_id, "body" => obj! {"text" => "hi"}},
            CODE_INVALID_PARAMS,
        );
        let id = b.next_id("set");
        b.expect_error(
            "room_set",
            &id,
            obj! {"room_id" => room_id, "title" => "Mine"},
            CODE_INVALID_PARAMS,
        );
        let id = b.next_id("help");
        b.expect_error(
            "command",
            &id,
            obj! {"room_id" => room_id, "body" => obj! {"text" => "/help"}},
            CODE_INVALID_PARAMS,
        );
    }
    b.expect_error(
        "room_list",
        "threads",
        obj! {"parent_room_id" => room.as_str()},
        CODE_INVALID_PARAMS,
    );
    b.expect_error(
        "room_set",
        "nested",
        obj! {"parent_room_id" => room.as_str()},
        CODE_INVALID_PARAMS,
    );
    b.expect_error(
        "reactions",
        "react",
        obj! {"message_id" => secret.as_str(), "emojis" => strs(&["👀"])},
        CODE_INVALID_PARAMS,
    );
    b.expect_error(
        "message",
        "reply",
        obj! {"body" => obj! {"text" => "re"}, "reply_to" => obj! {"message_id" => secret.as_str()}},
        CODE_INVALID_PARAMS,
    );
    let listed = list_rooms(&mut b, Object::new());
    let unjoined = room_ids(listed.get("not_joined"));
    assert!(
        !unjoined.contains(&room),
        "private room listed to a non-member: {unjoined:?}"
    );
    let unjoined =
        room_ids(list_rooms(&mut b, obj! {"parent_room_id" => "general"}).get("not_joined"));
    assert!(
        !unjoined.contains(&aside),
        "private thread listed to a non-member: {unjoined:?}"
    );

    // Only members may add others; adding someone gives them the room.
    let (open, _) = save_room(&mut a, "open", obj! {"title" => "Open"});
    b.expect_error(
        "room_join",
        "not-a-member",
        obj! {"room_id" => open.as_str(), "user_id" => "guest_3"},
        CODE_DENIED,
    );
    for (id, user_id) in [
        ("unknown-user", "nobody"),
        ("empty-user", ""),
        ("spaced-user", "guest 2"),
    ] {
        a.expect_error(
            "room_join",
            id,
            obj! {"room_id" => room.as_str(), "user_id" => user_id},
            CODE_INVALID_PARAMS,
        );
    }
    let (before, result) = a.request(
        "room_join",
        "add",
        obj! {"room_id" => room.as_str(), "user_id" => "guest_2"},
    );
    assert!(
        result.is_empty() && methods(&before) == vec!["room_update"],
        "adding a member: {before:?} then {result:?}"
    );
    check_membership(&membership_only(&before[0]), &room, "guest_2", true);
    let added = b.read();
    check_membership(&membership_of(&added), &room, "guest_2", true);
    let joined = joined_record(&added, "guest_2");
    assert!(
        joined["room_id"] == Json::from(room.as_str())
            && joined.get("private") == Some(&Json::from(true)),
        "added member's room_update: {joined:?}"
    );
    let messages = records(&history_page(&mut b, &room, Object::new()), "messages");
    assert_eq!(messages.len(), 1, "added member's history: {messages:?}");
    // Its public thread is visible to the new member, who is not in it.
    let unjoined =
        room_ids(list_rooms(&mut b, obj! {"parent_room_id" => room.as_str()}).get("not_joined"));
    assert_eq!(
        unjoined,
        vec![thread.clone()],
        "threads of the private room"
    );
    // Adding a member again changes nothing.
    a.result(
        "room_join",
        "again",
        obj! {"room_id" => room.as_str(), "user_id" => "guest_2"},
    );
    b.expect_quiet();
    // Its threads are for its members: someone outside it cannot be added
    // to one.
    a.expect_error(
        "room_join",
        "outsider",
        obj! {"room_id" => thread.as_str(), "user_id" => "guest_3"},
        CODE_DENIED,
    );
    join_room(&mut b, &thread);
    expect_membership(&a, &thread, "guest_2", true);
    let (other, _) = save_room(
        &mut a,
        "other-thread",
        obj! {"parent_room_id" => room.as_str(), "title" => "Other", "private" => false},
    );
    let update = room_updated(&b, "updated");
    assert_eq!(
        update.get("room_id"),
        Some(&Json::from(other.as_str())),
        "new thread for a member of its private room: {update:?}"
    );

    // A message may not move where fewer people can see it, which would
    // show them the private room; within the same audience, or to a wider
    // one, it may.
    let (public, _) = save(
        &mut a,
        "public",
        obj! {"body" => obj! {"text" => "in general"}},
    );
    b.notification("message");
    c.notification("message");
    a.expect_error(
        "message",
        "into-private",
        obj! {"message_id" => public.as_str(), "room_id" => room.as_str(), "body" => obj! {"text" => "in general"}},
        CODE_DENIED,
    );
    let (moved, _) = save(
        &mut a,
        "into-thread",
        obj! {"message_id" => secret.as_str(), "room_id" => thread.as_str(), "body" => obj! {"text" => "just us"}},
    );
    b.notification("message");
    assert_eq!(moved, secret, "moved message");
    a.expect_error(
        "message",
        "into-aside",
        obj! {"message_id" => secret.as_str(), "room_id" => aside.as_str(), "body" => obj! {"text" => "just us"}},
        CODE_DENIED,
    );
    c.expect_quiet();
    // private is fixed at creation.
    let (_, edited) = save_room(
        &mut b,
        "edit",
        obj! {"room_id" => room.as_str(), "title" => "DM", "private" => false},
    );
    assert_eq!(
        edited.get("private"),
        Some(&Json::from(true)),
        "private changed on edit: {edited:?}"
    );
    room_updated(&a, "updated");

    // Removing someone else is for the room's creator and moderators.
    b.expect_error(
        "room_leave",
        "remove-creator",
        obj! {"room_id" => room.as_str(), "user_id" => "guest_1"},
        CODE_DENIED,
    );
    let (before, result) = a.request(
        "room_leave",
        "remove",
        obj! {"room_id" => room.as_str(), "user_id" => "guest_2"},
    );
    assert!(
        result.is_empty() && methods(&before) == vec!["room_update", "room_update"],
        "removing a member: {before:?} then {result:?}"
    );
    // Losing the private room loses its threads: the removed member leaves
    // the one they joined, and is told of it.
    check_membership(&membership_only(&before[1]), &thread, "guest_2", false);
    expect_left(&b, &room, "guest_2");
    expect_left(&b, &thread, "guest_2");
    let left = room_updated(&b, "left");
    assert_eq!(
        left,
        obj! {"room_id" => other.as_str()},
        "removed member's update for a thread they had not joined"
    );
    for room_id in [&room, &thread] {
        let id = b.next_id("after-removal");
        b.expect_error(
            "history",
            &id,
            obj! {"room_id" => room_id.as_str()},
            CODE_INVALID_PARAMS,
        );
    }
    save(
        &mut a,
        "after",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "without b"}},
    );
    b.expect_quiet();
    // Removing someone not in the room changes nothing.
    a.result(
        "room_leave",
        "remove-again",
        obj! {"room_id" => room.as_str(), "user_id" => "guest_2"},
    );
    for client in [&mut a, &mut b, &mut c] {
        client.expect_quiet();
    }
}

/// A room with more members than max_listed_members lists its most recently
/// active members and member_count, the total (§4.2.1).
#[test]
fn test_member_lists_are_truncated_with_member_count() {
    let mut config = default_config();
    config.max_listed_members = 2;
    let server = new_test_server(config);
    let mut clients = dial_group(&server, 3);
    // guest_1 posts last, so guest_1 and guest_3, who joined last, are the
    // most recently active.
    save(
        &mut clients[0],
        "post",
        obj! {"body" => obj! {"text" => "hi"}},
    );
    for other in &clients[1..] {
        other.notification("message");
    }
    let listed = list_rooms(
        &mut clients[1],
        obj! {"room_id" => "general", "members" => true},
    );
    let mut entry = listed["not_joined"].as_list();
    if entry.is_empty() {
        entry = listed["joined"].as_list();
    }
    let general = entry[0].as_object().unwrap();
    assert!(
        general.get("member_count") == Some(&Json::from(3i64))
            && member_ids(general) == ids(&["guest_1", "guest_3"])
            && listed["users"].as_list().len() == 2,
        "truncated listing: {listed:?}"
    );
    // user_id lists only that member, also one the truncated listing leaves
    // out, and no one for a user who isn't a member.
    for (id, want) in [("guest_2", vec!["guest_2"]), ("nobody", vec![])] {
        let one = list_rooms(
            &mut clients[1],
            obj! {"room_id" => "general", "members" => true, "user_id" => id},
        );
        let mut rooms = one["not_joined"].as_list();
        if rooms.is_empty() {
            rooms = one["joined"].as_list();
        }
        let room = rooms[0].as_object().unwrap();
        assert!(
            !room.contains_key("member_count")
                && member_ids(room) == want
                && one["users"].as_list().len() == want.len(),
            "listing of {id}: {one:?}"
        );
    }
    // 0 lists every member.
    let mut unlimited = default_config();
    unlimited.max_listed_members = 0;
    let other = new_test_server(unlimited);
    let mut everyone = dial_group(&other, 3);
    let all = nth(
        &list_rooms(
            &mut everyone[0],
            obj! {"room_id" => "general", "members" => true},
        ),
        "joined",
        0,
    );
    assert!(
        !all.contains_key("member_count") && member_ids(&all).len() == 3,
        "unlimited listing: {all:?}"
    );
    // A room within the bound carries no member_count.
    let (ops, _) = save_room(&mut clients[0], "ops", obj! {"title" => "Ops"});
    let ops_entry = nth(
        &list_rooms(
            &mut clients[0],
            obj! {"room_id" => ops.as_str(), "members" => true},
        ),
        "joined",
        0,
    );
    assert!(
        !ops_entry.contains_key("member_count"),
        "untruncated listing: {ops_entry:?}"
    );
}

/// Leaving a private room sends room_update left once for each thread the
/// user could see there, and nothing about private threads they were never
/// in, whose room_ids stay unknown to them.
#[test]
fn test_leaving_a_private_room_hides_only_what_was_visible() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let (mut a, mut b) = (clients.remove(0), clients.remove(0));
    let (room, _) = save_room(&mut a, "room", obj! {"title" => "P", "private" => true});
    a.request(
        "room_join",
        "add",
        obj! {"room_id" => room.as_str(), "user_id" => b.user_id.as_str()},
    );
    b.drain();
    let (public, _) = save_room(
        &mut a,
        "public",
        obj! {"parent_room_id" => room.as_str(), "title" => "Public", "private" => false},
    );
    let (nested, _) = save_room(
        &mut a,
        "nested",
        obj! {"parent_room_id" => public.as_str(), "title" => "Nested"},
    );
    let (aside, _) = save_room(
        &mut a,
        "aside",
        obj! {"parent_room_id" => room.as_str(), "title" => "Aside", "private" => true},
    );
    save_room(
        &mut a,
        "inside-aside",
        obj! {"parent_room_id" => aside.as_str(), "title" => "Inside"},
    );
    let (shared, _) = save_room(
        &mut a,
        "shared",
        obj! {"parent_room_id" => room.as_str(), "title" => "Shared", "private" => true},
    );
    a.request(
        "room_join",
        "add-shared",
        obj! {"room_id" => shared.as_str(), "user_id" => b.user_id.as_str()},
    );
    let (in_shared, _) = save_room(
        &mut a,
        "in-shared",
        obj! {"parent_room_id" => shared.as_str(), "title" => "In shared", "private" => false},
    );
    b.drain();
    a.drain();

    let (before, _) = b.request("room_leave", "leave", obj! {"room_id" => room.as_str()});
    let mut left: Vec<String> = before
        .iter()
        .filter(|frame| frame.get("method") == Some(&Json::from("room_update")))
        .flat_map(|frame| {
            frame["params"].as_object().unwrap()["left"]
                .as_list()
                .iter()
                .map(|entry| {
                    entry.as_object().unwrap()["room_id"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect::<Vec<_>>()
        })
        .collect();
    left.sort();
    let mut want = vec![room, public, nested, shared, in_shared];
    want.sort();
    assert_eq!(left, want, "left (not {aside})");
}

/// A message moved out of a private room to where more people can see it
/// does not name the private room, and a reply cannot quote a message that
/// some who see the reply cannot see.
#[test]
fn test_moves_and_replies_out_of_private_rooms() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let (mut a, b) = (clients.remove(0), clients.remove(0));
    let (room, _) = save_room(&mut a, "room", obj! {"title" => "P", "private" => true});
    let (id, _) = save(
        &mut a,
        "secret",
        obj! {"room_id" => room.as_str(), "body" => obj! {"text" => "now public"}},
    );
    a.expect_error(
        "message",
        "reply",
        obj! {"body" => obj! {"text" => "re"}, "reply_to" => obj! {"message_id" => id.as_str()}},
        CODE_DENIED,
    );
    let (_, moved) = save(
        &mut a,
        "move",
        obj! {"message_id" => id.as_str(), "room_id" => "general", "body" => obj! {"text" => "now public"}},
    );
    let seen = b.notification("message");
    assert!(
        !seen.contains_key("prev_room_id") && seen == moved,
        "move out of a private room: {seen:?}"
    );
    // Within the same audience a reply may quote it.
    save(
        &mut a,
        "inner",
        obj! {"room_id" => room.as_str(), "body" => obj! {"text" => "inner"}},
    );
    let (inner, _) = save(
        &mut a,
        "inner-2",
        obj! {"room_id" => room.as_str(), "body" => obj! {"text" => "inner"}},
    );
    save(
        &mut a,
        "quote",
        obj! {"room_id" => room.as_str(), "body" => obj! {"text" => "re"}, "reply_to" => obj! {"message_id" => inner.as_str()}},
    );
}
