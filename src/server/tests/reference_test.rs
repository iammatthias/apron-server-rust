//! The upload and write tests of reference_test.go, test by test,
//! with the helpers the other reference_*_test.rs files share. Each keeps the
//! Go test's name, tables, and literal expectations.

use std::sync::mpsc;

use rust_stdlib::context::Context;
use rust_stdlib::io::PipeWriter;
use rust_stdlib::net::http;
use rust_stdlib::time::Duration;

use super::helpers::*;
use crate::obj;
use crate::server::embeds::{FILE_PATH, WRITE_PATH};
use crate::server::media_types::{image_size, upload_content_type};
use crate::server::protocol::*;

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
        409,
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
        let valid = image_size(content_type, Some(&file)).is_some();
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
            "embeds" => vec![Json::from(obj! {"kind" => "upload"}), Json::from(obj! {"kind" => "upload", "title" => "late.png"})],
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
        left.len() == 1 && left[0]["title"] == Json::from("late.png"),
        "after failed upload: {left:?}"
    );
    // The second write URL is never used, so it expires, and the message,
    // with neither text nor embeds, is a tombstone.
    let expired = a.notification("message");
    assert!(
        expired["deleted"] == Json::from(true) && !expired.contains_key("body"),
        "after expiry: {expired:?}"
    );
    let late = written[1].as_object().unwrap()["write_url"]
        .as_str()
        .unwrap();
    assert_eq!(
        http_do("PUT", late, Some(b"late"), "").0,
        409,
        "expired write URL"
    );
}

/// Starts a PUT of what is written to the returned pipe, as Go's tests do
/// with an `io.Pipe` body in a goroutine; the receiver gets the status, or
/// 0 when the request failed. The status is sent before the response body
/// is closed, where Go closes it first: rust-stdlib's close waits for the
/// request body to end, which a reply that comes before the body ends
/// would otherwise wait on.
pub(super) fn put_from_pipe(write_url: &str) -> (PipeWriter, mpsc::Receiver<u16>) {
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
pub(super) fn writer_status(status: &mpsc::Receiver<u16>) -> u16 {
    status
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the writer never finished")
}

pub(super) fn write_urls(result: &Object) -> Vec<String> {
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
    let (status, header, _) = http_do("POST", &write_url, Some(&png_of_size(16)), "image/png");
    assert!(
        status == 405 && header.get("Allow") == Some("PUT, OPTIONS"),
        "POST: {status}, Allow {:?}",
        header.get("Allow")
    );
    assert_eq!(
        http_do("PUT", &write_url, Some(&png_of_size(16)), "image/png").0,
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
        "upload",
        obj! {"room_id" => "general", "body" => obj! {"embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
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
    assert_eq!(response.status_code, 409, "status");
}

/// The i-th room record in a room_list array.
pub(super) fn nth(listed: &Object, key: &str, i: usize) -> Object {
    listed[key].as_list()[i].as_object().cloned().unwrap()
}

/// Reports whether a key is missing or null, as Go's `m[key] == nil`.
pub(super) fn absent(o: &Object, key: &str) -> bool {
    o.get(key).is_none_or(|v| *v == Json::Null)
}

pub(super) fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}

pub(super) fn empty() -> Json {
    Json::Array(vec![])
}
