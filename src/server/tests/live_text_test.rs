//! Live text (§4.8.3, §4.8.5, §4.8.6), ported from apron-server-cloudflare's
//! test/live-text.test.ts and test/live-text.integration.test.ts.

use std::io::Read;
use std::sync::{mpsc, Arc, Mutex};

use rust_stdlib::io::PipeWriter;
use rust_stdlib::net::http;
use rust_stdlib::time::Duration;

use super::helpers::*;
use crate::obj;
use crate::server::config::Config;
use crate::server::live_text::*;
use crate::server::protocol::*;

fn encode(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

/// §4.8.6's reference `keep_last`, in Python's words.
fn reference(output: &[u8], limit: usize) -> Vec<u8> {
    if output.len() <= limit {
        return output.to_vec();
    }
    let tail = &output[output.len() - limit..];
    if let Some(i) = tail.iter().position(|&b| b < 0x20) {
        return tail[i..].to_vec();
    }
    let start = tail
        .iter()
        .position(|&b| !(0x80..0xc0).contains(&b))
        .unwrap_or(tail.len());
    tail[start..].to_vec()
}

fn keep_append(bytes: &[u8], limit: usize) -> Vec<u8> {
    let mut buffer = LiveBuffer::new(LiveKind::Append, limit);
    buffer.push(bytes);
    buffer.end(false);
    buffer.kept().to_vec()
}

#[test]
fn test_live_text_string_decodes_as_whatwg() {
    assert_eq!(
        live_text_string(&[0x61, 0xf1, 0x80, 0x80, 0xe1, 0x80, 0xc2, 0x62]),
        "a\u{FFFD}\u{FFFD}\u{FFFD}b"
    );
    assert_eq!(
        live_text_string(&[0xe1, 0x80, 0xe2, 0xf0, 0x91, 0x92, 0xf1, 0xbf, 0x41]),
        "\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}A"
    );
    assert_eq!(live_text_string(&[0x65, 0xe2, 0x82]), "e\u{FFFD}");
    assert_eq!(live_text_string(&[0xef, 0xbb, 0xbf, 0x62]), "\u{FEFF}b");
}

#[test]
fn test_keep_last_and_the_appends_first_part() {
    assert_eq!(keep_last(b"abc\x1b[31mdef", 100), b"abc\x1b[31mdef");
    assert_eq!(keep_last(b"line one\nline two\nxy", 8), b"\nxy");
    assert_eq!(keep_last(b"\x1b[31mred\x1b[0m", 6), b"\x1b[0m");
    assert_eq!(keep_last(&encode("aééé"), 5), encode("éé"));
    assert_eq!(keep_last(&[0x61, 0xe2, 0x82, 0xac, 0x62], 3), [0x62]);
    assert_eq!(keep_last(&[0x80, 0x80, 0x80], 2), [0u8; 0]);
    // The reference function on pseudo-random bytes and limits.
    let alphabet = [
        0x0a, 0x1b, 0x20, 0x41, 0x7e, 0x80, 0x9f, 0xbf, 0xc3, 0xe2, 0xf0,
    ];
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = |n: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % n as u64) as usize
    };
    for _ in 0..500 {
        let input: Vec<u8> = (0..next(40))
            .map(|_| alphabet[next(alphabet.len())])
            .collect();
        let limit = 1 + next(30);
        assert_eq!(
            keep_last(&input, limit),
            reference(&input, limit),
            "{input:?} {limit}"
        );
    }
    assert_eq!(keep_append(&encode("héllo"), 2), encode("h"));
    assert_eq!(keep_append(&encode("héllo"), 3), encode("hé"));
    assert_eq!(keep_append(&encode("abc"), 5), encode("abc"));
    assert_eq!(keep_append(&encode("€"), 2), encode(""));
    assert_eq!(
        keep_append(&[0x61, 0xff, 0xe2, 0x82], 10),
        encode("a\u{FFFD}\u{FFFD}")
    );
}

#[test]
fn test_terminal_buffer_keeps_one_cut_of_everything() {
    for limit in [16, 23, 40, 63] {
        let mut buffer = LiveBuffer::new(LiveKind::Terminal, limit);
        let mut all = Vec::new();
        for chunk in 0..40 {
            let lead = if chunk % 3 != 0 { "é" } else { "\n" };
            let piece = encode(&format!(
                "{lead}\x1b[3{}mchunk {chunk} {}",
                chunk % 8,
                "x".repeat(chunk % 7)
            ));
            all.extend_from_slice(&piece);
            assert_eq!(buffer.push(&piece), piece);
            assert_eq!(buffer.kept(), reference(&all, limit));
        }
        assert_eq!(buffer.received, all.len());
    }
    // Backspace and form feed stay terminal control functions.
    let mut buffer = LiveBuffer::new(LiveKind::Terminal, 64);
    let output = encode("abc\x08\x08de\x0cclear\x08");
    assert_eq!(buffer.push(&output), output);
    assert_eq!(buffer.end(false), encode(""));
    assert_eq!(buffer.kept(), output);
}

#[test]
fn test_append_buffer_keeps_its_first_part() {
    let mut buffer = LiveBuffer::new(LiveKind::Append, 5);
    assert_eq!(buffer.push(b"ab"), b"ab");
    assert_eq!(buffer.push(&encode("cé€")), encode("cé"));
    assert!(buffer.full);
    assert_eq!(buffer.kept(), encode("abcé"));
    assert_eq!(buffer.push(b"more"), b"");
}

#[test]
fn test_append_backspace_and_form_feed() {
    let text = |b: &LiveBuffer| live_text_string(b.kept());
    let mut buffer = LiveBuffer::new(LiveKind::Append, 64);
    buffer.push(&encode("caf\u{e9}\x08"));
    assert_eq!(text(&buffer), "caf");
    buffer.push(&encode("e \u{1F680}\x08\u{1F600}"));
    assert_eq!(text(&buffer), "cafe \u{1F600}");
    buffer.push(b"\x08\x08");
    assert_eq!(text(&buffer), "cafe");
    // U+FFFD from an invalid byte is one code point too.
    buffer.push(&[0xff, 0x08, 0x21]);
    assert_eq!(text(&buffer), "cafe!");

    let mut buffer = LiveBuffer::new(LiveKind::Append, 64);
    buffer.push(b"draft one\x0cdraft two");
    assert_eq!(text(&buffer), "draft two");
    buffer.push(&encode(
        "\x0c\x08\x08\x08Hello wrold\x08\x08\x08\x08orld, caf\u{e9}\x08e",
    ));
    assert_eq!(text(&buffer), "Hello world, cafe");
    buffer.push(b"\x0c");
    assert_eq!(buffer.kept(), b"");
    assert_eq!(keep_append(b"\x08\x08ok", 10), b"ok");
}

#[test]
fn test_append_edits_the_same_however_split() {
    let text = encode("ab\u{e9}\u{20ac}\u{1F680}\x08x\x0cy\u{e9}\u{1F600}\x08\u{1F431}\x08z\u{e9}");
    let whole = keep_append(&text, 64);
    assert_eq!(live_text_string(&whole), "y\u{e9}z\u{e9}");
    for cut in 0..=text.len() {
        let mut buffer = LiveBuffer::new(LiveKind::Append, 64);
        let mut sent = buffer.push(&text[..cut]);
        sent.extend(buffer.push(&text[cut..]));
        sent.extend(buffer.end(false));
        assert_eq!(buffer.kept(), whole, "cut at {cut}");
        assert_eq!(sent, text, "readers at cut {cut}");
    }
}

#[test]
fn test_append_sends_whole_characters() {
    let mut buffer = LiveBuffer::new(LiveKind::Append, 64);
    assert_eq!(buffer.push(&[0x61, 0xc3]), b"a");
    assert_eq!(buffer.kept(), b"a");
    assert_eq!(buffer.push(&[0xa9, 0x08, 0x62]), encode("\u{e9}\x08b"));
    assert_eq!(buffer.kept(), b"ab");
    assert_eq!(buffer.push(&[0xe2, 0x82]), b"");
    assert_eq!(buffer.end(false), encode("\u{FFFD}"));
    assert_eq!(buffer.kept(), encode("ab\u{FFFD}"));
    // Cut at its input limit, a partial character is dropped; a clean end
    // reads it as U+FFFD.
    let mut cut = LiveBuffer::new(LiveKind::Append, 8);
    cut.push(b"ab\x08\x08xyz");
    assert_eq!(cut.push(&[0xc3]), b"");
    assert_eq!(cut.end(true), b"");
    assert_eq!(cut.kept(), b"xyz");
    let mut clean = LiveBuffer::new(LiveKind::Append, 8);
    clean.push(b"ab\x08\x08xyz");
    clean.push(&[0xc3]);
    assert_eq!(clean.end(false), encode("\u{FFFD}"));
    assert_eq!(clean.kept(), encode("xyz\u{FFFD}"));
}

#[test]
fn test_append_limit_counts_the_edited_text() {
    let mut buffer = LiveBuffer::new(LiveKind::Append, 4);
    buffer.push(b"abcd\x08\x08ef");
    assert!(!buffer.full);
    assert_eq!(buffer.kept(), b"abef");
    assert_eq!(buffer.push(b"gh"), b"");
    assert!(buffer.full);
    assert_eq!(buffer.kept(), b"abef");
    let mut cut = LiveBuffer::new(LiveKind::Append, 4);
    assert_eq!(
        cut.push(&encode("xy\x0c\u{e9}a\u{20ac}z")),
        encode("xy\x0c\u{e9}a")
    );
    assert!(cut.full);
    assert_eq!(cut.kept(), encode("\u{e9}a"));
    let mut drafts = LiveBuffer::new(LiveKind::Append, 4);
    for _ in 0..1000 {
        drafts.push(b"four\x0c");
        assert!(!drafts.full);
    }
    assert_eq!(drafts.kept(), b"");
}

#[test]
fn test_live_policy_and_notice() {
    let limits = LiveLimits::default();
    assert_eq!(
        (limits.max, limits.moderator_max, limits.append_max_bytes),
        (Duration::from_secs(120), Duration::from_secs(300), 4096),
        "Cloudflare's Workers Paid policy"
    );
    assert_eq!(
        (
            limits.terminal_keep_bytes,
            limits.max_input_bytes,
            limits.concurrent
        ),
        (32 << 10, 2 << 20, 4)
    );
    let notice = command_notice(
        LiveKind::Terminal,
        "https://chat.example/write/t",
        limits.max,
        limits.terminal_keep_bytes,
        &limits,
    );
    assert!(notice.starts_with("Stream a terminal into this room within 2 minutes (80×40, up to 120 seconds and 2 MB; the last 32 KB is kept):\n\n```sh\nscript -qfc 'stty cols 80 rows 40; YOUR_COMMAND' /dev/null | curl -sT - 'https://chat.example/write/t'\n```"), "{notice}");
    let notice = command_notice(
        LiveKind::Append,
        "https://chat.example/write/a",
        limits.moderator_max,
        4000,
        &limits,
    );
    assert!(notice.starts_with("Stream text into this room within 2 minutes (up to 300 seconds and 4,000 bytes; it is appended to your message as markdown, revised by backspace and form feed):\n\n```sh\nyour-llm-command | curl -sT - 'https://chat.example/write/a'\n```"), "{notice}");
}

/// A `PUT` whose body is what is written to the pipe; the receiver gets the
/// status and the answer's text, read to its line feed rather than to the
/// body's end: rust-stdlib's client ends a response body only once the
/// request body has ended too, and the server may answer before that.
fn stream_to(write_url: &str) -> (PipeWriter, mpsc::Receiver<(u16, String)>) {
    let (body, pipe) = rust_stdlib::io::pipe();
    let (done, answer) = mpsc::channel();
    let request = http::Request::new("PUT", write_url)
        .unwrap()
        .with_body(http::RequestBody::reader(body));
    std::thread::spawn(
        move || match http::client::DEFAULT_CLIENT.do_request(request) {
            Ok(response) => {
                let mut text = Vec::new();
                if let Some(mut body) = response.body.clone() {
                    let mut buf = [0u8; 512];
                    while !text.ends_with(b"\n") {
                        match body.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => text.extend_from_slice(&buf[..n]),
                        }
                    }
                }
                let _ = done.send((
                    response.status_code,
                    String::from_utf8_lossy(&text).into_owned(),
                ));
            }
            Err(_) => {
                let _ = done.send((0, String::new()));
            }
        },
    );
    (pipe, answer)
}

fn answer(answer: &mpsc::Receiver<(u16, String)>) -> (u16, String) {
    answer
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the writer was never answered")
}

/// A reader of a live text's url, collecting what it reads.
struct Reader {
    status: u16,
    header: http::Header,
    got: Arc<Mutex<(Vec<u8>, bool)>>,
}

impl Reader {
    fn open(url: &str) -> Reader {
        let response = http::client::get(url).unwrap_or_else(|e| panic!("GET {url}: {e}"));
        let got = Arc::new(Mutex::new((Vec::new(), false)));
        if let Some(mut body) = response.body.clone() {
            let got = got.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match body.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.lock().unwrap().0.extend_from_slice(&buf[..n]),
                    }
                }
                got.lock().unwrap().1 = true;
            });
        }
        Reader {
            status: response.status_code,
            header: response.header,
            got,
        }
    }

    fn text(&self) -> Vec<u8> {
        self.got.lock().unwrap().0.clone()
    }

    fn wait_for(&self, want: &[u8]) {
        wait_for(|| self.text().windows(want.len()).any(|w| w == want));
    }

    fn ended(&self) -> Vec<u8> {
        wait_for(|| self.got.lock().unwrap().1);
        self.text()
    }
}

/// Runs a command and returns its ~private notice's text and its result.
fn live_command(c: &mut TestClient, text: &str, extra: Object) -> (String, Object) {
    let id = c.next_id("live");
    let mut params = obj! {"body" => obj! {"text" => text}};
    params.extend(extra);
    let (before, result) = c.request("command", &id, params);
    let notice = before
        .iter()
        .map(|f| notification_params(f, "message"))
        .find(|m| m["from"].as_object().unwrap()["user_id"] == Json::from("~private"))
        .unwrap_or_else(|| panic!("no notice before {result:?}: {before:?}"));
    let text = notice["body"].as_object().unwrap()["text"]
        .as_str()
        .unwrap()
        .to_owned();
    (text, result)
}

fn written(result: &Object) -> Object {
    result["embeds"].as_list()[0].as_object().unwrap().clone()
}

fn body_of(snapshot: &Object) -> Object {
    snapshot["body"].as_object().unwrap().clone()
}

/// Reads frames until a message snapshot from `user_id`.
fn message_from(c: &TestClient, user_id: &str) -> Object {
    loop {
        let frame = c.read();
        if frame.get("method") == Some(&Json::from("message")) {
            let params = notification_params(&frame, "message");
            if params["from"].as_object().unwrap()["user_id"] == Json::from(user_id) {
                return params;
            }
        }
    }
}

/// Reads frames until a later snapshot of `message_id`.
fn snapshot_of(c: &TestClient, message_id: &str) -> Object {
    loop {
        let frame = c.read();
        if frame.get("method") == Some(&Json::from("message")) {
            let params = notification_params(&frame, "message");
            if params.get("message_id") == Some(&Json::from(message_id)) {
                return params;
            }
        }
    }
}

/// Reads frames until the snapshot of `message_id` that gives its live
/// embed a `url` (§4.8.5), returning the snapshot and the url.
fn url_added(c: &TestClient, message_id: &str) -> (Object, String) {
    let snapshot = snapshot_of(c, message_id);
    let url = body_of(&snapshot)["embeds"].as_list()[0]
        .as_object()
        .unwrap()
        .get("url")
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("the next snapshot has no url: {snapshot:?}"))
        .to_owned();
    (snapshot, url)
}

/// The live embed of a message's first snapshot, which has no `url` while
/// it waits for its writer (§4.8.5).
fn waiting_embed(result: &Object) -> Object {
    body_of(result["snapshot"].as_object().unwrap())["embeds"].as_list()[0]
        .as_object()
        .unwrap()
        .clone()
}

fn live_config() -> Config {
    default_config()
}

/// A terminal embed's og, as the server gives it (§4.8.1).
fn card(title: &str) -> Json {
    obj! {"title" => title, "description" => "Terminal output. Open it to watch."}.into()
}

#[test]
fn test_live_text_is_advertised_and_toggled() {
    let server = admin_test_server();
    let (_, frame) = dial_raw(&server);
    let caps = frame["params"].as_object().unwrap()["capabilities"].clone();
    for cap in ["embed:terminal", "embed:append"] {
        assert!(caps.as_list().contains(&Json::from(cap)), "{caps:?}");
    }
    assert!(!caps.as_list().contains(&Json::from("embed:stream")));
    let mut admin = admin(&server);
    assert!(private_reply(&mut admin, "/toggle livetext").contains("Live text is now **off**"));
    let (_, later) = dial_raw(&server);
    let caps = later["params"].as_object().unwrap()["capabilities"].clone();
    assert!(
        !caps.as_list().contains(&Json::from("embed:terminal")),
        "{caps:?}"
    );
    assert_eq!(
        command_error(&mut admin, "/embed-terminal"),
        (
            CODE_INVALID_PARAMS,
            "Unknown command /embed-terminal; try /help".into()
        )
    );
    let frame = reply(
        &mut admin,
        "message",
        "post",
        obj! {"body" => obj! {"embeds" => vec![Json::from(obj! {"kind" => "terminal"})]}},
    );
    assert_eq!(
        frame["error"],
        Json::from(obj! {"code" => CODE_DENIED, "message" => "Live text is turned off here"})
    );
    assert!(private_reply(&mut admin, "/toggle livetext").contains("Live text is now **on**"));
}

#[test]
fn test_embed_terminal_streams_then_keeps_its_output() {
    let server = new_test_server(live_config());
    let mut writer = dial_test_client(&server);
    let watcher = dial_test_client(&server);
    writer.drain();
    let (notice, result) = live_command(&mut writer, "/embed-terminal make test", Object::new());
    let embed = written(&result);
    let write_url = embed["write_url"].as_str().unwrap().to_owned();
    assert!(
        write_url.starts_with(&format!("{}/write/", server.http.url)),
        "{write_url}"
    );
    assert!(notice.starts_with("Stream a terminal into this room within 2 minutes (80×40, up to 120 seconds and 2 MB; the last 32 KB is kept):"), "{notice}");
    assert!(notice.contains(&format!(
        "script -qfc 'stty cols 80 rows 40; YOUR_COMMAND' /dev/null | curl -sT - '{write_url}'"
    )));

    let (put, done) = stream_to(&write_url);
    put.write_shared(b"\x1b[32mok\x1b[0m 1\r\n").unwrap();
    let posted = message_from(&watcher, &writer.user_id);
    let body = body_of(&posted);
    let live = body["embeds"].as_list()[0].as_object().unwrap().clone();
    let url = live["url"].as_str().unwrap().to_owned();
    assert!(
        url.starts_with(&format!("{}{LIVE_PATH}", server.http.url)),
        "{url}"
    );
    assert_eq!(
        body,
        obj! {"text" => "", "format" => "plain", "embeds" => vec![Json::from(obj! {
            "embed_id" => embed["embed_id"].clone(), "kind" => "terminal", "title" => "make test", "url" => url.as_str(), "og" => card("make test"),
        })]}
    );
    let reader = Reader::open(&url);
    assert_eq!(reader.status, 200);
    assert_eq!(
        reader.header.get("Content-Type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(reader.header.get("X-Content-Type-Options"), Some("nosniff"));
    assert_eq!(
        reader.header.get("Cache-Control"),
        Some("no-store, no-transform")
    );
    assert_eq!(reader.header.get("Access-Control-Allow-Origin"), Some("*"));
    reader.wait_for(b"ok\x1b[0m 1\r\n");
    put.write_shared(b"\x1b[31mfail\x1b[0m 2\r\n").unwrap();
    reader.wait_for(b"fail");
    put.close();
    assert_eq!(answer(&done), (200, "Done: the text is posted.\n".into()));
    let output = "\x1b[32mok\x1b[0m 1\r\n\x1b[31mfail\x1b[0m 2\r\n";
    assert_eq!(reader.ended(), output.as_bytes());
    let finished = snapshot_of(&watcher, posted["message_id"].as_str().unwrap());
    assert_eq!(
        body_of(&finished)["embeds"],
        Json::from(vec![Json::from(obj! {
            "embed_id" => embed["embed_id"].clone(), "kind" => "terminal", "title" => "make test", "output" => output, "og" => card("make test"),
        })])
    );
    assert_eq!(finished["prev_log_id"], posted["log_id"]);
    assert_eq!(http_get(&url).0, 404, "the url after the text ended");
    assert_eq!(
        http_do("PUT", &write_url, Some(b"again"), "").0,
        409,
        "the write_url again"
    );
}

#[test]
fn test_embed_append_replies_and_merges_into_markdown() {
    let server = new_test_server(live_config());
    let mut writer = dial_test_client(&server);
    let (question, _) = save(
        &mut writer,
        "q",
        obj! {"body" => obj! {"text" => "What now?"}},
    );
    writer.drain();
    let (notice, result) = live_command(
        &mut writer,
        "/embed-append **Plan:** ",
        obj! {"reply_to" => obj! {"message_id" => question.as_str()}},
    );
    let embed = written(&result);
    let write_url = embed["write_url"].as_str().unwrap().to_owned();
    assert_eq!(embed["kind"], Json::from("append"));
    assert!(
        notice.contains(&format!("your-llm-command | curl -sT - '{write_url}'")),
        "{notice}"
    );
    let (put, done) = stream_to(&write_url);
    put.write_shared(b"1. Roll ").unwrap();
    let posted = message_from(&writer, &writer.user_id);
    assert_eq!(
        posted["reply_to"],
        Json::from(obj! {"message_id" => question.as_str()})
    );
    let body = body_of(&posted);
    assert_eq!(body["text"], Json::from("**Plan:**\n\n"));
    assert_eq!(body["format"], Json::from("markdown"));
    let url = body["embeds"].as_list()[0].as_object().unwrap()["url"]
        .as_str()
        .unwrap()
        .to_owned();
    let reader = Reader::open(&url);
    reader.wait_for(b"1. Roll ");
    put.write_shared(b"back.\n2. Renew the *cert*.\n").unwrap();
    put.close();
    assert_eq!(answer(&done).0, 200);
    let merged = snapshot_of(&writer, posted["message_id"].as_str().unwrap());
    assert_eq!(
        body_of(&merged),
        obj! {"text" => "**Plan:**\n\n1. Roll back.\n2. Renew the *cert*.\n", "format" => "markdown"}
    );
    assert_eq!(reader.ended(), b"1. Roll back.\n2. Renew the *cert*.\n");
}

#[test]
fn test_append_edits_reach_readers_and_the_snapshot() {
    let server = new_test_server(live_config());
    let mut writer = dial_test_client(&server);
    writer.drain();
    let result = super::helpers::post_embeds(
        &mut writer,
        "revise",
        obj! {"body" => obj! {"text" => "Plan:", "format" => "markdown", "embeds" => vec![Json::from(obj! {"kind" => "append"})]}},
    );
    let message_id = result["message_id"].as_str().unwrap().to_owned();
    let (put, done) = stream_to(written(&result)["write_url"].as_str().unwrap());
    let (_, url) = url_added(&writer, &message_id);
    let early = Reader::open(&url);
    put.write_shared(b"\x08\x08 first draft\x0c").unwrap();
    put.write_shared(b" Hello wrold\x08\x08\x08\x08").unwrap();
    early.wait_for(b"wrold\x08\x08\x08\x08");
    put.write_shared(&[0x6f, 0x72, 0x6c, 0x64, 0x2c, 0x20, 0x63, 0x61, 0x66, 0xc3])
        .unwrap();
    put.write_shared(&[0xa9, 0x08, 0x65]).unwrap();
    early.wait_for(&encode("caf\u{e9}\x08e"));
    let late = Reader::open(&url);
    late.wait_for(b" Hello world, cafe");
    put.write_shared(&encode(" \u{1F680}\x08!")).unwrap();
    late.wait_for(b"!");
    put.close();
    assert_eq!(answer(&done), (200, "Done: the text is posted.\n".into()));
    assert_eq!(
        early.ended(),
        encode("\x08\x08 first draft\x0c Hello wrold\x08\x08\x08\x08orld, caf\u{e9}\x08e \u{1F680}\x08!")
    );
    assert_eq!(late.ended(), encode(" Hello world, cafe \u{1F680}\x08!"));
    let merged = snapshot_of(&writer, &message_id);
    assert_eq!(
        body_of(&merged),
        obj! {"text" => "Plan: Hello world, cafe !", "format" => "markdown"}
    );
}

#[test]
fn test_append_write_stops_at_what_it_keeps() {
    let server = new_test_server(live_config());
    let mut writer = dial_test_client(&server);
    writer.drain();
    let (_, result) = live_command(&mut writer, "/embed-append", Object::new());
    let (put, done) = stream_to(written(&result)["write_url"].as_str().unwrap());
    put.write_shared(&"a".repeat(1000).into_bytes()).unwrap();
    let id = message_from(&writer, &writer.user_id)["message_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for _ in 0..4 {
        let _ = put.write_shared(&"b\x08".repeat(500).into_bytes());
    }
    let _ = put.write_shared(&"c".repeat(1000).into_bytes());
    put.close();
    assert_eq!(
        answer(&done),
        (
            413,
            "Stopped at the 4 KB limit; what was kept is posted.\n".into()
        )
    );
    assert_eq!(
        body_of(&snapshot_of(&writer, &id)),
        obj! {"text" => "a".repeat(1000), "format" => "markdown"}
    );
    // A character cut at the input limit is dropped, for readers too.
    let (_, result) = live_command(&mut writer, "/embed-append", Object::new());
    let (put, done) = stream_to(written(&result)["write_url"].as_str().unwrap());
    put.write_shared(&format!("{}x", "a\x08".repeat(2047)).into_bytes())
        .unwrap();
    let posted = message_from(&writer, &writer.user_id);
    let url = body_of(&posted)["embeds"].as_list()[0].as_object().unwrap()["url"]
        .as_str()
        .unwrap()
        .to_owned();
    let reader = Reader::open(&url);
    reader.wait_for(b"x");
    let _ = put.write_shared(&encode("\u{e9} and more"));
    put.close();
    assert_eq!(
        answer(&done),
        (
            413,
            "Stopped at the 4 KB limit; what was kept is posted.\n".into()
        )
    );
    assert_eq!(reader.ended(), b"x");
    assert_eq!(
        body_of(&snapshot_of(
            &writer,
            posted["message_id"].as_str().unwrap()
        )),
        obj! {"text" => "x", "format" => "markdown"}
    );
}

#[test]
fn test_message_embeds_get_their_url_when_the_write_starts() {
    let server = new_test_server(live_config());
    let mut writer = dial_test_client(&server);
    writer.drain();
    let result = super::helpers::post_embeds(
        &mut writer,
        "post",
        obj! {"body" => obj! {"text" => "Build:", "embeds" => vec![Json::from(obj! {"kind" => "terminal", "title" => "ci", "output" => "forged", "og" => obj! {"title" => "x"}})]}},
    );
    let message_id = result["message_id"].as_str().unwrap().to_owned();
    let posted = result["snapshot"].as_object().unwrap().clone();
    let embed_id = waiting_embed(&result)["embed_id"].clone();
    assert_eq!(
        waiting_embed(&result),
        obj! {"embed_id" => embed_id.clone(), "kind" => "terminal", "title" => "ci", "og" => card("ci")},
        "the embed waits for its writer, with no url, and the server's og for the sender's"
    );
    assert_eq!(
        written(&result).keys().cloned().collect::<Vec<_>>(),
        ["embed_id", "kind", "write_url"]
    );
    assert!(
        server.app.lock().live_ids.is_empty(),
        "no url before the write"
    );
    let (put, done) = stream_to(written(&result)["write_url"].as_str().unwrap());
    let (started, url) = url_added(&writer, &message_id);
    assert!(
        url.starts_with(&format!("{}{LIVE_PATH}", server.http.url)),
        "{url}"
    );
    assert_eq!(
        body_of(&started),
        obj! {"text" => "Build:", "format" => "plain", "embeds" => vec![Json::from(obj! {
            "embed_id" => embed_id.clone(), "kind" => "terminal", "title" => "ci", "url" => url.as_str(), "og" => card("ci"),
        })]}
    );
    assert_eq!(started["prev_log_id"], posted["log_id"]);
    assert_ne!(started["log_id"], posted["log_id"]);
    // A reader before the first bytes waits for them.
    let early = Reader::open(&url);
    assert_eq!(early.status, 200);
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(
        !early.got.lock().unwrap().1,
        "a reader before the first bytes ended"
    );
    put.write_shared(b"step 1\n").unwrap();
    early.wait_for(b"step 1\n");
    put.close();
    assert_eq!(answer(&done), (200, "Done: the text is posted.\n".into()));
    assert_eq!(early.ended(), b"step 1\n");
    let finished = snapshot_of(&writer, &message_id);
    assert_eq!(finished["prev_log_id"], started["log_id"]);
    assert_eq!(
        body_of(&finished),
        obj! {"text" => "Build:", "format" => "plain", "embeds" => vec![Json::from(obj! {
            "embed_id" => embed_id.clone(), "kind" => "terminal", "title" => "ci", "output" => "step 1\n", "og" => card("ci"),
        })]}
    );
    // A save keeps the output and takes a new title, its og retitled with
    // it; a kind cannot change.
    let (_, saved) = save(
        &mut writer,
        "retitle",
        obj! {"message_id" => result["message_id"].clone(), "body" => obj! {"text" => "Build:", "embeds" => vec![Json::from(obj! {"embed_id" => embed_id.clone(), "kind" => "terminal", "title" => "ci 2", "output" => "forged", "og" => obj! {"title" => "forged"}})]}},
    );
    assert_eq!(
        body_of(&saved)["embeds"],
        Json::from(vec![Json::from(
            obj! {"embed_id" => embed_id.clone(), "kind" => "terminal", "title" => "ci 2", "output" => "step 1\n", "og" => card("ci 2")}
        )])
    );
    let (_, untitled) = save(
        &mut writer,
        "untitle",
        obj! {"message_id" => result["message_id"].clone(), "body" => obj! {"text" => "Build:", "embeds" => vec![Json::from(obj! {"embed_id" => embed_id.clone(), "kind" => "terminal"})]}},
    );
    assert_eq!(
        body_of(&untitled)["embeds"],
        Json::from(vec![Json::from(
            obj! {"embed_id" => embed_id.clone(), "kind" => "terminal", "output" => "step 1\n", "og" => card("Terminal")}
        )])
    );
    writer.expect_error(
        "message",
        "kind",
        obj! {"message_id" => result["message_id"].clone(), "body" => obj! {"text" => "Build:", "embeds" => vec![Json::from(obj! {"embed_id" => embed_id, "kind" => "append"})]}},
        CODE_INVALID_PARAMS,
    );
    // A terminal or append in any other command is invalid_params.
    let frame = reply(
        &mut writer,
        "command",
        "help-embed",
        obj! {"body" => obj! {"text" => "/help", "embeds" => vec![Json::from(obj! {"kind" => "terminal"})]}},
    );
    assert_eq!(
        frame["error"],
        Json::from(
            obj! {"code" => CODE_INVALID_PARAMS, "message" => "A terminal or append embed goes in a message; or use /embed-terminal or /embed-append"}
        )
    );
}

#[test]
fn test_one_append_and_one_start_per_message() {
    let server = new_test_server(live_config());
    let mut writer = dial_test_client(&server);
    writer.drain();
    let two = |a: &str, b: &str| {
        obj! {"body" => obj! {"text" => "x", "embeds" => vec![Json::from(obj! {"kind" => a}), Json::from(obj! {"kind" => b})]}}
    };
    let frame = reply(&mut writer, "message", "appends", two("append", "append"));
    assert_eq!(
        frame["error"],
        Json::from(
            obj! {"code" => CODE_INVALID_PARAMS, "message" => "A message has at most one append embed"}
        )
    );
    let frame = reply(&mut writer, "message", "two", two("terminal", "append"));
    assert_eq!(
        frame["error"],
        Json::from(
            obj! {"code" => CODE_DENIED, "message" => "A message can start one live text (terminal or append) at a time"}
        )
    );
}

#[test]
fn test_saving_without_the_embed_ends_the_text() {
    let server = new_test_server(live_config());
    let mut writer = dial_test_client(&server);
    writer.drain();
    let result = super::helpers::post_embeds(
        &mut writer,
        "post",
        obj! {"body" => obj! {"text" => "Build:", "embeds" => vec![Json::from(obj! {"kind" => "terminal"})]}},
    );
    let (put, done) = stream_to(written(&result)["write_url"].as_str().unwrap());
    put.write_shared(b"partial").unwrap();
    url_added(&writer, result["message_id"].as_str().unwrap());
    save(
        &mut writer,
        "stop",
        obj! {"message_id" => result["message_id"].clone(), "body" => obj! {"text" => "never mind"}},
    );
    assert_eq!(
        answer(&done),
        (
            200,
            "Stopped: the message or its embed was removed.\n".into()
        )
    );
    put.close();
    writer.expect_quiet();
}

#[test]
fn test_time_limits_by_role() {
    let mut config = admin_config();
    config.live.max = Duration::from_millis(300);
    config.live.moderator_max = Duration::from_secs(1);
    let server = new_test_server(config);
    let mut guest = dial_test_client(&server);
    guest.drain();
    let (notice, result) = live_command(&mut guest, "/embed-terminal", Object::new());
    assert!(notice.contains("up to 0 seconds"), "{notice}");
    let (put, done) = stream_to(written(&result)["write_url"].as_str().unwrap());
    put.write_shared(b"tick\n").unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        answer(&done),
        (
            408,
            "Stopped at the 0-second limit; what was kept is posted.\n".into()
        )
    );
    let took = started.elapsed();
    assert!(took < std::time::Duration::from_millis(900), "{took:?}");
    put.close();
    let mut admin = admin(&server);
    let (notice, result) = live_command(&mut admin, "/embed-terminal", Object::new());
    assert!(notice.contains("up to 1 seconds"), "{notice}");
    let (put, done) = stream_to(written(&result)["write_url"].as_str().unwrap());
    put.write_shared(b"tick\n").unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        answer(&done),
        (
            408,
            "Stopped at the 1-second limit; what was kept is posted.\n".into()
        )
    );
    assert!(started.elapsed() >= std::time::Duration::from_millis(900));
    put.close();
}

#[test]
fn test_one_open_text_per_user_and_unused_writes_expire() {
    let mut config = live_config();
    config.live.write_window = Duration::from_millis(300);
    let server = new_test_server(config);
    let mut writer = dial_test_client(&server);
    writer.drain();
    let (_, first) = live_command(&mut writer, "/embed-terminal", Object::new());
    assert_eq!(
        command_error(&mut writer, "/embed-append"),
        (
            CODE_DENIED,
            "You already have a live text open; finish it, or let its write_url expire, before you start another".into()
        )
    );
    wait_for(|| server.app.lock().embeds.is_empty());
    assert_eq!(
        http_do(
            "PUT",
            written(&first)["write_url"].as_str().unwrap(),
            Some(b"late"),
            ""
        )
        .0,
        409
    );
    // A message's unused write expires: its embed leaves, and a message
    // with no text left is a tombstone.
    let result = super::helpers::post_embeds(
        &mut writer,
        "post",
        obj! {"body" => obj! {"embeds" => vec![Json::from(obj! {"kind" => "terminal"})]}},
    );
    let expired = snapshot_of(&writer, result["message_id"].as_str().unwrap());
    assert_eq!(expired["deleted"], Json::from(true), "{expired:?}");
}

#[test]
fn test_start_and_reader_limits() {
    let mut config = live_config();
    config.live.concurrent = 0;
    let server = new_test_server(config);
    let mut writer = dial_test_client(&server);
    writer.drain();
    let mut starts = 0;
    let refusal = loop {
        let id = writer.next_id("start");
        let frame = reply(
            &mut writer,
            "command",
            &id,
            obj! {"body" => obj! {"text" => "/embed-terminal"}},
        );
        if frame.contains_key("error") {
            break frame;
        }
        starts += 1;
        // Each ends at once, so the next is not refused for one open.
        let write_url = written(frame["result"].as_object().unwrap())["write_url"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(http_do("PUT", &write_url, Some(b"x\n"), "").0, 200);
    };
    assert_eq!(starts, 3, "a user's (here a guest IP's) burst");
    let (message, data) = retry_after_of(&refusal);
    assert_eq!(message, "Live text limit reached");
    assert!(!data.contains_key("ext"), "{data:?}");
    // Readers of one text at once, then of every text together.
    let mut config = live_config();
    config.live.readers_per_text = 2;
    config.live.readers = 3;
    config.live.readers_per_address = 0;
    let server = new_test_server(config);
    let mut writers = [dial_test_client(&server), dial_test_client(&server)];
    let mut texts = Vec::new();
    for (i, writer) in writers.iter_mut().enumerate() {
        writer.drain();
        let result = super::helpers::post_embeds(
            writer,
            &format!("post-{i}"),
            obj! {"body" => obj! {"text" => "x", "embeds" => vec![Json::from(obj! {"kind" => "terminal"})]}},
        );
        let (put, done) = stream_to(written(&result)["write_url"].as_str().unwrap());
        let (_, url) = url_added(writer, result["message_id"].as_str().unwrap());
        texts.push((put, done, url));
    }
    let refused = |url: &str| {
        let (status, header, body) = http_do("GET", url, None, "");
        (
            status,
            header.get("Retry-After").map(str::to_owned),
            header.get("Apron-Live-Refused").map(str::to_owned),
            String::from_utf8_lossy(&body).into_owned(),
        )
    };
    let first = [Reader::open(&texts[0].2), Reader::open(&texts[0].2)];
    assert_eq!((first[0].status, first[1].status), (200, 200));
    assert_eq!(
        refused(&texts[0].2),
        (
            429,
            Some("10".into()),
            Some("readers".into()),
            "This live text has as many readers as it may have\n".into()
        )
    );
    let second = Reader::open(&texts[1].2);
    assert_eq!(second.status, 200);
    assert_eq!(
        refused(&texts[1].2),
        (
            429,
            Some("10".into()),
            Some("readers".into()),
            "Live text has as many readers as the server allows\n".into()
        )
    );
    // The first text's readers go when it ends, leaving their places.
    let (put, done, ended_url) = texts.remove(0);
    put.write_shared(b"x").unwrap();
    put.close();
    answer(&done);
    for reader in &first {
        reader.ended();
    }
    assert_eq!(
        refused(&ended_url),
        (
            404,
            None,
            Some("ended".into()),
            "This live text has ended, or never existed\n".into()
        )
    );
    let again = Reader::open(&texts[0].2);
    assert_eq!(again.status, 200, "a place left by an ended text");
    let (put, done, _) = texts.remove(0);
    put.write_shared(b"x").unwrap();
    put.close();
    answer(&done);
    second.ended();
    again.ended();

    // Readers from one address across every text, that address's own
    // limit, which is not marked.
    let mut config = live_config();
    config.live.readers_per_address = 2;
    let server = new_test_server(config);
    let mut writers = [dial_test_client(&server), dial_test_client(&server)];
    let mut texts = Vec::new();
    for (i, writer) in writers.iter_mut().enumerate() {
        writer.drain();
        let result = super::helpers::post_embeds(
            writer,
            &format!("again-{i}"),
            obj! {"body" => obj! {"text" => "x", "embeds" => vec![Json::from(obj! {"kind" => "terminal"})]}},
        );
        let (put, done) = stream_to(written(&result)["write_url"].as_str().unwrap());
        let (_, url) = url_added(writer, result["message_id"].as_str().unwrap());
        texts.push((put, done, url));
    }
    let readers = [Reader::open(&texts[0].2), Reader::open(&texts[1].2)];
    assert_eq!(
        readers.iter().map(|r| r.status).collect::<Vec<_>>(),
        [200, 200]
    );
    assert_eq!(
        refused(&texts[0].2),
        (
            429,
            Some("10".into()),
            None,
            "Too many live text readers from your address\n".into()
        )
    );
    for (put, done, _) in texts {
        put.write_shared(b"x").unwrap();
        put.close();
        answer(&done);
    }
}

#[test]
fn test_guests_who_only_read_get_no_live_text() {
    let mut config = live_config();
    config.guest_posting = false;
    let server = new_test_server(config);
    let mut guest = dial_test_client(&server);
    guest.drain();
    assert_eq!(command_error(&mut guest, "/embed-terminal").0, CODE_DENIED);
    assert_eq!(
        private_reply(&mut guest, "/help"),
        "- `/help`: list the commands you can use here"
    );
}

#[test]
fn test_live_urls_take_get_and_head_only() {
    let server = new_test_server(live_config());
    let unknown = format!("{}{LIVE_PATH}nope", server.http.url);
    let (status, header, body) = http_do("GET", &unknown, None, "");
    assert_eq!(
        (
            status,
            header.get("Content-Type"),
            String::from_utf8_lossy(&body).into_owned()
        ),
        (
            404,
            Some("text/plain; charset=utf-8"),
            "This live text has ended, or never existed\n".into()
        )
    );
    assert_eq!(http_do("POST", &unknown, Some(b"x"), "").0, 405);
    let (status, header, _) = http_do("OPTIONS", &unknown, None, "");
    assert_eq!(
        (status, header.get("Access-Control-Allow-Methods")),
        (204, Some("GET, HEAD, OPTIONS"))
    );
    let mut writer = dial_test_client(&server);
    writer.drain();
    let result = super::helpers::post_embeds(
        &mut writer,
        "post",
        obj! {"body" => obj! {"text" => "x", "embeds" => vec![Json::from(obj! {"kind" => "append"})]}},
    );
    let (put, done) = stream_to(written(&result)["write_url"].as_str().unwrap());
    let (_, url) = url_added(&writer, result["message_id"].as_str().unwrap());
    let (status, header, body) = http_do("HEAD", &url, None, "");
    assert_eq!(
        (status, header.get("Content-Security-Policy"), body.len()),
        (200, Some("default-src 'none'"), 0)
    );
    put.close();
    answer(&done);
}

/// What a text kept while it streams is in memory only: a restart keeps a
/// finished terminal's output, and removes the embed of one that was open,
/// with nothing kept, as Cloudflare's lost instance does.
#[test]
fn test_a_finished_terminal_outlives_a_restart_and_an_open_one_does_not() {
    use crate::store::{self, Store};
    let dir = TempDir::new("apron-live-");
    let server = super::persist_test::start_with_store(
        Arc::new(store::Memory::new()),
        &format!("{dir}/before"),
    );
    let mut writer = dial_test_client(&server);
    writer.drain();
    let finished = super::helpers::post_embeds(
        &mut writer,
        "done",
        obj! {"body" => obj! {"text" => "a", "embeds" => vec![Json::from(obj! {"kind" => "terminal"})]}},
    );
    assert_eq!(
        http_do(
            "PUT",
            written(&finished)["write_url"].as_str().unwrap(),
            Some(b"kept\n"),
            ""
        )
        .0,
        200
    );
    url_added(&writer, finished["message_id"].as_str().unwrap());
    snapshot_of(&writer, finished["message_id"].as_str().unwrap());
    let open = super::helpers::post_embeds(
        &mut writer,
        "open",
        obj! {"body" => obj! {"text" => "b", "embeds" => vec![Json::from(obj! {"kind" => "terminal"})]}},
    );
    let crashed = Arc::new(store::Memory::new());
    crashed.apply(&server.app.lock().dump_locked()).unwrap();
    let restored = super::persist_test::start_with_store(crashed, &format!("{dir}/after"));
    let st = restored.app.lock();
    let kept: Vec<(String, Object)> = st
        .embeds
        .values()
        .map(|e| (e.kind.clone(), e.owned.clone()))
        .collect();
    assert_eq!(kept, [("terminal".to_owned(), obj! {"output" => "kept\n"})]);
    let open_id = open["message_id"].as_str().unwrap();
    let snapshot = st.snapshot(open_id);
    assert_eq!(
        snapshot["body"],
        Json::from(obj! {"text" => "b", "format" => "plain"})
    );
    assert!(st.live_ids.is_empty());
}

/// A web writer's `PUT` comes from another origin (§4.8.3): its preflight
/// and its answer allow any.
#[test]
fn test_writes_are_allowed_from_any_origin() {
    let server = new_test_server(live_config());
    let mut writer = dial_test_client(&server);
    writer.drain();
    let (_, result) = live_command(&mut writer, "/embed-append", Object::new());
    let write_url = written(&result)["write_url"].as_str().unwrap().to_owned();
    let (status, header, _) = http_do("OPTIONS", &write_url, None, "");
    assert_eq!(
        (
            status,
            header.get("Access-Control-Allow-Origin"),
            header.get("Access-Control-Allow-Methods"),
            header.get("Access-Control-Allow-Headers"),
        ),
        (204, Some("*"), Some("PUT, OPTIONS"), Some("Content-Type"))
    );
    let (status, header, body) = http_do("PUT", &write_url, Some(b"hi"), "text/plain");
    assert_eq!(
        (
            status,
            header.get("Access-Control-Allow-Origin"),
            header.get("Content-Type"),
            String::from_utf8_lossy(&body).into_owned()
        ),
        (
            200,
            Some("*"),
            Some("text/plain; charset=utf-8"),
            "Done: the text is posted.\n".into()
        )
    );
}

/// A writer that disconnects ends the text at once, with what arrived
/// (§4.8.5): there is no grace period.
#[test]
fn test_a_writer_that_disconnects_ends_the_text() {
    use std::io::Write;
    let server = new_test_server(live_config());
    let mut writer = dial_test_client(&server);
    writer.drain();
    let result = super::helpers::post_embeds(
        &mut writer,
        "post",
        obj! {"body" => obj! {"text" => "Build:", "embeds" => vec![Json::from(obj! {"kind" => "terminal"})]}},
    );
    let message_id = result["message_id"].as_str().unwrap().to_owned();
    let write_url = written(&result)["write_url"].as_str().unwrap().to_owned();
    let address = server.http.url.trim_start_matches("http://").to_owned();
    let path = &write_url[server.http.url.len()..];
    let mut socket = std::net::TcpStream::connect(&address).unwrap();
    write!(
        socket,
        "PUT {path} HTTP/1.1\r\nHost: {address}\r\nContent-Length: 1000\r\n\r\nhalf\n"
    )
    .unwrap();
    url_added(&writer, &message_id);
    let cut = std::time::Instant::now();
    drop(socket);
    let finished = snapshot_of(&writer, &message_id);
    assert!(cut.elapsed() < std::time::Duration::from_secs(1));
    assert_eq!(
        body_of(&finished)["embeds"].as_list()[0]
            .as_object()
            .unwrap()
            .get("output"),
        Some(&Json::from("half\n"))
    );
    assert!(server.app.lock().live_ids.is_empty());
}

/// A request from a browser that opens `url` as a page
/// (`Sec-Fetch-Mode: navigate`), not following a redirect; the body is
/// left unread, since a text's streams until it ends.
fn navigate(method: &str, url: &str) -> (u16, http::Header) {
    use rust_stdlib::net::http::client::Client;
    use rust_stdlib::net::http::{BoxError, ERR_USE_LAST_RESPONSE};
    let client = Client {
        check_redirect: Some(Arc::new(|_, _| {
            Err(Box::new(ERR_USE_LAST_RESPONSE) as BoxError)
        })),
        ..Client::default()
    };
    let mut request = http::Request::new(method, url).unwrap();
    request.header.set("Sec-Fetch-Mode", "navigate");
    let response = client
        .do_request(request)
        .unwrap_or_else(|e| panic!("{method} {url}: {e}"));
    (response.status_code, response.header)
}

/// Starts a terminal titled `title` in a message, with a sender's og: its
/// writer, the writer's answer, the message's id, its embed's id and its url.
fn live_terminal(
    c: &mut TestClient,
    title: &str,
) -> (
    PipeWriter,
    mpsc::Receiver<(u16, String)>,
    String,
    Json,
    String,
) {
    let result = super::helpers::post_embeds(
        c,
        "terminal",
        obj! {"body" => obj! {"text" => "Build:", "embeds" => vec![Json::from(obj! {"kind" => "terminal", "title" => title, "og" => obj! {"title" => "forged"}})]}},
    );
    let message_id = result["message_id"].as_str().unwrap().to_owned();
    let embed_id = waiting_embed(&result)["embed_id"].clone();
    let (put, done) = stream_to(written(&result)["write_url"].as_str().unwrap());
    let (_, url) = url_added(c, &message_id);
    (put, done, message_id, embed_id, url)
}

#[test]
fn test_a_terminal_opened_as_a_page_goes_to_the_viewer() {
    let mut config = live_config();
    config.terminal_viewer_url = "http://terminal.test/view".into();
    let server = new_test_server(config);
    let mut writer = dial_test_client(&server);
    writer.drain();
    let (put, done, message_id, embed_id, url) = live_terminal(&mut writer, "ci");
    // A save while it is live keeps the server's og too (§4.8.1).
    let (_, saved) = save(
        &mut writer,
        "resave",
        obj! {"message_id" => message_id.as_str(), "body" => obj! {"text" => "Build:", "embeds" => vec![Json::from(obj! {"embed_id" => embed_id.clone(), "kind" => "terminal", "title" => "ci", "og" => obj! {"title" => "forged"}})]}},
    );
    assert_eq!(
        body_of(&saved)["embeds"],
        Json::from(vec![Json::from(
            obj! {"embed_id" => embed_id, "kind" => "terminal", "title" => "ci", "url" => url.as_str(), "og" => card("ci")}
        )])
    );
    // The url goes in the fragment (§4.8.5), and a redirect holds no
    // reader's place.
    let location = format!(
        "http://terminal.test/view#stream={}",
        url.replace(':', "%3A").replace('/', "%2F")
    );
    for _ in 0..3 {
        let (status, header) = navigate("GET", &url);
        assert_eq!(
            (
                status,
                header.get("Location"),
                header.get("Vary"),
                header.get("Cache-Control")
            ),
            (
                302,
                Some(location.as_str()),
                Some("Sec-Fetch-Mode"),
                Some("no-store")
            )
        );
    }
    // HEAD, even from a page, gets the text's headers.
    let (status, header) = navigate("HEAD", &url);
    assert_eq!(
        (status, header.get("Content-Type"), header.get("Vary")),
        (
            200,
            Some("text/plain; charset=utf-8"),
            Some("Sec-Fetch-Mode")
        )
    );
    let reader = Reader::open(&url);
    assert_eq!(
        (reader.status, reader.header.get("Vary")),
        (200, Some("Sec-Fetch-Mode"))
    );
    put.write_shared(b"ok\n").unwrap();
    reader.wait_for(b"ok\n");
    put.close();
    assert_eq!(answer(&done), (200, "Done: the text is posted.\n".into()));
    assert_eq!(reader.ended(), b"ok\n");
    let finished = snapshot_of(&writer, &message_id);
    assert_eq!(
        body_of(&finished)["embeds"].as_list()[0]
            .as_object()
            .unwrap()["og"],
        card("ci")
    );
    assert_eq!(navigate("GET", &url).0, 404, "an ended text, from a page");

    // An append's url is never redirected, and it has no og.
    let result = super::helpers::post_embeds(
        &mut writer,
        "append",
        obj! {"body" => obj! {"text" => "logs:", "embeds" => vec![Json::from(obj! {"kind" => "append", "og" => obj! {"title" => "forged"}})]}},
    );
    assert_eq!(waiting_embed(&result).get("og"), None);
    let (put, done) = stream_to(written(&result)["write_url"].as_str().unwrap());
    let (_, append_url) = url_added(&writer, result["message_id"].as_str().unwrap());
    let (status, header) = navigate("GET", &append_url);
    assert_eq!(
        (status, header.get("Location"), header.get("Vary")),
        (200, None, None)
    );
    put.close();
    answer(&done);
}

#[test]
fn test_without_a_viewer_a_page_gets_the_text() {
    // An https viewer reads only https, so an http url has none; an empty
    // one is none anywhere.
    for viewer in [DEFAULT_TERMINAL_VIEWER_URL, ""] {
        let mut config = live_config();
        config.terminal_viewer_url = viewer.into();
        let server = new_test_server(config);
        let mut writer = dial_test_client(&server);
        writer.drain();
        let (put, done, _, _, url) = live_terminal(&mut writer, "ci");
        let (status, header) = navigate("GET", &url);
        assert_eq!(
            (status, header.get("Location"), header.get("Vary")),
            (200, None, None),
            "{viewer:?}"
        );
        put.close();
        answer(&done);
    }
}
