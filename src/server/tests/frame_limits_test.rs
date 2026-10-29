//! Frame bounds, apron-server-cloudflare's by default (its SPEC.md, section
//! 6): 16 KiB frames, JSON nested at most 8 deep with at most 2048 values,
//! request ids of at most 128 bytes, and 4 KiB message texts.

use rust_stdlib::time;

use super::helpers::*;
use crate::obj;
use crate::server::protocol::*;
use crate::ws;

/// A history request whose params carry `extra`, an unknown key.
fn history_with(id: &str, extra: &str) -> String {
    format!(r#"{{"method":"history","id":"{id}","params":{{"room_id":"general","x":{extra}}}}}"#)
}

/// The reply to `raw`, which must come next.
fn reply(c: &mut TestClient, raw: &str) -> Object {
    c.write_raw(raw);
    c.read()
}

fn error_of(frame: &Object) -> (Option<&str>, Json, &str) {
    let error = frame["error"]
        .as_object()
        .unwrap_or_else(|| panic!("no error: {frame:?}"));
    (
        frame.get("id").and_then(Json::as_str),
        error["code"].clone(),
        error["message"].as_str().unwrap(),
    )
}

#[test]
fn test_json_depth_is_bounded() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    // The frame is depth 1 and params depth 2, so six arrays make 8.
    let nested = |arrays: usize| format!("{}{}", "[".repeat(arrays), "]".repeat(arrays));
    let ok = reply(&mut c, &history_with("eight", &nested(6)));
    assert!(ok.contains_key("result"), "depth 8: {ok:?}");
    let deep = reply(&mut c, &history_with("nine", &nested(7)));
    assert_eq!(
        error_of(&deep),
        (
            Some("nine"),
            Json::from(CODE_TOO_LARGE),
            "JSON nesting is too deep"
        )
    );
    // Without an id, or as a notification, it is not answered.
    c.write_raw(&format!(
        r#"{{"method":"history","params":{{"x":{}}}}}"#,
        nested(7)
    ));
    c.write_raw(&format!(
        r#"{{"method":"activity","id":"a","params":{{"room_id":"general","x":{}}}}}"#,
        nested(7)
    ));
    c.expect_quiet();
}

#[test]
fn test_json_values_are_bounded() {
    // 2048 values with keys take more than 16 KiB.
    let server = new_test_server(large_frames_config());
    let mut c = dial_test_client(&server);
    // The frame, method, id, params, room_id and the array are 6 values.
    let numbers = |n: usize| format!("[{}]", vec!["0"; n].join(","));
    let ok = reply(&mut c, &history_with("full", &numbers(2042)));
    assert!(ok.contains_key("result"), "2048 values: {ok:?}");
    let over = reply(&mut c, &history_with("over", &numbers(2043)));
    assert_eq!(
        error_of(&over),
        (
            Some("over"),
            Json::from(CODE_TOO_LARGE),
            "JSON structure is too large"
        )
    );
    // Object keys are not values.
    let keys: Vec<String> = (0..2041).map(|i| format!(r#""k{i}":0"#)).collect();
    let keyed = reply(
        &mut c,
        &history_with("keys", &format!("{{{}}}", keys.join(","))),
    );
    assert!(
        keyed.contains_key("result"),
        "2048 values with keys: {keyed:?}"
    );
}

#[test]
fn test_request_ids_are_bounded() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let id = "i".repeat(128);
    let ok = reply(&mut c, &history_with(&id, "0"));
    assert_eq!(
        ok.get("id").and_then(Json::as_str),
        Some(id.as_str()),
        "{ok:?}"
    );
    let long = reply(&mut c, &history_with(&"i".repeat(129), "0"));
    assert_eq!(
        error_of(&long),
        (
            None,
            Json::from(CODE_INVALID_REQUEST),
            "Request id must be a bounded string"
        )
    );
}

#[test]
fn test_message_text_is_bounded() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let text = "é".repeat(2048);
    save(
        &mut c,
        "full",
        obj! {"body" => obj! {"text" => text.as_str()}},
    );
    c.expect_error(
        "message",
        "over",
        obj! {"room_id" => "general", "body" => obj! {"text" => format!("{text}x")}},
        CODE_TOO_LARGE,
    );
    c.expect_error(
        "command",
        "command",
        obj! {"body" => obj! {"text" => format!("/help {}", "x".repeat(4096))}},
        CODE_TOO_LARGE,
    );
}

#[test]
fn test_frames_are_bounded() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    let frame = |size: usize| {
        let empty = history_with("f", r#""""#);
        history_with("f", &format!(r#""{}""#, "x".repeat(size - empty.len())))
    };
    let ok = reply(&mut c, &frame(16 << 10));
    assert!(ok.contains_key("result"), "16 KiB frame: {ok:?}");
    c.write_raw(&frame((16 << 10) + 1));
    match c.read_raw(time::SECOND * 2) {
        Err(ws::Error::Closed { code, .. }) => assert_eq!(code, ws::STATUS_MESSAGE_TOO_BIG),
        other => panic!("oversized frame: {other:?}"),
    }
}

/// The bounds are configurable.
#[test]
fn test_frame_limits_follow_config() {
    let mut config = default_config();
    config.frame.max_depth = 3;
    config.frame.max_id_bytes = 8;
    let server = new_test_server(config);
    let mut c = dial_test_client(&server);
    let deep = reply(&mut c, &history_with("d", "[[]]"));
    assert_eq!(error_of(&deep).1, Json::from(CODE_TOO_LARGE));
    let long = reply(&mut c, &history_with("123456789", "0"));
    assert_eq!(error_of(&long).1, Json::from(CODE_INVALID_REQUEST));
}
