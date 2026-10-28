//! The shared fixture `tests/fixtures/push.json` of the Apron protocol
//! repository, loaded from `$APRON_GO_DIR/testdata/apron` (default
//! `~/Developer/forks/apron-server-go`).
//!
//! Payloads: each case is checked against the rules of PushPayload in
//! `schema/apron.schema.json` and the 2048-byte bound, so a valid case passes
//! and an invalid one breaks a rule. Each valid case with a message is what
//! `push_payload` makes of a snapshot of that message carrying log_id,
//! format, embeds, and ext, once its text is cut to this server's 1000
//! characters (`long-text-that-fits` has more), and the invalid cases a server could be handed
//! (a log_id, a text too long) come out conforming.
//!
//! Registrations are sent to a server. Their keys are synthetic ("BKx"), so
//! a subscription's real keys take their place. The valid relay and webpush
//! cases register; `extension-kind` conforms to the schema but names a kind
//! this server does not offer, and is refused as the Go server refuses it;
//! the invalid cases are refused with invalid params.

use super::helpers::*;
use super::webpush_test::test_subscription;
use crate::obj;
use crate::server::default_config;
use crate::server::protocol::*;
use crate::server::push::{
    parse_wake_names, push_key, push_payload, valid_push_id, MAX_PUSH_PAYLOAD_BYTES,
    MAX_PUSH_TEXT_RUNES,
};

fn fixture() -> Object {
    let dir = std::env::var("APRON_GO_DIR").unwrap_or_else(|_| {
        format!(
            "{}/Developer/forks/apron-server-go",
            std::env::var("HOME").unwrap_or_default()
        )
    });
    let path = format!("{dir}/testdata/apron/tests/fixtures/push.json");
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let fixture = decode_object(&data).expect("push.json is an object");
    assert_eq!(fixture["kind"], Json::from("push"), "fixture kind");
    fixture
}

fn cases<'a>(fixture: &'a Object, key: &str) -> Vec<&'a Object> {
    let cases: Vec<&Object> = fixture[key]
        .as_list()
        .iter()
        .filter_map(Json::as_object)
        .collect();
    assert!(!cases.is_empty(), "no {key} in push.json");
    cases
}

/// The first rule of §4.9's PushPayload that payload breaks, if any.
fn payload_problem(payload: &Object) -> Option<&'static str> {
    if let Some(push_id) = payload.get("push_id") {
        if !push_id.as_str().is_some_and(valid_push_id) {
            return Some("push_id");
        }
    }
    if let Some(unread) = payload.get("unread") {
        match unread {
            Json::Number(n) if *n >= 0.0 && n.fract() == 0.0 => {}
            _ => return Some("unread"),
        }
    }
    if let Some(message) = payload.get("message") {
        let Some(message) = message.as_object() else {
            return Some("message");
        };
        if message.contains_key("log_id") {
            return Some("message.log_id");
        }
        for key in ["message_id", "room_id"] {
            if message.get(key).and_then(Json::as_str).is_none() {
                return Some("message required fields");
            }
        }
        let from = message.get("from").and_then(Json::as_object);
        if !from.is_some_and(|f| f.get("user_id").and_then(Json::as_str).is_some()) {
            return Some("message.from.user_id");
        }
    }
    if encode_json(payload).unwrap().len() > MAX_PUSH_PAYLOAD_BYTES {
        return Some("size");
    }
    None
}

/// A stored snapshot of the message a payload carries: the message with
/// log_id, a body format and embeds, and ext, which a payload never carries.
fn snapshot_of(message: &Object) -> Object {
    let mut snapshot = message.clone();
    snapshot.insert("log_id".into(), "1724803299999".into());
    snapshot.insert("ext".into(), obj! {"x" => 1i64}.into());
    if let Some(Json::Object(body)) = snapshot.get_mut("body") {
        body.insert("format".into(), "markdown".into());
        body.insert(
            "embeds".into(),
            Json::from(vec![Json::from(obj! {"kind" => "upload"})]),
        );
    }
    snapshot
}

/// What push_payload makes of the message of a fixture payload, with its
/// push_id and unread; without unread in the fixture, the count is left
/// out for comparison.
fn produced(payload: &Object) -> Object {
    let message = payload["message"].as_object().unwrap();
    let push_id = payload.get("push_id").and_then(Json::as_str).unwrap_or("");
    let unread = match payload.get("unread") {
        Some(Json::Number(n)) => *n as i64,
        _ => 0,
    };
    let mut got = decode_object(&push_payload(push_id, unread, &snapshot_of(message))).unwrap();
    if !payload.contains_key("unread") {
        got.remove("unread");
    }
    got
}

/// payload as this server sends it: a text longer than MAX_PUSH_TEXT_RUNES,
/// which fits the bound but not this server's choice, is truncated with an
/// ellipsis (push.go).
fn server_cut(payload: &Object) -> Object {
    let mut payload = payload.clone();
    if let Some(Json::Object(message)) = payload.get_mut("message") {
        if let Some(Json::Object(body)) = message.get_mut("body") {
            if let Some(Json::String(text)) = body.get_mut("text") {
                if text.chars().count() > MAX_PUSH_TEXT_RUNES {
                    *text = text
                        .chars()
                        .take(MAX_PUSH_TEXT_RUNES - 1)
                        .collect::<String>()
                        + "…";
                }
            }
        }
    }
    payload
}

#[test]
fn test_push_fixture_payloads() {
    let fixture = fixture();
    for case in cases(&fixture, "payloads") {
        let name = case["name"].as_str().unwrap();
        let payload = case["payload"].as_object().unwrap();
        let problem = payload_problem(payload);
        if case["valid"] == Json::from(true) {
            assert_eq!(problem, None, "{name}: valid, but breaks a rule");
            if payload.contains_key("message") {
                assert_eq!(
                    produced(payload),
                    server_cut(payload),
                    "{name}: push_payload"
                );
            }
        } else {
            assert!(
                problem.is_some(),
                "{name}: expected to break a rule ({:?}), but conforms",
                case.get("why")
            );
        }
    }
    // What the server is handed is cut to a conforming payload.
    for name in ["message-with-log-id", "over-2048-bytes"] {
        let case = cases(&fixture, "payloads")
            .into_iter()
            .find(|c| c["name"] == Json::from(name))
            .unwrap_or_else(|| panic!("no payload {name}"));
        let produced = produced(case["payload"].as_object().unwrap());
        assert_eq!(
            payload_problem(&produced),
            None,
            "{name}: push_payload made {produced:?}"
        );
    }
}

#[test]
fn test_push_fixture_registrations() {
    let fixture = fixture();
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    for case in cases(&fixture, "registrations") {
        let name = case["name"].as_str().unwrap();
        let mut params = case["params"].as_object().unwrap().clone();
        if params.contains_key("keys") {
            params.insert("keys".into(), test_subscription().1.into());
        }
        let kind = params
            .get("kind")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned();
        let valid = case["valid"] == Json::from(true);
        if valid && (kind == "relay" || kind == "webpush") {
            c.result("push_register", name, params.clone());
            let url = params["url"].as_str().unwrap();
            let st = server.app.lock();
            let p = st
                .pushes
                .get(&push_key(&c.user_id, url))
                .unwrap_or_else(|| panic!("{name}: not registered"));
            let wake: Vec<String> = params
                .get("wake")
                .map(|w| {
                    w.as_list()
                        .iter()
                        .filter_map(Json::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_else(|| vec!["mentions".into(), "replies".into()]);
            assert!(
                p.kind == kind
                    && p.push_id == params.get("push_id").and_then(Json::as_str).unwrap_or("")
                    && p.keys.is_some() == params.contains_key("keys")
                    && p.wake == parse_wake_names(&wake),
                "{name}: registered {p:?}"
            );
            continue;
        }
        let frame = c.call("push_register", name, params);
        let failure = frame["error"]
            .as_object()
            .unwrap_or_else(|| panic!("{name}: {frame:?}"));
        assert_eq!(
            failure["code"],
            Json::from(CODE_INVALID_PARAMS),
            "{name}: {frame:?}"
        );
        if valid {
            assert_eq!(
                failure["message"],
                Json::from(format!(
                    "Unknown push kind {}; this server supports relay and webpush",
                    quote(&kind)
                )),
                "{name}"
            );
        }
    }
}
