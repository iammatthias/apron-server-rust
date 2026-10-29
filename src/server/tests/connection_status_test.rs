//! The connection-status probe of apron-web's EXT.md §5, ported from
//! apron-server-cloudflare's `connection-status.integration.test.ts`.

use rust_stdlib::context::Context;
use rust_stdlib::net::http::{self, client::DEFAULT_CLIENT, Header, Request};
use rust_stdlib::time;

use super::helpers::*;
use crate::obj;
use crate::server::protocol::*;
use crate::server::server::RETRY_AFTER_SECONDS;

fn probe(server: &TestServer, path: &str, headers: &[(&str, &str)]) -> (u16, Header, Json) {
    let url = format!("{}{path}", server.http.url);
    let mut request = Request::new("GET", &url).unwrap();
    for (name, value) in headers {
        request.header.set(name, value);
    }
    let response = DEFAULT_CLIENT.do_request(request).unwrap();
    let body = response
        .body
        .as_ref()
        .map(|b| b.read_all().unwrap())
        .unwrap_or_default();
    let mut json = Json::Null;
    let _ = rust_stdlib::encoding::json::v2::unmarshal(&body, &mut json, &[]);
    (response.status_code, response.header, json)
}

const PROBE: &str = "/ws?apron_connection_status=1";

#[test]
fn test_available_probe_admits_no_connection() {
    let server = new_test_server(default_config());
    let (status, header, body) = probe(&server, PROBE, &[]);
    assert_eq!(status, 200);
    assert_eq!(body, Json::from(obj! {"available" => true}));
    assert_eq!(header.get("Apron-Connection-Status"), Some("1"));
    assert_eq!(header.get("Access-Control-Allow-Origin"), Some("*"));
    assert_eq!(
        header.get("Access-Control-Expose-Headers"),
        Some("Retry-After, Apron-Connection-Status")
    );
    assert!(
        server.app.lock().clients.is_empty(),
        "a probe admitted a connection"
    );
}

#[test]
fn test_probe_keeps_origin_checks() {
    let server = new_test_server(default_config());
    let (status, header, body) = probe(&server, PROBE, &[("Origin", "https://not-allowed.test")]);
    assert_eq!(status, 403);
    assert_eq!(body, Json::from(obj! {"error" => "Origin not allowed"}));
    assert_eq!(header.get("Apron-Connection-Status"), Some("1"));
}

#[test]
fn test_probe_reports_capacity_and_shutdown() {
    let mut config = default_config();
    config.max_connections = 1;
    let mut server = new_test_server(config);
    let held = dial_test_client(&server);
    let (status, header, body) = probe(&server, PROBE, &[]);
    assert_eq!(status, 429);
    assert_eq!(body, Json::from(obj! {"error" => "Server at capacity"}));
    assert_eq!(
        header.get("Retry-After"),
        Some(RETRY_AFTER_SECONDS.to_string().as_str())
    );
    assert_eq!(header.get("Apron-Connection-Status"), Some("1"));
    drop(held);

    let (ctx, cancel) = Context::background().with_timeout(time::SECOND * 5);
    server.app.shutdown(&ctx).unwrap();
    cancel();
    let (status, header, body) = probe(&server, PROBE, &[]);
    assert_eq!(status, http::STATUS_SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        Json::from(obj! {"error" => "Server is shutting down"})
    );
    assert_eq!(header.get("Apron-Connection-Status"), Some("1"));
    server.stop();
}

/// Only the probe's own answers on the WebSocket URL are marked, not other
/// paths or upgrades.
#[test]
fn test_probe_marks_only_its_own_answers() {
    let server = new_test_server(default_config());
    let (_, header, _) = probe(&server, "/healthz?apron_connection_status=1", &[]);
    assert_eq!(header.get("Apron-Connection-Status"), None);
    let (status, header, _) = probe(
        &server,
        PROBE,
        &[
            ("Origin", "https://not-allowed.test"),
            ("Connection", "Upgrade"),
            ("Upgrade", "websocket"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ],
    );
    assert_eq!(status, 403);
    assert_eq!(header.get("Apron-Connection-Status"), None);
}
