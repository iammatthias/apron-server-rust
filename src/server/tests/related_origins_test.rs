//! `/.well-known/webauthn` (SPEC section 3), ported from
//! apron-server-cloudflare's `related-origins.integration.test.ts`: the
//! `--webauthn.origin`s as WebAuthn related origins, on the RP ID host only.

use std::sync::Arc;

use rust_stdlib::net::http;

use super::helpers::*;
use crate::server::config::Config;
use crate::webauthn::{self, WebAuthn};

const PATH: &str = "/.well-known/webauthn";

/// A self-hosted server whose RP ID is its own host, used from a shared
/// client elsewhere.
fn self_hosted() -> TestServer {
    let web_authn = WebAuthn::new(webauthn::Config {
        rpid: "apron.shazow.net".into(),
        rp_display_name: "Apron".into(),
        rp_origins: vec![
            "https://apron.shazow.net".into(),
            "https://web.apron.chat".into(),
        ],
    })
    .unwrap();
    new_test_server(Config {
        web_authn: Some(Arc::new(web_authn)),
        ..default_config()
    })
}

/// `method` of `path` with the `Host` header `host`, as a browser sends it.
fn well_known(server: &TestServer, host: &str, method: &str, path: &str) -> http::Response {
    let mut request = http::Request::new(method, &format!("{}{path}", server.http.url)).unwrap();
    request.host = host.to_owned();
    http::client::DEFAULT_CLIENT.do_request(request).unwrap()
}

fn body_of(response: &http::Response) -> String {
    let body = response
        .body
        .as_ref()
        .map(|b| b.read_all().unwrap())
        .unwrap_or_default();
    String::from_utf8(body).unwrap()
}

#[test]
fn test_publishes_rp_origins_as_related_origins_on_the_rp_id_host() {
    let server = self_hosted();
    let response = well_known(&server, "apron.shazow.net", "GET", PATH);
    assert_eq!(response.status_code, 200);
    assert_eq!(
        response.header.get("Content-Type"),
        Some("application/json")
    );
    assert_eq!(
        response.header.get("Cache-Control"),
        Some("public, max-age=300")
    );
    assert_eq!(
        body_of(&response),
        r#"{"origins":["https://apron.shazow.net","https://web.apron.chat"]}"#
    );
    // Host names compare without case, as browsers send them, and the port
    // is not part of the host name.
    assert_eq!(
        well_known(&server, "Apron.Shazow.NET", "GET", PATH).status_code,
        200
    );
    assert_eq!(
        well_known(&server, "apron.shazow.net:8443", "GET", PATH).status_code,
        200
    );
    let head = well_known(&server, "apron.shazow.net", "HEAD", PATH);
    assert_eq!(head.status_code, 200);
    assert_eq!(head.header.get("Content-Type"), Some("application/json"));
    assert_eq!(body_of(&head), "");
}

#[test]
fn test_is_not_found_on_a_host_other_than_the_rp_id() {
    let server = self_hosted();
    // As in production: the server on server.apron.chat, RP ID apron.chat.
    assert_eq!(
        well_known(&server, "server.apron.chat", "GET", PATH).status_code,
        404
    );
    assert_eq!(
        well_known(&server, "web.apron.shazow.net", "GET", PATH).status_code,
        404
    );
    // Only GET and HEAD, and only that path.
    assert_eq!(
        well_known(&server, "apron.shazow.net", "POST", PATH).status_code,
        404
    );
    assert_eq!(
        well_known(&server, "apron.shazow.net", "GET", "/.well-known/webauthn/").status_code,
        404
    );
}

#[test]
fn test_is_not_found_where_passkeys_are_not_configured() {
    let server = new_test_server(default_config());
    assert_eq!(
        well_known(&server, "localhost", "GET", PATH).status_code,
        404
    );
}
