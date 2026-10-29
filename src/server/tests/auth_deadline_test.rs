//! A connection that does not sign in is closed with 1008, as
//! apron-server-cloudflare closes it (its SPEC.md, section 6).

use rust_stdlib::time::{self, Duration};

use super::helpers::*;
use super::webauthn_test::*;
use crate::obj;
use crate::ws;

fn deadline_server(deadline: Duration) -> TestServer {
    let mut config = default_config();
    config.auth_timeout = deadline;
    config.web_authn = Some(test_web_authn());
    new_test_server(config)
}

/// Reads until the connection ends, and returns its close code and reason.
fn closed(c: &TestClient) -> (u16, String) {
    loop {
        match c.read_raw(time::SECOND * 2) {
            Ok(_) => continue,
            Err(ws::Error::Closed { code, reason }) => return (code, reason),
            Err(e) => panic!("connection ended without a close frame: {e}"),
        }
    }
}

#[test]
fn test_unauthenticated_connection_is_closed() {
    let server = deadline_server(Duration::from_millis(200));
    let (c, _) = dial_raw(&server);
    assert_eq!(
        closed(&c),
        (
            ws::STATUS_POLICY_VIOLATION,
            "Authentication timed out".to_owned()
        )
    );
    assert!(server.app.lock().clients.is_empty(), "connection kept");
}

/// A passkey ceremony in progress is not a sign-in: the deadline counts from
/// the connection.
#[test]
fn test_passkey_begin_does_not_stop_the_deadline() {
    let server = deadline_server(Duration::from_millis(200));
    let (c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    c.write(
        &obj! {"method" => "auth", "id" => "begin", "params" => obj! {
            "scheme" => "webauthn", "action" => "login", "step" => "begin",
        }},
    );
    assert_eq!(closed(&c).0, ws::STATUS_POLICY_VIOLATION);
}

#[test]
fn test_signed_in_connection_outlives_the_deadline() {
    let server = deadline_server(time::SECOND);
    let mut c = dial_test_client(&server);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    c.expect_quiet();
}

/// Cloudflare's `unauthenticatedTimeoutSeconds`.
#[test]
fn test_default_deadline_is_thirty_seconds() {
    assert_eq!(
        crate::server::default_config().auth_timeout.as_nanos(),
        (time::SECOND * 30).as_nanos()
    );
}
