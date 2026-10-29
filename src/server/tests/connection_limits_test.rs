//! Connection caps and admissions, apron-server-cloudflare's (its SPEC.md,
//! section 6, Connections), after its admission and connection-status
//! integration tests.

use super::admin_test::{admin_config, token_auth, ADMIN_TOKEN};
use super::helpers::*;
use crate::server::limits::Limits;
use crate::server::protocol::*;
use crate::server::server::RETRY_AFTER_SECONDS;
use crate::server::Config;

fn limited(limits: Limits) -> Config {
    Config {
        limits,
        ..default_config()
    }
}

/// Connects from `ip` behind a proxy that names it in Cf-Connecting-IP.
fn dial_from(server: &TestServer, ip: &str) -> (TestClient, Object) {
    dial_server_frame(server, &[("Cf-Connecting-IP", ip)])
}

/// The error a refused connection gets after its server frame, without an
/// id, as (message, retry_after).
fn refusal(c: &TestClient) -> (String, i64) {
    let frame = c.read();
    assert!(!frame.contains_key("id"), "{frame:?}");
    let error = frame["error"].as_object().expect("error");
    assert_eq!(error["code"], Json::from(CODE_RETRY_AFTER), "{frame:?}");
    (
        error["message"].as_str().unwrap().to_owned(),
        match error["data"].as_object().unwrap()["retry_after"] {
            Json::Number(n) => n as i64,
            ref other => panic!("retry_after {other:?}"),
        },
    )
}

fn admitted(c: &TestClient) {
    welcome_text(&c.read());
}

fn proxied(limits: Limits) -> TestServer {
    let mut config = limited(limits);
    config.client_ip_header = "Cf-Connecting-IP".into();
    new_test_server(config)
}

#[test]
fn test_connections_per_ip_group_ipv6_by_56() {
    let server = proxied(Limits {
        connections_per_ip: 2,
        ..Limits::unlimited()
    });
    let mut held = Vec::new();
    for ip in ["2001:db8:1:2::1", "2001:db8:1:ff::7"] {
        let (c, _) = dial_from(&server, ip);
        admitted(&c);
        held.push(c);
    }
    let (c, _) = dial_from(&server, "2001:db8:1:20::1");
    assert_eq!(
        refusal(&c),
        (
            "Connection limit reached for this network".to_owned(),
            RETRY_AFTER_SECONDS
        )
    );
    let (other, _) = dial_from(&server, "2001:db8:1:102::1");
    admitted(&other);
    let (v4, _) = dial_from(&server, "192.0.2.10");
    admitted(&v4);
}

#[test]
fn test_guest_connections_per_ip_leave_room_for_accounts() {
    let server = proxied(Limits {
        connections_per_ip: 3,
        guest_connections_per_ip: 1,
        ..Limits::unlimited()
    });
    let (mut guest, _) = dial_from(&server, "198.51.100.1");
    admitted(&guest);
    guest_auth(&mut guest);
    let (pending, _) = dial_from(&server, "198.51.100.1");
    assert_eq!(
        refusal(&pending).0,
        "Connection limit reached for this network"
    );
    drop(guest);
    wait_for(|| server.app.lock().clients.is_empty());
    let (pending, _) = dial_from(&server, "198.51.100.1");
    admitted(&pending);
}

#[test]
fn test_account_signs_in_on_at_most_connections_per_user() {
    let mut config = admin_config();
    config.limits = Limits {
        connections_per_user: 2,
        ..Limits::unlimited()
    };
    let server = new_test_server(config);
    let mut held = Vec::new();
    for _ in 0..2 {
        let (mut c, _) = dial_raw(&server);
        assert!(token_auth(&mut c, ADMIN_TOKEN).contains_key("result"));
        held.push(c);
    }
    let (mut third, _) = dial_raw(&server);
    let reply = token_auth(&mut third, ADMIN_TOKEN);
    let error = reply["error"].as_object().expect("refused");
    assert_eq!(error["code"], Json::from(CODE_RETRY_AFTER));
    assert_eq!(
        error["message"].as_str(),
        Some("Connection limit reached for this account")
    );
    // Guests are not accounts: any number sign in.
    let guests: Vec<TestClient> = (0..3).map(|_| dial_test_client(&server)).collect();
    drop(held.pop());
    wait_for(|| server.app.lock().clients.len() == 5);
    assert!(token_auth(&mut third, ADMIN_TOKEN).contains_key("result"));
    drop(guests);
}

#[test]
fn test_admissions_per_ip_minute() {
    let server = proxied(Limits {
        admissions_per_ip_minute: 2,
        ..Limits::unlimited()
    });
    for _ in 0..2 {
        let (c, _) = dial_from(&server, "203.0.113.9");
        admitted(&c);
    }
    let (c, _) = dial_from(&server, "203.0.113.9");
    // A minute's allowance of 2 refills one every 30 s.
    assert_eq!(
        refusal(&c),
        ("Connection admission limit reached".to_owned(), 30)
    );
    let (other, _) = dial_from(&server, "203.0.113.10");
    admitted(&other);
}

#[test]
fn test_probe_reports_the_ip_cap_without_admitting() {
    let server = proxied(Limits {
        connections_per_ip: 1,
        admissions_per_ip_minute: 1,
        ..Limits::unlimited()
    });
    let (held, _) = dial_from(&server, "198.51.100.5");
    admitted(&held);
    let url = format!("{}/ws?apron_connection_status=1", server.http.url);
    let mut request = rust_stdlib::net::http::Request::new("GET", &url).unwrap();
    request.header.set("Cf-Connecting-IP", "198.51.100.5");
    let response = rust_stdlib::net::http::client::DEFAULT_CLIENT
        .do_request(request)
        .unwrap();
    let body = response.body.as_ref().unwrap().read_all().unwrap();
    assert_eq!(response.status_code, 429);
    assert_eq!(
        String::from_utf8_lossy(&body),
        r#"{"error":"Connection limit reached for this network"}"#
    );
    assert_eq!(
        response.header.get("Retry-After"),
        Some(RETRY_AFTER_SECONDS.to_string().as_str())
    );
    // With the held connection gone, the cap no longer applies, and the
    // next connection is refused for the admission rate instead.
    drop(held);
    wait_for(|| server.app.lock().clients.is_empty());
    let (c, _) = dial_from(&server, "198.51.100.5");
    assert_eq!(refusal(&c).0, "Connection admission limit reached");
}
