//! The send limit, delivery bound, and client address tests of
//! email_test.go.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rust_stdlib::context::Context;
use rust_stdlib::net::http::Request as HttpRequest;
use rust_stdlib::time::{self};

use super::email_test::{age_sends, dial_from, email_test_server, propose};
use super::helpers::*;
use crate::obj;
use crate::server::email::*;
use crate::server::limits::IpKey;
use crate::server::protocol::*;

/// Emails are limited per address and per client, deliveries in progress
/// are bounded, refused proposals leave nothing behind, and a full table
/// forgets only entries whose limits have lapsed.
#[test]
fn test_email_send_limits() {
    let (server, _mailbox) =
        email_test_server(|config| config.client_ip_header = "X-Forwarded-For".into());
    let app = &server.app;
    // At most MAX_EMAIL_SENDS_PER_WINDOW emails an hour to one address.
    for i in 0..MAX_EMAIL_SENDS_PER_WINDOW {
        propose(
            &mut dial_from(&server, &format!("203.0.113.{i}")),
            "carol@example.com",
        );
        age_sends(app, "carol@example.com", EMAIL_RESEND_INTERVAL);
    }
    dial_from(&server, "203.0.113.100").expect_error(
        "auth",
        "capped",
        obj! {"scheme" => "email", "email" => "carol@example.com"},
        CODE_RETRY_AFTER,
    );
    // One client proposes at most CLIENT_SEND_BURST times, across
    // connections.
    for i in 0..CLIENT_SEND_BURST {
        propose(
            &mut dial_from(&server, "198.51.100.200"),
            &format!("c{i}@example.com"),
        );
    }
    let mut flooder = dial_from(&server, "198.51.100.200");
    flooder.expect_error(
        "auth",
        "client-sends",
        obj! {"scheme" => "email", "email" => "d@example.com"},
        CODE_RETRY_AFTER,
    );
    // Refused proposals are not tracked.
    let before = app.lock().email.addresses.len();
    for i in 0..100 {
        flooder.call(
            "auth",
            &format!("refused-{i}"),
            obj! {"scheme" => "email", "email" => format!("junk{i}@example.com")},
        );
    }
    let after = app.lock().email.addresses.len();
    assert_eq!(
        after,
        before,
        "refused proposals made {} entries",
        after - before
    );

    // A full table forgets an address whose emails are older than the
    // window, and refuses when every entry is within it.
    {
        let mut st = app.lock();
        let mut i = 0;
        while st.email.addresses.len() < MAX_TRACKED_EMAIL_STATE {
            let now = time::now();
            st.email
                .create_address(&format!("filler{i}@example.com"), &now)
                .unwrap()
                .sends = vec![now.clone()];
            i += 1;
        }
    }
    dial_from(&server, "192.0.2.50").expect_error(
        "auth",
        "full",
        obj! {"scheme" => "email", "email" => "late@example.com"},
        CODE_RETRY_AFTER,
    );
    age_sends(app, "filler0@example.com", time::HOUR);
    propose(&mut dial_from(&server, "192.0.2.51"), "late@example.com");
    let st = app.lock();
    let kept = st.email.addresses.contains_key("filler0@example.com");
    let kept_live = st.email.addresses.contains_key("filler1@example.com");
    assert!(
        !kept && kept_live,
        "eviction: lapsed kept {kept}, live kept {kept_live}"
    );
}

/// Holds each delivery until released.
struct BlockingMailbox {
    release: Arc<AtomicBool>,
}

impl EmailSender for BlockingMailbox {
    fn send_sign_in_code(&self, ctx: &Context, _message: &SignInEmail) -> Result<(), SendError> {
        while !self.release.load(Ordering::SeqCst) && ctx.err().is_none() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok(())
    }
}

/// Releases the blocking mailbox when dropped, before the server it is
/// declared after shuts down and waits for its deliveries.
struct Release(Arc<AtomicBool>);

impl Drop for Release {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Deliveries in progress are bounded; past the bound a proposal waits.
#[test]
fn test_email_deliveries_are_bounded() {
    let release = Arc::new(AtomicBool::new(false));
    let mailbox = Arc::new(BlockingMailbox {
        release: release.clone(),
    });
    let (server, _) = email_test_server(|config| {
        config.email_sender = Some(mailbox);
        config.client_ip_header = "X-Forwarded-For".into();
    });
    let _release = Release(release);
    for i in 0..MAX_CONCURRENT_EMAIL_SENDS {
        propose(
            &mut dial_from(&server, &format!("198.51.100.{i}")),
            &format!("q{i}@example.com"),
        );
    }
    dial_from(&server, "192.0.2.1").expect_error(
        "auth",
        "busy",
        obj! {"scheme" => "email", "email" => "busy@example.com"},
        CODE_RETRY_AFTER,
    );
}

/// The client key comes from the last entry across every line of the
/// configured header, without a port, else from the connection; a header
/// that names no address gives none, which refuses the connection.
#[test]
fn test_client_ip_from_a_proxy_header() {
    let mut config = default_config();
    config.client_ip_header = "X-Forwarded-For".into();
    let s = new_test_server(config);
    let request = |lines: &[&str]| {
        let mut r = HttpRequest::new("GET", "http://example.com/ws").unwrap();
        r.remote_addr = "10.0.0.1:5555".into();
        for line in lines {
            r.header.add("X-Forwarded-For", line);
        }
        r
    };
    let tests: [(&[&str], Option<&str>); 10] = [
        (&[], None),
        (&["203.0.113.7"], Some("v4:203.0.113.7")),
        (&["6.6.6.6, 203.0.113.7"], Some("v4:203.0.113.7")),
        (&["6.6.6.6", "203.0.113.7"], Some("v4:203.0.113.7")),
        (
            &["6.6.6.6", "198.51.100.1, 203.0.113.7:4711"],
            Some("v4:203.0.113.7"),
        ),
        (&["[2001:db8::1]:4711"], Some("v6:2001:db8::/56")),
        (&["2001:db8:0:ff::2"], Some("v6:2001:db8::/56")),
        (&["::ffff:203.0.113.7"], Some("v4:203.0.113.7")),
        (&["garbage-x"], None),
        (&["203.0.113.7, "], None),
    ];
    for (lines, want) in tests {
        assert_eq!(
            s.app.client_ip(&request(lines)).as_ref().map(IpKey::as_str),
            want,
            "client_ip({lines:?})"
        );
    }
    let plain = new_test_server(default_config());
    let mut r = request(&[]);
    r.header.set("X-Forwarded-For", "203.0.113.7");
    assert_eq!(
        plain.app.client_ip(&r).as_ref().map(IpKey::as_str),
        Some("v4:10.0.0.1"),
        "without a header configured"
    );
}

/// With the header configured, a connection without it is refused before
/// the upgrade, and the connection-status probe says why.
#[test]
fn test_missing_client_address_is_refused() {
    let mut config = default_config();
    config.client_ip_header = "Cf-Connecting-IP".into();
    let s = new_test_server(config);
    let (status, body) = http_get(&format!("{}/ws?apron_connection_status=1", s.http.url));
    assert_eq!(
        (status, String::from_utf8_lossy(&body).into_owned()),
        (
            403,
            r#"{"error":"Trusted client address unavailable"}"#.to_owned()
        )
    );
    let (status, _) = http_get(&format!("{}/ws", s.http.url));
    assert_eq!(status, 403, "an upgrade without the header");
    let (c, frame) = dial_headers(&s, &[("Cf-Connecting-IP", "198.51.100.4")]);
    assert_eq!(frame["method"].as_str(), Some("server"));
    drop(c);
}
