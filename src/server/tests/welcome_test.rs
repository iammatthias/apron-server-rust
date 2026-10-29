//! `server.welcome` and the `~private` welcome before `auth`, as
//! apron-server-cloudflare sends them (its SPEC.md, section 4, and
//! `read-only-guests.integration.test.ts`).

use super::helpers::*;
use super::webauthn_test::{test_web_authn, TEST_PASSKEY_ORIGIN};
use crate::obj;
use crate::server::protocol::*;
use crate::server::Config;
use rust_stdlib::time;

fn welcome_of(frame: &Object) -> String {
    notification_params(frame, "server")["welcome"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The server frame's welcome and the welcome notice that follows it, on a
/// connection from the passkey origin.
fn greeting(server: &TestServer) -> (String, String) {
    greeting_from(server, TEST_PASSKEY_ORIGIN)
}

fn greeting_from(server: &TestServer, origin: &str) -> (String, String) {
    let (c, frame) = dial_server_frame(server, &[("Origin", origin)]);
    (welcome_of(&frame), welcome_text(&c.read()))
}

const VERSION_LINE: &str = concat!(
    "Welcome to Apron Chat. Server version: `",
    env!("CARGO_PKG_VERSION"),
    "`"
);

#[test]
fn test_welcome_notice_says_guests_only_read() {
    type Case = (&'static str, fn(&mut Config), &'static str);
    let cases: [Case; 4] = [
        (
            "passkeys",
            |c| c.web_authn = Some(test_web_authn()),
            "\n\nGuests can read. *Sign in with passkey* to participate.",
        ),
        (
            "email",
            |c| c.email_sender = Some(super::email_test::test_mailbox(1).0),
            "\n\nGuests can read. *Sign in with email* to participate.",
        ),
        ("guests only", |_| {}, "\n\nGuests can read."),
        ("guest posting", |c| c.guest_posting = true, ""),
    ];
    for (name, configure, rest) in cases {
        let mut config = crate::server::default_config();
        configure(&mut config);
        let server = new_test_server(config);
        let (_, notice) = greeting(&server);
        assert_eq!(notice, format!("{VERSION_LINE}{rest}"), "{name}");
    }
}

#[test]
fn test_welcome_is_generals_description_else_a_summary() {
    let mut config = default_config();
    config.web_authn = Some(test_web_authn());
    config.retention = Some(time::HOUR * 24 * 7);
    let server = new_test_server(config);
    let summary = "Guests can post under a new name each visit. **Create a passkey** to post, react, and start threads; it signs you in on your next visit too. Bots sign in with a token their owner gets from `/invite-bot`. Messages are kept for 7 days.";
    assert_eq!(greeting(&server).0, summary, "without a description");
    // An origin not offered passkeys is told where they work.
    assert_eq!(
        greeting_from(&server, "http://localhost:9999"),
        (
            "Guests can post under a new name each visit. Passkeys work on this server's own site. Bots sign in with a token their owner gets from `/invite-bot`. Messages are kept for 7 days.".to_owned(),
            VERSION_LINE.to_owned()
        ),
        "another origin"
    );

    let mut c = dial_test_client(&server);
    let description = "Be **kind**.";
    c.request(
        "room_set",
        "describe",
        obj! {"room_id" => "general", "description" => description},
    );
    assert_eq!(greeting(&server).0, description, "general's description");

    c.request(
        "room_set",
        "clear",
        obj! {"room_id" => "general", "description" => ""},
    );
    assert_eq!(greeting(&server).0, summary, "a cleared description");
}

#[test]
fn test_welcome_flag_overrides_generals_description() {
    let mut config = default_config();
    config.welcome = "Configured.".into();
    let server = new_test_server(config);
    let mut c = dial_test_client(&server);
    c.request(
        "room_set",
        "describe",
        obj! {"room_id" => "general", "description" => "Described."},
    );
    assert_eq!(greeting(&server).0, "Configured.");
}

#[test]
fn test_read_only_summary() {
    let mut config = crate::server::default_config();
    config.email_sender = Some(super::email_test::test_mailbox(1).0);
    let server = new_test_server(config);
    assert_eq!(
        greeting(&server).0,
        "Guests can read along. **Sign in with email** to post, react, and start threads. Bots sign in with a token their owner gets from `/invite-bot`."
    );
}
