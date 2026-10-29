//! Registration limits, apron-server-cloudflare's chargeRegistration and its
//! identity cap (its SPEC.md, section 6), after quota.integration.test.ts:
//! every new account or bot, and every passkey added to an account, counts
//! against its IP's day and the server's.

use super::helpers::*;
use super::webauthn_test::*;
use crate::obj;
use crate::server::config::Config;
use crate::server::limits::Limits;
use crate::server::protocol::*;

const NETWORK: &str = "Registration limit reached for this network";

fn server(limits: Limits) -> TestServer {
    new_test_server(Config {
        limits,
        client_ip_header: "Cf-Connecting-IP".into(),
        web_authn: Some(test_web_authn()),
        ..admin_config()
    })
}

fn registrations(per_ip: u32, per_day: u32, identities: usize) -> Limits {
    Limits {
        registrations_per_ip_day: per_ip,
        registrations_per_day: per_day,
        identities,
        ..Limits::unlimited()
    }
}

fn dial_from(server: &TestServer, ip: &str) -> TestClient {
    dial_headers(
        server,
        &[("Origin", TEST_PASSKEY_ORIGIN), ("Cf-Connecting-IP", ip)],
    )
    .0
}

/// The admin user, made by its first sign-in from `ip`, which counts.
fn admin_from(server: &TestServer, ip: &str) -> TestClient {
    let mut c = dial_from(server, ip);
    passkey_result(&token_auth(&mut c, ADMIN_TOKEN));
    c.user_id = "admin".into();
    c.drain();
    c
}

/// The code, message and retry_after (absent as -1) of a refusal.
fn refusal(frame: &Object) -> (i64, String, i64) {
    let error = frame
        .get("error")
        .and_then(Json::as_object)
        .unwrap_or_else(|| panic!("want an error: {frame:?}"));
    let Json::Number(code) = error["code"] else {
        panic!("{error:?}")
    };
    let retry = match error.get("data").and_then(Json::as_object) {
        Some(data) => match data["retry_after"] {
            Json::Number(seconds) => seconds as i64,
            _ => panic!("{data:?}"),
        },
        None => -1,
    };
    (
        code as i64,
        error["message"].as_str().unwrap().to_owned(),
        retry,
    )
}

fn invite_token(c: &mut TestClient, user_id: &str) -> Object {
    let id = c.next_id("command");
    reply(
        c,
        "command",
        &id,
        obj! {"body" => obj! {"text" => format!("/invite-token {user_id}")}},
    )
}

/// Registers a passkey account from `ip`, returning the finish frame.
fn passkey_sign_up(server: &TestServer, ip: &str) -> (TestClient, Object) {
    let mut c = dial_from(server, ip);
    guest_auth(&mut c);
    let options = passkey_result(&passkey_call(
        &mut c,
        "begin",
        "register",
        "begin",
        Object::new(),
    ));
    let credential = new_test_authenticator().registration(&options, TEST_PASSKEY_ORIGIN);
    let frame = passkey_call(
        &mut c,
        "finish",
        "register",
        "finish",
        obj! {"credential" => credential},
    );
    c.drain();
    (c, frame)
}

/// Adds a passkey to the account c is signed in as, returning the finish
/// frame.
fn add_passkey(c: &mut TestClient) -> Object {
    let options = passkey_result(&passkey_call(c, "add", "register", "begin", Object::new()));
    let credential = new_test_authenticator().registration(&options, TEST_PASSKEY_ORIGIN);
    passkey_call(
        c,
        "add-end",
        "register",
        "finish",
        obj! {"credential" => credential},
    )
}

#[test]
fn test_registration_defaults_are_cloudflares() {
    let limits = Limits::default();
    assert_eq!(
        (
            limits.registrations_per_ip_day,
            limits.registrations_per_day,
            limits.identities
        ),
        (5, 300, 10_000)
    );
}

/// Five registrations a UTC day per IP key: the admin's first sign-in,
/// /invite-token accounts, a bot and passkeys added all count; the sixth is
/// retry_after until the day ends, and another address is unaffected.
#[test]
fn test_registrations_per_ip_day() {
    let server = server(registrations(5, 0, 0));
    let mut admin = admin_from(&server, "198.51.100.1");
    for user_id in ["one", "two"] {
        assert_eq!(invite_token(&mut admin, user_id).get("error"), None);
    }
    private_reply(&mut admin, "/invite-bot");
    let (mut account, frame) = passkey_sign_up(&server, "198.51.100.1");
    passkey_result(&frame);
    let (code, message, retry) = refusal(&add_passkey(&mut account));
    assert_eq!((code, message.as_str()), (CODE_RETRY_AFTER, NETWORK));
    let until_midnight = 86_400 - (rust_stdlib::time::now().unix() % 86_400);
    assert!(
        (until_midnight - 1..=until_midnight + 1).contains(&retry),
        "retry_after {retry}, want about {until_midnight}"
    );
    assert_eq!(
        refusal(&invite_token(&mut admin, "three")).1,
        NETWORK,
        "a sixth from the same address"
    );
    let (_, frame) = passkey_sign_up(&server, "198.51.100.2");
    passkey_result(&frame);
}

/// The server's day counts every address together.
#[test]
fn test_registrations_per_day() {
    let server = server(registrations(0, 3, 0));
    let mut admin = admin_from(&server, "198.51.100.1");
    assert_eq!(invite_token(&mut admin, "one").get("error"), None);
    let (_, frame) = passkey_sign_up(&server, "198.51.100.2");
    passkey_result(&frame);
    let (code, message, _) = refusal(&passkey_sign_up(&server, "198.51.100.3").1);
    assert_eq!(
        (code, message.as_str()),
        (CODE_RETRY_AFTER, "Registration limit reached")
    );
}

/// Past the identity cap a new account or bot is denied with
/// registration_closed, while a passkey added to an account still is not.
#[test]
fn test_identity_cap_closes_registration() {
    let server = server(registrations(0, 0, 3));
    let mut admin = admin_from(&server, "198.51.100.1");
    let (mut account, frame) = passkey_sign_up(&server, "198.51.100.2");
    passkey_result(&frame);
    assert_eq!(invite_token(&mut admin, "one").get("error"), None);
    let closed = (CODE_DENIED, "registration_closed".to_owned(), -1);
    assert_eq!(refusal(&invite_token(&mut admin, "two")), closed);
    // Kept open, so its guest's leave does not reach account mid-request.
    let (_guest, frame) = passkey_sign_up(&server, "198.51.100.3");
    assert_eq!(refusal(&frame), closed);
    account.drain();
    passkey_result(&add_passkey(&mut account));
    let id = account.next_id("command");
    let frame = reply(
        &mut account,
        "command",
        &id,
        obj! {"body" => obj! {"text" => "/invite-bot"}},
    );
    assert_eq!(refusal(&frame), closed, "a bot");
}

/// A sign-up with the /invite token counts against the signer's address,
/// and a refused one leaves the invite's use unspent.
#[test]
fn test_invite_sign_up_is_a_registration() {
    let server = server(registrations(1, 0, 0));
    let mut admin = admin_from(&server, "198.51.100.1");
    let invite = token_in(&private_reply(&mut admin, "/invite 2"));
    let mut first = dial_from(&server, "198.51.100.2");
    let up = |c: &mut TestClient, name: &str| {
        let id = c.next_id("auth");
        reply(
            c,
            "auth",
            &id,
            obj! {"scheme" => "token", "token" => invite.as_str(), "name" => name},
        )
    };
    passkey_result(&up(&mut first, "Ada"));
    let mut second = dial_from(&server, "198.51.100.2");
    assert_eq!(refusal(&up(&mut second, "Bea")).1, NETWORK);
    let mut third = dial_from(&server, "198.51.100.3");
    passkey_result(&up(&mut third, "Cy"));
    let mut fourth = dial_from(&server, "198.51.100.4");
    assert_eq!(
        refusal(&up(&mut fourth, "Di")).1,
        "This invite is used up or has expired; ask an admin for a new one",
        "Ada and Cy spent the two uses"
    );
}

/// An email sign-up, this server's extension, counts as a registration
/// like any other new account.
#[test]
fn test_email_sign_up_is_a_registration() {
    let (server, mailbox) = super::email_test::email_test_server(|config| {
        config.limits = registrations(1, 0, 0);
        config.client_ip_header = "Cf-Connecting-IP".into();
    });
    let sign_up = |email: &str| {
        let mut c = dial_from(&server, "198.51.100.1");
        super::email_test::propose(&mut c, email);
        let token = super::email_test::link_token(&mailbox.receive());
        let id = c.next_id("approve");
        reply(
            &mut c,
            "auth",
            &id,
            obj! {"scheme" => "email", "token" => token.as_str()},
        )
    };
    let first = sign_up("ada@example.com");
    assert!(passkey_result(&first).contains_key("token"), "{first:?}");
    let frame = sign_up("bea@example.com");
    assert_eq!(refusal(&frame).1, NETWORK);
}
