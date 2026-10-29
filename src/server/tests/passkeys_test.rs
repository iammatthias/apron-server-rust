//! /passkeys and the notice of an added passkey, as apron-server-cloudflare
//! has them (its SPEC.md, section 5, WebAuthn).

use rust_stdlib::time;

use super::admin_test::{command_error, private_reply};
use super::helpers::*;
use super::webauthn_test::*;
use crate::obj;
use crate::server::protocol::*;
use crate::server::push::PushRegistration;

/// The ~private notice in no room that c reads next.
fn roomless_notice(c: &TestClient) -> String {
    let frame = c.read();
    let notice = notification_params(&frame, "message");
    assert!(
        !notice.contains_key("room_id")
            && notice["from"]
                == Json::from(obj! {"user_id" => "~private", "name" => "System message to you"}),
        "notice: {frame:?}"
    );
    notice["body"].as_object().unwrap()["text"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Adds a passkey from a new authenticator to the account c is signed in
/// as, and returns the authenticator.
fn add_passkey(c: &mut TestClient) -> TestAuthenticator {
    let options = passkey_result(&passkey_call(c, "add", "register", "begin", Object::new()));
    let mut a = new_test_authenticator();
    let credential = a.registration(&options, TEST_PASSKEY_ORIGIN);
    passkey_result(&passkey_call(
        c,
        "add-end",
        "register",
        "finish",
        obj! {"credential" => credential},
    ));
    a
}

/// Signs a new connection in with authenticator a, returning the frame.
fn login(server: &TestServer, a: &mut TestAuthenticator) -> Object {
    let (mut c, _) = dial_origin(server, TEST_PASSKEY_ORIGIN);
    let options = passkey_result(&passkey_call(
        &mut c,
        "begin",
        "login",
        "begin",
        Object::new(),
    ));
    let credential = a.assertion(&options, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    passkey_call(
        &mut c,
        "finish",
        "login",
        "finish",
        obj! {"credential" => credential},
    )
}

/// A passkey added from one connection is told to the account's others;
/// /passkeys lists them with when each was added and used, and removes one,
/// told to the others too, with the account's push registrations, but never
/// the last one.
#[test]
fn test_passkeys_list_and_remove() {
    let server = passkey_test_server();
    let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let mut first = new_test_authenticator();
    let registered = register_test_passkey(&mut owner, &mut first);
    owner.drain();
    let (mut other, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    passkey_result(&passkey_call(
        &mut other,
        "resume",
        "token",
        "",
        obj! {"token" => registered["token"].clone()},
    ));
    other.drain();
    let mut second = add_passkey(&mut other);
    assert_eq!(
        roomless_notice(&owner),
        "A passkey was added to your account from another connection. If it wasn't you, remove it with `/passkeys`."
    );
    other.expect_quiet();
    passkey_result(&login(&server, &mut second));

    let today = time::now().utc().format("2006-01-02");
    let ids: Vec<String> = {
        let app = server.app.lock();
        let passkey = app.users[&owner.user_id].passkey.clone().unwrap();
        passkey
            .credentials
            .iter()
            .map(|c| crate::server::webpush::encode_base64_url(&c.id.0)[..8].to_owned())
            .collect()
    };
    assert_eq!(
        private_reply(&mut owner, "/passkeys"),
        format!(
            "Your passkeys:\n1. `{}…`, added {today}, last used {today}\n2. `{}…`, added {today}, last used {today}",
            ids[0], ids[1]
        )
    );
    for bad in [
        "/passkeys remove",
        "/passkeys remove x",
        "/passkeys remove 100",
        "/passkeys drop 1",
    ] {
        assert_eq!(
            command_error(&mut owner, bad),
            (
                CODE_INVALID_PARAMS,
                "Usage: /passkeys, or /passkeys remove <n>".into()
            ),
            "{bad}"
        );
    }
    for out_of_range in ["/passkeys remove 3", "/passkeys remove 0"] {
        assert_eq!(
            command_error(&mut owner, out_of_range),
            (
                CODE_INVALID_PARAMS,
                "You have 2 passkeys; see /passkeys".into()
            ),
        );
    }

    server.app.lock().add_push_locked(PushRegistration {
        user_id: owner.user_id.clone(),
        url: "https://push.example/phone".into(),
        ..PushRegistration::default()
    });
    let removed = format!("Removed the passkey `{}…` from your account.", ids[1]);
    assert_eq!(private_reply(&mut owner, "/passkeys remove 2"), removed);
    assert_eq!(roomless_notice(&other), removed);
    assert!(
        !server.app.lock().user_has_pushes(&owner.user_id),
        "push registrations kept"
    );
    assert!(
        login(&server, &mut second).contains_key("error"),
        "the removed passkey still signs in"
    );
    // It is free to register again, as a new account.
    let (mut again, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    guest_auth(&mut again);
    let options = passkey_result(&passkey_call(
        &mut again,
        "reg",
        "register",
        "begin",
        Object::new(),
    ));
    let credential = second.registration(&options, TEST_PASSKEY_ORIGIN);
    passkey_result(&passkey_call(
        &mut again,
        "reg-end",
        "register",
        "finish",
        obj! {"credential" => credential},
    ));
    assert_eq!(
        command_error(&mut owner, "/passkeys remove 1"),
        (CODE_DENIED, "You can't remove your only passkey".into()),
    );
    passkey_result(&login(&server, &mut first));
}

/// An account with no passkey is told so; a guest may not run /passkeys.
#[test]
fn test_passkeys_without_one() {
    let server = super::admin_test::admin_test_server();
    let mut admin = super::admin_test::admin(&server);
    assert_eq!(
        private_reply(&mut admin, "/passkeys"),
        "Your account has no passkey. Register one while signed in to add it."
    );
    let mut guest = dial_test_client(&server);
    assert_eq!(
        command_error(&mut guest, "/passkeys"),
        (
            CODE_DENIED,
            "Sign in with a passkey to use /passkeys".into()
        ),
    );
}
