//! The tests of webauthn_test.go that check what the server refuses. They
//! cover invalid proofs and registrations, malformed fields, and the requests
//! that run no ceremony. The software authenticator lives in webauthn_test.rs.

use rust_stdlib::time::{self};

use super::helpers::*;
use super::webauthn_test::{
    new_test_authenticator, passkey_call, passkey_denied, passkey_result, passkey_test_server,
    register_test_passkey, str_of, TEST_PASSKEY_ORIGIN,
};
use crate::obj;
use crate::server::protocol::*;

fn error_code(frame: &Object) -> Option<Json> {
    frame
        .get("error")
        .and_then(Json::as_object)
        .and_then(|e| e.get("code"))
        .cloned()
}

#[test]
fn test_passkey_rejects_invalid_proofs() {
    let server = passkey_test_server();
    let mut a = new_test_authenticator();
    let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    register_test_passkey(&mut owner, &mut a);
    for (name, origin, rp_id, flags) in [
        ("wrong origin", "https://evil.example", "localhost", 0x05),
        ("wrong RP", TEST_PASSKEY_ORIGIN, "evil.example", 0x05),
        (
            "no user verification",
            TEST_PASSKEY_ORIGIN,
            "localhost",
            0x01,
        ),
        ("no user presence", TEST_PASSKEY_ORIGIN, "localhost", 0x04),
    ] {
        let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
        let options = passkey_result(&passkey_call(
            &mut c,
            "begin",
            "login",
            "begin",
            Object::new(),
        ));
        let proof = a.assertion(&options, origin, rp_id, flags);
        let finish = passkey_call(
            &mut c,
            "finish",
            "login",
            "finish",
            obj! {"credential" => proof.clone()},
        );
        assert_eq!(
            error_code(&finish),
            Some(Json::from(CODE_DENIED)),
            "{name}: {finish:?}"
        );
        let retry = passkey_call(
            &mut c,
            "retry",
            "login",
            "finish",
            obj! {"credential" => proof},
        );
        assert_eq!(
            error_code(&retry),
            Some(Json::from(CODE_DENIED)),
            "{name} retry: {retry:?}"
        );
    }
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let first = passkey_result(&passkey_call(
        &mut c,
        "first",
        "login",
        "begin",
        Object::new(),
    ));
    let second = passkey_result(&passkey_call(
        &mut c,
        "second",
        "login",
        "begin",
        Object::new(),
    ));
    let proof = a.assertion(&first, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    passkey_denied(&passkey_call(
        &mut c,
        "superseded",
        "login",
        "finish",
        obj! {"challenge_id" => first["challenge_id"].clone(), "credential" => proof.clone()},
    ));
    let current = a.assertion(&second, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    passkey_result(&passkey_call(
        &mut c,
        "current",
        "login",
        "finish",
        obj! {"challenge_id" => second["challenge_id"].clone(), "credential" => current},
    ));
    let (mut other, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    passkey_denied(&passkey_call(
        &mut other,
        "cross-connection",
        "login",
        "finish",
        obj! {"challenge_id" => first["challenge_id"].clone(), "credential" => proof},
    ));
    let options = passkey_result(&passkey_call(
        &mut c,
        "expire",
        "login",
        "begin",
        Object::new(),
    ));
    {
        let mut st = server.app.lock();
        for conn in st.clients.values_mut() {
            if let Some(ceremony) = conn.ceremony.as_mut() {
                ceremony.expires = time::now().add(-time::SECOND);
            }
        }
    }
    let credential = a.assertion(&options, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    passkey_denied(&passkey_call(
        &mut c,
        "expired",
        "login",
        "finish",
        obj! {"credential" => credential},
    ));
    passkey_denied(&passkey_call(
        &mut other,
        "unauth-register",
        "register",
        "begin",
        Object::new(),
    ));
    // An origin not configured for passkeys is not offered them.
    let (mut wrong_origin, frame) = dial_origin(&server, "http://localhost:9999");
    assert_eq!(
        notification_params(&frame, "server")["auth"],
        strings(&["token", "guest"])
    );
    let refused = passkey_call(&mut wrong_origin, "origin", "login", "begin", Object::new());
    assert_eq!(
        refused["error"].as_object().unwrap()["code"],
        Json::from(CODE_UNSUPPORTED),
        "{refused:?}"
    );
}

#[test]
fn test_passkey_rejects_invalid_registration() {
    let server = passkey_test_server();
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    guest_auth(&mut c);
    let mut a = new_test_authenticator();
    let options = passkey_result(&passkey_call(
        &mut c,
        "begin",
        "register",
        "begin",
        Object::new(),
    ));
    let proof = a.registration(&options, "https://evil.example");
    passkey_denied(&passkey_call(
        &mut c,
        "bad-origin",
        "register",
        "finish",
        obj! {"credential" => proof},
    ));
    let proof = a.registration(&options, TEST_PASSKEY_ORIGIN);
    passkey_denied(&passkey_call(
        &mut c,
        "consumed",
        "register",
        "finish",
        obj! {"credential" => proof},
    ));
    for malformed in [
        Json::Null,
        Json::from("invalid"),
        Json::from(Vec::<Json>::new()),
        Json::from(Object::new()),
    ] {
        passkey_result(&passkey_call(
            &mut c,
            "begin",
            "register",
            "begin",
            Object::new(),
        ));
        let failure = passkey_call(
            &mut c,
            "malformed",
            "register",
            "finish",
            obj! {"credential" => malformed},
        );
        assert_eq!(
            error_code(&failure),
            Some(Json::from(CODE_INVALID_PARAMS)),
            "malformed credential: {failure:?}"
        );
    }
    let st = server.app.lock();
    let passkeys = st.users.values().filter(|u| u.passkey.is_some()).count();
    assert!(
        passkeys == 0 && st.credentials.is_empty() && st.sessions.is_empty(),
        "failed registration retained an account, credential, or session"
    );
}

/// A WebAuthn begin step authenticates nothing, so requests pipelined behind
/// it are denied (§3.2); a verified finish lets the ones behind it run.
#[test]
fn test_passkey_begin_is_no_barrier_pass() {
    let server = passkey_test_server();
    let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let mut a = new_test_authenticator();
    register_test_passkey(&mut owner, &mut a);

    let (c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    c.write(&obj! {"method" => "auth", "id" => "begin", "params" => obj! {"scheme" => "webauthn", "action" => "login", "step" => "begin"}});
    c.write(
        &obj! {"method" => "room_list", "id" => "list", "params" => obj! {"filter" => "joined"}},
    );
    let options = passkey_result(&c.read());
    let denied = c.read();
    assert!(
        denied.get("id").and_then(Json::as_str) == Some("list")
            && error_code(&denied) == Some(Json::from(CODE_DENIED)),
        "room_list behind begin: {denied:?}"
    );
    let credential = a.assertion(&options, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    c.write(
        &obj! {"method" => "auth", "id" => "finish", "params" => obj! {
            "scheme" => "webauthn", "action" => "login", "step" => "finish",
            "challenge_id" => options["challenge_id"].clone(), "credential" => credential,
        }},
    );
    c.write(
        &obj! {"method" => "room_list", "id" => "listed", "params" => obj! {"filter" => "joined"}},
    );
    passkey_result(&c.read());
    let listed = passkey_result(&c.read());
    assert_eq!(
        room_ids(listed.get("joined")),
        vec!["general".to_owned()],
        "room_list behind a verified finish: {listed:?}"
    );
}

#[test]
fn test_passkey_notifications_do_not_run_ceremonies() {
    let server = passkey_test_server();
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    guest_auth(&mut c);
    let mut a = new_test_authenticator();
    let options = passkey_result(&passkey_call(
        &mut c,
        "begin",
        "register",
        "begin",
        Object::new(),
    ));
    let proof = a.registration(&options, TEST_PASSKEY_ORIGIN);
    let challenge_id = str_of(&options, "challenge_id").to_owned();

    // This notification carries the current challenge and a malformed
    // proof. It must not consume the ceremony or produce a response.
    c.write(&obj! {"method" => "auth", "params" => obj! {
        "scheme" => "webauthn", "action" => "register", "step" => "finish",
        "challenge_id" => challenge_id, "credential" => Object::new(),
    }});
    let result = passkey_result(&passkey_call(
        &mut c,
        "finish",
        "register",
        "finish",
        obj! {"credential" => proof},
    ));
    assert!(
        you_of(&result)
            .get("user_id")
            .and_then(Json::as_str)
            .is_some_and(|id| !id.is_empty()),
        "registration result lost identity: {result:?}"
    );
}

#[test]
fn test_passkey_malformed_fields() {
    let server = passkey_test_server();
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    guest_auth(&mut c);

    // Actions require a valid step and reject unknown action names.
    for (id, params) in [
        (
            "unknown-action",
            obj! {"scheme" => "webauthn", "action" => "other", "step" => "begin"},
        ),
        (
            "no-step",
            obj! {"scheme" => "webauthn", "action" => "register"},
        ),
        (
            "bad-step",
            obj! {"scheme" => "webauthn", "action" => "register", "step" => "middle"},
        ),
    ] {
        c.write(&obj! {"method" => "auth", "id" => id, "params" => params});
        let frame = c.read();
        assert_eq!(
            error_code(&frame),
            Some(Json::from(CODE_INVALID_PARAMS)),
            "{id}: {frame:?}"
        );
    }

    let mut a = new_test_authenticator();
    let options = passkey_result(&passkey_call(
        &mut c,
        "begin",
        "register",
        "begin",
        Object::new(),
    ));
    let proof = a.registration(&options, TEST_PASSKEY_ORIGIN);
    // The opaque ID matches, but the action does not. The bound ceremony is
    // consumed before this policy failure and cannot be retried as
    // register.
    passkey_denied(&passkey_call(
        &mut c,
        "wrong-action",
        "login",
        "finish",
        obj! {"challenge_id" => options["challenge_id"].clone(), "credential" => proof.clone()},
    ));
    passkey_denied(&passkey_call(
        &mut c,
        "wrong-action-retry",
        "register",
        "finish",
        obj! {"credential" => proof},
    ));
    let options = passkey_result(&passkey_call(
        &mut c,
        "begin-again",
        "register",
        "begin",
        Object::new(),
    ));
    let proof = a.registration(&options, TEST_PASSKEY_ORIGIN);
    // Missing challenge_id is malformed and leaves the pending challenge in
    // place because no challenge can be matched.
    c.write(&obj! {"method" => "auth", "id" => "missing-challenge", "params" => obj! {
        "scheme" => "webauthn", "action" => "register", "step" => "finish", "credential" => proof.clone(),
    }});
    let missing = c.read();
    assert_eq!(
        error_code(&missing),
        Some(Json::from(CODE_INVALID_PARAMS)),
        "missing challenge_id: {missing:?}"
    );
    // A matching malformed credential is invalid_params and consumes the
    // challenge, so its later retry is a denied missing challenge.
    let failure = passkey_call(
        &mut c,
        "malformed",
        "register",
        "finish",
        obj! {"credential" => Object::new()},
    );
    assert_eq!(
        error_code(&failure),
        Some(Json::from(CODE_INVALID_PARAMS)),
        "malformed credential: {failure:?}"
    );
    passkey_denied(&passkey_call(
        &mut c,
        "retry",
        "register",
        "finish",
        obj! {"credential" => proof},
    ));
}
