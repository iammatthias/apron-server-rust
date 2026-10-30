//! /invite-purge: an admin takes away every way an account signs in and
//! gets a new token for it, ported from apron-server-cloudflare's "/invite-purge
//! removes every way a user signs in and gives the admin a new token for
//! them" (test/admin.integration.test.ts).

use std::sync::Arc;

use rust_stdlib::time;

use super::helpers::*;
use super::persist_test::start_with;
use super::webauthn_test::*;
use crate::obj;
use crate::server::protocol::*;
use crate::store::{self, Store};

/// Checks that c got the close error with message, and closed.
fn expect_closed(c: &TestClient, message: &str, what: &str) {
    assert_eq!(
        c.read(),
        obj! {"error" => obj! {"code" => CODE_DENIED, "message" => message}},
        "{what}"
    );
    assert!(c.read_raw(time::SECOND).is_err(), "{what} stayed open");
}

/// Connects from origin and signs in with token, returning the connection
/// and the reply.
fn signed_in(server: &TestServer, origin: &str, token: &str) -> (TestClient, Object) {
    let (mut c, _) = dial_origin(server, origin);
    let frame = token_auth(&mut c, token);
    c.drain();
    (c, frame)
}

fn error_of(frame: &Object) -> (i64, String) {
    let error = frame
        .get("error")
        .and_then(Json::as_object)
        .unwrap_or_else(|| panic!("want an error: {frame:?}"));
    (
        match error["code"] {
            Json::Number(code) => code as i64,
            ref other => panic!("code {other:?}"),
        },
        error["message"].as_str().unwrap().to_owned(),
    )
}

/// The notice /invite-purge sends on a server without a public URL, for
/// the new token it carries.
fn purge_notice(user_id: &str, passkeys: &str, token: &str) -> String {
    format!(
        "Signed `{user_id}` out everywhere and removed {passkeys} and every token they had. This new token signs in as them; it does not expire, and anyone who has it signs in as `{user_id}`, so hand it over privately.\n\n```\n{token}\n```\n\nTo sign in, authenticate with the token scheme: `{{\"method\": \"auth\", \"params\": {{\"scheme\": \"token\", \"token\": \"{token}\"}}}}`"
    )
}

#[test]
fn test_invite_purge_removes_every_way_in() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut a = new_test_authenticator();
    let (mut target, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut target, &mut a);
    let user_id = user_id_of(&registered);
    let session = registered["token"].as_str().unwrap().to_owned();
    target.user_id = user_id.clone();
    target.drain();
    let old_handle = server.app.lock().users[&user_id]
        .passkey
        .as_ref()
        .unwrap()
        .handle
        .clone();
    let (mut on_session, frame) = signed_in(&server, TEST_PASSKEY_ORIGIN, &session);
    assert_eq!(user_id_of(&passkey_result(&frame)), user_id, "session");
    let device = token_in(&private_reply(&mut target, "/invite-device add phone"));
    let (mut on_device, frame) = signed_in(&server, "", &device);
    assert_eq!(user_id_of(&passkey_result(&frame)), user_id, "device");
    on_device.result(
        "push_register",
        "push",
        obj! {"kind" => "relay", "url" => "https://fcm.googleapis.com/fcm/send/phone"},
    );
    let bot_token = token_in(&private_reply(&mut target, "/invite-bot"));
    let (mut bot, frame) = signed_in(&server, "", &bot_token);
    let bot_id = user_id_of(&passkey_result(&frame));
    for c in [&mut target, &mut on_session, &mut on_device, &mut admin] {
        c.drain();
    }

    let text = private_reply(&mut admin, &format!("/invite-purge @{user_id}"));
    let fresh = token_in(&text);
    assert_eq!(text, purge_notice(&user_id, "1 passkey", &fresh), "notice");
    assert!(
        fresh.starts_with("apron_invite_") && fresh.len() == "apron_invite_".len() + 43,
        "token {fresh:?}"
    );
    for (c, what) in [
        (&target, "the passkey connection"),
        (&on_session, "the session connection"),
        (&on_device, "the device connection"),
    ] {
        expect_closed(c, "Signed out by an admin", what);
    }
    {
        let st = server.app.lock();
        let u = &st.users[&user_id];
        assert!(
            u.passkey.is_none() && u.account(),
            "passkeys after: {:?}",
            u.passkey
        );
        assert!(st.credentials.is_empty(), "credentials left");
        assert!(
            !st.pushes.values().any(|p| p.user_id == user_id),
            "push registrations left"
        );
        assert!(
            !st.users[&bot_id].clients.is_empty(),
            "the bot was signed out"
        );
    }
    bot.drain();

    // Nothing they signed in with works any more, but the new token does.
    let (_, frame) = signed_in(&server, TEST_PASSKEY_ORIGIN, &session);
    assert_eq!(
        error_of(&frame),
        (CODE_DENIED, "Session expired; sign in again".into()),
        "old session"
    );
    let (_, frame) = signed_in(&server, "", &device);
    assert_eq!(error_of(&frame).0, CODE_DENIED, "old device token");
    let (mut login, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let options = passkey_result(&passkey_call(
        &mut login,
        "begin",
        "login",
        "begin",
        Object::new(),
    ));
    let credential = a.assertion(&options, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    let frame = passkey_call(
        &mut login,
        "finish",
        "login",
        "finish",
        obj! {"credential" => credential},
    );
    assert_eq!(
        error_of(&frame).0,
        CODE_DENIED,
        "removed passkey: {frame:?}"
    );
    let (mut on_fresh, frame) = signed_in(&server, TEST_PASSKEY_ORIGIN, &fresh);
    assert_eq!(user_id_of(&passkey_result(&frame)), user_id, "new token");
    on_fresh.user_id = user_id.clone();
    assert_eq!(
        private_reply(&mut on_fresh, "/invite-device list"),
        "You have no device tokens; get one with `/invite-device add`.",
        "device tokens after"
    );
    // A passkey added later takes a new user handle.
    let options = passkey_result(&passkey_call(
        &mut on_fresh,
        "add-begin",
        "register",
        "begin",
        Object::new(),
    ));
    let credential = new_test_authenticator().registration(&options, TEST_PASSKEY_ORIGIN);
    let added = passkey_result(&passkey_call(
        &mut on_fresh,
        "add-finish",
        "register",
        "finish",
        obj! {"credential" => credential},
    ));
    assert_eq!(user_id_of(&added), user_id, "passkey added after");
    on_fresh.drain();
    assert_ne!(
        server.app.lock().users[&user_id]
            .passkey
            .as_ref()
            .unwrap()
            .handle,
        old_handle,
        "user handle after"
    );

    // Again, the token it gave before stops working too.
    let text = private_reply(&mut admin, &format!("/invite-purge {user_id}"));
    let again = token_in(&text);
    assert_eq!(text, purge_notice(&user_id, "1 passkey", &again), "again");
    expect_closed(
        &on_fresh,
        "Signed out by an admin",
        "the new token's connection",
    );
    let (_, frame) = signed_in(&server, "", &fresh);
    assert_eq!(
        error_of(&frame),
        (
            CODE_DENIED,
            "This invite token is not valid; ask an admin for a new one".into()
        ),
        "the first new token"
    );
    let text = private_reply(&mut admin, &format!("/invite-purge {user_id}"));
    assert!(text.contains("removed 0 passkeys"), "{text}");
}

#[test]
fn test_invite_purge_refusals() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut other = account(&server);
    let mut plain = account(&server);
    let other_id = other.user_id.clone();
    private_reply(&mut admin, &format!("/admin {other_id}"));
    other.drain();
    let bot_token = token_in(&private_reply(&mut plain, "/invite-bot"));
    let (_, frame) = signed_in(&server, "", &bot_token);
    let bot_id = user_id_of(&passkey_result(&frame));
    let guest = dial_test_client(&server);
    assert_eq!(
        command_error(&mut other, &format!("/invite-purge {other_id}")),
        (CODE_DENIED, "You can't /invite-purge yourself".into()),
    );
    assert_eq!(
        command_error(&mut other, "/invite-purge admin"),
        (
            CODE_DENIED,
            "The admin user signs in with APRON_ADMIN_TOKEN only".into()
        ),
    );
    for id in [bot_id.as_str(), "bot_nobody"] {
        assert_eq!(
            command_error(&mut admin, &format!("/invite-purge {id}")),
            (
                CODE_DENIED,
                "A bot signs in with its token only; its owner replaces it with /invite-bot".into()
            ),
            "{id}"
        );
    }
    for id in ["nobody", guest.user_id.as_str()] {
        assert_eq!(
            command_error(&mut admin, &format!("/invite-purge {id}")),
            (CODE_INVALID_PARAMS, format!("No user has the user_id {id}")),
            "{id}"
        );
    }
    for text in ["/invite-purge", "/invite-purge a b"] {
        assert_eq!(
            command_error(&mut admin, text),
            (CODE_INVALID_PARAMS, "Usage: /invite-purge <user_id>".into()),
            "{text}"
        );
    }
    assert_eq!(
        command_error(&mut plain, &format!("/invite-purge {other_id}")),
        (CODE_DENIED, "Only an admin can use /invite-purge".into()),
    );
}

#[test]
fn test_invite_purge_survives_restart() {
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let dir = TempDir::new("apron-invite-purge-");
    let configure = |config: &mut crate::server::config::Config| {
        config.admin_token = admin_config().admin_token;
        config.web_authn = admin_config().web_authn;
    };
    let mut server = start_with(kept.clone(), &format!("{dir}/a"), configure);
    let mut admin = admin(&server);
    let (mut target, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut target, &mut new_test_authenticator());
    let user_id = user_id_of(&registered);
    target.user_id = user_id.clone();
    target.drain();
    let device = token_in(&private_reply(&mut target, "/invite-device add phone"));
    let fresh = token_in(&private_reply(
        &mut admin,
        &format!("/invite-purge {user_id}"),
    ));
    drop((admin, target));
    server.stop();

    let server = start_with(kept, &format!("{dir}/b"), configure);
    let (_, frame) = signed_in(
        &server,
        TEST_PASSKEY_ORIGIN,
        registered["token"].as_str().unwrap(),
    );
    assert_eq!(error_of(&frame).0, CODE_DENIED, "old session after restart");
    let (_, frame) = signed_in(&server, "", &device);
    assert_eq!(
        error_of(&frame).0,
        CODE_DENIED,
        "old device token after restart"
    );
    let (_, frame) = signed_in(&server, "", &fresh);
    assert_eq!(
        user_id_of(&passkey_result(&frame)),
        user_id,
        "new token after restart"
    );
    let st = server.app.lock();
    assert!(
        st.users[&user_id].passkey.is_none() && st.credentials.is_empty(),
        "passkeys after restart"
    );
}
