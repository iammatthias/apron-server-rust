//! Accounts, roles and the admin user, and checks that a revoked
//! sign-in runs nothing.

use std::sync::Arc;

use crate::obj;
use crate::server::config::Config;
use crate::server::protocol::*;

use super::super::webauthn_test::{
    new_test_authenticator, passkey_result, register_test_passkey, test_web_authn,
    TEST_PASSKEY_ORIGIN,
};
use super::*;
use rust_stdlib_crypto::sha256;

const LATE_POST: &[u8] =
    br#"{"method":"message","id":"late","params":{"room_id":"general","body":{"text":"still here"}}}"#;

/// Runs the command `text` on asker, whose connection in the server is
/// asker_conn, while holding the state lock, and checks before releasing it
/// that the command revoked `revoked`, a connection of user_id: it is still
/// connected, as its writer has not drained, but closing and signed out, so
/// a request already past the read loop is denied when it resolves its
/// identity. Returns the frames asker receives before the result.
pub fn command_revoking(
    server: &TestServer,
    asker: &mut TestClient,
    asker_conn: &Arc<crate::server::client::Client>,
    text: &str,
    revoked: &Arc<crate::server::client::Client>,
    user_id: &str,
) -> Vec<Object> {
    let command = encode_json(&obj! {
        "method" => "command", "id" => "reissue", "params" => obj! {"body" => obj! {"text" => text}},
    })
    .unwrap();
    let (command, _) = parse_request(&command, &FrameLimits::default());
    let (late, _) = parse_request(LATE_POST, &FrameLimits::default());
    {
        let mut st = server.app.lock();
        st.command_locked(asker_conn, &command)
            .unwrap_or_else(|e| panic!("{text}: {e:?}"));
        assert!(
            st.clients.contains_key(&revoked.id) && revoked.is_closing(),
            "the revoked connection is not closing"
        );
        assert!(
            st.client_user(revoked).is_none(),
            "the revoked connection is signed in"
        );
        assert!(
            !st.users[user_id].clients.contains(&revoked.id),
            "{user_id} keeps the revoked connection"
        );
        let messages = st.messages.len();
        let err = st.save_message_locked(revoked, &late).unwrap_err();
        assert_eq!(
            (err.code, err.message.as_str(), st.messages.len()),
            (CODE_DENIED, "Sign in before sending requests", messages),
            "in-flight message on the revoked connection"
        );
    }
    let mut before = Vec::new();
    loop {
        let frame = asker.read();
        if frame.get("id") == Some(&Json::from("reissue")) {
            assert!(frame.contains_key("result"), "{text}: {frame:?}");
            return before;
        }
        before.push(frame);
    }
}

/// Checks that frames the revoked connection c sends from now on are
/// ignored, a sign-in included, and that no message reached watcher.
pub fn assert_revoked_runs_nothing(
    server: &TestServer,
    c: &Arc<crate::server::client::Client>,
    watcher: &mut TestClient,
) {
    let (messages, users) = {
        let st = server.app.lock();
        (st.messages.len(), st.users.len())
    };
    server.app.process_frame(c, LATE_POST);
    server.app.process_frame(
        c,
        br#"{"method":"auth","id":"again","params":{"scheme":"guest"}}"#,
    );
    let st = server.app.lock();
    assert_eq!(
        (st.messages.len(), st.users.len(), st.client_user(c)),
        (messages, users, None),
        "the revoked connection posted or signed in"
    );
    drop(st);
    let frames = watcher.drain();
    assert!(
        frames
            .iter()
            .all(|f| f.get("method") != Some(&Json::from("message"))),
        "a message reached a member: {frames:?}"
    );
}

/// Gives user_id `role` in memory only, so a test guest can do what the
/// role allows (guests never hold roles otherwise).
pub fn grant_role(server: &TestServer, user_id: &str, role: &str) {
    let mut st = server.app.lock();
    let u = st.users.get_mut(user_id).expect("user exists");
    if !u.has_role(role) {
        u.roles.push(role.into());
    }
}

pub fn revoke_role(server: &TestServer, user_id: &str, role: &str) {
    let mut st = server.app.lock();
    st.users
        .get_mut(user_id)
        .expect("user exists")
        .roles
        .retain(|r| r != role);
}

/// Makes the guest user_id an account in memory only, one that signs in
/// with a token it was never given, so a test guest can do what only
/// accounts may.
pub fn make_account(server: &TestServer, user_id: &str) {
    server
        .app
        .lock()
        .users
        .get_mut(user_id)
        .expect("user exists")
        .invited = true;
}

/// Lifts user_id's limit on push_register requests, for tests that make
/// more than a minute's.
pub fn unlimit_push_registers(server: &TestServer, user_id: &str) {
    server
        .app
        .lock()
        .users
        .get_mut(user_id)
        .expect("user exists")
        .push_registers = Some(crate::rate::Limiter::new(crate::rate::INF, 1));
}

pub const ADMIN_TOKEN: &str = "admin-token-for-tests-0123456789";

/// A passkey server whose admin token is ADMIN_TOKEN.
pub fn admin_test_server() -> TestServer {
    new_test_server(admin_config())
}

pub fn admin_config() -> Config {
    Config {
        web_authn: Some(test_web_authn()),
        admin_token: Some(sha256::sum256(ADMIN_TOKEN.as_bytes())),
        ..default_config()
    }
}

/// Signs c in with `token` through the token scheme and returns the reply,
/// skipping the notifications before it.
pub fn token_auth(c: &mut TestClient, token: &str) -> Object {
    let id = c.next_id("token");
    reply(c, "auth", &id, obj! {"scheme" => "token", "token" => token})
}

/// Connects with no origin and signs in as the admin user.
pub fn admin(server: &TestServer) -> TestClient {
    admin_on(server, "")
}

/// Connects from origin and signs in as the admin user.
pub fn admin_on(server: &TestServer, origin: &str) -> TestClient {
    let (mut c, _) = dial_origin(server, origin);
    let frame = token_auth(&mut c, ADMIN_TOKEN);
    assert_eq!(user_id_of(&passkey_result(&frame)), "admin", "{frame:?}");
    c.user_id = "admin".into();
    c.drain();
    c
}

/// Connects on the passkey origin and registers a new passkey account.
pub fn account(server: &TestServer) -> TestClient {
    let (mut c, _) = dial_origin(server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut c, &mut new_test_authenticator());
    c.user_id = user_id_of(&registered);
    c.drain();
    c
}

pub fn user_id_of(result: &Object) -> String {
    you_of(result)["user_id"].as_str().unwrap().to_owned()
}

/// Runs a command and returns the text of the one ~private notice before
/// its empty result; other notifications it causes are skipped.
pub fn private_reply(c: &mut TestClient, text: &str) -> String {
    let id = c.next_id("command");
    let (before, result) = c.request("command", &id, obj! {"body" => obj! {"text" => text}});
    let private = obj! {"user_id" => "~private", "name" => "System message to you"};
    let notices: Vec<Object> = before
        .iter()
        .filter(|frame| frame.get("method") == Some(&Json::from("message")))
        .map(|frame| notification_params(frame, "message"))
        .filter(|notice| notice.get("from") == Some(&Json::from(private.clone())))
        .collect();
    assert!(
        result.is_empty() && notices.len() == 1,
        "{text} result {result:?} after {before:?}"
    );
    notices[0]["body"].as_object().unwrap()["text"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// How the admin commands' notices name a user: `**name** (`user_id`)`.
pub fn who(server: &TestServer, user_id: &str) -> String {
    let name = server.app.lock().users[user_id].name.clone();
    format!("**{name}** (`{user_id}`)")
}

/// Runs a command that fails and returns its error, skipping the
/// notifications before it.
pub fn command_error(c: &mut TestClient, text: &str) -> (i64, String) {
    let id = c.next_id("command");
    let frame = reply(c, "command", &id, obj! {"body" => obj! {"text" => text}});
    let error = frame
        .get("error")
        .and_then(Json::as_object)
        .unwrap_or_else(|| panic!("{text}: {frame:?}"));
    (
        match error["code"] {
            Json::Number(code) => code as i64,
            ref other => panic!("code {other:?}"),
        },
        error["message"].as_str().unwrap().to_owned(),
    )
}

/// The token in a notice's first code block.
pub fn token_in(text: &str) -> String {
    text.split("```\n")
        .nth(1)
        .and_then(|block| block.split('\n').next())
        .unwrap_or_else(|| panic!("no token block in {text:?}"))
        .to_owned()
}
