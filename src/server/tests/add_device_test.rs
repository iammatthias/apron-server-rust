//! /add-device, an extension Go lacks (docs/DEVIATIONS.md): an account
//! issues another bearer token, bound to the issuing origin, for a native
//! client to resume with (§3.2, §4.10).

use std::sync::Arc;

use rust_stdlib_crypto::sha256;

use super::helpers::*;
use super::persist_test::{start_with, start_with_store};
use super::webauthn_test::*;
use crate::obj;
use crate::server::protocol::*;
use crate::store::{self, Store};

const OTHER_ORIGIN: &str = "http://127.0.0.1:5173";

/// Signs a new connection on origin in as a passkey account, and returns it
/// with its user_id.
fn account(server: &TestServer) -> (TestClient, String) {
    let (mut c, _) = dial_origin(server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut c, &mut new_test_authenticator());
    let user_id = you_of(&registered)["user_id"].as_str().unwrap().to_owned();
    c.drain();
    (c, user_id)
}

/// Runs a command and returns the text of the one ~private notice before its
/// empty result.
fn private_reply(c: &mut TestClient, text: &str) -> String {
    let id = c.next_id("command");
    let (before, result) = c.request("command", &id, obj! {"body" => obj! {"text" => text}});
    assert!(
        result.is_empty() && before.len() == 1,
        "{text} result {result:?} after {before:?}"
    );
    let notice = notification_params(&before[0], "message");
    let body = notice["body"].as_object().unwrap();
    assert!(
        !notice.contains_key("message_id")
            && !notice.contains_key("log_id")
            && notice.get("room_id") == Some(&Json::from("general"))
            && body.get("format") == Some(&Json::from("markdown"))
            && notice.get("from")
                == Some(&Json::from(
                    obj! {"user_id" => "~private", "name" => "System message to you"}
                )),
        "{text} notice: {notice:?}"
    );
    body["text"].as_str().unwrap().to_owned()
}

/// Runs /add-device with args and returns the token its notice carries,
/// after checking the whole notice text, which names the device as shown.
fn add_device(c: &mut TestClient, user_id: &str, args: &str, shown: &str) -> String {
    let line = format!("/add-device {args}");
    let text = private_reply(c, &line);
    let token = text
        .split("```\n")
        .nth(1)
        .and_then(|block| block.strip_suffix('\n'))
        .unwrap_or_else(|| panic!("no token block in {text:?}"))
        .to_owned();
    assert_eq!(
        text,
        format!(
            "Sign in on {shown} as @{user_id} with this token. Keep it private: it opens your account until it goes 30 days unused.\n\n```\n{token}\n```\n\nIt works only from this origin, which the app sends:\n\n```\n{TEST_PASSKEY_ORIGIN}\n```"
        ),
        "add-device notice"
    );
    assert_eq!(token.len(), 43, "token {token:?}");
    token
}

fn resume(c: &mut TestClient, token: &str) -> Object {
    passkey_call(c, "resume", "token", "", obj! {"token" => token})
}

fn user_sessions(server: &TestServer, user_id: &str) -> usize {
    let st = server.app.lock();
    st.sessions
        .keys()
        .filter(|key| st.sessions.get(key).unwrap().user == user_id)
        .count()
}

#[test]
fn test_add_device() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server);
    let mut guest = dial_test_client(&server);
    ada.drain();

    let token = add_device(&mut ada, &ada_id, "Ada's  iPhone\u{7}", "“Ada's iPhone”");
    {
        let st = server.app.lock();
        let session = st.sessions.get(&sha256::sum256(token.as_bytes())).unwrap();
        assert_eq!(
            (session.user.as_str(), session.origin.as_str()),
            (ada_id.as_str(), TEST_PASSKEY_ORIGIN),
            "device session"
        );
    }
    assert_eq!(
        user_sessions(&server, &ada_id),
        2,
        "the passkey's and the device's"
    );
    add_device(&mut ada, &ada_id, "", "a new device");
    assert_eq!(user_sessions(&server, &ada_id), 3, "a session per device");
    // A command is never logged or broadcast.
    ada.expect_quiet();
    guest.expect_quiet();

    let (mut device, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let resumed = passkey_result(&resume(&mut device, &token));
    assert_eq!(
        (
            you_of(&resumed)["user_id"].clone(),
            resumed["token"].clone()
        ),
        (Json::from(ada_id.as_str()), Json::from(token.as_str())),
        "device resumed: {resumed:?}"
    );

    let (mut elsewhere, _) = dial_origin(&server, OTHER_ORIGIN);
    let frame = resume(&mut elsewhere, &token);
    assert_eq!(
        frame.get("error"),
        Some(&Json::from(
            obj! {"code" => CODE_DENIED, "message" => "Session expired; sign in again"}
        )),
        "token from another origin: {frame:?}"
    );

    let frame = guest.call(
        "command",
        "guest",
        obj! {"body" => obj! {"text" => "/add-device phone"}},
    );
    assert_eq!(
        frame.get("error"),
        Some(&Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "Sign in with a passkey or email before adding a device",
        })),
        "guest: {frame:?}"
    );
    assert_eq!(
        user_sessions(&server, &guest.user_id),
        0,
        "a guest got a session"
    );
}

#[test]
fn test_help_lists_add_device_for_accounts() {
    let server = passkey_test_server();
    let (mut ada, _) = account(&server);
    let mut guest = dial_test_client(&server);
    ada.drain();
    let listed =
        "- `/add-device [label]`: get a sign-in token for another device, such as the iOS app";
    assert_eq!(
        private_reply(&mut ada, "/help"),
        format!(
            "- `/help`: list the commands you can use here\n- `/avatar`: with one image attached: set your avatar\n{listed}"
        ),
        "account's help"
    );
    assert_eq!(
        private_reply(&mut guest, "/help"),
        "- `/help`: list the commands you can use here\n- `/avatar`: with one image attached: set your avatar",
        "guest's help"
    );
}

/// /add-device has a limiter of its own, five tokens at once and one more
/// every 12 minutes, whatever messages_per_minute allows.
#[test]
fn test_add_device_rate_limit() {
    let dir = TempDir::new("apron-add-device-");
    let server = start_with(
        Arc::new(store::Memory::new()),
        &format!("{dir}/uploads"),
        |config| config.messages_per_minute = 1,
    );
    let (mut ada, ada_id) = account(&server);
    for device in ["one", "two", "three", "four", "five"] {
        add_device(&mut ada, &ada_id, device, &format!("“{device}”"));
    }
    let frame = ada.call(
        "command",
        "sixth",
        obj! {"body" => obj! {"text" => "/add-device six"}},
    );
    assert_eq!(
        frame.get("error"),
        Some(&Json::from(obj! {
            "code" => CODE_RETRY_AFTER,
            "message" => "Too many devices added; try again later",
            "data" => obj! {"retry_after" => 720i64},
        })),
        "sixth token within the hour: {frame:?}"
    );
    assert_eq!(
        user_sessions(&server, &ada_id),
        6,
        "the limited command minted a token"
    );
}

#[test]
fn test_add_device_token_survives_restart() {
    let dir = TempDir::new("apron-add-device-");
    let path = format!("{dir}/aprond.db");
    let upload_dir = format!("{dir}/uploads");
    let open = || -> Arc<dyn Store> { Arc::new(store::SQLite::open(&path).unwrap()) };
    let mut server = start_with_store(open(), &upload_dir);
    let (mut ada, ada_id) = account(&server);
    let token = add_device(&mut ada, &ada_id, "iPad", "“iPad”");
    drop(ada);
    server.stop();

    let server = start_with_store(open(), &upload_dir);
    let (mut device, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let resumed = passkey_result(&resume(&mut device, &token));
    assert_eq!(
        you_of(&resumed)["user_id"],
        Json::from(ada_id.as_str()),
        "device resumed after restart: {resumed:?}"
    );
}
