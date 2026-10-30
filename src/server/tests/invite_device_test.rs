//! /invite-device: an account mints a bearer token under a device id that
//! signs it in on another device from any origin, and revokes it, as
//! apron-server-cloudflare's does (§3.2, §4.1).

use std::sync::Arc;

use rust_stdlib::time;

use super::helpers::*;
use super::persist_test::start_with_store;
use super::webauthn_test::*;
use crate::obj;
use crate::server::config::Config;
use crate::server::protocol::*;
use crate::server::push::PushRegistration;
use crate::store::{self, Store};

const OTHER_ORIGIN: &str = "http://127.0.0.1:5173";

/// Signs a new connection in as a passkey account, and returns it with its
/// user_id.
fn account(server: &TestServer) -> (TestClient, String) {
    let (mut c, _) = dial_origin(server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut c, &mut new_test_authenticator());
    let user_id = you_of(&registered)["user_id"].as_str().unwrap().to_owned();
    c.drain();
    (c, user_id)
}

/// Runs a command and returns the text of the one ~private notice before its
/// empty result.
fn only_notice(c: &mut TestClient, text: &str) -> String {
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

/// Runs /invite-device add name and returns the token its notice carries,
/// after checking the whole notice text.
fn invite_device(c: &mut TestClient, user_id: &str, name: &str, replaces: bool) -> String {
    invite_device_linked(c, user_id, name, replaces, "")
}

/// Runs /invite-device add without an id, checking that the token takes
/// name, and returns the token.
fn invite_unnamed_device(c: &mut TestClient, user_id: &str, name: &str) -> String {
    add_device(c, "/invite-device add", user_id, name, false, "")
}

/// invite_device on a server that writes link_server, already escaped, in
/// the notice's sign-in link; "" for none.
fn invite_device_linked(
    c: &mut TestClient,
    user_id: &str,
    name: &str,
    replaces: bool,
    link_server: &str,
) -> String {
    add_device(
        c,
        &format!("/invite-device add {name}"),
        user_id,
        name,
        replaces,
        link_server,
    )
}

fn add_device(
    c: &mut TestClient,
    command: &str,
    user_id: &str,
    name: &str,
    replaces: bool,
    link_server: &str,
) -> String {
    let text = only_notice(c, command);
    let token = text
        .split("```\n")
        .nth(1)
        .and_then(|block| block.strip_suffix('\n'))
        .unwrap_or_else(|| panic!("no token block in {text:?}"))
        .to_owned();
    let replaced = if replaces {
        ", and replaces its earlier token"
    } else {
        ""
    };
    let link = if link_server.is_empty() {
        String::new()
    } else {
        format!("Or open this link on **{name}**, which signs you in there with any Apron app: <https://link.apron.chat/#server={link_server}&token={token}>\n\n")
    };
    assert_eq!(
        text,
        format!(
            "This token signs in as you (`{user_id}`) on your device **{name}**{replaced}. It does not expire, and anyone who has it can sign in as you, so keep it secret. `/invite-device add {name}` again replaces it, and `/invite-device remove {name}` revokes it.\n\n```\n{token}\n```\n\n{link}To sign in, authenticate with the token scheme: `{{\"method\": \"auth\", \"params\": {{\"scheme\": \"token\", \"token\": \"{token}\"}}}}`"
        ),
        "invite-device notice"
    );
    assert!(
        token.starts_with("apron_device_") && token.len() == "apron_device_".len() + 43,
        "token {token:?}"
    );
    token
}

fn sign_in(c: &mut TestClient, token: &str) -> Object {
    passkey_call(c, "device", "token", "", obj! {"token" => token})
}

/// Connects on origin and signs in with a device token, returning the
/// connection and the auth response.
fn device(server: &TestServer, origin: &str, token: &str) -> (TestClient, Object) {
    let (mut c, _) = dial_origin(server, origin);
    let frame = sign_in(&mut c, token);
    c.drain();
    (c, frame)
}

fn invalid_token() -> Json {
    Json::from(obj! {
        "code" => CODE_DENIED,
        "message" => "This device token is not valid; get a new one with /invite-device add on a signed-in device",
    })
}

fn command_error(c: &mut TestClient, text: &str) -> Json {
    let id = c.next_id("command");
    let frame = c.call("command", &id, obj! {"body" => obj! {"text" => text}});
    frame
        .get("error")
        .cloned()
        .unwrap_or_else(|| panic!("{text}: {frame:?}"))
}

#[test]
fn test_invite_device_signs_in_from_any_origin() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server);
    let mut guest = dial_test_client(&server);
    ada.drain();

    let token = invite_device(&mut ada, &ada_id, "phone", false);
    // A command is never logged or broadcast.
    ada.expect_quiet();
    guest.expect_quiet();

    for origin in [TEST_PASSKEY_ORIGIN, OTHER_ORIGIN, ""] {
        let (_, frame) = device(&server, origin, &token);
        let result = passkey_result(&frame);
        assert_eq!(
            (result.len(), you_of(&result)["user_id"].clone()),
            (1, Json::from(ada_id.as_str())),
            "device from origin {origin:?}: no session token, signed in as ada: {result:?}"
        );
    }
    let (_, frame) = device(&server, OTHER_ORIGIN, "apron_device_not-a-token");
    assert_eq!(frame.get("error"), Some(&invalid_token()), "unknown token");
}

#[test]
fn test_invite_device_links_the_public_url() {
    let server = new_test_server(Config {
        web_authn: Some(test_web_authn()),
        public_url: "https://chat.example:8443/apron+chat/".into(),
        ..default_config()
    });
    let (mut ada, ada_id) = account(&server);
    let token = invite_device_linked(
        &mut ada,
        &ada_id,
        "phone",
        false,
        "wss://chat.example:8443/apron%2Bchat/ws",
    );
    let (_, frame) = device(&server, OTHER_ORIGIN, &token);
    assert_eq!(
        you_of(&passkey_result(&frame))["user_id"],
        Json::from(ada_id.as_str()),
        "the linked token signs in"
    );
}

#[test]
fn test_invite_device_has_no_link_without_a_public_url() {
    let server = passkey_test_server();
    let (mut ada, _) = account(&server);
    let text = only_notice(&mut ada, "/invite-device add phone");
    assert!(!text.contains("link.apron.chat"), "notice: {text:?}");
}

/// Expected values are apron-server-cloudflare's `apronLink(server, {token})`
/// run under Node.
#[test]
fn test_apron_link_escapes_as_cloudflare_does() {
    use crate::server::devices::apron_link;
    assert_eq!(
        apron_link(
            "wss://chat.example:8443/a b+!'()*&=#%é~._-/ws",
            "apron_device_Az09-_~.:/ ?"
        ),
        "https://link.apron.chat/#server=wss://chat.example:8443/a%20b%2B%21%27%28%29%2A%26%3D%23%25%C3%A9~._-/ws&token=apron_device_Az09-_~.:/%20%3F"
    );
}

#[test]
fn test_invite_device_denied_to_guests() {
    let server = passkey_test_server();
    let mut guest = dial_test_client(&server);
    assert_eq!(
        command_error(&mut guest, "/invite-device add phone"),
        Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "Sign in with a passkey to use /invite-device",
        }),
        "guest"
    );
    assert!(
        server.app.lock().devices.keys().next().is_none(),
        "a guest got a device token"
    );
}

#[test]
fn test_invite_device_ids_and_usage() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server);
    let usage = Json::from(obj! {
        "code" => CODE_INVALID_PARAMS, "message" => "Usage: /invite-device list|add|remove [<id>]",
    });
    let rule = Json::from(obj! {
        "code" => CODE_INVALID_PARAMS,
        "message" => "A device id is 1 to 32 letters, digits, _, . or -, starting with a letter or digit",
    });
    for text in [
        "/invite-device",
        "/invite-device phone",
        "/invite-device Add phone",
        "/invite-device add my phone",
        "/invite-device remove",
        "/invite-device remove my phone",
        "/invite-device list phone",
    ] {
        assert_eq!(command_error(&mut ada, text), usage, "{text}");
    }
    let long = "a".repeat(33);
    for name in [
        "-phone",
        "_phone",
        "pho/ne",
        "téléphone",
        "__proto__",
        long.as_str(),
    ] {
        for action in ["add", "remove"] {
            assert_eq!(
                command_error(&mut ada, &format!("/invite-device {action} {name}")),
                rule,
                "{action} {name:?}"
            );
        }
    }
    invite_device(&mut ada, &ada_id, &"a".repeat(32), false);
    invite_device(&mut ada, &ada_id, "Ada_s.i-Pad", false);
}

#[test]
fn test_invite_device_holds_five_ids() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server);
    let mut tokens: Vec<String> = ["phone", "tablet", "laptop"]
        .iter()
        .map(|name| invite_device(&mut ada, &ada_id, name, false))
        .collect();
    // Without an id, the first free device_<n>.
    tokens.push(invite_unnamed_device(&mut ada, &ada_id, "device_1"));
    tokens.push(invite_unnamed_device(&mut ada, &ada_id, "device_2"));
    let full = Json::from(obj! {
        "code" => CODE_DENIED,
        "message" => "You have 5 device tokens (`phone`, `tablet`, `laptop`, `device_1`, `device_2`); run /invite-device add with one of those ids to replace its token, or /invite-device remove to revoke one",
    });
    assert_eq!(
        command_error(&mut ada, "/invite-device add watch"),
        full,
        "sixth id"
    );
    assert_eq!(
        command_error(&mut ada, "/invite-device add"),
        full,
        "sixth, unnamed"
    );
    for token in &tokens {
        let (_, frame) = device(&server, OTHER_ORIGIN, token);
        assert!(frame.contains_key("result"), "kept token: {frame:?}");
    }
    // A held id is no sixth one.
    invite_device(&mut ada, &ada_id, "tablet", true);

    // Removing frees the id, and device_1 is taken again next.
    assert_eq!(
        only_notice(&mut ada, "/invite-device remove device_1"),
        "Revoked the device token for **device_1**.",
        "remove"
    );
    invite_unnamed_device(&mut ada, &ada_id, "device_1");
}

/// The urls of a user's push registrations, sorted.
fn push_urls(server: &TestServer, user_id: &str) -> Vec<String> {
    let mut urls: Vec<String> = server
        .app
        .lock()
        .pushes
        .values()
        .filter(|p| p.user_id == user_id)
        .map(|p| p.url.clone())
        .collect();
    urls.sort();
    urls
}

/// Registers https://fcm.googleapis.com/fcm/send/<name>, with name as the request id,
/// which a user may use once.
fn register_push(c: &mut TestClient, name: &str) {
    c.result(
        "push_register",
        name,
        obj! {"kind" => "relay", "url" => format!("https://fcm.googleapis.com/fcm/send/{name}")},
    );
}

/// Checks that c got the replacement's close error, and closed.
fn expect_replaced(c: &TestClient, what: &str) {
    expect_closed(c, "Device token replaced; sign in with the new one", what);
}

/// Checks that c got the close error with message, and closed.
fn expect_closed(c: &TestClient, message: &str, what: &str) {
    assert_eq!(
        c.read(),
        obj! {"error" => obj! {"code" => CODE_DENIED, "message" => message}},
        "{what}"
    );
    assert!(c.read_raw(time::SECOND).is_err(), "{what} stayed open");
}

#[test]
fn test_invite_device_same_name_revokes_old_token() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server);
    let old = invite_device(&mut ada, &ada_id, "phone", false);
    let tablet = invite_device(&mut ada, &ada_id, "tablet", false);
    let (mut phone, _) = device(&server, OTHER_ORIGIN, &old);
    let (mut other, _) = device(&server, "", &tablet);
    ada.drain();
    register_push(&mut ada, "ada");
    register_push(&mut phone, "phone");
    register_push(&mut other, "tablet");

    let current = invite_device(&mut ada, &ada_id, "phone", true);
    expect_replaced(&phone, "connection that signed in with the old token");
    ada.expect_quiet();
    other.expect_quiet();
    assert_eq!(
        push_urls(&server, &ada_id),
        [
            "https://fcm.googleapis.com/fcm/send/ada",
            "https://fcm.googleapis.com/fcm/send/tablet"
        ],
        "push registrations after a replacement"
    );
    let (_, frame) = device(&server, OTHER_ORIGIN, &old);
    assert_eq!(frame.get("error"), Some(&invalid_token()), "old token");

    // The asking connection stays open when it signed in with the token it
    // replaces, and counts as signed in with the new one, so the next
    // replacement closes it.
    let (mut phone, _) = device(&server, "", &current);
    invite_device(&mut phone, &ada_id, "phone", true);
    phone.expect_quiet();
    invite_device(&mut ada, &ada_id, "phone", true);
    expect_replaced(&phone, "the asking connection, at the next replacement");
    other.expect_quiet();
}

#[test]
fn test_invite_device_closes_a_device_that_got_a_session_token() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server);
    let token = invite_device(&mut ada, &ada_id, "phone", false);
    let (mut phone, _) = device(&server, TEST_PASSKEY_ORIGIN, &token);
    ada.drain();

    // Whoever holds a device token can add a passkey, which gives the
    // connection a session token.
    let options = passkey_result(&passkey_call(
        &mut phone,
        "register-start",
        "register",
        "begin",
        Object::new(),
    ));
    let credential = new_test_authenticator().registration(&options, TEST_PASSKEY_ORIGIN);
    let registered = passkey_result(&passkey_call(
        &mut phone,
        "register-end",
        "register",
        "finish",
        obj! {"credential" => credential},
    ));
    assert!(
        registered
            .get("token")
            .is_some_and(|t| t.as_str().is_some())
            && you_of(&registered)["user_id"] == Json::from(ada_id.as_str()),
        "register on a device connection: {registered:?}"
    );
    phone.drain();
    // The account's other connection is told of the new passkey.
    let told = ada.drain();
    assert!(
        format!("{told:?}").contains("A passkey was added to your account"),
        "ada: {told:?}"
    );

    invite_device(&mut ada, &ada_id, "phone", true);
    expect_replaced(&phone, "the device connection with a session token");
}

#[test]
fn test_invite_device_remove_revokes_a_token() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server);
    let phone_token = invite_device(&mut ada, &ada_id, "phone", false);
    let tablet_token = invite_device(&mut ada, &ada_id, "tablet", false);
    let (mut phone, _) = device(&server, OTHER_ORIGIN, &phone_token);
    let (mut tablet, _) = device(&server, "", &tablet_token);
    ada.drain();
    register_push(&mut ada, "ada");
    register_push(&mut phone, "phone");
    register_push(&mut tablet, "tablet");

    assert_eq!(
        command_error(&mut ada, "/invite-device remove laptop"),
        Json::from(obj! {
            "code" => CODE_INVALID_PARAMS,
            "message" => "You have no device token with the id laptop; yours are `phone`, `tablet`",
        }),
        "an id not held"
    );
    assert_eq!(
        only_notice(&mut ada, "/invite-device remove phone"),
        "Revoked the device token for **phone**.",
        "remove"
    );
    expect_closed(
        &phone,
        "Device token revoked",
        "connection that signed in with the removed token",
    );
    ada.expect_quiet();
    tablet.expect_quiet();
    assert_eq!(
        push_urls(&server, &ada_id),
        [
            "https://fcm.googleapis.com/fcm/send/ada",
            "https://fcm.googleapis.com/fcm/send/tablet"
        ],
        "push registrations after a removal"
    );
    let (_, frame) = device(&server, OTHER_ORIGIN, &phone_token);
    assert_eq!(frame.get("error"), Some(&invalid_token()), "removed token");

    // A device that removes its own token gets the notice and the result,
    // then is closed.
    assert_eq!(
        only_notice(&mut tablet, "/invite-device remove tablet"),
        "Revoked the device token for **tablet**.",
        "remove from the device itself"
    );
    expect_closed(
        &tablet,
        "Device token revoked",
        "the device that removed its own token",
    );
    ada.expect_quiet();
    assert!(
        server.app.lock().devices.keys().next().is_none(),
        "tokens left after removing both"
    );
    assert_eq!(
        command_error(&mut ada, "/invite-device remove tablet"),
        Json::from(obj! {
            "code" => CODE_INVALID_PARAMS,
            "message" => "You have no device tokens; get one with /invite-device add",
        }),
        "none held"
    );
}

/// The old token's connection, signed out at the replacement, runs nothing
/// more: a message it sends then is refused and reaches no one.
#[test]
fn test_replaced_device_token_connection_runs_nothing() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server);
    let old = invite_device(&mut ada, &ada_id, "phone", false);
    let (phone, _) = device(&server, OTHER_ORIGIN, &old);
    let conn = token_connection(&server, &ada_id, &old, true);
    let ada_conn = token_connection(&server, &ada_id, &old, false);
    ada.drain();

    let before = command_revoking(
        &server,
        &mut ada,
        &ada_conn,
        "/invite-device add phone",
        &conn,
        &ada_id,
    );
    assert_eq!(before.len(), 1, "only the notice: {before:?}");
    // The socket may be gone already; a frame that gets through is ignored.
    let _ = phone.ws.write(
        crate::ws::MessageType::Text,
        br#"{"method":"message","id":"late","params":{"body":{"text":"after the reissue"}}}"#,
        time::SECOND,
    );
    assert_eq!(
        phone.read(),
        obj! {"error" => obj! {
            "code" => CODE_DENIED,
            "message" => "Device token replaced; sign in with the new one",
        }},
        "the old token's connection gets only the close error"
    );
    assert!(
        phone.read_raw(time::SECOND).is_err(),
        "the old token's connection stayed open"
    );
    let mut watcher = dial_test_client(&server);
    assert_revoked_runs_nothing(&server, &conn, &mut watcher);
    let frames = ada.drain();
    assert!(
        frames
            .iter()
            .all(|f| f.get("method") != Some(&Json::from("message"))),
        "a message reached ada: {frames:?}"
    );
}

/// The UTC day today, as /invite-device list writes it.
fn today() -> String {
    time::now().utc().format("2006-01-02")
}

#[test]
fn test_invite_device_list() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server);
    assert_eq!(
        only_notice(&mut ada, "/invite-device list"),
        "You have no device tokens; get one with `/invite-device add`.",
        "none held"
    );
    let phone = invite_device(&mut ada, &ada_id, "phone", false);
    invite_device(&mut ada, &ada_id, "tablet", false);
    invite_unnamed_device(&mut ada, &ada_id, "device_1");
    device(&server, OTHER_ORIGIN, &phone);
    device(&server, OTHER_ORIGIN, &phone);
    ada.drain();
    let day = today();
    assert_eq!(
        only_notice(&mut ada, "/invite-device list"),
        format!("Your device tokens:\n- `phone`, added {day}, last used {day}\n- `tablet`, added {day}, never used\n- `device_1`, added {day}, never used"),
        "oldest first, with the days"
    );
    // A replacement is a new token, never used yet, at the end.
    invite_device(&mut ada, &ada_id, "phone", true);
    assert_eq!(
        only_notice(&mut ada, "/invite-device list"),
        format!("Your device tokens:\n- `tablet`, added {day}, never used\n- `device_1`, added {day}, never used\n- `phone`, added {day}, never used"),
        "after a replacement"
    );
}

#[test]
fn test_help_lists_invite_device_for_accounts() {
    let server = passkey_test_server();
    let (mut ada, _) = account(&server);
    let mut guest = dial_test_client(&server);
    ada.drain();
    let listed = "- `/invite-device list|add|remove [<id>]`: list, get or revoke tokens that sign in as you on another device";
    assert_eq!(
        only_notice(&mut ada, "/help"),
        format!(
            "- `/avatar`: with one image attached: set your avatar\n- `/help`: list the commands you can use here\n- `/invite-bot`: get a token that signs in as your bot, named after you; again, it replaces the token and renames the bot\n{listed}\n- `/passkeys [remove <n>]`: list your account's passkeys, or remove one of them"
        ),
        "account's help"
    );
    assert_eq!(
        only_notice(&mut guest, "/help"),
        "- `/help`: list the commands you can use here",
        "guest's help"
    );
}

#[test]
fn test_invite_device_tokens_survive_restart() {
    let dir = TempDir::new("apron-invite-device-");
    let path = format!("{dir}/aprond.db");
    let upload_dir = format!("{dir}/uploads");
    let open = || -> Arc<dyn Store> { Arc::new(store::SQLite::open(&path).unwrap()) };
    let mut server = start_with_store(open(), &upload_dir);
    let (mut ada, ada_id) = account(&server);
    let phone = invite_device(&mut ada, &ada_id, "phone", false);
    let tablet = invite_device(&mut ada, &ada_id, "tablet", false);
    let desk = invite_device(&mut ada, &ada_id, "desk", false);
    for name in ["laptop", "watch"] {
        invite_device(&mut ada, &ada_id, name, false);
    }
    only_notice(&mut ada, "/invite-device remove desk");
    invite_device(&mut ada, &ada_id, "tv", false);
    for (name, token) in [("phone", &phone), ("tablet", &tablet)] {
        let (mut c, _) = device(&server, "", token);
        register_push(&mut c, name);
    }
    // A registration stored before registrations recorded their device
    // token has none.
    server.app.lock().add_push_locked(PushRegistration {
        user_id: ada_id.clone(),
        url: "https://fcm.googleapis.com/fcm/send/untagged".into(),
        ..PushRegistration::default()
    });
    drop(ada);
    server.stop();

    let server = start_with_store(open(), &upload_dir);
    let (mut c, frame) = device(&server, OTHER_ORIGIN, &phone);
    assert_eq!(
        you_of(&passkey_result(&frame))["user_id"],
        Json::from(ada_id.as_str()),
        "device signed in after restart: {frame:?}"
    );
    assert_eq!(
        command_error(&mut c, "/invite-device add car"),
        Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "You have 5 device tokens (`phone`, `tablet`, `laptop`, `watch`, `tv`); run /invite-device add with one of those ids to replace its token, or /invite-device remove to revoke one",
        }),
        "ids restored oldest first, without the removed one"
    );
    let day = today();
    assert_eq!(
        only_notice(&mut c, "/invite-device list"),
        format!("Your device tokens:\n- `phone`, added {day}, last used {day}\n- `tablet`, added {day}, last used {day}\n- `laptop`, added {day}, never used\n- `watch`, added {day}, never used\n- `tv`, added {day}, never used"),
        "days restored"
    );
    let (_, frame) = device(&server, OTHER_ORIGIN, &desk);
    assert_eq!(
        frame.get("error"),
        Some(&invalid_token()),
        "removed token after restart"
    );
    let (mut c, _) = device(&server, OTHER_ORIGIN, &tablet);
    invite_device(&mut c, &ada_id, "phone", true);
    assert_eq!(
        push_urls(&server, &ada_id),
        [
            "https://fcm.googleapis.com/fcm/send/tablet",
            "https://fcm.googleapis.com/fcm/send/untagged"
        ],
        "push registrations after a restart and a replacement"
    );
}
