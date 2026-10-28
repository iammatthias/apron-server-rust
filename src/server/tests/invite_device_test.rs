//! /invite-device, an extension Go lacks (docs/DEVIATIONS.md): an account
//! mints a named bearer token that signs it in on another device from any
//! origin, as apron-server-cloudflare's does (§3.2, §4.1).

use std::sync::Arc;

use rust_stdlib::time;

use super::helpers::*;
use super::persist_test::start_with_store;
use super::webauthn_test::*;
use crate::obj;
use crate::server::protocol::*;
use crate::server::{default_config, Config};
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

/// Runs /invite-device name and returns the token its notice carries, after
/// checking the whole notice text.
fn invite_device(c: &mut TestClient, user_id: &str, name: &str, replaces: bool) -> String {
    invite_device_linked(c, user_id, name, replaces, "")
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
    let text = private_reply(c, &format!("/invite-device {name}"));
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
            "This token signs in as you (`{user_id}`) on your device **{name}**{replaced}. It does not expire, and anyone who has it can sign in as you, so keep it secret. `/invite-device {name}` again replaces it.\n\n```\n{token}\n```\n\n{link}To sign in, authenticate with the token scheme: `{{\"method\": \"auth\", \"params\": {{\"scheme\": \"token\", \"token\": \"{token}\"}}}}`"
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
        "message" => "This device token is not valid; get a new one with /invite-device on a signed-in device",
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
    let text = private_reply(&mut ada, "/invite-device phone");
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
        command_error(&mut guest, "/invite-device phone"),
        Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "Sign in with a passkey or email to use /invite-device",
        }),
        "guest"
    );
    assert!(
        server.app.lock().devices.keys().next().is_none(),
        "a guest got a device token"
    );
}

#[test]
fn test_invite_device_names() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server);
    let usage = Json::from(obj! {
        "code" => CODE_INVALID_PARAMS, "message" => "Usage: /invite-device <name>",
    });
    let rule = Json::from(obj! {
        "code" => CODE_INVALID_PARAMS,
        "message" => "A device name is 1 to 32 letters, digits, _, . or -, starting with a letter or digit",
    });
    assert_eq!(command_error(&mut ada, "/invite-device"), usage, "no name");
    assert_eq!(
        command_error(&mut ada, "/invite-device my phone"),
        usage,
        "two words"
    );
    let long = "a".repeat(33);
    for name in ["-phone", "_phone", "pho/ne", "téléphone", long.as_str()] {
        assert_eq!(
            command_error(&mut ada, &format!("/invite-device {name}")),
            rule,
            "name {name:?}"
        );
    }
    invite_device(&mut ada, &ada_id, &"a".repeat(32), false);
    invite_device(&mut ada, &ada_id, "Ada_s.i-Pad", false);
}

#[test]
fn test_invite_device_holds_three_names() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server);
    let tokens: Vec<String> = ["phone", "tablet", "laptop"]
        .iter()
        .map(|name| invite_device(&mut ada, &ada_id, name, false))
        .collect();
    assert_eq!(
        command_error(&mut ada, "/invite-device watch"),
        Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "You have 3 device tokens (`phone`, `tablet`, `laptop`); run /invite-device with one of those names to replace its token",
        }),
        "fourth name"
    );
    for token in &tokens {
        let (_, frame) = device(&server, OTHER_ORIGIN, token);
        assert!(frame.contains_key("result"), "kept token: {frame:?}");
    }
    // A held name is no fourth one.
    invite_device(&mut ada, &ada_id, "tablet", true);
}

#[test]
fn test_invite_device_same_name_revokes_old_token() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server);
    ada.result(
        "push_register",
        "push",
        obj! {"kind" => "relay", "url" => "https://relay.example/ada"},
    );
    let old = invite_device(&mut ada, &ada_id, "phone", false);
    let tablet = invite_device(&mut ada, &ada_id, "tablet", false);
    let (phone, _) = device(&server, OTHER_ORIGIN, &old);
    let (mut asker, _) = device(&server, "", &old);
    let (mut other, _) = device(&server, "", &tablet);
    ada.drain();
    assert_eq!(server.app.lock().pushes.len(), 1, "ada's registration");

    let new = invite_device(&mut asker, &ada_id, "phone", true);
    let failure = phone.read();
    assert_eq!(
        failure,
        obj! {"error" => obj! {
            "code" => CODE_DENIED,
            "message" => "Device token replaced; sign in with the new one",
        }},
        "connection that signed in with the old token"
    );
    assert!(
        phone.read_raw(time::SECOND).is_err(),
        "the old token's connection stayed open"
    );
    // The asking connection, though it signed in with the old token, the
    // tablet's, and the passkey's stay open.
    for c in [&mut asker, &mut other, &mut ada] {
        c.drain();
    }
    assert!(
        server.app.lock().pushes.is_empty(),
        "the replaced device keeps getting pushes"
    );
    let (_, frame) = device(&server, OTHER_ORIGIN, &old);
    assert_eq!(frame.get("error"), Some(&invalid_token()), "old token");
    let (_, frame) = device(&server, OTHER_ORIGIN, &new);
    assert!(frame.contains_key("result"), "new token: {frame:?}");
}

#[test]
fn test_help_lists_invite_device_for_accounts() {
    let server = passkey_test_server();
    let (mut ada, _) = account(&server);
    let mut guest = dial_test_client(&server);
    ada.drain();
    let listed = "- `/invite-device <name>`: get a token that signs in as you on another device, named <name>; at most 3 names, and a name again replaces its token";
    assert_eq!(
        private_reply(&mut ada, "/help"),
        format!(
            "- `/help`: list the commands you can use here\n- `/avatar`: with one image attached: set your avatar\n{listed}\n- `/invite-bot`: get a token that signs in as your bot, named after you; again, it replaces the token and renames the bot"
        ),
        "account's help"
    );
    assert_eq!(
        private_reply(&mut guest, "/help"),
        "- `/help`: list the commands you can use here\n- `/avatar`: with one image attached: set your avatar",
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
    invite_device(&mut ada, &ada_id, "tablet", false);
    invite_device(&mut ada, &ada_id, "laptop", false);
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
        command_error(&mut c, "/invite-device watch"),
        Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "You have 3 device tokens (`phone`, `tablet`, `laptop`); run /invite-device with one of those names to replace its token",
        }),
        "names restored oldest first"
    );
}
