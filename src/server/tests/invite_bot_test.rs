//! /invite-bot, an extension Go lacks (docs/DEVIATIONS.md): an account gets
//! a bot of its own, named after it, and a bearer token that signs in as the
//! bot from any origin, as apron-server-cloudflare's does (§3.2, §4.1).

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

/// Signs a new connection in as a passkey account named name, and returns
/// it with its user_id.
fn account(server: &TestServer, name: &str) -> (TestClient, String) {
    let (mut c, _) = dial_origin(server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut c, &mut new_test_authenticator());
    let user_id = you_of(&registered)["user_id"].as_str().unwrap().to_owned();
    c.result("me", "name", obj! {"name" => name});
    c.drain();
    (c, user_id)
}

/// Runs a command and returns the frames before its ~private notice, and
/// the notice's text; the notice comes last, just before the empty result.
fn private_reply(c: &mut TestClient, text: &str) -> (Vec<Object>, String) {
    let id = c.next_id("command");
    let (mut before, result) = c.request("command", &id, obj! {"body" => obj! {"text" => text}});
    assert!(result.is_empty(), "{text} result {result:?}");
    let last = before.pop().unwrap_or_else(|| panic!("{text}: no notice"));
    let notice = notification_params(&last, "message");
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
    (before, body["text"].as_str().unwrap().to_owned())
}

/// Runs /invite-bot and returns the token its notice carries and the frames
/// before the notice, after checking the whole notice text.
fn invite_bot(c: &mut TestClient, bot_id: &str, name: &str, server: &str) -> (String, Vec<Object>) {
    let (before, text) = private_reply(c, "/invite-bot");
    let token = text
        .split("```\n")
        .nth(1)
        .and_then(|block| block.strip_suffix('\n'))
        .unwrap_or_else(|| panic!("no token block in {text:?}"))
        .to_owned();
    assert_eq!(
        text,
        format!(
            "This token signs in as your bot **{name}** (`{bot_id}`) and replaces any earlier one. Anyone who has it can post as the bot, so keep it secret.\n\n```\n{token}\n```\n\nIf you're using an LLM, you can give it these instructions:\n\n```\nRead https://github.com/shazow/apron/blob/main/PROTOCOL.md\nConnect to {server}\nAuth using token scheme with this token: \"{token}\"\n```"
        ),
        "invite-bot notice"
    );
    assert!(
        token.starts_with("apron_bot_") && token.len() == "apron_bot_".len() + 43,
        "token {token:?}"
    );
    (token, before)
}

const NO_URL: &str = "this server's WebSocket URL";

/// Connects on origin and signs in with a bot token, returning the
/// connection and the auth response.
fn bot(server: &TestServer, origin: &str, token: &str) -> (TestClient, Object) {
    let (mut c, _) = dial_origin(server, origin);
    let frame = passkey_call(&mut c, "bot", "token", "", obj! {"token" => token});
    c.drain();
    (c, frame)
}

fn invalid_token() -> Json {
    Json::from(obj! {
        "code" => CODE_DENIED,
        "message" => "Bot token is not valid; its owner can get a new one with /invite-bot",
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

/// The user a room_update memberships frame says joined general.
fn joined_general(frame: &Object) -> Json {
    let params = notification_params(frame, "room_update");
    let membership = params["memberships"].as_list()[0]
        .as_object()
        .unwrap()
        .clone();
    assert_eq!(
        membership["room_id"],
        Json::from("general"),
        "membership {membership:?}"
    );
    let member = membership["members"].as_list()[0]
        .as_object()
        .unwrap()
        .clone();
    assert_eq!(member["joined"], Json::from(true), "member {member:?}");
    member["user"].clone()
}

#[test]
fn test_invite_bot_creates_a_bot_in_general() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server, "Ada");
    let mut guest = dial_test_client(&server);
    ada.drain();
    let bot_id = format!("bot_{ada_id}");

    let (token, before) = invite_bot(&mut ada, &bot_id, "Bot of Ada", NO_URL);
    let want = Json::from(obj! {"user_id" => bot_id.as_str(), "name" => "Bot of Ada"});
    assert_eq!(before.len(), 1, "frames before the notice: {before:?}");
    assert_eq!(joined_general(&before[0]), want, "owner sees the join");
    let seen = guest.drain();
    assert_eq!(seen.len(), 1, "guest frames: {seen:?}");
    assert_eq!(joined_general(&seen[0]), want, "member sees the join");

    for origin in [TEST_PASSKEY_ORIGIN, OTHER_ORIGIN, ""] {
        let (_, frame) = bot(&server, origin, &token);
        let result = passkey_result(&frame);
        let you = you_of(&result);
        assert_eq!(
            (
                result.len(),
                you["user_id"].clone(),
                you["name"].clone(),
                you["roles"].clone()
            ),
            (
                1,
                Json::from(bot_id.as_str()),
                Json::from("Bot of Ada"),
                Json::from(vec![Json::from("bot")])
            ),
            "bot from origin {origin:?}: no session token, signed in as the bot: {result:?}"
        );
    }
    let (_, frame) = bot(&server, "", "apron_bot_not-a-token");
    assert_eq!(frame.get("error"), Some(&invalid_token()), "unknown token");
}

#[test]
fn test_invite_bot_names_the_public_url() {
    let server = new_test_server(Config {
        web_authn: Some(test_web_authn()),
        public_url: "https://chat.example:8443/apron/".into(),
        ..default_config()
    });
    let (mut ada, ada_id) = account(&server, "Ada");
    invite_bot(
        &mut ada,
        &format!("bot_{ada_id}"),
        "Bot of Ada",
        "wss://chat.example:8443/apron/ws",
    );
}

#[test]
fn test_invite_bot_again_revokes_old_token() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server, "Ada");
    let bot_id = format!("bot_{ada_id}");
    let (old, _) = invite_bot(&mut ada, &bot_id, "Bot of Ada", NO_URL);
    let (mut first, _) = bot(&server, "", &old);
    first.result(
        "push_register",
        "push",
        obj! {"kind" => "relay", "url" => "https://relay.example/bot"},
    );
    assert_eq!(server.app.lock().pushes.len(), 1, "the bot's registration");

    // The bot exists, so nothing joins and nothing is renamed.
    let (new, before) = invite_bot(&mut ada, &bot_id, "Bot of Ada", NO_URL);
    assert!(before.is_empty(), "frames before the notice: {before:?}");
    assert_eq!(
        first.read(),
        obj! {"error" => obj! {
            "code" => CODE_DENIED,
            "message" => "Bot token replaced; sign in with the new one",
        }},
        "connection that signed in with the old token"
    );
    assert!(
        first.read_raw(time::SECOND).is_err(),
        "the old token's connection stayed open"
    );
    ada.drain();
    assert!(
        server.app.lock().pushes.is_empty(),
        "the replaced bot keeps getting pushes"
    );
    assert_eq!(server.app.lock().bots.keys().count(), 1, "one token");
    let (_, frame) = bot(&server, OTHER_ORIGIN, &old);
    assert_eq!(frame.get("error"), Some(&invalid_token()), "old token");
    let (_, frame) = bot(&server, OTHER_ORIGIN, &new);
    assert!(frame.contains_key("result"), "new token: {frame:?}");
}

/// The old token's connection, signed out at the replacement, runs nothing
/// more: a message it sends then is refused and reaches no one.
#[test]
fn test_replaced_bot_token_connection_runs_nothing() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server, "Ada");
    let bot_id = format!("bot_{ada_id}");
    let (old, _) = invite_bot(&mut ada, &bot_id, "Bot of Ada", NO_URL);
    let (first, _) = bot(&server, "", &old);
    let conn = token_connection(&server, &bot_id, &old, true);
    let ada_conn = token_connection(&server, &ada_id, &old, false);
    ada.drain();

    let before = command_revoking(&server, &mut ada, &ada_conn, "/invite-bot", &conn, &bot_id);
    assert_eq!(before.len(), 1, "only the notice: {before:?}");
    // The socket may be gone already; a frame that gets through is ignored.
    let _ = first.ws.write(
        crate::ws::MessageType::Text,
        br#"{"method":"message","id":"late","params":{"body":{"text":"after the reissue"}}}"#,
        time::SECOND,
    );
    assert_eq!(
        first.read(),
        obj! {"error" => obj! {
            "code" => CODE_DENIED,
            "message" => "Bot token replaced; sign in with the new one",
        }},
        "the old token's connection gets only the close error"
    );
    assert!(
        first.read_raw(time::SECOND).is_err(),
        "the old token's connection stayed open"
    );
    assert_revoked_runs_nothing(&server, &conn, &mut ada);
}

#[test]
fn test_invite_bot_denied_to_guests_and_bots() {
    let server = passkey_test_server();
    let mut guest = dial_test_client(&server);
    let denied = |command: &str| {
        Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => format!("Sign in with a passkey or email to use {command}"),
        })
    };
    assert_eq!(
        command_error(&mut guest, "/invite-bot"),
        denied("/invite-bot"),
        "guest"
    );
    let (mut ada, ada_id) = account(&server, "Ada");
    let (token, _) = invite_bot(&mut ada, &format!("bot_{ada_id}"), "Bot of Ada", NO_URL);
    let (mut b, _) = bot(&server, "", &token);
    assert_eq!(
        command_error(&mut b, "/invite-bot"),
        denied("/invite-bot"),
        "bot"
    );
    assert_eq!(
        command_error(&mut b, "/invite-device phone"),
        denied("/invite-device"),
        "bot"
    );
    assert_eq!(
        command_error(&mut ada, "/invite-bot please"),
        Json::from(obj! {"code" => CODE_INVALID_PARAMS, "message" => "Usage: /invite-bot"}),
        "arguments"
    );
    let app = server.app.lock();
    assert_eq!(app.bots.keys().count(), 1, "only ada's bot has a token");
    assert!(
        app.devices.keys().next().is_none(),
        "a bot got a device token"
    );
}

#[test]
fn test_bot_cannot_add_a_passkey() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server, "Ada");
    let (token, _) = invite_bot(&mut ada, &format!("bot_{ada_id}"), "Bot of Ada", NO_URL);
    let (mut b, _) = bot(&server, TEST_PASSKEY_ORIGIN, &token);
    let frame = passkey_call(&mut b, "register", "register", "begin", Object::new());
    assert_eq!(
        frame.get("error"),
        Some(&Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "A bot signs in only with its token; it cannot add a passkey or an email address",
        })),
        "bot passkey registration"
    );
}

#[test]
fn test_bot_cannot_add_an_email_address() {
    let (server, _mailbox) = super::email_test::email_test_server(|config| {
        config.web_authn = Some(test_web_authn());
    });
    let (mut ada, ada_id) = account(&server, "Ada");
    let (token, _) = invite_bot(&mut ada, &format!("bot_{ada_id}"), "Bot of Ada", NO_URL);
    let (mut b, _) = bot(&server, "", &token);
    let frame = b.call(
        "auth",
        "email",
        obj! {"scheme" => "email", "email" => "bot@example.com"},
    );
    assert_eq!(
        frame.get("error"),
        Some(&Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "A bot signs in only with its token; it cannot add a passkey or an email address",
        })),
        "bot email proposal"
    );
}

#[test]
fn test_help_lists_invite_bot_for_accounts() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server, "Ada");
    let mut guest = dial_test_client(&server);
    ada.drain();
    let listed = "- `/invite-bot`: get a token that signs in as your bot, named after you; again, it replaces the token and renames the bot";
    let (_, help) = private_reply(&mut ada, "/help");
    assert!(help.contains(listed), "account's help: {help:?}");
    let (_, help) = private_reply(&mut guest, "/help");
    assert!(!help.contains("/invite-bot"), "guest's help: {help:?}");
    let (token, _) = invite_bot(&mut ada, &format!("bot_{ada_id}"), "Bot of Ada", NO_URL);
    let (mut b, _) = bot(&server, "", &token);
    let (_, help) = private_reply(&mut b, "/help");
    assert!(!help.contains("/invite-"), "bot's help: {help:?}");
}

#[test]
fn test_bot_keeps_its_name() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server, "Ada");
    let (token, _) = invite_bot(&mut ada, &format!("bot_{ada_id}"), "Bot of Ada", NO_URL);
    let (mut b, _) = bot(&server, "", &token);
    let frame = b.call("me", "rename", obj! {"name" => "Skynet"});
    assert_eq!(
        frame.get("error"),
        Some(&Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "A bot is named after its owner, who can rename it with /invite-bot",
        })),
        "bot rename"
    );
    assert_eq!(
        server.app.lock().users[&format!("bot_{ada_id}")].name,
        "Bot of Ada",
        "a denied rename changed the name"
    );
    // The name it has, as a bot client sends on every connection, is no
    // change; nor is one that normalizes to it.
    for (id, name) in [("same", "Bot of Ada"), ("spaced", "  Bot  of Ada ")] {
        let result = b.result("me", id, obj! {"name" => name});
        assert_eq!(
            you_of(&result)["name"],
            Json::from("Bot of Ada"),
            "me {name:?}"
        );
    }
    // Other fields still change.
    let result = b.result("me", "status", obj! {"status" => "dnd"});
    assert_eq!(you_of(&result)["status"], Json::from("dnd"));
}

#[test]
fn test_invite_bot_renames_after_the_owner() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server, "Ada");
    let bot_id = format!("bot_{ada_id}");
    invite_bot(&mut ada, &bot_id, "Bot of Ada", NO_URL);
    let mut guest = dial_test_client(&server);
    ada.drain();
    let user = |frames: &[Object]| -> Vec<Json> {
        frames
            .iter()
            .filter(|f| f.get("method") == Some(&Json::from("user")))
            .map(|f| Json::from(notification_params(f, "user")))
            .collect()
    };
    let renamed = |name: &str| {
        Json::from(obj! {"new" => obj! {
            "user_id" => bot_id.as_str(), "name" => name,
            "status" => "offline", "roles" => vec![Json::from("bot")],
        }})
    };

    // The second name is cut to the name limit.
    let long = "G".repeat(64);
    let capped = format!("Bot of {}", "G".repeat(57));
    let mut token = String::new();
    for (owner, name) in [("Grace", "Bot of Grace"), (long.as_str(), capped.as_str())] {
        let id = ada.next_id("me");
        ada.result("me", &id, obj! {"name" => owner});
        guest.drain();
        let before;
        (token, before) = invite_bot(&mut ada, &bot_id, name, NO_URL);
        assert_eq!(user(&before), vec![renamed(name)], "owner: {before:?}");
        assert_eq!(user(&guest.drain()), vec![renamed(name)], "member");
    }
    let (_, frame) = bot(&server, "", &token);
    assert_eq!(
        you_of(&passkey_result(&frame))["name"],
        Json::from(capped.as_str()),
        "renamed bot signs in"
    );
}

#[test]
fn test_bot_ids_are_reserved() {
    // A guest asking for a bot's user_id, in any case, gets a guest_<n>.
    let server = passkey_test_server();
    for (n, requested) in ["bot_ada", "Bot_ada", "BOT_ADA", "bOt_x"]
        .iter()
        .enumerate()
    {
        let (mut c, _) = dial_raw(&server);
        let result = c.result(
            "auth",
            "guest",
            obj! {"scheme" => "guest", "user_id" => *requested},
        );
        assert_eq!(
            you_of(&result)["user_id"],
            Json::from(format!("guest_{}", n + 1)),
            "guest requesting {requested:?}"
        );
    }
    // So does a new email account, with a user_<n>.
    let (server, mailbox) = super::email_test::email_test_server(|_| {});
    for (n, requested) in ["bot_ada", "Bot_Ada"].iter().enumerate() {
        let (mut c, _) = dial_raw(&server);
        let email = format!("ada{n}@example.com");
        super::email_test::propose(&mut c, &email);
        let code = mailbox.receive().code;
        let (_, result) = super::email_test::approve(&mut c, &code, obj! {"user_id" => *requested});
        assert_eq!(
            you_of(&result)["user_id"],
            Json::from(format!("user_{}", n + 1)),
            "email account requesting {requested:?}: {result:?}"
        );
    }
}

/// /invite-bot never reissues a user_id (§3.3): a bot_<owner> someone else
/// holds, or one ever assigned, ignoring case, means no bot.
#[test]
fn test_invite_bot_denied_when_its_id_is_taken() {
    let server = passkey_test_server();
    let (mut ada, ada_id) = account(&server, "Ada");
    let bot_id = format!("bot_{ada_id}");
    {
        // A user who held the id before the prefix was reserved.
        let mut st = server.app.lock();
        let squatter = st.new_user_locked(&bot_id, "Not a bot");
        st.users.insert(bot_id.clone(), squatter);
        st.used_ids.insert(bot_id.to_lowercase());
    }
    assert_eq!(
        command_error(&mut ada, "/invite-bot"),
        Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => format!("The user_id {bot_id} belongs to someone else, so you cannot have a bot"),
        }),
        "held by another user"
    );
    // That user is gone, but its user_id was assigned.
    server.app.lock().users.remove(&bot_id);
    let taken = Json::from(obj! {
        "code" => CODE_DENIED,
        "message" => format!("The user_id {bot_id} was taken, so you cannot have a bot"),
    });
    assert_eq!(command_error(&mut ada, "/invite-bot"), taken, "used id");
    let st = server.app.lock();
    assert!(
        !st.users.contains_key(&bot_id) && st.bots.keys().next().is_none(),
        "a denied /invite-bot made a bot or a token"
    );
}

/// A user_id Config.roles names is never assigned to anyone but its holder,
/// so a role meant for a bot_ id cannot reach a bot: /invite-bot is denied.
#[test]
fn test_invite_bot_denied_for_a_role_holders_id() {
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let dir = TempDir::new("apron-bot-roles-");
    let upload_dir = format!("{dir}/uploads");
    let mut server = start_with_store(kept.clone(), &upload_dir);
    let (mut ada, ada_id) = account(&server, "Ada");
    let (_, laptop) = private_reply(&mut ada, "/invite-device laptop");
    let laptop = laptop.split("```\n").nth(1).unwrap().trim_end().to_owned();
    drop(ada);
    server.stop();

    let bot_id = format!("bot_{ada_id}");
    let roles_for = bot_id.to_uppercase();
    let server = super::persist_test::start_with(kept, &upload_dir, |config| {
        config.roles = std::collections::BTreeMap::from([("admin".into(), vec![roles_for])]);
    });
    let (mut ada, _) = dial_origin(&server, OTHER_ORIGIN);
    passkey_result(&passkey_call(
        &mut ada,
        "laptop",
        "token",
        "",
        obj! {"token" => laptop.as_str()},
    ));
    ada.drain();
    assert_eq!(
        command_error(&mut ada, "/invite-bot"),
        Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => format!("The user_id {bot_id} was taken, so you cannot have a bot"),
        }),
        "id granted a role"
    );
}

/// The token goes to the asking connection only: the owner's others get
/// the bot's join, and no notice.
#[test]
fn test_invite_bot_notice_only_to_the_asker() {
    let server = passkey_test_server();
    let (mut ada, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut ada, &mut new_test_authenticator());
    let ada_id = you_of(&registered)["user_id"].as_str().unwrap().to_owned();
    let (mut other, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    passkey_result(&passkey_call(
        &mut other,
        "resume",
        "token",
        "",
        obj! {"token" => registered["token"].clone()},
    ));
    ada.drain();
    other.drain();

    let bot_id = format!("bot_{ada_id}");
    let name = format!("Bot of {ada_id}");
    let (token, _) = invite_bot(&mut ada, &bot_id, &name, NO_URL);
    let frames = other.drain();
    assert_eq!(frames.len(), 1, "the owner's other connection: {frames:?}");
    assert_eq!(
        joined_general(&frames[0]),
        Json::from(obj! {"user_id" => bot_id.as_str(), "name" => name.as_str()}),
        "the join"
    );
    assert!(
        !format!("{frames:?}").contains(&token),
        "the token reached another connection"
    );
}

/// A bot entry whose bot is gone, or is no bot of that owner, is dropped at
/// start, from the store too.
#[test]
fn test_orphaned_bot_entries_dropped_at_restore() {
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let dir = TempDir::new("apron-bot-orphan-");
    let upload_dir = format!("{dir}/uploads");
    let mut server = start_with_store(kept.clone(), &upload_dir);
    let (mut ada, ada_id) = account(&server, "Ada");
    let bot_id = format!("bot_{ada_id}");
    let (token, _) = invite_bot(&mut ada, &bot_id, "Bot of Ada", NO_URL);
    drop(ada);
    server.stop();

    let orphan = "11".repeat(32);
    let stranger = "22".repeat(32);
    kept.apply(&[
        crate::store::Entry::put(
            "bot",
            &orphan,
            r#"{"bot":"bot_gone","owner":"gone","created":"2026-10-28T00:00:00Z"}"#,
        ),
        crate::store::Entry::put(
            "bot",
            &stranger,
            format!(
                r#"{{"bot":"{bot_id}","owner":"someone_else","created":"2026-10-28T00:00:00Z"}}"#
            ),
        ),
    ])
    .unwrap();
    let mut server = start_with_store(kept.clone(), &upload_dir);
    assert_eq!(
        server.app.lock().bots.keys().count(),
        1,
        "only the bot's own token is restored"
    );
    let (_, frame) = bot(&server, "", &token);
    assert!(frame.contains_key("result"), "the kept token: {frame:?}");
    server.stop();

    let mut ids = Vec::new();
    kept.load(&mut |e| {
        if e.kind == "bot" {
            ids.push(e.id);
        }
        Ok(())
    })
    .unwrap();
    assert!(
        ids.len() == 1 && !ids.contains(&orphan) && !ids.contains(&stranger),
        "bot entries in the store: {ids:?}"
    );
}

#[test]
fn test_invite_bot_tokens_survive_restart() {
    let dir = TempDir::new("apron-invite-bot-");
    let path = format!("{dir}/aprond.db");
    let upload_dir = format!("{dir}/uploads");
    let open = || -> Arc<dyn Store> { Arc::new(store::SQLite::open(&path).unwrap()) };
    let mut server = start_with_store(open(), &upload_dir);
    let (mut ada, ada_id) = account(&server, "Ada");
    let bot_id = format!("bot_{ada_id}");
    let (old, _) = invite_bot(&mut ada, &bot_id, "Bot of Ada", NO_URL);
    let (token, _) = invite_bot(&mut ada, &bot_id, "Bot of Ada", NO_URL);
    drop(ada);
    server.stop();

    let server = start_with_store(open(), &upload_dir);
    let (_, frame) = bot(&server, OTHER_ORIGIN, &old);
    assert_eq!(frame.get("error"), Some(&invalid_token()), "old token");
    let (mut b, frame) = bot(&server, OTHER_ORIGIN, &token);
    let you = you_of(&passkey_result(&frame));
    assert_eq!(
        (you["user_id"].clone(), you["roles"].clone()),
        (
            Json::from(bot_id.as_str()),
            Json::from(vec![Json::from("bot")])
        ),
        "bot signed in after restart: {frame:?}"
    );
    // The bot is still a member of general, and still no account.
    let app = server.app.lock();
    assert!(app.rooms["general"].members.contains(&bot_id), "membership");
    drop(app);
    assert_eq!(
        command_error(&mut b, "/invite-bot"),
        Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "Sign in with a passkey or email to use /invite-bot",
        }),
        "bot after restart"
    );
}
