//! `/purge`, ported from apron-server-cloudflare's
//! test/admin.integration.test.ts and test/push.integration.test.ts, and
//! the check that a purge leaves nothing of the user behind.

use rust_stdlib::time::Duration;
use std::collections::BTreeSet;
use std::sync::Arc;

use rust_stdlib::time;

use super::admin_test::*;
use super::helpers::*;
use super::persist_test::start_with;
use super::push_test::{add_push, go_idle, relay_push};
use super::webauthn_test::*;
use crate::obj;
use crate::server::protocol::*;
use crate::server::push::{PushHosts, WakeScope};
use crate::server::rooms::ReadCursor;
use crate::server::status::MuteState;
use crate::server::Config;
use crate::store::{self, Store};

/// An admin server with pushes to any host that wait a minute, so a wake
/// is still waiting when a command runs.
pub(super) fn account_config() -> Config {
    Config {
        allow_insecure_push: true,
        push_hosts: PushHosts::Any,
        push_delay: Duration::from_secs(60),
        ..admin_config()
    }
}

/// A passkey account named `name` on the passkey origin, and its session
/// token.
pub(super) fn named_account(server: &TestServer, name: &str) -> (TestClient, String) {
    let (mut c, _) = dial_origin(server, TEST_PASSKEY_ORIGIN);
    let registered = register_passkey_named(&mut c, &mut new_test_authenticator(), Some(name));
    c.user_id = user_id_of(&registered);
    c.drain();
    (c, registered["token"].as_str().unwrap().to_owned())
}

/// What `entangle` made: the user's message ids, the thread they created,
/// their device tokens and their bot's token.
pub(super) struct Entangled {
    pub message: String,
    pub upload_message: String,
    pub thread: String,
    pub devices: Vec<String>,
    pub bot_token: String,
}

/// Gives c's user one of everything a user can hold: messages, one with an
/// upload, reactions given and received, a thread they created and another
/// user joined, a read cursor, an avatar, device tokens, a bot, an invite
/// token, an address, push registrations with a wake waiting for them and
/// a coalescing window, mutes, a chosen status, limits and accepted
/// requests. `other` shares the rooms and replies to them.
pub(super) fn entangle(
    server: &TestServer,
    c: &mut TestClient,
    other: &mut TestClient,
) -> Entangled {
    let user_id = c.user_id.clone();
    c.drain();
    other.drain();
    let (message, _) = save(c, "first", obj! {"body" => obj! {"text" => "mine"}});
    let posted = post_embeds(
        c,
        "file",
        obj! {"room_id" => "general", "body" => obj! {"embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
    );
    let upload_message = posted["message_id"].as_str().unwrap().to_owned();
    let write_url = posted["embeds"].as_list()[0].as_object().unwrap()["write_url"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        http_do("PUT", &write_url, Some(&test_png()), "image/png").0,
        201
    );
    other.drain();
    let (theirs, _) = save(other, "theirs", obj! {"body" => obj! {"text" => "hello"}});
    c.drain();
    react(c, "react-theirs", &theirs, &["👍"]);
    other.drain();
    react(other, "react-mine", &message, &["🎉"]);
    c.drain();
    let (thread, _) = save_room(
        c,
        "thread",
        obj! {"parent_room_id" => "general", "title" => "Theirs"},
    );
    other.drain();
    join_room(other, &thread);
    c.drain();
    // A move carries the message's reaction sets in one record, which then
    // lists the user beside another.
    let body = obj! {"text" => "move me"};
    let (moving, _) = save(other, "moving", obj! {"body" => body.clone()});
    c.drain();
    react(c, "react-moving", &moving, &["👀"]);
    other.drain();
    react(other, "react-moving-own", &moving, &["👀"]);
    c.drain();
    other.request(
        "message",
        "move",
        obj! {"message_id" => moving.as_str(), "room_id" => thread.as_str(), "body" => body},
    );
    c.drain();

    let avatar = reply_to(
        c,
        "command",
        "avatar",
        obj! {"body" => obj! {"text" => "/avatar", "embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
    );
    let write_url = avatar["result"].as_object().unwrap()["embeds"].as_list()[0]
        .as_object()
        .unwrap()["write_url"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        http_do("PUT", &write_url, Some(&test_png()), "image/png").0,
        201
    );
    c.drain();
    let devices = ["phone", "tablet"]
        .iter()
        .map(|name| token_in(&private_reply(c, &format!("/invite-device {name}"))))
        .collect();
    let bot_token = token_in(&private_reply(c, "/invite-bot"));

    for name in ["laptop", "watch"] {
        add_push(
            server,
            &user_id,
            crate::server::push::PushRegistration {
                push_id: format!("{name}-id"),
                ..relay_push(format!("https://push.example/{name}"), WakeScope::DEFAULT)
            },
        );
    }
    go_idle(c);
    other.drain();
    save(
        other,
        "reply",
        obj! {"body" => obj! {"text" => "a reply"}, "reply_to" => obj! {"message_id" => message.as_str()}},
    );
    c.drain();
    {
        let mut st = server.app.lock();
        assert!(
            st.waking_users().contains(&user_id),
            "no wake waits for {user_id}"
        );
        st.push_woken
            .insert((user_id.clone(), "general".into()), time::now());
        let (_, key) = crate::server::invites::new_token("apron_invite_");
        st.invites.insert(
            key,
            crate::server::invites::InviteToken {
                user: user_id.clone(),
                created: time::now(),
            },
        );
        st.touch_invite(key);
        st.emails
            .insert("entangled@example.com".into(), user_id.clone());
        st.email.proposals.insert(
            u64::MAX,
            crate::server::email::EmailProposal {
                email: "new@example.com".into(),
                account_id: user_id.clone(),
                add: true,
                code: "123456".into(),
                handle: String::new(),
                secret: String::new(),
                state: String::new(),
                expires: time::now().add(time::Duration::from_secs(600)),
                attempts: 0,
                name: String::new(),
                user_id: String::new(),
            },
        );
        let from = st.users[&user_id].from();
        let general = st.rooms.get_mut("general").unwrap();
        general.reads.insert(
            user_id.clone(),
            ReadCursor {
                from,
                message_id: message.clone(),
                id: 1,
            },
        );
        st.touch_room("general");
        let u = st.users.get_mut(&user_id).unwrap();
        u.email = "entangled@example.com".into();
        u.chosen = "dnd".into();
        u.mute = MuteState {
            forever: true,
            ..MuteState::default()
        };
        u.room_mutes.insert(
            "general".into(),
            MuteState {
                forever: true,
                ..MuteState::default()
            },
        );
        st.touch_user(&user_id);
        assert!(st.limits.users().contains(&user_id), "no limit rows");
        assert!(st.users[&user_id].dedup.iter().next().is_some(), "no dedup");
    }
    Entangled {
        message,
        upload_message,
        thread,
        devices,
        bot_token,
    }
}

/// Every place the server keeps `user_id`, ignoring case: each store entry
/// a store holding the state would have, as `<kind> <id>`, and each map
/// that lives in memory only. Text in `ignore`, such as a longer user_id
/// that contains this one, does not count.
pub(super) fn traces(server: &TestServer, user_id: &str, ignore: &[&str]) -> BTreeSet<String> {
    let needle = user_id.to_lowercase();
    let has = |text: &str| {
        let mut text = text.to_lowercase();
        for skip in ignore {
            text = text.replace(&skip.to_lowercase(), "");
        }
        text.contains(&needle)
    };
    let st = server.app.lock();
    let mut found = BTreeSet::new();
    for entry in st.dump_locked() {
        let value = String::from_utf8_lossy(entry.value.as_deref().unwrap_or_default());
        if has(&entry.id) || has(&value) {
            found.insert(format!("{} {}", entry.kind, entry.id));
        }
    }
    let mut memory = |place: &str, text: &str| {
        if has(text) {
            found.insert(format!("{place} {text}"));
        }
    };
    for id in st.users.keys() {
        memory("users", id);
    }
    for id in st.credentials.values() {
        memory("credentials", id);
    }
    for id in st.emails.values() {
        memory("emails", id);
    }
    for p in st.email.proposals.values() {
        memory("proposals", &p.account_id);
    }
    for (id, room) in st.push_woken.keys() {
        memory("push_woken", &format!("{id} {room}"));
    }
    for id in st.waking_users() {
        memory("wakes", &id);
    }
    for id in st.limits.users() {
        memory("limits", &id);
    }
    for conn in st.clients.values() {
        memory("connections", conn.user.as_deref().unwrap_or(""));
    }
    for m in st.messages.values() {
        memory("message owners", &m.owner);
    }
    for e in st.embeds.values() {
        memory("embeds", &format!("{:?}", e.purpose));
    }
    found
}

/// The entries of a store that hold `user_id`, ignoring case, as
/// `<kind> <id>`; text in `ignore` does not count.
pub(super) fn stored_traces(s: &dyn Store, user_id: &str, ignore: &[&str]) -> BTreeSet<String> {
    let needle = user_id.to_lowercase();
    let mut found = BTreeSet::new();
    s.load(&mut |entry| {
        let value = String::from_utf8_lossy(entry.value.as_deref().unwrap_or_default());
        let mut text = format!("{} {value}", entry.id).to_lowercase();
        for skip in ignore {
            text = text.replace(&skip.to_lowercase(), "");
        }
        if text.contains(&needle) {
            found.insert(format!("{} {}", entry.kind, entry.id));
        }
        Ok(())
    })
    .unwrap();
    found
}

/// A purge leaves nothing of the user or their bot but their user_ids,
/// which stay used, in memory and in the store.
#[test]
fn test_purge_leaves_nothing_behind() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (mut c, _) = named_account(&server, "Dave");
    let (mut other, _) = named_account(&server, "Erin");
    let made = entangle(&server, &mut c, &mut other);
    let user_id = c.user_id.clone();
    admin.drain();

    let text = private_reply(&mut admin, &format!("/purge @{user_id}"));
    assert_eq!(
        text,
        format!("Purged `{user_id}`: 2 messages, 2 reaction sets, 2 uploads.")
    );
    let lower = user_id.to_lowercase();
    assert_eq!(
        traces(&server, &user_id, &[]),
        BTreeSet::from([format!("used_id {lower}"), format!("used_id bot_{lower}")]),
    );
    let st = server.app.lock();
    for r in st.rooms.values() {
        let missing: Vec<_> = r
            .log
            .iter()
            .filter(|id| !st.records.contains_key(id))
            .collect();
        assert!(
            missing.is_empty(),
            "{} logs removed records {missing:?}",
            r.id
        );
    }
    let carried = st
        .records
        .values()
        .filter(|r| r.kind == crate::server::server::RecordKind::Reactions)
        .map(|r| r.value()["reactions"].as_list().len())
        .collect::<Vec<_>>();
    assert!(
        carried.contains(&1) && !carried.contains(&0),
        "reaction records {carried:?}"
    );
    assert!(
        st.users.contains_key(&other.user_id)
            && st.messages.values().any(|m| m.owner == other.user_id),
        "the purge took another user's content"
    );
    assert!(
        !st.messages.contains_key(&made.message) && !st.messages.contains_key(&made.upload_message),
        "the user's messages stayed"
    );
    assert_eq!(
        st.rooms[&made.thread].creator, "",
        "the thread kept its creator"
    );
    drop(st);
    for token in made.devices.iter().chain([&made.bot_token]) {
        let (mut again, _) = dial_raw(&server);
        let frame = token_auth(&mut again, token);
        assert_eq!(error_code(&frame), Some(CODE_DENIED), "{frame:?}");
    }
}

/// The purged user's connections close with a connection-level denied,
/// and nobody is told: no membership is logged, and no leave goes out.
#[test]
fn test_purge_closes_connections_silently() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (mut bob, _) = named_account(&server, "Bob");
    let (mut carol, _) = named_account(&server, "Carol");
    let bob_id = bob.user_id.clone();
    bob.drain();
    save(&mut bob, "post", obj! {"body" => obj! {"text" => "spam"}});
    carol.drain();
    admin.drain();
    let records = server.app.lock().records.len();

    private_reply(&mut admin, &format!("/purge {bob_id}"));
    let closing = bob.read();
    assert_eq!(
        closing.get("error"),
        Some(&Json::from(
            obj! {"code" => CODE_DENIED, "message" => "Removed by an admin"}
        )),
        "{closing:?}"
    );
    carol.expect_quiet();
    let st = server.app.lock();
    // Bob's message and his join of general go, and nothing is logged.
    assert_eq!(st.records.len(), records - 2);
}

/// /purge removes the threads it leaves empty, and retires the user_id so a
/// session for it never signs in again.
#[test]
fn test_purge_removes_empty_threads_and_retires_the_user_id() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (mut bob, bob_token) = named_account(&server, "Bob");
    let (mut carol, _) = named_account(&server, "Carol");
    let bob_id = bob.user_id.clone();
    bob.drain();
    carol.drain();
    let (alone, _) = save_room(
        &mut bob,
        "alone",
        obj! {"parent_room_id" => "general", "title" => "Alone"},
    );
    let (shared, _) = save_room(
        &mut bob,
        "shared",
        obj! {"parent_room_id" => "general", "title" => "Shared"},
    );
    carol.drain();
    join_room(&mut carol, &shared);
    admin.drain();

    private_reply(&mut admin, &format!("/purge {bob_id}"));
    {
        let st = server.app.lock();
        assert!(
            !st.rooms.contains_key(&alone),
            "the thread only Bob was in stayed"
        );
        assert!(
            st.rooms.contains_key(&shared),
            "the thread Carol is in went"
        );
        assert_eq!(st.rooms[&shared].creator, "", "the creator stayed");
    }

    let (code, message) = command_error(&mut admin, &format!("/invite-token {bob_id}"));
    assert_eq!(
        (code, message),
        (
            CODE_INVALID_PARAMS,
            format!("The user_id {bob_id} is taken")
        )
    );
    let (mut device, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let frame = token_auth(&mut device, &bob_token);
    assert_eq!(error_code(&frame), Some(CODE_DENIED), "{frame:?}");
}

/// /purge revokes the user's invite, device and bot tokens.
#[test]
fn test_purge_revokes_tokens() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let invite = token_in(&private_reply(&mut admin, "/invite-token invited"));
    let (mut c, _) = dial_raw(&server);
    passkey_result(&token_auth(&mut c, &invite));
    c.user_id = "invited".into();
    c.drain();
    let device = token_in(&private_reply(&mut c, "/invite-device phone"));
    let bot = token_in(&private_reply(&mut c, "/invite-bot"));
    admin.drain();

    private_reply(&mut admin, "/purge invited");
    for (token, message) in [
        (&invite, "This invite token is not valid; ask an admin for a new one"),
        (&device, "This device token is not valid; get a new one with /invite-device on a signed-in device"),
        (&bot, "Bot token is not valid; its owner can get a new one with /invite-bot"),
    ] {
        let (mut again, _) = dial_raw(&server);
        let frame = token_auth(&mut again, token);
        let error = frame["error"].as_object().unwrap_or_else(|| panic!("{frame:?}"));
        assert_eq!(error["message"], Json::from(message));
    }
}

/// Only admins purge; not themselves or the admin user, and not a user_id
/// nobody has.
#[test]
fn test_purge_refusals() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (mut dave, _) = named_account(&server, "Dave");
    let dave_id = dave.user_id.clone();
    assert_eq!(
        command_error(&mut dave, "/purge admin"),
        (CODE_DENIED, "Only an admin can use /purge".into())
    );
    private_reply(&mut admin, &format!("/admin {dave_id}"));
    dave.drain();
    for (text, want) in [
        (
            format!("/purge {dave_id}"),
            (CODE_DENIED, "You can't purge yourself".to_owned()),
        ),
        (
            "/purge admin".to_owned(),
            (CODE_DENIED, "The admin user can't be purged".to_owned()),
        ),
        (
            "/purge nobody_123".to_owned(),
            (
                CODE_INVALID_PARAMS,
                "No user has the user_id nobody_123".to_owned(),
            ),
        ),
        (
            "/purge".to_owned(),
            (CODE_INVALID_PARAMS, "Usage: /purge <user_id>".to_owned()),
        ),
        (
            "/purge a b".to_owned(),
            (CODE_INVALID_PARAMS, "Usage: /purge <user_id>".to_owned()),
        ),
    ] {
        assert_eq!(command_error(&mut dave, &text), want, "{text}");
    }
    let help = private_reply(&mut admin, "/help");
    assert!(
        help.contains("- `/purge <user_id>`: disconnect a user and delete their account, bot, and everything they posted or uploaded"),
        "{help}"
    );
    let long = "x".repeat(300);
    let (_, message) = command_error(&mut admin, &format!("/purge {long}"));
    assert_eq!(message.chars().count(), 200, "{message}");
}

/// A guest can be purged too, and its user_id is not issued again.
#[test]
fn test_purge_a_guest() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let mut guest = dial_test_client(&server);
    save(&mut guest, "post", obj! {"body" => obj! {"text" => "hi"}});
    admin.drain();
    let text = private_reply(&mut admin, &format!("/purge {}", guest.user_id));
    assert_eq!(
        text,
        format!(
            "Purged `{}`: 1 message, 0 reaction sets, 0 uploads.",
            guest.user_id
        )
    );
    assert!(server.app.lock().used_ids.contains(&guest.user_id));
}

/// A purge reaches the store: after a restart the user is gone and their
/// user_id still taken.
#[test]
fn test_purge_persists() {
    let dir = TempDir::new("apron-purge-");
    let path = format!("{dir}/aprond.db");
    let open = || -> Arc<dyn Store> { Arc::new(store::SQLite::open(&path).unwrap()) };
    let upload_dir = format!("{dir}/uploads");
    let configure = |config: &mut Config| {
        *config = Config {
            store: config.store.clone(),
            upload_dir: config.upload_dir.clone(),
            ..account_config()
        }
    };
    let user_id = {
        let mut server = start_with(open(), &upload_dir, configure);
        let mut admin = admin(&server);
        let (mut c, _) = named_account(&server, "Dave");
        let (mut other, _) = named_account(&server, "Erin");
        entangle(&server, &mut c, &mut other);
        admin.drain();
        private_reply(&mut admin, &format!("/purge {}", c.user_id));
        server.stop();
        c.user_id.clone()
    };
    let lower = user_id.to_lowercase();
    assert_eq!(
        stored_traces(&*open(), &user_id, &[]),
        BTreeSet::from([format!("used_id {lower}"), format!("used_id bot_{lower}")]),
        "the store keeps the purged user"
    );
    let server = start_with(open(), &upload_dir, configure);
    assert_eq!(
        traces(&server, &user_id, &[]),
        BTreeSet::from([format!("used_id {lower}"), format!("used_id bot_{lower}")]),
    );
}
