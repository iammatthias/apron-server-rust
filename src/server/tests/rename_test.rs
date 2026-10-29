//! `/rename`, ported from apron-server-cloudflare's
//! test/admin.integration.test.ts and test/push.integration.test.ts, and
//! the check that a rename moves everything kept under the old user_id.

use std::collections::BTreeSet;
use std::io::Write;
use std::sync::Arc;

use super::admin_test::*;
use super::helpers::*;
use super::persist_test::start_with;
use super::purge_test::{account_config, entangle, named_account, stored_traces, traces};
use super::reference_test::{put_from_pipe, writer_status};
use super::webauthn_test::*;
use crate::obj;
use crate::server::protocol::*;
use crate::server::push::push_key;
use crate::server::Config;
use crate::store::{self, Store};

/// What `traces` finds of a user_id that has a bot, the bot's own user_id
/// aside, split into the bot's user and token entries, which name it as the
/// owner, and the rest. The bot keeps its user_id and token through a
/// rename, as on Cloudflare, so its entries keep their places.
fn held(server: &TestServer, from: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let bot = format!("bot_{from}");
    traces(server, from, &[&bot])
        .into_iter()
        .partition(|place| place.starts_with("bot ") || *place == format!("user {bot}"))
}

/// What `traces` should find under `to` after `from` was renamed to it,
/// given what it found under `from` before: the same places, under the new
/// user_id, but the sessions, which a rename deletes.
fn moved(before: &BTreeSet<String>, from: &str, to: &str) -> BTreeSet<String> {
    before
        .iter()
        .filter(|place| !place.starts_with("session "))
        .map(|place| {
            place
                .replace(from, to)
                .replace(&from.to_lowercase(), &to.to_lowercase())
        })
        .collect()
}

/// A rename moves every place that held the user to the new user_id and
/// leaves the old one only in used_ids; the bot keeps its user_id.
#[test]
fn test_rename_moves_everything() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (mut c, _) = named_account(&server, "Dave");
    let (mut other, _) = named_account(&server, "Erin");
    let made = entangle(&server, &mut c, &mut other);
    let from = c.user_id.clone();
    let bot = format!("bot_{from}");
    let (bot_entries, before) = held(&server, &from);
    assert_eq!(bot_entries.len(), 2, "the bot's entries: {bot_entries:?}");
    assert!(
        before.len() > 20,
        "the user is held in few places: {before:?}"
    );
    admin.drain();

    let to = "david_moved";
    let text = private_reply(&mut admin, &format!("/rename @{from} @{to}"));
    assert_eq!(text, format!("Renamed `{from}` to `{to}`."));
    let (left_bot, left) = held(&server, &from);
    assert!(
        left_bot.is_empty(),
        "the bot still names {from}: {left_bot:?}"
    );
    assert_eq!(
        left,
        BTreeSet::from([format!("used_id {}", from.to_lowercase())]),
    );
    let mut want = moved(&before, &from, to);
    want.extend(bot_entries);
    assert_eq!(traces(&server, to, &[]), want);

    let st = server.app.lock();
    assert_eq!(st.messages[&made.message].owner, to);
    assert_eq!(st.rooms[&made.thread].creator, to);
    assert!(st.users.contains_key(&bot), "the bot was renamed");
    drop(st);
    let (mut again, _) = dial_raw(&server);
    assert_eq!(
        user_id_of(&passkey_result(&token_auth(&mut again, &made.bot_token))),
        bot,
        "the bot's token"
    );
    for token in &made.devices {
        let (mut device, _) = dial_raw(&server);
        assert_eq!(
            user_id_of(&passkey_result(&token_auth(&mut device, token))),
            to
        );
    }
}

/// /rename moves a registered user, their passkey, rooms and admin status
/// to a new user_id; their connections become the new user and those who
/// share a room learn of it (§3.3).
#[test]
fn test_rename_moves_a_user_and_announces_it() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (mut dave, mut authenticator) = {
        let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
        let mut a = new_test_authenticator();
        let registered = register_passkey_named(&mut c, &mut a, Some("Dave"));
        c.user_id = user_id_of(&registered);
        c.drain();
        (c, a)
    };
    let (mut erin, _) = named_account(&server, "Erin");
    let from = dave.user_id.clone();
    private_reply(&mut admin, &format!("/admin {from}"));
    dave.drain();
    erin.drain();
    let (earlier, _) = save(
        &mut dave,
        "before",
        obj! {"body" => obj! {"text" => "before the rename"}},
    );
    save(
        &mut dave,
        "edit-before",
        obj! {"message_id" => earlier.as_str(), "body" => obj! {"text" => "edited before"}},
    );
    erin.drain();
    admin.drain();

    let to = "david";
    let text = private_reply(&mut admin, &format!("/rename @{from} @{to}"));
    assert_eq!(text, format!("Renamed `{from}` to `{to}`."));
    let you = notification_params(&dave.read(), "user");
    assert_eq!(
        you,
        obj! {"you" => obj! {
            "user_id" => to, "name" => "Dave", "roles" => strings(&["admin"]), "status" => "online",
            "ext" => obj! {"permissions" => obj! {"add_members" => true, "move_any" => true}},
        }},
    );
    let change = loop {
        let frame = erin.read();
        if frame.get("method") == Some(&Json::from("user")) {
            break notification_params(&frame, "user");
        }
    };
    assert_eq!(
        change,
        obj! {
            "new" => obj! {"user_id" => to, "name" => "Dave", "roles" => strings(&["admin"]), "status" => "online"},
            "old" => obj! {"user_id" => from.as_str(), "name" => "Dave"},
        },
    );
    dave.drain();
    dave.user_id = to.into();
    save(
        &mut dave,
        "post",
        obj! {"body" => obj! {"text" => "renamed"}},
    );
    // The earlier message was rewritten to the new id, so it is still theirs.
    save(
        &mut dave,
        "edit",
        obj! {"message_id" => earlier.as_str(), "body" => obj! {"text" => "edited after"}},
    );
    // Still an admin.
    private_reply(&mut dave, "/role admin");

    {
        let st = server.app.lock();
        assert!(st.users[to].joined.contains("general"));
        assert!(st.credentials.values().all(|id| id != &from));
        assert!(!st.users.contains_key(&from));
        assert!(
            st.used_ids.contains(&from.to_lowercase()),
            "the old user_id is free"
        );
        let froms: BTreeSet<String> = st.messages[&earlier]
            .records
            .iter()
            .map(|id| {
                st.records[id].value()["from"].as_object().unwrap()["user_id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(st.messages[&earlier].records.len(), 3);
        assert_eq!(froms, BTreeSet::from([to.to_owned()]));
    }

    // The passkey signs in as the new user_id.
    let (mut other, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let options = passkey_result(&passkey_call(
        &mut other,
        "begin",
        "login",
        "begin",
        Object::new(),
    ));
    let credential = authenticator.assertion(&options, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    let logged_in = passkey_result(&passkey_call(
        &mut other,
        "finish",
        "login",
        "finish",
        obj! {"credential" => credential},
    ));
    assert_eq!(user_id_of(&logged_in), to);
}

/// The refusals: a taken, guest's, bot's or malformed new user_id, the
/// admin user either way, an unknown or guest user, a bot, and a non-admin.
#[test]
fn test_rename_refusals() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (mut dave, _) = named_account(&server, "Dave");
    let (erin, _) = named_account(&server, "Erin");
    let guest = dial_test_client(&server);
    let from = dave.user_id.clone();
    private_reply(&mut dave, "/invite-bot");
    admin.drain();
    let usage = (
        CODE_INVALID_PARAMS,
        "Usage: /rename <old_user_id> <new_user_id>".to_owned(),
    );
    let malformed = (
        CODE_INVALID_PARAMS,
        "A user_id is 1 to 64 letters, digits, _ or -, starting with a letter or digit, ending with a letter, digit or _, and not guest_ or bot_".to_owned(),
    );
    for (text, want) in [
        (
            format!("/rename {from} {}", erin.user_id),
            (
                CODE_INVALID_PARAMS,
                format!("The user_id {} is taken", erin.user_id),
            ),
        ),
        (
            format!("/rename {from} general"),
            (
                CODE_INVALID_PARAMS,
                "The user_id general is taken".to_owned(),
            ),
        ),
        (format!("/rename {from} guest_77"), malformed.clone()),
        (format!("/rename {from} bot_x"), malformed.clone()),
        (format!("/rename {from} no@pe"), malformed.clone()),
        (format!("/rename {from} nope-"), malformed.clone()),
        (
            format!("/rename {from} admin"),
            (CODE_INVALID_PARAMS, "The user_id admin is taken".to_owned()),
        ),
        (
            "/rename nobody_123 somebody_else".to_owned(),
            (
                CODE_INVALID_PARAMS,
                "No registered user has the user_id nobody_123".to_owned(),
            ),
        ),
        (
            format!("/rename {} somebody_else", guest.user_id),
            (
                CODE_INVALID_PARAMS,
                format!("No registered user has the user_id {}", guest.user_id),
            ),
        ),
        (
            format!("/rename bot_{from} somebody_else"),
            (CODE_DENIED, "A bot's user_id is fixed".to_owned()),
        ),
        (
            "/rename admin somebody_else".to_owned(),
            (CODE_DENIED, "The admin user's user_id is fixed".to_owned()),
        ),
        (format!("/rename {from}"), usage.clone()),
        (format!("/rename {from} a b"), usage.clone()),
    ] {
        assert_eq!(command_error(&mut admin, &text), want, "{text}");
    }
    assert_eq!(
        command_error(&mut dave, &format!("/rename {from} somebody_else")),
        (CODE_DENIED, "Only an admin can use /rename".to_owned())
    );
    let help = private_reply(&mut admin, "/help");
    assert!(
        help.contains(
            "- `/rename <old_user_id> <new_user_id>`: change a registered user's user_id"
        ),
        "{help}"
    );
    assert!(
        server.app.lock().users.contains_key(&from),
        "a refused rename moved the user"
    );
}

/// /invite-token makes a user whose token /rename moves and /purge revokes.
#[test]
fn test_rename_moves_the_invite_token() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let token = token_in(&private_reply(&mut admin, "/invite-token invited"));
    private_reply(&mut admin, "/rename invited renamed");
    let (mut second, _) = dial_raw(&server);
    assert_eq!(
        user_id_of(&passkey_result(&token_auth(&mut second, &token))),
        "renamed"
    );
    second.drain();
    private_reply(&mut admin, "/purge renamed");
    let (mut third, _) = dial_raw(&server);
    let frame = token_auth(&mut third, &token);
    assert_eq!(
        frame["error"].as_object().unwrap()["message"],
        Json::from("This invite token is not valid; ask an admin for a new one")
    );
}

/// The user's sessions are refused after a rename, sending the client back
/// to its passkey.
#[test]
fn test_rename_ends_sessions() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (dave, session) = named_account(&server, "Dave");
    private_reply(&mut admin, &format!("/rename {} david", dave.user_id));
    let (mut resumed, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let frame = token_auth(&mut resumed, &session);
    assert_eq!(
        frame["error"].as_object().unwrap()["message"],
        Json::from("Session expired; sign in again")
    );
}

/// A room's creator may remove anyone from it across /rename, until /purge.
#[test]
fn test_rename_keeps_the_creator() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (mut bob, _) = named_account(&server, "Bob");
    let (mut carol, _) = named_account(&server, "Carol");
    let (mut dan, _) = named_account(&server, "Dan");
    bob.drain();
    let (room, _) = save_room(
        &mut bob,
        "thread",
        obj! {"parent_room_id" => "general", "title" => "Bob's"},
    );
    for c in [&mut carol, &mut dan] {
        c.drain();
        join_room(c, &room);
    }
    admin.drain();
    private_reply(&mut admin, &format!("/rename {} robert", bob.user_id));
    bob.drain();
    let frame = reply(
        &mut bob,
        "room_leave",
        "remove-dan",
        obj! {"room_id" => room.as_str(), "user_id" => dan.user_id.as_str()},
    );
    assert_eq!(
        frame.get("result"),
        Some(&Json::from(Object::new())),
        "{frame:?}"
    );
    private_reply(&mut admin, "/purge robert");
    assert_eq!(server.app.lock().rooms[&room].creator, "");
}

/// Push registrations move with their push_id, and the room the user was
/// last woken for stays coalesced; mutes and the chosen status move too
/// (Cloudflare's push.integration.test.ts).
#[test]
fn test_rename_moves_pushes_and_mutes() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (mut c, _) = named_account(&server, "Eve");
    let (mut other, _) = named_account(&server, "Erin");
    entangle(&server, &mut c, &mut other);
    admin.drain();
    private_reply(&mut admin, &format!("/rename {} eva", c.user_id));
    let st = server.app.lock();
    let p = &st.pushes[&push_key("eva", "https://push.example/laptop")];
    assert_eq!(
        (p.user_id.as_str(), p.push_id.as_str()),
        ("eva", "laptop-id")
    );
    assert!(st
        .push_woken
        .contains_key(&("eva".to_owned(), "general".to_owned())));
    assert!(st.waking_users().contains(&"eva".to_owned()));
    let u = &st.users["eva"];
    assert!(u.mute.forever && u.room_mutes["general"].forever && u.chosen == "dnd");
}

/// A rename reaches the store: after a restart the old user_id is only
/// used, and the new one holds the user.
#[test]
fn test_rename_persists() {
    let dir = TempDir::new("apron-rename-");
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
    let (from, made) = {
        let mut server = start_with(open(), &upload_dir, configure);
        let mut admin = admin(&server);
        let (mut c, _) = named_account(&server, "Dave");
        let (mut other, _) = named_account(&server, "Erin");
        let made = entangle(&server, &mut c, &mut other);
        admin.drain();
        private_reply(&mut admin, &format!("/rename {} david", c.user_id));
        server.stop();
        (c.user_id.clone(), made)
    };
    let bot = format!("bot_{from}");
    assert_eq!(
        stored_traces(&*open(), &from, &[&bot]),
        BTreeSet::from([format!("used_id {}", from.to_lowercase())]),
        "the store keeps the old user_id"
    );
    let server = start_with(open(), &upload_dir, configure);
    assert_eq!(
        held(&server, &from),
        (
            BTreeSet::new(),
            BTreeSet::from([format!("used_id {}", from.to_lowercase())])
        ),
    );
    let st = server.app.lock();
    assert_eq!(
        st.users[&bot].owner.as_deref(),
        Some("david"),
        "the bot's owner"
    );
    assert!(
        st.bots.of_bot(&bot).is_some(),
        "the bot's token did not survive the restart"
    );
    assert_eq!(st.messages[&made.upload_message].owner, "david");
    assert!(st.users["david"].passkey.is_some() && st.users["david"].joined.contains(&made.thread));
    assert!(
        st.users["david"].dedup.get("first").is_some(),
        "the accepted requests did not move in the store"
    );
}

/// A request the renamed user retries after the rename replays its first
/// outcome, as their accepted request ids move with them.
#[test]
fn test_rename_keeps_accepted_requests() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (mut dave, _) = named_account(&server, "Dave");
    dave.drain();
    let (first, _) = save(&mut dave, "once", obj! {"body" => obj! {"text" => "once"}});
    let messages = server.app.lock().messages.len();
    admin.drain();
    private_reply(&mut admin, &format!("/rename {} david", dave.user_id));
    dave.drain();
    let frame = reply(
        &mut dave,
        "message",
        "once",
        obj! {"room_id" => "general", "body" => obj! {"text" => "once"}},
    );
    assert_eq!(
        frame["result"].as_object().unwrap()["message_id"],
        Json::from(first.as_str())
    );
    assert_eq!(
        server.app.lock().messages.len(),
        messages,
        "the retry posted again"
    );
}

/// Retention after a rename discards the rewritten records like any other,
/// by their log_ids, which the rewrite kept.
#[test]
fn test_rename_then_retention() {
    let server = new_test_server(Config {
        retention: Some(rust_stdlib::time::Duration::from_hours(1)),
        ..account_config()
    });
    let mut admin = admin(&server);
    let (mut dave, _) = named_account(&server, "Dave");
    dave.drain();
    let (old, _) = save(&mut dave, "old", obj! {"body" => obj! {"text" => "old"}});
    let (kept, _) = save(&mut dave, "kept", obj! {"body" => obj! {"text" => "kept"}});
    admin.drain();
    private_reply(&mut admin, &format!("/rename {} david", dave.user_id));
    let cutoff: i64 = kept.parse().unwrap();
    let mut st = server.app.lock();
    st.expire_history_locked(&rust_stdlib::time::unix_milli(cutoff + 3_600_000));
    assert!(!st.messages.contains_key(&old) && st.messages[&kept].owner == "david");
}

/// A user_id `--role` grants is free for /rename, and the renamed user gets
/// the granted roles, as one /invite-token makes does. `admin` is never
/// free, even before the admin user first signs in.
#[test]
fn test_rename_to_a_granted_user_id() {
    let mut config = account_config();
    config.roles = std::collections::BTreeMap::from([
        ("admin".into(), vec!["boss".into()]),
        ("mod".into(), vec!["moderator".into()]),
    ]);
    let server = new_test_server(config);
    let mut admin = admin(&server);
    let token = token_in(&private_reply(&mut admin, "/invite-token boss"));
    private_reply(&mut admin, "/invite-token someone");
    server.app.lock().users.remove("admin");
    server.app.lock().used_ids.remove("admin");
    let (mut boss, _) = dial_raw(&server);
    passkey_result(&token_auth(&mut boss, &token));
    boss.drain();
    assert_eq!(
        command_error(&mut boss, "/rename someone admin"),
        (CODE_INVALID_PARAMS, "The user_id admin is taken".to_owned())
    );
    private_reply(&mut boss, "/rename someone moderator");
    assert_eq!(
        server.app.lock().users["moderator"].roles,
        vec!["mod".to_owned()]
    );
}

/// A timed mute still ends after a rename: its timer is set again for the
/// new user_id.
#[test]
fn test_rename_keeps_timed_mutes_running() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (dave, _) = named_account(&server, "Dave");
    {
        let mut st = server.app.lock();
        let u = st.users.get_mut(&dave.user_id).unwrap();
        u.mute.until = rust_stdlib::time::now().add(rust_stdlib::time::Duration::from_millis(300));
        st.schedule_mute_locked(&dave.user_id);
    }
    private_reply(&mut admin, &format!("/rename {} david", dave.user_id));
    std::thread::sleep(std::time::Duration::from_millis(800));
    assert!(
        server.app.lock().users["david"].mute.until.is_zero(),
        "the mute did not end"
    );
}

/// The renamed user's bot stays theirs: purging them under the new user_id
/// takes the bot and its token too.
#[test]
fn test_rename_then_purge_takes_the_bot() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (mut dave, _) = named_account(&server, "Dave");
    let from = dave.user_id.clone();
    let bot = format!("bot_{from}");
    let bot_token = token_in(&private_reply(&mut dave, "/invite-bot"));
    admin.drain();

    private_reply(&mut admin, &format!("/rename {from} david"));
    private_reply(&mut admin, "/purge david");
    assert!(
        !server.app.lock().users.contains_key(&bot),
        "the bot outlived its purged owner"
    );
    let (mut again, _) = dial_raw(&server);
    let frame = token_auth(&mut again, &bot_token);
    assert_eq!(
        frame.get("error"),
        Some(&Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "Bot token is not valid; its owner can get a new one with /invite-bot",
        })),
        "the purged bot's token: {frame:?}"
    );
}

/// After a rename, /invite-bot finds the bot the user already has and
/// mints it a new token, instead of making a second bot.
#[test]
fn test_rename_then_invite_bot_rotates_the_bot() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (mut dave, _) = named_account(&server, "Dave");
    let from = dave.user_id.clone();
    let bot = format!("bot_{from}");
    let first = token_in(&private_reply(&mut dave, "/invite-bot"));
    admin.drain();

    private_reply(&mut admin, &format!("/rename {from} david"));
    dave.drain();
    let text = private_reply(&mut dave, "/invite-bot");
    assert!(text.contains(&format!("(`{bot}`)")), "{text}");
    let second = token_in(&text);
    let st = server.app.lock();
    assert!(!st.users.contains_key("bot_david"), "a second bot was made");
    assert_eq!(
        st.users[&bot].owner.as_deref(),
        Some("david"),
        "the bot's owner"
    );
    drop(st);
    let (mut old, _) = dial_raw(&server);
    assert!(
        token_auth(&mut old, &first).contains_key("error"),
        "the replaced token still signs in"
    );
    let (mut new, _) = dial_raw(&server);
    assert_eq!(
        user_id_of(&passkey_result(&token_auth(&mut new, &second))),
        bot
    );
    // The bot's owner, by owner and not by name, may still remove it.
    dave.drain();
    dave.request(
        "room_leave",
        "remove-bot",
        obj! {"room_id" => "general", "user_id" => bot.as_str()},
    );
}

/// An avatar whose upload is under way when its user is renamed becomes the
/// renamed user's.
#[test]
fn test_rename_during_an_avatar_upload() {
    let server = new_test_server(account_config());
    let mut admin = admin(&server);
    let (mut dave, _) = named_account(&server, "Dave");
    let from = dave.user_id.clone();
    let reply = reply_to(
        &mut dave,
        "command",
        "avatar",
        obj! {"body" => obj! {"text" => "/avatar", "embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
    );
    let write_url = reply["result"].as_object().unwrap()["embeds"].as_list()[0]
        .as_object()
        .unwrap()["write_url"]
        .as_str()
        .unwrap()
        .to_owned();
    let png = test_png();
    let (mut pipe, writer) = put_from_pipe(&write_url);
    let _ = pipe.write_all(&png[..8]);
    let token = write_url[write_url.rfind('/').unwrap() + 1..].to_owned();
    wait_for(|| !server.app.lock().writes.contains_key(&token));
    // The write has taken its purpose and is reading the body.
    std::thread::sleep(std::time::Duration::from_millis(100));
    admin.drain();
    private_reply(&mut admin, &format!("/rename {from} david"));
    let _ = pipe.write_all(&png[8..]);
    pipe.close();
    assert_eq!(writer_status(&writer), 201, "writer status");
    let st = server.app.lock();
    let david = &st.users["david"];
    assert!(
        !david.avatar.is_empty() && david.avatar_embed.is_some(),
        "the renamed user has no avatar"
    );
    assert!(
        st.embeds.contains_key(david.avatar_embed.as_ref().unwrap()),
        "the avatar's upload is gone"
    );
}
