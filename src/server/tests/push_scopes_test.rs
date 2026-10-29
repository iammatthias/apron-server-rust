//! Which wake scopes a message triggers, ported from push_test.go. The relay
//! fixture lives in push_test.rs.

use rust_stdlib::time::Duration;

use super::helpers::*;
use super::push_test::{
    add_push, go_idle, list, new_test_relay, paths, push_client, push_test_server, relay_push,
    server_message, strs,
};
use super::status_test::add_account;
use crate::obj;
use crate::server::protocol::*;
use crate::server::push::*;

/// Wake scopes (§4.9): mentions, replies, private, joined; [] wakes for
/// nothing, and without wake the default is mentions and replies.
#[test]
fn test_push_wake_scopes() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = push_client(&server);
    make_account(&server, &a.user_id);
    add_account(&server, "carol", &[&a]);
    // Only admins and mods wake for joined.
    grant_role(&server, "carol", "mod");
    for (name, wake) in [
        ("default", WakeScope::DEFAULT),
        ("joined", WakeScope::JOINED),
        ("private", WakeScope::PRIVATE),
        ("replies", WakeScope::REPLIES),
        ("mentions", WakeScope::MENTIONS),
        ("nothing", WakeScope::NONE),
    ] {
        add_push(
            &server,
            "carol",
            relay_push(format!("{}/{name}", relay.url), wake),
        );
    }
    let post = |a: &mut TestClient, params: Object| -> String {
        let id = a.next_id("post");
        save(a, &id, params).0
    };

    // A message in a joined room wakes only joined.
    post(&mut a, obj! {"body" => obj! {"text" => "chatter"}});
    assert_eq!(
        paths(&relay.pushes(&server, &mut a)),
        strs(&["/joined"]),
        "joined room message"
    );
    // A mention wakes mentions and the default, and joined in a joined room.
    post(
        &mut a,
        obj! {"body" => obj! {"text" => "@carol", "mentions" => list(&["carol"])}},
    );
    assert_eq!(
        paths(&relay.pushes(&server, &mut a)),
        strs(&["/default", "/joined", "/mentions"]),
        "mention"
    );
    // A reply to carol's message wakes replies and the default.
    let own = format_id(server_message(&server, "carol", "carol's"));
    a.notification("message");
    post(
        &mut a,
        obj! {"body" => obj! {"text" => "re"}, "reply_to" => obj! {"message_id" => own.as_str()}},
    );
    assert_eq!(
        paths(&relay.pushes(&server, &mut a)),
        strs(&["/default", "/joined", "/replies"]),
        "reply"
    );
    // A message in a private room carol joined wakes private and joined,
    // and so does one in a thread of it.
    let (secret, _) = save_room(
        &mut a,
        "secret",
        obj! {"title" => "Secret", "private" => true},
    );
    a.request(
        "room_join",
        "add-carol",
        obj! {"room_id" => secret.as_str(), "user_id" => "carol"},
    );
    post(
        &mut a,
        obj! {"room_id" => secret.as_str(), "body" => obj! {"text" => "psst"}},
    );
    assert_eq!(
        paths(&relay.pushes(&server, &mut a)),
        strs(&["/joined", "/private"]),
        "private room message"
    );
    let (thread, _) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => secret.as_str(), "private" => false},
    );
    a.request(
        "room_join",
        "add-carol-thread",
        obj! {"room_id" => thread.as_str(), "user_id" => "carol"},
    );
    post(
        &mut a,
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "in the thread"}},
    );
    assert_eq!(
        paths(&relay.pushes(&server, &mut a)),
        strs(&["/joined", "/private"]),
        "private thread message"
    );
    // A room carol has not joined wakes neither joined nor private.
    grant_role(&server, &a.user_id, "mod");
    let (open_room, _) = save_room(&mut a, "open", obj! {"title" => "Open"});
    post(
        &mut a,
        obj! {"room_id" => open_room.as_str(), "body" => obj! {"text" => "elsewhere"}},
    );
    assert!(
        relay.pushes(&server, &mut a).is_empty(),
        "unjoined room message woke"
    );
}

/// A wake list of more than 16 names is denied, and a name past 64
/// characters too_large, as on Cloudflare; at the bounds it registers.
#[test]
fn test_wake_names_past_the_bounds_are_refused() {
    let server = push_test_server();
    let mut a = push_client(&server);
    let endpoint = "http://127.0.0.1:1/p";
    let mut register = |id: &str, wake: Vec<String>| -> Json {
        let frame = a.call(
            "push_register",
            id,
            obj! {"kind" => "relay", "url" => endpoint, "wake" => wake},
        );
        frame.get("error").or(frame.get("result")).cloned().unwrap()
    };
    let mut many = vec!["ext:filler".to_owned(); 16];
    many[0] = "replies".into();
    assert_eq!(register("sixteen", many.clone()), Json::from(Object::new()));
    many.push("mentions".into());
    assert_eq!(
        register("seventeen", many),
        Json::from(obj! {"code" => CODE_DENIED, "message" => "wake lists at most 16 scope names"})
    );
    // 64 characters, each two bytes in UTF-8: JavaScript's length counts
    // them as 64.
    assert_eq!(
        register("long", vec!["é".repeat(64)]),
        Json::from(Object::new())
    );
    assert_eq!(
        register("longer", vec!["é".repeat(65), "private".into()]),
        Json::from(
            obj! {"code" => CODE_TOO_LARGE, "message" => "a wake scope name is at most 64 characters"}
        )
    );
    assert_eq!(
        server.app.lock().pushes[&push_key(&a.user_id, endpoint)].wake,
        WakeScope(0),
        "the last registration that took"
    );
}

/// private wakes the members of a private room for messages in its
/// threads, joined or not (§4.9).
#[test]
fn test_private_wakes_for_threads_of_joined_rooms() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = push_client(&server);
    make_account(&server, &a.user_id);
    add_account(&server, "carol", &[&a]);
    add_push(
        &server,
        "carol",
        relay_push(format!("{}/private", relay.url), WakeScope::PRIVATE),
    );
    add_account(&server, "dave", &[&a]);
    add_push(
        &server,
        "dave",
        relay_push(
            format!("{}/dave", relay.url),
            WakeScope::PRIVATE | WakeScope::JOINED,
        ),
    );
    let (secret, _) = save_room(
        &mut a,
        "secret",
        obj! {"title" => "Secret", "private" => true},
    );
    a.request(
        "room_join",
        "add-carol",
        obj! {"room_id" => secret.as_str(), "user_id" => "carol"},
    );
    let (thread, _) = save_room(
        &mut a,
        "thread",
        obj! {"parent_room_id" => secret.as_str(), "private" => false},
    );
    relay.pushes(&server, &mut a);
    save(
        &mut a,
        "post",
        obj! {"room_id" => thread.as_str(), "body" => obj! {"text" => "in a thread"}},
    );
    let got = relay.pushes(&server, &mut a);
    assert!(
        paths(&got) == strs(&["/private"]) && got[0].header("Urgency") == "high",
        "a message in a thread of a private room carol joined woke {:?}",
        paths(&got)
    );
    // A public room's thread wakes no one for private.
    let (public, _) = save_room(
        &mut a,
        "public-thread",
        obj! {"parent_room_id" => "general"},
    );
    save(
        &mut a,
        "post-public",
        obj! {"room_id" => public.as_str(), "body" => obj! {"text" => "public"}},
    );
    let got = relay.pushes(&server, &mut a);
    assert!(got.is_empty(), "a public thread woke {:?}", paths(&got));
}

/// A mention in a private room wakes a member who wakes for mentions alone,
/// and never someone outside it, mentioned or not (§4.9, §4.2.4).
#[test]
fn test_mentions_wake_in_private_rooms() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = push_client(&server);
    make_account(&server, &a.user_id);
    add_account(&server, "carol", &[&a]);
    add_push(
        &server,
        "carol",
        relay_push(format!("{}/carol", relay.url), WakeScope::MENTIONS),
    );
    add_account(&server, "dave", &[&a]);
    add_push(
        &server,
        "dave",
        relay_push(format!("{}/dave", relay.url), WakeScope::MENTIONS),
    );
    let (dm, _) = save_room(&mut a, "dm", obj! {"private" => true});
    a.request(
        "room_join",
        "add-carol",
        obj! {"room_id" => dm.as_str(), "user_id" => "carol"},
    );
    relay.pushes(&server, &mut a);
    save(
        &mut a,
        "plain",
        obj! {"room_id" => dm.as_str(), "body" => obj! {"text" => "no mention"}},
    );
    let got = relay.pushes(&server, &mut a);
    assert!(
        got.is_empty(),
        "a message without a mention woke {:?}",
        paths(&got)
    );
    save(
        &mut a,
        "mention",
        obj! {"room_id" => dm.as_str(), "body" => obj! {"text" => "@carol @dave look", "mentions" => list(&["carol", "dave"])}},
    );
    let got = relay.pushes(&server, &mut a);
    assert!(
        paths(&got) == strs(&["/carol"]) && got[0].header("Urgency") == "high",
        "a mention in a private room woke {:?}",
        paths(&got)
    );
    assert_eq!(
        got[0].message()["room_id"],
        Json::from(dm.as_str()),
        "pushed"
    );
}

/// A bot never wakes for joined, even holding mod (Cloudflare's isBotId
/// check): its registration drops joined and its server frame never lists
/// it.
#[test]
fn test_joined_never_for_a_bot_mod() {
    let relay = new_test_relay();
    let mut config = default_config();
    config.allow_insecure_push = true;
    config.push_hosts = PushHosts::Any;
    config.admin_token = super::helpers::admin_config().admin_token;
    let server = new_test_server(config);
    let mut admin = super::helpers::admin_on(&server, "http://localhost:5173");
    let token = token_in(&private_reply(&mut admin, "/invite-token announcer"));
    let (mut bot, _) = dial_raw(&server);
    token_auth(&mut bot, &token);
    bot.drain();
    private_reply(&mut admin, "/role announcer bot");
    bot.notification("user");
    assert_eq!(
        private_reply(&mut admin, "/role announcer mod"),
        "**announcer** (`announcer`) now has the role `mod`."
    );
    bot.notification("user");
    bot.expect_quiet();
    bot.result(
        "push_register",
        "joined",
        obj! {"kind" => "relay", "url" => format!("{}/announcer", relay.url), "wake" => list(&["joined", "mentions"])},
    );
    assert_eq!(
        server.app.lock().pushes[&push_key("announcer", &format!("{}/announcer", relay.url))].wake,
        WakeScope::MENTIONS
    );
    let (mut again, _) = dial_raw(&server);
    token_auth(&mut again, &token);
    again.expect_quiet();
}

/// joined is for admins and mods (apron-server-cloudflare's
/// JOINED_WAKE_ROLES): a registration keeps it only for them, a wake checks
/// the role as it is now, and a connection's server frame lists it only
/// where its user may wake for it, with a new frame when that changes.
#[test]
fn test_joined_only_for_admins_and_mods() {
    let relay = new_test_relay();
    let mut config = default_config();
    config.allow_insecure_push = true;
    config.push_hosts = PushHosts::Any;
    config.admin_token = super::helpers::admin_config().admin_token;
    config.push_delay = Duration::from_secs(0);
    let server = new_test_server(config);
    let mut admin = super::helpers::admin_on(&server, "http://localhost:5173");
    let mut regular = push_client(&server);
    let mut moderator = push_client(&server);
    grant_role(&server, &moderator.user_id, "mod");
    for c in [&mut regular, &mut moderator] {
        c.drain();
        let id = c.user_id.clone();
        c.result(
            "push_register",
            "joined",
            obj! {"kind" => "relay", "url" => format!("{}/{id}", relay.url), "wake" => list(&["joined", "mentions"])},
        );
    }
    let wake_of = |user_id: &str| {
        server.app.lock().pushes[&push_key(user_id, &format!("{}/{user_id}", relay.url))].wake
    };
    assert_eq!(
        wake_of(&regular.user_id),
        WakeScope::MENTIONS,
        "a regular user's"
    );
    assert_eq!(
        wake_of(&moderator.user_id),
        WakeScope::MENTIONS | WakeScope::JOINED,
        "a mod's"
    );
    // A registration that kept joined wakes for it only while the role does.
    add_push(
        &server,
        &regular.user_id,
        relay_push(format!("{}/kept", relay.url), WakeScope::JOINED),
    );
    go_idle(&mut regular);
    go_idle(&mut moderator);
    admin.drain();
    save(
        &mut admin,
        "chatter",
        obj! {"body" => obj! {"text" => "chatter"}},
    );
    let woken = paths(&relay.pushes(&server, &mut admin));
    assert_eq!(
        woken,
        vec![format!("/{}", moderator.user_id)],
        "joined wakes"
    );

    // A sign-in of a mod sends a server frame listing joined after the
    // result; a regular user's sends none.
    let joined = strs(&["mentions", "replies", "private", "joined", "badge"]);
    let plain = strs(&["mentions", "replies", "private", "badge"]);
    assert_eq!(admin.user_id, "admin");
    let (mut again, frame) = dial_origin(&server, "http://localhost:5173");
    assert_eq!(server_wake(&frame), plain, "before sign-in");
    super::helpers::token_auth(&mut again, super::helpers::ADMIN_TOKEN);
    assert_eq!(
        server_wake(&again.read()),
        joined,
        "after an admin's sign-in"
    );

    // A role change sends `you`, then the server frame with the scopes it
    // now gives.
    let regular_id = regular.user_id.clone();
    regular.drain();
    super::helpers::private_reply(&mut admin, &format!("/role {regular_id} mod"));
    let you = regular.read();
    assert!(
        notification_params(&you, "user").contains_key("you"),
        "{you:?}"
    );
    assert_eq!(server_wake(&regular.read()), joined, "after the grant");
    super::helpers::private_reply(&mut admin, &format!("/role {regular_id} mod"));
    regular.notification("user");
    assert_eq!(server_wake(&regular.read()), plain, "after the revocation");
    // Another role changes no scopes, so no server frame follows.
    super::helpers::private_reply(&mut admin, &format!("/role {regular_id} friend"));
    regular.notification("user");
    regular.expect_quiet();
}
