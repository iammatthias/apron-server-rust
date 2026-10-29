//! Adding and removing others with room_join and room_leave's user_id, and
//! `/kick`, ported from apron-server-cloudflare's
//! test/admin.integration.test.ts.

use super::admin_test::{account, admin, admin_test_server, private_reply, token_auth};
use super::helpers::*;
use crate::obj;
use crate::server::protocol::*;

fn join(c: &mut TestClient, id: &str, room_id: &str, user_id: &str) -> Option<i64> {
    let frame = reply(
        c,
        "room_join",
        id,
        obj! {"room_id" => room_id, "user_id" => user_id},
    );
    error_code(&frame)
}

fn remove(c: &mut TestClient, id: &str, room_id: &str, user_id: &str) -> Option<i64> {
    let frame = reply(
        c,
        "room_leave",
        id,
        obj! {"room_id" => room_id, "user_id" => user_id},
    );
    error_code(&frame)
}

/// Signs in the bot of the account c with a new /invite-bot token, and
/// returns its connection.
fn invite_bot(server: &TestServer, c: &mut TestClient) -> TestClient {
    let text = private_reply(c, "/invite-bot");
    let token = text
        .split("```\n")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned();
    let (mut bot, _) = dial_raw(server);
    let frame = token_auth(&mut bot, &token);
    bot.user_id = you_of(frame["result"].as_object().unwrap())["user_id"]
        .as_str()
        .unwrap()
        .to_owned();
    bot.drain();
    bot
}

/// An admin adds and removes anyone; an account adds its own bot, and
/// anyone while addmember is on; only accounts are added; an account
/// removes its own bot, and a guest adds no one.
#[test]
fn test_adding_and_removing_others() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut bob = account(&server);
    let carol = account(&server);
    let mut guest = dial_test_client(&server);
    let (bob_id, carol_id, guest_id) = (
        bob.user_id.clone(),
        carol.user_id.clone(),
        guest.user_id.clone(),
    );
    admin.drain();
    let (room, _) = save_room(
        &mut admin,
        "thread",
        obj! {"parent_room_id" => "general", "title" => "Invites"},
    );
    assert_eq!(join(&mut admin, "add-bob", &room, &bob_id), None);
    guest.drain();
    join_room(&mut guest, &room);
    assert_eq!(
        join(&mut guest, "guest-adds", &room, &carol_id),
        Some(CODE_DENIED)
    );

    private_reply(&mut admin, "/toggle addmember");
    assert_eq!(
        join(&mut bob, "add-carol", &room, &carol_id),
        Some(CODE_DENIED)
    );
    let bot = invite_bot(&server, &mut bob);
    let bot_id = bot.user_id.clone();
    assert_eq!(join(&mut bob, "add-bot", &room, &bot_id), None);
    assert_eq!(join(&mut admin, "admin-adds", &room, &carol_id), None);
    private_reply(&mut admin, "/toggle addmember");
    assert_eq!(join(&mut bob, "add-carol-on", &room, &carol_id), None);

    // Only accounts are added.
    let frame = reply(
        &mut admin,
        "room_join",
        "add-guest",
        obj! {"room_id" => room.as_str(), "user_id" => guest_id.as_str()},
    );
    assert_eq!(
        frame["error"].as_object().unwrap()["message"],
        Json::from(format!("{guest_id} is not a registered user"))
    );

    // Bob removes his bot but nobody else; the admin removes Bob.
    let frame = reply(
        &mut bob,
        "room_leave",
        "remove-carol",
        obj! {"room_id" => room.as_str(), "user_id" => carol_id.as_str()},
    );
    assert_eq!(
        frame["error"].as_object().unwrap()["message"],
        Json::from("Only an admin, the room's creator, or a bot's owner, can remove someone else")
    );
    assert_eq!(remove(&mut bob, "remove-bot", &room, &bot_id), None);
    assert_eq!(
        remove(&mut bob, "remove-admin", &room, "admin"),
        Some(CODE_DENIED)
    );
    bob.drain();
    assert_eq!(remove(&mut admin, "remove-bob", &room, &bob_id), None);
    expect_left(&bob, &room, &bob_id);
    guest.drain();
    assert_eq!(remove(&mut admin, "remove-bob-again", &room, &bob_id), None);
    assert_eq!(
        remove(&mut admin, "remove-nobody", &room, "nobody_123"),
        Some(CODE_INVALID_PARAMS)
    );
    // A connected guest can be removed.
    assert_eq!(
        remove(&mut admin, "remove-guest", "general", &guest_id),
        None
    );
    expect_left(&guest, "general", &guest_id);
}

/// A room's creator, if an account, removes anyone from it, across saves of
/// its fields; nobody created general.
#[test]
fn test_creator_removes_anyone() {
    let server = admin_test_server();
    let mut bob = account(&server);
    let mut carol = account(&server);
    let mut dan = account(&server);
    let (carol_id, dan_id) = (carol.user_id.clone(), dan.user_id.clone());
    bob.drain();
    let (room, _) = save_room(
        &mut bob,
        "thread",
        obj! {"parent_room_id" => "general", "title" => "Bob's"},
    );
    assert_eq!(join(&mut bob, "add-carol", &room, &carol_id), None);
    assert_eq!(join(&mut bob, "add-dan", &room, &dan_id), None);
    assert_eq!(
        remove(&mut dan, "dan-removes", &room, &carol_id),
        Some(CODE_DENIED)
    );
    let bob_id = bob.user_id.clone();
    assert_eq!(
        remove(&mut carol, "carol-removes", &room, &bob_id),
        Some(CODE_DENIED)
    );
    assert_eq!(
        remove(&mut bob, "general", "general", &carol_id),
        Some(CODE_DENIED)
    );
    let frame = reply(
        &mut carol,
        "room_set",
        "save",
        obj! {"room_id" => room.as_str(), "title" => "Renamed"},
    );
    assert!(frame.contains_key("result"), "{frame:?}");
    carol.drain();
    assert_eq!(remove(&mut bob, "remove-carol", &room, &carol_id), None);
    expect_left(&carol, &room, &carol_id);

    // A guest's thread gives it no say over who is in it.
    let mut guest = dial_test_client(&server);
    dan.drain();
    let (theirs, _) = save_room(&mut guest, "theirs", obj! {"parent_room_id" => "general"});
    dan.drain();
    join_room(&mut dan, &theirs);
    assert_eq!(
        remove(&mut guest, "guest-removes", &theirs, &dan_id),
        Some(CODE_DENIED)
    );
}

/// `/kick <user_id>` removes an account or a guest from the room of the
/// command and tells the admin; only an admin may kick.
#[test]
fn test_kick() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut bob = account(&server);
    let mut guest = dial_test_client(&server);
    let (bob_id, guest_id) = (bob.user_id.clone(), guest.user_id.clone());
    admin.drain();
    bob.drain();

    assert_eq!(
        private_reply(&mut admin, &format!("/kick @{bob_id}")),
        format!("Removed `{bob_id}` from this room.")
    );
    expect_left(&bob, "general", &bob_id);
    let rooms = list_rooms(&mut bob, obj! {"filter" => "joined"});
    assert!(room_ids(rooms.get("joined")).is_empty(), "{rooms:?}");
    let kick = |c: &mut TestClient, id: &str, text: &str| {
        let frame = reply(c, "command", id, obj! {"body" => obj! {"text" => text}});
        frame["error"]
            .as_object()
            .map(|e| (e["code"].clone(), e["message"].clone()))
    };
    assert_eq!(
        kick(&mut admin, "again", &format!("/kick {bob_id}")),
        Some((
            Json::from(CODE_INVALID_PARAMS),
            Json::from(format!("{bob_id} is not in this room"))
        ))
    );
    join_room(&mut bob, "general");
    guest.drain();

    assert_eq!(
        private_reply(&mut admin, &format!("/kick {guest_id}")),
        format!("Removed `{guest_id}` from this room.")
    );
    expect_left(&guest, "general", &guest_id);
    assert_eq!(
        kick(&mut admin, "self", "/kick admin"),
        Some((
            Json::from(CODE_DENIED),
            Json::from("You can't kick yourself; leave the room instead")
        ))
    );
    assert_eq!(
        kick(&mut admin, "nobody", "/kick nobody_123").map(|e| e.0),
        Some(Json::from(CODE_INVALID_PARAMS))
    );
    for text in ["/kick", "/kick a b"] {
        assert_eq!(
            kick(&mut admin, "usage", text),
            Some((
                Json::from(CODE_INVALID_PARAMS),
                Json::from("Usage: /kick <user_id>")
            ))
        );
    }
    assert_eq!(
        kick(&mut bob, "not-admin", "/kick admin"),
        Some((
            Json::from(CODE_DENIED),
            Json::from("Only an admin can use /kick")
        ))
    );
}

/// Only accounts start private rooms, and only an account that is a member
/// adds others to one, whatever addmember says; a bot member adds no one.
#[test]
fn test_private_room_members() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut bob = account(&server);
    let carol = account(&server);
    let mut guest = dial_test_client(&server);
    let frame = reply(&mut guest, "room_set", "private", obj! {"private" => true});
    assert_eq!(
        frame["error"].as_object().unwrap()["message"],
        Json::from("Sign in to start a private room")
    );
    private_reply(&mut admin, "/toggle addmember");
    bob.drain();
    let (room, _) = save_room(&mut bob, "private", obj! {"private" => true});
    let mut bot = invite_bot(&server, &mut bob);
    assert_eq!(join(&mut bob, "add-bot", &room, &bot.user_id), None);
    bot.drain();
    let frame = reply(
        &mut bot,
        "room_join",
        "bot-adds",
        obj! {"room_id" => room.as_str(), "user_id" => carol.user_id.as_str()},
    );
    assert_eq!(
        frame["error"].as_object().unwrap()["message"],
        Json::from("Only a signed-in member who is not a bot can add someone to a private room")
    );
    assert_eq!(join(&mut bob, "add-carol", &room, &carol.user_id), None);
}
