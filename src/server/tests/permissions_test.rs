//! Moderator moves and `ext:permissions` (EXTENSIONS.md), ported from
//! apron-server-cloudflare's test/admin.integration.test.ts.

use super::admin_test::{account, admin, admin_test_server, private_reply, token_auth};
use super::helpers::*;
use crate::obj;
use crate::server::protocol::*;

/// Reads frames until a `user` notification with `you`, and returns its ext.
fn own_ext(c: &mut TestClient) -> Json {
    loop {
        let frame = c.read();
        if frame.get("method") == Some(&Json::from("user")) {
            let params = notification_params(&frame, "user");
            if let Some(you) = params.get("you").and_then(Json::as_object) {
                return you.get("ext").cloned().unwrap_or_default();
            }
        }
    }
}

/// Reads frames until a `user` notification with `new` for user_id.
fn their_new(c: &mut TestClient, user_id: &str) -> Object {
    loop {
        let frame = c.read();
        if frame.get("method") == Some(&Json::from("user")) {
            let params = notification_params(&frame, "user");
            if let Some(new) = params.get("new").and_then(Json::as_object) {
                if new.get("user_id") == Some(&Json::from(user_id)) && new.contains_key("roles") {
                    return new.clone();
                }
            }
        }
    }
}

/// The ext of a `you` whose permissions grant `granted`, each `true`.
fn permissions(granted: &[&str]) -> Json {
    let fields: Object = granted
        .iter()
        .map(|key| ((*key).to_owned(), Json::Bool(true)))
        .collect();
    Json::from(obj! {"permissions" => fields})
}

fn move_to(c: &mut TestClient, id: &str, message_id: &str, room_id: &str) -> Object {
    reply(
        c,
        "message",
        id,
        obj! {"message_id" => message_id, "room_id" => room_id, "body" => obj! {"text" => "tidy me"}},
    )
}

fn denied(frame: &Object) -> bool {
    frame
        .get("error")
        .and_then(Json::as_object)
        .is_some_and(|e| e.get("code") == Some(&Json::from(CODE_DENIED)))
}

/// Admin, mod and threader move others' messages, keeping their content;
/// every account but a bot adds members; only the user is told their own
/// permissions.
#[test]
fn test_permissions_and_moderator_moves() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut tia = account(&server);
    let mut mate = account(&server);
    let tia_id = tia.user_id.clone();
    admin.drain();
    tia.drain();
    let (posted, _) = save(
        &mut mate,
        "post",
        obj! {"body" => obj! {"text" => "tidy me"}},
    );
    admin.drain();
    tia.drain();
    let (thread, _) = save_room(
        &mut admin,
        "thread",
        obj! {"parent_room_id" => "general", "title" => "Tidied"},
    );
    tia.drain();
    mate.drain();

    assert!(denied(&move_to(&mut tia, "before", &posted, &thread)));
    for role in ["threader", "mod", "admin"] {
        private_reply(&mut admin, &format!("/role {tia_id} {role}"));
        let want: &[&str] = &["add_members", "move_any"];
        assert_eq!(own_ext(&mut tia), permissions(want), "{role}");
        assert!(!their_new(&mut mate, &tia_id).contains_key("ext"), "{role}");
        let frame = move_to(&mut tia, &format!("{role}-in"), &posted, &thread);
        assert!(frame.contains_key("result"), "{role} in: {frame:?}");
        let frame = move_to(&mut tia, &format!("{role}-out"), &posted, "general");
        assert!(frame.contains_key("result"), "{role} out: {frame:?}");
        // A move keeps the content as it was.
        let changed = reply(
            &mut tia,
            "message",
            &format!("{role}-edit"),
            obj! {"message_id" => posted.as_str(), "room_id" => thread.as_str(), "body" => obj! {"text" => "mine now"}},
        );
        assert_eq!(
            changed["error"].as_object().unwrap()["message"],
            Json::from(
                "An admin, mod or threader may move someone else's message but not change it"
            )
        );
        // Nor may a moderator edit it where it is.
        assert!(denied(&reply(
            &mut tia,
            "message",
            &format!("{role}-same"),
            obj! {"message_id" => posted.as_str(), "room_id" => "general", "body" => obj! {"text" => "tidy me"}},
        )));
        private_reply(&mut admin, &format!("/role {tia_id} {role}"));
        assert_eq!(
            own_ext(&mut tia),
            permissions(&["add_members"]),
            "{role} taken"
        );
        their_new(&mut mate, &tia_id);
        mate.drain();
        tia.drain();
    }
    assert!(denied(&move_to(&mut tia, "after", &posted, &thread)));

    // An owner's bot may move nothing and add no one, so it is told
    // neither, even with mod.
    let text = private_reply(&mut tia, "/invite-bot");
    let token = text
        .split("```\n")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned();
    let (mut bot, _) = dial_raw(&server);
    let frame = token_auth(&mut bot, &token);
    let you = you_of(frame["result"].as_object().unwrap());
    assert_eq!(you["ext"], permissions(&[]), "bot sign-in");
    let bot_id = you["user_id"].as_str().unwrap().to_owned();
    bot.drain();
    private_reply(&mut admin, &format!("/role {bot_id} mod"));
    assert_eq!(own_ext(&mut bot), permissions(&[]), "bot with mod");
    assert!(denied(&move_to(&mut bot, "bot-move", &posted, &thread)));
}

/// A guest who may post has the defaults, and `me` cannot write them.
#[test]
fn test_permissions_belong_to_the_server() {
    let server = admin_test_server();
    let mut guest = dial_test_client(&server);
    let you = you_of(&guest.result("me", "guest", obj! {"status" => "dnd"}));
    assert_eq!(you["ext"], permissions(&[]), "guest you: {you:?}");
    let mut ada = account(&server);
    let you = you_of(&ada.result(
        "me",
        "forge",
        obj! {"ext" => obj! {"permissions" => strings(&["move_any"]), "bio" => "hi"}},
    ));
    assert_eq!(
        you["ext"],
        Json::from(obj! {"bio" => "hi", "permissions" => obj! {"add_members" => true}}),
    );
    assert!(!server.app.lock().users[&ada.user_id]
        .ext
        .contains_key("permissions"));
}

/// `/toggle addmember` sends each connected account but admins and bots
/// its new permissions in `you`.
#[test]
fn test_toggle_addmember_sends_permissions() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut ada = account(&server);
    let mut guest = dial_test_client(&server);
    admin.drain();
    ada.drain();
    let (before, _) = admin.request(
        "command",
        "off",
        obj! {"body" => obj! {"text" => "/toggle addmember"}},
    );
    assert_eq!(
        methods(&before),
        vec!["message"],
        "admin told only the notice"
    );
    let you = you_of(&admin.result("me", "admin-me", Object::new()));
    assert_eq!(
        you["ext"],
        permissions(&["add_members", "move_any"]),
        "an admin adds members while addmember is off"
    );
    let frame = ada.read();
    assert_eq!(
        notification_params(&frame, "user"),
        obj! {"you" => obj! {"user_id" => ada.user_id.as_str(), "ext" => permissions(&[])}},
    );
    admin.expect_quiet();
    guest.expect_quiet();
    private_reply(&mut admin, "/toggle addmember");
    assert_eq!(own_ext(&mut ada), permissions(&["add_members"]));
}

/// A guest who only reads is told it may not write.
#[test]
fn test_read_only_guest_may_not_write() {
    let server = new_test_server(crate::server::config::default_config());
    let mut guest = dial_test_client(&server);
    let you = you_of(&guest.result("me", "me", Object::new()));
    assert_eq!(
        you["ext"],
        Json::from(obj! {"permissions" => obj! {"write" => false}})
    );
}
