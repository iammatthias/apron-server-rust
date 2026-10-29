//! /toggle, as apron-server-cloudflare has it (its SPEC.md, section 5,
//! Admins): features an admin turns off and on for everyone, kept across
//! restarts, and offered to each new connection while on.

use std::sync::Arc;

use super::admin_test::*;
use super::helpers::*;
use super::persist_test::start_with;
use crate::obj;
use crate::server::protocol::*;
use crate::server::Config;
use crate::store::{self, Store};

fn params(frame: &Object) -> Object {
    frame["params"].as_object().cloned().unwrap()
}

fn has_capability(frame: &Object, name: &str) -> bool {
    params(frame)["capabilities"]
        .as_list()
        .contains(&Json::from(name))
}

fn settings(frame: &Object) -> Object {
    params(frame)["ext"].as_object().unwrap()["settings"]
        .as_object()
        .cloned()
        .unwrap()
}

/// Only admins toggle; the argument is one of the four features.
#[test]
fn test_toggle_usage() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut ada = account(&server);
    assert!(private_reply(&mut admin, "/help")
        .contains("/toggle <activity|uploads|presence|addmember>"));
    for bad in ["/toggle", "/toggle typing", "/toggle activity uploads"] {
        assert_eq!(
            command_error(&mut admin, bad),
            (
                CODE_INVALID_PARAMS,
                "Usage: /toggle activity|uploads|presence|addmember".into()
            ),
            "{bad}"
        );
    }
    assert_eq!(
        command_error(&mut ada, "/toggle activity"),
        (CODE_DENIED, "Only an admin can use /toggle".into()),
    );
}

/// Activity off: new connections are not offered it or read cursors, and
/// typing is not relayed; the toggle survives a restart, and
/// toggling back offers it again.
#[test]
fn test_toggle_activity_persists() {
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let dir = TempDir::new("apron-toggle-");
    let configure = |config: &mut Config| {
        config.admin_token = admin_config().admin_token;
    };
    let mut server = start_with(kept.clone(), &format!("{dir}/a"), configure);
    let mut boss = admin(&server);
    let (_, before) = dial_raw(&server);
    assert!(
        has_capability(&before, "activity")
            && settings(&before)["read_cursors"] == Json::Bool(true)
    );
    assert_eq!(
        private_reply(&mut boss, "/toggle activity"),
        "Activity is now **off**: typing is no longer relayed, and new connections are not offered it."
    );
    // Typing is no longer relayed.
    let typist = dial_test_client(&server);
    let mut watcher = dial_test_client(&server);
    watcher.drain();
    typist.write(&obj! {"method" => "activity", "params" => obj! {"typing" => 5i64}});
    watcher.expect_quiet();
    drop((boss, typist, watcher));
    server.stop();

    let server = start_with(kept, &format!("{dir}/b"), configure);
    let (_, after) = dial_raw(&server);
    assert!(
        !has_capability(&after, "activity")
            && settings(&after)["read_cursors"] == Json::Bool(false),
        "after restart: {after:?}"
    );
    let mut boss = admin(&server);
    assert_eq!(
        private_reply(&mut boss, "/toggle activity"),
        "Activity is now **on**: typing is relayed, and new connections are offered it."
    );
    let (_, again) = dial_raw(&server);
    assert!(has_capability(&again, "activity"), "{again:?}");
}

/// Uploads off: new connections are not offered upload embeds or media
/// types, /help leaves out /avatar, and new upload embeds and /avatar are
/// denied.
#[test]
fn test_toggle_uploads() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    assert_eq!(
        private_reply(&mut admin, "/toggle uploads"),
        "Uploads are now **off**: new attachments and avatars are refused, and new connections are not offered uploads."
    );
    let (_, frame) = dial_raw(&server);
    assert!(!has_capability(&frame, "embed:upload"), "{frame:?}");
    assert_eq!(
        params(&frame)["ext"].as_object().unwrap()["media"],
        Json::from(Object::new())
    );
    let mut ada = account(&server);
    assert!(!private_reply(&mut ada, "/help").contains("/avatar"));
    let id = ada.next_id("post");
    let frame = ada.call(
        "message",
        &id,
        obj! {"body" => obj! {"text" => "pic", "embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
    );
    assert_eq!(
        frame.get("error"),
        Some(&Json::from(
            obj! {"code" => CODE_DENIED, "message" => "Uploads are turned off here"}
        )),
    );
    let id = ada.next_id("avatar");
    let frame = ada.call(
        "command",
        &id,
        obj! {"body" => obj! {"text" => "/avatar", "embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
    );
    assert_eq!(
        frame.get("error"),
        Some(&Json::from(
            obj! {"code" => CODE_DENIED, "message" => "Uploads are turned off here"}
        )),
    );
    assert_eq!(
        private_reply(&mut admin, "/toggle uploads"),
        "Uploads are now **on**."
    );
    assert!(private_reply(&mut ada, "/help").contains("/avatar"));
}

/// Presence off: every connection is told each user's status is now "",
/// new connections are not offered the optional statuses, and a user's
/// chosen status is still kept in their `you`; turned on, statuses show
/// again.
#[test]
fn test_toggle_presence() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut ada = account(&server);
    let mut watcher = account(&server);
    watcher.statuses = true;
    watcher.drain();
    let status_of = |frames: &[Object], user_id: &str| {
        frames.iter().rev().find_map(|frame| {
            let new = frame.get("params")?.as_object()?.get("new")?.as_object()?;
            (new.get("user_id") == Some(&Json::from(user_id))).then(|| new["status"].clone())
        })
    };
    assert_eq!(
        private_reply(&mut admin, "/toggle presence"),
        "Status is now **off**: no one's status is shown, and connected clients were told to clear the ones they were shown."
    );
    let frames = watcher.drain();
    assert_eq!(
        status_of(&frames, &ada.user_id),
        Some(Json::from("")),
        "{frames:?}"
    );
    let (_, frame) = dial_raw(&server);
    assert!(!params(&frame).contains_key("status"), "{frame:?}");
    ada.drain();
    let you = you_of(&ada.result("me", "dnd", obj! {"status" => "dnd"}));
    assert_eq!(you["status"], Json::from("dnd"));
    watcher.drain();
    assert_eq!(
        private_reply(&mut admin, "/toggle presence"),
        "Status is now **on**: others see who is online, idle, busy (`dnd`) or offline."
    );
    let frames = watcher.drain();
    assert_eq!(
        status_of(&frames, &ada.user_id),
        Some(Json::from("dnd")),
        "{frames:?}"
    );
    let (_, frame) = dial_raw(&server);
    assert_eq!(params(&frame)["status"], strings(&["dnd", "invisible"]));
}

/// Adding members off: an account may not add another to a room, but an
/// admin may, and an owner may add their bot; new connections are told
/// `add_members: false`.
#[test]
fn test_toggle_addmember() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut ada = account(&server);
    let bob = account(&server);
    private_reply(&mut ada, "/invite-bot");
    assert_eq!(
        private_reply(&mut admin, "/toggle addmember"),
        "Adding members is now **off**: only admins can add others to a room, and owners their bots."
    );
    ada.drain();
    grant_role(&server, &ada.user_id, "mod");
    let (room, _) = save_room(&mut ada, "room", obj! {"title" => "Ada's"});
    let id = ada.next_id("add");
    let refused = ada.call(
        "room_join",
        &id,
        obj! {"room_id" => room.as_str(), "user_id" => bob.user_id.as_str()},
    );
    assert_eq!(
        refused.get("error"),
        Some(&Json::from(
            obj! {"code" => CODE_DENIED, "message" => "Only an admin, or a bot's owner, can add someone else here"}
        )),
    );
    let bot_id = format!("bot_{}", ada.user_id);
    let (_, added) = ada.request(
        "room_join",
        "add-bot",
        obj! {"room_id" => room.as_str(), "user_id" => bot_id.as_str()},
    );
    assert!(added.is_empty(), "{added:?}");
    admin.drain();
    let (_, joined) = admin.request("room_join", "join", obj! {"room_id" => room.as_str()});
    assert!(joined.is_empty());
    let (_, added) = admin.request(
        "room_join",
        "add-bob",
        obj! {"room_id" => room.as_str(), "user_id" => bob.user_id.as_str()},
    );
    assert!(added.is_empty(), "{added:?}");
    assert_eq!(
        private_reply(&mut admin, "/toggle addmember"),
        "Adding members is now **on**: any registered user can add another to a room."
    );
}
