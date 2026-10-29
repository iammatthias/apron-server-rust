//! Reading frames: the notifications and replies a test checks.

use crate::obj;
use crate::server::protocol::*;
use crate::server::status::STATUS_OFFLINE;

use super::*;

/// The text of the `~private` welcome that follows the server frame, after
/// checking that it is one, in no room.
pub fn welcome_text(frame: &Object) -> String {
    let notice = notification_params(frame, "message");
    assert!(
        !notice.contains_key("room_id")
            && !notice.contains_key("message_id")
            && notice["from"]
                == Json::from(obj! {"user_id" => "~private", "name" => "System message to you"}),
        "welcome notice = {frame:?}"
    );
    notice["body"].as_object().unwrap()["text"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// A JSON array of strings.
pub fn strings(values: &[&str]) -> Json {
    Json::Array(values.iter().map(|v| Json::from(*v)).collect())
}

pub fn you_of(result: &Object) -> Object {
    result["you"].as_object().cloned().unwrap()
}

/// Reads the room_update that tells user_id's connection of its join to
/// general at sign-in.
pub fn expect_joined_default(c: &TestClient, user_id: &str) -> Object {
    check_joined_default(&c.read(), user_id)
}

/// Checks a room_update joined for user_id's join to general and returns its
/// membership record.
pub fn check_joined_default(frame: &Object, user_id: &str) -> Object {
    let record = joined_record(frame, user_id);
    assert_eq!(
        record.get("room_id"),
        Some(&Json::from("general")),
        "joined {record:?}, want general"
    );
    let membership = membership_of(frame);
    check_membership(&membership, "general", user_id, true);
    membership
}

/// The one membership record of a room_update frame (§4.2.3).
pub fn membership_of(frame: &Object) -> Object {
    let update = notification_params(frame, "room_update");
    let records = update.get("memberships").map(Json::as_list).unwrap_or(&[]);
    assert!(
        records.len() == 1,
        "room_update = {update:?}, want one membership record"
    );
    records[0].as_object().cloned().unwrap()
}

/// The membership record of a room_update that carries nothing else, as the
/// room's other members receive it.
pub fn membership_only(frame: &Object) -> Object {
    let update = notification_params(frame, "room_update");
    assert!(
        update.len() == 1,
        "room_update = {update:?}, want its membership alone"
    );
    membership_of(frame)
}

/// Reads a room_update carrying only a membership record: one entry, for
/// user_id in room_id, as the room's other members receive it.
pub fn expect_membership(c: &TestClient, room_id: &str, user_id: &str, joined: bool) -> Object {
    let params = membership_only(&c.read());
    check_membership(&params, room_id, user_id, joined);
    params
}

/// Reads the room_update that tells a user's connection it left or was
/// removed from room_id: left and the membership.
pub fn expect_left(c: &TestClient, room_id: &str, user_id: &str) -> Object {
    check_left(&c.read(), room_id, user_id)
}

pub fn check_left(frame: &Object, room_id: &str, user_id: &str) -> Object {
    let update = notification_params(frame, "room_update");
    let want_left: Json = vec![Json::from(obj! {"room_id" => room_id})].into();
    assert!(
        update.len() == 2 && update.get("left") == Some(&want_left),
        "room_update = {update:?}, want left {room_id} and its membership"
    );
    let membership = membership_of(frame);
    check_membership(&membership, room_id, user_id, false);
    membership
}

/// Checks a live membership record's shape.
pub fn check_membership(params: &Object, room_id: &str, user_id: &str, joined: bool) {
    let members = params.get("members").map(Json::as_list).unwrap_or(&[]);
    assert!(
        members.len() == 1
            && params.len() == 3
            && params.get("room_id") == Some(&Json::from(room_id)),
        "membership = {params:?}, want one entry in {room_id}"
    );
    parse_id(params.get("log_id"));
    let entry = members[0].as_object().unwrap();
    let user = entry
        .get("user")
        .and_then(Json::as_object)
        .cloned()
        .unwrap_or_default();
    assert!(
        entry.len() == 2
            && user.get("user_id") == Some(&Json::from(user_id))
            && entry.get("joined") == Some(&Json::from(joined)),
        "membership entry = {entry:?}, want {user_id} joined={joined}"
    );
}

/// Requires a frame to be the named notification and returns its params.
pub fn notification_params(frame: &Object, method: &str) -> Object {
    let params = frame.get("params").and_then(Json::as_object);
    assert!(
        frame.get("method").and_then(Json::as_str) == Some(method)
            && params.is_some()
            && frame.get("id").is_none(),
        "frame = {frame:?}, want {method} notification"
    );
    params.cloned().unwrap()
}

/// Names each frame's method, or "reply" for a reply.
pub fn methods(frames: &[Object]) -> Vec<String> {
    frames
        .iter()
        .map(|frame| match frame.get("method").and_then(Json::as_str) {
            Some(method) if !method.is_empty() => method.to_owned(),
            _ => "reply".to_owned(),
        })
        .collect()
}

/// Makes the clients keep the bare status announcements of others (§4.5).
pub fn watching(clients: &mut [&mut TestClient]) {
    for c in clients {
        c.statuses = true;
    }
}

/// Checks a bare announcement of user_id's status, `user` `{new: {user_id,
/// status}}`, with seen when status is offline, and returns the seen.
pub fn check_status(frame: &Object, user_id: &str, status: &str) -> String {
    let params = notification_params(frame, "user");
    let mut want = obj! {"new" => obj! {"user_id" => user_id, "status" => status}};
    let seen = params
        .get("new")
        .and_then(Json::as_object)
        .and_then(|n| n.get("seen"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    if status == STATUS_OFFLINE {
        assert!(seen.parse::<i64>().is_ok_and(|s| s > 0), "seen {seen:?}");
        want.get_mut("new")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("seen".into(), seen.as_str().into());
    }
    assert_eq!(params, want, "user notification");
    seen
}

/// The wake scopes of a `server` frame's push, failing on any other frame.
pub fn server_wake(frame: &Object) -> Vec<String> {
    assert_eq!(
        frame.get("method"),
        Some(&Json::from("server")),
        "want server: {frame:?}"
    );
    frame["params"].as_object().unwrap()["push"]
        .as_object()
        .unwrap()["wake"]
        .as_list()
        .iter()
        .map(|scope| scope.as_str().unwrap().to_owned())
        .collect()
}

/// Reads the `server` frame a moderator's sign-in sends after its result,
/// which lists wake scope `joined`.
pub fn expect_joined_wake(c: &TestClient) {
    let wake = server_wake(&c.read());
    assert!(wake.iter().any(|s| s == "joined"), "wake scopes {wake:?}");
}

/// Sends a request and returns its reply, result or error, skipping the
/// notifications before it.
pub fn reply(c: &mut TestClient, method: &str, id: &str, params: Object) -> Object {
    c.write(&obj! {"method" => method, "id" => id, "params" => params});
    loop {
        let frame = c.read();
        if frame.contains_key("id") {
            return frame;
        }
    }
}

/// The error code of a reply, if it is an error.
pub fn error_code(frame: &Object) -> Option<i64> {
    match frame.get("error")?.as_object()?.get("code")? {
        Json::Number(code) => Some(*code as i64),
        _ => None,
    }
}

/// A retry_after reply's message and data, failing on any other reply.
pub fn retry_after_of(frame: &Object) -> (String, Object) {
    let error = frame
        .get("error")
        .and_then(Json::as_object)
        .unwrap_or_else(|| panic!("want retry_after: {frame:?}"));
    assert_eq!(error["code"], Json::from(CODE_RETRY_AFTER), "{frame:?}");
    (
        error["message"].as_str().unwrap().to_owned(),
        error["data"].as_object().unwrap().clone(),
    )
}
