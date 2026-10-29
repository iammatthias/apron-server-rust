//! Rooms and messages: saving, joining, reacting and paging history.

use crate::obj;
use crate::server::protocol::*;

use super::*;

/// Sends room_list and returns its result.
pub fn list_rooms(c: &mut TestClient, params: Object) -> Object {
    let id = c.next_id("list");
    c.result("room_list", &id, params)
}

/// Lists the room_id of each room record in a room_list array.
pub fn room_ids(value: Option<&Json>) -> Vec<String> {
    let Some(Json::Array(list)) = value else {
        panic!("room list {value:?} is not an array")
    };
    list.iter()
        .map(|entry| {
            entry.as_object().unwrap()["room_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// Sends a message request and returns the result ID and the sender's copy
/// of the broadcast snapshot, which precedes the result (§1).
pub fn save(c: &mut TestClient, request_id: &str, mut params: Object) -> (String, Object) {
    if !params.contains_key("room_id") {
        params.insert("room_id".into(), "general".into());
    }
    let room_id = params["room_id"].clone();
    let (before, result) = c.request("message", request_id, params);
    let id = result
        .get("message_id")
        .and_then(Json::as_str)
        .map(str::to_owned);
    assert!(
        id.is_some() && before.len() == 1,
        "message result {result:?} after {before:?}, want one broadcast first"
    );
    let id = id.unwrap();
    let snapshot = notification_params(&before[0], "message");
    assert!(
        snapshot.get("message_id") == Some(&Json::from(id.as_str()))
            && snapshot.get("room_id") == Some(&room_id),
        "result and snapshot disagree: {result:?} vs {snapshot:?}"
    );
    assert!(
        !snapshot.contains_key("message"),
        "snapshot is not flat: {snapshot:?}"
    );
    assert!(result.len() == 1, "message result: {result:?}");
    (id, snapshot)
}

/// Sends room_set and returns the room ID and the record of the room_update
/// that precedes the result: joined for a new room, followed by the
/// creator's membership, or updated for an edit. The joined record's members
/// are checked and removed, so it compares with updated records.
pub fn save_room(c: &mut TestClient, request_id: &str, params: Object) -> (String, Object) {
    let editing = params.contains_key("room_id");
    let (before, result) = c.request("room_set", request_id, params);
    assert_eq!(
        methods(&before),
        vec!["room_update"],
        "room_set frames = {before:?}, want one room_update"
    );
    let mut record;
    if editing {
        record = update_record(&before[0], "updated");
    } else {
        // The creator receives the room with its members and the creator's
        // membership in one room_update (§4.2.4).
        record = joined_record(&before[0], &c.user_id);
        let membership = membership_of(&before[0]);
        check_membership(
            &membership,
            record["room_id"].as_str().unwrap(),
            &c.user_id,
            true,
        );
        assert!(
            membership.get("log_id") == record.get("latest_log_id")
                && parse_id(membership.get("log_id")) > parse_id(record.get("log_id")),
            "creator membership {membership:?} does not follow the room record {record:?}"
        );
        assert_eq!(
            member_ids(&record),
            vec![c.user_id.clone()],
            "new room members"
        );
        record.remove("members");
    }
    assert!(
        result.len() == 1 && result.get("room_id") == record.get("room_id"),
        "room_set result {result:?} disagrees with {record:?}"
    );
    (record["room_id"].as_str().unwrap().to_owned(), record)
}

/// Sends room_join and returns the room record of the room_update joined
/// that follows the membership and precedes the result. The record keeps its
/// members.
pub fn join_room(c: &mut TestClient, room_id: &str) -> Object {
    let id = c.next_id("join");
    let (before, result) = c.request("room_join", &id, obj! {"room_id" => room_id});
    assert!(
        methods(&before) == vec!["room_update"] && result.is_empty(),
        "room_join {room_id}: {before:?} then {result:?}"
    );
    let membership = membership_of(&before[0]);
    check_membership(&membership, room_id, &c.user_id, true);
    let record = joined_record(&before[0], &c.user_id);
    assert!(
        record.get("room_id") == Some(&Json::from(room_id))
            && record.get("latest_log_id") == membership.get("log_id"),
        "room_join {room_id} record: {record:?}"
    );
    record
}

/// Sends room_leave and checks the membership and room_update left that
/// precede its result.
pub fn leave_room(c: &mut TestClient, room_id: &str) {
    let id = c.next_id("leave");
    let (before, result) = c.request("room_leave", &id, obj! {"room_id" => room_id});
    assert!(
        methods(&before) == vec!["room_update"] && result.is_empty(),
        "room_leave {room_id}: {before:?} then {result:?}"
    );
    check_left(&before[0], room_id, &c.user_id);
}

/// Reads a room_update notification and returns its one record in field.
pub fn room_updated(c: &TestClient, field: &str) -> Object {
    update_record(&c.read(), field)
}

/// Requires a room_update carrying one record in field alone.
pub fn update_record(frame: &Object, field: &str) -> Object {
    let update = notification_params(frame, "room_update");
    let records = update.get(field).map(Json::as_list).unwrap_or(&[]);
    assert!(
        records.len() == 1 && update.len() == 1,
        "room_update = {update:?}, want one {field} record"
    );
    records[0].as_object().cloned().unwrap()
}

/// Requires a room_update joined carrying one record with its members, and
/// users holding each member's current object once. A non-empty member must
/// be among them.
pub fn joined_record(frame: &Object, member: &str) -> Object {
    let update = notification_params(frame, "room_update");
    let records = update.get("joined").map(Json::as_list).unwrap_or(&[]);
    let with_membership = update.contains_key("memberships");
    assert!(
        records.len() == 1 && (update.len() == 2 || (with_membership && update.len() == 3)),
        "room_update = {update:?}, want one joined record and users"
    );
    let record = records[0].as_object().cloned().unwrap();
    let members = member_ids(&record);
    let users: Vec<String> = update
        .get("users")
        .map(Json::as_list)
        .unwrap_or(&[])
        .iter()
        .map(|u| {
            u.as_object().unwrap()["user_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert!(
        members == users && (member.is_empty() || members.iter().any(|m| m == member)),
        "joined members {members:?} with users {users:?}, want {member:?} among them"
    );
    record
}

/// Lists the user_ids of a room record's members.
pub fn member_ids(entry: &Object) -> Vec<String> {
    entry
        .get("members")
        .map(Json::as_list)
        .unwrap_or(&[])
        .iter()
        .map(|m| {
            m.as_object().unwrap()["user_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// Sets reactions and returns the broadcast that precedes the result.
pub fn react(c: &mut TestClient, request_id: &str, message_id: &str, emojis: &[&str]) -> Object {
    let list: Vec<Json> = emojis.iter().map(|e| Json::from(*e)).collect();
    let (before, result) = c.request(
        "reactions",
        request_id,
        obj! {"message_id" => message_id, "emojis" => list},
    );
    assert!(
        result.is_empty() && before.len() == 1,
        "reactions result {result:?} after {before:?}, want one broadcast first"
    );
    notification_params(&before[0], "reactions")
}

pub fn history_page(c: &mut TestClient, room_id: &str, mut params: Object) -> Object {
    params.insert("room_id".into(), room_id.into());
    let id = c.next_id("history");
    c.result("history", &id, params)
}

/// Lists the log_ids of a history array, empty when it is omitted.
pub fn log_ids(page: &Object, key: &str) -> Vec<String> {
    let Some(raw) = page.get(key) else {
        return vec![];
    };
    let Json::Array(list) = raw else {
        panic!("history {key} is not a non-empty array: {page:?}")
    };
    assert!(
        !list.is_empty(),
        "history {key} is not a non-empty array: {page:?}"
    );
    list.iter()
        .map(|v| {
            v.as_object().unwrap()["log_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// Returns a history array, empty when it is omitted.
pub fn records(page: &Object, key: &str) -> Vec<Object> {
    log_ids(page, key);
    page.get(key)
        .map(Json::as_list)
        .unwrap_or(&[])
        .iter()
        .map(|v| v.as_object().cloned().unwrap())
        .collect()
}

pub fn parse_id(value: Option<&Json>) -> i64 {
    let Some(Json::String(text)) = value else {
        panic!("log id {value:?} is not a string")
    };
    match text.parse::<i64>() {
        Ok(id) if id > 0 => id,
        _ => panic!("log id {text:?} is not a positive integer"),
    }
}
