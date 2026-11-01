//! Activity (§4.6) as apron-server-cloudflare limits it, ported from its
//! test/read-cursors.integration.test.ts and protocol.integration.test.ts.

use super::helpers::*;
use crate::obj;
use crate::server::activity::{ACTIVITY_RELAYS_PER_MINUTE, MAX_TYPING_SECONDS};
use crate::server::protocol::*;

fn activities(frames: &[Object]) -> Vec<Object> {
    frames
        .iter()
        .filter(|f| f.get("method") == Some(&Json::from("activity")))
        .map(|f| notification_params(f, "activity"))
        .collect()
}

fn read(c: &TestClient, message_id: &str) {
    c.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => "general", "read_message_id" => message_id}});
}

/// A read cursor in a public room goes to the user's other connections
/// only, within its own allowance, and room_list follows with the user's
/// own cursor alone; no read receipts there.
#[test]
fn test_read_cursors_stay_with_the_user() {
    assert_eq!(
        ACTIVITY_RELAYS_PER_MINUTE, 10,
        "Cloudflare's relay allowance"
    );
    let server = super::helpers::admin_test_server();
    let mut other = dial_test_client(&server);
    let mut first = super::helpers::admin(&server);
    let mut second = super::helpers::admin(&server);
    other.drain();
    let mut ids = Vec::new();
    for i in 0..12 {
        let (id, _) = save(
            &mut other,
            &format!("m{i}"),
            obj! {"body" => obj! {"text" => "x"}},
        );
        ids.push(id);
    }
    first.drain();
    second.drain();
    other.drain();
    for id in &ids {
        read(&first, id);
    }
    let want: Vec<Object> = ids[..10]
        .iter()
        .map(|id| obj! {"room_id" => "general", "from" => obj! {"user_id" => "admin", "name" => "Admin"}, "read_message_id" => id.as_str()})
        .collect();
    let echoed = activities(&first.drain());
    assert!(echoed.is_empty(), "echoed to the sender: {echoed:?}");
    assert_eq!(
        activities(&second.drain()),
        want,
        "relayed past the allowance"
    );
    assert!(activities(&other.drain()).is_empty(), "a read receipt");
    // Typing has its own allowance.
    first.write(
        &obj! {"method" => "activity", "params" => obj! {"room_id" => "general", "typing" => 5i64}},
    );
    let typing = other.notification("activity");
    assert_eq!(typing["typing"], Json::from(5i64));
    assert!(first
        .drain()
        .iter()
        .all(|f| f.get("method") != Some(&Json::from("message"))));

    // The kept cursor, the furthest, follows a listing, and only for its user.
    let listing = |c: &mut TestClient| {
        c.drain();
        c.write(&obj! {"method" => "room_list", "id" => "list", "params" => obj! {"filter" => "joined"}});
        activities(&c.drain())
    };
    let kept = listing(&mut second);
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(kept[0]["read_message_id"], Json::from(ids[11].as_str()));
    assert!(listing(&mut other).is_empty(), "others' cursors listed");
}

/// A guest's read cursor is dropped: guests keep nothing.
#[test]
fn test_guest_cursors_are_dropped() {
    let server = new_test_server(default_config());
    let mut guest = dial_test_client(&server);
    let (id, _) = save(&mut guest, "post", obj! {"body" => obj! {"text" => "x"}});
    read(&guest, &id);
    guest.drain();
    assert!(server.app.lock().rooms["general"].reads.is_empty());
}

/// Typing goes to the room capped at MAX_TYPING_SECONDS, at most
/// ACTIVITY_RELAYS_PER_MINUTE a minute; past that it is dropped and the
/// sender told once with a ~private notice.
#[test]
fn test_typing_is_capped_and_throttled() {
    assert_eq!(MAX_TYPING_SECONDS, 30, "Cloudflare's typing cap");
    let server = new_test_server(default_config());
    let mut a = dial_test_client(&server);
    let mut b = dial_test_client(&server);
    a.drain();
    for _ in 0..ACTIVITY_RELAYS_PER_MINUTE + 2 {
        a.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => "general", "typing" => 600i64}});
    }
    let own = a.drain();
    let relayed = activities(&b.drain());
    assert_eq!(relayed.len(), ACTIVITY_RELAYS_PER_MINUTE as usize);
    assert!(
        relayed.iter().all(|p| p["typing"] == Json::from(30i64)),
        "{relayed:?}"
    );
    let notices: Vec<Json> = own
        .iter()
        .filter(|f| f.get("method") == Some(&Json::from("message")))
        .map(|f| notification_params(f, "message")["body"].clone())
        .collect();
    assert_eq!(
        notices,
        vec![Json::from(obj! {
            "text" => "Typing updates are limited to 10 per minute, so others may not see you typing for a moment.",
            "format" => "plain",
        })]
    );
}

/// Typing goes to every connection in the room but the sending one: the
/// typist's other devices see it too, as Cloudflare's deliver does.
#[test]
fn test_typing_reaches_the_typists_other_connections() {
    let server = super::helpers::admin_test_server();
    let mut other = dial_test_client(&server);
    let mut first = super::helpers::admin(&server);
    let mut second = super::helpers::admin(&server);
    for c in [&mut other, &mut first, &mut second] {
        c.drain();
    }
    first.write(
        &obj! {"method" => "activity", "params" => obj! {"room_id" => "general", "typing" => 5i64}},
    );
    let want = vec![
        obj! {"room_id" => "general", "from" => obj! {"user_id" => "admin", "name" => "Admin"}, "typing" => 5i64},
    ];
    assert_eq!(
        activities(&first.drain()),
        Vec::<Object>::new(),
        "echoed to the sender"
    );
    assert_eq!(
        activities(&second.drain()),
        want,
        "the typist's other device"
    );
    assert_eq!(activities(&other.drain()), want, "another member");
}

/// A fractional typing value is floored, as Cloudflare's Math.floor does,
/// and relayed rather than refused.
#[test]
fn test_fractional_typing_is_floored() {
    let server = new_test_server(default_config());
    let mut a = dial_test_client(&server);
    let mut b = dial_test_client(&server);
    a.drain();
    b.drain();
    for typing in ["4.9", "0.5", "45.7", "1e0"] {
        a.write_raw(&format!(
            r#"{{"method":"activity","params":{{"room_id":"general","typing":{typing}}}}}"#
        ));
    }
    a.drain();
    let typed: Vec<Json> = activities(&b.drain())
        .into_iter()
        .map(|p| p["typing"].clone())
        .collect();
    assert_eq!(
        typed,
        vec![
            Json::from(4i64),
            Json::from(0i64),
            Json::from(30i64),
            Json::from(1i64)
        ]
    );
}

/// A read cursor need not name a message, as on Cloudflare: one naming an
/// unknown id is kept and relayed in its canonical spelling, and only one
/// that is not a positive decimal string is refused.
#[test]
fn test_read_cursor_naming_an_unknown_message_is_relayed() {
    let server = super::helpers::admin_test_server();
    let mut first = super::helpers::admin(&server);
    let mut second = super::helpers::admin(&server);
    for id in ["0", "-1", "x1", "9007199254740992", "0042"] {
        read(&first, id);
    }
    first.drain();
    assert_eq!(
        activities(&second.drain()),
        vec![
            obj! {"room_id" => "general", "from" => obj! {"user_id" => "admin", "name" => "Admin"}, "read_message_id" => "42"}
        ]
    );
    assert_eq!(
        server.app.lock().rooms["general"].reads["admin"].message_id,
        "42"
    );
}

fn read_in(c: &TestClient, room_id: &str, message_id: &str) {
    c.write(&obj! {"method" => "activity", "params" => obj! {"room_id" => room_id, "read_message_id" => message_id}});
}

fn joined_listing(c: &mut TestClient) -> Vec<Object> {
    c.drain();
    c.write(
        &obj! {"method" => "room_list", "id" => "list", "params" => obj! {"filter" => "joined"}},
    );
    activities(&c.drain())
}

/// A private room's members see each other's read cursors, live and after a
/// listing, and nobody else does (apron-server-cloudflare's "shows a private
/// room's members each other's read cursors").
#[test]
fn test_private_room_read_receipts() {
    let server = super::helpers::admin_test_server();
    let mut ada = super::helpers::admin(&server);
    let mut bob = super::helpers::account(&server);
    let mut carol = super::helpers::account(&server);
    let (_, frame) = dial_raw(&server);
    assert_eq!(
        frame["params"].as_object().unwrap()["ext"]
            .as_object()
            .unwrap()["settings"]
            .as_object()
            .unwrap()["read_receipts"],
        Json::from("private")
    );
    ada.drain();
    let (room_id, _) = save_room(&mut ada, "create", obj! {"private" => true});
    ada.request(
        "room_join",
        "add",
        obj! {"room_id" => room_id.as_str(), "user_id" => bob.user_id.as_str()},
    );
    let (one, _) = save(
        &mut ada,
        "one",
        obj! {"room_id" => room_id.as_str(), "body" => obj! {"text" => "one"}},
    );
    ada.drain();
    bob.drain();
    carol.drain();
    read_in(&bob, &room_id, &one);
    let echoed = activities(&bob.drain());
    let bob_name = server.app.lock().users[&bob.user_id].from();
    assert_eq!(
        activities(&ada.drain()),
        vec![
            obj! {"room_id" => room_id.as_str(), "from" => bob_name, "read_message_id" => one.as_str()}
        ],
        "relayed to the other member"
    );
    assert!(echoed.is_empty(), "echoed to the reader");
    assert!(
        activities(&carol.drain()).is_empty(),
        "relayed outside the room"
    );
    // Ada's other device lists the room: Bob's cursor, by user_id alone.
    let mut second = super::helpers::admin(&server);
    assert_eq!(
        joined_listing(&mut second),
        vec![
            obj! {"room_id" => room_id.as_str(), "from" => obj! {"user_id" => bob.user_id.as_str()}, "read_message_id" => one.as_str()}
        ]
    );
    assert!(
        joined_listing(&mut carol).is_empty(),
        "listed outside the room"
    );
    // A public room's cursor still goes to the user's own connections only.
    let (general, _) = save(&mut ada, "general", obj! {"body" => obj! {"text" => "hi"}});
    ada.drain();
    second.drain();
    read_in(&bob, "general", &general);
    assert!(activities(&bob.drain()).is_empty(), "echoed to the reader");
    assert!(
        activities(&ada.drain()).is_empty(),
        "a public room's receipt"
    );
}

/// A room past MAX_READ_RECEIPT_MEMBERS registered members keeps each
/// cursor to its own user.
#[test]
fn test_large_private_rooms_have_no_read_receipts() {
    use crate::server::activity::MAX_READ_RECEIPT_MEMBERS;
    assert_eq!(MAX_READ_RECEIPT_MEMBERS, 10, "Cloudflare's limit");
    let server = super::helpers::admin_test_server();
    let mut ada = super::helpers::admin(&server);
    let mut bob = super::helpers::account(&server);
    ada.drain();
    let (room_id, _) = save_room(&mut ada, "create", obj! {"private" => true});
    let mut members = vec![bob.user_id.clone()];
    for i in 0..MAX_READ_RECEIPT_MEMBERS - 1 {
        let user_id = format!("member{i}");
        super::status_test::add_account(&server, &user_id, &[]);
        members.push(user_id);
    }
    for (i, user_id) in members.iter().enumerate() {
        ada.request(
            "room_join",
            &format!("add{i}"),
            obj! {"room_id" => room_id.as_str(), "user_id" => user_id.as_str()},
        );
    }
    let (one, _) = save(
        &mut ada,
        "one",
        obj! {"room_id" => room_id.as_str(), "body" => obj! {"text" => "one"}},
    );
    ada.drain();
    read_in(&bob, &room_id, &one);
    bob.drain();
    assert!(
        activities(&ada.drain()).is_empty(),
        "a receipt in a room of {} members",
        MAX_READ_RECEIPT_MEMBERS + 1
    );
    let mut second = super::helpers::admin(&server);
    assert!(joined_listing(&mut second).is_empty());
}

/// A member who chose invisible shows no read receipt, live or after a
/// listing, until they are visible again; their own devices still get it.
#[test]
fn test_invisible_members_show_no_read_receipts() {
    let server = super::helpers::admin_test_server();
    let mut ada = super::helpers::account(&server);
    let mut bob = super::helpers::admin(&server);
    let mut mine = super::helpers::admin(&server);
    ada.drain();
    let (room_id, _) = save_room(&mut ada, "create", obj! {"private" => true});
    ada.request(
        "room_join",
        "add",
        obj! {"room_id" => room_id.as_str(), "user_id" => "admin"},
    );
    let (one, _) = save(
        &mut ada,
        "one",
        obj! {"room_id" => room_id.as_str(), "body" => obj! {"text" => "one"}},
    );
    bob.drain();
    bob.request("me", "hide", obj! {"status" => "invisible"});
    ada.drain();
    mine.drain();
    read_in(&bob, &room_id, &one);
    bob.drain();
    let own = activities(&mine.drain());
    assert_eq!(own.len(), 1, "{own:?}");
    assert_eq!(own[0]["read_message_id"], Json::from(one.as_str()));
    assert!(activities(&ada.drain()).is_empty(), "an invisible receipt");
    assert!(
        joined_listing(&mut ada).is_empty(),
        "an invisible member listed"
    );
    bob.request("me", "show", obj! {"status" => "online"});
    assert_eq!(
        joined_listing(&mut ada),
        vec![
            obj! {"room_id" => room_id.as_str(), "from" => obj! {"user_id" => "admin"}, "read_message_id" => one.as_str()}
        ]
    );
}

/// `ext.settings.read_receipts` is "private" by default, and false with
/// --read-receipts, which sends cursors in every room, as "private" does
/// not describe.
#[test]
fn test_read_receipts_setting() {
    let setting = |config: crate::server::config::Config| {
        let server = new_test_server(config);
        let (_, frame) = dial_raw(&server);
        frame["params"].as_object().unwrap()["ext"]
            .as_object()
            .unwrap()["settings"]
            .as_object()
            .unwrap()["read_receipts"]
            .clone()
    };
    assert_eq!(setting(default_config()), Json::from("private"));
    let mut everyone = default_config();
    everyone.read_receipts = true;
    assert_eq!(setting(everyone), Json::from(false));
}
