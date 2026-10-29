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

/// A read cursor goes to the user's other connections only, within its own
/// allowance, and room_list follows with the user's own cursor alone; no
/// read receipts.
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
    let notices: Vec<String> = own
        .iter()
        .filter(|f| f.get("method") == Some(&Json::from("message")))
        .map(|f| {
            notification_params(f, "message")["body"]
                .as_object()
                .unwrap()["text"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        notices,
        vec!["Typing updates are limited to 10 per minute, so others may not see you typing for a moment."]
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
