//! Posting limits, apron-server-cloudflare's (its SPEC.md, section 6,
//! Posting and registration), after its quota.integration.test.ts.

use super::helpers::*;
use crate::obj;
use crate::server::config::Config;
use crate::server::limits::{Limits, Posts};
use crate::server::protocol::*;

fn proxied(limits: Limits) -> TestServer {
    new_test_server(Config {
        limits,
        client_ip_header: "Cf-Connecting-IP".into(),
        ..default_config()
    })
}

fn posts(minute: u32, day: u32) -> Posts {
    Posts { minute, day }
}

/// A guest signed in from `ip`.
fn guest_from(server: &TestServer, ip: &str) -> TestClient {
    let (mut c, _) = dial_headers(server, &[("Cf-Connecting-IP", ip)]);
    guest_auth(&mut c);
    c.drain();
    c
}

/// An account (an invited user, in memory) signed in from `ip`.
fn account_from(server: &TestServer, ip: &str) -> TestClient {
    let c = guest_from(server, ip);
    make_account(server, &c.user_id);
    c
}

fn post(c: &mut TestClient) -> Object {
    let id = c.next_id("post");
    reply(
        c,
        "message",
        &id,
        obj! {"room_id" => "general", "body" => obj! {"text" => "bounded"}},
    )
}

fn posted(c: &mut TestClient) -> String {
    let frame = post(c);
    frame
        .get("result")
        .and_then(Json::as_object)
        .and_then(|r| r.get("message_id"))
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("post refused: {frame:?}"))
        .to_owned()
}

fn refused(frame: &Object) -> (String, i64) {
    let (message, data) = retry_after_of(frame);
    let Json::Number(seconds) = data["retry_after"] else {
        panic!("retry_after {data:?}")
    };
    (message, seconds as i64)
}

#[test]
fn test_guests_of_one_address_share_their_allowance() {
    let server = proxied(Limits {
        guest_posts: posts(5, 0),
        ..Limits::unlimited()
    });
    for _ in 0..5 {
        posted(&mut guest_from(&server, "198.51.100.1"));
    }
    let mut fresh = guest_from(&server, "198.51.100.1");
    let (message, wait) = refused(&post(&mut fresh));
    // Five a minute drain one every 12 s.
    assert_eq!(message, "Guest posting limit reached");
    assert!((11..=12).contains(&wait), "retry_after {wait}");
    posted(&mut guest_from(&server, "198.51.100.2"));
}

#[test]
fn test_accounts_post_their_own_minute_under_the_address_minute() {
    let server = proxied(Limits {
        posts: posts(20, 0),
        ip_posts: posts(30, 0),
        ..Limits::unlimited()
    });
    let mut a = account_from(&server, "203.0.113.5");
    let mut b = account_from(&server, "203.0.113.5");
    for _ in 0..20 {
        posted(&mut a);
    }
    assert_eq!(refused(&post(&mut a)).0, "Posting limit reached");
    for _ in 0..10 {
        posted(&mut b);
    }
    assert_eq!(refused(&post(&mut b)).0, "Posting limit reached");
}

#[test]
fn test_any_role_gives_trusted_limits_for_the_address_too() {
    let server = proxied(Limits {
        posts: posts(20, 0),
        trusted_posts: posts(50, 0),
        ip_posts: posts(30, 0),
        server_posts: posts(110, 0),
        ..Limits::unlimited()
    });
    let mut moderator = account_from(&server, "192.0.2.1");
    grant_role(&server, &moderator.user_id, "mod");
    let mut friend = account_from(&server, "192.0.2.2");
    grant_role(&server, &friend.user_id, "friend");
    for _ in 0..50 {
        posted(&mut moderator);
    }
    assert_eq!(refused(&post(&mut moderator)).0, "Posting limit reached");
    for _ in 0..50 {
        posted(&mut friend);
    }
    // The server's 110 still holds: a third trusted account gets the 10 left.
    let mut admin = account_from(&server, "192.0.2.3");
    grant_role(&server, &admin.user_id, "admin");
    for _ in 0..10 {
        posted(&mut admin);
    }
    assert_eq!(refused(&post(&mut admin)).0, "Posting limit reached");

    // Without the role, the account limit counts what was spent under it.
    let server = proxied(Limits {
        posts: posts(20, 0),
        trusted_posts: posts(50, 0),
        ..Limits::unlimited()
    });
    let mut moderator = account_from(&server, "192.0.2.1");
    grant_role(&server, &moderator.user_id, "mod");
    for _ in 0..20 {
        posted(&mut moderator);
    }
    revoke_role(&server, &moderator.user_id, "mod");
    assert_eq!(refused(&post(&mut moderator)).0, "Posting limit reached");
}

/// Every accepted change counts, a reaction, a join, a leave, a room and a
/// name alike; one that changes nothing and a deduplicated retry do not.
#[test]
fn test_every_change_is_a_post_and_no_change_is_none() {
    let server = proxied(Limits {
        trusted_posts: posts(7, 0),
        ..Limits::unlimited()
    });
    let mut a = account_from(&server, "198.51.100.9");
    grant_role(&server, &a.user_id, "mod");
    let message_id = posted(&mut a);
    let room = reply(&mut a, "room_set", "room", obj! {"title" => "Quota"});
    let room_id = room["result"].as_object().unwrap()["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let charged = [
        (
            "reactions",
            obj! {"message_id" => message_id.as_str(), "emojis" => strings(&["👍"])},
        ),
        ("room_leave", obj! {"room_id" => room_id.as_str()}),
        ("room_join", obj! {"room_id" => room_id.as_str()}),
        ("me", obj! {"name" => "Renamed"}),
    ];
    let free = [
        (
            "reactions",
            obj! {"message_id" => message_id.as_str(), "emojis" => strings(&["👍"])},
        ),
        ("room_join", obj! {"room_id" => room_id.as_str()}),
        ("me", obj! {"name" => "Renamed"}),
    ];
    for (i, (method, params)) in charged.into_iter().chain(free).enumerate() {
        let frame = reply(&mut a, method, &format!("r{i}"), params);
        assert!(frame.contains_key("result"), "{method}: {frame:?}");
    }
    // A post, a room and four changes of seven: one post is left, and its
    // retry is free.
    let retry = obj! {"room_id" => "general", "body" => obj! {"text" => "once"}};
    for _ in 0..2 {
        let frame = reply(&mut a, "message", "same-id", retry.clone());
        assert!(frame.contains_key("result"), "{frame:?}");
    }
    let (message, _) = refused(&reply(
        &mut a,
        "reactions",
        "over",
        obj! {"message_id" => message_id.as_str(), "emojis" => strings(&["🎉"])},
    ));
    assert_eq!(message, "Posting limit reached");
    let (message, _) = refused(&reply(
        &mut a,
        "room_leave",
        "leave",
        obj! {"room_id" => room_id.as_str()},
    ));
    assert_eq!(message, "Posting limit reached");
    let (message, _) = refused(&reply(&mut a, "me", "name", obj! {"name" => "Again"}));
    assert_eq!(message, "Posting limit reached");
}

#[test]
fn test_daily_limits_name_whose_day_is_full() {
    let server = proxied(Limits {
        posts: posts(0, 2),
        server_posts: posts(0, 3),
        ..Limits::unlimited()
    });
    let mut poster = account_from(&server, "198.51.100.20");
    posted(&mut poster);
    posted(&mut poster);
    let (message, wait) = refused(&post(&mut poster));
    assert_eq!(message, "Daily posting limit reached");
    let to_midnight = 86_400 - rust_stdlib::time::now().unix() % 86_400;
    assert!(
        (to_midnight - 2..=to_midnight).contains(&wait),
        "{wait} vs {to_midnight}"
    );
    let mut other = account_from(&server, "198.51.100.21");
    posted(&mut other);
    assert_eq!(
        refused(&post(&mut other)).0,
        "Daily posting limit reached for the server"
    );
}
