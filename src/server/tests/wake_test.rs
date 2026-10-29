//! When a message wakes whom (wake.rs), ported from apron-server-cloudflare's
//! `push.integration.test.ts`: "push delay", "held wakes", and the store's
//! coalescing and `wakesPerMessage` cases.

use rust_stdlib::time::{self, Duration};

use super::helpers::*;
use super::push_test::*;
use super::webauthn_test::{new_test_authenticator, register_test_passkey, TEST_PASSKEY_ORIGIN};
use crate::obj;
use crate::server::config::Config;
use crate::server::protocol::*;
use crate::server::push::{PushHosts, WakeScope};

const DELAY: Duration = Duration::from_millis(300);

fn wake_config(delay: Duration) -> Config {
    let mut config = default_config();
    config.allow_insecure_push = true;
    config.push_hosts = PushHosts::Any;
    config.push_delay = delay;
    config.web_authn = Some(super::webauthn_test::test_web_authn());
    config
}

/// A server whose wakes wait `delay`, with the default coalescing windows.
fn wake_server(delay: Duration) -> TestServer {
    let server = new_test_server(wake_config(delay));
    server.app.lock().badge_delay = Duration::from_secs(0);
    server
}

/// Registers a relay endpoint `<relay>/<name>` for c's user.
fn subscribe(c: &mut TestClient, relay: &TestRelay, name: &str) {
    c.drain();
    let id = c.next_id("subscribe");
    c.result(
        "push_register",
        &id,
        obj! {"kind" => "relay", "url" => format!("{}/{name}", relay.url)},
    );
}

/// An account on the passkey origin, and the session token that signs
/// another connection in as it.
fn passkey_account(server: &TestServer) -> (TestClient, String) {
    let (mut c, _) = dial_origin(server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut c, &mut new_test_authenticator());
    c.user_id = super::admin_test::user_id_of(&registered);
    c.drain();
    (c, registered["token"].as_str().unwrap().to_owned())
}

fn second_connection(server: &TestServer, user_id: &str, token: &str) -> TestClient {
    let (mut c, _) = dial_origin(server, TEST_PASSKEY_ORIGIN);
    super::admin_test::token_auth(&mut c, token);
    c.user_id = user_id.to_owned();
    c.drain();
    c
}

fn idle_for(c: &mut TestClient, seconds: i64) {
    c.drain();
    let frames = c.status(obj! {"idle" => seconds});
    assert!(frames.is_empty(), "frames after idle: {frames:?}");
}

fn back(c: &mut TestClient) {
    c.drain();
    c.status(obj! {"idle" => false});
}

fn mention(room_id: &str, text: &str, users: &[&str]) -> Object {
    obj! {"room_id" => room_id, "body" => obj! {"text" => text, "mentions" => list(users)}}
}

fn post(c: &mut TestClient, params: Object) -> String {
    let id = c.next_id("post");
    save(c, &id, params).0
}

fn thread(c: &mut TestClient, title: &str) -> String {
    let id = c.next_id("thread");
    save_room(
        c,
        &id,
        obj! {"parent_room_id" => "general", "title" => title},
    )
    .0
}

/// Waits out DELAY, with room to spare, so a push that was due has gone.
fn wait_out() {
    time::sleep(DELAY + Duration::from_millis(400));
}

#[test]
fn test_push_waits_for_those_still_away() {
    let relay = new_test_relay();
    let server = wake_server(DELAY);
    let mut alice = push_client(&server);
    let mut clients: Vec<TestClient> = (0..4).map(|_| push_client(&server)).collect();
    let (mut joiner, token) = passkey_account(&server);
    for (c, name) in clients.iter_mut().zip(["stay", "back", "post", "other"]) {
        subscribe(c, &relay, name);
        go_idle(c);
    }
    subscribe(&mut joiner, &relay, "join");
    go_idle(&mut joiner);
    let ids: Vec<String> = clients.iter().map(|c| c.user_id.clone()).collect();
    let id = |i: usize| ids[i].as_str();
    alice.drain();
    let room = thread(&mut alice, "Delay");
    let joiner_id = joiner.user_id.clone();
    post(
        &mut alice,
        mention("general", "around?", &[id(0), id(1), id(2), &joiner_id]),
    );
    post(&mut alice, mention(&room, "and you?", &[id(3), id(2)]));
    assert!(
        relay.pushes(&server, &mut alice).is_empty(),
        "pushed before the wait"
    );
    // One comes back, one posts in general, and one signs in again,
    // attended.
    back(&mut clients[1]);
    clients[2].drain();
    post(
        &mut clients[2],
        obj! {"room_id" => "general", "body" => obj! {"text" => "here"}},
    );
    let _again = second_connection(&server, &joiner_id, &token);
    wait_out();
    // Only general's wake is dropped for the poster: their mention in the
    // thread still pushes.
    assert_eq!(
        paths(&relay.pushes(&server, &mut alice)),
        strs(&["/other", "/post", "/stay"]),
        "pushes after the wait"
    );
    wait_out();
    assert!(relay.pushes(&server, &mut alice).is_empty(), "pushed again");
}

#[test]
fn test_dropped_wake_spends_no_coalescing() {
    let relay = new_test_relay();
    let server = wake_server(DELAY);
    let mut alice = push_client(&server);
    let mut bob = push_client(&server);
    subscribe(&mut bob, &relay, "bob");
    go_idle(&mut bob);
    let bob_id = bob.user_id.clone();
    alice.drain();
    post(&mut alice, mention("general", "one", &[&bob_id]));
    // Back, then away again before the wait is over: he was there, so the
    // wake is gone.
    back(&mut bob);
    idle_for(&mut bob, 0);
    wait_out();
    assert!(
        relay.pushes(&server, &mut alice).is_empty(),
        "a dropped wake pushed"
    );
    // The next mention in the same room is pushed, not coalesced away.
    post(&mut alice, mention("general", "two", &[&bob_id]));
    wait_out();
    let got = relay.pushes(&server, &mut alice);
    assert_eq!(paths(&got), strs(&["/bob"]));
    assert_eq!(
        got[0].message()["body"].as_object().unwrap()["text"],
        Json::from("two")
    );
}

#[test]
fn test_push_is_the_message_as_it_is_when_the_wait_ends() {
    let relay = new_test_relay();
    let server = wake_server(DELAY);
    let mut alice = push_client(&server);
    let mut bob = push_client(&server);
    let mut carol = push_client(&server);
    subscribe(&mut bob, &relay, "bob");
    subscribe(&mut carol, &relay, "carol");
    go_idle(&mut bob);
    go_idle(&mut carol);
    let (bob_id, carol_id) = (bob.user_id.clone(), carol.user_id.clone());
    alice.drain();
    // Deleted within the wait: the text it had is never pushed.
    let secret = post(&mut alice, mention("general", "oops, a secret", &[&bob_id]));
    post(
        &mut alice,
        obj! {"message_id" => secret.as_str(), "deleted" => true},
    );
    wait_out();
    assert!(
        relay.pushes(&server, &mut alice).is_empty(),
        "a deleted message pushed"
    );
    // Edited within the wait: pushed as edited, to Bob, whom it still
    // mentions, and not to Carol.
    let typo = post(
        &mut alice,
        mention("general", "hi bob and carol", &[&bob_id, &carol_id]),
    );
    let mut edit = mention("general", "hi bob", &[&bob_id]);
    edit.insert("message_id".into(), typo.as_str().into());
    post(&mut alice, edit);
    wait_out();
    let got = relay.pushes(&server, &mut alice);
    assert_eq!(paths(&got), strs(&["/bob"]));
    assert_eq!(
        got[0].message()["body"].as_object().unwrap()["text"],
        Json::from("hi bob")
    );
}

/// Cloudflare's "spends wake slots only on users with live registrations,
/// and coalesces per user and room", and its joined window.
#[test]
fn test_wakes_coalesce_per_user_and_room() {
    let relay = new_test_relay();
    let server = wake_server(Duration::from_secs(0));
    let mut alice = push_client(&server);
    let mut bob = push_client(&server);
    subscribe(&mut bob, &relay, "bob");
    go_idle(&mut bob);
    let bob_id = bob.user_id.clone();
    alice.drain();
    let room = thread(&mut alice, "Elsewhere");
    post(&mut alice, mention("general", "one", &[&bob_id]));
    post(&mut alice, mention("general", "two", &[&bob_id]));
    post(&mut alice, mention(&room, "three", &[&bob_id]));
    let texts = |got: &[RelayRequest]| -> Vec<String> {
        got.iter()
            .map(|r| {
                r.message()["body"].as_object().unwrap()["text"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    };
    let mut got = texts(&relay.pushes(&server, &mut alice));
    got.sort();
    assert_eq!(got, strs(&["one", "three"]), "one wake a room a minute");
    let rewind = |seconds: i64| {
        let mut st = server.app.lock();
        let woken = st
            .push_woken
            .get_mut(&(bob_id.clone(), "general".to_owned()))
            .unwrap();
        *woken = woken.add(-Duration::from_secs(seconds));
    };
    rewind(59);
    post(&mut alice, mention("general", "four", &[&bob_id]));
    assert!(
        relay.pushes(&server, &mut alice).is_empty(),
        "woken within the minute"
    );
    rewind(2);
    post(&mut alice, mention("general", "five", &[&bob_id]));
    assert_eq!(texts(&relay.pushes(&server, &mut alice)), strs(&["five"]));

    // One pushed only for joined is woken once in five minutes.
    let mut moderator = push_client(&server);
    grant_role(&server, &moderator.user_id, "mod");
    let mod_id = moderator.user_id.clone();
    moderator.drain();
    moderator.result(
        "push_register",
        "joined",
        obj! {"kind" => "relay", "url" => format!("{}/mod", relay.url), "wake" => list(&["joined"])},
    );
    go_idle(&mut moderator);
    alice.drain();
    post(&mut alice, obj! {"body" => obj! {"text" => "chatter"}});
    assert_eq!(paths(&relay.pushes(&server, &mut alice)), strs(&["/mod"]));
    let rewind_mod = |seconds: i64| {
        let mut st = server.app.lock();
        let woken = st
            .push_woken
            .get_mut(&(mod_id.clone(), "general".to_owned()))
            .unwrap();
        *woken = woken.add(-Duration::from_secs(seconds));
    };
    rewind_mod(61);
    post(&mut alice, obj! {"body" => obj! {"text" => "more chatter"}});
    assert!(
        relay.pushes(&server, &mut alice).is_empty(),
        "joined woken within five minutes"
    );
    rewind_mod(240);
    post(&mut alice, obj! {"body" => obj! {"text" => "still more"}});
    assert_eq!(paths(&relay.pushes(&server, &mut alice)), strs(&["/mod"]));
}

/// Cloudflare's "wakes at most wakesPerMessage users for one message": users
/// with no registration that wakes, or none on an allowed host, take no
/// wake.
#[test]
fn test_wakes_at_most_ten_users_a_message() {
    let relay = new_test_relay();
    let mut config = wake_config(Duration::from_secs(0));
    config.push_hosts = PushHosts::parse(&strs(&["127.0.0.1"])).unwrap();
    let server = new_test_server(config);
    let mut alice = push_client(&server);
    let port = relay.url.rsplit_once(':').unwrap().1.to_owned();
    let mut users = Vec::new();
    for i in 0..14 {
        let user_id = format!("user{i:02}");
        super::status_test::add_account(&server, &user_id, &[]);
        let url = match i {
            // No registration that wakes for a mention, and one on a host
            // --push.hosts no longer allows.
            0 => format!("{}/{user_id}", relay.url),
            1 => format!("http://localhost:{port}/{user_id}"),
            _ => format!("{}/{user_id}", relay.url),
        };
        let wake = if i == 0 {
            WakeScope::PRIVATE
        } else {
            WakeScope::DEFAULT
        };
        add_push(&server, &user_id, relay_push(url, wake));
        users.push(user_id);
    }
    alice.drain();
    let mentioned: Vec<&str> = users.iter().map(String::as_str).collect();
    post(&mut alice, mention("general", "everyone", &mentioned));
    let want: Vec<String> = users[2..12].iter().map(|id| format!("/{id}")).collect();
    assert_eq!(
        paths(&relay.pushes(&server, &mut alice)),
        want,
        "the first ten who wake"
    );
}

#[test]
fn test_held_wakes_pushed_when_idle_if_they_came_after_attention() {
    let relay = new_test_relay();
    let server = wake_server(Duration::from_secs(0));
    let mut alice = push_client(&server);
    let mut bob = push_client(&server);
    let mut carol = push_client(&server);
    let mut dave = push_client(&server);
    for (c, name) in [
        (&mut bob, "bob"),
        (&mut carol, "carol"),
        (&mut dave, "dave"),
    ] {
        subscribe(c, &relay, name);
    }
    alice.drain();
    // All three are attended: nothing goes.
    let held = post(
        &mut alice,
        mention(
            "general",
            "look",
            &[&bob.user_id, &carol.user_id, &dave.user_id],
        ),
    );
    assert!(
        relay.pushes(&server, &mut alice).is_empty(),
        "attended users pushed"
    );
    // Bob was last attended a minute ago, before it came: it is pushed now.
    idle_for(&mut bob, 60);
    let got = relay.pushes(&server, &mut alice);
    assert_eq!(paths(&got), strs(&["/bob"]));
    assert_eq!(got[0].message()["message_id"], Json::from(held.as_str()));
    // Carol and Dave were attended until now, after it came: neither is
    // pushed.
    idle_for(&mut carol, 0);
    idle_for(&mut dave, 0);
    assert!(
        relay.pushes(&server, &mut alice).is_empty(),
        "pushed what came while attended"
    );
    // Released once: back and idle again pushes nothing more.
    back(&mut bob);
    idle_for(&mut bob, 120);
    assert!(
        relay.pushes(&server, &mut alice).is_empty(),
        "released twice"
    );
}

#[test]
fn test_held_wakes_skip_rooms_posted_in_and_wait_for_the_last_connection() {
    let relay = new_test_relay();
    let server = wake_server(Duration::from_secs(0));
    let mut alice = push_client(&server);
    let (mut bob, token) = passkey_account(&server);
    let bob_id = bob.user_id.clone();
    let mut phone = second_connection(&server, &bob_id, &token);
    subscribe(&mut bob, &relay, "bob");
    alice.drain();
    let room = thread(&mut alice, "Held");
    post(&mut alice, mention(&room, "and here", &[&bob_id]));
    post(&mut alice, mention("general", "here", &[&bob_id]));
    // Bob answers in general: he saw that one.
    bob.drain();
    post(
        &mut bob,
        obj! {"room_id" => "general", "body" => obj! {"text" => "yes"}},
    );
    // One connection goes idle while the other is attended: nothing yet.
    idle_for(&mut bob, 60);
    assert!(
        relay.pushes(&server, &mut alice).is_empty(),
        "pushed while attended"
    );
    phone.drain();
    idle_for(&mut phone, 60);
    let got = relay.pushes(&server, &mut alice);
    assert_eq!(paths(&got), strs(&["/bob"]));
    assert_eq!(got[0].message()["room_id"], Json::from(room.as_str()));
}

#[test]
fn test_held_wakes_send_one_push_the_newest_that_wakes() {
    let relay = new_test_relay();
    let server = wake_server(Duration::from_secs(0));
    let mut alice = push_client(&server);
    let mut bob = push_client(&server);
    subscribe(&mut bob, &relay, "bob");
    let bob_id = bob.user_id.clone();
    alice.drain();
    let rooms: Vec<String> = ["One", "Two", "Three", "Four"]
        .iter()
        .map(|t| thread(&mut alice, t))
        .collect();
    let mut ids = Vec::new();
    for (room, text) in rooms.iter().zip(["first", "second", "third", "fourth"]) {
        ids.push(post(&mut alice, mention(room, text, &[&bob_id])));
    }
    // The newest is deleted: the next newest stands for them.
    post(
        &mut alice,
        obj! {"message_id" => ids[3].as_str(), "deleted" => true},
    );
    // Bob muted the third's room: the one before stands in for it.
    bob.drain();
    bob.status(obj! {"room_id" => rooms[2].as_str(), "mute" => true});
    idle_for(&mut bob, 60);
    let got = relay.pushes(&server, &mut alice);
    assert_eq!(paths(&got), strs(&["/bob"]), "one push");
    assert_eq!(
        got[0].message()["body"].as_object().unwrap()["text"],
        Json::from("second")
    );
}

/// A user holds at most MAX_HELD_WAKES, 8; the oldest go first.
#[test]
fn test_held_wakes_keep_the_newest_eight() {
    let relay = new_test_relay();
    let server = wake_server(Duration::from_secs(0));
    let mut alice = push_client(&server);
    let mut bob = push_client(&server);
    subscribe(&mut bob, &relay, "bob");
    let bob_id = bob.user_id.clone();
    alice.drain();
    let rooms: Vec<String> = (0..9)
        .map(|n| thread(&mut alice, &format!("Room {n}")))
        .collect();
    let ids: Vec<String> = rooms
        .iter()
        .map(|room| post(&mut alice, mention(room, "look", &[&bob_id])))
        .collect();
    // All but the first are deleted: it was the ninth held, so it is gone.
    for id in &ids[1..] {
        post(
            &mut alice,
            obj! {"message_id" => id.as_str(), "deleted" => true},
        );
    }
    idle_for(&mut bob, 60);
    assert!(
        relay.pushes(&server, &mut alice).is_empty(),
        "a ninth held wake was kept"
    );
}

/// The default `--push.delay` is 30 seconds: nothing goes at once.
#[test]
fn test_wakes_wait_by_default() {
    let relay = new_test_relay();
    let mut config = default_config();
    config.allow_insecure_push = true;
    config.push_hosts = PushHosts::Any;
    let server = new_test_server(config);
    let mut alice = push_client(&server);
    let mut bob = push_client(&server);
    subscribe(&mut bob, &relay, "bob");
    go_idle(&mut bob);
    let bob_id = bob.user_id.clone();
    alice.drain();
    post(&mut alice, mention("general", "soon", &[&bob_id]));
    time::sleep(Duration::from_millis(200));
    assert!(
        relay.pushes(&server, &mut alice).is_empty(),
        "pushed at once"
    );
    assert_eq!(server.app.lock().pending_wakes.len(), 1, "waiting wakes");
}

#[test]
fn test_no_joined_wake_is_held() {
    let relay = new_test_relay();
    let server = wake_server(Duration::from_secs(0));
    let mut alice = push_client(&server);
    let mut moderator = push_client(&server);
    grant_role(&server, &moderator.user_id, "mod");
    moderator.drain();
    moderator.result(
        "push_register",
        "mod",
        obj! {"kind" => "relay", "url" => format!("{}/mod", relay.url), "wake" => list(&["mentions", "joined"])},
    );
    alice.drain();
    let held = post(
        &mut alice,
        mention("general", "look", &[&moderator.user_id]),
    );
    // More chatter than a user holds, each only for joined: none is held.
    for n in 0..9 {
        post(
            &mut alice,
            obj! {"body" => obj! {"text" => format!("chatter {n}")}},
        );
    }
    assert!(
        relay.pushes(&server, &mut alice).is_empty(),
        "an attended moderator pushed"
    );
    moderator.drain();
    idle_for(&mut moderator, 60);
    let got = relay.pushes(&server, &mut alice);
    assert_eq!(paths(&got), strs(&["/mod"]));
    assert_eq!(got[0].header("Urgency"), "high");
    assert_eq!(got[0].message()["message_id"], Json::from(held.as_str()));
}

/// Shutdown stops the wakes still waiting: a wake lost with the server is
/// not pushed, and none keeps shutdown waiting.
#[test]
fn test_shutdown_stops_waiting_wakes() {
    let relay = new_test_relay();
    let server = wake_server(time::HOUR);
    let mut alice = push_client(&server);
    let mut bob = push_client(&server);
    subscribe(&mut bob, &relay, "bob");
    go_idle(&mut bob);
    let bob_id = bob.user_id.clone();
    alice.drain();
    post(&mut alice, mention("general", "later", &[&bob_id]));
    assert_eq!(server.app.lock().pending_wakes.len(), 1, "waiting wakes");
    let (ctx, cancel) =
        rust_stdlib::context::Context::background().with_timeout(Duration::from_secs(5));
    server
        .app
        .shutdown(&ctx)
        .expect("shutdown with a waiting wake");
    cancel();
    assert!(
        server.app.lock().pending_wakes.is_empty(),
        "wakes after shutdown"
    );
}
