//! The last-seen tests of status_test.go, test by test. Each keeps the Go
//! test's name, tables, and literal expectations.

use std::sync::Arc;

use rust_stdlib::time::{self};

use super::helpers::*;
use crate::obj;
use crate::server::protocol::*;
use crate::store::{self, Store};

use super::persist_test::start_with_store;
use super::status_test::{
    add_account, check_seen, coalescing, expect_listed_seen, expect_no_seen, expect_profile_status,
    expect_seen_between, expect_status, listed_objects, resume, seen_after, seen_millis,
    set_status, status_id, wait_connections, wait_stored,
};
use super::webauthn_test::*;

/// never does. The next change to offline brings a later seen.
#[test]
fn test_seen_on_disconnect() {
    let server = passkey_test_server();
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut b, &mut new_test_authenticator());
    let (token, user_id) = (registered["token"].clone(), b.user_id.clone());
    expect_registered(&a, &user_id);
    watching(&mut [&mut a]);
    a.drain();
    b.drain();
    // Never offline since it signed up, so no seen yet.
    expect_listed_seen(&mut a, &user_id, "online", "");

    drop(b);
    let seen = expect_status(&a, &user_id, "offline");
    expect_listed_seen(&mut a, &user_id, "offline", &seen);
    // A newcomer learns seen from a listing; its snapshot after auth leaves
    // offline users out.
    let (mut g, _) = dial_raw(&server);
    guest_auth(&mut g);
    g.drain();
    expect_listed_seen(&mut g, &user_id, "offline", &seen);
    a.drain();

    // Back online: no seen, in the announcement or in listings, and none in
    // the user's own you.
    time::sleep(time::MILLISECOND * 2);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let resumed = b.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => token.clone()},
    );
    expect_no_seen("you after a reconnect", &resumed["you"]);
    b.user_id = user_id.clone();
    expect_status(&a, &user_id, "online");
    expect_listed_seen(&mut a, &user_id, "online", "");
    let (_, own) = listed_objects(&mut b, &user_id);
    assert!(
        !own.contains_key("seen") && own.get("status") == Some(&Json::from("online")),
        "own listed object: {own:?}"
    );
    b.status(obj! {"idle" => 300i64});
    expect_status(&a, &user_id, "idle");
    expect_listed_seen(&mut a, &user_id, "idle", "");
    b.status(obj! {"idle" => false});
    expect_status(&a, &user_id, "online");
    // In order, so each is a change and the last leaves "" for the dnd
    // below to change.
    for status in ["dnd", ""] {
        set_status(&mut b, status);
        expect_profile_status(&a, &user_id, status);
        expect_listed_seen(&mut a, &user_id, status, "");
    }
    // dnd shows offline without a connection, with a new seen.
    set_status(&mut b, "dnd");
    expect_profile_status(&a, &user_id, "dnd");
    drop(b);
    let later = expect_status(&a, &user_id, "offline");
    seen_after(&later, &seen);
    expect_listed_seen(&mut a, &user_id, "offline", &later);
    a.expect_quiet();
}

/// shows them without seen, and a later disconnect brings a new one.
#[test]
fn test_seen_with_invisible() {
    let server = passkey_test_server();
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut b, &mut new_test_authenticator());
    let (token, user_id) = (registered["token"].clone(), b.user_id.clone());
    expect_registered(&a, &user_id);
    watching(&mut [&mut a]);
    a.drain();
    b.drain();
    let (mut other, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    other.result(
        "auth",
        "other",
        obj! {"scheme" => "token", "token" => token.clone()},
    );
    other.drain();
    a.expect_quiet();

    let result = b.result("me", &status_id(), obj! {"status" => "invisible"});
    expect_no_seen("me result", &result["you"]);
    expect_no_seen(
        "you on another connection",
        &other.notification("user")["you"],
    );
    let params = notification_params(&a.read(), "user");
    let profile = params["new"].as_object().unwrap();
    let seen = profile
        .get("seen")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    assert!(
        profile.get("user_id") == Some(&Json::from(user_id.as_str()))
            && profile.get("status") == Some(&Json::from("offline")),
        "profile change to invisible = {profile:?}"
    );
    check_seen(&seen);
    expect_listed_seen(&mut a, &user_id, "offline", &seen);

    // Connections come and go: nothing is sent, and seen stays.
    time::sleep(time::MILLISECOND * 2);
    let (mut third, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let result = third.result(
        "auth",
        "third",
        obj! {"scheme" => "token", "token" => token.clone()},
    );
    expect_no_seen("you of an invisible user", &result["you"]);
    b.status(obj! {"idle" => 300i64});
    drop(third);
    drop(other);
    drop(b);
    wait_connections(&server, &user_id, 0);
    a.expect_quiet();
    expect_listed_seen(&mut a, &user_id, "offline", &seen);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    b.result(
        "auth",
        "back",
        obj! {"scheme" => "token", "token" => token.clone()},
    );
    b.user_id = user_id.clone();
    b.drain();
    a.expect_quiet();
    expect_listed_seen(&mut a, &user_id, "offline", &seen);
    // The user's own listed object is the shown one, seen included; the
    // chosen status is in you.
    let (_, own) = listed_objects(&mut b, &user_id);
    assert!(
        own.get("status") == Some(&Json::from("offline"))
            && own.get("seen") == Some(&Json::from(seen.as_str())),
        "own listed object while invisible: {own:?}"
    );

    set_status(&mut b, "online");
    let params = notification_params(&a.read(), "user");
    let profile = params["new"].as_object().unwrap();
    assert!(
        profile.get("status") == Some(&Json::from("online")) && !profile.contains_key("seen"),
        "profile change to online = {profile:?}"
    );
    expect_listed_seen(&mut a, &user_id, "online", "");
    drop(b);
    seen_after(&expect_status(&a, &user_id, "offline"), &seen);
}

/// was kept, is listed without it.
#[test]
fn test_seen_survives_restart() {
    let dir = TempDir::new("apron-seen-");
    let path = format!("{dir}/aprond.db");
    let uploads = format!("{dir}/uploads");
    let open = || -> Arc<dyn Store> { Arc::new(store::SQLite::open(&path).unwrap()) };
    let mut server = start_with_store(open(), &uploads);
    let (mut a, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    register_test_passkey(&mut a, &mut new_test_authenticator());
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut b, &mut new_test_authenticator());
    let user_id = b.user_id.clone();
    expect_registered(&a, &user_id);
    add_account(&server, "never", &[&a, &b]);
    watching(&mut [&mut a]);
    a.drain();
    set_status(&mut b, "invisible");
    expect_profile_status(&a, &user_id, "offline");
    let (_, user) = listed_objects(&mut a, &user_id);
    let seen = user
        .get("seen")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    check_seen(&seen);
    expect_listed_seen(&mut a, "never", "offline", "");
    server.stop();

    let server = start_with_store(open(), &uploads);
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let result = c.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => registered["token"].clone()},
    );
    let you = &result["you"];
    assert_eq!(
        you.as_object().unwrap()["status"],
        Json::from("invisible"),
        "you after restart: {you:?}"
    );
    expect_no_seen("you after restart", you);
    c.user_id = user_id.clone();
    c.drain();
    expect_listed_seen(&mut c, &user_id, "offline", &seen);
    expect_listed_seen(&mut c, "never", "offline", "");
    drop((a, b, c, server));
}

/// A coalesced offline carries the seen of when the user became offline,
/// not when it was sent (§4.5.2).
#[test]
fn test_coalesced_offline_carries_seen() {
    let server = new_test_server(coalescing(600, 0));
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    register_test_passkey(&mut b, &mut new_test_authenticator());
    let user_id = b.user_id.clone();
    expect_registered(&a, &user_id);
    watching(&mut [&mut a]);
    a.drain();
    let closing = time::now().unix_milli();
    drop(b);
    wait_connections(&server, &user_id, 0);
    let closed = time::now().unix_milli();
    a.expect_quiet();
    time::sleep(time::MILLISECOND * 800);
    let seen = expect_status(&a, &user_id, "offline");
    expect_seen_between("coalesced offline", &seen, closing, closed);
    expect_listed_seen(&mut a, &user_id, "offline", &seen);
    a.expect_quiet();
}

/// nobody sees seen change while the shown status stays offline (§4.5.2).
#[test]
fn test_hidden_flap_keeps_seen() {
    let server = new_test_server(coalescing(500, 0));
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let token = register_test_passkey(&mut b, &mut new_test_authenticator())["token"].clone();
    let user_id = b.user_id.clone();
    expect_registered(&a, &user_id);
    watching(&mut [&mut a]);
    a.drain();
    // b's online went out at its sign-in; a window later, its offline goes
    // at once, and starts a new window.
    time::sleep(time::MILLISECOND * 600);
    drop(b);
    let seen = expect_status(&a, &user_id, "offline");
    expect_listed_seen(&mut a, &user_id, "offline", &seen);

    time::sleep(time::MILLISECOND * 2);
    let flap = resume(&server, &token, &user_id);
    a.expect_quiet();
    // Until the change is sent, a listing shows what was last announced.
    expect_listed_seen(&mut a, &user_id, "offline", &seen);
    time::sleep(time::MILLISECOND * 2);
    drop(flap);
    wait_connections(&server, &user_id, 0);
    a.expect_quiet();
    expect_listed_seen(&mut a, &user_id, "offline", &seen);
    time::sleep(time::MILLISECOND * 700);
    a.expect_quiet();
    expect_listed_seen(&mut a, &user_id, "offline", &seen);
    let kept = server.app.lock().users[&user_id].seen;
    assert_eq!(
        kept,
        seen_millis(&seen),
        "seen after a hidden flap = {kept}, want {seen}"
    );
}

/// The last one's close sets a later seen.
#[test]
fn test_seen_only_with_the_last_connection() {
    let server = passkey_test_server();
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let token = register_test_passkey(&mut b, &mut new_test_authenticator())["token"].clone();
    let user_id = b.user_id.clone();
    expect_registered(&a, &user_id);
    watching(&mut [&mut a]);
    a.drain();
    drop(b);
    let seen = expect_status(&a, &user_id, "offline");

    time::sleep(time::MILLISECOND * 2);
    let first = resume(&server, &token, &user_id);
    expect_status(&a, &user_id, "online");
    let second = resume(&server, &token, &user_id);
    a.expect_quiet();
    drop(first);
    wait_connections(&server, &user_id, 1);
    a.expect_quiet();
    expect_listed_seen(&mut a, &user_id, "online", "");
    let kept = server.app.lock().users[&user_id].seen;
    assert_eq!(
        kept,
        seen_millis(&seen),
        "seen after closing one of two connections = {kept}, want {seen}"
    );

    drop(second);
    let later = expect_status(&a, &user_id, "offline");
    seen_after(&later, &seen);
    expect_listed_seen(&mut a, &user_id, "offline", &later);
}

/// seen, before the status of the second (§4.5.2).
#[test]
fn test_seen_when_the_last_connection_signs_in_elsewhere() {
    let server = passkey_test_server();
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    register_test_passkey(&mut b, &mut new_test_authenticator());
    expect_registered(&a, &b.user_id);
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let other = register_test_passkey(&mut c, &mut new_test_authenticator());
    let c_id = c.user_id.clone();
    expect_registered(&a, &c_id);
    watching(&mut [&mut a]);
    a.drain();
    drop(c);
    expect_status(&a, &c_id, "offline");

    b.drain();
    let switching = time::now().unix_milli();
    b.result(
        "auth",
        "elsewhere",
        obj! {"scheme" => "token", "token" => other["token"].clone()},
    );
    let switched = time::now().unix_milli();
    let seen = expect_status(&a, &b.user_id, "offline");
    expect_seen_between("the account left", &seen, switching, switched);
    expect_status(&a, &c_id, "online");
    a.expect_quiet();
    expect_listed_seen(&mut a, &b.user_id, "offline", &seen);
}

/// user_id.
#[test]
fn test_listings_carry_seen() {
    let server = passkey_test_server();
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    register_test_passkey(&mut b, &mut new_test_authenticator());
    let user_id = b.user_id.clone();
    expect_registered(&a, &user_id);
    grant_role(&server, &b.user_id, "mod");
    let (room, _) = save_room(&mut b, "room", obj! {"title" => "Room"});
    watching(&mut [&mut a]);
    a.drain();
    drop(b);
    let seen = expect_status(&a, &user_id, "offline");
    let check = |what: &str, lists: &[&[Json]]| {
        for list in lists {
            let found = list
                .iter()
                .filter_map(Json::as_object)
                .rfind(|o| o.get("user_id") == Some(&Json::from(user_id.as_str())));
            assert!(
                found.is_some_and(|o| o.get("status") == Some(&Json::from("offline"))
                    && o.get("seen") == Some(&Json::from(seen.as_str()))),
                "{what}: {list:?}, want {user_id} offline with seen {seen}"
            );
        }
    };

    let (before, _) = a.request("room_join", "join", obj! {"room_id" => room.as_str()});
    let update = notification_params(&before[0], "room_update");
    let joined = update["joined"].as_list()[0].as_object().unwrap();
    check(
        "room_update joined",
        &[joined["members"].as_list(), update["users"].as_list()],
    );
    let listed = list_rooms(
        &mut a,
        obj! {"room_id" => room.as_str(), "members" => true, "user_id" => user_id.as_str()},
    );
    let members = listed["joined"].as_list()[0].as_object().unwrap()["members"].as_list();
    assert!(
        members.len() == 1,
        "room_list members for {user_id}: {members:?}"
    );
    check(
        "room_list by user_id",
        &[members, listed["users"].as_list()],
    );
}

/// one that never connected stays without seen.
#[test]
fn test_seen_after_crash() {
    let dir = TempDir::new("apron-crash-seen-");
    let path = format!("{dir}/aprond.db");
    let uploads = format!("{dir}/uploads");
    let open = || -> Arc<dyn Store> { Arc::new(store::SQLite::open(&path).unwrap()) };
    let server = start_with_store(open(), &uploads);
    let mut a = dial_test_client(&server);
    let sign_up = |a: &TestClient| {
        let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
        let token = register_test_passkey(&mut c, &mut new_test_authenticator())["token"].clone();
        expect_registered(a, &c.user_id);
        (c, token)
    };
    let (mut back, token) = sign_up(&a);
    let (mut fresh, _) = sign_up(&a);
    let (mut hidden, _) = sign_up(&a);
    let (mut none, _) = sign_up(&a);
    add_account(&server, "never", &[&a]);
    watching(&mut [&mut a]);
    for c in [&mut a, &mut back, &mut fresh, &mut hidden, &mut none] {
        c.drain();
    }

    let back_id = back.user_id.clone();
    drop(back);
    let left = seen_millis(&expect_status(&a, &back_id, "offline"));
    time::sleep(time::MILLISECOND * 2);
    let back = resume(&server, &token, &back_id);
    expect_status(&a, &back.user_id, "online");
    let returned = time::now().unix_milli();
    set_status(&mut hidden, "invisible");
    expect_profile_status(&a, &hidden.user_id, "offline");
    let (_, user) = listed_objects(&mut a, &hidden.user_id);
    let hidden_seen = user
        .get("seen")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    none.drain();
    set_status(&mut none, "");
    expect_profile_status(&a, &none.user_id, "");

    // The store has all of it, and the server crashes: it goes on running,
    // unseen, while another starts on the same file.
    wait_stored(&path, &back.user_id, |u| u.shown && u.seen == left);
    wait_stored(&path, &fresh.user_id, |u| u.shown && u.seen == 0);
    let hidden_ms = seen_millis(&hidden_seen);
    wait_stored(&path, &hidden.user_id, |u| !u.shown && u.seen == hidden_ms);
    wait_stored(&path, &none.user_id, |u| u.shown && u.seen == 0);
    let crashed = time::now().unix_milli();
    let restarted = start_with_store(open(), &uploads);
    let restored = time::now().unix_milli();
    let mut g = dial_test_client(&restarted);
    g.drain();
    for id in [back.user_id.as_str(), fresh.user_id.as_str()] {
        let (_, user) = listed_objects(&mut g, id);
        let seen = user
            .get("seen")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned();
        expect_seen_between(
            &format!("{id} after a crash"),
            &seen,
            crashed.max(returned),
            restored,
        );
        expect_listed_seen(&mut g, id, "offline", &seen);
        let ms = seen_millis(&seen);
        wait_stored(&path, id, |u| !u.shown && u.seen == ms);
    }
    expect_listed_seen(&mut g, &hidden.user_id, "offline", &hidden_seen);
    expect_listed_seen(&mut g, &none.user_id, "", "");
    expect_listed_seen(&mut g, "never", "offline", "");
    drop((g, a, back, fresh, hidden, none, restarted, server));
}
