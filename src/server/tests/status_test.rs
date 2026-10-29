//! status_test.go, test by test. Each keeps the Go test's name, tables, and
//! literal expectations.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use rust_stdlib::encoding::json::v2 as json;
use rust_stdlib::time::{self, Time};

use super::helpers::*;
use crate::obj;
use crate::rate::{every, Limiter};
use crate::server::persist::{StoredUser, ENTRY_USER};
use crate::server::protocol::*;
use crate::server::status::*;
use crate::server::webauthn::PasskeyUser;
use crate::store::{self, Store};

use super::email_test::{approve, email_test_server, propose};
use super::persist_test::start_with_store;
use super::webauthn_test::*;

static STATUS_REQUESTS: AtomicI64 = AtomicI64::new(0);

/// A request ID unique across connections, which share a user's
/// deduplication (§1.2).
fn status_id() -> String {
    format!(
        "status-{}",
        STATUS_REQUESTS.fetch_add(1, Ordering::SeqCst) + 1
    )
}

impl TestClient {
    /// Sends a status request, whose result must be {}, and returns the
    /// notifications that precede the result.
    pub(super) fn status(&mut self, params: Object) -> Vec<Object> {
        let (before, result) = self.request("status", &status_id(), params);
        assert!(result.is_empty(), "status result = {result:?}, want {{}}");
        before
    }

    /// Sends a status request that must fail with code, and returns the
    /// error.
    fn status_error(&mut self, params: Object, code: i64) -> Object {
        let id = status_id();
        let frame = self.call("status", &id, params.clone());
        let failure = frame.get("error").and_then(Json::as_object);
        assert!(
            failure.is_some_and(|f| f.get("code") == Some(&Json::from(code))),
            "status {params:?}: {frame:?}, want error {code}"
        );
        failure.cloned().unwrap()
    }
}

/// Sends a status request from c that changes a mute, and checks that the
/// change reaches c, before the result, and each of others.
pub(super) fn expect_echo(
    c: &mut TestClient,
    params: Object,
    room_id: &str,
    mute: Json,
    others: &[&TestClient],
) {
    let frames = c.status(params.clone());
    assert!(
        frames.len() == 1,
        "frames before the result of {params:?}: {frames:?}"
    );
    check_mute(&frames[0], room_id, &mute);
    for other in others {
        expect_mute(other, room_id, &mute);
    }
}

pub(super) fn expect_mute(c: &TestClient, room_id: &str, mute: &Json) {
    check_mute(&c.read(), room_id, mute);
}

pub(super) fn check_mute(frame: &Object, room_id: &str, mute: &Json) {
    let mut want = obj! {"mute" => mute.clone()};
    if !room_id.is_empty() {
        want.insert("room_id".into(), room_id.into());
    }
    let params = notification_params(frame, "status");
    assert_eq!(params, want, "status");
}

/// Reads a bare announcement of user_id's status, with seen when status is
/// offline, and returns the seen.
fn expect_status(c: &TestClient, user_id: &str, status: &str) -> String {
    let seen = check_status(&c.read(), user_id, status);
    if status == STATUS_OFFLINE {
        check_seen(&seen);
    }
    seen
}

/// Checks that seen is in the format of a log_id, and recent (§4.5.2).
fn check_seen(seen: &str) {
    let ms = seen.parse::<i64>();
    assert!(
        matches!(ms, Ok(ms) if ms.to_string() == seen && ms > 0 && ms < 1 << 53),
        "seen = {seen:?}, want a log_id"
    );
    let at = time::unix_milli(ms.unwrap());
    assert!(
        time::since(&at) <= time::MINUTE && time::until(&at) <= time::SECOND,
        "seen = {at:?}, want about now"
    );
}

/// user_id's status in the users of a room_list of general.
fn listed_status(c: &mut TestClient, user_id: &str) -> Json {
    let listed = list_rooms(c, obj! {"room_id" => "general", "members" => true});
    for user in listed["users"].as_list() {
        let user = user.as_object().unwrap();
        if user.get("user_id") == Some(&Json::from(user_id)) {
            return user.get("status").cloned().unwrap_or_default();
        }
    }
    Json::Null
}

/// Sets c's status with `me` and returns the status in `you`.
fn set_status(c: &mut TestClient, status: &str) -> Json {
    let result = c.result("me", &status_id(), obj! {"status" => status});
    you_of(&result).get("status").cloned().unwrap_or_default()
}

/// Reads the `user` `new` a profile change sends others, and checks the
/// status it carries.
fn expect_profile_status(c: &TestClient, user_id: &str, status: &str) {
    let params = notification_params(&c.read(), "user");
    let object = params.get("new").and_then(Json::as_object);
    assert!(
        object.is_some_and(|o| o.get("user_id") == Some(&Json::from(user_id))
            && o.get("status") == Some(&Json::from(status))),
        "profile change = {object:?}, want {user_id} {status:?}"
    );
}

/// Go's `addAccount`: an account without connections, a member of general,
/// whose membership each of others reads.
pub(super) fn add_account(server: &TestServer, id: &str, others: &[&TestClient]) {
    {
        let mut st = server.app.lock();
        let name = format!("{}{}", id[..1].to_uppercase(), &id[1..]);
        let mut u = st.new_user_locked(id, &name);
        u.passkey = Some(PasskeyUser::default());
        st.users.insert(id.to_owned(), u);
        st.add_member_locked(id, "general");
    }
    for other in others {
        expect_membership(other, "general", id, true);
    }
}

/// Waits until user_id has n connections: the server detaches a closed
/// connection on its own time, so a test that closes one waits for it before
/// it checks what the close did, or did not, send.
fn wait_connections(server: &TestServer, user_id: &str, n: usize) {
    let deadline = time::now().add(time::SECOND);
    loop {
        let open = server
            .app
            .lock()
            .users
            .get(user_id)
            .map_or(0, |u| u.clients.len());
        if open == n {
            return;
        }
        assert!(
            !time::now().after(&deadline),
            "{user_id} has {open} connections, want {n}"
        );
        time::sleep(time::MILLISECOND);
    }
}

/// The `idle` of a status request: false, or seconds since attention
/// stopped (§4.5.3).
fn idle_param(idle: bool) -> Json {
    if idle {
        Json::from(300i64)
    } else {
        Json::from(false)
    }
}

/// Returns user_id's bare member object in general and its complete object
/// in users, from a room_list of general with members.
fn listed_objects(c: &mut TestClient, user_id: &str) -> (Object, Object) {
    let listed = list_rooms(c, obj! {"room_id" => "general", "members" => true});
    let find = |list: &[Json]| {
        list.iter()
            .filter_map(Json::as_object)
            .rfind(|o| o.get("user_id") == Some(&Json::from(user_id)))
            .cloned()
    };
    let joined = listed["joined"].as_list()[0].as_object().unwrap();
    let member = find(joined["members"].as_list());
    let user = find(listed["users"].as_list());
    match (member, user) {
        (Some(member), Some(user)) => (member, user),
        _ => panic!("{user_id} is not listed: {listed:?}"),
    }
}

/// Checks that user_id is listed with status, and with seen in both its
/// member object and its complete object when seen is not "" (§4.5.2), and
/// without it otherwise.
fn expect_listed_seen(c: &mut TestClient, user_id: &str, status: &str, seen: &str) {
    let (member, user) = listed_objects(c, user_id);
    for object in [member, user] {
        let got = object.get("seen");
        let has = got.is_some();
        assert!(
            object.get("status") == Some(&Json::from(status))
                && has == !seen.is_empty()
                && (!has || got == Some(&Json::from(seen))),
            "listed {object:?}, want status {status:?} and seen {seen:?}"
        );
    }
}

/// Checks that a user's own object carries no seen (§4.5.2).
fn expect_no_seen(what: &str, you: &Json) {
    let you = you.as_object().unwrap();
    assert!(!you.contains_key("seen"), "{what} carries seen: {you:?}");
}

/// Requires seen to be later than before, both in the format of a log_id.
fn seen_after(seen: &str, before: &str) {
    check_seen(seen);
    let later: i64 = seen.parse().unwrap();
    let earlier: i64 = before.parse().unwrap_or(0);
    assert!(later > earlier, "seen {seen} is not after {before}");
}

/// Signs a new connection in to user_id's account with its session token,
/// and drains what follows the result.
fn resume(server: &TestServer, token: &Json, user_id: &str) -> TestClient {
    let (mut c, _) = dial_origin(server, TEST_PASSKEY_ORIGIN);
    let id = c.next_id("resume");
    c.result(
        "auth",
        &id,
        obj! {"scheme" => "token", "token" => token.clone()},
    );
    c.user_id = user_id.to_owned();
    c.drain();
    c
}

/// seen, in the format of a log_id, as a number.
fn seen_millis(seen: &str) -> i64 {
    check_seen(seen);
    seen.parse().unwrap()
}

/// Requires seen to be no earlier than from and no later than to, in Unix
/// milliseconds.
fn expect_seen_between(what: &str, seen: &str, from: i64, to: i64) {
    let ms = seen_millis(seen);
    assert!(
        ms >= from && ms <= to,
        "{what}: seen {ms} is not within [{from}, {to}]"
    );
}

/// Waits until the SQLite store at path, which a running server writes in
/// the background, holds a user entry for user_id that want accepts, and
/// returns it.
fn wait_stored(path: &str, user_id: &str, want: impl Fn(&StoredUser) -> bool) -> StoredUser {
    let deadline = time::now().add(time::SECOND * 2);
    loop {
        let s = store::SQLite::open(path).unwrap_or_else(|e| panic!("open {path}: {e:?}"));
        let mut stored = StoredUser::default();
        let mut found = false;
        let mut decoded = Ok(());
        s.load(&mut |e| {
            if e.kind != ENTRY_USER || e.id != user_id {
                return Ok(());
            }
            found = true;
            decoded = json::unmarshal(&e.value.unwrap_or_default(), &mut stored, &[])
                .map_err(|e| e.to_string());
            Ok(())
        })
        .unwrap_or_else(|e| panic!("load {path}: {e:?}"));
        let _ = s.close();
        if let Err(e) = decoded {
            panic!("decode stored {user_id}: {e}");
        }
        if found && want(&stored) {
            return stored;
        }
        assert!(
            !time::now().after(&deadline),
            "stored {user_id} = {stored:?} (found {found})"
        );
        time::sleep(time::MILLISECOND * 5);
    }
}

/// The user objects of a list, by user_id.
fn statuses_by_user(frames: &[Object]) -> BTreeMap<String, String> {
    frames
        .iter()
        .map(|frame| {
            let params = notification_params(frame, "user");
            let object = params["new"].as_object().unwrap();
            (
                object["user_id"].as_str().unwrap().to_owned(),
                object["status"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// reaches those who share a room as `user` `new`.
#[test]
fn test_status_values_and_derivation() {
    let server = passkey_test_server();
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut b, &mut new_test_authenticator());
    let token = registered["token"].clone();
    expect_registered(&a, &b.user_id);
    watching(&mut [&mut a, &mut b]);
    b.drain();
    a.drain();
    let b_id = b.user_id.clone();
    let you = you_of(&registered);
    assert_eq!(
        you["status"],
        Json::from("online"),
        "you of a new account: {you:?}"
    );
    assert_eq!(
        listed_status(&mut a, &b_id),
        Json::from("online"),
        "listed status"
    );

    // online: idle once no connection is attended, online again when one
    // is, offline without connections. The user's own connections are not
    // told: their `you` shows the status they set.
    let frames = b.status(obj! {"idle" => 300i64});
    assert!(frames.is_empty(), "frames after idle: {frames:?}");
    expect_status(&a, &b_id, "idle");
    assert_eq!(
        listed_status(&mut a, &b_id),
        Json::from("idle"),
        "listed status while idle"
    );
    // An attended second connection makes the user online; idle again when
    // it goes.
    let (mut second, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    second.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => token.clone()},
    );
    expect_status(&a, &b_id, "online");
    // Zero seconds since attention stopped is idle too (§4.5.3).
    second.status(obj! {"idle" => 0i64});
    expect_status(&a, &b_id, "idle");
    b.status(obj! {"idle" => false});
    expect_status(&a, &b_id, "online");
    let you = you_of(&b.result("me", "me", Object::new()));
    assert_eq!(
        you["status"],
        Json::from("online"),
        "you while online: {you:?}"
    );
    // room_id scopes only mute, so room_id without mute is invalid_params
    // and changes nothing (§4.5).
    b.status_error(
        obj! {"room_id" => "general", "idle" => 300i64},
        CODE_INVALID_PARAMS,
    );
    a.expect_quiet();
    b.status(obj! {"idle" => 300i64});
    expect_status(&a, &b_id, "idle");
    drop(second);
    drop(b);
    expect_status(&a, &b_id, "offline");
    assert_eq!(
        listed_status(&mut a, &b_id),
        Json::from("offline"),
        "listed status without connections"
    );
    a.expect_quiet();

    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    b.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => token.clone()},
    );
    b.user_id = b_id.clone();
    expect_status(&a, &b_id, "online");
    b.drain();

    // dnd shows dnd, connected and attended or not.
    assert_eq!(
        set_status(&mut b, "dnd"),
        Json::from("dnd"),
        "you after dnd"
    );
    expect_profile_status(&a, &b_id, "dnd");
    b.status(obj! {"idle" => 300i64});
    b.status(obj! {"idle" => false});
    assert_eq!(
        listed_status(&mut a, &b_id),
        Json::from("dnd"),
        "listed status while dnd"
    );
    a.expect_quiet();

    // invisible shows offline to others; `you` shows invisible.
    assert_eq!(
        set_status(&mut b, "invisible"),
        Json::from("invisible"),
        "you after invisible"
    );
    expect_profile_status(&a, &b_id, "offline");
    assert_eq!(
        listed_status(&mut a, &b_id),
        Json::from("offline"),
        "listed status while invisible"
    );

    // "" is no status.
    assert_eq!(set_status(&mut b, ""), Json::from(""), "you after none");
    expect_profile_status(&a, &b_id, "");
    b.status(obj! {"idle" => 300i64});
    assert_eq!(
        listed_status(&mut a, &b_id),
        Json::from(""),
        "listed status after none"
    );
    a.expect_quiet();

    // A value the server does not support, derived ones included, is
    // stored as "": unchanged here, so nobody is told.
    for value in ["away", "idle", "offline", "Online"] {
        assert_eq!(
            set_status(&mut b, value),
            Json::from(""),
            "you after {value:?}"
        );
    }
    a.expect_quiet();
    b.expect_quiet();
    // Not a string, it is invalid.
    b.expect_error("me", "bad", obj! {"status" => true}, CODE_INVALID_PARAMS);

    // online again derives the status from the connections, idle here.
    assert_eq!(
        set_status(&mut b, "online"),
        Json::from("online"),
        "you after online"
    );
    expect_profile_status(&a, &b_id, "idle");
    a.expect_quiet();
    // A status set on one connection reaches the user's others as `you`.
    let (mut other, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    other.result(
        "auth",
        "again",
        obj! {"scheme" => "token", "token" => token.clone()},
    );
    expect_status(&a, &b_id, "online");
    other.drain();
    set_status(&mut other, "dnd");
    let notified = b.notification("user");
    let you = notified["you"].as_object().unwrap();
    assert_eq!(
        you["status"],
        Json::from("dnd"),
        "you on another connection: {you:?}"
    );
    expect_profile_status(&a, &b_id, "dnd");
}

/// again, and listings and the snapshot after a sign-in agree.
#[test]
fn test_dnd_only_while_connected() {
    let server = passkey_test_server();
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut b, &mut new_test_authenticator());
    let token = registered["token"].clone();
    expect_registered(&a, &b.user_id);
    watching(&mut [&mut a]);
    b.drain();
    a.drain();
    set_status(&mut b, "dnd");
    expect_profile_status(&a, &b.user_id, "dnd");
    let (mut second, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    second.result(
        "auth",
        "second",
        obj! {"scheme" => "token", "token" => token.clone()},
    );
    second.drain();
    a.expect_quiet();

    // Closing one of two connections changes nothing; the last shows
    // offline.
    drop(second);
    a.expect_quiet();
    let b_id = b.user_id.clone();
    drop(b);
    expect_status(&a, &b_id, "offline");
    assert_eq!(
        listed_status(&mut a, &b_id),
        Json::from("offline"),
        "listed status while dnd without connections"
    );
    // A sign-in elsewhere leaves the disconnected dnd user out.
    let (mut g, _) = dial_raw(&server);
    watching(&mut [&mut g]);
    guest_auth(&mut g);
    let frames = g.drain();
    assert!(frames.len() == 1, "snapshot after a sign-in: {frames:?}");
    check_status(&frames[0], &a.user_id, "online");
    a.drain();

    // A reconnect shows dnd again; `you` still shows the status set.
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let resumed = b.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => token.clone()},
    );
    let you = you_of(&resumed);
    assert_eq!(
        you["status"],
        Json::from("dnd"),
        "you after a reconnect while dnd: {you:?}"
    );
    let user_id = you_of(&registered)["user_id"].as_str().unwrap().to_owned();
    expect_status(&a, &user_id, "dnd");
    assert_eq!(
        listed_status(&mut a, &user_id),
        Json::from("dnd"),
        "listed status while dnd and connected"
    );
    a.expect_quiet();
}

/// (§4.5). The same holds for a user who set "".
#[test]
fn test_invisible_privacy() {
    let server = passkey_test_server();
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut b, &mut new_test_authenticator());
    expect_registered(&a, &b.user_id);
    watching(&mut [&mut a]);
    a.drain();
    let b_id = b.user_id.clone();
    for (status, want) in [("invisible", "offline"), ("", "")] {
        set_status(&mut b, status);
        b.drain();
        expect_profile_status(&a, &b_id, want);
        b.status(obj! {"idle" => 300i64});
        b.status(obj! {"idle" => false});
        let (mut second, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
        second.result(
            "auth",
            "resume",
            obj! {"scheme" => "token", "token" => registered["token"].clone()},
        );
        drop(second);
        // A newcomer's snapshot after auth leaves b out.
        let (mut c, _) = dial_raw(&server);
        watching(&mut [&mut c]);
        guest_auth(&mut c);
        let frames = c.drain();
        assert!(frames.len() == 1, "snapshot with b {status:?}: {frames:?}");
        check_status(&frames[0], &a.user_id, "online");
        expect_membership(&a, "general", &c.user_id, true);
        expect_status(&a, &c.user_id, "online");
        // Joining a room announces nothing either.
        grant_role(&server, &c.user_id, "mod");
        let (ops, _) = save_room(&mut c, &format!("ops-{status}"), obj! {"title" => "Ops"});
        b.drain();
        join_room(&mut b, &ops);
        expect_membership(&c, &ops, &b_id, true);
        let frames = c.drain();
        assert!(
            frames.is_empty(),
            "frames after b {status:?} joined: {frames:?}"
        );
        assert_eq!(
            listed_status(&mut c, &b_id),
            Json::from(want),
            "listed status of b {status:?}"
        );
        // A guest that goes leaves its rooms.
        let c_id = c.user_id.clone();
        drop(c);
        expect_membership(&a, "general", &c_id, false);
        a.expect_quiet();
        b.drain();
    }
}

/// A flapping user's changes reach others at once for a few, then coalesced
/// to the latest at most every STATUS_COALESCE.
#[test]
fn test_status_changes_coalesce() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    a.drain();
    watching(&mut [&mut a]);
    // b's first status, online when it signed in, took one of the burst.
    for i in 0..STATUS_BURST - 1 {
        let idle = i % 2 == 0;
        b.status(obj! {"idle" => idle_param(idle)});
        expect_status(&a, &b.user_id, if idle { "idle" } else { "online" });
    }
    // Past the burst, changes wait, and only the latest is sent.
    for idle in [false, true, false] {
        b.status(obj! {"idle" => idle_param(idle)});
    }
    a.expect_quiet();
    time::sleep(STATUS_COALESCE + time::MILLISECOND * 200);
    expect_status(&a, &b.user_id, "online");
    a.expect_quiet();
}

/// mute is cleared or ends (§4.5). Others never see a mute.
#[test]
fn test_mute_echo_to_all_connections() {
    let server = passkey_test_server();
    let mut observer = dial_test_client(&server);
    let (mut first, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut first, &mut new_test_authenticator());
    let (mut second, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    second.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => registered["token"].clone()},
    );
    second.user_id = first.user_id.clone();
    expect_registered(&observer, &first.user_id);
    watching(&mut [&mut observer]);
    first.drain();
    second.drain();
    observer.drain();
    let steps: Vec<(Object, &str, Json)> = vec![
        (obj! {"mute" => 60i64}, "", Json::from(60i64)),
        (obj! {"mute" => true}, "", Json::from(true)),
        (obj! {"mute" => false}, "", Json::from(false)),
        (
            obj! {"mute" => 10 * MAX_MUTE_SECONDS},
            "",
            Json::from(MAX_MUTE_SECONDS),
        ),
        (
            obj! {"room_id" => "general", "mute" => true},
            "general",
            Json::from(true),
        ),
        (
            obj! {"room_id" => "general", "mute" => false},
            "general",
            Json::from(false),
        ),
    ];
    for (params, room_id, mute) in steps {
        expect_echo(&mut first, params, room_id, mute, &[&second]);
    }
    // Invalid values, and a room the user cannot see, are invalid_params
    // and change nothing, the valid fields beside them included.
    for params in [
        // mute seconds are a positive integer: 0 is not false (§4.5).
        obj! {"mute" => -1i64},
        obj! {"mute" => 0i64},
        obj! {"room_id" => "general", "mute" => 0i64},
        obj! {"mute" => Json::Number(1.5)},
        obj! {"mute" => "60"},
        obj! {"mute" => Json::Null},
        obj! {"room_id" => "general"},
        obj! {"room_id" => "general", "idle" => false},
        obj! {"room_id" => "missing", "mute" => true},
        obj! {"room_id" => 5i64, "mute" => true},
        obj! {"mute" => true, "idle" => "yes"},
        obj! {"mute" => true, "room_id" => Json::Null},
        // idle is false or seconds since attention stopped (§4.5.3).
        obj! {"mute" => true, "idle" => true},
        obj! {"mute" => true, "idle" => -1i64},
        obj! {"mute" => true, "idle" => Json::Number(1.5)},
        obj! {"mute" => true, "idle" => Json::Null},
    ] {
        second.status_error(params, CODE_INVALID_PARAMS);
    }
    first.expect_quiet();
    second.expect_quiet();

    // Timed mutes end by themselves, sent as false to every connection.
    expect_echo(
        &mut second,
        obj! {"mute" => 1i64},
        "",
        Json::from(1i64),
        &[&first],
    );
    expect_echo(
        &mut second,
        obj! {"room_id" => "general", "mute" => 1i64},
        "general",
        Json::from(1i64),
        &[&first],
    );
    time::sleep(time::MILLISECOND * 1200);
    for c in [&mut first, &mut second] {
        let mut frames = c.drain();
        assert!(
            frames.len() == 2,
            "frames after the mutes ran out: {frames:?}"
        );
        // The two timers run in either order.
        let scoped = frames[0]
            .get("params")
            .and_then(Json::as_object)
            .is_some_and(|p| p.contains_key("room_id"));
        if scoped {
            frames.swap(0, 1);
        }
        check_mute(&frames[0], "", &Json::from(false));
        check_mute(&frames[1], "general", &Json::from(false));
    }
    observer.expect_quiet();
    let listed = list_rooms(
        &mut observer,
        obj! {"room_id" => "general", "members" => true},
    );
    for user in listed["users"].as_list() {
        assert!(
            !user.as_object().unwrap().contains_key("mute"),
            "mute shown to others: {user:?}"
        );
    }
    let own = list_rooms(&mut second, obj! {"room_id" => "general"});
    for room in own["joined"].as_list() {
        assert!(
            !room.as_object().unwrap().contains_key("mute"),
            "mute in a room record: {room:?}"
        );
    }
}

/// starts attended.
#[test]
fn test_after_auth_mutes_and_statuses() {
    let server = passkey_test_server();
    let mut clients = dial_group(&server, 3);
    clients[1].status(obj! {"idle" => 300i64});
    set_status(&mut clients[2], "dnd");
    let mut invisible = dial_test_client(&server);
    set_status(&mut invisible, "invisible");
    for c in &mut clients {
        c.drain();
    }
    // An account without connections, which shows offline, and one with
    // dnd, which without them shows offline too: both are left out.
    {
        let others: Vec<&TestClient> = clients.iter().collect();
        add_account(&server, "away", &others);
        add_account(&server, "busy", &others);
    }
    server.app.lock().users.get_mut("busy").unwrap().chosen = STATUS_DND.into();

    let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut owner, &mut new_test_authenticator());
    owner.drain();
    for c in &mut clients {
        c.drain();
    }
    grant_role(&server, &owner.user_id, "mod");
    let (ops, _) = save_room(&mut owner, "ops", obj! {"title" => "Ops"});
    owner.status(obj! {"mute" => true});
    owner.status(obj! {"room_id" => ops.as_str(), "mute" => true});
    owner.status(obj! {"room_id" => "general", "mute" => 60i64});
    owner.status(obj! {"room_id" => "general", "mute" => false});
    owner.drain();

    // A connection that sends status before it signs in: as a request it
    // is denied, and without an id ignored. Nothing changes, and the
    // owner's connection is told nothing.
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    watching(&mut [&mut c]);
    c.write(&obj! {"method" => "status", "params" => obj! {"mute" => false}});
    c.write(&obj! {"method" => "status", "params" => obj! {"idle" => 300i64}});
    c.status_error(obj! {"mute" => false}, CODE_DENIED);
    c.status_error(obj! {"idle" => 300i64}, CODE_DENIED);
    c.status_error(obj! {"room_id" => "missing", "mute" => true}, CODE_DENIED);
    let (before, _) = c.request(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => registered["token"].clone()},
    );
    assert!(
        before.is_empty(),
        "frames before the auth result: {before:?}"
    );
    owner.expect_quiet();
    // A moderator's sign-in first sends a server frame listing joined.
    expect_joined_wake(&c);
    let frames = c.drain();
    assert!(frames.len() == 5, "frames after auth: {frames:?}");
    check_mute(&frames[0], "", &Json::from(true));
    check_mute(&frames[1], &ops, &Json::from(true));
    let want: BTreeMap<String, String> = [
        (clients[0].user_id.clone(), "online".to_owned()),
        (clients[1].user_id.clone(), "idle".to_owned()),
        (clients[2].user_id.clone(), "dnd".to_owned()),
    ]
    .into();
    assert_eq!(statuses_by_user(&frames[2..]), want, "statuses after auth");
    // The idle sent before sign-in did not apply: the new connection
    // starts attended, so the owner stays online when the first one goes,
    // and is idle only once the new one says so.
    let attended = &mut clients[0];
    attended.drain();
    watching(&mut [&mut *attended]);
    let owner_id = owner.user_id.clone();
    drop(owner);
    attended.expect_quiet();
    {
        let st = server.app.lock();
        let u = &st.users[&owner_id];
        let status = u.shown_status(st.attended(u));
        assert_eq!(status, STATUS_ONLINE, "owner status");
    }
    c.status(obj! {"idle" => 300i64});
    expect_status(attended, &owner_id, "idle");
    c.expect_quiet();

    // A guest gets the snapshot too, after the auth result.
    let (mut g, _) = dial_raw(&server);
    watching(&mut [&mut g]);
    guest_auth(&mut g);
    let frames = g.drain();
    assert!(frames.len() == 4, "guest snapshot: {frames:?}");
}

/// auth result's `you` carries the status, and the mutes follow it.
#[test]
fn test_status_survives_restart() {
    let dir = TempDir::new("apron-status-");
    let path = format!("{dir}/aprond.db");
    let uploads = format!("{dir}/uploads");
    let open = || -> Arc<dyn Store> { Arc::new(store::SQLite::open(&path).unwrap()) };
    let mut server = start_with_store(open(), &uploads);
    let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut owner, &mut new_test_authenticator());
    owner.drain();
    set_status(&mut owner, "dnd");
    owner.status(obj! {"mute" => true});
    owner.status(obj! {"room_id" => "general", "mute" => 3600i64});
    server.stop();

    let server = start_with_store(open(), &uploads);
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let result = c.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => registered["token"].clone()},
    );
    let you = you_of(&result);
    assert_eq!(
        you["status"],
        Json::from("dnd"),
        "you after restart: {you:?}"
    );
    let frames = c.drain();
    assert!(frames.len() == 2, "frames after auth: {frames:?}");
    check_mute(&frames[0], "", &Json::from(true));
    let params = notification_params(&frames[1], "status");
    let mute = match params.get("mute") {
        Some(Json::Number(n)) => *n,
        _ => 0.0,
    };
    assert!(
        params.get("room_id") == Some(&Json::from("general")) && (3590.0..=3600.0).contains(&mute),
        "room mute after restart: {params:?}"
    );
    drop((c, owner, server));
}

/// elsewhere is.
#[test]
fn test_additions_are_not_sign_ins() {
    let (server, mailbox) = email_test_server(|config| {
        config.web_authn = Some(test_web_authn());
    });
    let other = dial_test_client(&server);
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    guest_auth(&mut c);
    expect_membership(&other, "general", &c.user_id, true);
    watching(&mut [&mut c]);
    c.drain();
    let frames = c.status(obj! {"mute" => true});
    assert!(frames.len() == 1, "mute echo: {frames:?}");
    check_mute(&frames[0], "", &Json::from(true));

    // A guest's passkey registration makes a new account, a sign-in (§3.3.3):
    // after its result, the account's join to general and the statuses,
    // and no mute, which stays the guest's.
    let mut authenticator = new_test_authenticator();
    let options = passkey_result(&passkey_call(
        &mut c,
        "register-begin",
        "register",
        "begin",
        Object::new(),
    ));
    let credential = authenticator.registration(&options, TEST_PASSKEY_ORIGIN);
    let registered = passkey_result(&passkey_call(
        &mut c,
        "register-finish",
        "register",
        "finish",
        obj! {"credential" => credential},
    ));
    let account = account_id(&registered);
    assert!(
        account != c.user_id && registered.get("token").is_some_and(|t| *t != Json::Null),
        "passkey registration: {registered:?}"
    );
    c.user_id = account;
    let frames = c.drain();
    assert!(
        frames.len() == 2,
        "frames after a passkey registration: {frames:?}"
    );
    check_membership(&membership_only(&frames[0]), "general", &c.user_id, true);
    check_status(&frames[1], &other.user_id, "online");
    let frames = c.status(obj! {"mute" => true});
    assert!(frames.len() == 1, "the account's mute echo: {frames:?}");
    check_mute(&frames[0], "", &Json::from(true));

    // Nor is an address added to the account.
    propose(&mut c, "added@example.com");
    let message = mailbox.receive();
    assert!(message.add, "addition email: {message:?}");
    let (_, result) = approve(&mut c, &message.code, Object::new());
    assert!(result.is_empty(), "approving an addition: {result:?}");
    let frames = c.drain();
    assert!(
        frames.is_empty(),
        "frames after an address addition: {frames:?}"
    );

    // A sign-in to the account on another connection is sent the mute and
    // the statuses after its result.
    let (mut signed_in, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    watching(&mut [&mut signed_in]);
    let (before, _) = signed_in.request(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => registered["token"].clone()},
    );
    assert!(
        before.is_empty(),
        "frames before the sign-in result: {before:?}"
    );
    let frames = signed_in.drain();
    assert!(frames.len() == 2, "frames after a sign-in: {frames:?}");
    check_mute(&frames[0], "", &Json::from(true));
    check_status(&frames[1], &other.user_id, "online");
}

/// room_id scopes only mute (§4.5): idle is the sending connection's with
/// any room_id, and the unscoped mute is untouched by a scoped one. A mute
/// of a room the user cannot see is invalid_params, and then the idle
/// beside it does not apply either.
#[test]
fn test_room_id_scopes_only_mute() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    watching(&mut [&mut a]);
    a.drain();

    // A mute of a room the user cannot see changes nothing.
    b.status_error(
        obj! {"room_id" => "missing", "idle" => 300i64, "mute" => true},
        CODE_INVALID_PARAMS,
    );
    a.expect_quiet();
    // Without a mute, room_id is invalid_params (§4.5), and the idle beside
    // it does not apply either.
    b.status_error(
        obj! {"room_id" => "missing", "idle" => 300i64},
        CODE_INVALID_PARAMS,
    );
    a.expect_quiet();
    let frames = b.status(obj! {"idle" => 300i64});
    assert!(frames.is_empty(), "frames after an idle: {frames:?}");
    expect_status(&a, &b.user_id, "idle");
    // A visible room: idle applies to the connection, the mute to the room.
    let frames = b.status(obj! {"room_id" => "general", "idle" => false, "mute" => true});
    assert!(
        frames.len() == 1,
        "frames after a mute of general: {frames:?}"
    );
    check_mute(&frames[0], "general", &Json::from(true));
    expect_status(&a, &b.user_id, "online");
    a.expect_quiet();
    let st = server.app.lock();
    let u = &st.users[&b.user_id];
    let now = time::now();
    assert!(
        !u.mute.active(&now) && st.room_muted(u, "general", &now),
        "mutes: unscoped {:?}, rooms {:?}",
        u.mute,
        u.room_mutes
    );
}

/// A client's `status` is a request (§4.5): answered {} once applied,
/// denied before sign-in, and with a bad id or params answered like any
/// request. A `status` without an id is a notification with no meaning,
/// ignored as one with an unknown method is (§1), before sign-in and after,
/// whatever its params.
#[test]
fn test_status_is_a_request() {
    let server = new_test_server(default_config());
    let mut a = dial_test_client(&server);
    watching(&mut [&mut a]);
    a.drain();
    let (mut b, _) = dial_raw(&server);
    let notifications = [
        r#"{"method":"status","params":{"idle":true}}"#,
        r#"{"method":"status","params":{"mute":true}}"#,
        r#"{"method":"status","params":{"mute":-1}}"#,
        r#"{"method":"status","params":[]}"#,
        r#"{"method":"status","params":null}"#,
        r#"{"method":"status"}"#,
    ];
    for frame in notifications {
        b.write_raw(frame);
    }
    b.expect_quiet();
    b.status_error(obj! {"idle" => 300i64}, CODE_DENIED);
    b.status_error(obj! {"mute" => true}, CODE_DENIED);

    guest_auth(&mut b);
    expect_membership(&a, "general", &b.user_id, true);
    expect_status(&a, &b.user_id, "online");
    b.drain();
    a.expect_quiet();
    for frame in notifications {
        b.write_raw(frame);
    }
    b.expect_quiet();
    a.expect_quiet();
    {
        let st = server.app.lock();
        let u = &st.users[&b.user_id];
        let now = time::now();
        let status = u.shown_status(st.attended(u));
        assert!(
            !u.mute.active(&now) && status == STATUS_ONLINE,
            "after status notifications: mute {:?}, status {status}",
            u.mute
        );
    }

    // As a request it applies, and answers {}.
    let frames = b.status(obj! {"idle" => 300i64});
    assert!(
        frames.is_empty(),
        "frames before the idle result: {frames:?}"
    );
    expect_status(&a, &b.user_id, "idle");
    // A notification does not end it.
    b.write_raw(r#"{"method":"status","params":{"idle":false}}"#);
    b.expect_quiet();
    a.expect_quiet();
    assert_eq!(
        listed_status(&mut a, &b.user_id),
        Json::from("idle"),
        "listed status after an idle notification"
    );
    // A bad id or params are answered like those of any request.
    b.write_raw(r#"{"method":"status","id":5,"params":{"idle":false}}"#);
    let reply = b.read();
    let code = |reply: &Object| {
        reply
            .get("error")
            .and_then(Json::as_object)
            .and_then(|e| e.get("code"))
            .cloned()
    };
    assert!(
        matches!(reply.get("id"), None | Some(Json::Null))
            && code(&reply) == Some(Json::from(CODE_INVALID_REQUEST)),
        "bad id on status: {reply:?}"
    );
    b.write_raw(r#"{"method":"status","id":"bad-params","params":[]}"#);
    let reply = b.read();
    assert!(
        reply.get("id") == Some(&Json::from("bad-params"))
            && code(&reply) == Some(Json::from(CODE_INVALID_PARAMS)),
        "bad params on status: {reply:?}"
    );
    b.status_error(obj! {"idle" => "no"}, CODE_INVALID_PARAMS);
    a.expect_quiet();
    b.status(obj! {"idle" => false});
    expect_status(&a, &b.user_id, "online");
}

/// The server limits each user's `status` requests (§4.5): beyond the limit
/// a request is retry_after, with the seconds to wait, and changes nothing,
/// neither idle nor mute.
#[test]
fn test_status_rate_limit() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    watching(&mut [&mut a]);
    a.drain();

    // The default: a burst of STATUS_REQUEST_BURST, refilled one a second,
    // so a quick run of more is refused.
    for i in 0..STATUS_REQUEST_BURST + 2 {
        b.write(&obj! {
            "method" => "status",
            "id" => status_id(),
            "params" => obj! {"idle" => false, "seq" => i},
        });
    }
    let mut limited = 0;
    for _ in 0..STATUS_REQUEST_BURST + 2 {
        let frame = b.read();
        if let Some(failure) = frame.get("error").and_then(Json::as_object) {
            assert_eq!(
                failure.get("code"),
                Some(&Json::from(CODE_RETRY_AFTER)),
                "status beyond the burst: {frame:?}"
            );
            limited += 1;
        }
    }
    assert!(
        limited > 0,
        "no status of {} was limited",
        STATUS_REQUEST_BURST + 2
    );

    // A limit of two, refilled hourly.
    server
        .app
        .lock()
        .users
        .get_mut(&b.user_id)
        .unwrap()
        .status_requests = Some(Limiter::new(every(time::HOUR), 2));
    b.status(obj! {"idle" => 300i64});
    expect_status(&a, &b.user_id, "idle");
    expect_echo(&mut b, obj! {"mute" => true}, "", Json::from(true), &[]);
    for params in [
        obj! {"idle" => false},
        obj! {"mute" => false},
        obj! {"room_id" => "general", "mute" => true},
    ] {
        let failure = b.status_error(params.clone(), CODE_RETRY_AFTER);
        let wait = failure
            .get("data")
            .and_then(Json::as_object)
            .and_then(|d| d.get("retry_after"));
        assert!(
            matches!(wait, Some(Json::Number(n)) if *n >= 1.0),
            "retry_after of {params:?}: {failure:?}"
        );
    }
    b.expect_quiet();
    a.expect_quiet();
    let st = server.app.lock();
    let u = &st.users[&b.user_id];
    let now = time::now();
    let status = u.shown_status(st.attended(u));
    assert!(
        u.mute.forever && !st.room_muted(u, "general", &now) && status == STATUS_IDLE,
        "after limited requests: mute {:?}, room mutes {:?}, status {status}",
        u.mute,
        u.room_mutes
    );
}

/// account is sent both.
#[test]
fn test_repeat_auth_is_no_sign_in() {
    let server = passkey_test_server();
    let other = dial_test_client(&server);

    let mut g = dial_test_client(&server);
    watching(&mut [&mut g]);
    g.drain();
    expect_echo(&mut g, obj! {"mute" => true}, "", Json::from(true), &[]);
    let (before, result) = g.request("auth", "again", obj! {"scheme" => "guest"});
    assert!(
        before.is_empty() && you_of(&result)["user_id"] == Json::from(g.user_id.as_str()),
        "guest auth again: {before:?} then {result:?}"
    );
    g.expect_quiet();

    let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let mut authenticator = new_test_authenticator();
    let registered = register_test_passkey(&mut owner, &mut authenticator);
    watching(&mut [&mut owner]);
    owner.drain();
    expect_echo(
        &mut owner,
        obj! {"room_id" => "general", "mute" => true},
        "general",
        Json::from(true),
        &[],
    );
    let (before, result) = owner.request(
        "auth",
        "resume-again",
        obj! {"scheme" => "token", "token" => registered["token"].clone()},
    );
    assert!(
        before.is_empty() && you_of(&result)["user_id"] == Json::from(owner.user_id.as_str()),
        "token auth as the same user: {before:?} then {result:?}"
    );
    owner.expect_quiet();
    let options = passkey_result(&passkey_call(
        &mut owner,
        "login-begin",
        "login",
        "begin",
        Object::new(),
    ));
    let assertion = authenticator.assertion(&options, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    let logged_in = passkey_result(&passkey_call(
        &mut owner,
        "login-finish",
        "login",
        "finish",
        obj! {"credential" => assertion},
    ));
    assert_eq!(
        you_of(&logged_in)["user_id"],
        Json::from(owner.user_id.as_str()),
        "passkey login as the same user: {logged_in:?}"
    );
    owner.expect_quiet();

    // A sign-in as the account elsewhere is sent the mute and the statuses.
    let (mut signed_in, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    watching(&mut [&mut signed_in]);
    signed_in.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => logged_in["token"].clone()},
    );
    let frames = signed_in.drain();
    assert!(frames.len() == 3, "frames after a sign-in: {frames:?}");
    check_mute(&frames[0], "general", &Json::from(true));
    let want: BTreeMap<String, String> = [
        (other.user_id.clone(), "online".to_owned()),
        (g.user_id.clone(), "online".to_owned()),
    ]
    .into();
    assert_eq!(
        statuses_by_user(&frames[1..]),
        want,
        "statuses after a sign-in"
    );
}

/// Every current user object in room_list and room_update carries the
/// status others see (§4.5), offline and "" included: a room's members and
/// users in a room_list with members, and in a room_update joined.
#[test]
fn test_listings_carry_status() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 3);
    for (i, status) in [(1, ""), (2, "invisible")] {
        set_status(&mut clients[i], status);
        for c in &mut clients {
            c.drain();
        }
    }
    let others: Vec<&TestClient> = clients.iter().collect();
    add_account(&server, "away", &others);
    let mut invisible = clients.pop().unwrap();
    let mut none = clients.pop().unwrap();
    let mut online = clients.pop().unwrap();
    let want: BTreeMap<String, Json> = [
        (online.user_id.clone(), Json::from("online")),
        (none.user_id.clone(), Json::from("")),
        (invisible.user_id.clone(), Json::from("offline")),
        ("away".to_owned(), Json::from("offline")),
    ]
    .into();
    let check = |what: &str, members: &[Json], users: &[Json]| {
        for list in [members, users] {
            let mut got = BTreeMap::new();
            for object in list {
                let object = object.as_object().unwrap();
                let Some(status) = object.get("status") else {
                    panic!("{what}: {object:?} without status")
                };
                got.insert(
                    object["user_id"].as_str().unwrap().to_owned(),
                    status.clone(),
                );
            }
            assert_eq!(got, want, "{what} statuses");
        }
    };
    let listed = list_rooms(&mut online, obj! {"filter" => "joined", "members" => true});
    check(
        "room_list",
        listed["joined"].as_list()[0].as_object().unwrap()["members"].as_list(),
        listed["users"].as_list(),
    );

    grant_role(&server, &none.user_id, "mod");
    let (room, _) = save_room(&mut none, "room", obj! {"title" => "Room"});
    join_room(&mut invisible, &room);
    server.app.lock().add_member_locked("away", &room);
    online.drain();
    let (before, _) = online.request("room_join", "join", obj! {"room_id" => room.as_str()});
    let update = notification_params(&before[0], "room_update");
    check(
        "room_update joined",
        update["joined"].as_list()[0].as_object().unwrap()["members"].as_list(),
        update["users"].as_list(),
    );
}

/// The statuses sent after a sign-in are only of the users that the user's
/// rooms list in members (§4.5): past max_listed_members, a room lists its
/// most recently active members (§4.2.1), the user who just joined
/// included.
#[test]
fn test_after_auth_statuses_are_bounded() {
    let mut config = default_config();
    config.max_listed_members = 2;
    let server = new_test_server(config);
    let mut clients = dial_group(&server, 4);
    save(
        &mut clients[0],
        "post",
        obj! {"body" => obj! {"text" => "hi"}},
    );
    for c in &mut clients {
        c.drain();
    }
    let (mut g, _) = dial_raw(&server);
    watching(&mut [&mut g]);
    guest_auth(&mut g);
    let got: Vec<String> = g
        .drain()
        .iter()
        .map(|frame| {
            notification_params(frame, "user")["new"]
                .as_object()
                .unwrap()["user_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    // general lists g, who joined last, and clients[0], who posted.
    assert_eq!(
        got,
        vec![clients[0].user_id.clone()],
        "statuses after sign-in, want the listed members"
    );
}

/// A `me` that changes the status counts against the user's limit on status
/// changes, as a status request does (§4.5): beyond it the `me` is
/// retry_after and changes nothing, while one that leaves the status as it
/// is passes.
#[test]
fn test_me_status_changes_are_limited() {
    let server = new_test_server(default_config());
    let mut clients = dial_group(&server, 2);
    for c in &clients {
        make_account(&server, &c.user_id);
    }
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    watching(&mut [&mut a]);
    a.drain();
    server
        .app
        .lock()
        .users
        .get_mut(&b.user_id)
        .unwrap()
        .status_requests = Some(Limiter::new(every(time::HOUR), 1));
    assert_eq!(set_status(&mut b, "dnd"), Json::from("dnd"), "status");
    expect_profile_status(&a, &b.user_id, "dnd");
    let frame = b.call(
        "me",
        &status_id(),
        obj! {"status" => "online", "name" => "Bea"},
    );
    let failure = frame.get("error").and_then(Json::as_object);
    assert!(
        failure.is_some_and(|f| f.get("code") == Some(&Json::from(CODE_RETRY_AFTER))),
        "me beyond the limit: {frame:?}"
    );
    // `me` is no request of ext:limits' rows, so its refusal names no
    // category: data holds retry_after alone (Cloudflare b97f119).
    let data = failure.unwrap()["data"].as_object().expect("data");
    assert_eq!(data.keys().collect::<Vec<_>>(), ["retry_after"], "{data:?}");
    assert_eq!(
        set_status(&mut b, "dnd"),
        Json::from("dnd"),
        "unchanged status"
    );
    b.expect_quiet();
    a.expect_quiet();
    let st = server.app.lock();
    let u = &st.users[&b.user_id];
    assert!(
        u.chosen == STATUS_DND && u.name != "Bea",
        "after a limited me: status {:?} name {:?}",
        u.chosen,
        u.name
    );
}

/// A user mutes at most MAX_ROOM_MUTES rooms at once: muting another is
/// denied, while changing or removing a room's mute is not.
#[test]
fn test_room_mutes_are_bounded() {
    let server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    grant_role(&server, &c.user_id, "mod");
    let (room, _) = save_room(&mut c, "room", obj! {"title" => "Room"});
    expect_echo(
        &mut c,
        obj! {"room_id" => room.as_str(), "mute" => true},
        &room,
        Json::from(true),
        &[],
    );
    {
        let mut st = server.app.lock();
        let u = st.users.get_mut(&c.user_id).unwrap();
        for i in 0..MAX_ROOM_MUTES - 1 {
            u.room_mutes.insert(
                format!("gone-{i}"),
                MuteState {
                    forever: true,
                    until: Time::default(),
                },
            );
        }
    }
    c.status_error(obj! {"room_id" => "general", "mute" => 60i64}, CODE_DENIED);
    expect_echo(
        &mut c,
        obj! {"room_id" => room.as_str(), "mute" => 60i64},
        &room,
        Json::from(60i64),
        &[],
    );
    expect_echo(
        &mut c,
        obj! {"room_id" => "general", "mute" => false},
        "general",
        Json::from(false),
        &[],
    );
    expect_echo(
        &mut c,
        obj! {"room_id" => room.as_str(), "mute" => false},
        &room,
        Json::from(false),
        &[],
    );
    expect_echo(
        &mut c,
        obj! {"room_id" => "general", "mute" => true},
        "general",
        Json::from(true),
        &[],
    );
}

/// others are told of no change at all.
#[test]
fn test_sign_in_to_existing_account_is_a_departure() {
    let server = passkey_test_server();
    let mut observer = dial_test_client(&server);
    watching(&mut [&mut observer]);
    observer.drain();

    // A guest that registers a passkey becomes a new account, which takes
    // over from it (§3.3.3).
    let (mut newcomer, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    register_test_passkey(&mut newcomer, &mut new_test_authenticator());
    expect_registered(&observer, &newcomer.user_id);
    observer.expect_quiet();

    for status in ["online", "invisible", ""] {
        let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
        let registered = register_test_passkey(&mut owner, &mut new_test_authenticator());
        set_status(&mut owner, status);
        let owner_id = owner.user_id.clone();
        drop(owner);
        // Wait for the detach, so the account's going offline is drained
        // here.
        wait_connections(&server, &owner_id, 0);
        observer.drain();

        let (mut guest, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
        guest_auth(&mut guest);
        expect_membership(&observer, "general", &guest.user_id, true);
        observer.drain();
        guest.request(
            "auth",
            "resume",
            obj! {"scheme" => "token", "token" => registered["token"].clone()},
        );
        expect_membership(&observer, "general", &guest.user_id, false);
        let frames = observer.drain();
        if status == "online" {
            assert!(
                frames.len() == 1,
                "after a sign-in to an online account: {frames:?}"
            );
            check_status(&frames[0], &owner_id, "online");
        } else {
            assert!(
                frames.is_empty(),
                "after a sign-in to an account with status {status:?}: {frames:?}"
            );
        }
        drop(guest);
        observer.drain();
    }
}

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

/// became offline, not when it was sent (§4.5.2).
#[test]
fn test_coalesced_offline_carries_seen() {
    let server = passkey_test_server();
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    register_test_passkey(&mut b, &mut new_test_authenticator());
    let user_id = b.user_id.clone();
    expect_registered(&a, &user_id);
    watching(&mut [&mut a]);
    a.drain();
    // b's first status, online when it signed in, took one of the burst.
    for i in 0..STATUS_BURST - 1 {
        let idle = i % 2 == 0;
        b.status(obj! {"idle" => idle_param(idle)});
        expect_status(&a, &user_id, if idle { "idle" } else { "online" });
    }
    let closing = time::now().unix_milli();
    drop(b);
    wait_connections(&server, &user_id, 0);
    let closed = time::now().unix_milli();
    a.expect_quiet();
    time::sleep(STATUS_COALESCE + time::MILLISECOND * 200);
    let seen = expect_status(&a, &user_id, "offline");
    expect_seen_between("coalesced offline", &seen, closing, closed);
    expect_listed_seen(&mut a, &user_id, "offline", &seen);
    a.expect_quiet();
}

/// nobody sees seen change while the shown status stays offline (§4.5.2).
#[test]
fn test_hidden_flap_keeps_seen() {
    let server = passkey_test_server();
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let token = register_test_passkey(&mut b, &mut new_test_authenticator())["token"].clone();
    let user_id = b.user_id.clone();
    expect_registered(&a, &user_id);
    watching(&mut [&mut a]);
    a.drain();
    // b has one change of its burst left, which refills no more.
    server
        .app
        .lock()
        .users
        .get_mut(&user_id)
        .unwrap()
        .status_limit = Some(Limiter::new(every(time::HOUR), 1));
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
    time::sleep(STATUS_COALESCE + time::MILLISECOND * 200);
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
