//! The status value, privacy, coalescing, and listing tests of status_test.go,
//! test by test, with the helpers the other status_*_test.rs files share. Each
//! keeps the Go test's name, tables, and literal expectations.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use rust_stdlib::encoding::json::v2 as json;
use rust_stdlib::time::{self};

use super::helpers::*;
use crate::obj;
use crate::server::persist::{StoredUser, ENTRY_USER};
use crate::server::protocol::*;
use crate::server::status::*;
use crate::server::webauthn::PasskeyUser;
use crate::store::{self, Store};

use super::persist_test::start_with_store;
use super::webauthn_test::*;

static STATUS_REQUESTS: AtomicI64 = AtomicI64::new(0);

/// A request ID unique across connections, which share a user's
/// deduplication (§1.2).
pub(super) fn status_id() -> String {
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
    pub(super) fn status_error(&mut self, params: Object, code: i64) -> Object {
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
pub(super) fn expect_status(c: &TestClient, user_id: &str, status: &str) -> String {
    let seen = check_status(&c.read(), user_id, status);
    if status == STATUS_OFFLINE {
        check_seen(&seen);
    }
    seen
}

/// Checks that seen is in the format of a log_id, and recent (§4.5.2).
pub(super) fn check_seen(seen: &str) {
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
pub(super) fn set_status(c: &mut TestClient, status: &str) -> Json {
    let result = c.result("me", &status_id(), obj! {"status" => status});
    you_of(&result).get("status").cloned().unwrap_or_default()
}

/// Reads the `user` `new` a profile change sends others, and checks the
/// status it carries.
pub(super) fn expect_profile_status(c: &TestClient, user_id: &str, status: &str) {
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
pub(super) fn wait_connections(server: &TestServer, user_id: &str, n: usize) {
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
pub(super) fn listed_objects(c: &mut TestClient, user_id: &str) -> (Object, Object) {
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
pub(super) fn expect_listed_seen(c: &mut TestClient, user_id: &str, status: &str, seen: &str) {
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
pub(super) fn expect_no_seen(what: &str, you: &Json) {
    let you = you.as_object().unwrap();
    assert!(!you.contains_key("seen"), "{what} carries seen: {you:?}");
}

/// Requires seen to be later than before, both in the format of a log_id.
pub(super) fn seen_after(seen: &str, before: &str) {
    check_seen(seen);
    let later: i64 = seen.parse().unwrap();
    let earlier: i64 = before.parse().unwrap_or(0);
    assert!(later > earlier, "seen {seen} is not after {before}");
}

/// Signs a new connection in to user_id's account with its session token,
/// and drains what follows the result.
pub(super) fn resume(server: &TestServer, token: &Json, user_id: &str) -> TestClient {
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
pub(super) fn seen_millis(seen: &str) -> i64 {
    check_seen(seen);
    seen.parse().unwrap()
}

/// Requires seen to be no earlier than from and no later than to, in Unix
/// milliseconds.
pub(super) fn expect_seen_between(what: &str, seen: &str, from: i64, to: i64) {
    let ms = seen_millis(seen);
    assert!(
        ms >= from && ms <= to,
        "{what}: seen {ms} is not within [{from}, {to}]"
    );
}

/// Waits until the SQLite store at path, which a running server writes in
/// the background, holds a user entry for user_id that want accepts, and
/// returns it.
pub(super) fn wait_stored(
    path: &str,
    user_id: &str,
    want: impl Fn(&StoredUser) -> bool,
) -> StoredUser {
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
pub(super) fn statuses_by_user(frames: &[Object]) -> BTreeMap<String, String> {
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

/// A user's changes reach others at most once a status_coalesce, the
/// latest winning (apron-server-cloudflare's 60 s by default).
#[test]
fn test_status_changes_coalesce() {
    let server = new_test_server(coalescing(500, 0));
    let mut clients = dial_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    a.drain();
    watching(&mut [&mut a]);
    // b's online, when it signed in, went out just now: changes wait.
    for idle in [true, false, true] {
        b.status(obj! {"idle" => idle_param(idle)});
    }
    a.expect_quiet();
    time::sleep(time::MILLISECOND * 700);
    expect_status(&a, &b.user_id, "idle");
    a.expect_quiet();
    // A change after a quiet window goes at once.
    time::sleep(time::MILLISECOND * 600);
    b.status(obj! {"idle" => idle_param(false)});
    expect_status(&a, &b.user_id, "online");
}

/// The test server with status changes coalesced over `coalesce_ms` and
/// a closed connection's change held for `grace_ms`.
pub(super) fn coalescing(coalesce_ms: i64, grace_ms: i64) -> crate::server::config::Config {
    let mut config = default_config();
    config.web_authn = Some(test_web_authn());
    config.limits.status_coalesce = time::Duration::from_millis(coalesce_ms);
    config.limits.offline_grace = time::Duration::from_millis(grace_ms);
    config
}

/// A change a closed connection caused waits offline_grace, so a reconnect
/// within it shows others nothing, and an offline that goes out after it
/// carries the seen of the close (§4.5.2).
#[test]
fn test_offline_waits_out_the_grace() {
    let server = new_test_server(coalescing(0, 500));
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let token = register_test_passkey(&mut b, &mut new_test_authenticator())["token"].clone();
    let user_id = b.user_id.clone();
    expect_registered(&a, &user_id);
    watching(&mut [&mut a]);
    a.drain();
    drop(b);
    wait_connections(&server, &user_id, 0);
    let back = resume(&server, &token, &user_id);
    time::sleep(time::MILLISECOND * 700);
    a.expect_quiet();
    let closing = time::now().unix_milli();
    drop(back);
    wait_connections(&server, &user_id, 0);
    let closed = time::now().unix_milli();
    a.expect_quiet();
    time::sleep(time::MILLISECOND * 700);
    let seen = expect_status(&a, &user_id, "offline");
    expect_seen_between("offline after the grace", &seen, closing, closed);
    expect_listed_seen(&mut a, &user_id, "offline", &seen);
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
