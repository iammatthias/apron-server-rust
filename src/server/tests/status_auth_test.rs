//! The status tests of status_test.go about sign-in and auth, test by test.
//! Each keeps the Go test's name, tables, and literal expectations.

use std::collections::BTreeMap;

use super::helpers::*;
use crate::obj;
use crate::server::protocol::*;
use crate::server::status::*;

use super::email_test::{approve, email_test_server, propose};
use super::status_test::{
    add_account, check_mute, expect_echo, expect_status, set_status, statuses_by_user,
    wait_connections,
};
use super::webauthn_test::*;

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
