//! Status changes and mute ends on presence boundaries, as
//! apron-server-cloudflare's alarm announces them since 2cb64d3: a waiting
//! change goes out at the next multiple of `presence_alarm` (a guest's of
//! `guest_presence_alarm`) since the epoch, or at the first event after it
//! is due, whichever comes first. The test boundaries are milliseconds
//! where Cloudflare's are 15 and 60 seconds.

use rust_stdlib::time;

use super::helpers::*;
use super::status_test::*;
use super::webauthn_test::*;
use crate::obj;
use crate::server::client::PING_FRAME;

const USER_ROUND: i64 = 2_000;
const GUEST_ROUND: i64 = 4_000;
const WAIT: i64 = 300;
/// How late after its boundary a frame may arrive on a busy test machine.
const SLACK: i64 = 400;

fn config(coalesce_ms: i64, grace_ms: i64) -> crate::server::config::Config {
    let mut config = coalescing(coalesce_ms, grace_ms);
    config.limits.presence_alarm = time::Duration::from_millis(USER_ROUND);
    config.limits.guest_presence_alarm = time::Duration::from_millis(GUEST_ROUND);
    config
}

fn now() -> i64 {
    time::now().unix_milli()
}

fn boundary(at: i64, round: i64) -> i64 {
    (at + round - 1).div_euclid(round) * round
}

/// Sleeps until just after a multiple of `round`, so a wait that starts now
/// ends well before the next boundary.
fn align(round: i64) {
    let past = now().rem_euclid(round);
    time::sleep(time::Duration::from_millis(round - past + 20));
}

/// Reads c's next frame within `timeout_ms`, as sent, and when it came.
fn read_at(c: &TestClient, timeout_ms: i64) -> (String, i64) {
    let raw = c
        .read_raw(time::Duration::from_millis(timeout_ms))
        .expect("a frame before the timeout");
    (String::from_utf8(raw).unwrap(), now())
}

fn offline_frame(user_id: &str, seen: &str) -> String {
    format!(
        r#"{{"method":"user","params":{{"new":{{"seen":"{seen}","status":"offline","user_id":"{user_id}"}}}}}}"#
    )
}

/// A registered user who closes their connection is shown offline after
/// the grace, at the next presence boundary rather than when the grace
/// ends.
#[test]
fn test_offline_goes_out_on_the_presence_boundary() {
    let server = new_test_server(config(0, WAIT));
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    register_test_passkey(&mut b, &mut new_test_authenticator());
    let user_id = b.user_id.clone();
    expect_registered(&a, &user_id);
    watching(&mut [&mut a]);
    a.drain();
    align(USER_ROUND);
    let closing = now();
    drop(b);
    wait_connections(&server, &user_id, 0);
    let (frame, at) = read_at(&a, USER_ROUND + SLACK);
    let seen = check_status(&decode_frame(frame.as_bytes()), &user_id, "offline");
    assert_eq!(frame, offline_frame(&user_id, &seen));
    let due = boundary(closing + WAIT, USER_ROUND);
    assert!(
        at >= due && at < due + SLACK,
        "offline at {at}, want on the boundary {due}"
    );
    a.expect_quiet();
}

/// A guest's change waits for the coarser guest boundary.
#[test]
fn test_guest_change_goes_out_on_the_guest_boundary() {
    let server = new_test_server(config(WAIT, 0));
    let mut a = dial_test_client(&server);
    watching(&mut [&mut a]);
    a.drain();
    align(GUEST_ROUND);
    let signing_in = now();
    let mut b = dial_test_client(&server);
    expect_membership(&a, "general", &b.user_id, true);
    expect_status(&a, &b.user_id, "online");
    b.status(obj! {"idle" => 300i64});
    let (frame, at) = read_at(&a, GUEST_ROUND + SLACK);
    assert_eq!(
        frame,
        format!(
            r#"{{"method":"user","params":{{"new":{{"status":"idle","user_id":"{}"}}}}}}"#,
            b.user_id
        )
    );
    let due = boundary(signing_in + WAIT, GUEST_ROUND);
    assert!(
        at >= due && at < due + SLACK,
        "idle at {at}, want on the guest boundary {due}"
    );
    assert!(
        at - signing_in > GUEST_ROUND / 2,
        "idle at {at}, before the guest boundary"
    );
}

/// A frame from anyone after a change is due announces it before its
/// boundary, as Cloudflare's sweep does; the liveness ping, which
/// Cloudflare answers without waking the object, does not.
#[test]
fn test_an_event_after_the_due_time_announces_early() {
    let server = new_test_server(config(0, WAIT));
    let mut a = dial_test_client(&server);
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    register_test_passkey(&mut b, &mut new_test_authenticator());
    let user_id = b.user_id.clone();
    expect_registered(&a, &user_id);
    watching(&mut [&mut a]);
    a.drain();
    align(USER_ROUND);
    let closing = now();
    drop(b);
    wait_connections(&server, &user_id, 0);
    time::sleep(time::Duration::from_millis(WAIT + 200));
    a.write_raw(std::str::from_utf8(PING_FRAME).unwrap());
    let (pong, _) = read_at(&a, SLACK);
    assert_eq!(pong, r#"{"method":"pong"}"#);
    assert!(
        a.read_raw(time::Duration::from_millis(100)).is_err(),
        "a frame after the ping"
    );
    let frames = a.drain();
    let at = now();
    assert!(frames.len() == 1, "frames before the fence: {frames:?}");
    check_status(&frames[0], &user_id, "offline");
    assert!(
        at < boundary(closing + WAIT, USER_ROUND),
        "offline at {at}, want before the boundary"
    );
    a.expect_quiet();
}

/// A timed mute's end is told on the presence boundary after it.
#[test]
fn test_mute_end_goes_out_on_the_presence_boundary() {
    let server = new_test_server(config(0, 0));
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    register_test_passkey(&mut b, &mut new_test_authenticator());
    b.drain();
    align(USER_ROUND);
    let muting = now();
    let frames = b.status(obj! {"mute" => 1i64});
    check_mute(&frames[0], "", &1i64.into());
    let (frame, at) = read_at(&b, USER_ROUND + SLACK);
    assert_eq!(frame, r#"{"method":"status","params":{"mute":false}}"#);
    let due = boundary(muting + 1_000, USER_ROUND);
    assert!(
        at >= due && at < due + SLACK,
        "mute end at {at}, want on the boundary {due}"
    );
}
