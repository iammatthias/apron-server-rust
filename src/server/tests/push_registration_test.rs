//! Push registration, expiry, and persistence, ported from push_test.go.
//! The relay fixture lives in push_test.rs.

use std::sync::Arc;

use rust_stdlib::time::{self, Time};

use super::helpers::*;
use super::persist_test::{start_with, start_with_store};
use super::push_test::{
    add_push, list, new_test_relay, paths, push_client, push_group, push_test_server, relay_push,
    strs,
};
use super::status_test::add_account;
use super::webpush_test::test_subscription;
use crate::obj;
use crate::server::config::Config;
use crate::server::open;
use crate::server::persist::{ENTRY_PUSH, ENTRY_USER};
use crate::server::protocol::*;
use crate::server::push::*;
use crate::server::status::{MuteState, STATUS_DND, STATUS_INVISIBLE, STATUS_NONE, STATUS_ONLINE};
use crate::server::webpush::{encode_base64_url, parse_push_keys, VapidKey};
use crate::store::{self, Entry, Store};
use crate::ws;

#[test]
fn test_push_registration() {
    let server = push_test_server();
    let mut clients = push_group(&server, 2);
    let mut b = clients.pop().unwrap();
    let mut a = clients.pop().unwrap();
    unlimit_push_registers(&server, &a.user_id);
    let (_, keys) = test_subscription();
    let endpoint = "https://push.example.net/s/abc";
    let cases: Vec<Object> = vec![
        obj! {"kind" => "ext:other", "url" => endpoint},
        obj! {"kind" => "relay"},
        obj! {"kind" => "relay", "url" => "ftp://relay.example/a"},
        obj! {"kind" => "relay", "url" => "/relative"},
        obj! {"kind" => "relay", "url" => "https://user:pass@relay.example/a"},
        obj! {"kind" => "relay", "url" => "https://relay.example/a b"},
        obj! {"kind" => "relay", "url" => endpoint, "token" => 5i64},
        obj! {"kind" => "relay", "url" => endpoint, "push_id" => ""},
        obj! {"kind" => "relay", "url" => endpoint, "push_id" => "has space"},
        obj! {"kind" => "relay", "url" => endpoint, "push_id" => "dot.ted"},
        obj! {"kind" => "relay", "url" => endpoint, "push_id" => "a".repeat(65)},
        obj! {"kind" => "relay", "url" => endpoint, "push_id" => 7i64},
        obj! {"kind" => "relay", "url" => endpoint, "keys" => "abc"},
        obj! {"kind" => "relay", "url" => endpoint, "keys" => obj! {"p256dh" => keys["p256dh"].clone()}},
        obj! {"kind" => "relay", "url" => endpoint, "keys" => obj! {"p256dh" => "AAAA", "auth" => keys["auth"].clone()}},
        obj! {"kind" => "webpush", "url" => endpoint},
        obj! {"kind" => "webpush", "url" => endpoint, "keys" => obj! {"p256dh" => keys["p256dh"].clone(), "auth" => "AAAA"}},
        obj! {"kind" => "relay", "url" => endpoint, "wake" => "mentions"},
        obj! {"kind" => "relay", "url" => endpoint, "wake" => Json::from(vec![Json::from("mentions"), Json::from(5i64)])},
        obj! {"kind" => "relay", "url" => endpoint, "wake" => Json::Null},
    ];
    for (i, params) in cases.into_iter().enumerate() {
        a.expect_error(
            "push_register",
            &format!("bad-{i}"),
            params,
            CODE_INVALID_PARAMS,
        );
    }
    // A url rejected for its size is too_large (§1.1).
    a.expect_error(
        "push_register",
        "long-url",
        obj! {"kind" => "relay", "url" => format!("https://relay.example/{}", "a".repeat(MAX_PUSH_URL_BYTES))},
        CODE_TOO_LARGE,
    );
    let registration = |user: &str| {
        server
            .app
            .lock()
            .pushes
            .get(&push_key(user, endpoint))
            .cloned()
    };
    // A registration belongs to its user and url: another user's of the
    // same url is their own, and re-registering replaces only the caller's.
    // Scopes the server does not implement are ignored.
    a.result(
        "push_register",
        "webpush",
        obj! {
            "kind" => "webpush", "url" => endpoint, "keys" => keys.clone(), "push_id" => "t65S5XBst9bSDpjJ",
            "wake" => list(&["mentions", "private", "ext:later", "unknown"]), "token" => "ignored",
        },
    );
    b.result(
        "push_register",
        "relay",
        obj! {"kind" => "relay", "url" => endpoint, "token" => "tok"},
    );
    let first = registration(&a.user_id).expect("webpush registration");
    assert!(
        first.kind == "webpush"
            && first.token.is_empty()
            && first.push_id == "t65S5XBst9bSDpjJ"
            && first.wake == WakeScope::MENTIONS | WakeScope::PRIVATE
            && first.keys.is_some(),
        "webpush registration: {first:?}"
    );
    let other = registration(&b.user_id).expect("relay registration");
    assert!(
        other.kind == "relay"
            && other.token == "tok"
            && other.wake == WakeScope::DEFAULT
            && other.keys.is_none(),
        "relay registration: {other:?}"
    );
    a.result(
        "push_register",
        "again",
        obj! {"kind" => "relay", "url" => endpoint, "keys" => keys.clone(), "wake" => Json::from(Vec::<Json>::new())},
    );
    let again = registration(&a.user_id).expect("re-registration");
    assert!(
        again.generation != first.generation
            && again.kind == "relay"
            && again.keys.is_some()
            && again.push_id.is_empty()
            && again.wake.is_empty()
            && !again.renewed.before(&first.renewed),
        "re-registration: {again:?}"
    );
    // Another spelling of the same endpoint is the same registration.
    a.result(
        "push_register",
        "spelling",
        obj! {"kind" => "relay", "url" => "HTTPS://Push.Example.NET:443/s/abc", "keys" => keys.clone(), "wake" => Json::from(Vec::<Json>::new())},
    );
    let spellings = server.app.lock().sorted_pushes(&a.user_id).len();
    assert_eq!(
        spellings, 1,
        "registrations of one endpoint under two spellings"
    );
    a.expect_error(
        "push_register",
        "long",
        obj! {"kind" => "relay", "url" => format!("https://push.example.net/{}", "a".repeat(MAX_PUSH_URL_BYTES - "https://push.example.net/".len() + 1))},
        CODE_TOO_LARGE,
    );
    // Unregistering removes only the caller's; an unknown url succeeds.
    a.result(
        "push_unregister",
        "unregister",
        obj! {"url" => "https://PUSH.example.net/s/abc"},
    );
    a.result(
        "push_unregister",
        "unknown",
        obj! {"url" => "https://push.example.net/never"},
    );
    assert!(
        registration(&a.user_id).is_none() && registration(&b.user_id).is_some(),
        "unregister removed the wrong registration"
    );
    a.expect_error(
        "push_unregister",
        "no-url",
        Object::new(),
        CODE_INVALID_PARAMS,
    );

    // A user holds at most five; another replaces the least recently
    // registered, and registering a url again renews it.
    for i in 0..5 {
        a.result(
            "push_register",
            &format!("many-{i}"),
            obj! {"kind" => "relay", "url" => format!("{endpoint}{i}")},
        );
        time::sleep(time::MILLISECOND);
    }
    a.result(
        "push_register",
        "renew",
        obj! {"kind" => "relay", "url" => format!("{endpoint}0")},
    );
    a.result(
        "push_register",
        "sixth",
        obj! {"kind" => "relay", "url" => format!("{endpoint}new")},
    );
    let prefix = format!("{} {endpoint}", a.user_id);
    let urls: Vec<String> = server
        .app
        .lock()
        .sorted_pushes(&a.user_id)
        .iter()
        .map(|k| k.trim_start_matches(&prefix).to_owned())
        .collect();
    assert!(
        urls.len() == 5
            && !urls.contains(&"1".to_owned())
            && urls.contains(&"0".to_owned())
            && urls.contains(&"new".to_owned()),
        "registrations after the sixth: {urls:?}"
    );
    a.expect_quiet();
    b.expect_quiet();
}

#[test]
fn test_push_registrations_expire() {
    let relay = new_test_relay();
    let server = push_test_server();
    let mut a = push_client(&server);
    add_account(&server, "dora", &[&a]);
    let stale = add_push(
        &server,
        "dora",
        PushRegistration {
            renewed: time::now().add(-time::Duration::from_hours(7 * 24) - time::MINUTE),
            ..relay_push(format!("{}/stale", relay.url), WakeScope::DEFAULT)
        },
    );
    add_push(
        &server,
        "dora",
        PushRegistration {
            renewed: time::now().add(-time::Duration::from_hours(6 * 24)),
            ..relay_push(format!("{}/fresh", relay.url), WakeScope::DEFAULT)
        },
    );
    save(
        &mut a,
        "mention",
        obj! {"body" => obj! {"text" => "@dora", "mentions" => list(&["dora"])}},
    );
    assert_eq!(
        paths(&relay.pushes(&server, &mut a)),
        strs(&["/fresh"]),
        "deliveries"
    );
    assert!(
        !server.app.lock().pushes.contains_key(&stale),
        "an expired registration was kept"
    );
}

/// Registrations, with their keys, push_id, and scopes, survive a restart,
/// and so do the VAPID key and the status and mutes the user set (§4.5). A
/// stored status the server does not support loads as "".
#[test]
fn test_push_and_status_survive_restart() {
    let memory: Arc<dyn Store> = Arc::new(store::Memory::new());
    let (_, keys) = test_subscription();
    let relay_url = "https://relay.example/erin";
    let stored = crate::server::persist::StoredPush {
        user: "erin".into(),
        kind: "relay".into(),
        url: relay_url.into(),
        token: "tok".into(),
        wake: WakeScope::DEFAULT.names(),
        renewed: time::now(),
        ..Default::default()
    };
    memory
        .apply(&[
            Entry::put(
                ENTRY_USER,
                "erin",
                br#"{"name":"Erin","passkey":{"handle":"aA=="}}"#.to_vec(),
            ),
            Entry::put(
                ENTRY_USER,
                "finn",
                br#"{"name":"Finn","passkey":{"handle":"aA=="},"status":"invisible"}"#.to_vec(),
            ),
            Entry::put(
                ENTRY_USER,
                "gail",
                br#"{"name":"Gail","passkey":{"handle":"aQ=="},"status":"away"}"#.to_vec(),
            ),
            Entry::put(
                ENTRY_PUSH,
                &push_key("erin", relay_url),
                encode_json(&stored).unwrap(),
            ),
        ])
        .unwrap();
    let dir = TempDir::new("apron-push-");
    let mut server = start_with_store(memory.clone(), &dir);
    let (_, frame) = dial_raw(&server);
    let key = frame["params"].as_object().unwrap()["push"]
        .as_object()
        .unwrap()["webpush"]
        .as_object()
        .unwrap()["key"]
        .clone();
    {
        let mut st = server.app.lock();
        let relay = st.pushes.get(&push_key("erin", relay_url)).cloned();
        assert!(
            relay.as_ref().is_some_and(|r| r.token == "tok"
                && r.wake == WakeScope::DEFAULT
                && r.live(&time::now())),
            "relay registration: {relay:?}"
        );
        let subscription = parse_push_keys(
            keys["p256dh"].as_str().unwrap(),
            keys["auth"].as_str().unwrap(),
        )
        .unwrap();
        st.add_push_locked(PushRegistration {
            user_id: "erin".into(),
            kind: "webpush".into(),
            url: "https://push.example/s".into(),
            push_id: "p1".into(),
            keys: Some(subscription),
            wake: WakeScope::JOINED | WakeScope::BADGE,
            ..PushRegistration::default()
        });
        let (erin, finn, gail) = (
            &st.users["erin"].chosen,
            &st.users["finn"].chosen,
            &st.users["gail"].chosen,
        );
        assert!(
            finn == STATUS_INVISIBLE && gail == STATUS_NONE && erin == STATUS_ONLINE,
            "loaded statuses: erin {erin:?} finn {finn:?} gail {gail:?}"
        );
        let erin = st.users.get_mut("erin").unwrap();
        erin.chosen = STATUS_DND.into();
        erin.mute = MuteState {
            forever: false,
            until: time::now().add(time::HOUR),
        };
        erin.room_mutes.insert(
            "general".into(),
            MuteState {
                forever: true,
                until: Time::default(),
            },
        );
        st.users.get_mut("finn").unwrap().chosen = STATUS_NONE.into();
        st.touch_user("erin");
        st.touch_user("finn");
    }
    server.stop();

    let dir2 = TempDir::new("apron-push-");
    let server = start_with_store(memory.clone(), &dir2);
    let (_, frame) = dial_raw(&server);
    let again = frame["params"].as_object().unwrap()["push"]
        .as_object()
        .unwrap()["webpush"]
        .as_object()
        .unwrap()["key"]
        .clone();
    assert_eq!(again, key, "VAPID key changed across a restart");
    {
        let st = server.app.lock();
        let web = st.pushes.get(&push_key("erin", "https://push.example/s"));
        assert!(
            web.is_some_and(|w| w.kind == "webpush"
                && w.push_id == "p1"
                && w.wake == WakeScope::JOINED | WakeScope::BADGE
                && w.keys
                    .as_ref()
                    .is_some_and(|k| encode_base64_url(&k.auth) == keys["auth"].as_str().unwrap())),
            "webpush registration after restart: {web:?}"
        );
        assert!(
            st.pushes.contains_key(&push_key("erin", relay_url)) && st.pushes.len() == 2,
            "registrations after restart: {:?}",
            st.pushes.keys()
        );
        let erin = &st.users["erin"];
        assert!(
            erin.chosen == STATUS_DND
                && st.users["finn"].chosen == STATUS_NONE
                && erin.mute.active(&time::now())
                && erin.room_mutes["general"].forever,
            "status after restart: {:?} {:?}",
            erin.chosen,
            st.users["finn"].chosen
        );
    }
    let mut stored = Vec::new();
    memory
        .load(&mut |e| {
            if e.kind == ENTRY_PUSH {
                stored.push(e.id);
            }
            Ok(())
        })
        .unwrap();
    stored.sort();
    assert_eq!(
        stored,
        strs(&[
            "erin https://push.example/s",
            "erin https://relay.example/erin"
        ]),
        "stored registrations"
    );
    // A configured VAPID key replaces the stored one, and a malformed one
    // stops the server from starting.
    let configured = VapidKey::generate().unwrap();
    let mut config = default_config();
    config.vapid_private_key = configured.encoded();
    let configured_server = new_test_server(config.clone());
    let public = configured_server
        .app
        .lock()
        .vapid
        .as_ref()
        .unwrap()
        .public
        .clone();
    assert_eq!(
        public, configured.public,
        "the configured VAPID key is not used"
    );
    config.vapid_private_key = "nope".into();
    assert!(open(config).is_err(), "a malformed VAPID key was accepted");
}

/// With push disabled, stored registrations are kept but not loaded;
/// enabled again, they apply.
#[test]
fn test_disabled_push_ignores_stored_registrations() {
    let memory: Arc<dyn Store> = Arc::new(store::Memory::new());
    let url = "https://relay.example/erin";
    let stored = crate::server::persist::StoredPush {
        user: "erin".into(),
        kind: "relay".into(),
        url: url.into(),
        renewed: time::now(),
        ..Default::default()
    };
    memory
        .apply(&[
            Entry::put(
                ENTRY_USER,
                "erin",
                br#"{"name":"Erin","passkey":{"handle":"aA=="}}"#.to_vec(),
            ),
            Entry::put(
                ENTRY_PUSH,
                &push_key("erin", url),
                encode_json(&stored).unwrap(),
            ),
        ])
        .unwrap();
    let dir = TempDir::new("apron-push-");
    let mut server = start_with(memory.clone(), &dir, |c: &mut Config| c.disable_push = true);
    assert_eq!(server.app.lock().pushes.len(), 0, "with push disabled");
    server.stop();
    let server = start_with_store(memory, &dir);
    assert_eq!(server.app.lock().pushes.len(), 1, "with push enabled again");
    drop(server);
}

/// push_register is limited to PUSH_REGISTERS_PER_MINUTE a user, across
/// their connections, refused requests included.
#[test]
fn test_push_register_rate_limit() {
    use super::webauthn_test::*;
    let mut config = default_config();
    config.web_authn = Some(test_web_authn());
    let server = new_test_server(config);
    let (mut a, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut a, &mut new_test_authenticator());
    a.drain();
    let token = registered["token"].as_str().unwrap().to_owned();
    let (_, keys) = test_subscription();
    let params = obj! {"kind" => "webpush", "url" => "https://fcm.googleapis.com/fcm/send/again", "keys" => keys};
    a.expect_error(
        "push_register",
        "refused",
        obj! {"kind" => "webpush", "url" => "https://relay.example/x"},
        CODE_INVALID_PARAMS,
    );
    for i in 1..10 {
        a.result("push_register", &format!("again-{i}"), params.clone());
    }
    let _ = a.ws.close(ws::STATUS_NORMAL_CLOSURE, "bye");
    let (mut second, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    super::helpers::token_auth(&mut second, &token);
    let over = reply(&mut second, "push_register", "over", params);
    let error = over["error"].as_object().expect("an error");
    assert_eq!(error["code"], Json::from(CODE_RETRY_AFTER), "{over:?}");
    assert_eq!(error["message"], Json::from("Push registrations limited"));
    let data = error["data"].as_object().unwrap();
    assert_eq!(data.keys().collect::<Vec<_>>(), ["retry_after"], "data");
    assert!(
        matches!(data["retry_after"], Json::Number(n) if n > 0.0),
        "{data:?}"
    );
}

/// push_register refuses in Cloudflare's order with Cloudflare's texts:
/// kind, wake, push_id, the url's size, then the url, then the keys.
#[test]
fn test_push_register_refusals() {
    let server = push_test_server();
    let mut c = push_client(&server);
    let (_, keys) = test_subscription();
    let url = "https://push.example.net/p";
    let long = format!(
        "https://push.example.net/{}",
        "x".repeat(MAX_PUSH_URL_BYTES)
    );
    let refusals = [
        (
            obj! {"kind" => "apns", "url" => url},
            CODE_INVALID_PARAMS,
            "Unknown push kind; this server offers relay and webpush",
        ),
        (
            obj! {"kind" => "webpush", "url" => long.as_str(), "push_id" => "a b"},
            CODE_INVALID_PARAMS,
            "push_id must be 1 to 64 letters, digits, _ or -",
        ),
        (
            obj! {"kind" => "webpush", "url" => long.as_str(), "keys" => keys.clone()},
            CODE_TOO_LARGE,
            "url is at most 512 bytes",
        ),
        (
            obj! {"kind" => "relay", "url" => "https://push.example.net/p", "token" => "t".repeat(MAX_PUSH_TOKEN_LEN + 1)},
            CODE_TOO_LARGE,
            "token is at most 4096 bytes",
        ),
        (
            obj! {"kind" => "webpush", "url" => url, "keys" => obj! {"p256dh" => 7i64, "auth" => "x"}},
            CODE_INVALID_PARAMS,
            "keys.p256dh must be an uncompressed P-256 public key in base64url",
        ),
        (
            obj! {"kind" => "webpush", "url" => url, "keys" => obj! {"p256dh" => keys["p256dh"].clone(), "auth" => "AAAA"}},
            CODE_INVALID_PARAMS,
            "keys.auth must be 16 bytes in base64url",
        ),
    ];
    for (i, (params, code, message)) in refusals.into_iter().enumerate() {
        let frame = c.call("push_register", &format!("r{i}"), params);
        assert_eq!(
            frame.get("error"),
            Some(&Json::from(obj! {"code" => code, "message" => message})),
            "{message}"
        );
    }
}
