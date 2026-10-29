//! The user_ids a guest's passkey registration mints, after
//! apron-server-cloudflare's `userIdSlug` and `candidateUserIdFor`
//! (test/auth.integration.test.ts).

use std::cell::Cell;

use rust_stdlib::regexp::Regexp;

use super::helpers::*;
use super::webauthn_test::*;
use crate::obj;
use crate::server::protocol::*;
use crate::server::users::{candidate_user_id, user_id_slug, USER_ID_SLUG_ATTEMPTS};
use crate::server::Config;

#[test]
fn test_user_id_slugs_follow_cloudflare() {
    let cases = [
        ("Foo", "foo"),
        ("  Foo Bar!! ", "foo_bar"),
        // Cloudflare decomposes first and gets "zoe_angstrom"; without NFKD
        // each accented letter is a run of other characters.
        ("Zoë Ångström", "zo_ngstr_m"),
        ("A very long display name indeed", "a_very_long_disp"),
        ("abcdefghijklmno pq", "abcdefghijklmno"),
        ("Alexandria Ocasio-Cortez the 3rd", "alexandria_ocasi"),
        ("日本語", ""),
        ("", ""),
        ("!!!", ""),
        ("Guest", ""),
        ("guest 12", ""),
        ("Bot", ""),
        ("bot-army", ""),
        ("Guesthouse", "guesthouse"),
        ("Bottle", "bottle"),
        // user_<n> is this server's email-account counter.
        ("User", ""),
        ("user 7", ""),
        ("Username", "username"),
    ];
    for (name, want) in cases {
        assert_eq!(user_id_slug(name), want, "slug of {name:?}");
    }
}

#[test]
fn test_candidate_user_id_takes_the_first_free_slug() {
    let calls = Cell::new(0);
    let id = candidate_user_id("Foo", |_| {
        calls.set(calls.get() + 1);
        false
    });
    assert_eq!(calls.get(), 1);
    assert!(
        Regexp::new(r"^foo_[0-9]{4}$").unwrap().match_string(&id),
        "{id}"
    );
}

#[test]
fn test_candidate_user_id_falls_back_after_eight_taken() {
    let tried = std::cell::RefCell::new(Vec::new());
    let id = candidate_user_id("Foo", |id| {
        tried.borrow_mut().push(id.to_owned());
        true
    });
    assert_eq!(USER_ID_SLUG_ATTEMPTS, 8);
    assert_eq!(tried.borrow().len(), 8);
    let slugged = Regexp::new(r"^foo_[0-9]{4}$").unwrap();
    assert!(tried.borrow().iter().all(|id| slugged.match_string(id)));
    assert!(
        Regexp::new(r"^u_[A-Za-z0-9_-]{22}$")
            .unwrap()
            .match_string(&id),
        "{id}"
    );
}

#[test]
fn test_candidate_user_id_without_a_slug_is_random() {
    let calls = Cell::new(0);
    for name in ["", "Guest 3", "日本語"] {
        let id = candidate_user_id(name, |_| {
            calls.set(calls.get() + 1);
            false
        });
        assert!(
            Regexp::new(r"^u_[A-Za-z0-9_-]{22}$")
                .unwrap()
                .match_string(&id),
            "{id}"
        );
    }
    assert_eq!(calls.get(), 0);
}

/// A frame with every log_id taken out, after checking each is one, so
/// frames compare as literals.
fn without_log_ids(value: &Json) -> Json {
    match value {
        Json::Object(object) => Json::Object(
            object
                .iter()
                .filter(|(key, value)| {
                    if *key == "log_id" {
                        parse_id(Some(value));
                    }
                    *key != "log_id"
                })
                .map(|(key, value)| (key.clone(), without_log_ids(value)))
                .collect(),
        ),
        Json::Array(items) => Json::Array(items.iter().map(without_log_ids).collect()),
        other => other.clone(),
    }
}

fn frames_without_log_ids(frames: &[Object]) -> Vec<Json> {
    frames
        .iter()
        .map(|frame| without_log_ids(&Json::from(frame.clone())))
        .collect()
}

fn membership_frame(room_id: &str, user: Object, joined: bool) -> Json {
    Json::from(obj! {"method" => "room_update", "params" => obj! {
        "memberships" => vec![Json::from(obj! {
            "room_id" => room_id,
            "members" => vec![Json::from(obj! {"user" => user, "joined" => joined})],
        })],
    }})
}

fn status_frame(user_id: &str, status: &str) -> Json {
    Json::from(obj! {"method" => "user", "params" => obj! {
        "new" => obj! {"user_id" => user_id, "status" => status},
    }})
}

/// Begins a guest's registration with params and returns the WebAuthn user
/// the creation options offer and the options.
fn begin_registration(c: &mut TestClient, params: Object) -> (Object, Object) {
    let options = passkey_result(&passkey_call(c, "begin", "register", "begin", params));
    let user = passkey_public_key(&options)["user"]
        .as_object()
        .unwrap()
        .clone();
    (user, options)
}

fn finish_registration(c: &mut TestClient, options: &Object) -> Object {
    let credential = new_test_authenticator().registration(options, TEST_PASSKEY_ORIGIN);
    c.write(
        &obj! {"method" => "auth", "id" => "finish", "params" => obj! {
            "scheme" => "webauthn", "action" => "register", "step" => "finish",
            "challenge_id" => c.passkey_challenge.as_str(), "credential" => credential,
        }},
    );
    c.read()
}

/// The whole exchange of a guest in two rooms registering a passkey, as the
/// registering connection and someone in both rooms see it.
#[test]
fn test_guest_registration_frames() {
    let server = passkey_test_server();
    let mut a = dial_test_client(&server);
    grant_role(&server, &a.user_id, "mod");
    let (lab, _) = save_room(&mut a, "lab", obj! {"title" => "Lab"});
    let (mut b, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    guest_auth(&mut b);
    join_room(&mut b, &lab);
    let guest = b.user_id.clone();
    watching(&mut [&mut a, &mut b]);
    a.drain();
    b.drain();

    let (user, options) = begin_registration(&mut b, obj! {"name" => "  Ada   Lovelace "});
    let account = user["name"].as_str().unwrap().to_owned();
    assert!(
        Regexp::new(r"^ada_lovelace_[0-9]{4}$")
            .unwrap()
            .match_string(&account),
        "offered user {user:?}"
    );
    assert_eq!(
        user["displayName"],
        Json::from("Ada Lovelace"),
        "offered user {user:?}"
    );
    a.expect_quiet();
    b.expect_quiet();

    let reply = finish_registration(&mut b, &options);
    let result = reply["result"].as_object().unwrap();
    let token = result["token"].as_str().unwrap();
    assert_eq!(token.len(), 43, "token {token:?}");
    assert_eq!(
        Json::from(you_of(result)),
        Json::from(obj! {
            "user_id" => account.as_str(), "name" => "Ada Lovelace",
            "roles" => Vec::<Json>::new(), "status" => "online",
            "ext" => obj! {"permissions" => obj! {"add_members" => true}},
        }),
        "auth result"
    );
    let recorded = obj! {"user_id" => account.as_str(), "name" => "Ada Lovelace"};
    assert_eq!(
        frames_without_log_ids(&b.drain()),
        vec![
            membership_frame("general", recorded.clone(), true),
            membership_frame(&lab, recorded.clone(), true),
            status_frame(&a.user_id, "online"),
        ],
        "the registering connection after its result"
    );
    let guest_name = format!("Guest {}", &guest["guest_".len()..]);
    let guest_recorded = obj! {"user_id" => guest.as_str(), "name" => guest_name};
    assert_eq!(
        frames_without_log_ids(&a.drain()),
        vec![
            membership_frame("general", guest_recorded.clone(), false),
            membership_frame(&lab, guest_recorded.clone(), false),
            membership_frame("general", recorded.clone(), true),
            status_frame(&account, "online"),
            membership_frame(&lab, recorded.clone(), true),
            status_frame(&account, "online"),
            Json::from(obj! {"method" => "user", "params" => obj! {
                "new" => obj! {
                    "user_id" => account.as_str(), "name" => "Ada Lovelace",
                    "roles" => Vec::<Json>::new(), "status" => "online",
                },
                "old" => guest_recorded,
            }}),
        ],
        "someone in both rooms"
    );

    // The guest is retired for good: its user_id is gone and not reissued,
    // and the account persists with the passkey.
    let st = server.app.lock();
    assert!(!st.users.contains_key(&guest), "guest kept");
    assert!(st.used_ids.contains(&guest) && st.used_ids.contains(&account));
    assert!(
        st.users[&account].passkey.is_some(),
        "account has no passkey"
    );
}

/// A name that leaves no slug registers a u_<random> account under that
/// name; no name keeps the guest's.
#[test]
fn test_unusable_names_register_random_user_ids() {
    let random = Regexp::new(r"^u_[A-Za-z0-9_-]{22}$").unwrap();
    for (name, want) in [("日本語", "日本語"), ("Guest 9", "Guest 9"), ("bot", "bot")] {
        let server = passkey_test_server();
        let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
        let result = register_passkey_named(&mut c, &mut new_test_authenticator(), Some(name));
        let you = you_of(&result);
        assert!(
            random.match_string(&c.user_id),
            "{name:?} registered as {you:?}"
        );
        assert_eq!(
            you["name"],
            Json::from(want),
            "{name:?} registered as {you:?}"
        );
    }
    let server = passkey_test_server();
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    guest_auth(&mut c);
    let (user, _) = begin_registration(&mut c, Object::new());
    assert!(
        random.match_string(user["name"].as_str().unwrap()),
        "offered {user:?}"
    );
    assert_eq!(
        user["displayName"],
        Json::from("Guest 1"),
        "offered {user:?}"
    );
}

/// Eight taken `<slug>_<digits>` ids, here every one, fall back to a
/// random id; ids taken in another case, here by a role grant, count too.
#[test]
fn test_taken_slug_ids_fall_back_to_random() {
    let random = Regexp::new(r"^u_[A-Za-z0-9_-]{22}$").unwrap();
    let every: Vec<String> = (0..10_000).map(|n| format!("ada_{n:04}")).collect();

    let server = passkey_test_server();
    server.app.lock().used_ids.extend(every.iter().cloned());
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    register_passkey_named(&mut c, &mut new_test_authenticator(), Some("Ada"));
    assert!(
        random.match_string(&c.user_id),
        "registered as {}",
        c.user_id
    );

    let mut config: Config = crate::server::default_config();
    config.web_authn = Some(test_web_authn());
    config.roles.insert(
        "admin".into(),
        every.iter().map(|id| id.to_uppercase()).collect(),
    );
    let server = super::helpers::new_test_server(config);
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let result = register_passkey_named(&mut c, &mut new_test_authenticator(), Some("Ada"));
    assert!(
        random.match_string(&c.user_id),
        "registered as {}",
        c.user_id
    );
    assert_eq!(you_of(&result)["roles"], Json::from(Vec::<Json>::new()));
}

/// A user_id taken between begin and finish fails the finish, as
/// Cloudflare's does, and leaves the guest as it was.
#[test]
fn test_user_id_taken_after_begin_fails_the_finish() {
    let server = passkey_test_server();
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    guest_auth(&mut c);
    let guest = c.user_id.clone();
    let (user, options) = begin_registration(&mut c, obj! {"name" => "Ada"});
    let account = user["name"].as_str().unwrap().to_uppercase();
    assert!(server.app.lock().claim_user_id_locked(&account));
    let reply = finish_registration(&mut c, &options);
    assert_eq!(
        reply["error"],
        Json::from(obj! {"code" => CODE_INVALID_PARAMS, "message" => "identity already exists"}),
        "finish {reply:?}"
    );
    let me = c.result("me", "me", Object::new());
    assert_eq!(you_of(&me)["user_id"], Json::from(guest.as_str()));
}
