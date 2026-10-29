//! persist_test.go, test by test.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::helpers::*;
use crate::obj;
use rust_stdlib::encoding::json::v2 as json;
use rust_stdlib::time;

use super::webauthn_test::*;
use crate::server::persist::{DirtySet, StoredUser, ENTRY_META};
use crate::server::protocol::*;
use crate::server::{Config, State};
use crate::store::{self, Entry, Store};

/// Starts a passkey-enabled server on a store.
pub(super) fn start_with_store(s: Arc<dyn Store>, upload_dir: &str) -> TestServer {
    start_with(s, upload_dir, |_| {})
}

/// `start_with_store` with `configure` applied to the configuration.
pub(super) fn start_with(
    s: Arc<dyn Store>,
    upload_dir: &str,
    configure: impl FnOnce(&mut Config),
) -> TestServer {
    let mut config = default_config();
    config.web_authn = Some(test_web_authn());
    config.store = Some(s);
    config.upload_dir = upload_dir.to_owned();
    configure(&mut config);
    new_test_server(config)
}

impl State {
    /// Renders the whole state as the entries a store holding it would have,
    /// for checking that every change reaches the store (Go's `dumpLocked`).
    pub fn dump_locked(&self) -> Vec<Entry> {
        let mut all = DirtySet {
            used_ids: self.used_ids.iter().cloned().collect(),
            ..DirtySet::default()
        };
        for r in self.rooms.values() {
            all.rooms.insert(r.id.clone());
            all.records.extend(r.log.iter().copied());
        }
        all.messages = self.messages.keys().cloned().collect();
        all.users = self.users.keys().cloned().collect();
        all.sessions = self.sessions.keys().copied().collect();
        all.devices = self.devices.keys().copied().collect();
        all.bots = self.bots.keys().copied().collect();
        all.embeds = self.embeds.keys().cloned().collect();
        all.pushes = self.pushes.keys().cloned().collect();
        all.vapid = self.vapid_stored;
        let mut entries = self.entries_for(&all);
        entries.push(Entry::put(
            ENTRY_META,
            "counters",
            encode_json(&self.meta_locked()).unwrap(),
        ));
        entries
    }
}

fn load(s: &dyn Store) -> BTreeMap<String, String> {
    let mut got = BTreeMap::new();
    s.load(&mut |e| {
        got.insert(
            format!("{}/{}", e.kind, e.id),
            String::from_utf8(e.value.unwrap_or_default()).unwrap(),
        );
        Ok(())
    })
    .unwrap();
    got
}

#[test]
fn test_state_survives_restart() {
    type Opener = Box<dyn Fn() -> Arc<dyn Store>>;
    let dir = TempDir::new("apron-persist-");
    let path = format!("{dir}/aprond.db");
    let memory: Arc<dyn Store> = Arc::new(store::Memory::new());
    let openers: Vec<(&str, Opener)> = vec![
        ("memory", Box::new(move || memory.clone())),
        (
            "sqlite",
            Box::new(move || Arc::new(store::SQLite::open(&path).unwrap())),
        ),
    ];
    for (name, open) in openers {
        let upload_dir = format!("{dir}/uploads-{name}");
        let mut server = start_with_store(open(), &upload_dir);
        let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
        let registered = register_test_passkey(&mut owner, &mut new_test_authenticator());
        let owner_id = you_of(&registered)["user_id"].as_str().unwrap().to_owned();
        let token = registered["token"].as_str().unwrap().to_owned();
        let mut guest = dial_test_client(&server);
        owner.drain();

        let (hello, _) = save(
            &mut owner,
            "hello",
            obj! {"body" => obj! {"text" => "Hello <world> & all"}},
        );
        guest.drain();
        react(&mut guest, "react", &hello, &["👍"]);
        owner.drain();
        let (gone, _) = save(
            &mut owner,
            "gone",
            obj! {"body" => obj! {"text" => "Secret first line\nmore"}},
        );
        guest.drain();
        let (thread, _) = save_room(
            &mut owner,
            "thread",
            obj! {"parent_room_id" => "general", "description" => "Hello thread"},
        );
        let (ops, _) = save_room(
            &mut owner,
            "ops",
            obj! {"title" => "Ops", "private" => true},
        );
        owner.request(
            "message",
            "delete",
            obj! {"room_id" => "general", "message_id" => gone.as_str(), "deleted" => true},
        );
        let attached = post_embeds(
            &mut owner,
            "attach",
            obj! {"room_id" => ops.as_str(), "body" => obj! {"text" => "file", "embeds" => vec![Json::from(obj! {"kind" => "upload", "title" => "dots.png"})]}},
        );
        let write_url = attached["embeds"].as_list()[0].as_object().unwrap()["write_url"]
            .as_str()
            .unwrap()
            .to_owned();
        let image = test_png();
        assert_eq!(
            http_do("PUT", &write_url, Some(&image), "image/png").0,
            201,
            "{name}: upload"
        );
        let file_url = embeds_of(&owner.notification("message")).remove(0)["url"]
            .as_str()
            .unwrap()
            .to_owned();
        let file_path = file_url
            .strip_prefix(server.http.url.as_str())
            .unwrap()
            .to_owned();
        owner.drain();
        guest.drain();

        // The guest leaves first, so that shutdown changes nothing more.
        let guest_id = guest.user_id.clone();
        drop(guest);
        expect_membership(&owner, "general", &guest_id, false);
        owner.expect_quiet();
        // Every change reached the store: after shutdown it holds exactly
        // the state the server had.
        let want: BTreeMap<String, String> = server
            .app
            .lock()
            .dump_locked()
            .into_iter()
            .map(|e| {
                (
                    format!("{}/{}", e.kind, e.id),
                    String::from_utf8(e.value.unwrap()).unwrap(),
                )
            })
            .collect();

        let mut before: BTreeMap<String, Object> = BTreeMap::new();
        for room in ["general", thread.as_str(), ops.as_str()] {
            before.insert(
                room.to_owned(),
                history_page(&mut owner, room, obj! {"limit" => Json::from(1000i64)}),
            );
        }
        let stopping = time::now().unix_milli();
        server.stop();
        let reopened = open();
        let mut stored = load(reopened.as_ref());
        reopened.close().unwrap();
        // Shutdown closes the owner's connection, which shows them offline,
        // so it adds their seen and stores them as no longer shown otherwise
        // (§4.5.2).
        let key = format!("user/{owner_id}");
        let mut owner_user = StoredUser::default();
        let decoded = json::unmarshal(stored[&key].as_bytes(), &mut owner_user, &[]);
        assert!(
            decoded.is_ok() && owner_user.seen >= stopping && !owner_user.shown,
            "{name}: owner after shutdown: seen {}, shown {} ({decoded:?}), want seen at least {stopping}, not shown",
            owner_user.seen,
            owner_user.shown
        );
        owner_user.seen = 0;
        owner_user.shown = true;
        stored.insert(
            key,
            String::from_utf8(encode_json(&owner_user).unwrap()).unwrap(),
        );
        assert_eq!(
            stored, want,
            "{name}: the store after shutdown differs from the server's state"
        );

        let server = start_with_store(open(), &upload_dir);
        let (mut resumed, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
        let result = passkey_result(&passkey_call(
            &mut resumed,
            "resume",
            "token",
            "",
            obj! {"token" => token.as_str()},
        ));
        assert_eq!(
            you_of(&result)["user_id"],
            Json::from(owner_id.as_str()),
            "{name}: resumed as {:?}",
            result.get("you")
        );
        for (room, page) in &before {
            let after = history_page(&mut resumed, room, obj! {"limit" => Json::from(1000i64)});
            for key in ["rooms", "messages", "reactions"] {
                assert_eq!(
                    after.get(key),
                    page.get(key),
                    "{name}: {room} {key} after restart"
                );
            }
            if room == "general" {
                // The guest's leave is in the log.
                let memberships = records(&after, "memberships");
                let last = memberships.last().unwrap()["members"].as_list()[0]
                    .as_object()
                    .cloned()
                    .unwrap();
                assert!(
                    last["user"].as_object().unwrap()["user_id"] == Json::from(guest_id.as_str())
                        && last["joined"] == Json::from(false),
                    "{name}: guest after restart: {last:?}"
                );
            }
        }
        let listed = list_rooms(&mut resumed, obj! {"filter" => "joined"});
        let ids = room_ids(listed.get("joined"));
        assert_eq!(ids.len(), 3, "{name}: joined rooms after restart: {ids:?}");
        let (status, _, content) =
            http_do("GET", &format!("{}{file_path}", server.http.url), None, "");
        assert!(
            status == 200 && content == image,
            "{name}: upload after restart: {status}"
        );
        // Guest IDs are never reissued, across restarts too.
        let mut next = dial_test_client(&server);
        assert_ne!(next.user_id, guest_id, "{name}: guest ID reissued");
        // A private room stays private.
        next.expect_error(
            "history",
            "private",
            obj! {"room_id" => ops.as_str()},
            CODE_INVALID_PARAMS,
        );
        // A new message's log_id follows every restored record.
        resumed.drain();
        let (id, _) = save(
            &mut resumed,
            "after",
            obj! {"body" => obj! {"text" => "after"}},
        );
        assert!(
            parse_id(Some(&Json::from(id.as_str())))
                > parse_id(before["general"].get("latest_log_id")),
            "{name}: log_id {id} does not follow {:?}",
            before["general"].get("latest_log_id")
        );
    }
}

/// Restores a store written while a guest was connected and an upload was
/// pending, as after a crash: the guest is retired and the pending embed
/// leaves its message.
#[test]
fn test_restore_after_a_crash() {
    let dir = TempDir::new("apron-crash-");
    let server = start_with_store(Arc::new(store::Memory::new()), &format!("{dir}/before"));
    let mut guest = dial_test_client(&server);
    let pending = post_embeds(
        &mut guest,
        "pending",
        obj! {"room_id" => "general", "body" => obj! {"text" => "soon", "embeds" => vec![Json::from(obj! {"kind" => "upload"})]}},
    );
    let crashed = Arc::new(store::Memory::new());
    crashed.apply(&server.app.lock().dump_locked()).unwrap();

    let restored = start_with_store(crashed, &format!("{dir}/after"));
    assert!(
        !restored.app.lock().users.contains_key(&guest.user_id),
        "a guest outlived the restart"
    );
    let mut c = dial_test_client(&restored);
    let page = history_page(&mut c, "general", Object::new());
    let messages = records(&page, "messages");
    let last = messages.last().unwrap();
    assert!(
        last.get("message_id") == pending.get("message_id") && embeds_of(last).is_empty(),
        "pending upload after restart: {last:?}"
    );
    let memberships = records(&page, "memberships");
    let left = memberships
        .iter()
        .flat_map(|m| m["members"].as_list().to_vec())
        .any(|e| {
            let m = e.as_object().unwrap();
            m["user"].as_object().unwrap()["user_id"] == Json::from(guest.user_id.as_str())
                && m["joined"] == Json::from(false)
        });
    assert!(
        left,
        "no leave logged for the retired guest: {memberships:?}"
    );
    drop((c, guest, restored, server));
}

/// Roles from the configuration are granted to accounts, shown in their
/// current user objects, and never settable with `me`; a granted user_id
/// that was never used is not given to a guest. server.welcome is the
/// configured Markdown, and a summary without it.
#[test]
fn test_roles_and_welcome() {
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let dir = TempDir::new("apron-roles-");
    let mut server = start_with_store(kept.clone(), &format!("{dir}/before"));
    let (mut ada, frame) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    assert!(
        frame["params"].as_object().unwrap()["welcome"]
            .as_str()
            .unwrap()
            .starts_with("Guests can "),
        "welcome without configuration: {frame:?}"
    );
    let registered = register_test_passkey(&mut ada, &mut new_test_authenticator());
    let ada_id = you_of(&registered)["user_id"].as_str().unwrap().to_owned();
    assert_eq!(
        you_of(&registered).get("roles"),
        Some(&Json::Array(vec![])),
        "an account without roles: {registered:?}"
    );
    drop(ada);
    server.stop();

    let welcome = "Chat as a guest, or **sign in** to keep your name.";
    let server = start_with(kept.clone(), &format!("{dir}/after"), |config| {
        config.welcome = welcome.into();
        config.roles = BTreeMap::from([
            ("admin".into(), vec![ada_id.clone(), "Newbie".into()]),
            ("mod".into(), vec![ada_id.clone()]),
        ]);
    });
    let (mut ada, frame) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    assert_eq!(
        frame["params"].as_object().unwrap().get("welcome"),
        Some(&Json::from(welcome)),
        "server frame: {frame:?}"
    );
    let resumed = passkey_result(&passkey_call(
        &mut ada,
        "resume",
        "token",
        "",
        obj! {"token" => registered["token"].clone()},
    ));
    let admin_moderator = Json::from(vec!["admin".to_owned(), "mod".to_owned()]);
    assert_eq!(
        you_of(&resumed).get("roles"),
        Some(&admin_moderator),
        "resumed account's roles: {resumed:?}"
    );
    // `me` cannot set roles, nor clear them.
    let you = you_of(&ada.result(
        "me",
        "me",
        obj! {"roles" => Json::Array(vec![]), "name" => "Ada"},
    ));
    assert_eq!(
        you.get("roles"),
        Some(&admin_moderator),
        "me changed roles: {you:?}"
    );

    let (mut guest, _) = dial_raw(&server);
    let (_, authed) = guest.request(
        "auth",
        "auth",
        obj! {"scheme" => "guest", "user_id" => "newbie"},
    );
    guest.user_id = you_of(&authed)["user_id"].as_str().unwrap().to_owned();
    expect_joined_default(&guest, &guest.user_id);
    assert_ne!(guest.user_id, "newbie", "a guest took a granted user_id");
    let you = you_of(&guest.result(
        "me",
        "me",
        obj! {"roles" => Json::from(vec!["admin".to_owned()])},
    ));
    assert!(!you.contains_key("roles"), "me granted roles: {you:?}");
    // Roles travel in current objects, such as room_list's users, and not
    // in recorded ones.
    ada.drain();
    let listed = list_rooms(&mut guest, obj! {"room_id" => "general", "members" => true});
    let roles_of = |users: &Json| {
        users
            .as_list()
            .iter()
            .filter_map(Json::as_object)
            .find(|u| u["user_id"] == Json::from(ada_id.as_str()))
            .and_then(|u| u.get("roles").cloned())
    };
    assert_eq!(
        roles_of(&listed["users"]),
        Some(admin_moderator.clone()),
        "listed users: {:?}",
        listed["users"]
    );
    ada.user_id = ada_id.clone();
    let (_, snapshot) = save(&mut ada, "hello", obj! {"body" => obj! {"text" => "hi"}});
    guest.drain();
    assert_eq!(
        snapshot.get("from"),
        Some(&Json::from(
            obj! {"user_id" => ada_id.as_str(), "name" => "Ada"}
        )),
        "recorded sender"
    );
    // room_update joined carries them too.
    let (ops_room, _) = save_room(&mut ada, "ops", obj! {"title" => "Ops"});
    let (before, _) = guest.request(
        "room_join",
        "join-ops",
        obj! {"room_id" => ops_room.as_str()},
    );
    let joined = notification_params(&before[0], "room_update");
    assert_eq!(
        roles_of(&joined["users"]),
        Some(admin_moderator.clone()),
        "room_update joined users: {before:?}"
    );
    ada.drain();
    // An admin may remove others from any room they can see.
    let (room, _) = save_room(&mut guest, "room", obj! {"title" => "Mine"});
    ada.result(
        "room_leave",
        "remove",
        obj! {"room_id" => room.as_str(), "user_id" => guest.user_id.as_str()},
    );
    expect_left(&guest, &room, &guest.user_id);
    guest.expect_error(
        "room_leave",
        "remove-admin",
        obj! {"room_id" => "general", "user_id" => ada_id.as_str()},
        CODE_DENIED,
    );
    drop((ada, guest));
    let mut server = server;
    server.stop();

    // The roles are the account's now: they stay with the grants gone.
    let server = start_with(kept, &format!("{dir}/later"), |_| {});
    let (mut ada, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let resumed = passkey_result(&passkey_call(
        &mut ada,
        "resume",
        "token",
        "",
        obj! {"token" => registered["token"].clone()},
    ));
    assert_eq!(
        you_of(&resumed).get("roles"),
        Some(&admin_moderator),
        "roles after the grants went: {resumed:?}"
    );
    drop(server);
}
