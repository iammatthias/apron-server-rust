//! The admin token, roles and the admin commands, ported from
//! apron-server-cloudflare's test/admin.integration.test.ts and
//! test/idle-bots.integration.test.ts where this server has the feature.

use std::sync::Arc;

use rust_stdlib::regexp::Regexp;
use rust_stdlib_crypto::sha256;

use super::helpers::*;
use super::persist_test::start_with;
use super::webauthn_test::*;
use crate::obj;
use crate::server::protocol::*;
use crate::server::Config;
use crate::store::{self, Store};

pub const ADMIN_TOKEN: &str = "admin-token-for-tests-0123456789";

/// A passkey server whose admin token is ADMIN_TOKEN.
pub fn admin_test_server() -> TestServer {
    new_test_server(admin_config())
}

pub fn admin_config() -> Config {
    Config {
        web_authn: Some(test_web_authn()),
        admin_token: Some(sha256::sum256(ADMIN_TOKEN.as_bytes())),
        ..default_config()
    }
}

/// Signs c in with `token` through the token scheme and returns the reply,
/// skipping the notifications before it.
pub fn token_auth(c: &mut TestClient, token: &str) -> Object {
    let id = c.next_id("token");
    reply_to(c, "auth", &id, obj! {"scheme" => "token", "token" => token})
}

/// Sends a request and returns its reply, skipping notifications.
fn reply_to(c: &mut TestClient, method: &str, id: &str, params: Object) -> Object {
    c.write(&obj! {"method" => method, "id" => id, "params" => params});
    loop {
        let frame = c.read();
        if frame.contains_key("id") {
            return frame;
        }
    }
}

/// Connects with no origin and signs in as the admin user.
pub fn admin(server: &TestServer) -> TestClient {
    admin_on(server, "")
}

/// Connects from origin and signs in as the admin user.
pub fn admin_on(server: &TestServer, origin: &str) -> TestClient {
    let (mut c, _) = dial_origin(server, origin);
    let frame = token_auth(&mut c, ADMIN_TOKEN);
    assert_eq!(user_id_of(&passkey_result(&frame)), "admin", "{frame:?}");
    c.user_id = "admin".into();
    c.drain();
    c
}

/// Connects on the passkey origin and registers a new passkey account.
pub fn account(server: &TestServer) -> TestClient {
    let (mut c, _) = dial_origin(server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut c, &mut new_test_authenticator());
    c.user_id = user_id_of(&registered);
    c.drain();
    c
}

pub fn user_id_of(result: &Object) -> String {
    you_of(result)["user_id"].as_str().unwrap().to_owned()
}

/// Runs a command and returns the text of the one ~private notice before
/// its empty result; other notifications it causes are skipped.
pub fn private_reply(c: &mut TestClient, text: &str) -> String {
    let id = c.next_id("command");
    let (before, result) = c.request("command", &id, obj! {"body" => obj! {"text" => text}});
    let private = obj! {"user_id" => "~private", "name" => "System message to you"};
    let notices: Vec<Object> = before
        .iter()
        .filter(|frame| frame.get("method") == Some(&Json::from("message")))
        .map(|frame| notification_params(frame, "message"))
        .filter(|notice| notice.get("from") == Some(&Json::from(private.clone())))
        .collect();
    assert!(
        result.is_empty() && notices.len() == 1,
        "{text} result {result:?} after {before:?}"
    );
    notices[0]["body"].as_object().unwrap()["text"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// How the admin commands' notices name a user: `**name** (`user_id`)`.
pub fn who(server: &TestServer, user_id: &str) -> String {
    let name = server.app.lock().users[user_id].name.clone();
    format!("**{name}** (`{user_id}`)")
}

/// Runs a command that fails and returns its error, skipping the
/// notifications before it.
pub fn command_error(c: &mut TestClient, text: &str) -> (i64, String) {
    let id = c.next_id("command");
    let frame = reply_to(c, "command", &id, obj! {"body" => obj! {"text" => text}});
    let error = frame
        .get("error")
        .and_then(Json::as_object)
        .unwrap_or_else(|| panic!("{text}: {frame:?}"));
    (
        match error["code"] {
            Json::Number(code) => code as i64,
            ref other => panic!("code {other:?}"),
        },
        error["message"].as_str().unwrap().to_owned(),
    )
}

/// The admin token signs in as the user admin from any origin, without a
/// session token, making it on first use with the admin role and a join of
/// general after the result; the admin user never takes a passkey or a
/// device token, and a signed-in account cannot switch to it.
#[test]
fn test_admin_token_signs_in_as_admin() {
    let server = admin_test_server();
    let mut watcher = dial_test_client(&server);
    let (mut c, _) = dial_raw(&server);
    let frame = token_auth(&mut c, ADMIN_TOKEN);
    let result = passkey_result(&frame);
    assert_eq!(
        result,
        obj! {"you" => obj! {
            "user_id" => "admin", "name" => "Admin", "status" => "online",
            "roles" => strings(&["admin"]),
            "ext" => obj! {"permissions" => obj! {"add_members" => true, "move_any" => true}},
        }},
        "admin sign-in"
    );
    expect_joined_default(&c, "admin");
    expect_membership(&watcher, "general", "admin", true);
    c.user_id = "admin".into();
    c.drain();

    // A second connection signs in as the same user, joining nothing again.
    let mut again = admin_on(&server, TEST_PASSKEY_ORIGIN);
    watcher.drain();
    watcher.expect_quiet();

    let error = passkey_call(&mut again, "add", "register", "begin", Object::new());
    assert_eq!(
        error.get("error"),
        Some(&Json::from(obj! {
            "code" => CODE_DENIED,
            "message" => "The admin user signs in with APRON_ADMIN_TOKEN only; make your own account an admin with /admin",
        })),
        "passkey for the admin user"
    );
    assert_eq!(
        command_error(&mut again, "/invite-device phone"),
        (
            CODE_DENIED,
            "The admin user signs in with APRON_ADMIN_TOKEN only; make your own account an admin with /admin".into()
        ),
    );

    let mut ada = account(&server);
    let frame = token_auth(&mut ada, ADMIN_TOKEN);
    assert_eq!(
        frame.get("error"),
        Some(&Json::from(obj! {
            "code" => CODE_DENIED, "message" => "Identity switching requires reconnect",
        })),
        "an account presenting the admin token"
    );
    // A guest may become the admin; a wrong token is no admin token.
    let mut guest = dial_test_client(&server);
    let frame = token_auth(&mut guest, "admin-token-for-tests-012345678X");
    assert!(frame.contains_key("error"), "wrong token: {frame:?}");
    assert_eq!(
        user_id_of(&passkey_result(&token_auth(&mut guest, ADMIN_TOKEN))),
        "admin"
    );
}

/// Without a configured token, nothing signs in as admin, and nobody may
/// take the user_id either.
#[test]
fn test_no_admin_token() {
    let server = passkey_test_server();
    let (mut c, _) = dial_raw(&server);
    let frame = token_auth(&mut c, ADMIN_TOKEN);
    assert!(frame.contains_key("error"), "{frame:?}");
    assert!(
        server.app.lock().user_id_taken_locked("Admin"),
        "admin is free to take"
    );
}

/// The admin user and its role survive a restart.
#[test]
fn test_admin_user_persists() {
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let dir = TempDir::new("apron-admin-");
    let configure = |config: &mut Config| {
        config.admin_token = admin_config().admin_token;
    };
    let mut server = start_with(kept.clone(), &format!("{dir}/a"), configure);
    drop(admin(&server));
    server.stop();
    let server = start_with(kept, &format!("{dir}/b"), configure);
    let (mut c, _) = dial_raw(&server);
    let result = passkey_result(&token_auth(&mut c, ADMIN_TOKEN));
    assert_eq!(you_of(&result)["roles"], strings(&["admin"]));
    // Already in general: no join follows.
    c.expect_quiet();
}

/// The `user` notification that follows a profile change, from c's next
/// frames: `you` for the user's own connection, `new` for others.
fn user_update(c: &TestClient, key: &str) -> Object {
    let frame = c.read();
    notification_params(&frame, "user")[key]
        .as_object()
        .cloned()
        .unwrap_or_else(|| panic!("want user {key}: {frame:?}"))
}

/// The admin commands are listed and run for admins only (Cloudflare's
/// "lists and runs the admin commands for admins only").
#[test]
fn test_admin_commands_for_admins_only() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut alice = account(&server);
    let help = private_reply(&mut admin, "/help");
    for usage in [
        "/admin [remove] <user_id>",
        "/role <user_id> [<role>]",
        "/invite-bot",
    ] {
        assert!(help.contains(usage), "admin help lacks {usage}: {help}");
    }
    let plain = private_reply(&mut alice, "/help");
    assert!(
        plain.contains("/invite-bot") && !plain.contains("/admin") && !plain.contains("/role"),
        "account help: {plain}"
    );
    for (text, name) in [
        ("/admin admin".to_owned(), "admin"),
        (format!("/admin {}", alice.user_id), "admin"),
        ("/role admin".to_owned(), "role"),
    ] {
        assert_eq!(
            command_error(&mut alice, &text),
            (CODE_DENIED, format!("Only an admin can use /{name}")),
            "{text}"
        );
    }
    let mut guest = dial_test_client(&server);
    assert_eq!(
        command_error(&mut guest, "/role admin"),
        (CODE_DENIED, "Only an admin can use /role".into()),
    );
}

/// /admin makes an account an admin, but not a guest, bot, or unknown user;
/// the new admin runs the admin commands, and /admin remove takes the role
/// away, announced with `roles: []` (§3.3), though never from the user
/// admin.
#[test]
fn test_admin_grants_and_removes() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut carol = account(&server);
    let mut mate = account(&server);
    let guest = dial_test_client(&server);
    let carol_id = carol.user_id.clone();
    let who = who(&server, &carol_id);
    let name_of = |c: &TestClient| c.user_id.clone();
    let mut bot_owner = account(&server);
    let bot_token = private_reply(&mut bot_owner, "/invite-bot");
    assert!(bot_token.contains("apron_bot_"), "{bot_token}");
    admin.drain();
    carol.drain();
    mate.drain();

    assert_eq!(
        command_error(&mut carol, "/role admin"),
        (CODE_DENIED, "Only an admin can use /role".into()),
    );
    assert_eq!(
        private_reply(&mut admin, &format!("/admin {carol_id}")),
        format!("{who} is now an admin.")
    );
    let you = user_update(&carol, "you");
    assert_eq!(you["roles"], strings(&["admin"]), "carol's you: {you:?}");
    let new = user_update(&mate, "new");
    assert_eq!(new["roles"], strings(&["admin"]), "mate's new: {new:?}");
    assert_eq!(
        private_reply(&mut admin, &format!("/admin @{carol_id}")),
        format!("{who} is already an admin.")
    );
    admin.drain();
    // The new admin runs the admin commands.
    assert_eq!(
        private_reply(&mut carol, "/role admin"),
        "**Admin** (`admin`) has the roles `admin`."
    );
    for target in [name_of(&guest), "bot_nobody".into(), "nobody_123".into()] {
        let (code, message) = command_error(&mut admin, &format!("/admin {target}"));
        assert_eq!(code, CODE_INVALID_PARAMS, "/admin {target}: {message}");
    }
    assert_eq!(
        command_error(&mut admin, &format!("/admin bot_{}", bot_owner.user_id)),
        (CODE_DENIED, "A bot can't be an admin".into()),
    );
    for usage in ["/admin", "/admin remove", "/admin a b"] {
        assert_eq!(
            command_error(&mut admin, usage),
            (
                CODE_INVALID_PARAMS,
                "Usage: /admin [remove] <user_id>".into()
            ),
        );
    }

    mate.drain();
    carol.drain();
    assert_eq!(
        private_reply(&mut admin, &format!("/admin remove @{carol_id}")),
        format!("{who} is no longer an admin.")
    );
    assert_eq!(user_update(&carol, "you")["roles"], strings(&[]));
    assert_eq!(user_update(&mate, "new")["roles"], strings(&[]));
    assert_eq!(
        command_error(&mut carol, "/role admin"),
        (CODE_DENIED, "Only an admin can use /role".into()),
    );
    let listed = list_rooms(&mut mate, obj! {"room_id" => "general", "members" => true});
    let roles_of = |id: &str| {
        listed["users"]
            .as_list()
            .iter()
            .filter_map(Json::as_object)
            .find(|u| u["user_id"] == Json::from(id))
            .map(|u| u["roles"].clone())
    };
    assert_eq!(roles_of(&carol_id), Some(strings(&[])), "listed carol");
    assert_eq!(roles_of("admin"), Some(strings(&["admin"])), "listed admin");
    assert_eq!(
        private_reply(&mut admin, &format!("/admin remove {carol_id}")),
        format!("{who} was not an admin.")
    );
    assert_eq!(
        command_error(&mut admin, "/admin remove admin"),
        (CODE_DENIED, "The admin user is always an admin".into()),
    );
}

/// /role shows a user's roles and toggles one; any name is a label, and
/// `admin` also runs the admin commands.
#[test]
fn test_role_shows_and_toggles() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut labeled = account(&server);
    let mut mate = account(&server);
    let user_id = labeled.user_id.clone();
    let who = who(&server, &user_id);
    labeled.drain();
    mate.drain();
    assert_eq!(
        private_reply(&mut admin, &format!("/role {user_id}")),
        format!("{who} has no roles.")
    );
    assert_eq!(
        private_reply(&mut admin, &format!("/role @{user_id} Friend")),
        format!("{who} now has the role `friend`.")
    );
    assert_eq!(user_update(&labeled, "you")["roles"], strings(&["friend"]));
    assert_eq!(user_update(&mate, "new")["roles"], strings(&["friend"]));
    assert_eq!(
        command_error(&mut labeled, "/role admin"),
        (CODE_DENIED, "Only an admin can use /role".into()),
        "a label grants nothing"
    );
    private_reply(&mut admin, &format!("/role {user_id} admin"));
    labeled.drain();
    private_reply(&mut labeled, "/role admin");
    assert_eq!(
        private_reply(&mut admin, &format!("/role {user_id}")),
        format!("{who} has the roles `friend`, `admin`.")
    );
    assert_eq!(
        private_reply(&mut admin, &format!("/role {user_id} friend")),
        format!("{who} no longer has the role `friend`.")
    );
    private_reply(&mut admin, &format!("/role {user_id} admin"));
    labeled.drain();
    assert_eq!(
        command_error(&mut labeled, "/role admin"),
        (CODE_DENIED, "Only an admin can use /role".into()),
    );
    for text in [
        format!("/role {user_id} no!pe"),
        "/role guest_1 friend".into(),
        "/role nobody_123 friend".into(),
        "/role nobody_123".into(),
    ] {
        assert_eq!(
            command_error(&mut admin, &text).0,
            CODE_INVALID_PARAMS,
            "{text}"
        );
    }
    for text in ["/role admin admin", "/role admin bot"] {
        assert_eq!(command_error(&mut admin, text).0, CODE_DENIED, "{text}");
    }
    assert_eq!(
        command_error(&mut admin, "/role"),
        (
            CODE_INVALID_PARAMS,
            "Usage: /role <user_id> [<role>]".into()
        ),
    );
    // A passkey holder is never a bot, and nobody holds a ninth role.
    assert_eq!(
        command_error(&mut admin, &format!("/role {user_id} bot")),
        (
            CODE_DENIED,
            "A bot signs in with a token and holds no passkey; this user has one".into()
        ),
    );
    for n in 0..8 {
        private_reply(&mut admin, &format!("/role {user_id} r{n}"));
    }
    assert_eq!(
        command_error(&mut admin, &format!("/role {user_id} r8")),
        (CODE_DENIED, "A user has at most 8 roles".into()),
    );
}

/// A role an admin took away stays away across restarts, though the --role
/// grant that seeded it is still configured; a role given at runtime is
/// kept.
#[test]
fn test_roles_persist_and_seed_once() {
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let dir = TempDir::new("apron-seed-");
    let mut server = start_with(kept.clone(), &format!("{dir}/a"), |config| {
        config.admin_token = admin_config().admin_token;
    });
    let ada = account(&server);
    let ada_id = ada.user_id.clone();
    drop(ada);
    server.stop();

    let configure = |config: &mut Config| {
        config.admin_token = admin_config().admin_token;
        config.roles = std::collections::BTreeMap::from([("mod".into(), vec![ada_id.clone()])]);
    };
    let mut server = start_with(kept.clone(), &format!("{dir}/b"), configure);
    let mut boss = admin(&server);
    let who = who(&server, &ada_id);
    assert_eq!(
        private_reply(&mut boss, &format!("/role {ada_id}")),
        format!("{who} has the roles `mod`.")
    );
    private_reply(&mut boss, &format!("/role {ada_id} mod"));
    private_reply(&mut boss, &format!("/role {ada_id} friend"));
    drop(boss);
    server.stop();

    let server = start_with(kept, &format!("{dir}/c"), configure);
    let mut boss = admin(&server);
    assert_eq!(
        private_reply(&mut boss, &format!("/role {ada_id}")),
        format!("{who} has the roles `friend`.")
    );
}

/// The token in a notice's first code block.
pub fn token_in(text: &str) -> String {
    text.split("```\n")
        .nth(1)
        .and_then(|block| block.split('\n').next())
        .unwrap_or_else(|| panic!("no token block in {text:?}"))
        .to_owned()
}

/// /invite-token makes an account that signs in with the token from any
/// origin, named after its user_id, in general; the notice carries a
/// link.apron.chat link. Taken, guest and bot user_ids, and non-admins, are
/// refused. (Cloudflare's test also moves the token with /rename and
/// revokes it with /purge, which this server does not have.)
#[test]
fn test_invite_token_makes_a_token_account() {
    let server = new_test_server(Config {
        public_url: "https://chat.example".into(),
        ..admin_config()
    });
    let mut admin = admin(&server);
    let mut watcher = dial_test_client(&server);
    let text = private_reply(&mut admin, "/invite-token @invited");
    let token = token_in(&text);
    assert!(
        token.starts_with("apron_invite_") && token.len() == "apron_invite_".len() + 43,
        "token {token:?}"
    );
    assert_eq!(
        text,
        format!(
            "Created `invited`, who signs in with this token instead of a passkey. It does not expire, and anyone who has it signs in as `invited`, so hand it over privately.\n\n```\n{token}\n```\n\nOr send them this link, which signs them in with any Apron app: <https://link.apron.chat/#server=wss://chat.example/ws&token={token}>\n\nTo sign in, authenticate with the token scheme: `{{\"method\": \"auth\", \"params\": {{\"scheme\": \"token\", \"token\": \"{token}\"}}}}`"
        )
    );
    expect_membership(&watcher, "general", "invited", true);
    watcher.drain();

    let (mut first, _) = dial_raw(&server);
    let result = passkey_result(&token_auth(&mut first, &token));
    assert_eq!(
        result,
        obj! {"you" => obj! {
            "user_id" => "invited", "name" => "invited", "roles" => strings(&[]), "status" => "online",
            "ext" => obj! {"permissions" => obj! {"add_members" => true}},
        }},
    );
    first.drain();
    let you = you_of(&first.result("me", "rename", obj! {"name" => "Newcomer"}));
    assert_eq!(you["name"], Json::from("Newcomer"));
    // An account may add a passkey later.
    let (mut keyed, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    passkey_result(&token_auth(&mut keyed, &token));
    keyed.drain();
    let begin = passkey_call(&mut keyed, "add", "register", "begin", Object::new());
    assert!(begin.contains_key("result"), "passkey begin: {begin:?}");

    for (text, want) in [
        (
            "/invite-token invited",
            (
                CODE_INVALID_PARAMS,
                "The user_id invited is taken".to_owned(),
            ),
        ),
        (
            "/invite-token INVITED",
            (
                CODE_INVALID_PARAMS,
                "The user_id INVITED is taken".to_owned(),
            ),
        ),
        (
            "/invite-token admin",
            (CODE_INVALID_PARAMS, "The user_id admin is taken".to_owned()),
        ),
        (
            "/invite-token general",
            (
                CODE_INVALID_PARAMS,
                "The user_id general is taken".to_owned(),
            ),
        ),
        (
            "/invite-token",
            (
                CODE_INVALID_PARAMS,
                "Usage: /invite-token <user_id>".to_owned(),
            ),
        ),
    ] {
        assert_eq!(command_error(&mut admin, text), want, "{text}");
    }
    for bad in [
        "guest_9",
        "bot_x",
        "Bot",
        "-a",
        "a-",
        "a.b",
        &"a".repeat(65),
    ] {
        let (code, message) = command_error(&mut admin, &format!("/invite-token {bad}"));
        assert!(
            code == CODE_INVALID_PARAMS && message.starts_with("A user_id is 1 to 64"),
            "{bad}: {message}"
        );
    }
    let mut plain = account(&server);
    assert_eq!(
        command_error(&mut plain, "/invite-token other"),
        (CODE_DENIED, "Only an admin can use /invite-token".into()),
    );
    // Signed in as another account, the token is refused; unknown ones are too.
    assert_eq!(
        token_auth(&mut plain, &token).get("error"),
        Some(&Json::from(
            obj! {"code" => CODE_DENIED, "message" => "Identity switching requires reconnect"}
        )),
    );
    let (mut stranger, _) = dial_raw(&server);
    assert_eq!(
        token_auth(&mut stranger, &format!("{token}x")).get("error"),
        Some(&Json::from(
            obj! {"code" => CODE_DENIED, "message" => "This invite token is not valid; ask an admin for a new one"}
        )),
    );
}

/// An account token, and its account, survive a restart; a --role grant
/// for the user_id seeds its roles.
#[test]
fn test_invite_token_persists() {
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let dir = TempDir::new("apron-invite-");
    let configure = |config: &mut Config| {
        config.admin_token = admin_config().admin_token;
        config.roles = std::collections::BTreeMap::from([("mod".into(), vec!["Friend".into()])]);
    };
    let mut server = start_with(kept.clone(), &format!("{dir}/a"), configure);
    let mut boss = admin(&server);
    let token = token_in(&private_reply(&mut boss, "/invite-token friend"));
    drop(boss);
    server.stop();
    let server = start_with(kept, &format!("{dir}/b"), configure);
    let (mut c, _) = dial_raw(&server);
    let result = passkey_result(&token_auth(&mut c, &token));
    assert_eq!(you_of(&result)["user_id"], Json::from("friend"));
    assert_eq!(you_of(&result)["roles"], strings(&["mod"]));
}

/// /role <user_id> bot makes a token account a bot in full, but not a
/// passkey holder or an admin; taking the role away makes it an account
/// again. (Cloudflare's test also refuses a bot's /rename, which this server
/// does not have.)
#[test]
fn test_role_bot_makes_a_token_account_a_bot() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let person = account(&server);
    let token = token_in(&private_reply(&mut admin, "/invite-token announcer"));
    let (mut bot, _) = dial_raw(&server);
    assert_eq!(
        you_of(&passkey_result(&token_auth(&mut bot, &token)))["roles"],
        strings(&[])
    );
    bot.drain();
    assert_eq!(
        private_reply(&mut admin, "/role announcer bot"),
        "**announcer** (`announcer`) now has the role `bot`."
    );
    assert_eq!(user_update(&bot, "you")["roles"], strings(&["bot"]));
    assert_eq!(
        command_error(&mut bot, "/invite-bot"),
        (CODE_DENIED, "A bot can't use /invite-bot".into()),
    );
    let renamed = bot.call("me", "rename-self", obj! {"name" => "Other"});
    assert_eq!(
        renamed.get("error"),
        Some(&Json::from(
            obj! {"code" => CODE_DENIED, "message" => "A bot can't change its name"}
        )),
    );
    assert_eq!(
        command_error(&mut admin, "/admin announcer"),
        (CODE_DENIED, "A bot can't be an admin".into()),
    );
    bot.user_id = "announcer".into();
    save(&mut bot, "post", obj! {"body" => obj! {"text" => "beep"}});

    assert_eq!(
        command_error(&mut admin, &format!("/role {} bot", person.user_id)).0,
        CODE_DENIED
    );
    private_reply(&mut admin, "/invite-token boss");
    private_reply(&mut admin, "/admin boss");
    assert_eq!(
        command_error(&mut admin, "/role boss bot"),
        (
            CODE_DENIED,
            "An admin can't be a bot; take away admin first".into()
        ),
    );
    assert_eq!(
        command_error(&mut admin, "/role bot_nobody bot").0,
        CODE_INVALID_PARAMS
    );

    bot.drain();
    private_reply(&mut admin, "/role announcer bot");
    assert_eq!(user_update(&bot, "you")["roles"], strings(&[]));
    let you = you_of(&bot.result("me", "rename-after", obj! {"name" => "Other"}));
    assert_eq!(you["name"], Json::from("Other"));
}

/// An admin by --role, with the admin user never made, still cannot make a
/// user `admin` with /invite-token.
#[test]
fn test_invite_token_never_makes_admin() {
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let dir = TempDir::new("apron-invite-admin-");
    let mut server = start_with(kept.clone(), &format!("{dir}/a"), |_| {});
    let (mut ada, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut ada, &mut new_test_authenticator());
    let ada_id = user_id_of(&registered);
    drop(ada);
    server.stop();
    let server = start_with(kept, &format!("{dir}/b"), |config| {
        config.roles = std::collections::BTreeMap::from([("admin".into(), vec![ada_id])]);
    });
    let (mut ada, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    passkey_result(&token_auth(&mut ada, registered["token"].as_str().unwrap()));
    ada.drain();
    assert_eq!(
        command_error(&mut ada, "/invite-token Admin"),
        (CODE_INVALID_PARAMS, "The user_id Admin is taken".into()),
    );
}

fn joined_of(frames: &[Object], user_id: &str) -> bool {
    frames.iter().any(|frame| {
        frame.get("method") == Some(&Json::from("room_update"))
            && format!("{frame:?}").contains(&format!("\"user_id\": String(\"{user_id}\")"))
    })
}

/// /invite mints a sign-up token that makes an account per use, each with
/// its own token (Appendix B), joining general after the auth result; a
/// used-up invite is dropped when tried; a new invite replaces the last and
/// /invite 0 revokes it; more than 50 uses is denied. (Cloudflare's test
/// also exhausts its budget mid-sign-up, which this server has none of.)
#[test]
fn test_invite_signs_up_accounts() {
    let server = new_test_server(Config {
        public_url: "https://chat.example".into(),
        ..admin_config()
    });
    let mut admin = admin(&server);
    let text = private_reply(&mut admin, "/invite 2");
    let invite = token_in(&text);
    assert!(
        invite.starts_with("apron_join_") && invite.len() == "apron_join_".len() + 43,
        "{invite}"
    );
    let expires = server.app.lock().join_invite.clone().unwrap().expires_ms;
    let until = rust_stdlib::time::unix_milli(expires)
        .utc()
        .format("2006-01-02 15:04");
    assert_eq!(
        text,
        format!(
            "This invite signs up 2 new users until {until} UTC, and replaces any earlier one. Each gets their own token to sign in again with, and can add a passkey after.\n\n```\n{invite}\n```\n\nOr send this link, which signs each of them up with any Apron app: <https://link.apron.chat/#server=wss://chat.example/ws&token={invite}>\n\nTo sign up, authenticate with the token scheme and a name: `{{\"method\": \"auth\", \"params\": {{\"scheme\": \"token\", \"token\": \"{invite}\", \"name\": \"Ada\"}}}}`"
        )
    );
    let week = expires - rust_stdlib::time::now().unix_milli();
    assert!(
        (7 * 86_400_000 - 60_000..=7 * 86_400_000).contains(&week),
        "expires in {week} ms"
    );

    // A guest signs up with it: a new account named as asked, with its own
    // token, whose join of general follows the result.
    let mut ada = dial_test_client(&server);
    ada.drain();
    let (before, result) = ada.request(
        "auth",
        "join",
        obj! {"scheme" => "token", "token" => invite.as_str(), "name" => "Ada"},
    );
    let ada_id = user_id_of(&result);
    assert!(
        Regexp::new(r"^ada_\d{4}$").unwrap().match_string(&ada_id),
        "{ada_id}"
    );
    assert_eq!(you_of(&result)["name"], Json::from("Ada"));
    assert_eq!(you_of(&result)["roles"], strings(&[]));
    let own = result["token"].as_str().unwrap().to_owned();
    assert!(own.starts_with("apron_invite_"), "{own}");
    assert!(
        !joined_of(&before, &ada_id),
        "join before the result: {before:?}"
    );
    assert!(joined_of(&ada.drain(), &ada_id), "no join after the result");
    ada.user_id = ada_id.clone();
    save(
        &mut ada,
        "post",
        obj! {"body" => obj! {"text" => "hi from an invite"}},
    );
    let (mut again, _) = dial_raw(&server);
    assert_eq!(
        user_id_of(&passkey_result(&token_auth(&mut again, &own))),
        ada_id
    );

    // Without a name, a sign-up is a Member.
    let (mut second, _) = dial_raw(&server);
    let member = passkey_result(&token_auth(&mut second, &invite));
    assert_eq!(you_of(&member)["name"], Json::from("Member"));
    assert!(user_id_of(&member).starts_with("member_"), "{member:?}");
    assert!(joined_of(&second.drain(), &user_id_of(&member)));
    // The third finds it used up, and it is dropped.
    let (mut third, _) = dial_raw(&server);
    let used_up = Json::from(obj! {
        "code" => CODE_DENIED,
        "message" => "This invite is used up or has expired; ask an admin for a new one",
    });
    assert_eq!(token_auth(&mut third, &invite).get("error"), Some(&used_up));
    assert!(
        server.app.lock().join_invite.is_none(),
        "used-up invite kept"
    );
    // A signed-in account cannot sign up again.
    let fresh = token_in(&private_reply(&mut admin, "/invite 1"));
    assert_eq!(
        token_auth(&mut ada, &fresh).get("error"),
        Some(&Json::from(
            obj! {"code" => CODE_DENIED, "message" => "Identity switching requires reconnect"}
        )),
    );
    // An expired invite is denied and dropped.
    server.app.lock().join_invite.as_mut().unwrap().expires_ms =
        rust_stdlib::time::now().unix_milli();
    assert_eq!(token_auth(&mut third, &fresh).get("error"), Some(&used_up));
    assert!(
        server.app.lock().join_invite.is_none(),
        "expired invite kept"
    );

    // A new invite replaces the last; /invite 0 revokes it.
    let replaced = token_in(&private_reply(&mut admin, "/invite 1"));
    let latest = token_in(&private_reply(&mut admin, "/invite 1"));
    assert_eq!(
        token_auth(&mut third, &replaced).get("error"),
        Some(&used_up)
    );
    assert_eq!(
        private_reply(&mut admin, "/invite 0"),
        "The sign-up invite is revoked."
    );
    assert_eq!(token_auth(&mut third, &latest).get("error"), Some(&used_up));
    assert_eq!(
        command_error(&mut admin, "/invite 51"),
        (CODE_DENIED, "An invite signs up at most 50 users".into()),
    );
    for bad in [
        "/invite",
        "/invite -1",
        "/invite 1000",
        "/invite x",
        "/invite 1 2",
    ] {
        assert_eq!(
            command_error(&mut admin, bad),
            (CODE_INVALID_PARAMS, "Usage: /invite <uses>, 0 to 50".into()),
            "{bad}"
        );
    }
    assert_eq!(
        command_error(&mut ada, "/invite 1"),
        (CODE_DENIED, "Only an admin can use /invite".into()),
    );
}

/// The live invite and its remaining uses survive a restart.
#[test]
fn test_invite_persists() {
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let dir = TempDir::new("apron-join-");
    let configure = |config: &mut Config| {
        config.admin_token = admin_config().admin_token;
    };
    let mut server = start_with(kept.clone(), &format!("{dir}/a"), configure);
    let mut boss = admin(&server);
    let invite = token_in(&private_reply(&mut boss, "/invite 2"));
    let (mut first, _) = dial_raw(&server);
    passkey_result(&token_auth(&mut first, &invite));
    drop((boss, first));
    server.stop();
    let server = start_with(kept, &format!("{dir}/b"), configure);
    let (mut second, _) = dial_raw(&server);
    passkey_result(&token_auth(&mut second, &invite));
    let (mut third, _) = dial_raw(&server);
    assert!(
        token_auth(&mut third, &invite).contains_key("error"),
        "a third use"
    );
}

/// An admin creates a top-level room that a guest, who may not, finds with
/// room_list and joins, and in which a thread may start (Cloudflare's
/// "an admin creates a top-level room that others find with room_list").
#[test]
fn test_admin_creates_a_top_level_room() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut guest = dial_test_client(&server);
    admin.drain();
    guest.expect_error(
        "room_set",
        "guest-room",
        obj! {"title" => "Mine"},
        CODE_DENIED,
    );

    let (room_id, record) = save_room(
        &mut admin,
        "room",
        obj! {"title" => "Random", "description" => "Off topic"},
    );
    assert!(
        record["title"] == Json::from("Random")
            && record["description"] == Json::from("Off topic")
            && !record.contains_key("parent_room_id"),
        "{record:?}"
    );
    let browse = list_rooms(&mut guest, obj! {"filter" => "not_joined"});
    assert_eq!(room_ids(browse.get("not_joined")), vec![room_id.clone()]);
    join_room(&mut guest, &room_id);
    let browse = list_rooms(&mut guest, obj! {"filter" => "not_joined"});
    assert!(room_ids(browse.get("not_joined")).is_empty(), "{browse:?}");
    admin.drain();
    let (thread, _) = save_room(
        &mut guest,
        "thread",
        obj! {"parent_room_id" => room_id.as_str(), "title" => "Side"},
    );
    assert!(!thread.is_empty());
}
