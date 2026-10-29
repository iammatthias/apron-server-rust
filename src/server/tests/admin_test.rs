//! The admin token, roles and the admin commands, ported from
//! apron-server-cloudflare's test/admin.integration.test.ts and
//! test/idle-bots.integration.test.ts where this server has the feature.

use std::sync::Arc;

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

/// Signs c in with `token` through the token scheme and returns the frame.
pub fn token_auth(c: &mut TestClient, token: &str) -> Object {
    let id = c.next_id("token");
    c.call("auth", &id, obj! {"scheme" => "token", "token" => token})
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

/// Runs a command that fails and returns its error.
pub fn command_error(c: &mut TestClient, text: &str) -> (i64, String) {
    let id = c.next_id("command");
    let frame = c.call("command", &id, obj! {"body" => obj! {"text" => text}});
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
