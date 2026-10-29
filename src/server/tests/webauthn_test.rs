//! webauthn_test.go: passkey registration, discoverable login, and token
//! sessions, driven by a software authenticator through the same verifier
//! browser-created credentials reach.

use std::sync::Arc;

use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::encoding::json::v2 as json;
use rust_stdlib::regexp::Regexp;
use rust_stdlib::time::{self, Duration};
use rust_stdlib_crypto::{ecdsa, elliptic, rand, sha256};

use super::helpers::*;
use crate::cbor;
use crate::obj;
use crate::server::protocol::*;
use crate::server::webauthn::SESSION_LIFETIME;
use crate::server::Config;
use crate::webauthn::{self, WebAuthn};

pub const TEST_PASSKEY_ORIGIN: &str = "http://localhost:5173";

/// The relying party the passkey tests use, on localhost.
pub fn test_web_authn() -> Arc<WebAuthn> {
    Arc::new(
        WebAuthn::new(webauthn::Config {
            rpid: "localhost".into(),
            rp_display_name: "Apron".into(),
            rp_origins: vec![TEST_PASSKEY_ORIGIN.into()],
        })
        .unwrap(),
    )
}

pub fn passkey_test_server() -> super::helpers::TestServer {
    let config = Config {
        web_authn: Some(test_web_authn()),
        ..default_config()
    };
    new_test_server(config)
}

pub fn passkey_call(
    c: &mut TestClient,
    id: &str,
    action: &str,
    step: &str,
    extra: Object,
) -> Object {
    let mut params = obj! {"scheme" => "webauthn", "action" => action};
    if action == "token" {
        params = obj! {"scheme" => "token"};
    } else if !step.is_empty() {
        params.insert("step".into(), step.into());
        if step == "finish" && !c.passkey_challenge.is_empty() {
            params.insert("challenge_id".into(), c.passkey_challenge.as_str().into());
        }
    }
    params.extend(extra);
    c.write(&obj! {"method" => "auth", "id" => id, "params" => params});
    let frame = c.read();
    assert_eq!(
        frame.get("id").and_then(Json::as_str),
        Some(id),
        "unexpected response: {frame:?}"
    );
    if action != "token" && step == "begin" {
        if let Some(challenge_id) = frame
            .get("result")
            .and_then(Json::as_object)
            .and_then(|result| result.get("challenge_id"))
            .and_then(Json::as_str)
        {
            c.passkey_challenge = challenge_id.to_owned();
        }
    }
    frame
}

pub fn passkey_result(frame: &Object) -> Object {
    match frame.get("result").and_then(Json::as_object) {
        Some(result) => result.clone(),
        None => panic!("expected success: {frame:?}"),
    }
}

pub fn passkey_public_key(result: &Object) -> Object {
    match result.get("public_key").and_then(Json::as_object) {
        Some(public_key) => public_key.clone(),
        None => panic!("passkey result has no public_key: {result:?}"),
    }
}

pub fn passkey_denied(frame: &Object) {
    let code = frame
        .get("error")
        .and_then(Json::as_object)
        .and_then(|e| e.get("code"));
    assert_eq!(
        code,
        Some(&Json::from(CODE_DENIED)),
        "expected denial: {frame:?}"
    );
}

fn error_code(frame: &Object) -> Option<Json> {
    frame
        .get("error")
        .and_then(Json::as_object)
        .and_then(|e| e.get("code"))
        .cloned()
}

fn str_of<'a>(object: &'a Object, key: &str) -> &'a str {
    object
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("{key} is not a string in {object:?}"))
}

/// A software authenticator produces real ES256 credentials and signatures;
/// the server exercises the same verifier as browser-created credentials.
pub struct TestAuthenticator {
    key: ecdsa::PrivateKey,
    id: Vec<u8>,
    handle: String,
    counter: u32,
}

pub fn new_test_authenticator() -> TestAuthenticator {
    TestAuthenticator {
        key: ecdsa::generate_key(elliptic::p256()).unwrap(),
        id: rand::text().into_bytes(),
        handle: String::new(),
        counter: 0,
    }
}

fn b64(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
    json::marshal(
        &obj! {"type" => kind, "challenge" => challenge, "origin" => origin, "crossOrigin" => false},
        &[],
    )
    .unwrap()
}

impl TestAuthenticator {
    pub fn registration(&mut self, options: &Object, origin: &str) -> Object {
        let public_key = passkey_public_key(options);
        let Some(user) = public_key.get("user").and_then(Json::as_object) else {
            panic!("registration public key: {public_key:?}");
        };
        self.handle = str_of(user, "id").to_owned();
        let point = self.key.public_key.bytes().unwrap();
        use cbor::Value::*;
        let cose = cbor::marshal(&Map(vec![
            (Unsigned(1), Unsigned(2)),
            (Unsigned(3), Negative(6)),
            (Negative(0), Unsigned(1)),
            (Negative(1), Bytes(point[1..33].to_vec())),
            (Negative(2), Bytes(point[33..].to_vec())),
        ]));
        let mut data = sha256::sum256(b"localhost").to_vec();
        data.extend_from_slice(&[0x45, 0, 0, 0, 0]); // UP, UV, attested credential data.
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.id);
        data.extend_from_slice(&cose);
        let attestation = cbor::marshal(&Map(vec![
            (Text("fmt".into()), Text("none".into())),
            (Text("authData".into()), Bytes(data)),
            (Text("attStmt".into()), Map(vec![])),
        ]));
        obj! {
            "id" => b64(&self.id), "rawId" => b64(&self.id), "type" => "public-key", "clientExtensionResults" => Object::new(),
            "response" => obj! {
                "clientDataJSON" => b64(&client_data("webauthn.create", str_of(&public_key, "challenge"), origin)),
                "attestationObject" => b64(&attestation),
            },
        }
    }

    pub fn assertion(&mut self, options: &Object, origin: &str, rp_id: &str, flags: u8) -> Object {
        self.counter += 1;
        let public_key = passkey_public_key(options);
        let client = client_data("webauthn.get", str_of(&public_key, "challenge"), origin);
        let mut data = sha256::sum256(rp_id.as_bytes()).to_vec();
        data.push(flags);
        data.extend_from_slice(&self.counter.to_be_bytes());
        let mut signed = data.clone();
        signed.extend_from_slice(&sha256::sum256(&client));
        let signature = ecdsa::sign_asn1(&self.key, &sha256::sum256(&signed)).unwrap();
        obj! {
            "id" => b64(&self.id), "rawId" => b64(&self.id), "type" => "public-key", "clientExtensionResults" => Object::new(),
            "response" => obj! {
                "clientDataJSON" => b64(&client), "authenticatorData" => b64(&data),
                "signature" => b64(&signature), "userHandle" => self.handle.as_str(),
            },
        }
    }
}

/// Signs c in as a guest and registers a passkey, which makes a new account
/// with a u_<random> user_id that c.user_id then names.
pub fn register_test_passkey(c: &mut TestClient, a: &mut TestAuthenticator) -> Object {
    let result = register_passkey_named(c, a, None);
    assert!(
        Regexp::new(r"^u_[A-Za-z0-9_-]{22}$")
            .unwrap()
            .match_string(&c.user_id),
        "a registration without a name is not u_<random>: {}",
        c.user_id
    );
    result
}

/// register_test_passkey with the begin asking for `name`.
pub fn register_passkey_named(
    c: &mut TestClient,
    a: &mut TestAuthenticator,
    name: Option<&str>,
) -> Object {
    let guest = you_of(&guest_auth(c))["user_id"].clone();
    let options = passkey_result(&passkey_call(
        c,
        "register-start",
        "register",
        "begin",
        name.map(|name| obj! {"name" => name}).unwrap_or_default(),
    ));
    let public_key = passkey_public_key(&options);
    let selection = public_key
        .get("authenticatorSelection")
        .and_then(Json::as_object);
    assert!(
        selection.is_some_and(
            |s| s.get("residentKey").and_then(Json::as_str) == Some("required")
                && s.get("userVerification").and_then(Json::as_str) == Some("required")
        ),
        "registration did not require resident key and user verification: {public_key:?}"
    );
    let credential = a.registration(&options, TEST_PASSKEY_ORIGIN);
    let result = passkey_result(&passkey_call(
        c,
        "register-end",
        "register",
        "finish",
        obj! {"credential" => credential},
    ));
    let account = str_of(&you_of(&result), "user_id").to_owned();
    assert_ne!(
        Json::from(account.as_str()),
        guest,
        "registration kept the guest's user_id"
    );
    // The new account takes the guest's general, which its connection gets
    // as the logged join alone.
    expect_membership(c, "general", &account, true);
    c.user_id = account;
    result
}

/// Reads what someone in general sees of a guest that joined and then
/// registered a passkey as `account`: the guest's join and leave, the
/// account's join, and `user` linking them (§3.3.3). Returns the guest's
/// user_id.
pub fn expect_registered(c: &TestClient, account: &str) -> String {
    let next = || loop {
        let frame = c.read();
        if !is_status_announcement(&frame) {
            return frame;
        }
    };
    let joined = membership_only(&next());
    let guest = str_of(
        joined["members"].as_list()[0].as_object().unwrap()["user"]
            .as_object()
            .unwrap(),
        "user_id",
    )
    .to_owned();
    assert!(
        guest.starts_with("guest_"),
        "first membership is not a guest's: {joined:?}"
    );
    check_membership(&joined, "general", &guest, true);
    check_membership(&membership_only(&next()), "general", &guest, false);
    check_membership(&membership_only(&next()), "general", account, true);
    let user = notification_params(&next(), "user");
    let guest_name = format!("Guest {}", &guest["guest_".len()..]);
    assert_eq!(
        user["old"],
        Json::from(obj! {"user_id" => guest.as_str(), "name" => guest_name}),
        "user = {user:?}"
    );
    assert_eq!(
        str_of(user["new"].as_object().unwrap(), "user_id"),
        account,
        "user = {user:?}"
    );
    guest
}

/// The user_id a registration's result signed the connection in as.
pub fn account_id(result: &Object) -> String {
    str_of(&you_of(result), "user_id").to_owned()
}

fn token_of(result: &Object) -> String {
    str_of(result, "token").to_owned()
}

fn set_session_expiry(server: &super::helpers::TestServer, d: Duration) {
    let mut st = server.app.lock();
    let keys: Vec<_> = st.sessions.keys().copied().collect();
    for key in keys {
        st.sessions.renew(&key, time::now().add(d));
    }
}

#[test]
fn test_passkey_registration_login_and_session() {
    let server = passkey_test_server();
    let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let mut a = new_test_authenticator();
    let registered = register_test_passkey(&mut owner, &mut a);
    let identity = you_of(&registered)["user_id"].clone();
    let (mut other, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let options = passkey_result(&passkey_call(
        &mut other,
        "begin",
        "login",
        "begin",
        Object::new(),
    ));
    let public_key = passkey_public_key(&options);
    assert!(
        !public_key.contains_key("allowCredentials"),
        "discoverable login unexpectedly constrained credentials: {public_key:?}"
    );
    assert_eq!(
        public_key.get("userVerification").and_then(Json::as_str),
        Some("required"),
        "login did not require user verification: {public_key:?}"
    );
    let credential = a.assertion(&options, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    let finish = obj! {"credential" => credential};
    let logged_in = passkey_result(&passkey_call(
        &mut other,
        "finish",
        "login",
        "finish",
        finish.clone(),
    ));
    assert_eq!(
        you_of(&logged_in)["user_id"],
        identity,
        "login changed identity"
    );
    // Even the identical request ID cannot replay a completed ceremony.
    passkey_denied(&passkey_call(
        &mut other, "finish", "login", "finish", finish,
    ));
    let (mut resumed, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let token = token_of(&logged_in);
    let result = passkey_result(&passkey_call(
        &mut resumed,
        "resume",
        "token",
        "",
        obj! {"token" => token.as_str()},
    ));
    assert_eq!(
        you_of(&result)["user_id"],
        identity,
        "resume changed identity"
    );
    // Token sign-out is local to the client: drop the connection and
    // reconnect. The server retains the token until its normal expiry.
    drop(resumed);
    let (mut reconnected, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let result = passkey_result(&passkey_call(
        &mut reconnected,
        "resume",
        "token",
        "",
        obj! {"token" => token.as_str()},
    ));
    assert_eq!(
        you_of(&result)["user_id"],
        identity,
        "reconnect changed identity"
    );
    // A resume renews the session: a token close to expiry is good for a
    // full lifetime again after use.
    set_session_expiry(&server, time::MINUTE);
    let (mut renewed, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let result = passkey_result(&passkey_call(
        &mut renewed,
        "resume",
        "token",
        "",
        obj! {"token" => token.as_str()},
    ));
    assert_eq!(
        result.get("token").and_then(Json::as_str),
        Some(token.as_str()),
        "resume did not return the presented token"
    );
    let renewed_expiry = server
        .app
        .lock()
        .sessions
        .get(&sha256::sum256(token.as_bytes()))
        .unwrap()
        .expires
        .clone();
    assert!(
        !renewed_expiry.before(&time::now().add(SESSION_LIFETIME - time::MINUTE)),
        "resume did not renew the session: expires {renewed_expiry:?}"
    );
    set_session_expiry(&server, -time::SECOND);
    passkey_denied(&passkey_call(
        &mut reconnected,
        "expired",
        "token",
        "",
        obj! {"token" => token_of(&registered)},
    ));
}

#[test]
fn test_registration_takes_requested_name() {
    let server = passkey_test_server();
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let guest = you_of(&guest_auth(&mut c));
    let user_of = |options: &Object| -> Object {
        match passkey_public_key(options)
            .get("user")
            .and_then(Json::as_object)
        {
            Some(user) => user.clone(),
            None => panic!("creation options have no user: {options:?}"),
        }
    };

    // A begin offers the new account as Cloudflare does: its user_id, made
    // from the name, as the user name, and the name as the display name. A
    // begin that is superseded changes nothing: the name and user_id apply
    // only to the registration that finishes.
    let abandoned = passkey_result(&passkey_call(
        &mut c,
        "begin-abandoned",
        "register",
        "begin",
        obj! {"name" => "Abandoned"},
    ));
    let user = user_of(&abandoned);
    assert!(
        Regexp::new(r"^abandoned_[0-9]{4}$")
            .unwrap()
            .match_string(str_of(&user, "name"))
            && str_of(&user, "displayName") == "Abandoned",
        "passkey not offered as the requested name's account: {user:?}"
    );
    let options = passkey_result(&passkey_call(
        &mut c,
        "begin",
        "register",
        "begin",
        obj! {"name" => "  Ada   Lovelace "},
    ));
    let user = user_of(&options);
    let account = str_of(&user, "name").to_owned();
    assert!(
        Regexp::new(r"^ada_lovelace_[0-9]{4}$")
            .unwrap()
            .match_string(&account)
            && str_of(&user, "displayName") == "Ada Lovelace",
        "passkey not offered as the normalized requested name's account: {user:?}"
    );
    let mut a = new_test_authenticator();
    let credential = a.registration(&options, TEST_PASSKEY_ORIGIN);
    let result = passkey_result(&passkey_call(
        &mut c,
        "finish",
        "register",
        "finish",
        obj! {"credential" => credential},
    ));
    let you = you_of(&result);
    assert!(
        you["user_id"] != guest["user_id"]
            && str_of(&you, "user_id") == account
            && str_of(&you, "name") == "Ada Lovelace",
        "registration did not make the offered account with the requested name: {you:?}"
    );

    // Adding a passkey to an account keeps the account's name, whatever is
    // asked.
    let (mut other, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    passkey_result(&passkey_call(
        &mut other,
        "resume",
        "token",
        "",
        obj! {"token" => token_of(&result)},
    ));
    let adding = passkey_result(&passkey_call(
        &mut other,
        "begin-add",
        "register",
        "begin",
        obj! {"name" => "Someone else"},
    ));
    assert_eq!(
        str_of(&user_of(&adding), "name"),
        "Ada Lovelace",
        "added passkey not labelled with the account's name"
    );
    let credential = new_test_authenticator().registration(&adding, TEST_PASSKEY_ORIGIN);
    let added = passkey_result(&passkey_call(
        &mut other,
        "finish-add",
        "register",
        "finish",
        obj! {"credential" => credential},
    ));
    assert_eq!(
        str_of(&you_of(&added), "name"),
        "Ada Lovelace",
        "adding a passkey renamed the account"
    );
}

#[test]
fn test_adding_passkey_preserves_stored_name() {
    for rename_during_registration in [false, true] {
        let server = passkey_test_server();
        let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
        let mut original = new_test_authenticator();
        let registered = register_test_passkey(&mut owner, &mut original);
        let (mut other, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
        passkey_result(&passkey_call(
            &mut other,
            "resume",
            "token",
            "",
            obj! {"token" => token_of(&registered)},
        ));
        let rename = |owner: &mut TestClient, other: &mut TestClient| {
            owner.write(
                &obj! {"method" => "me", "id" => "rename", "params" => obj! {"name" => "Updated name"}},
            );
            let result = passkey_result(&owner.read());
            assert_eq!(
                str_of(&you_of(&result), "name"),
                "Updated name",
                "rename was not accepted: {result:?}"
            );
            // The same user's other connection learns of the change.
            let you = other.notification("user")["you"]
                .as_object()
                .cloned()
                .unwrap();
            assert_eq!(
                str_of(&you, "name"),
                "Updated name",
                "other connection's user notification: {you:?}"
            );
        };
        if !rename_during_registration {
            rename(&mut owner, &mut other);
        }
        let options = passkey_result(&passkey_call(
            &mut other,
            "begin",
            "register",
            "begin",
            Object::new(),
        ));
        if rename_during_registration {
            rename(&mut owner, &mut other);
        }
        let mut additional = new_test_authenticator();
        let credential = additional.registration(&options, TEST_PASSKEY_ORIGIN);
        let result = passkey_result(&passkey_call(
            &mut other,
            "finish",
            "register",
            "finish",
            obj! {"credential" => credential},
        ));
        let assert_identity = |result: &Object| {
            let you = you_of(result);
            assert!(
                you["user_id"] == you_of(&registered)["user_id"]
                    && str_of(&you, "name") == "Updated name",
                "rename during registration {rename_during_registration}: registration lost the stored identity: {you:?}"
            );
        };
        assert_identity(&result);
        // Both credentials must restore the accepted name on fresh
        // connections.
        for authenticator in [&mut original, &mut additional] {
            let (mut fresh, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
            let options = passkey_result(&passkey_call(
                &mut fresh,
                "login-begin",
                "login",
                "begin",
                Object::new(),
            ));
            let credential =
                authenticator.assertion(&options, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
            let result = passkey_result(&passkey_call(
                &mut fresh,
                "login-finish",
                "login",
                "finish",
                obj! {"credential" => credential},
            ));
            assert_identity(&result);
        }
    }
}

#[test]
fn test_passkey_rejects_invalid_proofs() {
    let server = passkey_test_server();
    let mut a = new_test_authenticator();
    let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    register_test_passkey(&mut owner, &mut a);
    for (name, origin, rp_id, flags) in [
        ("wrong origin", "https://evil.example", "localhost", 0x05),
        ("wrong RP", TEST_PASSKEY_ORIGIN, "evil.example", 0x05),
        (
            "no user verification",
            TEST_PASSKEY_ORIGIN,
            "localhost",
            0x01,
        ),
        ("no user presence", TEST_PASSKEY_ORIGIN, "localhost", 0x04),
    ] {
        let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
        let options = passkey_result(&passkey_call(
            &mut c,
            "begin",
            "login",
            "begin",
            Object::new(),
        ));
        let proof = a.assertion(&options, origin, rp_id, flags);
        let finish = passkey_call(
            &mut c,
            "finish",
            "login",
            "finish",
            obj! {"credential" => proof.clone()},
        );
        assert_eq!(
            error_code(&finish),
            Some(Json::from(CODE_DENIED)),
            "{name}: {finish:?}"
        );
        let retry = passkey_call(
            &mut c,
            "retry",
            "login",
            "finish",
            obj! {"credential" => proof},
        );
        assert_eq!(
            error_code(&retry),
            Some(Json::from(CODE_DENIED)),
            "{name} retry: {retry:?}"
        );
    }
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let first = passkey_result(&passkey_call(
        &mut c,
        "first",
        "login",
        "begin",
        Object::new(),
    ));
    let second = passkey_result(&passkey_call(
        &mut c,
        "second",
        "login",
        "begin",
        Object::new(),
    ));
    let proof = a.assertion(&first, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    passkey_denied(&passkey_call(
        &mut c,
        "superseded",
        "login",
        "finish",
        obj! {"challenge_id" => first["challenge_id"].clone(), "credential" => proof.clone()},
    ));
    let current = a.assertion(&second, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    passkey_result(&passkey_call(
        &mut c,
        "current",
        "login",
        "finish",
        obj! {"challenge_id" => second["challenge_id"].clone(), "credential" => current},
    ));
    let (mut other, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    passkey_denied(&passkey_call(
        &mut other,
        "cross-connection",
        "login",
        "finish",
        obj! {"challenge_id" => first["challenge_id"].clone(), "credential" => proof},
    ));
    let options = passkey_result(&passkey_call(
        &mut c,
        "expire",
        "login",
        "begin",
        Object::new(),
    ));
    {
        let mut st = server.app.lock();
        for conn in st.clients.values_mut() {
            if let Some(ceremony) = conn.ceremony.as_mut() {
                ceremony.expires = time::now().add(-time::SECOND);
            }
        }
    }
    let credential = a.assertion(&options, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    passkey_denied(&passkey_call(
        &mut c,
        "expired",
        "login",
        "finish",
        obj! {"credential" => credential},
    ));
    passkey_denied(&passkey_call(
        &mut other,
        "unauth-register",
        "register",
        "begin",
        Object::new(),
    ));
    let (mut wrong_origin, _) = dial_origin(&server, "http://localhost:9999");
    passkey_denied(&passkey_call(
        &mut wrong_origin,
        "origin",
        "login",
        "begin",
        Object::new(),
    ));
}

#[test]
fn test_passkey_rejects_invalid_registration() {
    let server = passkey_test_server();
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    guest_auth(&mut c);
    let mut a = new_test_authenticator();
    let options = passkey_result(&passkey_call(
        &mut c,
        "begin",
        "register",
        "begin",
        Object::new(),
    ));
    let proof = a.registration(&options, "https://evil.example");
    passkey_denied(&passkey_call(
        &mut c,
        "bad-origin",
        "register",
        "finish",
        obj! {"credential" => proof},
    ));
    let proof = a.registration(&options, TEST_PASSKEY_ORIGIN);
    passkey_denied(&passkey_call(
        &mut c,
        "consumed",
        "register",
        "finish",
        obj! {"credential" => proof},
    ));
    for malformed in [
        Json::Null,
        Json::from("invalid"),
        Json::from(Vec::<Json>::new()),
        Json::from(Object::new()),
    ] {
        passkey_result(&passkey_call(
            &mut c,
            "begin",
            "register",
            "begin",
            Object::new(),
        ));
        let failure = passkey_call(
            &mut c,
            "malformed",
            "register",
            "finish",
            obj! {"credential" => malformed},
        );
        assert_eq!(
            error_code(&failure),
            Some(Json::from(CODE_INVALID_PARAMS)),
            "malformed credential: {failure:?}"
        );
    }
    let st = server.app.lock();
    let passkeys = st.users.values().filter(|u| u.passkey.is_some()).count();
    assert!(
        passkeys == 0 && st.credentials.is_empty() && st.sessions.is_empty(),
        "failed registration retained an account, credential, or session"
    );
}

/// A WebAuthn begin step authenticates nothing, so requests pipelined behind
/// it are denied (§3.2); a verified finish lets the ones behind it run.
#[test]
fn test_passkey_begin_is_no_barrier_pass() {
    let server = passkey_test_server();
    let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let mut a = new_test_authenticator();
    register_test_passkey(&mut owner, &mut a);

    let (c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    c.write(&obj! {"method" => "auth", "id" => "begin", "params" => obj! {"scheme" => "webauthn", "action" => "login", "step" => "begin"}});
    c.write(
        &obj! {"method" => "room_list", "id" => "list", "params" => obj! {"filter" => "joined"}},
    );
    let options = passkey_result(&c.read());
    let denied = c.read();
    assert!(
        denied.get("id").and_then(Json::as_str) == Some("list")
            && error_code(&denied) == Some(Json::from(CODE_DENIED)),
        "room_list behind begin: {denied:?}"
    );
    let credential = a.assertion(&options, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    c.write(
        &obj! {"method" => "auth", "id" => "finish", "params" => obj! {
            "scheme" => "webauthn", "action" => "login", "step" => "finish",
            "challenge_id" => options["challenge_id"].clone(), "credential" => credential,
        }},
    );
    c.write(
        &obj! {"method" => "room_list", "id" => "listed", "params" => obj! {"filter" => "joined"}},
    );
    passkey_result(&c.read());
    let listed = passkey_result(&c.read());
    assert_eq!(
        room_ids(listed.get("joined")),
        vec!["general".to_owned()],
        "room_list behind a verified finish: {listed:?}"
    );
}

#[test]
fn test_passkey_notifications_do_not_run_ceremonies() {
    let server = passkey_test_server();
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    guest_auth(&mut c);
    let mut a = new_test_authenticator();
    let options = passkey_result(&passkey_call(
        &mut c,
        "begin",
        "register",
        "begin",
        Object::new(),
    ));
    let proof = a.registration(&options, TEST_PASSKEY_ORIGIN);
    let challenge_id = str_of(&options, "challenge_id").to_owned();

    // This notification carries the current challenge and a malformed
    // proof. It must not consume the ceremony or produce a response.
    c.write(&obj! {"method" => "auth", "params" => obj! {
        "scheme" => "webauthn", "action" => "register", "step" => "finish",
        "challenge_id" => challenge_id, "credential" => Object::new(),
    }});
    let result = passkey_result(&passkey_call(
        &mut c,
        "finish",
        "register",
        "finish",
        obj! {"credential" => proof},
    ));
    assert!(
        you_of(&result)
            .get("user_id")
            .and_then(Json::as_str)
            .is_some_and(|id| !id.is_empty()),
        "registration result lost identity: {result:?}"
    );
}

#[test]
fn test_passkey_malformed_fields() {
    let server = passkey_test_server();
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    guest_auth(&mut c);

    // Actions require a valid step and reject unknown action names.
    for (id, params) in [
        (
            "unknown-action",
            obj! {"scheme" => "webauthn", "action" => "other", "step" => "begin"},
        ),
        (
            "no-step",
            obj! {"scheme" => "webauthn", "action" => "register"},
        ),
        (
            "bad-step",
            obj! {"scheme" => "webauthn", "action" => "register", "step" => "middle"},
        ),
    ] {
        c.write(&obj! {"method" => "auth", "id" => id, "params" => params});
        let frame = c.read();
        assert_eq!(
            error_code(&frame),
            Some(Json::from(CODE_INVALID_PARAMS)),
            "{id}: {frame:?}"
        );
    }

    let mut a = new_test_authenticator();
    let options = passkey_result(&passkey_call(
        &mut c,
        "begin",
        "register",
        "begin",
        Object::new(),
    ));
    let proof = a.registration(&options, TEST_PASSKEY_ORIGIN);
    // The opaque ID matches, but the action does not. The bound ceremony is
    // consumed before this policy failure and cannot be retried as
    // register.
    passkey_denied(&passkey_call(
        &mut c,
        "wrong-action",
        "login",
        "finish",
        obj! {"challenge_id" => options["challenge_id"].clone(), "credential" => proof.clone()},
    ));
    passkey_denied(&passkey_call(
        &mut c,
        "wrong-action-retry",
        "register",
        "finish",
        obj! {"credential" => proof},
    ));
    let options = passkey_result(&passkey_call(
        &mut c,
        "begin-again",
        "register",
        "begin",
        Object::new(),
    ));
    let proof = a.registration(&options, TEST_PASSKEY_ORIGIN);
    // Missing challenge_id is malformed and leaves the pending challenge in
    // place because no challenge can be matched.
    c.write(&obj! {"method" => "auth", "id" => "missing-challenge", "params" => obj! {
        "scheme" => "webauthn", "action" => "register", "step" => "finish", "credential" => proof.clone(),
    }});
    let missing = c.read();
    assert_eq!(
        error_code(&missing),
        Some(Json::from(CODE_INVALID_PARAMS)),
        "missing challenge_id: {missing:?}"
    );
    // A matching malformed credential is invalid_params and consumes the
    // challenge, so its later retry is a denied missing challenge.
    let failure = passkey_call(
        &mut c,
        "malformed",
        "register",
        "finish",
        obj! {"credential" => Object::new()},
    );
    assert_eq!(
        error_code(&failure),
        Some(Json::from(CODE_INVALID_PARAMS)),
        "malformed credential: {failure:?}"
    );
    passkey_denied(&passkey_call(
        &mut c,
        "retry",
        "register",
        "finish",
        obj! {"credential" => proof},
    ));
}

#[test]
fn test_sign_in_replaces_guest_and_deduplicates_per_user() {
    let server = passkey_test_server();
    let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut owner, &mut new_test_authenticator());
    owner.user_id = str_of(&you_of(&registered), "user_id").to_owned();
    let (mut observer, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    guest_auth(&mut observer);
    let (mut switcher, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let guest = you_of(&guest_auth(&mut switcher));
    let guest_id = str_of(&guest, "user_id").to_owned();
    // Each guest's join to general reaches general's members.
    expect_membership(&owner, "general", &observer.user_id, true);
    expect_membership(&owner, "general", &guest_id, true);
    expect_membership(&observer, "general", &guest_id, true);

    // Signing in to an existing account replaces the guest identity, which
    // is retired as when it disconnects: its leave is logged in general and
    // reaches general's members, the switching connection included, which
    // now acts as the passkey user, after its result: every notification a
    // sign-in causes on its connection follows the result (§3.2). It is a
    // departure, not a user_id change: no `user` with `old` follows (§3.3).
    let (before, result) = switcher.request(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => token_of(&registered)},
    );
    assert!(
        result.get("you") == registered.get("you") && before.is_empty(),
        "sign-in {result:?} after {before:?}"
    );
    let leave = membership_only(&switcher.read());
    check_membership(&leave, "general", &guest_id, false);
    for member in [&owner, &observer] {
        let observed = expect_membership(member, "general", &guest_id, false);
        assert_eq!(observed, leave, "member's copy differs");
    }
    observer.expect_quiet();
    owner.expect_quiet();
    switcher.expect_quiet();

    // Request IDs deduplicate per user, across that user's connections.
    let params = obj! {"room_id" => "general", "body" => obj! {"text" => "once"}};
    let (id, _) = save(&mut owner, "same", params.clone());
    switcher.notification("message");
    observer.notification("message");
    let again = switcher.result("message", "same", params);
    assert_eq!(
        again.get("message_id").and_then(Json::as_str),
        Some(id.as_str()),
        "duplicate result: {again:?}"
    );
    switcher.expect_error(
        "message",
        "same",
        obj! {"room_id" => "general", "body" => obj! {"text" => "different"}},
        CODE_INVALID_PARAMS,
    );
    observer.expect_quiet();
}
