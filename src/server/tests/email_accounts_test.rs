//! The email address tests of email_test.go about accounts. They cover
//! adding an address, persistence, normalization, and the admin user.

use std::collections::BTreeMap;
use std::sync::Arc;

use rust_stdlib::time::{self};

use super::email_test::{
    age_sends, approve, email_test_server, link_token, pending_code, propose, sign_in_by_email,
    test_mailbox,
};
use super::helpers::*;
use super::webauthn_test::{
    new_test_authenticator, passkey_call, passkey_result, register_test_passkey, test_web_authn,
    TEST_PASSKEY_ORIGIN,
};
use crate::obj;
use crate::server::email::*;
use crate::server::protocol::*;
use crate::store::{self, Store};

/// On a signed-in connection a proposal is to add the address to that
/// account, by a code only that connection can present, or a link only a
/// connection signed in to that account can present. A sign-in link
/// presented by someone signed in is denied, so an attacker's link cannot
/// join the attacker's address to their account, nor can an attacker's
/// addition link join a victim's address to the attacker's, and an address
/// is never taken from another account.
#[test]
fn test_email_additions() {
    let (server, mailbox) = email_test_server(|config| {
        config.web_authn = Some(test_web_authn());
        config.roles = BTreeMap::from([("admin".into(), vec!["victim@example.com".into()])]);
    });
    let app = &server.app;
    let (mut victim, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    guest_auth(&mut victim);
    victim.drain();
    let (diary, _) = save_room(
        &mut victim,
        "diary",
        obj! {"title" => "Diary", "parent_room_id" => "general"},
    );
    let (secret, _) = save(
        &mut victim,
        "secret",
        obj! {"room_id" => diary.as_str(), "body" => obj! {"text" => "my secret"}},
    );

    // The attacker's sign-in link, presented by the signed-in victim, is
    // denied and changes nothing; it still signs its own proposer in, to an
    // account of its own.
    let (mut attacker, _) = dial_raw(&server);
    propose(&mut attacker, "mallory@evil.example");
    let link = link_token(&mailbox.receive());
    victim.expect_error(
        "auth",
        "link",
        obj! {"scheme" => "email", "token" => link.as_str()},
        CODE_DENIED,
    );
    let (mut later, _) = dial_raw(&server);
    let (_, result) = sign_in_by_email(&mut later, &link, Object::new());
    assert_ne!(
        user_id_of(&result),
        victim.user_id,
        "the attacker became the victim: {result:?}"
    );
    expect_joined_default(&later, &user_id_of(&result));
    victim.drain();

    // Nor can an account take another account's address: nothing is sent,
    // and the pending code is denied.
    age_sends(app, "mallory@evil.example", time::HOUR);
    propose(&mut victim, "mallory@evil.example");
    let approve_owned = pending_code(app, &victim.user_id);
    victim.expect_error(
        "auth",
        "owned",
        obj! {"scheme" => "email", "token" => approve_owned.as_str()},
        CODE_DENIED,
    );

    // The victim proposes adding their own address.
    propose(&mut victim, "victim@example.com");
    let message = mailbox.receive();
    assert!(
        message.add
            && !message.link.is_empty()
            && message.text().contains("add this address")
            && message.text().contains(&message.link),
        "addition email: {message:?}"
    );
    // Someone else's proposal for the address does not touch it, the code
    // works on no other connection, and the link on no connection of another
    // account or none (§4.11.3), which leaves the proposal.
    age_sends(app, "victim@example.com", time::MINUTE);
    let (mut other, _) = dial_raw(&server);
    propose(&mut other, "victim@example.com");
    mailbox.receive();
    other.expect_error(
        "auth",
        "elsewhere",
        obj! {"scheme" => "email", "token" => message.code.as_str()},
        CODE_DENIED,
    );
    other.expect_error(
        "auth",
        "link-not-signed-in",
        obj! {"scheme" => "email", "token" => link_token(&message)},
        CODE_DENIED,
    );
    let mut stranger = dial_test_client(&server);
    stranger.expect_error(
        "auth",
        "link-other-account",
        obj! {"scheme" => "email", "token" => link_token(&message)},
        CODE_DENIED,
    );
    victim.drain();
    // Approving adds the address to the guest, which becomes an account
    // keeping its messages, with the roles its address was granted: {} and a
    // user notification with the new roles.
    let (before, result) = approve(&mut victim, &message.code, Object::new());
    assert!(
        result.is_empty() && before.len() == 1,
        "approving an addition: {result:?} after {before:?}"
    );
    let you = notification_params(&before[0], "user")["you"]
        .as_object()
        .cloned()
        .unwrap();
    assert_eq!(
        you.get("roles"),
        Some(&strings(&["admin"])),
        "profile after the addition: {you:?}"
    );
    save(
        &mut victim,
        "edit",
        obj! {"message_id" => secret.as_str(), "room_id" => diary.as_str(), "body" => obj! {"text" => "still mine"}},
    );
    // An account holds one address.
    propose(&mut victim, "second@example.com");
    let code = pending_code(app, &victim.user_id);
    victim.expect_error(
        "auth",
        "second",
        obj! {"scheme" => "email", "token" => code.as_str()},
        CODE_DENIED,
    );

    // A passkey registration on the signed-in account adds the passkey to
    // it (§4.10), and signs in to it later.
    let mut authenticator = new_test_authenticator();
    let options = passkey_result(&passkey_call(
        &mut victim,
        "register-begin",
        "register",
        "begin",
        Object::new(),
    ));
    let credential = authenticator.registration(&options, TEST_PASSKEY_ORIGIN);
    let registered = passkey_result(&passkey_call(
        &mut victim,
        "register-finish",
        "register",
        "finish",
        obj! {"credential" => credential},
    ));
    assert_eq!(
        user_id_of(&registered),
        victim.user_id,
        "passkey registration: {registered:?}"
    );
    let (mut login, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let begin = passkey_result(&passkey_call(
        &mut login,
        "login-begin",
        "login",
        "begin",
        Object::new(),
    ));
    let credential = authenticator.assertion(&begin, TEST_PASSKEY_ORIGIN, "localhost", 0x05);
    let logged_in = passkey_result(&passkey_call(
        &mut login,
        "login-finish",
        "login",
        "finish",
        obj! {"credential" => credential},
    ));
    assert_eq!(
        user_id_of(&logged_in),
        victim.user_id,
        "passkey login: {logged_in:?}"
    );
    // The address signs in on a connection not signed in.
    age_sends(app, "victim@example.com", time::HOUR);
    let (mut fresh, _) = dial_raw(&server);
    propose(&mut fresh, "victim@example.com");
    let code = mailbox.receive().code;
    let (_, again) = sign_in_by_email(&mut fresh, &code, Object::new());
    assert_eq!(
        user_id_of(&again),
        victim.user_id,
        "sign-in with the account's address: {again:?}"
    );
}

/// A passkey account has no address, so a proposal on it is an addition,
/// which another connection signed in to the account by its token approves
/// with the link (§4.11.3).
#[test]
fn test_email_adds_to_a_passkey_account() {
    let (server, mailbox) = email_test_server(|config| config.web_authn = Some(test_web_authn()));
    let (mut owner, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut owner, &mut new_test_authenticator());
    let owner_id = user_id_of(&registered);
    owner.drain();
    propose(&mut owner, "owner@example.com");
    let (mut tab, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    tab.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => registered["token"].clone()},
    );
    tab.drain();
    let (_, result) = approve(&mut tab, &link_token(&mailbox.receive()), Object::new());
    assert!(
        result.is_empty(),
        "adding an address to a passkey account: {result:?}"
    );
    let added = server.app.lock().emails.get("owner@example.com").cloned();
    assert_eq!(added, Some(owner_id), "the address was not added");
}

/// Email accounts, their addresses, their tokens, and the roles granted to
/// their addresses survive a restart; so does a guest that added an
/// address, which signs in with it afterwards.
#[test]
fn test_email_accounts_persist() {
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let (sender, mailbox) = test_mailbox(4);
    let start = || {
        let mut config = default_config();
        config.store = Some(kept.clone());
        config.email_sender = Some(sender.clone());
        config.roles = BTreeMap::from([("admin".into(), vec!["Ada@example.com".into()])]);
        new_test_server(config)
    };
    let mut server = start();
    let (mut c, _) = dial_raw(&server);
    propose(&mut c, "ada@example.com");
    let (_, result) = sign_in_by_email(&mut c, &mailbox.receive().code, Object::new());
    let you = you_of(&result);
    assert!(
        you["user_id"] == "user_1".into() && you.get("roles") == Some(&strings(&["admin"])),
        "sign-in: {result:?}"
    );
    let mut guest = dial_test_client(&server);
    let (id, _) = save(
        &mut guest,
        "hello",
        obj! {"body" => obj! {"text" => "hello"}},
    );
    propose(&mut guest, "bob@example.com");
    approve(&mut guest, &mailbox.receive().code, Object::new());
    server.stop();

    let server = start();
    let (mut c, _) = dial_raw(&server);
    let resumed = c.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => result["token"].clone()},
    );
    assert!(
        user_id_of(&resumed) == "user_1"
            && you_of(&resumed).get("roles") == Some(&strings(&["admin"])),
        "resumed after restart: {resumed:?}"
    );
    let (mut back, _) = dial_raw(&server);
    propose(&mut back, "bob@example.com");
    let (_, again) = sign_in_by_email(&mut back, &mailbox.receive().code, Object::new());
    assert_eq!(
        user_id_of(&again),
        guest.user_id,
        "the guest's address after restart: {again:?}"
    );
    back.drain();
    save(
        &mut back,
        "edit",
        obj! {"message_id" => id.as_str(), "body" => obj! {"text" => "edited"}},
    );
}

#[test]
fn test_normalize_email() {
    for (value, want) in [
        (" Ada@Example.COM ", "ada@example.com"),
        ("a.b+c@mail.example.org", "a.b+c@mail.example.org"),
        ("Ada <ada@example.com>", ""),
        ("ada@localhost", ""),
        ("ada@[10.0.0.5]", ""),
        ("ada@10.0.0.5", ""),
        ("ada@-bad.example", ""),
        ("ada@exa_mple.com", ""),
        ("ada", ""),
        ("", ""),
    ] {
        assert_eq!(normalize_email(value), want, "normalize_email({value:?})");
    }
}

/// The admin user signs in with the admin token only, so it can neither
/// propose an address nor approve the addition of one, which would let it
/// sign in by email.
#[test]
fn test_email_refused_to_the_admin_user() {
    let (server, mailbox) = email_test_server(|config| {
        config.admin_token = Some(rust_stdlib_crypto::sha256::sum256(
            super::helpers::ADMIN_TOKEN.as_bytes(),
        ));
    });
    let mut admin = super::helpers::admin(&server);
    let denied = Json::from(obj! {
        "code" => CODE_DENIED,
        "message" => crate::server::admin::ADMIN_SIGNS_IN_WITH_TOKEN,
    });
    let frame = admin.call(
        "auth",
        "propose",
        obj! {"scheme" => "email", "email" => "admin@example.com"},
    );
    assert_eq!(
        frame.get("error"),
        Some(&denied),
        "admin's proposal: {frame:?}"
    );
    assert!(
        server.app.lock().email.proposals.is_empty(),
        "the admin's proposal was kept"
    );

    // An addition proposed for the admin user, however it came to be, is
    // refused on approval.
    let mut guest = dial_test_client(&server);
    propose(&mut guest, "admin@example.com");
    let link = link_token(&mailbox.receive());
    for p in server.app.lock().email.proposals.values_mut() {
        p.account_id = "admin".into();
    }
    admin.drain();
    let frame = admin.call(
        "auth",
        "approve",
        obj! {"scheme" => "email", "token" => link.as_str()},
    );
    assert_eq!(
        frame.get("error"),
        Some(&denied),
        "admin's approval: {frame:?}"
    );
    let st = server.app.lock();
    assert!(
        st.emails.is_empty() && st.users["admin"].email.is_empty(),
        "the admin user got an address"
    );
}
