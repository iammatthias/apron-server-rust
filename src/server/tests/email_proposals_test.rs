//! The email proposal tests of email_test.go. They cover what a proposal
//! reveals, whom it names, and when it ends, expires, or outlives its
//! connection.

use std::sync::{Arc, Weak};

use rust_stdlib::time::{self};

use super::email_test::{age_sends, email_test_server, link_token, propose, sign_in_by_email};
use super::helpers::*;
use super::webauthn_test::{
    new_test_authenticator, register_test_passkey, test_web_authn, TEST_PASSKEY_ORIGIN,
};
use crate::obj;
use crate::server::email::*;
use crate::server::protocol::*;

/// A proposal is answered with the same {} and nothing else whether or not
/// the address has an account.
#[test]
fn test_email_proposals_do_not_reveal_accounts() {
    let (server, mailbox) = email_test_server(|_| {});
    let (mut c, _) = dial_raw(&server);
    propose(&mut c, "ada@example.com");
    sign_in_by_email(&mut c, &mailbox.receive().code, Object::new());
    age_sends(&server.app, "ada@example.com", time::MINUTE);
    let mut replies: Vec<Vec<Object>> = Vec::new();
    for email in ["ada@example.com", "nobody@example.com"] {
        let (mut asker, _) = dial_raw(&server);
        let (mut before, result) = asker.request(
            "auth",
            "propose",
            obj! {"scheme" => "email", "email" => email},
        );
        asker.expect_quiet();
        before.push(result);
        replies.push(before);
        mailbox.receive();
    }
    assert!(
        replies[0] == replies[1] && replies[0].len() == 1 && replies[0][0].is_empty(),
        "replies differ: {replies:?}"
    );
}

/// A proposal's name and user_id apply only when its own connection approves
/// it: a link opened on another connection is the address's owner reading
/// the email, whose new account the proposer must not name.
#[test]
fn test_email_proposals_name_only_their_own_approvals() {
    let (server, mailbox) = email_test_server(|_| {});
    let (mut squatter, _) = dial_raw(&server);
    let result = squatter.result(
        "auth",
        "propose",
        obj! {"scheme" => "email", "email" => "victim@example.com", "user_id" => "squatted", "name" => "Squatter"},
    );
    assert!(result.is_empty(), "proposal result: {result:?}");
    let (mut victim, _) = dial_raw(&server);
    let (_, result) = sign_in_by_email(&mut victim, &link_token(&mailbox.receive()), Object::new());
    let you = you_of(&result);
    assert!(
        you["user_id"] != "squatted".into()
            && you.get("name") != Some(&"Squatter".into())
            && user_id_of(&result).starts_with(ACCOUNT_ID_PREFIX),
        "the proposer named the victim's account: {you:?}"
    );

    // On the proposing connection, the proposal's own values apply.
    let (mut proposer, _) = dial_raw(&server);
    let result = proposer.result(
        "auth",
        "propose",
        obj! {"scheme" => "email", "email" => "carol@example.com", "user_id" => "carol", "name" => "Carol"},
    );
    assert!(result.is_empty(), "proposal result: {result:?}");
    let (_, result) = sign_in_by_email(&mut proposer, &mailbox.receive().code, Object::new());
    let you = you_of(&result);
    assert!(
        you["user_id"] == "carol".into() && you["name"] == "Carol".into(),
        "the proposal's own values: {you:?}"
    );
}

/// A connection's pending proposal is dropped when its identity changes, so
/// an addition proposed by one account cannot be approved by another, nor a
/// sign-in link used once its connection signed in some other way.
#[test]
fn test_email_proposals_end_with_their_identity() {
    let (server, mailbox) = email_test_server(|config| config.web_authn = Some(test_web_authn()));
    let app = &server.app;
    let (mut other, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    let registered = register_test_passkey(&mut other, &mut new_test_authenticator());
    let token = registered
        .get("token")
        .and_then(Json::as_str)
        .filter(|token| !token.is_empty())
        .expect("no token for the second account")
        .to_owned();
    let (mut c, _) = dial_origin(&server, TEST_PASSKEY_ORIGIN);
    register_test_passkey(&mut c, &mut new_test_authenticator());
    c.drain();
    propose(&mut c, "first@example.com");
    let code = mailbox.receive().code;
    let resumed = c.result(
        "auth",
        "switch",
        obj! {"scheme" => "token", "token" => token.as_str()},
    );
    assert_eq!(
        user_id_of(&resumed),
        other.user_id,
        "switching accounts: {resumed:?}"
    );
    c.expect_error(
        "auth",
        "after-switch",
        obj! {"scheme" => "email", "token" => code.as_str()},
        CODE_DENIED,
    );
    let added = app.lock().emails.get("first@example.com").cloned();
    assert!(added.is_none(), "the address was added to {added:?}");

    // A sign-in proposal ends when its connection signs in as a guest.
    let (mut fresh, _) = dial_raw(&server);
    propose(&mut fresh, "fresh@example.com");
    let link = link_token(&mailbox.receive());
    guest_auth(&mut fresh);
    let (mut reader, _) = dial_raw(&server);
    reader.expect_error(
        "auth",
        "stale-link",
        obj! {"scheme" => "email", "token" => link.as_str()},
        CODE_DENIED,
    );
}

#[test]
fn test_email_proposals_expire_and_are_invalidated() {
    let (server, mailbox) = email_test_server(|_| {});
    let app = &server.app;
    let (mut c, _) = dial_raw(&server);
    propose(&mut c, "ada@example.com");
    let first = mailbox.receive();
    // A newer proposal replaces the older one, its link included.
    propose(&mut c, "bob@example.com");
    let second = mailbox.receive();
    if first.code != second.code {
        c.expect_error(
            "auth",
            "old",
            obj! {"scheme" => "email", "token" => first.code.as_str()},
            CODE_DENIED,
        );
    }
    c.expect_error(
        "auth",
        "old-link",
        obj! {"scheme" => "email", "token" => link_token(&first)},
        CODE_DENIED,
    );
    // A few wrong tokens invalidate it.
    for _ in 0..MAX_EMAIL_ATTEMPTS - 2 {
        let id = c.next_id("wrong");
        c.expect_error(
            "auth",
            &id,
            obj! {"scheme" => "email", "token" => "wrong"},
            CODE_DENIED,
        );
    }
    c.expect_error(
        "auth",
        "last-wrong",
        obj! {"scheme" => "email", "token" => "nope"},
        CODE_DENIED,
    );
    c.expect_error(
        "auth",
        "invalidated",
        obj! {"scheme" => "email", "token" => second.code.as_str()},
        CODE_DENIED,
    );
    // An expired proposal is denied.
    propose(&mut c, "carol@example.com");
    let expired = mailbox.receive();
    {
        let mut st = app.lock();
        let ids: Vec<ProposalId> = st.clients.values().filter_map(|c| c.proposal).collect();
        for id in ids {
            if let Some(p) = st.email.proposals.get_mut(&id) {
                p.expires = time::now().add(-time::SECOND);
            }
        }
    }
    c.expect_error(
        "auth",
        "expired",
        obj! {"scheme" => "email", "token" => expired.code.as_str()},
        CODE_DENIED,
    );
    // A connection may propose only a few times.
    for i in 0..EMAIL_SENDS_PER_CONNECTION - 3 {
        propose(&mut c, &format!("user{i}@example.com"));
        mailbox.receive();
    }
    c.expect_error(
        "auth",
        "flood",
        obj! {"scheme" => "email", "email" => "flood@example.com"},
        CODE_RETRY_AFTER,
    );
    // A valid token is kept when the rest of the request is invalid.
    let (mut other, _) = dial_raw(&server);
    propose(&mut other, "dave@example.com");
    let code = mailbox.receive().code;
    other.expect_error(
        "auth",
        "bad-name",
        obj! {"scheme" => "email", "token" => code.as_str(), "name" => 7i64},
        CODE_INVALID_PARAMS,
    );
    sign_in_by_email(&mut other, &code, Object::new());
    // A sign-in code on a connection signed in is denied.
    let mut signed_in = dial_test_client(&server);
    let (mut fresh, _) = dial_raw(&server);
    propose(&mut fresh, "erin@example.com");
    signed_in.expect_error(
        "auth",
        "signed-in",
        obj! {"scheme" => "email", "token" => link_token(&mailbox.receive())},
        CODE_DENIED,
    );
    // Email sign-in is not offered without a sender, and external sign-in
    // not at all, neither to propose nor to approve.
    fresh.expect_error(
        "auth",
        "external",
        obj! {"scheme" => "external", "token" => link_token(&second)},
        CODE_UNSUPPORTED,
    );
    let plain = new_test_server(default_config());
    let (mut guest, _) = dial_raw(&plain);
    guest.expect_error(
        "auth",
        "email",
        obj! {"scheme" => "email", "email" => "ada@example.com"},
        CODE_UNSUPPORTED,
    );
    // Token is offered everywhere, for bots and devices.
    guest.expect_error(
        "auth",
        "token",
        obj! {"scheme" => "token", "token" => "x"},
        CODE_DENIED,
    );
    guest.expect_error(
        "auth",
        "external",
        obj! {"scheme" => "external", "return_url" => "https://web.apron.chat/"},
        CODE_UNSUPPORTED,
    );
    // A scheme not offered is unsupported before its user_id is read.
    for scheme in ["email", "webauthn", "external"] {
        guest.expect_error(
            "auth",
            &format!("bad-id-{scheme}"),
            obj! {"scheme" => scheme, "user_id" => ""},
            CODE_UNSUPPORTED,
        );
    }
    fresh.expect_error(
        "auth",
        "bad-id-offered",
        obj! {"scheme" => "email", "email" => "frank@example.com", "user_id" => ""},
        CODE_INVALID_PARAMS,
    );
    fresh.expect_error(
        "auth",
        "bad-id-token",
        obj! {"scheme" => "token", "token" => "x", "user_id" => ""},
        CODE_INVALID_PARAMS,
    );
}

/// Waits up to `limit` for `done`, checking every few milliseconds.
fn eventually(limit: std::time::Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if done() {
            return true;
        }
        if std::time::Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// A disconnect does not cancel a proposal: its link still signs in
/// elsewhere, until the proposal expires (§4.11.1).
#[test]
fn test_email_proposals_outlive_their_connection() {
    let (server, mailbox) = email_test_server(|_| {});
    let app = &server.app;
    let (mut c, _) = dial_raw(&server);
    propose(&mut c, "ada@example.com");
    let ada = mailbox.receive();
    let mut bob_client = dial_test_client(&server);
    propose(&mut bob_client, "bob@example.com");
    let bob = mailbox.receive();
    drop(c);
    let closed = eventually(std::time::Duration::from_secs(1), || {
        app.lock().clients.len() == 1
    });
    assert!(
        closed,
        "{} connections still open",
        app.lock().clients.len()
    );
    let (mut reader, _) = dial_raw(&server);
    let (_, result) = sign_in_by_email(&mut reader, &link_token(&ada), Object::new());
    assert!(
        result.contains_key("you"),
        "sign-in after the proposer left: {result:?}"
    );
    // An expired link is denied.
    {
        let mut st = app.lock();
        let ids: Vec<ProposalId> = st.email.links.values().copied().collect();
        for id in ids {
            if let Some(p) = st.email.proposals.get_mut(&id) {
                p.expires = time::now().add(-time::SECOND);
            }
        }
    }
    let mut late = dial_test_client(&server);
    late.expect_error(
        "auth",
        "expired-link",
        obj! {"scheme" => "email", "token" => link_token(&bob)},
        CODE_DENIED,
    );
}

/// A proposal kept after its connection closes keeps neither the closed
/// connection nor, for an addition, the retired guest that proposed it.
#[test]
fn test_email_proposals_keep_no_closed_connection() {
    let (server, mailbox) = email_test_server(|_| {});
    let app = &server.app;
    let (mut sign_in, _) = dial_raw(&server);
    propose(&mut sign_in, "ada@example.com");
    mailbox.receive();
    let mut guest = dial_test_client(&server);
    propose(&mut guest, "bob@example.com");
    mailbox.receive();
    let guest_id = guest.user_id.clone();
    let clients: Vec<Weak<crate::server::client::Client>> = app
        .lock()
        .clients
        .values()
        .map(|conn| Arc::downgrade(&conn.client))
        .collect();
    drop(sign_in);
    drop(guest);
    let released = eventually(std::time::Duration::from_secs(5), || {
        !app.lock().users.contains_key(&guest_id) && clients.iter().all(|c| c.upgrade().is_none())
    });
    assert!(
        released,
        "a closed connection or its retired guest is still kept"
    );
    let links = app.lock().email.links.len();
    assert_eq!(links, 2, "{links} proposals kept, want 2");
}
