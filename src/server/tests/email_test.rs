//! email_test.go.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Weak};

use rust_stdlib::context::Context;
use rust_stdlib::net::http::Request as HttpRequest;
use rust_stdlib::net::url;
use rust_stdlib::time::{self, Duration};

use super::helpers::*;
use super::webauthn_test::{
    new_test_authenticator, passkey_call, passkey_result, register_test_passkey, test_web_authn,
    TEST_PASSKEY_ORIGIN,
};
use crate::obj;
use crate::server::email::*;
use crate::server::limits::IpKey;
use crate::server::protocol::*;
use crate::server::{Config, Server};
use crate::store::{self, Store};

/// An EmailSender that keeps what it is asked to send.
pub(super) struct TestMailbox(SyncSender<SignInEmail>);

impl EmailSender for TestMailbox {
    fn send_sign_in_code(&self, _ctx: &Context, message: &SignInEmail) -> Result<(), SendError> {
        // A test that does not read its mail drops it.
        let _ = self.0.try_send(message.clone());
        Ok(())
    }
}

pub(super) struct Mailbox(Receiver<SignInEmail>);

impl Mailbox {
    /// The next message sent to the mailbox.
    pub(super) fn receive(&self) -> SignInEmail {
        self.0
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("no email was sent")
    }
}

pub(super) fn test_mailbox(capacity: usize) -> (Arc<TestMailbox>, Mailbox) {
    let (tx, rx) = sync_channel(capacity);
    (Arc::new(TestMailbox(tx)), Mailbox(rx))
}

pub(super) fn email_test_server(configure: impl FnOnce(&mut Config)) -> (TestServer, Mailbox) {
    let (sender, mailbox) = test_mailbox(16);
    let mut config = default_config();
    config.email_sender = Some(sender);
    config.email_link_url = "https://chat.example/login#ignored".into();
    configure(&mut config);
    (new_test_server(config), mailbox)
}

/// Proposes an email sign-in or addition on c, which must be answered with
/// {} (§4.11).
pub(super) fn propose(c: &mut TestClient, email: &str) {
    let id = c.next_id("propose");
    let result = c.result("auth", &id, obj! {"scheme" => "email", "email" => email});
    assert!(result.is_empty(), "proposal result: {result:?}");
}

/// Approves a proposal on c with token and returns the notifications before
/// the result, then the result.
pub(super) fn approve(c: &mut TestClient, token: &str, extra: Object) -> (Vec<Object>, Object) {
    let mut params = obj! {"scheme" => "email", "token" => token};
    params.extend(extra);
    let id = c.next_id("approve");
    c.request("auth", &id, params)
}

/// Approves a sign-in and returns the notifications before the result, then
/// the result, which must carry you and a token.
fn sign_in_by_email(c: &mut TestClient, token: &str, extra: Object) -> (Vec<Object>, Object) {
    let (before, result) = approve(c, token, extra);
    assert!(
        result.get("token").and_then(Json::as_str).is_some(),
        "sign-in result without a token: {result:?}"
    );
    c.user_id = user_id_of(&result);
    (before, result)
}

fn user_id_of(result: &Object) -> String {
    you_of(result)["user_id"].as_str().unwrap().to_owned()
}

/// The form-encoded fragment of an email's link.
fn link_fragment(message: &SignInEmail) -> BTreeMap<String, Vec<String>> {
    let fragment = message.link.split_once('#').map_or("", |(_, f)| f);
    let (values, err) = url::parse_query(fragment);
    assert!(err.is_none(), "link fragment {:?}: {err:?}", message.link);
    values.0
}

fn fragment_value(message: &SignInEmail, key: &str) -> String {
    link_fragment(message)
        .get(key)
        .and_then(|values| values.first())
        .cloned()
        .unwrap_or_default()
}

/// The token in an email's link.
fn link_token(message: &SignInEmail) -> String {
    let token = fragment_value(message, "token");
    assert!(!token.is_empty(), "no link token in {:?}", message.link);
    token
}

/// The code of the proposal pending on a connection of user_id, which may
/// not have been sent.
fn pending_code(app: &Server, user_id: &str) -> String {
    let st = app.lock();
    for conn in st.clients.values() {
        if conn.user.as_deref() == Some(user_id) {
            if let Some(p) = conn.proposal.and_then(|id| st.email.proposals.get(&id)) {
                return p.code.clone();
            }
        }
    }
    panic!("no proposal pending for {user_id}");
}

/// Moves an address's sends back by d, as if time had passed.
fn age_sends(app: &Server, email: &str, d: Duration) {
    let mut st = app.lock();
    if let Some(state) = st.email.addresses.get_mut(email) {
        for sent in &mut state.sends {
            *sent = sent.add(-d);
        }
    }
}

/// Connects as a client at ip, for a server that reads X-Forwarded-For.
fn dial_from(server: &TestServer, ip: &str) -> TestClient {
    let forwarded = format!("203.0.113.9, {ip}");
    dial_headers(server, &[("X-Forwarded-For", &forwarded)]).0
}

fn code_of(frame: &Object) -> Option<Json> {
    frame
        .get("error")
        .and_then(Json::as_object)
        .and_then(|e| e.get("code"))
        .cloned()
}

#[test]
fn test_email_sign_in() {
    let (server, mailbox) =
        email_test_server(|config| config.public_url = "https://chat.example/app/".into());
    let app = &server.app;
    let (mut proposer, frame) = dial_raw(&server);
    let params = frame["params"].as_object().unwrap();
    assert!(
        params.get("auth") == Some(&strings(&["email", "token", "guest"]))
            && params.get("signup") == Some(&strings(&["email", "token"])),
        "auth schemes: {:?}, signup {:?}",
        params.get("auth"),
        params.get("signup")
    );

    // A proposal authenticates nothing, so on a connection not signed in the
    // requests behind it are still denied; the address is normalized.
    let state = "q8Rz/+&=é";
    proposer.write(&obj! {"method" => "auth", "id" => "propose", "params" => obj! {"scheme" => "email", "email" => " Ada@Example.com ", "state" => state}});
    proposer.write(&obj! {"method" => "room_list", "id" => "list", "params" => Object::new()});
    let reply = proposer.read();
    assert!(
        reply.get("id") == Some(&"propose".into())
            && reply
                .get("result")
                .and_then(Json::as_object)
                .is_some_and(|r| r.is_empty()),
        "proposal reply: {reply:?}"
    );
    let reply = proposer.read();
    assert!(
        reply.get("id") == Some(&"list".into()) && code_of(&reply) == Some(CODE_DENIED.into()),
        "request behind a proposal: {reply:?}"
    );
    let message = mailbox.receive();
    assert!(
        message.to == "ada@example.com"
            && !message.add
            && message.code.len() == 6
            && message.code.bytes().all(|b| b.is_ascii_digit()),
        "sent: {message:?}"
    );
    // The link is built from the configured page, with an unguessable token,
    // the proposal's state unchanged, and this server's WebSocket URL in its
    // fragment, and no address (§4.11.2).
    let link = link_token(&message);
    let want = format!(
        "https://chat.example/login#token={link}&state={}&server=wss%3A%2F%2Fchat.example%2Fapp%2Fws",
        url::query_escape(state)
    );
    assert!(
        message.link == want
            && link.len() >= 26
            && !message.link.contains("ada")
            && fragment_value(&message, "state") == state,
        "link {:?}, want {want:?}",
        message.link
    );
    let text = message.text();
    assert!(
        text.contains(&message.code) && text.contains(&message.link),
        "text: {text:?}"
    );
    // Another proposal for the address so soon is retry_after.
    proposer.expect_error(
        "auth",
        "again",
        obj! {"scheme" => "email", "email" => "ada@example.com"},
        CODE_RETRY_AFTER,
    );
    proposer.expect_error(
        "auth",
        "invalid",
        obj! {"scheme" => "email", "email" => "Ada <ada@example.com>"},
        CODE_INVALID_PARAMS,
    );
    proposer.expect_error(
        "auth",
        "missing",
        obj! {"scheme" => "email"},
        CODE_INVALID_PARAMS,
    );
    // state is a string of at most 256 bytes.
    proposer.expect_error(
        "auth",
        "long-state",
        obj! {"scheme" => "email", "email" => "bob@example.com", "state" => "s".repeat(MAX_STATE_BYTES + 1)},
        CODE_TOO_LARGE,
    );
    proposer.expect_error(
        "auth",
        "state-type",
        obj! {"scheme" => "email", "email" => "bob@example.com", "state" => 7i64},
        CODE_INVALID_PARAMS,
    );

    // The code works only on the proposing connection; the link token on any
    // connection not signed in, which it signs in: a new account, which joins
    // general, after the result (§3.2).
    let (mut reader, _) = dial_raw(&server);
    reader.expect_error(
        "auth",
        "code-elsewhere",
        obj! {"scheme" => "email", "token" => message.code.as_str()},
        CODE_DENIED,
    );
    reader.expect_error(
        "auth",
        "wrong",
        obj! {"scheme" => "email", "token" => "wrong"},
        CODE_DENIED,
    );
    let (before, result) = sign_in_by_email(
        &mut reader,
        &link,
        obj! {"name" => "Ada", "user_id" => "ada"},
    );
    let you = you_of(&result);
    assert!(
        you["user_id"] == "ada".into() && you["name"] == "Ada".into(),
        "new account: {result:?}"
    );
    assert!(
        before.is_empty(),
        "frames before the sign-in result: {before:?}"
    );
    expect_joined_default(&reader, "ada");
    // The proposal is consumed: neither token works again.
    let (mut third, _) = dial_raw(&server);
    third.expect_error(
        "auth",
        "reuse",
        obj! {"scheme" => "email", "token" => link.as_str()},
        CODE_DENIED,
    );
    proposer.expect_error(
        "auth",
        "code-after",
        obj! {"scheme" => "email", "token" => message.code.as_str()},
        CODE_DENIED,
    );
    // The bearer token resumes the account on later connections.
    let resumed = third.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => result["token"].clone()},
    );
    assert!(
        user_id_of(&resumed) == "ada" && resumed.get("token") == result.get("token"),
        "token resume: {resumed:?}"
    );
    // Signing in again with the code, on the proposing connection, finds the
    // same account.
    age_sends(app, "ada@example.com", time::MINUTE);
    let (mut fourth, _) = dial_raw(&server);
    propose(&mut fourth, "ada@example.com");
    let code = mailbox.receive().code;
    let (_, again) = sign_in_by_email(&mut fourth, &code, obj! {"user_id" => "other"});
    assert_eq!(user_id_of(&again), "ada", "second sign-in: {again:?}");
}

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

/// A proposal, or a denied approval, changes no authentication, so on a
/// connection signed in the requests behind it run as before (§3.2).
#[test]
fn test_email_requests_leave_authentication_alone() {
    let (server, mailbox) = email_test_server(|_| {});
    let mut c = dial_test_client(&server);
    for params in [
        obj! {"scheme" => "email", "email" => "ada@example.com"},
        obj! {"scheme" => "email", "token" => "000000"},
    ] {
        let (auth, list) = (c.next_id("auth"), c.next_id("list"));
        c.write(&obj! {"method" => "auth", "id" => auth.as_str(), "params" => params.clone()});
        c.write(&obj! {"method" => "room_list", "id" => list.as_str(), "params" => obj! {"filter" => "joined"}});
        c.read(); // the auth reply
        let reply = c.read();
        assert!(
            reply.get("id") == Some(&list.as_str().into()) && reply.contains_key("result"),
            "request behind {params:?}: {reply:?}"
        );
    }
    mailbox.receive();
    let you = you_of(&c.result("me", "me", Object::new()));
    assert_eq!(
        you["user_id"],
        c.user_id.as_str().into(),
        "identity changed: {you:?}"
    );
}

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
    let clients: Vec<Weak<crate::server::server::Client>> = app
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

/// Failed attempts count against the proposal a link token names, whichever
/// connection makes them, and a few cancel it (§4.11.1).
#[test]
fn test_email_failed_attempts_count_from_any_connection() {
    let (server, mailbox) = email_test_server(|_| {});
    let (mut c, _) = dial_raw(&server);
    propose(&mut c, "ada@example.com");
    let message = mailbox.receive();
    let link = link_token(&message);
    let wrong = format!(
        "{}{}",
        &link[..LINK_HANDLE_BYTES],
        "A".repeat(link.len() - LINK_HANDLE_BYTES)
    );
    for i in 0..MAX_EMAIL_ATTEMPTS - 1 {
        let (mut guesser, _) = dial_raw(&server);
        guesser.expect_error(
            "auth",
            &format!("guess-{i}"),
            obj! {"scheme" => "email", "token" => wrong.as_str()},
            CODE_DENIED,
        );
    }
    // One more attempt, a wrong code on its own connection, cancels it.
    c.expect_error(
        "auth",
        "last",
        obj! {"scheme" => "email", "token" => "wrong"},
        CODE_DENIED,
    );
    let (mut reader, _) = dial_raw(&server);
    reader.expect_error(
        "auth",
        "cancelled",
        obj! {"scheme" => "email", "token" => link.as_str()},
        CODE_DENIED,
    );
    c.expect_error(
        "auth",
        "cancelled-code",
        obj! {"scheme" => "email", "token" => message.code.as_str()},
        CODE_DENIED,
    );
}

/// Without a public URL, a link carries the WebSocket URL its proposal's
/// connection reached, so a page such as link.apron.chat knows where to sign
/// in.
#[test]
fn test_email_links_name_the_server_without_a_public_url() {
    let (server, mailbox) =
        email_test_server(|config| config.email_link_url = "https://link.apron.chat/".into());
    let (mut c, _) = dial_raw(&server);
    propose(&mut c, "ada@example.com");
    let message = mailbox.receive();
    assert!(
        fragment_value(&message, "server") == ws_url(&server)
            && message.link.starts_with("https://link.apron.chat/#token="),
        "link {:?}, want server {:?}",
        message.link,
        ws_url(&server)
    );
}

/// A link's token approves with scheme token too, as a client presents a
/// link that isn't its own (§4.11.2); wrong tokens still count against the
/// proposal, and a bearer token for no session is still an expired session.
#[test]
fn test_email_approves_with_the_token_scheme() {
    let (server, mailbox) = email_test_server(|_| {});
    let (mut proposer, _) = dial_raw(&server);
    propose(&mut proposer, "ada@example.com");
    let message = mailbox.receive();
    let link = link_token(&message);
    let (mut reader, _) = dial_raw(&server);
    let result = reader.result(
        "auth",
        "link",
        obj! {"scheme" => "token", "token" => link.as_str()},
    );
    assert!(
        you_of(&result).contains_key("user_id") && result.contains_key("token"),
        "sign-in by link with scheme token: {result:?}"
    );
    // Used up, under either scheme.
    let (mut again, _) = dial_raw(&server);
    again.expect_error(
        "auth",
        "reuse",
        obj! {"scheme" => "email", "token" => link.as_str()},
        CODE_DENIED,
    );

    // A code on the proposing connection approves with scheme token as well.
    let (mut second, _) = dial_raw(&server);
    propose(&mut second, "bob@example.com");
    let code = mailbox.receive().code;
    let result = second.result(
        "auth",
        "code",
        obj! {"scheme" => "token", "token" => code.as_str()},
    );
    assert!(
        result.contains_key("you"),
        "sign-in by code with scheme token: {result:?}"
    );

    // Wrong tokens behind a link's handle count against its proposal under
    // scheme token too.
    let (mut third, _) = dial_raw(&server);
    propose(&mut third, "carol@example.com");
    let link = link_token(&mailbox.receive());
    let wrong = format!(
        "{}{}",
        &link[..LINK_HANDLE_BYTES],
        "A".repeat(link.len() - LINK_HANDLE_BYTES)
    );
    for i in 0..MAX_EMAIL_ATTEMPTS {
        let (mut guesser, _) = dial_raw(&server);
        guesser.expect_error(
            "auth",
            &format!("guess-{i}"),
            obj! {"scheme" => "token", "token" => wrong.as_str()},
            CODE_DENIED,
        );
    }
    let (mut late, _) = dial_raw(&server);
    late.expect_error(
        "auth",
        "cancelled",
        obj! {"scheme" => "token", "token" => link.as_str()},
        CODE_DENIED,
    );

    // Any other token is no temporary token: its resume fails as before.
    let (mut stranger, _) = dial_raw(&server);
    let frame = stranger.call(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => "st_unknown"},
    );
    let failure = frame["error"].as_object().unwrap();
    assert_eq!(
        failure["message"],
        "Session expired; sign in again".into(),
        "unknown bearer token: {frame:?}"
    );
}

/// Emails are limited per address and per client, deliveries in progress
/// are bounded, refused proposals leave nothing behind, and a full table
/// forgets only entries whose limits have lapsed.
#[test]
fn test_email_send_limits() {
    let (server, _mailbox) =
        email_test_server(|config| config.client_ip_header = "X-Forwarded-For".into());
    let app = &server.app;
    // At most MAX_EMAIL_SENDS_PER_WINDOW emails an hour to one address.
    for i in 0..MAX_EMAIL_SENDS_PER_WINDOW {
        propose(
            &mut dial_from(&server, &format!("203.0.113.{i}")),
            "carol@example.com",
        );
        age_sends(app, "carol@example.com", EMAIL_RESEND_INTERVAL);
    }
    dial_from(&server, "203.0.113.100").expect_error(
        "auth",
        "capped",
        obj! {"scheme" => "email", "email" => "carol@example.com"},
        CODE_RETRY_AFTER,
    );
    // One client proposes at most CLIENT_SEND_BURST times, across
    // connections.
    for i in 0..CLIENT_SEND_BURST {
        propose(
            &mut dial_from(&server, "198.51.100.200"),
            &format!("c{i}@example.com"),
        );
    }
    let mut flooder = dial_from(&server, "198.51.100.200");
    flooder.expect_error(
        "auth",
        "client-sends",
        obj! {"scheme" => "email", "email" => "d@example.com"},
        CODE_RETRY_AFTER,
    );
    // Refused proposals are not tracked.
    let before = app.lock().email.addresses.len();
    for i in 0..100 {
        flooder.call(
            "auth",
            &format!("refused-{i}"),
            obj! {"scheme" => "email", "email" => format!("junk{i}@example.com")},
        );
    }
    let after = app.lock().email.addresses.len();
    assert_eq!(
        after,
        before,
        "refused proposals made {} entries",
        after - before
    );

    // A full table forgets an address whose emails are older than the
    // window, and refuses when every entry is within it.
    {
        let mut st = app.lock();
        let mut i = 0;
        while st.email.addresses.len() < MAX_TRACKED_EMAIL_STATE {
            let now = time::now();
            st.email
                .create_address(&format!("filler{i}@example.com"), &now)
                .unwrap()
                .sends = vec![now.clone()];
            i += 1;
        }
    }
    dial_from(&server, "192.0.2.50").expect_error(
        "auth",
        "full",
        obj! {"scheme" => "email", "email" => "late@example.com"},
        CODE_RETRY_AFTER,
    );
    age_sends(app, "filler0@example.com", time::HOUR);
    propose(&mut dial_from(&server, "192.0.2.51"), "late@example.com");
    let st = app.lock();
    let kept = st.email.addresses.contains_key("filler0@example.com");
    let kept_live = st.email.addresses.contains_key("filler1@example.com");
    assert!(
        !kept && kept_live,
        "eviction: lapsed kept {kept}, live kept {kept_live}"
    );
}

/// Holds each delivery until released.
struct BlockingMailbox {
    release: Arc<AtomicBool>,
}

impl EmailSender for BlockingMailbox {
    fn send_sign_in_code(&self, ctx: &Context, _message: &SignInEmail) -> Result<(), SendError> {
        while !self.release.load(Ordering::SeqCst) && ctx.err().is_none() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok(())
    }
}

/// Releases the blocking mailbox when dropped, before the server it is
/// declared after shuts down and waits for its deliveries.
struct Release(Arc<AtomicBool>);

impl Drop for Release {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Deliveries in progress are bounded; past the bound a proposal waits.
#[test]
fn test_email_deliveries_are_bounded() {
    let release = Arc::new(AtomicBool::new(false));
    let mailbox = Arc::new(BlockingMailbox {
        release: release.clone(),
    });
    let (server, _) = email_test_server(|config| {
        config.email_sender = Some(mailbox);
        config.client_ip_header = "X-Forwarded-For".into();
    });
    let _release = Release(release);
    for i in 0..MAX_CONCURRENT_EMAIL_SENDS {
        propose(
            &mut dial_from(&server, &format!("198.51.100.{i}")),
            &format!("q{i}@example.com"),
        );
    }
    dial_from(&server, "192.0.2.1").expect_error(
        "auth",
        "busy",
        obj! {"scheme" => "email", "email" => "busy@example.com"},
        CODE_RETRY_AFTER,
    );
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

/// The client key comes from the last entry across every line of the
/// configured header, without a port, else from the connection; a header
/// that names no address gives none, which refuses the connection.
#[test]
fn test_client_ip_from_a_proxy_header() {
    let mut config = default_config();
    config.client_ip_header = "X-Forwarded-For".into();
    let s = new_test_server(config);
    let request = |lines: &[&str]| {
        let mut r = HttpRequest::new("GET", "http://example.com/ws").unwrap();
        r.remote_addr = "10.0.0.1:5555".into();
        for line in lines {
            r.header.add("X-Forwarded-For", line);
        }
        r
    };
    let tests: [(&[&str], Option<&str>); 10] = [
        (&[], None),
        (&["203.0.113.7"], Some("v4:203.0.113.7")),
        (&["6.6.6.6, 203.0.113.7"], Some("v4:203.0.113.7")),
        (&["6.6.6.6", "203.0.113.7"], Some("v4:203.0.113.7")),
        (
            &["6.6.6.6", "198.51.100.1, 203.0.113.7:4711"],
            Some("v4:203.0.113.7"),
        ),
        (&["[2001:db8::1]:4711"], Some("v6:2001:db8::/56")),
        (&["2001:db8:0:ff::2"], Some("v6:2001:db8::/56")),
        (&["::ffff:203.0.113.7"], Some("v4:203.0.113.7")),
        (&["garbage-x"], None),
        (&["203.0.113.7, "], None),
    ];
    for (lines, want) in tests {
        assert_eq!(
            s.app.client_ip(&request(lines)).as_ref().map(IpKey::as_str),
            want,
            "client_ip({lines:?})"
        );
    }
    let plain = new_test_server(default_config());
    let mut r = request(&[]);
    r.header.set("X-Forwarded-For", "203.0.113.7");
    assert_eq!(
        plain.app.client_ip(&r).as_ref().map(IpKey::as_str),
        Some("v4:10.0.0.1"),
        "without a header configured"
    );
}

/// With the header configured, a connection without it is refused before
/// the upgrade, and the connection-status probe says why.
#[test]
fn test_missing_client_address_is_refused() {
    let mut config = default_config();
    config.client_ip_header = "Cf-Connecting-IP".into();
    let s = new_test_server(config);
    let (status, body) = http_get(&format!("{}/ws?apron_connection_status=1", s.http.url));
    assert_eq!(
        (status, String::from_utf8_lossy(&body).into_owned()),
        (
            403,
            r#"{"error":"Trusted client address unavailable"}"#.to_owned()
        )
    );
    let (status, _) = http_get(&format!("{}/ws", s.http.url));
    assert_eq!(status, 403, "an upgrade without the header");
    let (c, frame) = dial_headers(&s, &[("Cf-Connecting-IP", "198.51.100.4")]);
    assert_eq!(frame["method"].as_str(), Some("server"));
    drop(c);
}

/// The admin user signs in with the admin token only, so it can neither
/// propose an address nor approve the addition of one, which would let it
/// sign in by email.
#[test]
fn test_email_refused_to_the_admin_user() {
    let (server, mailbox) = email_test_server(|config| {
        config.admin_token = Some(rust_stdlib_crypto::sha256::sum256(
            super::admin_test::ADMIN_TOKEN.as_bytes(),
        ));
    });
    let mut admin = super::admin_test::admin(&server);
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
