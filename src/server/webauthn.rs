//! Passkeys (§4.10) and the bearer token sessions of passkey and email
//! sign-in (§3.2): webauthn.go, ported call for call against
//! `crate::webauthn`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::encoding::json::jsontext::Value;
use rust_stdlib::time::{self, Duration, Time};
use rust_stdlib_crypto::{rand, sha256};

use super::devices::DEVICE_TOKEN_PREFIX;
use super::protocol::*;
use super::server::{Client, State};
use super::users::normalize_name;
use crate::obj;
use crate::webauthn::protocol::{
    self as wa, AuthenticatorSelection, ResidentKeyRequirement, UserVerificationRequirement,
};
use crate::webauthn::{self, Credential, SessionData, User};

pub use crate::webauthn::WebAuthn;

pub const PASSKEY_LIFETIME: Duration = Duration::from_mins(2);
pub const SESSION_LIFETIME: Duration = Duration::from_hours(30 * 24);

/// A passkey user's handle and credentials, persisted with the user
/// (persist.rs). Go's `passkeyUser` also points back at its user; here the
/// user owns it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PasskeyUser {
    pub handle: Vec<u8>,
    pub credentials: Vec<Credential>,
}

/// The `webauthn::User` of one ceremony: Go's `passkeyUser`, or
/// `labelledPasskeyUser` when `label` is the display name a guest's
/// registration asks for, which password managers show as the user name.
struct PasskeyView<'a> {
    user_id: &'a str,
    handle: &'a [u8],
    credentials: &'a [Credential],
    label: String,
}

impl User for PasskeyView<'_> {
    fn webauthn_id(&self) -> &[u8] {
        self.handle
    }
    fn webauthn_name(&self) -> String {
        self.label.clone()
    }
    fn webauthn_display_name(&self) -> String {
        self.label.clone()
    }
    fn webauthn_credentials(&self) -> &[Credential] {
        self.credentials
    }
}

/// Go's `passkeyUser.WebAuthnName`: the user's name, or its user_id.
fn passkey_name(name: &str, user_id: &str) -> String {
    if name.is_empty() {
        user_id.to_owned()
    } else {
        name.to_owned()
    }
}

#[derive(Clone, Debug)]
pub struct PasskeyCeremony {
    pub challenge_id: String,
    pub action: String,
    pub identity_id: String,
    pub rp_id: String,
    pub origin: String,
    /// The user handle a registration's passkey gets; empty for a login.
    pub handle: Vec<u8>,
    /// The display name a guest's registration asked for, applied when it
    /// finishes; empty for a login, or a passkey added to an account.
    pub name: String,
    pub data: SessionData,
    pub expires: Time,
}

/// A bearer token's sign-in (§3.2): the account it resumes, bound to the
/// frontend origin that signed in.
#[derive(Clone, Debug)]
pub struct Session {
    pub user: String,
    pub origin: String,
    pub expires: Time,
}

/// The SHA-256 of a bearer token.
pub type SessionKey = [u8; 32];

/// The sessions by key, with an index by expiry every change keeps in step,
/// so a prune visits only the expired sessions.
#[derive(Default)]
pub struct Sessions {
    by_key: BTreeMap<SessionKey, Session>,
    by_expiry: BTreeSet<(i64, SessionKey)>,
}

impl Sessions {
    pub fn get(&self, key: &SessionKey) -> Option<&Session> {
        self.by_key.get(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &SessionKey> {
        self.by_key.keys()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    pub fn insert(&mut self, key: SessionKey, session: Session) {
        self.remove(&key);
        self.by_expiry.insert((session.expires.unix_nano(), key));
        self.by_key.insert(key, session);
    }

    pub fn remove(&mut self, key: &SessionKey) -> Option<Session> {
        let session = self.by_key.remove(key)?;
        self.by_expiry.remove(&(session.expires.unix_nano(), *key));
        Some(session)
    }

    pub fn renew(&mut self, key: &SessionKey, expires: Time) {
        if let Some(mut session) = self.remove(key) {
            session.expires = expires;
            self.insert(*key, session);
        }
    }

    /// The sessions expired at `now`.
    pub fn expired(&self, now: &Time) -> Vec<SessionKey> {
        self.by_expiry
            .range(..=(now.unix_nano(), [u8::MAX; 32]))
            .map(|(_, key)| *key)
            .filter(|key| !now.before(&self.by_key[key].expires))
            .collect()
    }
}

fn denied(message: &str) -> RpcError {
    RpcError::new(CODE_DENIED, message)
}

fn missing_challenge() -> RpcError {
    denied("Passkey challenge is missing or expired; try again")
}

fn verification_failed() -> RpcError {
    denied("Passkey verification failed")
}

impl State {
    fn ceremony_slot(&mut self, c: &Client) -> &mut Option<PasskeyCeremony> {
        &mut self
            .clients
            .get_mut(&c.id)
            .expect("a connection is registered while it reads")
            .ceremony
    }

    /// Runs with passkeys configured. One outstanding challenge is retained
    /// per connection; finishing consumes it even on failure. Auth responses
    /// are never deduplicated, so replay cannot resurrect a consumed
    /// challenge.
    pub fn authenticate_passkey(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<Json, RpcError> {
        let w = self
            .config
            .web_authn
            .clone()
            .expect("authenticate checks passkeys are configured");
        let action = parse_string(&req.params, "action", true)?;
        if action.is_empty() {
            return Err(invalid_params("action must be a non-empty string"));
        }
        if !wa::is_origin_in_haystack(&c.origin, &w.config.rp_origins) {
            return Err(denied("Frontend origin is not configured for passkeys"));
        }
        let now = time::now();
        self.prune_sessions_locked(&now);
        match action.as_str() {
            "register" | "login" => {
                let step = parse_string(&req.params, "step", true)?;
                if step.is_empty() {
                    return Err(invalid_params("step must be a non-empty string"));
                }
                match step.as_str() {
                    "begin" => self.begin_passkey(c, req, &action, &w, &now),
                    "finish" => self.finish_passkey_ceremony(c, req, &action, &w, &now),
                    _ => Err(invalid_params("Passkey step must be begin or finish")),
                }
            }
            _ => Err(invalid_params("Unknown passkey action")),
        }
    }

    fn begin_passkey(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
        action: &str,
        w: &WebAuthn,
        now: &Time,
    ) -> Result<Json, RpcError> {
        // Starting any new ceremony replaces the previous pending one. The
        // replacement happens before policy and library errors so a stale
        // pending challenge can never be resumed after a new begin was
        // attempted.
        *self.ceremony_slot(c) = None;

        let mut identity_id = String::new();
        let mut handle = Vec::new();
        let mut name = String::new();
        let (public_key, mut data) = if action == "register" {
            let Some(user_id) = self.client_user(c) else {
                return Err(denied("Sign in as a guest before adding a passkey"));
            };
            let u = &self.users[&user_id];
            identity_id = user_id.clone();
            let fresh;
            let passkey = match &u.passkey {
                Some(passkey) => passkey,
                None => {
                    fresh = PasskeyUser {
                        handle: rand::text().into_bytes(),
                        credentials: Vec::new(),
                    };
                    &fresh
                }
            };
            // A guest becoming an account may ask for its name with the
            // begin (§3.2); a passkey added to an account keeps the
            // account's name.
            if !u.account() {
                name = normalize_name(&parse_string(&req.params, "name", false)?);
            }
            if passkey.credentials.len() >= 10 {
                return Err(denied("This identity already has ten passkeys"));
            }
            let exclusions = passkey
                .credentials
                .iter()
                .map(Credential::descriptor)
                .collect();
            let registering = PasskeyView {
                user_id: &u.id,
                handle: &passkey.handle,
                credentials: &passkey.credentials,
                label: if name.is_empty() {
                    passkey_name(&u.name, &u.id)
                } else {
                    name.clone()
                },
            };
            let (mut creation, data) = w
                .begin_registration(
                    &registering,
                    [
                        webauthn::with_registration_origin(c.origin.clone()),
                        webauthn::with_resident_key_requirement(ResidentKeyRequirement::REQUIRED),
                        webauthn::with_authenticator_selection(AuthenticatorSelection {
                            resident_key: ResidentKeyRequirement::REQUIRED,
                            user_verification: UserVerificationRequirement::REQUIRED,
                            ..AuthenticatorSelection::default()
                        }),
                        webauthn::with_exclusions(exclusions),
                    ],
                )
                .map_err(|_| denied("Unable to begin passkey registration"))?;
            handle = passkey.handle.clone();
            creation.response.timeout = PASSKEY_LIFETIME.milliseconds();
            (encode_value(&creation.response)?, data)
        } else {
            let (mut assertion, data) = w
                .begin_discoverable_login([
                    webauthn::with_login_origin(c.origin.clone()),
                    webauthn::with_user_verification(UserVerificationRequirement::REQUIRED),
                ])
                .map_err(|_| denied("Unable to begin passkey sign-in"))?;
            assertion.response.timeout = PASSKEY_LIFETIME.milliseconds();
            (encode_value(&assertion.response)?, data)
        };

        data.expires = now.add(PASSKEY_LIFETIME);
        let challenge_id = rand::text();
        *self.ceremony_slot(c) = Some(PasskeyCeremony {
            challenge_id: challenge_id.clone(),
            action: action.to_owned(),
            identity_id,
            rp_id: w.config.rpid.clone(),
            origin: c.origin.clone(),
            handle,
            name,
            expires: data.expires.clone(),
            data,
        });
        let result: Json = obj! {"challenge_id" => challenge_id, "public_key" => public_key}.into();
        c.send_result(req, result.clone());
        Ok(result)
    }

    fn finish_passkey_ceremony(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
        action: &str,
        w: &WebAuthn,
        now: &Time,
    ) -> Result<Json, RpcError> {
        let challenge_id = parse_string(&req.params, "challenge_id", true)?;
        if challenge_id.is_empty() {
            return Err(invalid_params("challenge_id must be a non-empty string"));
        }
        // An ID from another connection or a superseded begin does not
        // identify the current ceremony and therefore must not consume the
        // current one. A finish carrying the current ID consumes it before
        // parsing or verifying the proof, including malformed proofs and
        // policy failures.
        let slot = self.ceremony_slot(c);
        if slot
            .as_ref()
            .is_none_or(|ceremony| ceremony.challenge_id != challenge_id)
        {
            return Err(missing_challenge());
        }
        let ceremony = slot.take().expect("checked above");
        if ceremony.action != action
            || ceremony.rp_id != w.config.rpid
            || ceremony.origin != c.origin
            || !now.before(&ceremony.expires)
        {
            return Err(missing_challenge());
        }
        let current = self.client_user(c);
        if ceremony.action == "register" && current.as_deref() != Some(&ceremony.identity_id) {
            return Err(denied("Identity changed; try again"));
        }
        let raw = parse_passkey_credential(&req.params, &ceremony.action)?;
        let user_id = if ceremony.action == "register" {
            let user_id = ceremony.identity_id.clone();
            let parsed = wa::parse_credential_creation_response_bytes(&raw)
                .map_err(|_| verification_failed())?;
            let registering = PasskeyView {
                user_id: &user_id,
                handle: &ceremony.handle,
                credentials: &[],
                label: String::new(),
            };
            let credential = w
                .create_credential(&registering, &ceremony.data, parsed)
                .map_err(|_| verification_failed())?;
            if self.credentials.contains_key(&credential.id.0) {
                return Err(denied("Passkey is already registered"));
            }
            let u = self.users.get_mut(&user_id).expect("the connection's user");
            if u.passkey
                .as_ref()
                .is_some_and(|user| user.handle != ceremony.handle || user.credentials.len() >= 10)
            {
                return Err(denied("Registration changed; try again"));
            }
            let credential_id = credential.id.0.clone();
            u.passkey
                .get_or_insert_with(|| PasskeyUser {
                    handle: ceremony.handle.clone(),
                    credentials: Vec::new(),
                })
                .credentials
                .push(credential);
            // The account takes the name its registration asked for.
            let renamed = !ceremony.name.is_empty() && ceremony.name != u.name;
            if renamed {
                u.name = ceremony.name.clone();
            }
            self.touch_user(&user_id);
            // A guest that becomes an account takes the roles its user_id
            // was granted.
            if self.grant_roles_locked(&user_id) || renamed {
                self.notify_profile_locked(&user_id, Some(c), &ExtObject::new(), &[]);
            }
            self.credentials.insert(credential_id, user_id.clone());
            user_id
        } else {
            let parsed = wa::parse_credential_request_response_bytes(&raw)
                .map_err(|_| verification_failed())?;
            let users = &self.users;
            let credentials = &self.credentials;
            let (verified, credential) = w
                .validate_passkey_login(
                    |id: &[u8], handle: &[u8]| {
                        let passkey = credentials
                            .get(id)
                            .and_then(|user_id| users.get(user_id))
                            .and_then(|u| Some((u, u.passkey.as_ref()?)))
                            .filter(|(_, passkey)| passkey.handle == handle);
                        match passkey {
                            Some((u, passkey)) => Ok(PasskeyView {
                                user_id: &u.id,
                                handle: &passkey.handle,
                                credentials: &passkey.credentials,
                                label: passkey_name(&u.name, &u.id),
                            }),
                            None => Err("unknown credential"),
                        }
                    },
                    &ceremony.data,
                    &parsed,
                )
                .map_err(|_| verification_failed())?;
            if credential.authenticator.clone_warning {
                return Err(verification_failed());
            }
            let user_id = verified.user_id.to_owned();
            let passkey = self
                .users
                .get_mut(&user_id)
                .and_then(|u| u.passkey.as_mut())
                .expect("the verified user has a passkey");
            for stored in &mut passkey.credentials {
                if stored.id == credential.id {
                    *stored = credential.clone();
                }
            }
            user_id
        };
        // A registration adds the passkey to the signed-in connection's
        // account, and a login as the user the connection is signed in as
        // changes no user: neither is a sign-in (§4.5).
        let sign_in = ceremony.action != "register" && current.as_deref() != Some(&user_id);
        self.sign_in_locked(c, req, &user_id, now, sign_in, false)
    }

    /// Makes an account the connection's identity after a passkey or email
    /// sign-in, or a passkey registration, with a new bearer token for later
    /// connections in the result (§3.2). The connection's previous token is
    /// forgotten. `sign_in` is whether the auth signed the connection in as
    /// a user it was not signed in as, rather than adding a passkey to it or
    /// authenticating it again as the same user, which alone sends what
    /// follows a sign-in (§4.5). `join_default` joins a new account to the
    /// default room.
    pub fn sign_in_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
        user_id: &str,
        now: &Time,
        sign_in: bool,
        join_default: bool,
    ) -> Result<Json, RpcError> {
        let previous = self.conn_token(c);
        self.sessions.remove(&previous);
        self.touch_session(previous);
        let (token, key) = self.new_session_locked(user_id, &c.origin, now);
        self.set_conn_token(c, key);
        Ok(self
            .switch_user_locked(
                c,
                req,
                user_id,
                obj! {"token" => token},
                sign_in,
                join_default,
            )
            .into())
    }

    /// Issues a bearer token that resumes the account from the origin for
    /// SESSION_LIFETIME, renewed on each use (§3.2). Only its SHA-256 is
    /// kept, as the session's key.
    pub fn new_session_locked(
        &mut self,
        user_id: &str,
        origin: &str,
        now: &Time,
    ) -> (String, [u8; 32]) {
        let mut secret = [0u8; 32];
        rand::read(&mut secret);
        let token = URL_SAFE_NO_PAD.encode(secret);
        let key = sha256::sum256(token.as_bytes());
        self.sessions.insert(
            key,
            Session {
                user: user_id.to_owned(),
                origin: origin.to_owned(),
                expires: now.add(SESSION_LIFETIME),
            },
        );
        self.touch_session(key);
        (token, key)
    }

    /// Forgets expired sessions. Go ranges over every session; the expiry
    /// index visits only the expired ones.
    pub fn prune_sessions_locked(&mut self, now: &Time) {
        for key in self.sessions.expired(now) {
            self.sessions.remove(&key);
            self.touch_session(key);
        }
    }

    /// Resumes a passkey or email sign-in through the protocol's token
    /// scheme (§3.2). Keeping this outside the WebAuthn action space
    /// preserves §4.10's register/login action grammar while retaining the
    /// example server's bearer token policy.
    pub fn authenticate_token(&mut self, c: &Arc<Client>, req: &Request) -> Result<Json, RpcError> {
        let now = time::now();
        *self.ceremony_slot(c) = None;
        let token = parse_string(&req.params, "token", true)?;
        if token.is_empty() {
            return Err(invalid_params("token must be a non-empty string"));
        }
        if token.starts_with(DEVICE_TOKEN_PREFIX) {
            return self.authenticate_device_locked(c, req, &token);
        }
        self.prune_sessions_locked(&now);
        let key = sha256::sum256(token.as_bytes());
        let Some(user_id) = self
            .sessions
            .get(&key)
            .filter(|session| session.origin == c.origin && now.before(&session.expires))
            .map(|session| session.user.clone())
        else {
            // A temporary token approves its proposal with this scheme too,
            // as a client presents the token of a link that isn't its own
            // (§4.11.2).
            if self.config.email_sender.is_some() && self.may_approve_locked(c, &token) {
                return self.approve_locked(c, req);
            }
            return Err(denied("Session expired; sign in again"));
        };
        // Each successful resume renews the session for a full lifetime, so
        // an active user is never forced back through a ceremony. The token
        // itself is not rotated, since several tabs may share one persisted
        // token: the result carries the presented token, which clients keep
        // as the latest.
        self.sessions.renew(&key, now.add(SESSION_LIFETIME));
        self.touch_session(key);
        self.set_conn_token(c, key);
        // Resuming the user the connection is signed in as is no sign-in
        // (§4.5), and sends nothing after its result.
        let sign_in = self.client_user(c).as_deref() != Some(&user_id);
        Ok(self
            .switch_user_locked(c, req, &user_id, obj! {"token" => token}, sign_in, false)
            .into())
    }

    fn conn_token(&self, c: &Client) -> [u8; 32] {
        self.clients.get(&c.id).map_or([0; 32], |conn| conn.token)
    }

    pub(super) fn set_conn_token(&mut self, c: &Client, key: [u8; 32]) {
        if let Some(conn) = self.clients.get_mut(&c.id) {
            conn.token = key;
        }
    }
}

fn encode_value<T: rust_stdlib::encoding::json::v2::MarshalTo>(
    value: &T,
) -> Result<Json, RpcError> {
    let encoded = encode_json(value)
        .ok_or_else(|| RpcError::new(CODE_INTERNAL_ERROR, "Unable to encode passkey options"))?;
    decode_non_null::<Json>(&encoded)
        .ok_or_else(|| RpcError::new(CODE_INTERNAL_ERROR, "Unable to encode passkey options"))
}

fn null_or_absent(value: Option<&Value>) -> bool {
    value.is_none_or(|v| v.0.trim_ascii() == b"null")
}

fn non_empty_string(value: Option<&Value>) -> bool {
    value
        .and_then(|v| decode_non_null::<String>(&v.0))
        .is_some_and(|text| !text.is_empty())
}

/// Performs only wire-shape validation. A syntactically shaped credential
/// with invalid base64, authenticator data, origin, RP, UV, or signature
/// remains a failed proof and is reported as denied by the caller.
fn parse_passkey_credential(params: &Params, action: &str) -> Result<Vec<u8>, RpcError> {
    let Some(raw) = params.get("credential") else {
        return Err(invalid_params("Missing credential"));
    };
    let Some(credential) = decode_non_null::<BTreeMap<String, Value>>(&raw.0) else {
        return Err(invalid_params("credential must be an object"));
    };
    for name in ["id", "rawId", "type"] {
        if !non_empty_string(credential.get(name)) {
            return Err(invalid_params(format!(
                "credential.{name} must be a non-empty string"
            )));
        }
    }
    if decode_non_null::<String>(&credential["type"].0).is_some_and(|t| t != "public-key") {
        return Err(invalid_params("credential.type must be public-key"));
    }
    if let Some(value) = credential.get("clientExtensionResults") {
        if decode_non_null::<BTreeMap<String, Value>>(&value.0).is_none() {
            return Err(invalid_params(
                "credential.clientExtensionResults must be an object",
            ));
        }
    }
    let attachment = credential.get("authenticatorAttachment");
    if !null_or_absent(attachment) && !non_empty_string(attachment) {
        return Err(invalid_params(
            "credential.authenticatorAttachment must be a non-empty string",
        ));
    }
    let Some(response) = credential
        .get("response")
        .and_then(|raw| decode_non_null::<BTreeMap<String, Value>>(&raw.0))
    else {
        return Err(invalid_params("credential.response must be an object"));
    };
    let fields: &[&str] = if action == "register" {
        &["clientDataJSON", "attestationObject"]
    } else {
        &["clientDataJSON", "authenticatorData", "signature"]
    };
    for name in fields {
        if !non_empty_string(response.get(*name)) {
            return Err(invalid_params(format!(
                "credential.response.{name} must be a non-empty string"
            )));
        }
    }
    let handle = response.get("userHandle");
    if !null_or_absent(handle) && !non_empty_string(handle) {
        return Err(invalid_params(
            "credential.response.userHandle must be a non-empty string",
        ));
    }
    let transports = response.get("transports");
    if !null_or_absent(transports)
        && decode_non_null::<Vec<String>>(&transports.expect("present").0).is_none()
    {
        return Err(invalid_params(
            "credential.response.transports must be an array",
        ));
    }
    encode_json(&credential).ok_or_else(|| invalid_params("credential is invalid"))
}
