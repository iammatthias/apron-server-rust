//! Differential gate for src/webauthn: replays the registrations, assertions
//! and option payloads that `tools/differential/webauthn` ran through
//! go-webauthn v0.18.2 (configured as aprond configures it) and checks this
//! port reaches the same verdict, error, and stored credential bytes.
//!
//! Regenerate the vectors with `go run . > vectors.json` in that directory.

use apron::server::protocol::encode_json;
use apron::webauthn::protocol::webauthncose::CoseAlgorithmIdentifier;
use apron::webauthn::protocol::{
    self, AuthenticatorSelection, CredentialParameter, CredentialType, Error, ErrorType,
    ResidentKeyRequirement, UrlEncodedBase64, UserVerificationRequirement,
};
use apron::webauthn::{
    with_authenticator_selection, with_exclusions, with_login_origin, with_registration_origin,
    with_resident_key_requirement, with_user_verification, Config, Credential, SessionData, User,
    WebAuthn,
};
use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::encoding::json::{self, v2};
use rust_stdlib_derive::Deserialize;

/// Registrations go-webauthn accepts or rejects for a reason this port
/// does not share: attestation formats it does not verify
/// (docs/DEVIATIONS.md). Each must still fail here.
const ATTESTATION_DEVIATIONS: &[&str] = &[
    "packed-x5c",
    "fmt-tpm",
    "fmt-fido-u2f",
    "fmt-apple",
    "fmt-android-key",
    "fmt-android-safetynet",
    "fmt-compound",
];

#[derive(Debug, Default, Deserialize)]
struct Vectors {
    #[json("rp_id")]
    rp_id: String,
    #[json("rp_origins")]
    rp_origins: Vec<String>,
    #[json("options")]
    options: Vec<OptionsVector>,
    #[json("registrations")]
    registrations: Vec<RegistrationVector>,
    #[json("assertions")]
    assertions: Vec<AssertionVector>,
    #[json("fixtures")]
    fixtures: Vec<FixtureVector>,
}

#[derive(Debug, Default, Deserialize)]
struct SessionVector {
    #[json("challenge")]
    challenge: String,
    #[json("rp_id")]
    rp_id: String,
    #[json("origin")]
    origin: String,
    #[json("user_id")]
    user_id: String,
    #[json("allowed_credential_ids")]
    allowed_credential_ids: Vec<String>,
    #[json("user_verification")]
    user_verification: String,
    #[json("cred_params")]
    cred_params: Vec<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct Expect {
    #[json("ok")]
    ok: bool,
    #[json("error_type")]
    error_type: String,
    #[json("error_details")]
    error_details: String,
    #[json("error_info")]
    error_info: String,
    #[json("error")]
    error: String,
    #[json("credential")]
    credential: String,
    #[json("clone_warning")]
    clone_warning: bool,
}

#[derive(Debug, Default, Deserialize)]
struct Exclusion {
    #[json("id")]
    id: String,
    #[json("transports")]
    transports: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct OptionsVector {
    #[json("name")]
    name: String,
    #[json("user_handle")]
    user_handle: String,
    #[json("user_name")]
    user_name: String,
    #[json("exclusions")]
    exclusions: Vec<Exclusion>,
    #[json("session")]
    session: SessionVector,
    #[json("public_key")]
    public_key: String,
}

#[derive(Debug, Default, Deserialize)]
struct RegistrationVector {
    #[json("name")]
    name: String,
    #[json("user_handle")]
    user_handle: String,
    #[json("session")]
    session: SessionVector,
    #[json("response")]
    response: String,
    #[json("expect")]
    expect: Expect,
}

#[derive(Debug, Default, Deserialize)]
struct AssertionVector {
    #[json("name")]
    name: String,
    #[json("user_handle")]
    user_handle: String,
    #[json("stored")]
    stored: String,
    #[json("session")]
    session: SessionVector,
    #[json("response")]
    response: String,
    #[json("expect")]
    expect: Expect,
}

#[derive(Debug, Default, Deserialize)]
struct FixtureVector {
    #[json("name")]
    name: String,
    #[json("response")]
    response: String,
    #[json("expect")]
    expect: Expect,
}

struct TestUser {
    handle: Vec<u8>,
    name: String,
    credentials: Vec<Credential>,
}

impl User for TestUser {
    fn webauthn_id(&self) -> &[u8] {
        &self.handle
    }
    fn webauthn_name(&self) -> String {
        self.name.clone()
    }
    fn webauthn_display_name(&self) -> String {
        self.name.clone()
    }
    fn webauthn_credentials(&self) -> &[Credential] {
        &self.credentials
    }
}

fn b64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("vector base64url")
}

fn load() -> Vectors {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tools/differential/webauthn/vectors.json"
    );
    json::unmarshal(&std::fs::read(path).expect("read vectors")).expect("decode vectors")
}

fn webauthn(v: &Vectors) -> WebAuthn {
    WebAuthn::new(Config {
        rpid: v.rp_id.clone(),
        rp_display_name: "Apron".into(),
        rp_origins: v.rp_origins.clone(),
    })
    .expect("config")
}

fn session(s: &SessionVector) -> SessionData {
    SessionData {
        challenge: s.challenge.clone(),
        relying_party_id: s.rp_id.clone(),
        origin: s.origin.clone(),
        user_id: b64(&s.user_id),
        allowed_credential_ids: s.allowed_credential_ids.iter().map(|id| b64(id)).collect(),
        user_verification: UserVerificationRequirement::new(s.user_verification.clone()),
        cred_params: s
            .cred_params
            .iter()
            .map(|&alg| CredentialParameter {
                kind: CredentialType::PUBLIC_KEY,
                algorithm: CoseAlgorithmIdentifier(alg),
            })
            .collect(),
        ..SessionData::default()
    }
}

fn marshal<T: v2::MarshalTo>(value: &T) -> String {
    String::from_utf8(encode_json(value).expect("marshal")).expect("utf-8")
}

/// Compares a verdict with Go's; returns the differences.
fn compare(name: &str, got: &Result<Credential, Error>, want: &Expect) -> Vec<String> {
    let mut diffs = Vec::new();
    match got {
        Ok(credential) => {
            if !want.ok {
                diffs.push(format!(
                    "{name}: accepted, Go rejected with {:?}",
                    want.error
                ));
                return diffs;
            }
            let encoded = marshal(credential);
            if encoded != want.credential {
                diffs.push(format!(
                    "{name}: credential\n  got  {encoded}\n  want {}",
                    want.credential
                ));
            }
            if credential.authenticator.clone_warning != want.clone_warning {
                diffs.push(format!(
                    "{name}: clone warning {}",
                    credential.authenticator.clone_warning
                ));
            }
        }
        Err(err) => {
            if want.ok {
                diffs.push(format!("{name}: rejected with {err:?}, Go accepted"));
                return diffs;
            }
            let (kind, details, info) = if want.error_type.is_empty() {
                ("", want.error.as_str(), "")
            } else {
                (
                    want.error_type.as_str(),
                    want.error_details.as_str(),
                    want.error_info.as_str(),
                )
            };
            if err.kind.as_str() != kind || err.details != details || err.info != info {
                diffs.push(format!(
                    "{name}: error\n  got  {:?} {:?} {:?}\n  want {kind:?} {details:?} {info:?}",
                    err.kind.as_str(),
                    err.details,
                    err.info
                ));
            }
        }
    }
    diffs
}

#[test]
fn registrations_match_go() {
    let v = load();
    let w = webauthn(&v);
    let mut diffs = Vec::new();
    for r in &v.registrations {
        let user = TestUser {
            handle: b64(&r.user_handle),
            name: "Ada".into(),
            credentials: Vec::new(),
        };
        let got = protocol::parse_credential_creation_response_bytes(r.response.as_bytes())
            .and_then(|parsed| w.create_credential(&user, &session(&r.session), parsed));
        if ATTESTATION_DEVIATIONS.contains(&r.name.as_str()) {
            match &got {
                Err(err) if err.kind == ErrorType::InvalidAttestation => {}
                other => diffs.push(format!("{}: deviation must reject, got {other:?}", r.name)),
            }
            continue;
        }
        diffs.extend(compare(&r.name, &got, &r.expect));
        if let Ok(credential) = &got {
            // A stored credential reads back to the same bytes, as persist.go
            // reloads it.
            let mut reloaded = Credential::default();
            v2::unmarshal(r.expect.credential.as_bytes(), &mut reloaded, &[]).expect("reload");
            assert_eq!(marshal(&reloaded), marshal(credential), "{}", r.name);
        }
    }
    assert!(
        v.registrations.len() > 120,
        "{} vectors",
        v.registrations.len()
    );
    assert!(
        diffs.is_empty(),
        "{} of {} differ:\n{}",
        diffs.len(),
        v.registrations.len(),
        diffs.join("\n")
    );
}

#[test]
fn assertions_match_go() {
    let v = load();
    let w = webauthn(&v);
    let mut diffs = Vec::new();
    for a in &v.assertions {
        let mut stored = Credential::default();
        v2::unmarshal(a.stored.as_bytes(), &mut stored, &[]).expect("stored credential");
        let user = TestUser {
            handle: b64(&a.user_handle),
            name: "Ada".into(),
            credentials: vec![stored.clone()],
        };
        let got = protocol::parse_credential_request_response_bytes(a.response.as_bytes())
            .and_then(|parsed| {
                w.validate_passkey_login(
                    |id: &[u8], handle: &[u8]| {
                        if id == stored.id.0.as_slice() && handle == user.handle.as_slice() {
                            Ok(&user)
                        } else {
                            Err("unknown credential")
                        }
                    },
                    &session(&a.session),
                    &parsed,
                )
                .map(|(_, credential)| credential)
            });
        diffs.extend(compare(&a.name, &got, &a.expect));
    }
    assert!(v.assertions.len() > 50, "{} vectors", v.assertions.len());
    assert!(
        diffs.is_empty(),
        "{} of {} differ:\n{}",
        diffs.len(),
        v.assertions.len(),
        diffs.join("\n")
    );
}

fn normalize(json: &str, challenge: &str) -> String {
    json.replace(
        &format!("\"challenge\":\"{challenge}\""),
        "\"challenge\":\"CHALLENGE\"",
    )
}

#[test]
fn options_match_go() {
    let v = load();
    let w = webauthn(&v);
    for o in &v.options {
        let (got, got_session, want_session) = if o.name == "login" {
            let (mut assertion, session) = w
                .begin_discoverable_login([
                    with_login_origin(&v.rp_origins[0]),
                    with_user_verification(UserVerificationRequirement::REQUIRED),
                ])
                .expect("begin login");
            assertion.response.timeout = 120_000;
            (marshal(&assertion.response), session, &o.session)
        } else {
            let user = TestUser {
                handle: b64(&o.user_handle),
                name: o.user_name.clone(),
                credentials: Vec::new(),
            };
            let exclusions = o
                .exclusions
                .iter()
                .map(|e| {
                    let mut credential = Credential::default();
                    credential.id.0 = b64(&e.id);
                    credential.attestation_format = "none".into();
                    credential.transport = e
                        .transports
                        .iter()
                        .map(|t| protocol::AuthenticatorTransport::new(t.clone()))
                        .collect();
                    credential.descriptor()
                })
                .collect();
            let (mut creation, session) = w
                .begin_registration(
                    &user,
                    [
                        with_registration_origin(&v.rp_origins[0]),
                        with_resident_key_requirement(ResidentKeyRequirement::REQUIRED),
                        with_authenticator_selection(AuthenticatorSelection {
                            resident_key: ResidentKeyRequirement::REQUIRED,
                            user_verification: UserVerificationRequirement::REQUIRED,
                            ..AuthenticatorSelection::default()
                        }),
                        with_exclusions(exclusions),
                    ],
                )
                .expect("begin registration");
            creation.response.timeout = 120_000;
            (marshal(&creation.response), session, &o.session)
        };
        assert_eq!(
            normalize(&got, &got_session.challenge),
            normalize(&o.public_key, &want_session.challenge),
            "{}",
            o.name
        );
        assert_eq!(UrlEncodedBase64(b64(&got_session.challenge)).0.len(), 32);
        assert_eq!(
            got_session.relying_party_id, want_session.rp_id,
            "{}",
            o.name
        );
        assert_eq!(got_session.origin, want_session.origin, "{}", o.name);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&got_session.user_id),
            want_session.user_id,
            "{}",
            o.name
        );
        assert_eq!(
            got_session.user_verification.as_str(),
            want_session.user_verification,
            "{}",
            o.name
        );
        let params: Vec<i64> = got_session
            .cred_params
            .iter()
            .map(|p| p.algorithm.0)
            .collect();
        assert_eq!(params, want_session.cred_params, "{}", o.name);
    }
    assert_eq!(v.options.len(), 3);
}

#[test]
fn fixture_credentials_match_go() {
    let v = load();
    let mut diffs = Vec::new();
    for f in &v.fixtures {
        let got = protocol::parse_credential_creation_response_bytes(f.response.as_bytes())
            .map(|_| Credential::default());
        diffs.extend(compare(&f.name, &got, &f.expect));
    }
    assert!(!v.fixtures.is_empty());
    assert!(diffs.is_empty(), "{}", diffs.join("\n"));
}
