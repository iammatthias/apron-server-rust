//! The shared fixture `tests/fixtures/webauthn.json` of the Apron protocol
//! repository, loaded from `$APRON_GO_DIR/testdata/apron` (default
//! `~/Developer/forks/apron-server-go`).
//!
//! The fixture shows canonical wire shapes for a client to parse, with
//! synthetic bytes. The gate (docs/PORT.md) is that the options this port
//! sends for the fixture's inputs carry every member the fixture shows with
//! the same value, except where go-webauthn itself sends something else,
//! which `tests/webauthn_differential.rs` pins to Go's bytes:
//!
//! * `challenge` is random: it must be 32 bytes of base64url.
//! * `pubKeyCredParams` lists all ten algorithms go-webauthn offers; the
//!   fixture's entries must be among them.
//! * `attestation` is omitted (the conveyance default, `none`).
//! * `allowCredentials` is omitted rather than `[]`: no credentials either way.
//!
//! The fixture's finish credential must pass the wire-shape parse and fail
//! at its synthetic attestation, as it does in Go.

use apron::server::protocol::encode_json;
use apron::webauthn::protocol::{
    self, AuthenticatorSelection, ErrorType, ResidentKeyRequirement, UserVerificationRequirement,
};
use apron::webauthn::{
    with_authenticator_selection, with_exclusions, with_login_origin, with_registration_origin,
    with_resident_key_requirement, with_user_verification, Config, Credential, User, WebAuthn,
};
use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::encoding::json::{self, v2, Value};

struct FixtureUser {
    handle: Vec<u8>,
    name: String,
}

impl User for FixtureUser {
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
        &[]
    }
}

fn fixture() -> Value {
    let dir = std::env::var("APRON_GO_DIR").unwrap_or_else(|_| {
        format!(
            "{}/Developer/forks/apron-server-go",
            std::env::var("HOME").expect("HOME")
        )
    });
    let path = format!("{dir}/testdata/apron/tests/fixtures/webauthn.json");
    let data = std::fs::read(&path).unwrap_or_else(|err| panic!("read {path}: {err}"));
    json::unmarshal(&data).expect("fixture JSON")
}

fn get<'a>(v: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(v, |v, key| match v {
        Value::Object(m) => m.get(key).unwrap_or_else(|| panic!("missing {key}")),
        _ => panic!("not an object at {key}"),
    })
}

fn text(v: &Value) -> &str {
    v.as_str().expect("string")
}

fn members(v: &Value) -> Vec<(String, Value)> {
    match v {
        Value::Object(m) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        _ => panic!("not an object"),
    }
}

fn webauthn(rp_id: &str) -> WebAuthn {
    WebAuthn::new(Config {
        rpid: rp_id.into(),
        rp_display_name: "Apron".into(),
        rp_origins: vec!["https://demo.example".into()],
    })
    .expect("config")
}

fn marshal<T: v2::MarshalTo>(value: &T) -> Value {
    json::unmarshal(&encode_json(value).expect("marshal")).expect("reparse")
}

/// Compares our options with the fixture's under the gate in the module doc.
fn check_options(case: &str, ours: &Value, fixture: &Value) {
    let ours = members(ours);
    let find = |key: &str| ours.iter().find(|(k, _)| k == key).map(|(_, v)| v);
    for (key, want) in members(fixture) {
        match key.as_str() {
            "challenge" => {
                let got = URL_SAFE_NO_PAD
                    .decode(text(find("challenge").expect("challenge")))
                    .unwrap();
                assert_eq!(got.len(), 32, "{case}: challenge");
            }
            "pubKeyCredParams" => {
                let Some(Value::Array(got)) = find(&key) else {
                    panic!("{case}: {key}")
                };
                let Value::Array(want) = want else {
                    panic!("{case}: {key}")
                };
                assert_eq!(got.len(), 10, "{case}: {key}");
                for entry in want {
                    assert!(got.contains(&entry), "{case}: {key} lacks {entry}");
                }
            }
            "attestation" => {
                assert_eq!(text(&want), "none", "{case}");
                assert!(find(&key).is_none(), "{case}: Go omits attestation");
            }
            "allowCredentials" => {
                assert_eq!(want, Value::Array(Vec::new()), "{case}");
                assert!(
                    find(&key).is_none(),
                    "{case}: Go omits empty allowCredentials"
                );
            }
            _ => assert_eq!(find(&key), Some(&want), "{case}: {key}"),
        }
    }
    for (key, _) in &ours {
        assert!(
            members(fixture).iter().any(|(k, _)| k == key),
            "{case}: {key} is not in the fixture"
        );
    }
}

#[test]
fn fixture_wire_shapes() {
    let f = fixture();
    assert_eq!(text(get(&f, &["kind"])), "webauthn");
    let Value::Array(cases) = get(&f, &["cases"]) else {
        panic!("cases")
    };
    assert_eq!(cases.len(), 2);
    for case in cases {
        let name = text(get(case, &["name"]));
        let public_key = get(case, &["begin_result", "public_key"]);
        match name {
            "register" => {
                let rp_id = text(get(public_key, &["rp", "id"]));
                let w = webauthn(rp_id);
                let user = FixtureUser {
                    handle: URL_SAFE_NO_PAD
                        .decode(text(get(public_key, &["user", "id"])))
                        .unwrap(),
                    name: text(get(case, &["begin", "params", "name"])).into(),
                };
                let (mut creation, session) = w
                    .begin_registration(
                        &user,
                        [
                            with_registration_origin("https://demo.example"),
                            with_resident_key_requirement(ResidentKeyRequirement::REQUIRED),
                            with_authenticator_selection(AuthenticatorSelection {
                                resident_key: ResidentKeyRequirement::REQUIRED,
                                user_verification: UserVerificationRequirement::REQUIRED,
                                ..AuthenticatorSelection::default()
                            }),
                            with_exclusions(Vec::new()),
                        ],
                    )
                    .expect("begin registration");
                creation.response.timeout = 120_000;
                check_options(name, &marshal(&creation.response), public_key);
                assert_eq!(session.user_id, user.handle);
                // user_labeled_from_requested_name.
                assert_eq!(creation.response.user.name, "Ada");

                // credential_is_browser_json: the shape parses, and the
                // synthetic attestation is what fails.
                let credential = get(case, &["finish", "params", "credential"]);
                let err = protocol::parse_credential_creation_response_bytes(
                    credential.to_string().as_bytes(),
                )
                .unwrap_err();
                assert_eq!(err.kind, ErrorType::ParseError);
                assert_eq!(err.details, "Error parsing attestation response");
            }
            "discoverable-login" => {
                let w = webauthn(text(get(public_key, &["rpId"])));
                let (mut assertion, session) = w
                    .begin_discoverable_login([
                        with_login_origin("https://demo.example"),
                        with_user_verification(UserVerificationRequirement::REQUIRED),
                    ])
                    .expect("begin login");
                assertion.response.timeout = 120_000;
                check_options(name, &marshal(&assertion.response), public_key);
                // discoverable, allow_credentials_is_empty.
                assert!(session.user_id.is_empty());
                assert!(assertion.response.allowed_credentials.is_empty());
            }
            other => panic!("unexpected case {other}"),
        }
    }
}
