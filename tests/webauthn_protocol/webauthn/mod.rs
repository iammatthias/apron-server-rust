//! The `webauthn` package tests: authenticator_test.go
//! TestAuthenticator_UpdateCounter, and the registration_test.go and
//! login_test.go cases for the ceremonies the port has
//! (`BeginRegistration`, `CreateCredential`, `BeginDiscoverableLogin`,
//! `ValidatePasskeyLogin`, `ValidateDiscoverableLogin`).
//!
//! The port has no `ValidateLogin` for a known user; its checks after the
//! user lookup are the ones `ValidatePasskeyLogin` runs, so the
//! `ValidateLogin` cases here run through `ValidatePasskeyLogin`, with the
//! user handle set to the user's ID and the session's user ID left empty.
//! The `BeginLogin` cases for behavior it shares with
//! `BeginDiscoverableLogin` run through the latter.
//!
//! Not ported, for options or configuration the port does not have:
//! TestWithRegistrationRelyingPartyID and TestWithLoginRelyingPartyID
//! cases that use `WithRegistrationRelyingPartyID`,
//! `WithRegistrationRelyingPartyName` or `WithLoginRelyingPartyID`;
//! TestBeginRegistration_EncodeUserIDAsString and the string and int
//! handle cases of TestBeginRegistrationUserHandleAfterOptions
//! (`EncodeUserIDAsString`); the ShouldEncodeString case of
//! TestEntityEncoding; TestBeginMediatedRegistration_EnforceTimeout and
//! TestBeginLogin_EnforceTimeout (`Timeouts`);
//! TestBeginRegistrationHintsSetAuthenticatorAttachment (hints);
//! TestValidateFilteredCredential and
//! TestCreateCredentialPropagatesFilteringFailure (`Filtering`);
//! TestRegistrationOptions and TestLoginOptions cases for options the
//! port does not have, and their Empty cases (no option applied);
//! TestBeginRegistrationOptionError and
//! TestBeginLoginOptionError (the port's options cannot fail);
//! TestBeginRegistration_StoresSessionExtensions,
//! TestCreateCredentialAcceptsSolicitedExtensionOutput,
//! TestCreateCredentialRejectsUnhonouredCredentialProtectionPolicy and
//! the SolicitedOutput case of TestValidateLoginExtensionOutputs
//! (requesting extensions); TestBeginDiscoverableMediatedLogin,
//! TestBeginMediatedLogin_NoCredentials, the ShouldSucceedMediationConditional
//! case of TestCreateCredential_Full, and BeginLogin-only behavior
//! (mediation, `BeginLogin`); TestSelectAuthenticator
//! (`SelectAuthenticator`); TestValidateLogin_Errors (`ValidateLogin`'s
//! user ID check).
//!
//! Not ported, out of the subset: the MDS cases of TestCreateCredential_Full
//! and TestValidateLogin_Full; TestCreateCredentialOpaqueOrigin,
//! TestValidateLoginOpaqueOrigin, and the opaque origin cases of
//! TestCreateCredentialBoundOrigin and TestValidateLoginBoundOrigin;
//! TestBeginRegistrationAppIDExcludePruning*, TestBeginLoginAppIDPruning*,
//! TestBeginDiscoverableLoginAppIDPruning and
//! TestValidateLoginAppIDFromSessionReplacesRPID (AppID);
//! TestRegistration_FinishRegistrationFailure, TestFinishRegistration_Success,
//! TestLogin_FinishLoginFailure, TestFinishDiscoverableLogin_Failure and
//! TestFinishPasskeyLogin_Failure (`http.Request` parsing; the success
//! cases of the Finish* helpers are ported as parse then validate);
//! TestAuthenticator_Msgp* and TestAuthenticator_DecodeMsgInvalidTypes
//! (msgp); and the `ValidateLogin` subtests of
//! TestFinishLoginFailureSessionChallenge.

use super::assertion::{assertion_body, spec_vector_none_es256, SUCCESS as ASSERTION_SUCCESS};
use super::*;
use apron::webauthn::protocol::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAttachment, AuthenticatorFlags,
    AuthenticatorSelection, AuthenticatorTransport, CredentialDescriptor,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions, ResidentKeyRequirement,
    UrlEncodedBase64, UserEntity, UserVerificationRequirement,
};
use apron::webauthn::{
    with_authenticator_selection, with_challenge, with_exclusions, with_login_origin,
    with_registration_origin, with_resident_key_requirement, with_user_verification, Authenticator,
    Config, Credential, CredentialFlags, RegistrationOption, SessionData, User, WebAuthn,
};
use rust_stdlib::encoding::json::{self, v2, Bytes};
use rust_stdlib::time;

mod login;
mod registration;

/// Go's `testUserID`.
const TEST_USER_ID: &[u8] = b"test-user-id";

/// Go's `defaultUser`.
#[derive(Clone, Default)]
struct TestUser {
    id: Vec<u8>,
    credentials: Vec<Credential>,
}

impl User for TestUser {
    fn webauthn_id(&self) -> &[u8] {
        &self.id
    }
    fn webauthn_name(&self) -> String {
        String::new()
    }
    fn webauthn_display_name(&self) -> String {
        String::new()
    }
    fn webauthn_credentials(&self) -> &[Credential] {
        &self.credentials
    }
}

fn user(id: &[u8]) -> TestUser {
    TestUser {
        id: id.to_vec(),
        credentials: Vec::new(),
    }
}

fn user_with(id: &[u8], credentials: Vec<Credential>) -> TestUser {
    TestUser {
        id: id.to_vec(),
        credentials,
    }
}

fn credential(id: &[u8], public_key: &[u8], flags: u8) -> Credential {
    Credential {
        id: Bytes(id.to_vec()),
        public_key: Bytes(public_key.to_vec()),
        flags: CredentialFlags::new(AuthenticatorFlags(flags)),
        ..Credential::default()
    }
}

const UP: u8 = AuthenticatorFlags::USER_PRESENT;
const UV: u8 = AuthenticatorFlags::USER_VERIFIED;
const BE: u8 = AuthenticatorFlags::BACKUP_ELIGIBLE;
const BS: u8 = AuthenticatorFlags::BACKUP_STATE;
const AT: u8 = AuthenticatorFlags::ATTESTED_CREDENTIAL_DATA;

fn config(rpid: &str, display_name: &str, origins: &[&str]) -> Config {
    Config {
        rpid: rpid.into(),
        rp_display_name: display_name.into(),
        rp_origins: strings(origins),
    }
}

/// Go's `New`.
fn new(config: Config) -> WebAuthn {
    WebAuthn::new(config).expect("valid configuration")
}

/// Go's `&WebAuthn{Config: ...}`, which skips `New`.
fn unvalidated(rpid: &str, origins: &[&str]) -> WebAuthn {
    WebAuthn {
        config: config(rpid, "", origins),
    }
}

fn expired() -> time::Time {
    time::now().add(-time::HOUR)
}

fn es256() -> Vec<apron::webauthn::protocol::CredentialParameter> {
    params(&[-7])
}

const REG_NONE_ES256_ATTESTATION_OBJECT: &str = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220";
const REG_NONE_ES256_CLIENT_DATA_JSON: &str = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d";
const REG_NONE_ES256_CREDENTIAL_ID: &str =
    "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4";
const REG_NONE_ES256_CHALLENGE: &str =
    "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130";
const RP_ID_HASH: &str = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5";

/// Go's `testRegistrationSpecVectorNoneES256Flags`: the W3C none ES256
/// registration with its flags byte replaced. Returns the body, the
/// challenge and the credential ID.
fn registration_none_es256_flags(flags: u8) -> (String, String, Vec<u8>) {
    let attestation_object = REG_NONE_ES256_ATTESTATION_OBJECT.replacen(
        &format!("{RP_ID_HASH}59"),
        &format!("{RP_ID_HASH}{flags:02x}"),
        1,
    );
    assert!(attestation_object.contains(&format!("{RP_ID_HASH}{flags:02x}")));
    registration_body(&attestation_object, &hex(REG_NONE_ES256_CLIENT_DATA_JSON))
}

fn registration_body(
    attestation_object: &str,
    client_data_json: &[u8],
) -> (String, String, Vec<u8>) {
    let credential_id = hex(REG_NONE_ES256_CREDENTIAL_ID);
    let body = creation_body(&credential_id, client_data_json, &hex(attestation_object));
    let challenge = URL_SAFE_NO_PAD.encode(hex(REG_NONE_ES256_CHALLENGE));
    (body, challenge, credential_id)
}

/// Go's `testRegistrationSpecVectorNoneES256`: the flags as published,
/// UP, BE, BS and AT.
fn registration_none_es256() -> (String, String, Vec<u8>) {
    registration_none_es256_flags(UP | BE | BS | AT)
}

/// Go's `testRegistrationSpecVectorNoneES256Origin`. Go re-marshals the
/// client data with its keys sorted; the origin is replaced in place.
fn registration_none_es256_origin(origin: &str) -> (String, String, Vec<u8>) {
    let client_data = String::from_utf8(hex(REG_NONE_ES256_CLIENT_DATA_JSON)).unwrap();
    let client_data = client_data.replacen(
        r#""origin":"https://example.org""#,
        &format!(r#""origin":"{origin}""#),
        1,
    );
    registration_body(REG_NONE_ES256_ATTESTATION_OBJECT, client_data.as_bytes())
}

/// Go's `testRegistrationSpecVectorPackedSelfES256`.
fn registration_packed_self_es256() -> (String, String, Vec<u8>) {
    let credential_id = hex("455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58c");
    let body = creation_body(
        &credential_id,
        &hex("7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2265476e4374334c55745936366b336a506a796e6962506b31716e666644616966715a774c33417032392d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205539685458764b453255526b4d6e625f307859485667227d"),
        &hex("a363666d74667061636b65646761747453746d74a263616c672663736967584630440220067a20754ab925005dbf378097c92120031581c73228d1fb4f5b881bcd7da98302207fc7b147558c7c0eba3af18bd9d121fa3d3a26d17fe3f220272178f473b6006d68617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000df850e09db6afbdfab51697791506cfc0020455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58ca5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2"),
    );
    let challenge = URL_SAFE_NO_PAD.encode(hex(
        "7869c2b772d4b58eba9378cf8f29e26cf935aa77df0da89fa99c0bdc0a76f7e5",
    ));
    (body, challenge, credential_id)
}

fn parse_registration(body: &str) -> apron::webauthn::protocol::ParsedCredentialCreationData {
    parse_credential_creation_response_bytes(body.as_bytes()).expect("parse registration")
}

/// Go's `newRegistrationFixture`.
fn registration_fixture() -> (
    WebAuthn,
    SessionData,
    apron::webauthn::protocol::ParsedCredentialCreationData,
) {
    let (body, challenge, _) = registration_none_es256();
    let session = SessionData {
        challenge,
        user_id: TEST_USER_ID.to_vec(),
        cred_params: es256(),
        ..SessionData::default()
    };
    (
        unvalidated("example.org", &["https://example.org"]),
        session,
        parse_registration(&body),
    )
}

/// Go's `testLoginSpecVectorNoneES256`, with the user handle the
/// `ValidateLogin` cases leave to the session.
fn login_none_es256_with_handle() -> (ParsedCredentialAssertionData, Vec<u8>, String, Vec<u8>) {
    let (mut parsed, key, challenge, id) = spec_vector_none_es256();
    parsed.response.user_handle = TEST_USER_ID.to_vec();
    (parsed, key, challenge, id)
}

fn passkey_login(
    w: &WebAuthn,
    user: &TestUser,
    session: &SessionData,
    parsed: &ParsedCredentialAssertionData,
) -> Result<Credential, Error> {
    w.validate_passkey_login(|_, _| Ok::<_, String>(user), session, parsed)
        .map(|(_, credential)| credential)
}

// authenticator_test.go

#[test]
fn test_authenticator_update_counter() {
    let cases = [
        ("IncreasedCounter", 1, 2, false),
        ("UnchangedCounter", 1, 1, true),
        ("DecreasedCounter", 2, 1, true),
        ("ZeroCounter", 0, 0, false),
        ("CounterReturnedToZero", 1, 0, true),
    ];
    for (name, sign_count, auth_data_count, want) in cases {
        let mut authenticator = Authenticator {
            aaguid: Bytes(vec![0; 16]),
            sign_count,
            clone_warning: false,
            ..Authenticator::default()
        };
        authenticator.update_counter(auth_data_count);
        assert_eq!(authenticator.clone_warning, want, "{name}");
        let expected_count = if want { sign_count } else { auth_data_count };
        assert_eq!(authenticator.sign_count, expected_count, "{name}");
    }
}
