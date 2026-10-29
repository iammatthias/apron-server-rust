//! credential_test.go. Not ported: the `Response` and `ResponseBody`
//! subtests of TestParseCredentialCreationResponse and
//! TestParseCredentialCreationResponse_NilRequest (`http.Request` and
//! `io.Reader` parsing), and TestGetAppID (AppID).

use super::*;
use apron::webauthn::protocol::{
    AuthenticatorAttachment, AuthenticatorFlags, AuthenticatorTransport, CeremonyType,
    CollectedClientData,
};

const SUCCESS: &str = vector!("credential_creation_success.json");
const TRAILING_DATA: &str = vector!("credential_creation_trailingData.json");

const ID: &str =
    "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g";
const AUTH_DATA: &str = "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw";
const RPID_HASH: &str = "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA";
const CREDENTIAL_PUB_KEY: &str = "pSJYIMfCKfxl2SvnqJIiHQysHmpmITNgtCkQ5ESExSRjqrhXAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNc";
const ATT_OBJECT: &str = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw";
const CLIENT_DATA_JSON: &str = "eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ";

/// Go compares whole structs, including `Raw` and the client extension
/// outputs, which the port cannot build by hand; each field is compared
/// instead, and the outputs through `appid` and `Present`.
#[test]
fn test_parse_credential_creation_response() {
    let actual = parse_credential_creation_response_bytes(SUCCESS.as_bytes())
        .expect("ShouldParseCredentialRequest");
    assert_eq!(actual.id, ID);
    assert_eq!(actual.kind, "public-key");
    assert_eq!(actual.raw_id, b64url(ID));
    assert_eq!(actual.client_extension_results.appid, Some(true));
    assert_eq!(actual.client_extension_results.present(), ["appid"]);
    assert_eq!(
        actual.authenticator_attachment,
        AuthenticatorAttachment::PLATFORM
    );

    assert_eq!(actual.raw.id, ID);
    assert_eq!(actual.raw.kind, "public-key");
    assert_eq!(actual.raw.raw_id.0, b64url(ID));
    assert_eq!(
        actual.raw.client_extension_results,
        actual.client_extension_results
    );
    assert_eq!(actual.raw.authenticator_attachment, "platform");
    let raw = &actual.raw.attestation_response;
    assert_eq!(raw.client_data_json.0, b64url(CLIENT_DATA_JSON));
    assert_eq!(raw.attestation_object.0, b64url(ATT_OBJECT));
    assert_eq!(raw.transports, ["usb", "nfc", "fake"]);

    assert_eq!(
        actual.response.transports,
        [
            AuthenticatorTransport::USB,
            AuthenticatorTransport::NFC,
            AuthenticatorTransport::new("fake")
        ]
    );
    assert_eq!(
        actual.response.collected_client_data,
        CollectedClientData {
            kind: CeremonyType::new("webauthn.create"),
            challenge: "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE".into(),
            origin: "https://webauthn.io".into(),
            ..CollectedClientData::default()
        }
    );
    let att = &actual.response.attestation_object;
    assert_eq!(att.format, "none");
    assert_eq!(att.raw_auth_data, b64url(AUTH_DATA));
    assert_eq!(att.auth_data.rpid_hash, b64url(RPID_HASH));
    assert_eq!(att.auth_data.counter, 0);
    assert_eq!(att.auth_data.flags, AuthenticatorFlags(0x41));
    assert_eq!(att.auth_data.att_data.aaguid, vec![0; 16]);
    assert_eq!(att.auth_data.att_data.credential_id, b64url(ID));
    assert_eq!(
        cose_members(&att.auth_data.att_data.credential_public_key),
        cose_members(&b64url(CREDENTIAL_PUB_KEY))
    );

    let err = parse_credential_creation_response_bytes(TRAILING_DATA.as_bytes())
        .expect_err("ShouldHandleTrailingData");
    assert_eq!(err.to_string(), "Parse error for Registration");
    assert_protocol_error(
        &err,
        ErrorType::InvalidRequest,
        "Parse error for Registration",
        "body contains trailing data",
    );
}

/// Go builds the parsed data by hand from the same vector this test
/// parses. On the error case Go also returns the client data hash; the
/// port returns only the error.
#[test]
fn test_parsed_credential_creation_data_verify() {
    let expected_hash = vec![
        0xa, 0xaf, 0x43, 0xda, 0x7e, 0xd3, 0x94, 0x98, 0x9b, 0xbc, 0x47, 0xcb, 0x0, 0x72, 0x6b,
        0xbc, 0xf3, 0xa2, 0x4a, 0x49, 0x5f, 0x84, 0x4f, 0x45, 0x97, 0x91, 0x6a, 0x2d, 0xff, 0x47,
        0xbc, 0xad,
    ];
    let verify = |pcc: &mut ParsedCredentialCreationData| {
        pcc.verify(
            "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE",
            "webauthn.io",
            &strings(&["https://webauthn.io"]),
            &[],
            TopOriginVerificationMode::Explicit,
            false,
            false,
            false,
            &params(&[-7]),
        )
    };

    let mut pcc = unpack_creation(SUCCESS);
    assert_eq!(
        verify(&mut pcc),
        Ok(expected_hash),
        "SuccessfulVerificationTest"
    );

    let mut pcc = unpack_creation(SUCCESS);
    pcc.id = "bm90LXRoZS1hdHRlc3RlZC1jcmVkZW50aWFsLWlkISE".into();
    pcc.raw_id = b"not-the-attested-credential-id!!".to_vec();
    let err = verify(&mut pcc).expect_err("ShouldFailWhenRawIDIsNotTheAttestedCredentialID");
    assert_eq!(
        err.to_string(),
        "Error validating the attested credential id"
    );
}

/// Go calls `CredentialCreationResponse.Parse` on a struct; the port
/// parses the JSON of that struct.
#[test]
fn test_credential_creation_response_parse_errors() {
    let cases = [
        ("ShouldFailMissingID", r#"{}"#, "Missing ID"),
        (
            "ShouldFailIDNotBase64",
            r#"{"id":"not valid base64 %%%"}"#,
            "ID not base64.RawURLEncoded",
        ),
        (
            "ShouldFailMissingType",
            r#"{"id":"dGVzdA"}"#,
            "Missing type",
        ),
        (
            "ShouldFailBadType",
            r#"{"id":"dGVzdA","type":"bad-type"}"#,
            "Type not public-key",
        ),
        (
            "ShouldFailRawIDMismatch",
            r#"{"id":"dGVzdA","type":"public-key","rawId":"bm90IHRlc3Q"}"#,
            "ID does not match rawId",
        ),
        (
            "ShouldFailRawIDMissing",
            r#"{"id":"dGVzdA","type":"public-key"}"#,
            "ID does not match rawId",
        ),
    ];
    for (name, body, info) in cases {
        let err = parse_credential_creation_response_bytes(body.as_bytes()).expect_err(name);
        assert_eq!(err.to_string(), "Parse error for Registration", "{name}");
        assert_protocol_error(
            &err,
            ErrorType::InvalidRequest,
            "Parse error for Registration",
            info,
        );
    }
}

#[test]
fn test_credential_creation_response_parse_raw_id_mismatch_is_distinguishable() {
    let err = parse_credential_creation_response_bytes(
        br#"{"id":"dGVzdA","type":"public-key","rawId":"bm90IHRlc3Q"}"#,
    )
    .expect_err("mismatch");
    assert_eq!(err.details, "Parse error for Registration");
    assert_eq!(err.info, "ID does not match rawId");
}
