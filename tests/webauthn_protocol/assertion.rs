//! assertion_test.go. Not ported: TestParseCredentialRequestResponse_NilRequest
//! and TestParseCredentialRequestResponse_Success (`http.Request`
//! parsing), the AppID cases of TestParsedCredentialAssertionData_Verify
//! (ShouldFailWithAppIDNotMatchingAuthenticatorData,
//! ShouldFailWithAppIDMatchingAuthenticatorData), and
//! TestParsedCredentialAssertionData_VerifyDoesNotWriteBeyondAuthenticatorData,
//! which checks Go slice capacity aliasing that Rust's `Vec` cannot have.

use super::*;
use apron::webauthn::protocol::{
    AuthenticatorAttachment, AuthenticatorFlags, CeremonyType, CollectedClientData,
};

pub(crate) const SUCCESS: &str = vector!("credential_assertion_success.json");
const TRAILING_DATA: &str = vector!("credential_assertion_trailingData.json");

const ID: &str = "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng";

/// Go's `testAssertionSpecVectorNoneES256`: the W3C none ES256 test
/// vector, with its credential public key and challenge.
pub(crate) fn spec_vector_none_es256() -> (ParsedCredentialAssertionData, Vec<u8>, String, Vec<u8>)
{
    let credential_id = hex("f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4");
    let cred_pub_key = hex("a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220");
    let challenge = URL_SAFE_NO_PAD.encode(hex(
        "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408",
    ));
    let body = assertion_body(
        &credential_id,
        &hex("bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"),
        &hex("7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"),
        &hex("3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"),
        None,
    );
    let parsed = parse_credential_request_response_bytes(body.as_bytes()).expect("spec vector");
    (parsed, cred_pub_key, challenge, credential_id)
}

/// An authentication response body, as Go's test fixtures marshal one.
pub(crate) fn assertion_body(
    id: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
    user_handle: Option<&[u8]>,
) -> String {
    let id = URL_SAFE_NO_PAD.encode(id);
    let user_handle = user_handle.map_or(String::new(), |h| {
        format!(r#","userHandle":"{}""#, URL_SAFE_NO_PAD.encode(h))
    });
    format!(
        r#"{{"id":"{id}","rawId":"{id}","type":"public-key","response":{{"authenticatorData":"{}","clientDataJSON":"{}","signature":"{}"{user_handle}}}}}"#,
        URL_SAFE_NO_PAD.encode(authenticator_data),
        URL_SAFE_NO_PAD.encode(client_data_json),
        URL_SAFE_NO_PAD.encode(signature),
    )
}

/// Go reads the body through `ParseCredentialRequestResponseBody`; the
/// port parses the same bytes. As for registration, each field is
/// compared in place of whole structs.
#[test]
fn test_parse_credential_request_response() {
    let auth_data = b64url("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFXJJiGa3OAAI1vMYKZIsLJfHwVQMANwCOw-atj9C0vhWpfWU-whzNjeQS21Lpxfdk_G-omAtffWztpGoErlNOfuXWRqm9Uj9ANJck1p6lAQIDJiABIVggKAhfsdHcBIc0KPgAcRyAIK_-Vi-nCXHkRHPNaCMBZ-4iWCBxB8fGYQSBONi9uvq0gv95dGWlhJrBwCsj_a4LJQKVHQ");
    let signature = b64url("MEUCIBtIVOQxzFYdyWQyxaLR0tik1TnuPhGVhXVSNgFwLmN5AiEAnxXdCq0UeAVGWxOaFcjBZ_mEZoXqNboY5IkQDdlWZYc");
    let user_handle = b64url("0ToAAAAAAAAAAA");

    let actual = parse_credential_request_response_bytes(SUCCESS.as_bytes())
        .expect("ShouldParseCredentialAssertion");
    assert_eq!(actual.id, ID);
    assert_eq!(actual.kind, "public-key");
    assert_eq!(actual.raw_id, b64url(ID));
    assert_eq!(actual.client_extension_results.appid, None);
    assert_eq!(actual.client_extension_results.present(), ["vendorAppID"]);
    assert_eq!(
        actual.authenticator_attachment,
        AuthenticatorAttachment::default()
    );
    assert_eq!(
        actual.response.collected_client_data,
        CollectedClientData {
            kind: CeremonyType::new("webauthn.get"),
            challenge: "E4PTcIH_HfX1pC6Sigk1SC9NAlgeztN0439vi8z_c9k".into(),
            origin: "https://webauthn.io".into(),
            hint: "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
                .into(),
            ..CollectedClientData::default()
        }
    );
    let ad = &actual.response.authenticator_data;
    assert_eq!(
        ad.rpid_hash,
        b64url("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA")
    );
    assert_eq!(ad.counter, 1553097241);
    assert_eq!(ad.flags, AuthenticatorFlags(0x45));
    assert_eq!(ad.att_data.aaguid, b64url("rc4AAjW8xgpkiwsl8fBVAw"));
    assert_eq!(ad.att_data.credential_id, b64url(ID));
    assert_eq!(
        cose_members(&ad.att_data.credential_public_key),
        cose_members(&b64url("pQMmIAEhWCAoCF-x0dwEhzQo-ABxHIAgr_5WL6cJceREc81oIwFn7iJYIHEHx8ZhBIE42L26-rSC_3l0ZaWEmsHAKyP9rgslApUdAQI"))
    );
    assert_eq!(actual.response.signature, signature);
    assert_eq!(actual.response.user_handle, user_handle);
    let raw = &actual.raw;
    assert_eq!((raw.id.as_str(), raw.kind.as_str()), (ID, "public-key"));
    assert_eq!(raw.raw_id.0, b64url(ID));
    assert_eq!(raw.assertion_response.authenticator_data.0, auth_data);
    assert_eq!(raw.assertion_response.signature.0, signature);
    assert_eq!(raw.assertion_response.user_handle.0, user_handle);

    let err = parse_credential_request_response_bytes(TRAILING_DATA.as_bytes())
        .expect_err("ShouldHandleTrailingData");
    assert_eq!(err.to_string(), "Parse error for Assertion");
    assert_protocol_error(
        &err,
        ErrorType::InvalidRequest,
        "Parse error for Assertion",
        "body contains trailing data",
    );
}

#[test]
fn test_parse_credential_request_response_bytes() {
    let cases = [
        (
            "ShouldFailInvalidJSON",
            "not json",
            "invalid character 'o' in literal null (expecting 'u')",
        ),
        (
            "ShouldFailTrailingData",
            TRAILING_DATA,
            "body contains trailing data",
        ),
    ];
    for (name, data, info) in cases {
        let err = parse_credential_request_response_bytes(data.as_bytes()).expect_err(name);
        assert_eq!(err.to_string(), "Parse error for Assertion", "{name}");
        assert_protocol_error(
            &err,
            ErrorType::InvalidRequest,
            "Parse error for Assertion",
            info,
        );
    }
    let result =
        parse_credential_request_response_bytes(SUCCESS.as_bytes()).expect("ShouldSucceed");
    assert_eq!(result.id, ID);
}

/// Go calls `CredentialAssertionResponse.Parse` on a struct; the port
/// parses the JSON of that struct.
#[test]
fn test_credential_assertion_response_parse_errors() {
    let cases = [
        (
            "ShouldFailMissingID",
            r#"{}"#,
            "CredentialAssertionResponse with ID missing",
        ),
        (
            "ShouldFailIDNotBase64",
            r#"{"id":"not valid base64 %%%"}"#,
            "CredentialAssertionResponse with ID not base64url encoded",
        ),
        (
            "ShouldFailBadType",
            r#"{"id":"dGVzdA","type":"bad-type"}"#,
            "CredentialAssertionResponse with bad type",
        ),
        (
            "ShouldFailRawIDMismatch",
            r#"{"id":"dGVzdA","type":"public-key","rawId":"bm90IHRlc3Q"}"#,
            "CredentialAssertionResponse with ID that does not match the rawId",
        ),
        (
            "ShouldFailIDDecodingToNoBytes",
            r#"{"id":"\r\n","type":"public-key"}"#,
            "CredentialAssertionResponse with ID that decodes to no bytes",
        ),
        (
            "ShouldFailRawIDMissing",
            r#"{"id":"dGVzdA","type":"public-key"}"#,
            "CredentialAssertionResponse with ID that does not match the rawId",
        ),
    ];
    for (name, body, want) in cases {
        let err = parse_credential_request_response_bytes(body.as_bytes()).expect_err(name);
        assert_eq!(err.to_string(), want, "{name}");
    }
}

#[test]
fn test_parsed_credential_assertion_data_verify() {
    let (par, cred_pub_key, challenge, _) = spec_vector_none_es256();
    let wrong_key = hex("a5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2");
    // Name, challenge, RP ID, credential public key, expected error.
    type Case<'a> = (&'a str, &'a str, &'a str, &'a [u8], Option<&'a str>);
    let cases: [Case; 5] = [
        (
            "ShouldSucceed",
            &challenge,
            "example.org",
            &cred_pub_key,
            None,
        ),
        (
            "ShouldFailClientDataVerification",
            "wrong-challenge",
            "example.org",
            &cred_pub_key,
            Some("Error validating challenge"),
        ),
        (
            "ShouldFailAuthDataVerification",
            &challenge,
            "wrong-rp-id.example.com",
            &cred_pub_key,
            Some("Error validating the authenticator response"),
        ),
        (
            "ShouldFailInvalidPublicKey",
            &challenge,
            "example.org",
            b"invalid-key",
            Some("Error parsing the assertion public key: Unsupported Public Key Type"),
        ),
        (
            "ShouldFailSignatureVerification",
            &challenge,
            "example.org",
            &wrong_key,
            Some("Error validating the assertion signature: <nil>"),
        ),
    ];
    for (name, challenge, rp_id, credential_bytes, want) in cases {
        let result = par.verify(
            challenge,
            rp_id,
            &strings(&["https://example.org"]),
            &[],
            TopOriginVerificationMode::Explicit,
            false,
            false,
            true,
            credential_bytes,
        );
        assert_eq!(
            result.map_err(|err| err.to_string()),
            want.map_or(Ok(()), |w| Err(w.to_string())),
            "{name}"
        );
    }
}

#[test]
fn test_credential_assertion_response_parse_authenticator_attachment() {
    let cases = [
        (
            "ShouldHandlePlatform",
            "platform",
            AuthenticatorAttachment::PLATFORM,
        ),
        (
            "ShouldHandleCrossPlatform",
            "cross-platform",
            AuthenticatorAttachment::CROSS_PLATFORM,
        ),
        ("ShouldHandleEmpty", "", AuthenticatorAttachment::default()),
    ];
    for (name, attachment, want) in cases {
        let data = if attachment.is_empty() {
            SUCCESS.to_string()
        } else {
            SUCCESS.replacen(
                r#""type":"public-key","#,
                &format!(r#""type":"public-key","authenticatorAttachment":"{attachment}","#),
                1,
            )
        };
        let result = parse_credential_request_response_bytes(data.as_bytes()).expect(name);
        assert_eq!(result.authenticator_attachment, want, "{name}");
    }
}

/// Go asserts only that parsing fails; it returns the JSON error as is,
/// which is the error asserted here.
#[test]
fn test_credential_assertion_response_parse_client_data_json_error() {
    let mut auth_data = vec![0u8; 32];
    auth_data.push(0x01);
    auth_data.extend_from_slice(&[0; 8]);
    let body = assertion_body(b"test", &auth_data, b"not valid json", b"", None);
    let err = parse_credential_request_response_bytes(body.as_bytes()).expect_err("client data");
    assert_protocol_error(
        &err,
        ErrorType::Other,
        "invalid character 'o' in literal null (expecting 'u')",
        "",
    );
}

#[test]
fn test_credential_assertion_response_parse_auth_data_error() {
    let body = assertion_body(
        b"test",
        &[0x01, 0x02],
        br#"{"type":"webauthn.get","challenge":"dGVzdA","origin":"https://example.org"}"#,
        b"",
        None,
    );
    let err = parse_credential_request_response_bytes(body.as_bytes()).expect_err("auth data");
    assert_eq!(err.to_string(), "Error unmarshalling auth data");
}
