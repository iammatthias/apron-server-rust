//! attestation_test.go. Not ported:
//! TestAttestationObject_VerifyAttestation_HandlerErrors, which registers
//! custom formats in Go's attestation registry.

use super::*;
use apron::webauthn::protocol::AttestationObject;

const RESPONSES: [&str; 4] = [
    vector!("attestation_response_0.json"),
    vector!("attestation_response_1.json"),
    vector!("attestation_response_2.json"),
    vector!("attestation_response_3.json"),
];

/// Go reads the challenge, RP ID, origin (the RP name) and parameters
/// from `testAttestationOptions`; they are inlined here.
#[test]
fn test_attestation_verify() {
    struct Case {
        name: &'static str,
        response: &'static str,
        challenge: &'static str,
        rp_id: &'static str,
        origin: &'static str,
        algorithms: &'static [i64],
        want: Result<&'static str, (ErrorType, &'static str, &'static str)>,
    }
    let cases = [
        Case {
            name: "ShouldVerifySelfAttestationEC256MacOS",
            response: RESPONSES[0],
            challenge: "rWiex8xDOPfiCgyFu4BLW6vVOmXKgPwHrlMCgEs9SBA",
            rp_id: "localhost",
            origin: "http://localhost:9005",
            algorithms: &[-7],
            want: Ok("basic_surrogate"),
        },
        Case {
            // Go verifies this fido-u2f attestation; the port rejects
            // the format as unsupported.
            name: "ShouldVerifyDirectAttestationEC256Titan",
            response: RESPONSES[1],
            challenge: "-Ri5NZTzJ8b6mvW3TVScLotEoALfgBa2Bn4YSaIObHc",
            rp_id: "webauthn.io",
            origin: "https://webauthn.io",
            algorithms: &[-7],
            want: Err((
                ErrorType::InvalidAttestation,
                "Invalid attestation format",
                "Attestation format fido-u2f is unsupported",
            )),
        },
        Case {
            name: "ShouldVerifyNoneAttestationEC256Titan",
            response: RESPONSES[2],
            challenge: "sVt4ScceMzqFSnfAq8hgLzblvo3fa4_aFVEcIESHIJ0",
            rp_id: "webauthn.io",
            origin: "https://webauthn.io",
            algorithms: &[-7],
            want: Ok("none"),
        },
        Case {
            // Go verifies this packed attestation's x5c chain; the port
            // rejects packed with x5c as unsupported.
            name: "ShouldVerifyPackedAttestationGramThanos",
            response: RESPONSES[3],
            challenge: "Dw4NDAsKCQgHBgUEAwIBAA",
            rp_id: "gramthanos.github.io",
            origin: "https://gramthanos.github.io",
            algorithms: &[-7, -37, -257, -8],
            want: Err((
                ErrorType::InvalidAttestation,
                "Basic attestation with an x5c certificate chain is not supported",
                "",
            )),
        },
    ];
    for tc in cases {
        let mut pcc = unpack_creation(tc.response);
        let result = pcc.verify(
            tc.challenge,
            tc.rp_id,
            &[tc.origin.to_string()],
            &[],
            TopOriginVerificationMode::Explicit,
            false,
            false,
            false,
            &params(tc.algorithms),
        );
        match tc.want {
            Ok(kind) => {
                assert_eq!(result.map(|hash| hash.len()), Ok(32), "{}", tc.name);
                assert_eq!(pcc.response.attestation_object.kind, kind, "{}", tc.name);
            }
            Err((kind, details, info)) => {
                let err = result.expect_err(tc.name);
                assert_protocol_error(&err, kind, details, info);
            }
        }
    }
}

#[test]
fn test_packed_attestation_verification() {
    let pcc = unpack_creation(RESPONSES[0]);
    let mut att = pcc.response.attestation_object.clone();
    assert_eq!(att.verify_attestation(&client_data_hash(&pcc)), Ok(()));
    assert_eq!(att.kind, "basic_surrogate");
}

/// Go calls `AuthenticatorAttestationResponse.Parse`, which reports
/// "Error parsing the authenticator response"; the port reaches it
/// through `ParseCredentialCreationResponseBytes`, which wraps that error
/// as Go's does.
#[test]
fn test_attestation_response_parse_errors() {
    let cases: [(&str, &[u8], &[u8]); 2] = [
        ("ShouldFailInvalidClientDataJSON", b"not-json", &[0xa0]),
        (
            "ShouldFailInvalidAttestationObjectCBOR",
            br#"{"type":"webauthn.create","challenge":"dGVzdA","origin":"https://example.com"}"#,
            b"not-cbor",
        ),
    ];
    for (name, client_data_json, attestation_object) in cases {
        let body = creation_body(b"test", client_data_json, attestation_object);
        let err = parse_credential_creation_response_bytes(body.as_bytes()).expect_err(name);
        assert_protocol_error(
            &err,
            ErrorType::ParseError,
            "Error parsing attestation response",
            "",
        );
    }
}

#[test]
fn test_attestation_response_parse_rejects_trailing_cbor() {
    let pcc = unpack_creation(RESPONSES[0]);
    let raw = &pcc.raw.attestation_response;
    let body = creation_body(
        &pcc.raw_id,
        &raw.client_data_json.0,
        &raw.attestation_object.0,
    );
    let reparsed =
        parse_credential_creation_response_bytes(body.as_bytes()).expect("untouched object");
    assert_eq!(reparsed.response.attestation_object.format, "packed");

    let mut attestation_object = raw.attestation_object.0.clone();
    attestation_object.push(0x01);
    let body = creation_body(&pcc.raw_id, &raw.client_data_json.0, &attestation_object);
    let err = parse_credential_creation_response_bytes(body.as_bytes()).expect_err("trailing");
    assert_protocol_error(
        &err,
        ErrorType::ParseError,
        "Error parsing attestation response",
        "",
    );
}

#[test]
fn test_attestation_object_verify_attestation_errors() {
    let cases = [
        (
            "ShouldFailNoneFormatWithStatement",
            AttestationObject {
                format: "none".into(),
                att_statement: Some(vec![("key".into(), Value::Text("value".into()))]),
                ..AttestationObject::default()
            },
        ),
        (
            "ShouldFailUnsupportedFormat",
            AttestationObject {
                format: "unsupported-format".into(),
                att_statement: Some(Vec::new()),
                ..AttestationObject::default()
            },
        ),
    ];
    for (name, mut att) in cases {
        let err = att.verify_attestation(b"hash").expect_err(name);
        assert_eq!(err.to_string(), "Invalid attestation format", "{name}");
    }
}

#[test]
fn test_attestation_object_verify_algorithm_mismatch() {
    let pcc = unpack_creation(RESPONSES[0]);
    let mut att = pcc.response.attestation_object.clone();
    let err = att
        .verify(
            "localhost",
            &client_data_hash(&pcc),
            false,
            false,
            &params(&[-257]),
        )
        .expect_err("RS256 only");
    assert_eq!(err.to_string(), "Invalid attestation format");
}
