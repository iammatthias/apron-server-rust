//! attestation_packed_test.go. Not ported, as the port rejects packed
//! attestation with an x5c chain: TestPackedFormat_BasicAttestationErrors,
//! TestPackedFormat_BasicAttestationSignatureAndTimeErrors and
//! TestPackedFormat_BasicAttestationCertRequirements.

use super::*;
use apron::webauthn::protocol::AttestationObject;

const ES256: &str = vector!("packed_es256.json");
const ES512: &str = vector!("packed_es512.json");
const SOLO2: &str = vector!("packed_solo2.json");
const SELF_ES256: &str = vector!("attestation_response_0.json");

/// Go calls the private `attestationFormatValidationHandlerPacked`; the
/// port's entry point is `VerifyAttestation`, which dispatches to it.
#[test]
fn test_verify_packed_format() {
    let x5c_unsupported = Err((
        ErrorType::InvalidAttestation,
        "Basic attestation with an x5c certificate chain is not supported",
    ));
    let cases = [
        // Go verifies the x5c chain of this and the Solo2 vector as
        // basic_full; the port rejects packed with x5c.
        ("ShouldSuccessfullyVerifyES256", ES256, x5c_unsupported),
        (
            "ShouldSuccessfullyVerifyES512SelfAttestation",
            ES512,
            Ok("basic_surrogate"),
        ),
        ("ShouldSuccessfullyVerifySolo2", SOLO2, x5c_unsupported),
    ];
    for (name, response, want) in cases {
        let pcc = unpack_creation(response);
        let mut att = pcc.response.attestation_object.clone();
        let result = att.verify_attestation(&client_data_hash(&pcc));
        match want {
            Ok(kind) => {
                assert_eq!(result, Ok(()), "{name}");
                assert_eq!(att.kind, kind, "{name}");
            }
            Err((kind, details)) => {
                let err = result.expect_err(name);
                assert_eq!((err.kind, err.details.as_str()), (kind, details), "{name}");
            }
        }
    }
}

fn packed(statement: Vec<(&str, Value)>) -> AttestationObject {
    AttestationObject {
        format: "packed".into(),
        att_statement: Some(
            statement
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        ),
        ..AttestationObject::default()
    }
}

const ES256_ALG: Value = Value::Negative(6);

#[test]
fn test_packed_format_handler_errors() {
    let cases = [
        ("ShouldFailMissingAlg", vec![], "Error retrieving alg value"),
        (
            "ShouldFailAlgWrongType",
            vec![("alg", Value::Text("not-int".into()))],
            "Error retrieving alg value",
        ),
        (
            "ShouldFailMissingSig",
            vec![("alg", ES256_ALG)],
            "Error retrieving sig value",
        ),
        (
            "ShouldFailSigWrongType",
            vec![("alg", ES256_ALG), ("sig", Value::Text("not-bytes".into()))],
            "Error retrieving sig value",
        ),
        (
            "ShouldReturnECDAANotImplemented",
            vec![
                ("alg", ES256_ALG),
                ("sig", Value::Bytes(b"sig".to_vec())),
                ("ecdaaKeyId", Value::Bytes(b"keyid".to_vec())),
            ],
            "This field is not yet supported by the WebAuthn spec",
        ),
    ];
    for (name, statement, want) in cases {
        let err = packed(statement)
            .verify_attestation(b"hash")
            .expect_err(name);
        assert_eq!(err.to_string(), want, "{name}");
    }
}

/// Go calls the private `handleSelfAttestation(alg, pub, "auth", "hash",
/// "sig")`; here the same inputs reach it through `VerifyAttestation`.
#[test]
fn test_packed_format_self_attestation_errors() {
    let valid_pub_key = unpack_creation(ES512)
        .response
        .attestation_object
        .auth_data
        .att_data
        .credential_public_key;
    let cases = [
        (
            "ShouldFailInvalidPublicKey",
            b"not-cbor".to_vec(),
            "Error parsing the public key: Unsupported Public Key Type",
        ),
        (
            "ShouldFailAlgorithmMismatch",
            valid_pub_key,
            "Public key algorithm does not equal att statement algorithm",
        ),
    ];
    for (name, public_key, want) in cases {
        let mut att = packed(vec![
            ("alg", ES256_ALG),
            ("sig", Value::Bytes(b"sig".to_vec())),
        ]);
        att.raw_auth_data = b"auth".to_vec();
        att.auth_data.att_data.credential_public_key = public_key;
        let err = att.verify_attestation(b"hash").expect_err(name);
        assert_eq!(err.to_string(), want, "{name}");
    }
}

/// Go calls the private `verifyKeyAlgorithm(keyAlg, attAlg)`; here an
/// ES256 self attestation carries the statement algorithm.
#[test]
fn test_verify_key_algorithm() {
    let pcc = unpack_creation(SELF_ES256);
    let hash = client_data_hash(&pcc);
    let cases = [
        ("ShouldSucceedWhenMatch", Value::Negative(6), None),
        (
            "ShouldFailWhenMismatch",
            Value::Negative(256),
            Some("Public key algorithm does not equal att statement algorithm"),
        ),
    ];
    for (name, alg, want) in cases {
        let mut att = pcc.response.attestation_object.clone();
        for (key, value) in att.att_statement.as_mut().expect("statement") {
            if key == "alg" {
                *value = alg.clone();
            }
        }
        let result = att.verify_attestation(&hash).map_err(|err| err.to_string());
        assert_eq!(
            result,
            want.map_or(Ok(()), |w| Err(w.to_string())),
            "{name}"
        );
    }
}
