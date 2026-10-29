//! go-webauthn v0.18.2's own tests, for the subset src/webauthn ports. Each
//! module holds the cases of one Go test file, under the Go test names, with
//! the Go vectors and expected errors. Large vectors live in
//! tests/data/webauthn/, copied verbatim from the Go test files.
//!
//! A Go case that exercises something the port leaves out (attestation
//! formats other than `none` and packed self attestation, the metadata
//! service, AppID, opaque origins, `http.Request` parsing, msgp, ES256K,
//! ML-DSA) is not ported. A case whose vector uses an attestation format the
//! port rejects asserts the rejection instead.

use apron::cbor::{self, Value};
use apron::webauthn::protocol::{Error, ErrorType};
use rust_stdlib::encoding::base64::{STANDARD, URL_SAFE_NO_PAD};
use rust_stdlib::encoding::hex as hexenc;

macro_rules! vector {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/webauthn/",
            $name
        ))
    };
}

fn hex(s: &str) -> Vec<u8> {
    hexenc::decode(s).expect("hex vector")
}

fn b64url(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("base64url vector")
}

fn b64std(s: &str) -> Vec<u8> {
    STANDARD.decode(s).expect("base64 vector")
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}

/// Go's `AssertIsProtocolError`.
#[track_caller]
fn assert_protocol_error(err: &Error, kind: ErrorType, details: &str, info: &str) {
    assert_eq!(
        (err.kind, err.details.as_str(), err.info.as_str()),
        (kind, details, info)
    );
}

/// The COSE key of an attestation object, as Go's
/// `MustExtractCBORKeyFromAttestationObject` finds it.
fn cose_key_from_attestation_object(attestation_object: &[u8]) -> Vec<u8> {
    let Value::Map(members) = cbor::unmarshal(attestation_object).expect("attestation object")
    else {
        panic!("attestation object is not a map");
    };
    let auth_data = members
        .into_iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(k), Value::Bytes(v)) if k == "authData" => Some(v),
            _ => None,
        })
        .expect("authData");
    let id_len = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
    auth_data[55 + id_len..].to_vec()
}

mod client;

mod authenticator;

mod base64;

mod extensions_outputs;

use apron::webauthn::protocol::webauthncose::CoseAlgorithmIdentifier;
use apron::webauthn::protocol::{
    parse_credential_creation_response_bytes, parse_credential_request_response_bytes,
    CredentialParameter, CredentialType, ParsedCredentialAssertionData,
    ParsedCredentialCreationData, TopOriginVerificationMode,
};
use rust_stdlib_crypto::sha256;

fn params(algorithms: &[i64]) -> Vec<CredentialParameter> {
    algorithms
        .iter()
        .map(|&alg| CredentialParameter {
            kind: CredentialType::PUBLIC_KEY,
            algorithm: CoseAlgorithmIdentifier(alg),
        })
        .collect()
}

/// Go's `attestationTestUnpackResponse`.
fn unpack_creation(response: &str) -> ParsedCredentialCreationData {
    parse_credential_creation_response_bytes(response.as_bytes()).expect("parse registration")
}

fn client_data_hash(parsed: &ParsedCredentialCreationData) -> [u8; 32] {
    sha256::sum256(&parsed.raw.attestation_response.client_data_json.0)
}

/// A registration response body, as Go's test fixtures marshal one.
fn creation_body(id: &[u8], client_data_json: &[u8], attestation_object: &[u8]) -> String {
    let id = URL_SAFE_NO_PAD.encode(id);
    format!(
        r#"{{"id":"{id}","rawId":"{id}","type":"public-key","response":{{"attestationObject":"{}","clientDataJSON":"{}"}}}}"#,
        URL_SAFE_NO_PAD.encode(attestation_object),
        URL_SAFE_NO_PAD.encode(client_data_json)
    )
}

/// The members of a COSE key in a fixed order, for comparing keys as Go
/// compares the `map[any]any` it decodes them to.
fn cose_members(key: &[u8]) -> Vec<(String, Value)> {
    let Value::Map(members) = cbor::unmarshal(key).expect("COSE key") else {
        panic!("COSE key is not a map");
    };
    let mut members: Vec<(String, Value)> = members
        .into_iter()
        .map(|(k, v)| (format!("{k:?}"), v))
        .collect();
    members.sort_by(|a, b| a.0.cmp(&b.0));
    members
}

mod attestation;

mod attestation_packed;

mod credential;

mod assertion;

mod webauthncose;

mod webauthn;
