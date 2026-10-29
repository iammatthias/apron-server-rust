//! webauthncose/webauthncose_test.go and webauthncose/signature_test.go.
//! Not ported: TestOKPDisplayPublicKey (`DisplayPublicKey`),
//! TestHasherFromCOSEAlg (`HasherFromCOSEAlg` is internal to the port),
//! TestUnsupportedKeyMethods (the port's key enum cannot hold a bare
//! `PublicKeyData`), TestFIDOPublicKey (FIDO U2F keys), the
//! ShouldHandleNilKey case of TestRSAExponent (no nil key in Rust), and
//! the `ToECDSA`, `TPMCurveID` and `DisplayPublicKey` checks of
//! TestParsePublicKey.

use super::*;
use apron::webauthn::protocol::webauthncose::{
    parse_public_key, parse_rsa_public_key_data_exponent, verify_signature, Ec2PublicKeyData,
    OkpPublicKeyData, PublicKey, PublicKeyData, RsaPublicKeyData,
};
use rust_stdlib_crypto::{ecdsa, ed25519, elliptic};
use rust_stdlib_derive::Deserialize;

const ALG_EDDSA: i64 = -8;
const ALG_ES256: i64 = -7;
const ALG_RS256: i64 = -257;

fn okp_key(algorithm: i64, x: Vec<u8>) -> OkpPublicKeyData {
    OkpPublicKeyData {
        public_key_data: PublicKeyData {
            key_type: 1,
            algorithm,
        },
        curve: 6,
        x_coord: x,
    }
}

#[test]
fn test_okp_signature_verification() {
    let (public, private) = ed25519::generate_key().expect("generate");
    let data = b"Sample data to sign";
    let valid_sig = ed25519::sign(&private, data).expect("sign");
    let key = okp_key(ALG_EDDSA, public.0);
    assert_eq!(key.verify(data, &valid_sig), Ok(true));
    assert_eq!(key.verify(data, b"invalid"), Ok(false));
}

#[test]
fn test_okp_verify_rejects_unsupported_algorithm() {
    let (public, private) = ed25519::generate_key().expect("generate");
    let data = b"Sample data to sign";
    let valid_sig = ed25519::sign(&private, data).expect("sign");
    let key = okp_key(ALG_RS256, public.0);
    let err = key.verify(data, &valid_sig).expect_err(
        "a key declaring an algorithm this library does not verify OKP keys with must not verify",
    );
    assert_eq!(err.to_string(), "OKP key has unsupported algorithm RS256");
}

#[test]
fn test_p256_signature_verification() {
    let key = PublicKey::Ec2(Ec2PublicKeyData {
        public_key_data: PublicKeyData {
            key_type: 2,
            algorithm: ALG_ES256,
        },
        curve: 1,
        x_coord: hex("f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316"),
        y_coord: hex("c24970ad7811ccd9da7f1b88f202bebac770663ef58ba68346186dd778200dd4"),
    });
    let valid_sig = hex("3045022053584980793ee4ec01d583f303604c4f85a7e87df3fe9551962c5ab69a5ce27b022100c801fd6186ca4681e87fbbb97c5cb659f039473995a75a9a9dffea2708d6f8fb");
    assert_eq!(verify_signature(&key, b"webauthnFTW", &valid_sig), Ok(true));
    assert_eq!(
        verify_signature(&key, b"webauthnFTL", &valid_sig),
        Ok(false)
    );
}

#[test]
fn test_rsa_exponent() {
    let cases: [(&str, &[u8], Result<i64, &str>); 6] = [
        ("ShouldHandle3ByteExponent", &[0x01, 0x00, 0x01], Ok(65537)),
        (
            "ShouldHandle3ByteExponentAlt",
            &[0x01, 0x00, 0x02],
            Ok(65538),
        ),
        (
            "ShouldHandle3ByteExponentLarge",
            &[0xff, 0xff, 0xff],
            Ok(16777215),
        ),
        (
            "ShouldHandle4ByteExponent",
            &[0x01, 0x00, 0x02, 0xff],
            Ok(16777983),
        ),
        (
            "ShouldHandleZeroLength",
            &[],
            Err("invalid exponent length"),
        ),
        (
            "ShouldHandleNilExponent",
            &[],
            Err("invalid exponent length"),
        ),
    ];
    for (name, exponent, want) in cases {
        let key = RsaPublicKeyData {
            exponent: exponent.to_vec(),
            ..RsaPublicKeyData::default()
        };
        assert_eq!(
            parse_rsa_public_key_data_exponent(&key).map_err(|err| err.to_string()),
            want.map_err(str::to_string),
            "{name}"
        );
    }
}

#[derive(Debug, Default, Deserialize)]
struct ParsePublicKeyVector {
    #[json("name")]
    name: String,
    #[json("attestation_object")]
    attestation_object: String,
    #[json("client_data_json")]
    client_data_json: String,
    #[json("authenticator_data")]
    authenticator_data: String,
    #[json("signature")]
    signature: String,
    #[json("key_kind")]
    key_kind: String,
    #[json("kty")]
    kty: i64,
    #[json("alg")]
    alg: i64,
    #[json("crv")]
    crv: i64,
    #[json("x")]
    x: String,
    #[json("y")]
    y: String,
    #[json("n")]
    n: String,
    #[json("e")]
    e: String,
}

impl ParsePublicKeyVector {
    /// The key Go's table expects, as the extraction read it from the Go
    /// struct literal.
    fn expected(&self) -> PublicKey {
        let public_key_data = PublicKeyData {
            key_type: self.kty,
            algorithm: self.alg,
        };
        match self.key_kind.as_str() {
            "EC2PublicKeyData" => PublicKey::Ec2(Ec2PublicKeyData {
                public_key_data,
                curve: self.crv,
                x_coord: hex(&self.x),
                y_coord: hex(&self.y),
            }),
            "RSAPublicKeyData" => PublicKey::Rsa(RsaPublicKeyData {
                public_key_data,
                modulus: hex(&self.n),
                exponent: hex(&self.e),
            }),
            "OKPPublicKeyData" => PublicKey::Okp(OkpPublicKeyData {
                public_key_data,
                curve: self.crv,
                x_coord: hex(&self.x),
            }),
            other => panic!("unexpected key kind {other}"),
        }
    }
}

fn parse_public_key_vectors() -> Vec<ParsePublicKeyVector> {
    rust_stdlib::encoding::json::unmarshal(vector!("parse_public_key_vectors.json").as_bytes())
        .expect("vectors")
}

/// Go's `MustConstructSignedData`.
fn signed_data(client_data_json: &str, authenticator_data: &str) -> Vec<u8> {
    let mut data = hex(authenticator_data);
    data.extend_from_slice(&sha256::sum256(&hex(client_data_json)));
    data
}

/// The W3C test vectors, including the tpm, android-key and apple ones:
/// only the credential public key is taken from their attestation
/// objects, so the attestation format never runs.
#[test]
fn test_parse_public_key() {
    let vectors = parse_public_key_vectors();
    assert_eq!(vectors.len(), 13);
    for tc in vectors {
        let key_bytes = cose_key_from_attestation_object(&hex(&tc.attestation_object));
        let result =
            parse_public_key(&key_bytes).unwrap_or_else(|err| panic!("{}: {err}", tc.name));
        let data = signed_data(&tc.client_data_json, &tc.authenticator_data);
        assert_eq!(
            verify_signature(&result, &data, &hex(&tc.signature)),
            Ok(true),
            "{}",
            tc.name
        );
        assert_eq!(result, tc.expected(), "{}", tc.name);
    }
}

/// Go's `mustMarshalCOSEKey`.
fn cose_key(kty: i64, alg: i64, extra: Vec<(i64, Value)>) -> Vec<u8> {
    let int = |n: i64| {
        if n >= 0 {
            Value::Unsigned(n as u64)
        } else {
            Value::Negative((-1 - n) as u64)
        }
    };
    let mut members = vec![(int(1), int(kty)), (int(3), int(alg))];
    members.extend(extra.into_iter().map(|(k, v)| (int(k), v)));
    cbor::marshal(&Value::Map(members))
}

/// Go generates fresh key material for the accept cases; the valid
/// Ed25519 and P-256 public keys of the W3C vectors stand in for it.
#[test]
fn test_parse_public_key_validation() {
    let vectors = parse_public_key_vectors();
    let okp_pub = hex(&vectors[9].x);
    let ec2_x = hex(&vectors[0].x);
    let ec2_y = hex(&vectors[0].y);
    let int = |n: i64| {
        if n >= 0 {
            Value::Unsigned(n as u64)
        } else {
            Value::Negative((-1 - n) as u64)
        }
    };
    let bytes = |b: &[u8]| Value::Bytes(b.to_vec());
    let cases = [
        (
            "ShouldAcceptValidOKPKey",
            cose_key(1, ALG_EDDSA, vec![(-1, int(6)), (-2, bytes(&okp_pub))]),
            None,
        ),
        (
            "ShouldAcceptValidOKPKeyWithFullySpecifiedAlgorithm",
            cose_key(1, -19, vec![(-1, int(6)), (-2, bytes(&okp_pub))]),
            None,
        ),
        (
            "ShouldAcceptValidEC2Key",
            cose_key(
                2,
                ALG_ES256,
                vec![(-1, int(1)), (-2, bytes(&ec2_x)), (-3, bytes(&ec2_y))],
            ),
            None,
        ),
        (
            "ShouldAcceptValidRSAKey",
            cose_key(
                3,
                ALG_RS256,
                vec![(-1, bytes(&[0xff])), (-2, bytes(&[0x01, 0x00, 0x01]))],
            ),
            None,
        ),
        (
            "ShouldRejectOKPWithInvalidXCoordLength",
            cose_key(1, ALG_EDDSA, vec![(-1, int(6)), (-2, bytes(&[0; 16]))]),
            Some("OKP key x coordinate has invalid length 16, expected 32"),
        ),
        (
            "ShouldRejectOKPWithUnsupportedAlgorithm",
            cose_key(1, ALG_RS256, vec![(-1, int(6)), (-2, bytes(&okp_pub))]),
            Some("OKP key has unsupported algorithm RS256"),
        ),
        (
            "ShouldRejectOKPWithUnregisteredAlgorithm",
            cose_key(1, 999, vec![(-1, int(6)), (-2, bytes(&okp_pub))]),
            Some("OKP key has unsupported algorithm 999"),
        ),
        (
            "ShouldRejectEC2WithUnsupportedAlgorithm",
            cose_key(
                2,
                999,
                vec![(-1, int(1)), (-2, bytes(&[0; 32])), (-3, bytes(&[0; 32]))],
            ),
            Some("Unsupported EC2 algorithm"),
        ),
        (
            "ShouldRejectEC2WithInvalidCoordLength",
            cose_key(
                2,
                ALG_ES256,
                vec![(-1, int(1)), (-2, bytes(&[0; 48])), (-3, bytes(&[0; 48]))],
            ),
            Some("EC2 key x or y coordinate has invalid length"),
        ),
        (
            "ShouldRejectEC2WithOffCurvePoint",
            cose_key(
                2,
                ALG_ES256,
                vec![(-1, int(1)), (-2, bytes(&[0; 32])), (-3, bytes(&[0; 32]))],
            ),
            Some("EC2 key point is not on curve"),
        ),
        (
            "ShouldRejectRSAWithEmptyModulus",
            cose_key(
                3,
                ALG_RS256,
                vec![(-1, bytes(&[])), (-2, bytes(&[0x01, 0x00, 0x01]))],
            ),
            Some("RSA key contains zero or empty modulus"),
        ),
        (
            "ShouldRejectRSAWithEmptyExponent",
            cose_key(3, ALG_RS256, vec![(-1, bytes(&[0xff])), (-2, bytes(&[]))]),
            Some("RSA key contains invalid exponent: invalid exponent length"),
        ),
    ];
    for (name, input, want) in cases {
        match (parse_public_key(&input), want) {
            (Ok(key), None) => assert_eq!(
                key.algorithm(),
                cbor_alg(&input),
                "{name}: the parsed key keeps its algorithm"
            ),
            (Err(err), Some(want)) => assert_eq!(err.to_string(), want, "{name}"),
            (result, want) => panic!("{name}: got {result:?}, want {want:?}"),
        }
    }
}

fn cbor_alg(key: &[u8]) -> i64 {
    let Value::Map(members) = cbor::unmarshal(key).expect("key") else {
        panic!("key is not a map");
    };
    members
        .iter()
        .find(|(k, _)| *k == Value::Unsigned(3))
        .and_then(|(_, v)| match *v {
            Value::Negative(n) => Some(-1 - n as i64),
            Value::Unsigned(n) => Some(n as i64),
            _ => None,
        })
        .expect("alg")
}

/// signature_test.go TestEC2PublicKeyDataVerifyRequiresCanonicalDER.
#[test]
fn test_ec2_public_key_data_verify_requires_canonical_der() {
    let private = ecdsa::generate_key(elliptic::p256()).expect("generate");
    let key = Ec2PublicKeyData {
        public_key_data: PublicKeyData {
            key_type: 2,
            algorithm: ALG_ES256,
        },
        curve: 1,
        x_coord: private.public_key.x.fill_bytes(32).expect("x"),
        y_coord: private.public_key.y.fill_bytes(32).expect("y"),
    };
    let data = b"data to sign";
    let der = ecdsa::sign_asn1(&private, &sha256::sum256(data)).expect("sign");
    assert_eq!(key.verify(data, &der), Ok(true));

    // The two INTEGERs of the signature, as `asn1.Marshal` encodes them.
    assert_eq!(der[0], 0x30);
    assert_eq!(usize::from(der[1]), der.len() - 2);
    let r_len = usize::from(der[3]);
    let minimal_r = der[2..4 + r_len].to_vec();
    let minimal_s = der[4 + r_len..].to_vec();
    let sequence = |elements: &[&[u8]]| {
        let content = elements.concat();
        assert!(content.len() < 0x80);
        [&[0x30, content.len() as u8][..], &content].concat()
    };
    let padded = |minimal: &[u8]| {
        let content = [&[0x00][..], &minimal[2..]].concat();
        [&[0x02, content.len() as u8][..], &content].concat()
    };
    let cases = [
        (
            "ShouldRejectTrailingDataAfterSignature",
            [&der[..], &[0xde, 0xad, 0xbe, 0xef]].concat(),
        ),
        (
            "ShouldRejectTrailingElementWithinSequence",
            sequence(&[&minimal_r, &minimal_s, &[0x02, 0x01, 0x7f]]),
        ),
        (
            "ShouldRejectBERPaddedR",
            sequence(&[&padded(&minimal_r), &minimal_s]),
        ),
        (
            "ShouldRejectBERPaddedS",
            sequence(&[&minimal_r, &padded(&minimal_s)]),
        ),
    ];
    for (name, have) in cases {
        assert_ne!(der, have, "{name}");
        let err = key.verify(data, &have).expect_err(name);
        assert_eq!(
            err.to_string(),
            "Signature invalid or not provided",
            "{name}"
        );
    }
}
