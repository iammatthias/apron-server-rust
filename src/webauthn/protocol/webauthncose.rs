//! go-webauthn's `webauthncose` package: COSE public keys (RFC 9053) and
//! the signatures they verify.
//!
//! Supported: EC2 keys on P-256, P-384 and P-521 (ES256, ES384, ES512 and the
//! fully specified ESP variants), OKP Ed25519 keys (EdDSA, Ed25519) and RSA
//! keys (RS1, RS256, RS384, RS512, PS256, PS384, PS512). Go also parses
//! secp256k1 (ES256K) and ML-DSA (AKP) keys; aprond never requests those
//! algorithms, so a registration cannot store one, and here they are
//! unsupported keys.

use std::fmt;

use rust_stdlib::encoding::json::{jsontext, v2};
use rust_stdlib_crypto::bigint::Int;
use rust_stdlib_crypto::{ecdsa, ed25519, elliptic, rsa, sha1, sha256, sha512, Hash};

use crate::cbor::{self, Field, FieldKey, FieldKind, FieldValue};

/// Go's `COSEAlgorithmIdentifier`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CoseAlgorithmIdentifier(pub i64);

impl CoseAlgorithmIdentifier {
    pub const ES256: Self = Self(-7);
    pub const EDDSA: Self = Self(-8);
    pub const ESP256: Self = Self(-9);
    pub const ED25519: Self = Self(-19);
    pub const ES384: Self = Self(-35);
    pub const ES512: Self = Self(-36);
    pub const PS256: Self = Self(-37);
    pub const PS384: Self = Self(-38);
    pub const PS512: Self = Self(-39);
    pub const ES256K: Self = Self(-47);
    pub const ESP384: Self = Self(-51);
    pub const ESP512: Self = Self(-52);
    pub const RS256: Self = Self(-257);
    pub const RS384: Self = Self(-258);
    pub const RS512: Self = Self(-259);
    pub const RS1: Self = Self(-65535);

    fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::ES256 => "ES256",
            Self::EDDSA => "EdDSA",
            Self::ESP256 => "ESP256",
            Self::ED25519 => "Ed25519",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
            Self::ES256K => "ES256K",
            Self::ESP384 => "ESP384",
            Self::ESP512 => "ESP512",
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::RS1 => "RS1",
            _ => return None,
        })
    }

    /// The hash of Go's `COSESignatureAlgorithmDetails`.
    fn hash(self) -> Option<Hash> {
        Some(match self {
            Self::RS1 => Hash::Sha1,
            Self::RS256 | Self::PS256 | Self::ES256 | Self::ESP256 | Self::ES256K => Hash::Sha256,
            Self::RS384 | Self::PS384 | Self::ES384 | Self::ESP384 => Hash::Sha384,
            Self::RS512 | Self::PS512 | Self::ES512 | Self::ESP512 => Hash::Sha512,
            Self::EDDSA | Self::ED25519 => Hash::Sha512,
            _ => return None,
        })
    }

    /// Go's `coseAlgorithmCurves`: the curve an algorithm fixes, and whether
    /// the key must name it.
    fn curve(self) -> Option<(CoseEllipticCurve, bool)> {
        Some(match self {
            Self::ES256 => (CoseEllipticCurve::P256, true),
            Self::ES384 => (CoseEllipticCurve::P384, true),
            Self::ES512 => (CoseEllipticCurve::P521, true),
            Self::EDDSA => (CoseEllipticCurve::ED25519, true),
            Self::ESP256 => (CoseEllipticCurve::P256, false),
            Self::ESP384 => (CoseEllipticCurve::P384, false),
            Self::ESP512 => (CoseEllipticCurve::P521, false),
            Self::ED25519 => (CoseEllipticCurve::ED25519, false),
            Self::ES256K => (CoseEllipticCurve::SECP256K1, false),
            _ => return None,
        })
    }
}

impl fmt::Display for CoseAlgorithmIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "{}", self.0),
        }
    }
}

impl v2::MarshalTo for CoseAlgorithmIdentifier {
    fn type_info() -> v2::TypeInfo {
        v2::TypeInfo::of::<CoseAlgorithmIdentifier>(
            "webauthncose.COSEAlgorithmIdentifier",
            v2::TypeKind::Int,
        )
    }

    fn marshal_default(&self, enc: &mut jsontext::Encoder<'_>) -> Result<(), jsontext::Error> {
        self.0.marshal_default(enc)
    }

    fn is_zero_value(&self) -> bool {
        self.0 == 0
    }
}

/// Go's `COSEEllipticCurve`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoseEllipticCurve(pub i64);

impl CoseEllipticCurve {
    pub const RESERVED: Self = Self(0);
    pub const P256: Self = Self(1);
    pub const P384: Self = Self(2);
    pub const P521: Self = Self(3);
    pub const X25519: Self = Self(4);
    pub const X448: Self = Self(5);
    pub const ED25519: Self = Self(6);
    pub const ED448: Self = Self(7);
    pub const SECP256K1: Self = Self(8);
}

impl fmt::Display for CoseEllipticCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
            Self::X25519 => "X25519",
            Self::X448 => "X448",
            Self::ED25519 => "Ed25519",
            Self::ED448 => "Ed448",
            Self::SECP256K1 => "secp256k1",
            Self(n) => return write!(f, "{n}"),
        };
        f.write_str(name)
    }
}

/// Go's `COSEKeyType` values.
pub const KEY_TYPE_OCTET: i64 = 1;
pub const KEY_TYPE_ELLIPTIC: i64 = 2;
pub const KEY_TYPE_RSA: i64 = 3;

/// Go's `webauthncose.Error`, or a CBOR error `ParsePublicKey` returns as
/// is. Its `Display` is Go's `Error()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// Go's `Type`; empty for a CBOR error.
    pub kind: &'static str,
    pub details: String,
}

impl Error {
    /// Go's `ErrUnsupportedKey`.
    pub fn unsupported_key() -> Error {
        Error {
            kind: "invalid_key_type",
            details: "Unsupported Public Key Type".into(),
        }
    }

    /// Go's `ErrUnsupportedAlgorithm`.
    pub fn unsupported_algorithm() -> Error {
        Error {
            kind: "unsupported_key_algorithm",
            details: "Unsupported public key algorithm".into(),
        }
    }

    /// Go's `ErrSigNotProvidedOrInvalid`.
    pub fn sig_not_provided_or_invalid() -> Error {
        Error {
            kind: "signature_not_provided_or_invalid",
            details: "Signature invalid or not provided".into(),
        }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Error {
        self.details = details.into();
        self
    }
}

impl From<cbor::Error> for Error {
    fn from(err: cbor::Error) -> Error {
        Error {
            kind: "",
            details: err.to_string(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.details)
    }
}

impl std::error::Error for Error {}

/// Go's `PublicKeyData`: the members every COSE key has.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicKeyData {
    pub key_type: i64,
    pub algorithm: i64,
}

/// Go's `EC2PublicKeyData`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ec2PublicKeyData {
    pub public_key_data: PublicKeyData,
    pub curve: i64,
    pub x_coord: Vec<u8>,
    pub y_coord: Vec<u8>,
}

/// Go's `RSAPublicKeyData`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RsaPublicKeyData {
    pub public_key_data: PublicKeyData,
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
}

/// Go's `OKPPublicKeyData`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OkpPublicKeyData {
    pub public_key_data: PublicKeyData,
    pub curve: i64,
    pub x_coord: Vec<u8>,
}

/// The key `ParsePublicKey` returns as an `any`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Okp(OkpPublicKeyData),
    Ec2(Ec2PublicKeyData),
    Rsa(RsaPublicKeyData),
}

impl PublicKey {
    /// The key's algorithm (Go reads it from each key type's embedded
    /// `PublicKeyData`).
    pub fn algorithm(&self) -> i64 {
        match self {
            PublicKey::Okp(k) => k.public_key_data.algorithm,
            PublicKey::Ec2(k) => k.public_key_data.algorithm,
            PublicKey::Rsa(k) => k.public_key_data.algorithm,
        }
    }
}

const fn int_field(key: i64, kind: FieldKind) -> Field {
    Field {
        key: FieldKey::Int(key),
        kind,
    }
}

const PUBLIC_KEY_DATA: &[Field] = &[
    int_field(1, FieldKind::Int64),
    int_field(3, FieldKind::Int64),
];
const EC2_FIELDS: &[Field] = &[
    int_field(1, FieldKind::Int64),
    int_field(3, FieldKind::Int64),
    int_field(-1, FieldKind::Int64),
    int_field(-2, FieldKind::ByteSlice),
    int_field(-3, FieldKind::ByteSlice),
];
const RSA_FIELDS: &[Field] = &[
    int_field(1, FieldKind::Int64),
    int_field(3, FieldKind::Int64),
    int_field(-1, FieldKind::ByteSlice),
    int_field(-2, FieldKind::ByteSlice),
];
const OKP_FIELDS: &[Field] = &[
    int_field(1, FieldKind::Int64),
    int_field(3, FieldKind::Int64),
    int_field(-1, FieldKind::Int64),
    int_field(-2, FieldKind::ByteSlice),
];

/// Decodes `PublicKeyData` from a COSE key, as `webauthncbor.Unmarshal(key,
/// &pk)` does.
pub fn parse_public_key_data(key_bytes: &[u8]) -> Result<PublicKeyData, cbor::Error> {
    let item = cbor::parse(key_bytes)?;
    let fields = cbor::decode_struct(&item, "webauthncose.PublicKeyData", PUBLIC_KEY_DATA)?;
    Ok(PublicKeyData {
        key_type: fields[0].int64(),
        algorithm: fields[1].int64(),
    })
}

fn decode_key<'a>(
    key_bytes: &'a [u8],
    go_type: &'static str,
    fields: &[Field],
) -> Result<Vec<FieldValue<'a>>, Error> {
    let item = cbor::parse(key_bytes)?;
    Ok(cbor::decode_struct(&item, go_type, fields)?)
}

/// Go's `ParsePublicKey`.
pub fn parse_public_key(key_bytes: &[u8]) -> Result<PublicKey, Error> {
    let pk = parse_public_key_data(key_bytes).map_err(|_| Error::unsupported_key())?;
    match pk.key_type {
        KEY_TYPE_OCTET => {
            let f = decode_key(key_bytes, "webauthncose.OKPPublicKeyData", OKP_FIELDS)?;
            let key = OkpPublicKeyData {
                public_key_data: pk,
                curve: f[2].int64(),
                x_coord: f[3].bytes(),
            };
            validate_okp_public_key(&key)?;
            Ok(PublicKey::Okp(key))
        }
        KEY_TYPE_ELLIPTIC => {
            let f = decode_key(key_bytes, "webauthncose.EC2PublicKeyData", EC2_FIELDS)?;
            let key = Ec2PublicKeyData {
                public_key_data: pk,
                curve: f[2].int64(),
                x_coord: f[3].bytes(),
                y_coord: f[4].bytes(),
            };
            validate_ec2_public_key(&key)?;
            Ok(PublicKey::Ec2(key))
        }
        KEY_TYPE_RSA => {
            let f = decode_key(key_bytes, "webauthncose.RSAPublicKeyData", RSA_FIELDS)?;
            let key = RsaPublicKeyData {
                public_key_data: pk,
                modulus: f[2].bytes(),
                exponent: f[3].bytes(),
            };
            validate_rsa_public_key(&key)?;
            Ok(PublicKey::Rsa(key))
        }
        _ => Err(Error::unsupported_key()),
    }
}

fn validate_key_curve(key_type: &str, algorithm: i64, curve: i64) -> Result<(), Error> {
    let alg = CoseAlgorithmIdentifier(algorithm);
    let Some((expected, required)) = alg.curve() else {
        return Ok(());
    };
    let crv = CoseEllipticCurve(curve);
    if crv == expected || (crv == CoseEllipticCurve::RESERVED && !required) {
        return Ok(());
    }
    let specified = if crv == CoseEllipticCurve::RESERVED {
        "no curve".to_owned()
    } else {
        format!("curve {crv}")
    };
    Err(Error::unsupported_key().with_details(format!(
        "{key_type} key with algorithm {alg} must specify curve {expected} but it specified {specified}"
    )))
}

fn validate_okp_public_key(k: &OkpPublicKeyData) -> Result<(), Error> {
    let alg = CoseAlgorithmIdentifier(k.public_key_data.algorithm);
    if alg != CoseAlgorithmIdentifier::EDDSA && alg != CoseAlgorithmIdentifier::ED25519 {
        return Err(Error::unsupported_algorithm()
            .with_details(format!("OKP key has unsupported algorithm {alg}")));
    }
    validate_key_curve("OKP", k.public_key_data.algorithm, k.curve)?;
    if k.x_coord.len() != ed25519::PUBLIC_KEY_SIZE {
        return Err(Error::unsupported_key().with_details(format!(
            "OKP key x coordinate has invalid length {}, expected {}",
            k.x_coord.len(),
            ed25519::PUBLIC_KEY_SIZE
        )));
    }
    Ok(())
}

/// Go's `ec2AlgCurve`, for the curves rust-stdlib implements.
fn ec2_alg_curve(algorithm: i64) -> Option<(std::sync::Arc<dyn elliptic::Curve>, usize)> {
    match CoseAlgorithmIdentifier(algorithm) {
        CoseAlgorithmIdentifier::ES512 | CoseAlgorithmIdentifier::ESP512 => {
            Some((elliptic::p521(), 66))
        }
        CoseAlgorithmIdentifier::ES384 | CoseAlgorithmIdentifier::ESP384 => {
            Some((elliptic::p384(), 48))
        }
        CoseAlgorithmIdentifier::ES256 | CoseAlgorithmIdentifier::ESP256 => {
            Some((elliptic::p256(), 32))
        }
        _ => None,
    }
}

fn validate_ec2_public_key(k: &Ec2PublicKeyData) -> Result<ecdsa::PublicKey, Error> {
    let Some((curve, byte_len)) = ec2_alg_curve(k.public_key_data.algorithm) else {
        return Err(Error::unsupported_algorithm().with_details("Unsupported EC2 algorithm"));
    };
    validate_key_curve("EC2", k.public_key_data.algorithm, k.curve)?;
    if k.x_coord.len() != byte_len || k.y_coord.len() != byte_len {
        return Err(
            Error::unsupported_key().with_details("EC2 key x or y coordinate has invalid length")
        );
    }
    let x = Int::from_be_bytes(&k.x_coord);
    let y = Int::from_be_bytes(&k.y_coord);
    if !curve.is_on_curve(&x, &y) {
        return Err(Error::unsupported_key().with_details("EC2 key point is not on curve"));
    }
    Ok(ecdsa::PublicKey { curve, x, y })
}

/// Go's `validateRSAPublicKey`.
fn validate_rsa_public_key(k: &RsaPublicKeyData) -> Result<rsa::PublicKey, Error> {
    if k.modulus.iter().all(|&b| b == 0) {
        return Err(Error::unsupported_key().with_details("RSA key contains zero or empty modulus"));
    }
    let e = parse_rsa_public_key_data_exponent(k).map_err(|err| {
        Error::unsupported_key().with_details(format!("RSA key contains invalid exponent: {err}"))
    })?;
    Ok(rsa::PublicKey {
        n: Int::from_be_bytes(&k.modulus),
        e,
    })
}

/// Go's `ParseRSAPublicKeyDataExponent`.
pub fn parse_rsa_public_key_data_exponent(k: &RsaPublicKeyData) -> Result<i64, Error> {
    if k.exponent.is_empty() {
        return Err(Error::unsupported_key().with_details("invalid exponent length"));
    }
    let mut exp: i64 = 0;
    for &b in &k.exponent {
        if exp > (i64::MAX >> 8) {
            return Err(Error::unsupported_key());
        }
        exp = (exp << 8) | i64::from(b);
    }
    if exp <= 0 {
        return Err(Error::unsupported_key());
    }
    Ok(exp)
}

fn digest(hash: Hash, data: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha1 => sha1::sum(data).to_vec(),
        Hash::Sha256 => sha256::sum256(data).to_vec(),
        Hash::Sha384 => sha512::sum384(data).to_vec(),
        _ => sha512::sum512(data).to_vec(),
    }
}

/// Splits a DER `ECDSA-Sig-Value` into the contents of its two INTEGERs if
/// `sig` is exactly the DER encoding Go's `asn1.Marshal` would write for
/// them, which go-webauthn checks by marshalling what it parsed.
fn ecdsa_der_integers(sig: &[u8]) -> Option<(&[u8], &[u8])> {
    fn tlv(data: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
        let (&first, rest) = data.split_first()?;
        if first != tag {
            return None;
        }
        let (&len, rest) = rest.split_first()?;
        let (len, rest) = match len {
            0..=0x7f => (usize::from(len), rest),
            0x81 => {
                let (&n, rest) = rest.split_first()?;
                if n < 0x80 {
                    return None;
                }
                (usize::from(n), rest)
            }
            0x82 => {
                let n = usize::from(u16::from_be_bytes([*rest.first()?, *rest.get(1)?]));
                if n < 0x100 {
                    return None;
                }
                (n, &rest[2..])
            }
            _ => return None,
        };
        (rest.len() >= len).then(|| rest.split_at(len))
    }
    fn minimal(int: &[u8]) -> bool {
        match int {
            [] => false,
            [0, next, ..] => next & 0x80 != 0,
            [0xff, next, ..] => next & 0x80 == 0,
            _ => true,
        }
    }
    let (body, rest) = tlv(sig, 0x30)?;
    if !rest.is_empty() {
        return None;
    }
    let (r, body) = tlv(body, 0x02)?;
    let (s, body) = tlv(body, 0x02)?;
    (body.is_empty() && minimal(r) && minimal(s)).then_some((r, s))
}

impl Ec2PublicKeyData {
    /// Go's `EC2PublicKeyData.Verify`.
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        let public_key = validate_ec2_public_key(self)?;
        let alg = CoseAlgorithmIdentifier(self.public_key_data.algorithm);
        let Some(hash) = alg.hash() else {
            return Err(Error::unsupported_algorithm()
                .with_details(format!("EC2 key algorithm {alg} has no registered hash")));
        };
        let (r, s) = ecdsa_der_integers(sig).ok_or_else(Error::sig_not_provided_or_invalid)?;
        // A negative integer is valid DER, and Go's ecdsa.Verify rejects it.
        if r[0] & 0x80 != 0 || s[0] & 0x80 != 0 {
            return Ok(false);
        }
        Ok(ecdsa::verify(
            &public_key,
            &digest(hash, data),
            &Int::from_be_bytes(r),
            &Int::from_be_bytes(s),
        ))
    }
}

impl RsaPublicKeyData {
    /// Go's `RSAPublicKeyData.Verify`. A failed check is an error, as Go's
    /// `rsa.Verify*` report it.
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        let public_key = validate_rsa_public_key(self)?;
        let alg = CoseAlgorithmIdentifier(self.public_key_data.algorithm);
        let hash = alg.hash().ok_or_else(Error::unsupported_algorithm)?;
        let hashed = digest(hash, data);
        let result = match alg {
            CoseAlgorithmIdentifier::PS256
            | CoseAlgorithmIdentifier::PS384
            | CoseAlgorithmIdentifier::PS512 => {
                rsa::verify_pss(&public_key, hash, &hashed, sig, None)
            }
            CoseAlgorithmIdentifier::RS1
            | CoseAlgorithmIdentifier::RS256
            | CoseAlgorithmIdentifier::RS384
            | CoseAlgorithmIdentifier::RS512 => {
                rsa::verify_pkcs1v15(&public_key, Some(hash), &hashed, sig)
            }
            _ => return Err(Error::unsupported_algorithm()),
        };
        result.map(|()| true).map_err(|err| Error {
            kind: "",
            details: err.to_string(),
        })
    }
}

impl OkpPublicKeyData {
    /// Go's `OKPPublicKeyData.Verify`.
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        validate_okp_public_key(self)?;
        let key = ed25519::PublicKey(self.x_coord.clone());
        ed25519::verify(&key, data, sig).map_err(|err| Error {
            kind: "",
            details: err.to_string(),
        })
    }
}

/// Go's `VerifySignature`.
pub fn verify_signature(key: &PublicKey, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
    match key {
        PublicKey::Okp(k) => k.verify(data, sig),
        PublicKey::Ec2(k) => k.verify(data, sig),
        PublicKey::Rsa(k) => k.verify(data, sig),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_der_must_be_canonical() {
        let canonical = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        assert_eq!(
            ecdsa_der_integers(&canonical),
            Some((&[1u8][..], &[2u8][..]))
        );
        for bad in [
            &[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02][..],
            &[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00],
            &[0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x05, 0x00],
            &[0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x02],
            &[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
            &[],
        ] {
            assert_eq!(ecdsa_der_integers(bad), None, "{bad:x?}");
        }
    }
}
