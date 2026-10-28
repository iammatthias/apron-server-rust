//! The cryptography of golang.org/x/crypto/acme over rust-stdlib-crypto:
//! ES256 JWS (RFC 7515, RFC 8555 §6.2), JWK thumbprints (RFC 7638), key
//! authorizations, the TLS-ALPN-01 certificate (RFC 8737) and the CSR.

use rust_stdlib::encoding::base64;
use rust_stdlib::encoding::json::v2::{self as json, Any};
use rust_stdlib::encoding::pem;
use rust_stdlib_crypto::x509::{self, pkix, BigInt, ObjectIdentifier};
use rust_stdlib_crypto::{ecdsa, elliptic, sha256};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// A P-256 key, the only key type this client creates.
pub type Key = ecdsa::PrivateKey;

pub fn generate_key() -> Result<Key, Error> {
    Ok(ecdsa::generate_key(elliptic::p256())?)
}

fn b64(data: &[u8]) -> String {
    base64::URL_SAFE_NO_PAD.encode(data)
}

fn json_string(s: &str) -> String {
    String::from_utf8(json::marshal(&s.to_string(), &[]).expect("a string marshals"))
        .expect("JSON is UTF-8")
}

fn coordinate(n: &rust_stdlib_crypto::bigint::Int) -> Vec<u8> {
    n.fill_bytes(32).expect("a P-256 coordinate fits 32 bytes")
}

/// Go's `jwkEncode`: the members in lexicographic order, as RFC 7638 needs.
pub fn jwk_encode(key: &Key) -> String {
    let public = &key.public_key;
    format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        b64(&coordinate(&public.x)),
        b64(&coordinate(&public.y))
    )
}

/// Go's `JWKThumbprint`.
pub fn jwk_thumbprint(key: &Key) -> String {
    b64(&sha256::sum256(jwk_encode(key).as_bytes()))
}

/// Go's `keyAuth`: the key authorization of a challenge token (RFC 8555
/// §8.1).
pub fn key_authorization(key: &Key, token: &str) -> String {
    format!("{token}.{}", jwk_thumbprint(key))
}

/// Go's `jwsEncodeJSON`. `payload` is the JSON body, or `None` for an empty
/// POST-as-GET payload; `kid` is the account URL, or `None` to embed the JWK.
pub fn jws_encode(
    key: &Key,
    kid: Option<&str>,
    nonce: &str,
    url: &str,
    payload: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let mut header = String::from(r#"{"alg":"ES256""#);
    match kid {
        Some(kid) => header += &format!(r#","kid":{}"#, json_string(kid)),
        None => header += &format!(r#","jwk":{}"#, jwk_encode(key)),
    }
    if !nonce.is_empty() {
        header += &format!(r#","nonce":{}"#, json_string(nonce));
    }
    header += &format!(r#","url":{}}}"#, json_string(url));
    let protected = b64(header.as_bytes());
    let payload = payload.map(b64).unwrap_or_default();
    let digest = sha256::sum256(format!("{protected}.{payload}").as_bytes());
    let (r, s) = ecdsa::sign(key, &digest)?;
    let mut sig = coordinate(&r);
    sig.extend(coordinate(&s));
    Ok(format!(
        r#"{{"protected":"{protected}","payload":"{payload}","signature":"{}"}}"#,
        b64(&sig)
    )
    .into_bytes())
}

/// Checks an ES256 JWS made by [`jws_encode`] or Go's `jwsEncodeJSON`
/// against `key`'s public half, and returns its protected header.
pub fn jws_verify(key: &ecdsa::PublicKey, jws: &[u8]) -> Result<Any, Error> {
    let mut v = Any::Null;
    json::unmarshal(jws, &mut v, &[])?;
    let field = |name: &str| match &v {
        Any::Object(m) => match m.get(name) {
            Some(Any::String(s)) => Ok(s.clone()),
            _ => Err(format!("jws: missing {name}")),
        },
        _ => Err("jws: not an object".to_string()),
    };
    let (protected, payload, signature) =
        (field("protected")?, field("payload")?, field("signature")?);
    let sig = base64::URL_SAFE_NO_PAD.decode(&signature)?;
    if sig.len() != 64 {
        return Err("jws: signature is not 64 bytes".into());
    }
    let digest = sha256::sum256(format!("{protected}.{payload}").as_bytes());
    let r = rust_stdlib_crypto::bigint::Int::from_be_bytes(&sig[..32]);
    let s = rust_stdlib_crypto::bigint::Int::from_be_bytes(&sig[32..]);
    if !ecdsa::verify(key, &digest, &r, &s) {
        return Err("jws: bad signature".into());
    }
    let mut header = Any::Null;
    json::unmarshal(
        &base64::URL_SAFE_NO_PAD.decode(&protected)?,
        &mut header,
        &[],
    )?;
    Ok(header)
}

/// The id-pe-acmeIdentifier extension (RFC 8737 §3).
fn acme_identifier_oid() -> ObjectIdentifier {
    ObjectIdentifier::new(vec![1, 3, 6, 1, 5, 5, 7, 1, 31])
}

/// The DER of the critical acmeIdentifier extension's value: an OCTET
/// STRING of the SHA-256 of the key authorization.
pub fn acme_identifier_value(key_authorization: &str) -> Vec<u8> {
    let mut value = vec![0x04, 32];
    value.extend(sha256::sum256(key_authorization.as_bytes()));
    value
}

/// Go's `TLSALPN01ChallengeCert`: a self-signed certificate for `domain`
/// carrying the key authorization, with a new P-256 key. Returns the DER
/// certificate and the key.
pub fn tls_alpn01_challenge_cert(
    account: &Key,
    token: &str,
    domain: &str,
) -> Result<(Vec<u8>, Key), Error> {
    let key = generate_key()?;
    let now = x509::Time::now();
    let mut tmpl = x509::Certificate {
        serial_number: Some(BigInt::from_i64(1)),
        not_before: now,
        not_after: now.add_secs(24 * 60 * 60),
        basic_constraints_valid: true,
        key_usage: x509::KeyUsage::KEY_ENCIPHERMENT | x509::KeyUsage::DIGITAL_SIGNATURE,
        ext_key_usage: vec![x509::ExtKeyUsage::SERVER_AUTH],
        extra_extensions: vec![pkix::Extension {
            id: acme_identifier_oid(),
            critical: true,
            value: acme_identifier_value(&key_authorization(account, token)),
        }],
        ..Default::default()
    };
    match x509::parse_ip(domain) {
        Some(ip) => tmpl.ip_addresses = vec![ip],
        None => {
            tmpl.dns_names = vec![domain.to_string()];
            tmpl.subject.common_name = domain.to_string();
        }
    }
    let der = x509::create_certificate(&tmpl, &tmpl, &key.public_key, &key)?;
    Ok((der, key))
}

/// autocert's `certRequest`: a CSR for `domain`, with it as the common name
/// and the only DNS name.
pub fn cert_request(key: &Key, domain: &str) -> Result<Vec<u8>, Error> {
    let mut req = x509::CertificateRequest {
        dns_names: vec![domain.to_string()],
        ..Default::default()
    };
    req.subject.common_name = domain.to_string();
    Ok(x509::create_certificate_request(&req, key)?)
}

/// autocert's `encodeECDSAKey`: an `EC PRIVATE KEY` PEM block.
pub fn encode_key(key: &Key) -> Result<Vec<u8>, Error> {
    let block = pem::Block {
        type_: "EC PRIVATE KEY".to_string(),
        headers: Default::default(),
        bytes: x509::marshal_ec_private_key(key)?,
    };
    Ok(pem::encode(&block)?)
}

/// autocert's `parsePrivateKey` for the key types this client uses: PKCS #8
/// or SEC 1 ECDSA. An RSA key is an error.
pub fn parse_key(der: &[u8]) -> Result<Key, Error> {
    if let Ok(x509::PrivateKey::Ecdsa(key)) = x509::parse_pkcs8_private_key(der) {
        return Ok(key);
    }
    if let Ok(key) = x509::parse_ec_private_key(der) {
        return Ok(key);
    }
    Err("acme/autocert: failed to parse private key".into())
}

#[cfg(test)]
mod tests {
    use super::super::manager_test::{go, TempDir};
    use super::*;
    use crate::test_gate::GO;

    const DIFFERENTIAL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tools/differential/acme");

    fn account() -> Key {
        let data = std::fs::read(format!("{DIFFERENTIAL}/testdata/account.pem")).unwrap();
        let (block, _) = pem::decode(&data).unwrap();
        parse_key(&block.bytes).unwrap()
    }

    // The values below are what golang.org/x/crypto/acme v0.57.0 prints for
    // testdata/account.pem (`go run . vectors testdata/account.pem tok-123`).
    #[test]
    fn test_thumbprint_and_key_authorization_match_go() {
        let key = account();
        assert_eq!(
            jwk_thumbprint(&key),
            "OIMm-jIXoTjJ4G4Ky3Hx0BCOOtYXAQcfoM_16nYhaNw"
        );
        assert_eq!(
            key_authorization(&key, "tok-123"),
            "tok-123.OIMm-jIXoTjJ4G4Ky3Hx0BCOOtYXAQcfoM_16nYhaNw"
        );
        assert_eq!(
            hex(&acme_identifier_value(&key_authorization(&key, "tok-123"))),
            "042096c8c9be8f646e66d19148c52b421b28c603d1a3ca7ecc8dfa5609ff7452bc83"
        );
    }

    #[test]
    fn test_go_vectors_are_current() {
        let Some(out) = go(&["vectors", "testdata/account.pem", "tok-123"]) else {
            return GO.unavailable("go vectors");
        };
        let key = account();
        let ka = key_authorization(&key, "tok-123");
        assert_eq!(
            out,
            format!(
                "thumbprint {}\nhttp01 {ka}\npath /.well-known/acme-challenge/tok-123\nalpn {} true\n",
                jwk_thumbprint(&key),
                hex(&acme_identifier_value(&ka))
            )
        );
    }

    #[test]
    fn test_jws_verifies_with_go() {
        let key = account();
        let jws = jws_encode(
            &key,
            None,
            "nonce-1",
            "https://ca.example/new-account",
            Some(br#"{"termsOfServiceAgreed":true}"#),
        )
        .unwrap();
        let header = jws_verify(&key.public_key, &jws).unwrap();
        assert_eq!(
            String::from_utf8(json::marshal(&header, &[]).unwrap()).unwrap(),
            format!(
                r#"{{"alg":"ES256","jwk":{},"nonce":"nonce-1","url":"https://ca.example/new-account"}}"#,
                jwk_encode(&key)
            )
        );
        let kid = jws_encode(
            &key,
            Some("https://ca.example/acct/1"),
            "n2",
            "https://ca.example/order",
            None,
        )
        .unwrap();
        jws_verify(&key.public_key, &kid).unwrap();

        let dir = TempDir::new();
        let path = format!("{}/jws.json", dir.0);
        std::fs::write(&path, &jws).unwrap();
        let out = go(&["verify-jws", "testdata/account.pem", &path]);
        std::fs::write(&path, &kid).unwrap();
        let out_kid = go(&["verify-jws", "testdata/account.pem", &path]);
        let (Some(out), Some(out_kid)) = (out, out_kid) else {
            return GO.unavailable("go verify-jws");
        };
        assert_eq!(
            out,
            format!(
                "protected {{\"alg\":\"ES256\",\"jwk\":{},\"nonce\":\"nonce-1\",\"url\":\"https://ca.example/new-account\"}}\npayload {{\"termsOfServiceAgreed\":true}}\n",
                jwk_encode(&key)
            )
        );
        assert_eq!(
            out_kid,
            "protected {\"alg\":\"ES256\",\"kid\":\"https://ca.example/acct/1\",\"nonce\":\"n2\",\"url\":\"https://ca.example/order\"}\npayload \n"
        );
    }

    #[test]
    fn test_tls_alpn01_cert_checks_with_go() {
        let key = account();
        let (der, _) = tls_alpn01_challenge_cert(&key, "tok-123", "chat.example").unwrap();
        let cert = x509::parse_certificate(&der).unwrap();
        let ext = cert
            .extensions
            .iter()
            .find(|e| e.id.equal(&acme_identifier_oid()))
            .expect("acmeIdentifier extension");
        assert!(ext.critical);
        assert_eq!(
            ext.value,
            acme_identifier_value(&key_authorization(&key, "tok-123"))
        );
        assert_eq!(cert.dns_names, ["chat.example"]);

        let dir = TempDir::new();
        let path = format!("{}/cert.der", dir.0);
        std::fs::write(&path, &der).unwrap();
        let out = go(&[
            "check-alpn",
            "testdata/account.pem",
            "tok-123",
            "chat.example",
            &path,
        ]);
        match out {
            Some(out) => assert_eq!(out, "ok\n"),
            None => GO.unavailable("go check-alpn"),
        }
    }

    #[test]
    fn test_csr_names_the_domain() {
        let key = generate_key().unwrap();
        let der = cert_request(&key, "chat.example").unwrap();
        let csr = x509::parse_certificate_request(&der).unwrap();
        csr.check_signature().unwrap();
        assert_eq!(csr.dns_names, ["chat.example"]);
        assert_eq!(csr.subject.common_name, "chat.example");
    }

    #[test]
    fn test_key_round_trips_through_pem() {
        let key = generate_key().unwrap();
        let encoded = encode_key(&key).unwrap();
        let (block, rest) = pem::decode(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(block.type_, "EC PRIVATE KEY");
        assert_eq!(
            jwk_encode(&parse_key(&block.bytes).unwrap()),
            jwk_encode(&key)
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|b| format!("{b:02x}")).collect()
    }
}
