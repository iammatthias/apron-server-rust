//! webpush_test.go.

use rust_stdlib::time::{self, Duration};
use rust_stdlib_crypto::bigint::Int;
use rust_stdlib_crypto::{ecdh, ecdsa, elliptic, rand, sha256};

use crate::obj;
use crate::server::protocol::*;
use crate::server::webpush::*;

/// The example of RFC 8291 Appendix A.
pub(super) struct Rfc8291 {
    pub plaintext: &'static str,
    pub as_public: &'static str,
    pub as_private: &'static str,
    pub ua_public: &'static str,
    pub ua_private: &'static str,
    pub salt: &'static str,
    pub auth: &'static str,
    pub body: &'static str,
}

pub(super) const RFC8291: Rfc8291 = Rfc8291 {
    plaintext: "When I grow up, I want to be a watermelon",
    as_public:
        "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
    as_private: "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
    ua_public:
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
    ua_private: "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94",
    salt: "DGv6ra1nlYgDCS1FRnbzlw",
    auth: "BTBZMqHH6r4Tts7J_aSIgg",
    body: concat!(
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml",
        "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT",
        "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
    ),
};

pub(super) fn must_decode(text: &str) -> Vec<u8> {
    decode_base64_url(text).unwrap_or_else(|| panic!("decode {text:?}"))
}

/// A browser's push subscription: its private key and the keys it
/// registers.
pub(super) fn test_subscription() -> (ecdh::PrivateKey, Object) {
    let private = ecdh::p256().generate_key().unwrap();
    let mut auth = [0u8; AUTH_SECRET_BYTES];
    rand::read(&mut auth);
    let keys = obj! {
        "p256dh" => encode_base64_url(&private.public_key().bytes()),
        "auth" => encode_base64_url(&auth),
    };
    (private, keys)
}

/// Decodes a JSON object, panicking on anything else.
pub(super) fn decode(data: &[u8]) -> Object {
    decode_object(data)
        .unwrap_or_else(|| panic!("not a JSON object: {:?}", String::from_utf8_lossy(data)))
}

/// Checks that the VAPID header's token is signed by the key k, r || s,
/// and returns its claims.
pub(super) fn check_vapid(header: &str, key: &str) -> Object {
    let rest = header
        .strip_prefix("vapid t=")
        .unwrap_or_else(|| panic!("header {header:?}"));
    let (token, k) = rest
        .split_once(", k=")
        .unwrap_or_else(|| panic!("header {header:?}"));
    assert_eq!(k, key, "k");
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "token {token:?}");
    assert_eq!(
        decode(&must_decode(parts[0])),
        obj! {"typ" => "JWT", "alg" => "ES256"},
        "JWT header"
    );
    let public = ecdsa::parse_uncompressed_public_key(elliptic::p256(), &must_decode(k)).unwrap();
    let signature = must_decode(parts[2]);
    let digest = sha256::sum256(format!("{}.{}", parts[0], parts[1]).as_bytes());
    assert_eq!(signature.len(), 64);
    assert!(
        ecdsa::verify(
            &public,
            &digest,
            &Int::from_be_bytes(&signature[..32]),
            &Int::from_be_bytes(&signature[32..])
        ),
        "the VAPID signature does not verify"
    );
    decode(&must_decode(parts[1]))
}

fn claims_of(header: &str) -> Object {
    let token = header
        .strip_prefix("vapid t=")
        .and_then(|rest| rest.split_once(", k="))
        .map(|(token, _)| token)
        .unwrap();
    decode(&must_decode(token.split('.').nth(1).unwrap()))
}

#[test]
fn test_web_push_encryption_matches_rfc8291() {
    let v = &RFC8291;
    let local = ecdh::p256()
        .private_key_from_bytes(&must_decode(v.as_private))
        .unwrap();
    assert_eq!(encode_base64_url(&local.public_key().bytes()), v.as_public);
    let keys = parse_push_keys(v.ua_public, v.auth).unwrap();
    let body =
        encrypt_push_with(v.plaintext.as_bytes(), &keys, &local, &must_decode(v.salt)).unwrap();
    assert_eq!(encode_base64_url(&body), v.body, "body");
    // The receiver's private key recovers it.
    let receiver = ecdh::p256()
        .private_key_from_bytes(&must_decode(v.ua_private))
        .unwrap();
    assert_eq!(
        decrypt_push(&body, &receiver, &keys.auth).unwrap(),
        v.plaintext.as_bytes()
    );

    // Each message has a fresh salt and server key.
    let first = encrypt_push(b"same", &keys).unwrap();
    let second = encrypt_push(b"same", &keys).unwrap();
    assert_ne!(
        first[..PUSH_HEADER_BYTES],
        second[..PUSH_HEADER_BYTES],
        "two messages share a salt and key"
    );
    for body in [&first, &second] {
        assert_eq!(decrypt_push(body, &receiver, &keys.auth).unwrap(), b"same");
    }
    // The largest payload fills the 4096 bytes a push service must accept.
    let largest = encrypt_push(&vec![0; MAX_PUSH_PLAINTEXT], &keys).unwrap();
    assert_eq!(largest.len(), PUSH_RECORD_SIZE);
    assert!(
        encrypt_push(&vec![0; MAX_PUSH_PLAINTEXT + 1], &keys).is_err(),
        "an oversized payload was encrypted"
    );
}

#[test]
fn test_parse_push_keys() {
    let v = &RFC8291;
    parse_push_keys(&format!("{}=", v.ua_public), &format!("{}==", v.auth)).expect("padded keys");
    let mut off_curve = must_decode(v.ua_public);
    off_curve[64] ^= 1;
    let mut compressed = must_decode(v.ua_public)[..33].to_vec();
    compressed[0] = 2;
    let standard = v.ua_public.replace('_', "/").replace('-', "+");
    for (name, p256dh, auth) in [
        (
            "off the curve",
            encode_base64_url(&off_curve),
            v.auth.to_owned(),
        ),
        (
            "compressed",
            encode_base64_url(&compressed),
            v.auth.to_owned(),
        ),
        ("zero point", encode_base64_url(&[0; 65]), v.auth.to_owned()),
        ("standard b64", standard, v.auth.to_owned()),
        (
            "short auth",
            v.ua_public.to_owned(),
            encode_base64_url(&[0; 15]),
        ),
        (
            "long auth",
            v.ua_public.to_owned(),
            encode_base64_url(&[0; 17]),
        ),
        ("empty", String::new(), String::new()),
    ] {
        assert!(parse_push_keys(&p256dh, &auth).is_err(), "{name}: accepted");
    }
}

#[test]
fn test_vapid_authorization() {
    let key = VapidKey::generate().unwrap();
    // The stored form round-trips to the same key.
    let again = VapidKey::parse(&key.encoded()).unwrap();
    assert_eq!(again.public, key.public);
    for bad in [
        String::new(),
        "not base64!".to_owned(),
        encode_base64_url(&[0; 31]),
        encode_base64_url(&[0; 32]),
    ] {
        assert!(VapidKey::parse(&bad).is_err(), "VAPID key {bad:?} accepted");
    }
    let now = time::date(2026, time::OCTOBER, 1, 12, 0, 0, 0, &time::Location::utc());
    let header = key
        .authorization(
            "https://push.example.net:8443/send/abc?x=1",
            "mailto:ops@example.com",
            &now,
        )
        .unwrap();
    // The advertised public key verifies the ES256 signature, r || s.
    let claims = check_vapid(&header, &key.public);
    let want = obj! {
        "aud" => "https://push.example.net:8443",
        "exp" => now.add(Duration::from_hours(12)).unix(),
        "sub" => "mailto:ops@example.com",
    };
    assert_eq!(claims, want, "JWT claims");
    // The audience is the origin, lowercased, without a default port.
    for (endpoint, want) in [
        ("HTTPS://Push.Example.NET:443/x", "https://push.example.net"),
        (
            "https://push.example.net:8443/",
            "https://push.example.net:8443",
        ),
        ("http://[::1]:80/x", "http://[::1]"),
    ] {
        let header = key.authorization(endpoint, "", &now).unwrap();
        assert_eq!(
            claims_of(&header).get("aud").and_then(Json::as_str),
            Some(want),
            "aud for {endpoint}"
        );
    }
    // Without a subject the token has no sub.
    let header = key
        .authorization("https://push.example.net/x", "", &now)
        .unwrap();
    assert!(
        !claims_of(&header).contains_key("sub"),
        "sub without a subject"
    );
}

/// A VAPID header is signed once per audience and subject and reused for
/// VAPID_TOKEN_REUSE, then signed again.
#[test]
fn test_vapid_tokens_are_reused() {
    let key = VapidKey::generate().unwrap();
    let now = time::date(2026, time::OCTOBER, 1, 12, 0, 0, 0, &time::Location::utc());
    let subject = "mailto:ops@example.com";
    let first = key
        .authorization("https://push.example.net/a", subject, &now)
        .unwrap();
    let again = key
        .authorization(
            "https://PUSH.example.net:443/b",
            subject,
            &now.add(VAPID_TOKEN_REUSE - time::SECOND),
        )
        .unwrap();
    assert_eq!(
        again, first,
        "a token was signed again for the same audience within the reuse period"
    );
    let other = key
        .authorization("https://push.example.net/a", "", &now)
        .unwrap();
    assert_ne!(other, first, "a token was reused for another subject");
    let other = key
        .authorization("https://other.example.net/a", subject, &now)
        .unwrap();
    assert_ne!(other, first, "a token was reused for another audience");
    let later = key
        .authorization(
            "https://push.example.net/a",
            subject,
            &now.add(VAPID_TOKEN_REUSE),
        )
        .unwrap();
    assert_ne!(later, first, "a token was reused past the reuse period");
}
