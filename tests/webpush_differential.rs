//! Differential gate for src/server/webpush.rs against apron-server-go's Web
//! Push code, through `tools/differential/webpush` (its own `go.mod`, with
//! the Go functions copied in).
//!
//! Go to Rust: `vectors.json` holds payloads Go encrypted. Each must decrypt
//! here, and each fixed case (RFC 8291's example and five with fixed keys
//! and salts) must encrypt here to Go's exact bytes. Regenerate it with
//! `go run . vectors > vectors.json` in that directory.
//!
//! Rust to Go: with `WEBPUSH_RUST_VECTORS` set to a path, the payloads this
//! port encrypts and the VAPID tokens it signs are written there for
//! `go run . check <path>`. `tools/differential/webpush/run.sh` runs both.

use apron::server::webpush::{
    decode_base64_url, decrypt_push, encode_base64_url, encrypt_push, encrypt_push_with, PushKeys,
    VapidKey, MAX_PUSH_PLAINTEXT,
};
use rust_stdlib::encoding::json::v2;
use rust_stdlib::time;
use rust_stdlib_crypto::{ecdh, rand};
use rust_stdlib_derive::{MarshalTo, UnmarshalFrom};

#[derive(Debug, Default, MarshalTo, UnmarshalFrom)]
struct Case {
    #[json("name")]
    name: String,
    #[json("ua_private")]
    ua_private: String,
    #[json("auth")]
    auth: String,
    #[json("as_private,omitzero")]
    as_private: String,
    #[json("salt,omitzero")]
    salt: String,
    #[json("plaintext")]
    plaintext: String,
    #[json("body")]
    body: String,
}

#[derive(Debug, Default, MarshalTo, UnmarshalFrom)]
struct Token {
    #[json("endpoint")]
    endpoint: String,
    #[json("subject")]
    subject: String,
    #[json("now")]
    now: i64,
    #[json("public")]
    public: String,
    #[json("authorization")]
    authorization: String,
}

#[derive(Debug, Default, MarshalTo, UnmarshalFrom)]
struct File {
    #[json("cases")]
    cases: Vec<Case>,
    #[json("tokens,omitzero")]
    tokens: Vec<Token>,
}

fn bytes(text: &str) -> Vec<u8> {
    decode_base64_url(text).unwrap_or_else(|| panic!("base64url {text:?}"))
}

fn keys_of(ua: &ecdh::PrivateKey, auth: &[u8]) -> PushKeys {
    PushKeys {
        p256dh: ua.public_key().bytes(),
        auth: auth.to_vec(),
    }
}

#[test]
fn go_payloads_open_in_rust() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tools/differential/webpush/vectors.json"
    );
    let mut file = File::default();
    v2::unmarshal(&std::fs::read(path).expect("read vectors"), &mut file, &[])
        .expect("decode vectors");
    let mut fixed = 0;
    for c in &file.cases {
        let ua = ecdh::p256()
            .private_key_from_bytes(&bytes(&c.ua_private))
            .unwrap();
        let auth = bytes(&c.auth);
        let body = bytes(&c.body);
        let plaintext = decrypt_push(&body, &ua, &auth)
            .unwrap_or_else(|e| panic!("{}: Go's payload does not open: {e}", c.name));
        assert_eq!(
            encode_base64_url(&plaintext),
            c.plaintext,
            "{}: plaintext",
            c.name
        );
        if !c.as_private.is_empty() {
            let local = ecdh::p256()
                .private_key_from_bytes(&bytes(&c.as_private))
                .unwrap();
            let ours = encrypt_push_with(&plaintext, &keys_of(&ua, &auth), &local, &bytes(&c.salt))
                .unwrap();
            assert_eq!(
                encode_base64_url(&ours),
                c.body,
                "{}: body differs from Go's",
                c.name
            );
            fixed += 1;
        }
    }
    assert!(
        file.cases.len() >= 14 && fixed >= 6,
        "{} cases, {fixed} fixed",
        file.cases.len()
    );
}

/// Payloads and VAPID tokens for Go to check. Without
/// `WEBPUSH_RUST_VECTORS` they are made, and opened here, but not written.
#[test]
fn rust_payloads_and_tokens_for_go() {
    let mut file = File::default();
    for (i, size) in [0usize, 1, 41, 300, 2048, MAX_PUSH_PLAINTEXT]
        .into_iter()
        .enumerate()
    {
        let ua = ecdh::p256().generate_key().unwrap();
        let mut auth = [0u8; 16];
        rand::read(&mut auth);
        let plaintext: Vec<u8> = (0..size).map(|n| b'a' + ((n + i) % 26) as u8).collect();
        let body = encrypt_push(&plaintext, &keys_of(&ua, &auth)).unwrap();
        assert_eq!(decrypt_push(&body, &ua, &auth).unwrap(), plaintext);
        file.cases.push(Case {
            name: format!("rust-{size}"),
            ua_private: encode_base64_url(&ua.bytes()),
            auth: encode_base64_url(&auth),
            plaintext: encode_base64_url(&plaintext),
            body: encode_base64_url(&body),
            ..Case::default()
        });
    }
    let key = VapidKey::generate().unwrap();
    let now = time::now();
    for (endpoint, subject) in [
        (
            "https://fcm.googleapis.com/fcm/send/abc",
            "mailto:ops@example.com",
        ),
        ("HTTPS://Push.Example.NET:443/x", ""),
        (
            "https://push.example.net:8443/send/abc?x=1",
            "https://chat.example",
        ),
        ("http://[::1]:80/x", ""),
    ] {
        file.tokens.push(Token {
            endpoint: endpoint.into(),
            subject: subject.into(),
            now: now.unix(),
            public: key.public.clone(),
            authorization: key.authorization(endpoint, subject, &now).unwrap(),
        });
    }
    if let Ok(path) = std::env::var("WEBPUSH_RUST_VECTORS") {
        std::fs::write(&path, v2::marshal(&file, &[]).unwrap()).expect("write Rust vectors");
    }
}
