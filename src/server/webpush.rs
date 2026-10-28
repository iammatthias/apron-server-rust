//! Web Push (§4.9, push kind webpush, and relay with keys): message
//! encryption for the client (RFC 8291, the aes128gcm content coding of
//! RFC 8188) and the server's VAPID identification to push services
//! (RFC 8292), through rust-stdlib-crypto.

use std::collections::BTreeMap;
use std::sync::Mutex;

use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::net::url::{self, Url};
use rust_stdlib::time::{Duration, Time};
use rust_stdlib_crypto::cipher::{self, Aead};
use rust_stdlib_crypto::{aes, ecdh, ecdsa, elliptic, hkdf, rand, sha256};

use super::protocol::encode_json;
use crate::obj;

/// P256_POINT_BYTES is an uncompressed P-256 point; AUTH_SECRET_BYTES is a
/// subscription's auth secret (RFC 8291 section 3.2).
pub const P256_POINT_BYTES: usize = 65;
pub const AUTH_SECRET_BYTES: usize = 16;
/// The rs of the one aes128gcm record a push carries.
pub const PUSH_RECORD_SIZE: usize = 4096;
/// The aes128gcm header: salt, record size, key ID length, and the server's
/// 65-byte ephemeral public key as key ID.
pub const PUSH_HEADER_BYTES: usize = 16 + 4 + 1 + P256_POINT_BYTES;
/// The longest payload one record holds: a push service accepts 4096 bytes
/// of body (RFC 8030 section 7.2), which holds the header, the payload with
/// its padding delimiter, and the 16-byte AES-GCM tag.
pub const MAX_PUSH_PLAINTEXT: usize = PUSH_RECORD_SIZE - PUSH_HEADER_BYTES - 1 - 16;
/// How long a VAPID token is valid; RFC 8292 allows at most 24 hours.
pub const VAPID_TOKEN_LIFETIME: Duration = Duration::from_hours(12);
/// How long a VAPID token is reused for its audience and subject before
/// another is signed, well within its lifetime; MAX_VAPID_TOKENS bounds the
/// tokens kept, one per push service origin.
pub const VAPID_TOKEN_REUSE: Duration = Duration::from_hours(1);
pub const MAX_VAPID_TOKENS: usize = 1024;
/// How long a push service keeps an undelivered webpush message, in seconds
/// (RFC 8030 section 5.2): a day, after which a chat notification is stale.
pub const PUSH_TTL: &str = "86400";

/// A subscription's keys (§4.9 keys): the client's P-256 public key and its
/// auth secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushKeys {
    pub p256dh: Vec<u8>,
    pub auth: Vec<u8>,
}

/// Decodes base64url, unpadded as §4.9 sends it, or padded.
pub fn decode_base64_url(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok()
}

pub fn encode_base64_url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Checks a subscription's keys: p256dh an uncompressed point on P-256,
/// which its length alone does not show, and auth 16 bytes.
pub fn parse_push_keys(p256dh: &str, auth: &str) -> Result<PushKeys, String> {
    let point = match decode_base64_url(p256dh) {
        Some(point) if point.len() == P256_POINT_BYTES && point[0] == 4 => point,
        _ => return Err("keys.p256dh must be an uncompressed P-256 point in base64url".into()),
    };
    if ecdh::p256().public_key_from_bytes(&point).is_err() {
        return Err("keys.p256dh is not a point on P-256".into());
    }
    let secret = match decode_base64_url(auth) {
        Some(secret) if secret.len() == AUTH_SECRET_BYTES => secret,
        _ => return Err("keys.auth must be 16 bytes in base64url".into()),
    };
    Ok(PushKeys {
        p256dh: point,
        auth: secret,
    })
}

/// Encrypts one push payload for a subscription (RFC 8291): a fresh ECDH
/// key pair and salt per message, one aes128gcm record with no padding past
/// its delimiter.
pub fn encrypt_push(plaintext: &[u8], keys: &PushKeys) -> Result<Vec<u8>, String> {
    let local = ecdh::p256().generate_key().map_err(|e| e.to_string())?;
    let mut salt = [0u8; 16];
    rand::read(&mut salt);
    encrypt_push_with(plaintext, keys, &local, &salt)
}

/// encrypt_push with the server's ephemeral key and the salt given, for
/// RFC 8291's test vector.
pub fn encrypt_push_with(
    plaintext: &[u8],
    keys: &PushKeys,
    local: &ecdh::PrivateKey,
    salt: &[u8],
) -> Result<Vec<u8>, String> {
    if plaintext.len() > MAX_PUSH_PLAINTEXT {
        return Err("push payload is too large".into());
    }
    let receiver = ecdh::p256()
        .public_key_from_bytes(&keys.p256dh)
        .map_err(|e| e.to_string())?;
    let secret = local.ecdh(&receiver).map_err(|e| e.to_string())?;
    let local_public = local.public_key().bytes();
    let (cek, nonce) = content_keys(&secret, &keys.auth, &keys.p256dh, &local_public, salt)?;
    let block = aes::Cipher::new(&cek).map_err(|e| e.to_string())?;
    let gcm = cipher::gcm(&block).map_err(|e| e.to_string())?;
    let mut body = Vec::with_capacity(PUSH_HEADER_BYTES + plaintext.len() + 1 + gcm.overhead());
    body.extend_from_slice(salt);
    body.extend_from_slice(&(PUSH_RECORD_SIZE as u32).to_be_bytes());
    body.push(P256_POINT_BYTES as u8);
    body.extend_from_slice(&local_public);
    // The last (and only) record ends with the 0x02 delimiter (RFC 8188
    // section 2).
    let mut record = Vec::with_capacity(plaintext.len() + 1);
    record.extend_from_slice(plaintext);
    record.push(2);
    gcm.seal(&mut body, &nonce, &record, &[])
        .map_err(|e| e.to_string())?;
    Ok(body)
}

/// The content encryption key and nonce of RFC 8291 section 3.4 for the
/// ECDH secret, the auth secret, the user agent's and the application
/// server's public keys, and the salt.
fn content_keys(
    secret: &[u8],
    auth: &[u8],
    ua_public: &[u8],
    as_public: &[u8],
    salt: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // key_info = "WebPush: info" || 0x00 || ua_public || as_public
    let mut key_info = b"WebPush: info\x00".to_vec();
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let ikm = hkdf::key(sha256::new, secret, auth, &key_info, 32).map_err(|e| e.to_string())?;
    let cek = hkdf::key(
        sha256::new,
        &ikm,
        salt,
        b"Content-Encoding: aes128gcm\x00",
        16,
    )
    .map_err(|e| e.to_string())?;
    let nonce = hkdf::key(sha256::new, &ikm, salt, b"Content-Encoding: nonce\x00", 12)
        .map_err(|e| e.to_string())?;
    Ok((cek, nonce))
}

/// The user agent's side of RFC 8291: recovers the payload of one aes128gcm
/// record with the subscription's private key. The server never decrypts;
/// the tests and the differential check do.
pub fn decrypt_push(
    body: &[u8],
    private: &ecdh::PrivateKey,
    auth: &[u8],
) -> Result<Vec<u8>, String> {
    if body.len() < PUSH_HEADER_BYTES || body[20] as usize != P256_POINT_BYTES {
        return Err("bad aes128gcm header".into());
    }
    let (salt, server_key) = (&body[..16], &body[21..PUSH_HEADER_BYTES]);
    let rs = u32::from_be_bytes([body[16], body[17], body[18], body[19]]);
    if rs as usize != PUSH_RECORD_SIZE {
        return Err(format!("record size {rs}"));
    }
    let server = ecdh::p256()
        .public_key_from_bytes(server_key)
        .map_err(|e| e.to_string())?;
    let secret = private.ecdh(&server).map_err(|e| e.to_string())?;
    let ua_public = private.public_key().bytes();
    let (cek, nonce) = content_keys(&secret, auth, &ua_public, server_key, salt)?;
    let block = aes::Cipher::new(&cek).map_err(|e| e.to_string())?;
    let gcm = cipher::gcm(&block).map_err(|e| e.to_string())?;
    let mut record = Vec::new();
    gcm.open(&mut record, &nonce, &body[PUSH_HEADER_BYTES..], &[])
        .map_err(|e| e.to_string())?;
    if record.last() != Some(&2) {
        return Err("record does not end with the last-record delimiter".into());
    }
    record.pop();
    Ok(record)
}

/// The server's VAPID key pair (RFC 8292), which server.push.webpush.key
/// advertises.
pub struct VapidKey {
    private: ecdsa::PrivateKey,
    /// The uncompressed public key in unpadded base64url.
    pub public: String,
    /// The Authorization header last signed for each audience and subject,
    /// reused for VAPID_TOKEN_REUSE.
    tokens: Mutex<BTreeMap<String, VapidToken>>,
}

/// A signed Authorization header and when it was signed.
struct VapidToken {
    header: String,
    signed: Time,
}

impl std::fmt::Debug for VapidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VapidKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl VapidKey {
    /// Generates a VAPID key pair.
    pub fn generate() -> Result<VapidKey, String> {
        let private = ecdsa::generate_key(elliptic::p256()).map_err(|e| e.to_string())?;
        VapidKey::of(private)
    }

    /// Reads a VAPID private key: the P-256 scalar in base64url, as web-push
    /// tools print it.
    pub fn parse(text: &str) -> Result<VapidKey, String> {
        let scalar = decode_base64_url(text.trim()).ok_or("a VAPID private key is base64url")?;
        let private = ecdsa::parse_raw_private_key(elliptic::p256(), &scalar)
            .map_err(|_| "a VAPID private key is a 32-byte P-256 scalar")?;
        VapidKey::of(private)
    }

    fn of(private: ecdsa::PrivateKey) -> Result<VapidKey, String> {
        let public = private.public_key.bytes().map_err(|e| e.to_string())?;
        Ok(VapidKey {
            private,
            public: encode_base64_url(&public),
            tokens: Mutex::new(BTreeMap::new()),
        })
    }

    /// The private scalar in unpadded base64url, as the store keeps it.
    pub fn encoded(&self) -> String {
        encode_base64_url(&self.private.bytes().unwrap_or_default())
    }

    /// The Authorization header that identifies this server to the push
    /// service of endpoint (RFC 8292 section 3): vapid t=<ES256 JWT for the
    /// endpoint's origin>, k=<public key>. subject, a mailto: or https: URL,
    /// is the contact the push service may use; empty leaves sub out. A
    /// header signed for the same audience and subject within
    /// VAPID_TOKEN_REUSE before now is reused, so a burst of pushes to one
    /// push service signs once.
    pub fn authorization(
        &self,
        endpoint: &str,
        subject: &str,
        now: &Time,
    ) -> Result<String, String> {
        let parsed = match url::parse(endpoint) {
            Ok(parsed) if !parsed.host.is_empty() => parsed,
            _ => return Err("push endpoint is not an absolute URL".into()),
        };
        let audience = origin(&parsed);
        let key = format!("{audience} {subject}");
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(token) = tokens.get(&key) {
            if !now.before(&token.signed) && now.sub(&token.signed) < VAPID_TOKEN_REUSE {
                return Ok(token.header.clone());
            }
        }
        let header = self.sign(&audience, subject, now)?;
        if tokens.len() >= MAX_VAPID_TOKENS {
            tokens.retain(|_, token| {
                now.sub(&token.signed) < VAPID_TOKEN_REUSE && !now.before(&token.signed)
            });
            if tokens.len() >= MAX_VAPID_TOKENS {
                tokens.clear();
            }
        }
        tokens.insert(
            key,
            VapidToken {
                header: header.clone(),
                signed: now.clone(),
            },
        );
        Ok(header)
    }

    /// Signs a VAPID Authorization header for an audience, valid for
    /// VAPID_TOKEN_LIFETIME from now.
    fn sign(&self, audience: &str, subject: &str, now: &Time) -> Result<String, String> {
        let mut claims = obj! {
            "aud" => audience,
            "exp" => now.add(VAPID_TOKEN_LIFETIME).unix(),
        };
        if !subject.is_empty() {
            claims.insert("sub".into(), subject.into());
        }
        let unsigned = format!(
            "{}.{}",
            encode_base64_url(br#"{"typ":"JWT","alg":"ES256"}"#),
            encode_base64_url(&encode_json(&claims).unwrap_or_default())
        );
        let digest = sha256::sum256(unsigned.as_bytes());
        let (r, s) = ecdsa::sign(&self.private, &digest).map_err(|e| e.to_string())?;
        // JWS ES256 signs as r || s, each 32 bytes (RFC 7518 section 3.4).
        let mut signature = r.fill_bytes(32).ok_or("signature r is too long")?;
        signature.extend(s.fill_bytes(32).ok_or("signature s is too long")?);
        Ok(format!(
            "vapid t={unsigned}.{}, k={}",
            encode_base64_url(&signature),
            self.public
        ))
    }
}

/// A URL's origin as push services compare a VAPID audience (RFC 6454): the
/// scheme and host lowercased, without a default port.
pub fn origin(u: &Url) -> String {
    let scheme = u.scheme.to_lowercase();
    format!("{scheme}://{}", host_port(&scheme, u))
}

/// The host of u lowercased, bracketed when it is an IPv6 address, with its
/// port unless it is the scheme's default.
pub(crate) fn host_port(scheme: &str, u: &Url) -> String {
    let mut host = u.hostname().to_lowercase();
    if host.contains(':') {
        host = format!("[{host}]");
    }
    let port = u.port();
    if !port.is_empty()
        && !(scheme == "https" && port == "443")
        && !(scheme == "http" && port == "80")
    {
        host.push(':');
        host.push_str(&port);
    }
    host
}
