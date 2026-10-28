//! The RFC 8555 client calls autocert makes, from golang.org/x/crypto/acme:
//! `Discover`, `Register`, `AuthorizeOrder`, `GetAuthorization`, `Accept`,
//! `WaitAuthorization`, `WaitOrder`, `CreateOrderCert` and
//! `RevokeAuthorization`, with nonce handling and `badNonce` retries.

use super::jws::{self, Error, Key};
use rust_stdlib::encoding::json::v2::{self as json, Any};
use rust_stdlib::encoding::pem;
use rust_stdlib::net::http;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Let's Encrypt's production directory, autocert's `DefaultACMEDirectory`.
pub const LETS_ENCRYPT_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// An RFC 7807 problem from the CA, Go's `*acme.Error`.
#[derive(Debug)]
pub struct Problem {
    pub status_code: u16,
    pub problem_type: String,
    pub detail: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}: {}",
            self.status_code, self.problem_type, self.detail
        )
    }
}

impl std::error::Error for Problem {}

#[derive(Clone, Debug, Default)]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

#[derive(Clone, Debug, Default)]
pub struct Order {
    pub uri: String,
    pub status: String,
    pub authz_urls: Vec<String>,
    pub finalize_url: String,
    pub cert_url: String,
}

#[derive(Clone, Debug, Default)]
pub struct Challenge {
    pub kind: String,
    pub uri: String,
    pub token: String,
    pub status: String,
}

#[derive(Clone, Debug, Default)]
pub struct Authorization {
    pub uri: String,
    pub status: String,
    pub challenges: Vec<Challenge>,
}

#[derive(Default)]
struct State {
    dir: Option<Directory>,
    kid: Option<String>,
    nonces: Vec<String>,
}

/// Go's `acme.Client` for one account key.
pub struct Client {
    pub directory_url: String,
    pub key: Key,
    http: http::Client,
    state: Mutex<State>,
}

struct Reply {
    status: u16,
    location: String,
    retry_after: Option<Duration>,
    body: Vec<u8>,
}

fn object(v: &Any) -> Option<&BTreeMap<String, Any>> {
    match v {
        Any::Object(m) => Some(m),
        _ => None,
    }
}

fn string(v: &Any, key: &str) -> String {
    match object(v).and_then(|m| m.get(key)) {
        Some(Any::String(s)) => s.clone(),
        _ => String::new(),
    }
}

fn identifier(v: &Any) -> String {
    object(v)
        .and_then(|m| m.get("identifier"))
        .map(|id| string(id, "value"))
        .unwrap_or_default()
}

fn parse(body: &[u8]) -> Result<Any, Error> {
    let mut v = Any::Null;
    json::unmarshal(body, &mut v, &[])?;
    Ok(v)
}

fn payload(v: Any) -> Vec<u8> {
    json::marshal(&v, &[]).expect("ACME payloads marshal")
}

fn obj<const N: usize>(entries: [(&str, Any); N]) -> Any {
    Any::Object(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

/// Go's `retryAfter`: seconds, or an HTTP date.
fn retry_after(value: &str) -> Option<Duration> {
    if let Ok(secs) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let t = http::parse_time(value).ok()?;
    let d = rust_stdlib::time::until(&t);
    Some(Duration::from_nanos(d.nanoseconds().max(0) as u64))
}

impl Client {
    /// A client for `directory_url` that reaches the CA through `http`, such
    /// as a client trusting a test CA's roots.
    pub fn new(directory_url: &str, key: Key, http: http::Client) -> Client {
        Client {
            directory_url: directory_url.to_string(),
            key,
            http,
            state: Mutex::new(State::default()),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn send(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
        accept: &str,
    ) -> Result<Reply, Error> {
        let mut req = http::Request::new(method, url)?;
        if let Some(body) = body {
            req = req.with_body(body);
            req.header.set("Content-Type", "application/jose+json");
        }
        req.header.set("User-Agent", "autocert");
        if !accept.is_empty() {
            req.header.set("Accept", accept);
        }
        let res = self.http.do_request(req)?;
        if let Some(nonce) = res.header.get("Replay-Nonce") {
            if !nonce.is_empty() {
                self.state().nonces.push(nonce.to_string());
            }
        }
        let body = match &res.body {
            Some(b) => {
                let data = b.read_all()?;
                let _ = b.close();
                data
            }
            None => Vec::new(),
        };
        Ok(Reply {
            status: res.status_code,
            location: res.header.get("Location").unwrap_or_default().to_string(),
            retry_after: res.header.get("Retry-After").and_then(retry_after),
            body,
        })
    }

    fn problem(reply: &Reply) -> Problem {
        let v = parse(&reply.body).unwrap_or_default();
        Problem {
            status_code: reply.status,
            problem_type: string(&v, "type"),
            detail: string(&v, "detail"),
        }
    }

    /// Go's `Discover`, cached.
    fn discover(&self) -> Result<Directory, Error> {
        if let Some(dir) = self.state().dir.clone() {
            return Ok(dir);
        }
        let reply = self.send("GET", &self.directory_url, None, "")?;
        if reply.status != 200 {
            return Err(Box::new(Self::problem(&reply)));
        }
        let v = parse(&reply.body)?;
        let dir = Directory {
            new_nonce: string(&v, "newNonce"),
            new_account: string(&v, "newAccount"),
            new_order: string(&v, "newOrder"),
        };
        if dir.new_order.is_empty() {
            // autocert's errPreRFC.
            return Err("acme/autocert: ACME server doesn't support RFC 8555".into());
        }
        self.state().dir = Some(dir.clone());
        Ok(dir)
    }

    fn nonce(&self) -> Result<String, Error> {
        if let Some(n) = self.state().nonces.pop() {
            return Ok(n);
        }
        let dir = self.discover()?;
        let reply = self.send("HEAD", &dir.new_nonce, None, "")?;
        self.state()
            .nonces
            .pop()
            .ok_or_else(|| format!("acme: nonce not returned (status {})", reply.status).into())
    }

    /// Go's `post`: a JWS POST, retried on `badNonce` and on 5xx and 429
    /// answers. `ok` lists the statuses that end it.
    fn post(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        embed_jwk: bool,
        ok: &[u16],
        accept: &str,
    ) -> Result<Reply, Error> {
        let mut attempt = 0;
        loop {
            let nonce = self.nonce()?;
            let kid = if embed_jwk {
                None
            } else {
                self.state().kid.clone()
            };
            let jws = jws::jws_encode(&self.key, kid.as_deref(), &nonce, url, body.as_deref())?;
            let reply = self.send("POST", url, Some(jws), accept)?;
            if ok.contains(&reply.status) {
                return Ok(reply);
            }
            let problem = Self::problem(&reply);
            let bad_nonce = problem.problem_type.to_lowercase().ends_with(":badnonce");
            if bad_nonce {
                self.state().nonces.clear();
            } else if !(reply.status >= 500 || reply.status == 429) {
                return Err(Box::new(problem));
            }
            attempt += 1;
            if attempt >= 5 {
                return Err(Box::new(problem));
            }
            if !bad_nonce {
                std::thread::sleep(
                    reply
                        .retry_after
                        .unwrap_or(Duration::from_secs(1 << attempt)),
                );
            }
        }
    }

    /// Go's `Register` with autocert's `AcceptTOS` prompt. An existing
    /// account for the key is reused.
    pub fn register(&self, email: &str) -> Result<(), Error> {
        let dir = self.discover()?;
        let contact = if email.is_empty() {
            Vec::new()
        } else {
            vec![Any::String(format!("mailto:{email}"))]
        };
        let mut body = BTreeMap::new();
        if !contact.is_empty() {
            body.insert("contact".to_string(), Any::Array(contact));
        }
        body.insert("termsOfServiceAgreed".to_string(), Any::Bool(true));
        let reply = self.post(
            &dir.new_account,
            Some(payload(Any::Object(body))),
            true,
            &[200, 201],
            "",
        )?;
        if reply.location.is_empty() {
            return Err("acme: account URL not returned".into());
        }
        self.state().kid = Some(reply.location);
        Ok(())
    }

    fn order(uri: &str, v: &Any) -> Order {
        let authz_urls = match object(v).and_then(|m| m.get("authorizations")) {
            Some(Any::Array(a)) => a
                .iter()
                .filter_map(|u| match u {
                    Any::String(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        Order {
            uri: uri.to_string(),
            status: string(v, "status"),
            authz_urls,
            finalize_url: string(v, "finalize"),
            cert_url: string(v, "certificate"),
        }
    }

    /// Go's `AuthorizeOrder` for one DNS name.
    pub fn authorize_order(&self, domain: &str) -> Result<Order, Error> {
        let dir = self.discover()?;
        let body = obj([(
            "identifiers",
            Any::Array(vec![obj([
                ("type", Any::String("dns".to_string())),
                ("value", Any::String(domain.to_string())),
            ])]),
        )]);
        let reply = self.post(&dir.new_order, Some(payload(body)), false, &[201], "")?;
        Ok(Self::order(&reply.location, &parse(&reply.body)?))
    }

    fn get_order(&self, url: &str) -> Result<(Order, Option<Duration>), Error> {
        let reply = self.post(url, None, false, &[200], "")?;
        Ok((Self::order(url, &parse(&reply.body)?), reply.retry_after))
    }

    fn authorization(uri: &str, v: &Any) -> Authorization {
        let challenges = match object(v).and_then(|m| m.get("challenges")) {
            Some(Any::Array(a)) => a
                .iter()
                .map(|c| Challenge {
                    kind: string(c, "type"),
                    uri: string(c, "url"),
                    token: string(c, "token"),
                    status: string(c, "status"),
                })
                .collect(),
            _ => Vec::new(),
        };
        Authorization {
            uri: uri.to_string(),
            status: string(v, "status"),
            challenges,
        }
    }

    /// Go's `GetAuthorization`.
    pub fn get_authorization(&self, url: &str) -> Result<Authorization, Error> {
        let reply = self.post(url, None, false, &[200], "")?;
        Ok(Self::authorization(url, &parse(&reply.body)?))
    }

    /// Go's `Accept`: tells the CA the challenge is ready.
    pub fn accept(&self, challenge: &Challenge) -> Result<(), Error> {
        self.post(&challenge.uri, Some(b"{}".to_vec()), false, &[200], "")?;
        Ok(())
    }

    /// Go's `RevokeAuthorization`: deactivates a pending authorization.
    pub fn revoke_authorization(&self, url: &str) -> Result<(), Error> {
        let body = obj([("status", Any::String("deactivated".to_string()))]);
        self.post(url, Some(payload(body)), false, &[200], "")?;
        Ok(())
    }

    /// Go's `WaitAuthorization`: polls until the authorization is valid.
    pub fn wait_authorization(&self, url: &str, deadline: Instant) -> Result<Authorization, Error> {
        loop {
            let reply = self.post(url, None, false, &[200], "")?;
            let z = Self::authorization(url, &parse(&reply.body)?);
            match z.status.as_str() {
                "valid" => return Ok(z),
                "invalid" | "revoked" | "deactivated" | "expired" => {
                    let v = parse(&reply.body)?;
                    let mut details = Vec::new();
                    if let Some(Any::Array(challenges)) =
                        object(&v).and_then(|m| m.get("challenges"))
                    {
                        for c in challenges {
                            if let Some(e) = object(c).and_then(|m| m.get("error")) {
                                details.push(format!(
                                    "{}: {}",
                                    string(e, "type"),
                                    string(e, "detail")
                                ));
                            }
                        }
                    }
                    return Err(format!(
                        "acme: authorization error for {}: {}",
                        identifier(&v),
                        details.join("; ")
                    )
                    .into());
                }
                _ => sleep_until_retry(reply.retry_after, deadline)?,
            }
        }
    }

    /// Go's `WaitOrder`: polls until the order is ready or valid.
    pub fn wait_order(&self, url: &str, deadline: Instant) -> Result<Order, Error> {
        loop {
            let (o, retry) = self.get_order(url)?;
            match o.status.as_str() {
                "ready" | "valid" => return Ok(o),
                "pending" | "processing" => sleep_until_retry(retry, deadline)?,
                _ => return Err(format!("acme: order {url} is {}", o.status).into()),
            }
        }
    }

    /// Go's `CreateOrderCert` with `bundle` set: finalizes the order with
    /// `csr` and returns the DER chain, leaf first.
    pub fn create_order_cert(
        &self,
        order: &Order,
        csr: &[u8],
        deadline: Instant,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let body = obj([(
            "csr",
            Any::String(rust_stdlib::encoding::base64::URL_SAFE_NO_PAD.encode(csr)),
        )]);
        self.post(&order.finalize_url, Some(payload(body)), false, &[200], "")?;
        let mut o = self.wait_order(&order.uri, deadline)?;
        while o.status != "valid" {
            sleep_until_retry(None, deadline)?;
            o = self.get_order(&order.uri)?.0;
        }
        let reply = self.post(
            &o.cert_url,
            None,
            false,
            &[200],
            "application/pem-certificate-chain",
        )?;
        let mut rest: &[u8] = &reply.body;
        let mut chain = Vec::new();
        while let Some((block, after)) = pem::decode(rest) {
            if block.type_ != "CERTIFICATE" {
                return Err(format!("acme: invalid PEM cert type {:?}", block.type_).into());
            }
            chain.push(block.bytes);
            rest = after;
        }
        if chain.is_empty() {
            return Err("acme: no certificate in the CA's response".into());
        }
        Ok(chain)
    }
}

fn sleep_until_retry(retry: Option<Duration>, deadline: Instant) -> Result<(), Error> {
    let wait = retry
        .unwrap_or(Duration::from_secs(1))
        .max(Duration::from_millis(100));
    if Instant::now() + wait > deadline {
        return Err("acme: deadline exceeded".into());
    }
    std::thread::sleep(wait);
    Ok(())
}
