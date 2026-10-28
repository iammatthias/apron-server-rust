//! autocert's `Manager` as main.go configures it: `AcceptTOS`,
//! `HostWhitelist(--tls.domain...)`, `DirCache(--tls.cache-dir)`, `Email`,
//! `TLSConfig()` and `HTTPHandler(nil)`.

use super::cache::{CacheError, DirCache};
use super::client::{Challenge, Client, Problem, LETS_ENCRYPT_URL};
use super::jws::{self, Error, Key};
use rust_stdlib::encoding::pem;
use rust_stdlib::net::{self, http};
use rust_stdlib::time as gotime;
use rust_stdlib_crypto::x509;
use rust_stdlib_tls::tls;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

/// The ALPN protocol of TLS-ALPN-01 (RFC 8737 §6.2).
pub const ALPN_PROTO: &str = "acme-tls/1";

/// How long a failed certificate request blocks the next one for that
/// domain, autocert's `createCertRetryAfter`.
const CREATE_CERT_RETRY_AFTER: Duration = Duration::from_secs(60);

/// What the core configures, from `--tls.*`.
pub struct Config {
    /// `HostWhitelist(--tls.domain...)`.
    pub domains: Vec<String>,
    /// `DirCache(--tls.cache-dir)`; empty keeps nothing on disk.
    pub cache_dir: String,
    /// `--tls.email`, the account contact.
    pub email: String,
    /// The CA's directory; Let's Encrypt's production directory in aprond.
    pub directory_url: String,
    /// The client for the CA, whose TLS configuration holds its roots.
    pub http: http::Client,
    /// autocert's `RenewBefore`; zero is a third of the lifetime, at most
    /// 30 days.
    pub renew_before: Duration,
}

impl Config {
    /// main.go's manager: Let's Encrypt, with the system roots.
    pub fn lets_encrypt(domains: Vec<String>, cache_dir: &str, email: &str) -> Config {
        Config {
            domains,
            cache_dir: cache_dir.to_string(),
            email: email.to_string(),
            directory_url: LETS_ENCRYPT_URL.to_string(),
            http: http_client(tls::Config::new()),
            renew_before: Duration::ZERO,
        }
    }
}

/// An HTTP client whose TLS connections use `config`.
pub fn http_client(config: tls::Config) -> http::Client {
    let transport = http::Transport {
        tls_client_config: Some(Arc::new(config)),
        ..http::Transport::default()
    };
    http::Client {
        transport: Some(Arc::new(transport)),
        timeout: gotime::Duration::from_secs(30),
        ..http::Client::default()
    }
}

/// A certificate and its key, autocert's `certState` once filled.
struct Issued {
    key: Key,
    chain: Vec<Vec<u8>>,
    not_before: i64,
    not_after: i64,
    tls: Arc<tls::Certificate>,
}

type Slot = Arc<Mutex<Option<Arc<Issued>>>>;

struct Inner {
    whitelist: HashSet<String>,
    cache: Option<DirCache>,
    email: String,
    directory_url: String,
    http: http::Client,
    renew_before: Duration,
    try_http01: AtomicBool,
    client: Mutex<Option<Arc<Client>>>,
    state: Mutex<HashMap<String, Slot>>,
    cert_tokens: Mutex<HashMap<String, Arc<tls::Certificate>>>,
    http_tokens: Mutex<HashMap<String, Vec<u8>>>,
    renewal: Mutex<HashMap<String, gotime::Timer>>,
}

/// autocert's `Manager`.
#[derive(Clone)]
pub struct Manager(Arc<Inner>);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// idna's `Lookup.ToASCII` for the names a TLS client sends: SNI is ASCII
/// (A-labels), so this lowercases and rejects anything else.
fn to_ascii(name: &str) -> Option<String> {
    name.is_ascii().then(|| name.to_ascii_lowercase())
}

fn now_unix() -> i64 {
    gotime::now().unix()
}

fn random_below(max: i64) -> i64 {
    if max <= 0 {
        return 0;
    }
    let mut b = [0u8; 8];
    rust_stdlib_crypto::rand::read(&mut b);
    (u64::from_le_bytes(b) % max as u64) as i64
}

impl Manager {
    pub fn new(config: Config) -> Manager {
        let whitelist = config.domains.iter().filter_map(|d| to_ascii(d)).collect();
        Manager(Arc::new(Inner {
            whitelist,
            cache: (!config.cache_dir.is_empty()).then_some(DirCache(config.cache_dir)),
            email: config.email,
            directory_url: config.directory_url,
            http: config.http,
            renew_before: config.renew_before,
            try_http01: AtomicBool::new(false),
            client: Mutex::new(None),
            state: Mutex::new(HashMap::new()),
            cert_tokens: Mutex::new(HashMap::new()),
            http_tokens: Mutex::new(HashMap::new()),
            renewal: Mutex::new(HashMap::new()),
        }))
    }

    /// autocert's `TLSConfig`: certificates chosen per SNI name, and the
    /// TLS-ALPN-01 protocol next to HTTP/2 and HTTP/1.1.
    pub fn tls_config(&self) -> tls::Config {
        let manager = self.clone();
        let mut config = tls::Config::new();
        config.get_certificate = Some(Arc::new(move |hello: &tls::ClientHelloInfo| {
            manager
                .get_certificate(hello)
                .map(Some)
                .map_err(|e| tls::Error::new(e.to_string()))
        }));
        config.next_protos = vec!["h2".into(), "http/1.1".into(), ALPN_PROTO.into()];
        config
    }

    /// autocert's `GetCertificate`.
    pub fn get_certificate(
        &self,
        hello: &tls::ClientHelloInfo,
    ) -> Result<Arc<tls::Certificate>, Error> {
        let name = hello.server_name.as_str();
        if name.is_empty() {
            return Err("acme/autocert: missing server name".into());
        }
        if !name.trim_matches('.').contains('.') {
            return Err("acme/autocert: server name component count invalid".into());
        }
        let name = to_ascii(name).ok_or("acme/autocert: server name contains invalid character")?;
        if hello.supported_protos.len() == 1 && hello.supported_protos[0] == ALPN_PROTO {
            if let Some(cert) = lock(&self.0.cert_tokens).get(&name) {
                return Ok(cert.clone());
            }
            if let Ok(issued) = self.cache_get(&format!("{name}+token"), &name) {
                return Ok(issued.tls.clone());
            }
            return Err(format!(
                "acme/autocert: no token cert for {}",
                rust_stdlib::strconv::quote(&name)
            )
            .into());
        }
        self.host_policy(&name)?;
        let domain = name.trim_end_matches('.').to_string();
        // autocert issues RSA certificates to clients without ECDSA; this
        // port issues ECDSA only (docs/DEVIATIONS.md).
        self.cert(&domain)
    }

    fn host_policy(&self, host: &str) -> Result<(), Error> {
        if !self.0.whitelist.contains(host) {
            return Err(format!(
                "acme/autocert: host {} not configured in HostWhitelist",
                rust_stdlib::strconv::quote(host)
            )
            .into());
        }
        Ok(())
    }

    /// autocert's `cert` then `createCert`: the domain's certificate from
    /// memory, the cache, or the CA. One caller requests it from the CA;
    /// others wait for that request.
    fn cert(&self, domain: &str) -> Result<Arc<tls::Certificate>, Error> {
        let mut state = lock(&self.0.state);
        if let Some(slot) = state.get(domain).cloned() {
            drop(state);
            return match &*lock(&slot) {
                Some(issued) => Ok(issued.tls.clone()),
                None => Err("acme/autocert: missing certificate".into()),
            };
        }
        if let Ok(issued) = self.cache_get(domain, domain) {
            let issued = Arc::new(issued);
            state.insert(
                domain.to_string(),
                Arc::new(Mutex::new(Some(issued.clone()))),
            );
            drop(state);
            self.start_renew(domain, issued.not_before, issued.not_after);
            return Ok(issued.tls.clone());
        }
        let slot: Slot = Arc::new(Mutex::new(None));
        let mut owned = lock(&slot);
        state.insert(domain.to_string(), slot.clone());
        drop(state);
        let key = jws::generate_key()?;
        match self.authorized_cert(&key, domain) {
            Ok(chain) => {
                let issued = Arc::new(issue(key, chain)?);
                *owned = Some(issued.clone());
                drop(owned);
                let _ = self.cache_put(domain, &issued.key, &issued.chain);
                self.start_renew(domain, issued.not_before, issued.not_after);
                Ok(issued.tls.clone())
            }
            Err(e) => {
                drop(owned);
                let weak = Arc::downgrade(&self.0);
                let domain = domain.to_string();
                // The timer runs once; its handle is not kept.
                let _ = gotime::after_func(CREATE_CERT_RETRY_AFTER.into(), move || {
                    if let Some(inner) = weak.upgrade() {
                        let mut state = lock(&inner.state);
                        if state.get(&domain).is_some_and(|s| lock(s).is_none()) {
                            state.remove(&domain);
                        }
                    }
                });
                Err(e)
            }
        }
    }

    /// autocert's `cacheGet`: a PEM key and chain, checked with `validCert`.
    fn cache_get(&self, name: &str, domain: &str) -> Result<Issued, Error> {
        let cache = self.0.cache.as_ref().ok_or(CacheError::Miss)?;
        let data = cache.get(name)?;
        let (priv_block, mut rest) = pem::decode(&data).ok_or(CacheError::Miss)?;
        if !priv_block.type_.contains("PRIVATE") {
            return Err(CacheError::Miss.into());
        }
        let key = jws::parse_key(&priv_block.bytes)?;
        let mut chain = Vec::new();
        while !rest.is_empty() {
            let Some((block, after)) = pem::decode(rest) else {
                break;
            };
            chain.push(block.bytes);
            rest = after;
        }
        if !rest.is_empty() {
            return Err(CacheError::Miss.into());
        }
        valid_cert(domain, &chain, &key, now_unix()).map_err(|_| CacheError::Miss)?;
        issue(key, chain)
    }

    /// autocert's `cachePut`.
    fn cache_put(&self, name: &str, key: &Key, chain: &[Vec<u8>]) -> Result<(), Error> {
        let Some(cache) = &self.0.cache else {
            return Ok(());
        };
        let mut buf = jws::encode_key(key)?;
        for der in chain {
            buf.extend(pem::encode(&pem::Block::new("CERTIFICATE", der.clone()))?);
        }
        Ok(cache.put(name, &buf)?)
    }

    /// autocert's `acmeClient`: the account key from the cache, registered
    /// once.
    fn client(&self) -> Result<Arc<Client>, Error> {
        let mut client = lock(&self.0.client);
        if let Some(c) = &*client {
            return Ok(c.clone());
        }
        let c = Client::new(
            &self.0.directory_url,
            self.account_key()?,
            self.0.http.clone(),
        );
        match c.register(&self.0.email) {
            Ok(()) => {}
            Err(e)
                if e.downcast_ref::<Problem>()
                    .is_some_and(|p| p.status_code == 409) => {}
            Err(e) => return Err(e),
        }
        let c = Arc::new(c);
        *client = Some(c.clone());
        Ok(c)
    }

    /// autocert's `accountKey`.
    fn account_key(&self) -> Result<Key, Error> {
        const KEY_NAME: &str = "acme_account+key";
        const LEGACY_KEY_NAME: &str = "acme_account.key";
        let Some(cache) = &self.0.cache else {
            return jws::generate_key();
        };
        let data = match cache.get(KEY_NAME) {
            Err(CacheError::Miss) => cache.get(LEGACY_KEY_NAME),
            other => other,
        };
        match data {
            Err(CacheError::Miss) => {
                let key = jws::generate_key()?;
                cache.put(KEY_NAME, &jws::encode_key(&key)?)?;
                Ok(key)
            }
            Err(e) => Err(e.into()),
            Ok(data) => match pem::decode(&data) {
                Some((block, _)) if block.type_.contains("PRIVATE") => jws::parse_key(&block.bytes),
                _ => Err("acme/autocert: invalid account key found in cache".into()),
            },
        }
    }

    /// autocert's `authorizedCert`: an order for `domain`, its challenges,
    /// and the issued chain for `key`.
    fn authorized_cert(&self, key: &Key, domain: &str) -> Result<Vec<Vec<u8>>, Error> {
        let deadline = Instant::now() + Duration::from_secs(5 * 60);
        let csr = jws::cert_request(key, domain)?;
        let client = self.client()?;
        let order = self.verify_rfc(&client, domain, deadline)?;
        let chain = client.create_order_cert(&order, &csr, deadline)?;
        valid_cert(domain, &chain, key, now_unix())?;
        Ok(chain)
    }

    /// autocert's `verifyRFC`.
    fn verify_rfc(
        &self,
        client: &Arc<Client>,
        domain: &str,
        deadline: Instant,
    ) -> Result<super::client::Order, Error> {
        let mut challenge_types = vec!["tls-alpn-01"];
        if self.0.try_http01.load(Ordering::SeqCst) {
            challenge_types.push("http-01");
        }
        let mut next_type = 0;
        // Go drops the errors that move on to the next challenge type; the
        // last one is kept here for the final error.
        let mut last_error: Option<Error> = None;
        let mut pending_authz: Vec<String> = Vec::new();
        let mut cleanups: Vec<Box<dyn FnOnce()>> = Vec::new();
        let result = 'authorize: loop {
            let order = match client.authorize_order(domain) {
                Ok(o) => o,
                Err(e) => break Err(e),
            };
            pending_authz.extend(order.authz_urls.iter().cloned());
            match order.status.as_str() {
                "ready" => break Ok(order),
                "pending" => {}
                status => {
                    break Err(format!(
                        "acme/autocert: invalid new order status {}; order URL: {}",
                        rust_stdlib::strconv::quote(status),
                        rust_stdlib::strconv::quote(&order.uri)
                    )
                    .into())
                }
            }
            for zurl in &order.authz_urls {
                let z = match client.get_authorization(zurl) {
                    Ok(z) => z,
                    Err(e) => break 'authorize Err(e),
                };
                if z.status != "pending" {
                    continue;
                }
                let mut chal = None;
                while chal.is_none() && next_type < challenge_types.len() {
                    chal = z
                        .challenges
                        .iter()
                        .find(|c| c.kind == challenge_types[next_type])
                        .cloned();
                    next_type += 1;
                }
                let Some(chal) = chal else {
                    let mut text = format!(
                        "acme/autocert: unable to satisfy {} for domain {}: no viable challenge type found",
                        rust_stdlib::strconv::quote(&z.uri),
                        rust_stdlib::strconv::quote(domain)
                    );
                    if let Some(e) = &last_error {
                        text += &format!(" (last: {e})");
                    }
                    break 'authorize Err(text.into());
                };
                match self.fulfill(client, &chal, domain) {
                    Ok(cleanup) => cleanups.push(cleanup),
                    Err(_) => continue 'authorize,
                }
                if client.accept(&chal).is_err() {
                    continue 'authorize;
                }
                if let Err(e) = client.wait_authorization(&z.uri, deadline) {
                    last_error = Some(e);
                    continue 'authorize;
                }
            }
            match client.wait_order(&order.uri, deadline) {
                Ok(o) => break Ok(o),
                Err(_) => continue 'authorize,
            }
        };
        for cleanup in cleanups {
            cleanup();
        }
        // autocert's deactivatePendingAuthz, in the background.
        let client = client.clone();
        std::thread::spawn(move || {
            for u in pending_authz {
                if client
                    .get_authorization(&u)
                    .is_ok_and(|z| z.status == "pending")
                {
                    let _ = client.revoke_authorization(&u);
                }
            }
        });
        result
    }

    /// autocert's `fulfill`: makes the challenge's response available and
    /// returns its cleanup.
    fn fulfill(
        &self,
        client: &Client,
        chal: &Challenge,
        domain: &str,
    ) -> Result<Box<dyn FnOnce()>, Error> {
        match chal.kind.as_str() {
            "tls-alpn-01" => {
                let (der, key) = jws::tls_alpn01_challenge_cert(&client.key, &chal.token, domain)?;
                let name = format!("{domain}+token");
                let _ = self.cache_put(&name, &key, std::slice::from_ref(&der));
                let issued = issue(key, vec![der])?;
                lock(&self.0.cert_tokens).insert(domain.to_string(), issued.tls);
                let inner = self.0.clone();
                let domain = domain.to_string();
                Ok(Box::new(move || {
                    lock(&inner.cert_tokens).remove(&domain);
                    if let Some(cache) = &inner.cache {
                        let _ = cache.delete(&name);
                    }
                }))
            }
            "http-01" => {
                let path = format!("/.well-known/acme-challenge/{}", chal.token);
                let response = jws::key_authorization(&client.key, &chal.token);
                lock(&self.0.http_tokens).insert(path.clone(), response.clone().into_bytes());
                let name = http_token_cache_key(&path);
                if let Some(cache) = &self.0.cache {
                    let _ = cache.put(&name, response.as_bytes());
                }
                let inner = self.0.clone();
                Ok(Box::new(move || {
                    lock(&inner.http_tokens).remove(&path);
                    if let Some(cache) = &inner.cache {
                        let _ = cache.delete(&name);
                    }
                }))
            }
            other => Err(format!(
                "acme/autocert: unknown challenge type {}",
                rust_stdlib::strconv::quote(other)
            )
            .into()),
        }
    }

    /// autocert's `HTTPHandler(nil)`: answers HTTP-01 challenges and
    /// redirects everything else to HTTPS.
    pub fn http_handler(&self) -> Arc<dyn http::Handler> {
        self.0.try_http01.store(true, Ordering::SeqCst);
        let manager = self.clone();
        http::handler_func(move |w, r| {
            if !r.url.path.starts_with("/.well-known/acme-challenge/") {
                handle_http_redirect(w, r);
                return;
            }
            if let Err(e) = manager.host_policy(&r.host) {
                http::http_error(w, &e.to_string(), 403);
                return;
            }
            match manager.http_token(&r.url.path) {
                Ok(data) => {
                    let _ = w.write(&data);
                }
                Err(e) => http::http_error(w, &e, 404),
            }
        })
    }

    fn http_token(&self, path: &str) -> Result<Vec<u8>, String> {
        if let Some(v) = lock(&self.0.http_tokens).get(path) {
            return Ok(v.clone());
        }
        let Some(cache) = &self.0.cache else {
            return Err(format!(
                "acme/autocert: no token at {}",
                rust_stdlib::strconv::quote(path)
            ));
        };
        cache
            .get(&http_token_cache_key(path))
            .map_err(|e| e.to_string())
    }

    /// autocert's `startRenew` and `domainRenewal`.
    fn start_renew(&self, domain: &str, not_before: i64, not_after: i64) {
        let mut renewal = lock(&self.0.renewal);
        if renewal.contains_key(domain) {
            return;
        }
        let next = self.next_renewal(not_before, not_after);
        renewal.insert(
            domain.to_string(),
            schedule_renewal(Arc::downgrade(&self.0), domain.to_string(), next),
        );
    }

    /// autocert's `domainRenewal.next`: when to renew, in seconds from now.
    fn next_renewal(&self, not_before: i64, not_after: i64) -> Duration {
        next_renewal(self.0.renew_before, not_before, not_after, now_unix())
    }

    /// autocert's `domainRenewal.do`.
    pub(super) fn renew(&self, domain: &str) -> Result<Duration, Error> {
        if let Ok(issued) = self.cache_get(domain, domain) {
            let next = self.next_renewal(issued.not_before, issued.not_after);
            if next > Duration::ZERO {
                self.replace(domain, issued);
                return Ok(next);
            }
        }
        let key = match lock(&self.0.state)
            .get(domain)
            .and_then(|s| lock(s).clone())
        {
            Some(issued) => issued.key.clone(),
            None => jws::generate_key()?,
        };
        let chain = self.authorized_cert(&key, domain)?;
        let issued = issue(key, chain)?;
        self.cache_put(domain, &issued.key, &issued.chain)?;
        let next = self.next_renewal(issued.not_before, issued.not_after);
        self.replace(domain, issued);
        Ok(next)
    }

    fn replace(&self, domain: &str, issued: Issued) {
        lock(&self.0.state).insert(
            domain.to_string(),
            Arc::new(Mutex::new(Some(Arc::new(issued)))),
        );
    }
}

fn schedule_renewal(inner: Weak<Inner>, domain: String, after: Duration) -> gotime::Timer {
    let weak = inner.clone();
    gotime::after_func(after.into(), move || {
        let Some(inner) = weak.upgrade() else { return };
        let manager = Manager(inner);
        let next = manager.renew(&domain).unwrap_or_else(|_| {
            let half_hour = 30 * 60;
            Duration::from_secs((half_hour + random_below(half_hour)) as u64)
        });
        let timer = schedule_renewal(Arc::downgrade(&manager.0), domain.clone(), next);
        lock(&manager.0.renewal).insert(domain.clone(), timer);
    })
}

/// autocert's `domainRenewal.next` for a certificate valid from
/// `not_before` to `not_after` (Unix seconds) at `now`.
pub fn next_renewal(renew_before: Duration, not_before: i64, not_after: i64, now: i64) -> Duration {
    let thirty_days = 30 * 24 * 60 * 60;
    let mut threshold = ((not_after - not_before) / 3).min(thirty_days);
    if !renew_before.is_zero() {
        threshold = (renew_before.as_secs() as i64).min(thirty_days);
    }
    let max_jitter = (threshold / 10).min(60 * 60);
    let jitter = random_below(max_jitter);
    let renew_at = not_after - (threshold - jitter);
    Duration::from_secs((renew_at - now).max(0) as u64)
}

fn http_token_cache_key(path: &str) -> String {
    format!("{}+http-01", rust_stdlib::path::base(path))
}

/// autocert's `handleHTTPRedirect`.
fn handle_http_redirect(w: &mut dyn http::ResponseWriter, r: &mut http::Request) {
    if r.method != "GET" && r.method != "HEAD" {
        http::http_error(w, "Use HTTPS", 400);
        return;
    }
    let host = match net::split_host_port(&r.host) {
        Ok((host, _)) => net::join_host_port(&host, "443"),
        Err(_) => r.host.clone(),
    };
    let target = format!("https://{host}{}", r.url.request_uri());
    http::redirect(w, r, &target, 302);
}

/// Builds the TLS certificate of a key and chain, with the leaf's validity.
fn issue(key: Key, chain: Vec<Vec<u8>>) -> Result<Issued, Error> {
    let leaf = x509::parse_certificate(chain.first().ok_or("acme/autocert: no public key found")?)?;
    let tls = Arc::new(tls::Certificate {
        certificate: chain.clone(),
        private_key: Some(tls::PrivateKey::Sec1(x509::marshal_ec_private_key(&key)?)),
        ..Default::default()
    });
    Ok(Issued {
        key,
        chain,
        not_before: leaf.not_before.unix_secs(),
        not_after: leaf.not_after.unix_secs(),
        tls,
    })
}

/// autocert's `validCert` for ECDSA keys: the chain parses, the leaf is
/// current, names `domain`, was not revoked in Let's Encrypt's 2022
/// incident, and holds `key`'s public half.
pub fn valid_cert(domain: &str, chain: &[Vec<u8>], key: &Key, now: i64) -> Result<(), Error> {
    let all: Vec<u8> = chain.concat();
    let certs = x509::parse_certificates(&all).map_err(|_| "acme/autocert: no public key found")?;
    let leaf = certs.first().ok_or("acme/autocert: no public key found")?;
    if now < leaf.not_before.unix_secs() {
        return Err("acme/autocert: certificate is not valid yet".into());
    }
    if now > leaf.not_after.unix_secs() {
        return Err("acme/autocert: expired certificate".into());
    }
    leaf.verify_hostname(domain)?;
    let lets_encrypt_fix_deploy = 1_643_158_080; // 2022-01-26T00:48:00Z
    if leaf.issuer.organization == ["Let's Encrypt"]
        && leaf.not_before.unix_secs() < lets_encrypt_fix_deploy
    {
        return Err("acme/autocert: certificate was probably revoked by Let's Encrypt".into());
    }
    match &leaf.public_key {
        Some(x509::PublicKey::Ecdsa(public)) => {
            if public.x != key.public_key.x || public.y != key.public_key.y {
                return Err("acme/autocert: private key does not match public key".into());
            }
            Ok(())
        }
        Some(x509::PublicKey::Rsa(_)) => {
            Err("acme/autocert: private key type does not match public key type".into())
        }
        _ => Err("acme/autocert: unknown public key algorithm".into()),
    }
}
