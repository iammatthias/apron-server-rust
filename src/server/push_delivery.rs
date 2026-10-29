//! Push delivery (§4.9): the queues, lanes and concurrency limits behind
//! PushDeliverer, which posts payloads to relays and Web Push services.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;

use rust_stdlib::concurrent::WaitGroup;
use rust_stdlib::context::Context;
use rust_stdlib::net::http::client::Client;
use rust_stdlib::net::http::header::{BoxError, ERR_USE_LAST_RESPONSE};
use rust_stdlib::net::http::Request as HttpRequest;
use rust_stdlib::net::url;
use rust_stdlib::time::{self};

use super::outbound::{self};
use super::push::{
    PushRegistration, MAX_CONCURRENT_PUSH_POST, MAX_PUSH_PER_HOST, MAX_PUSH_QUEUED,
    MAX_PUSH_QUEUED_PER_HOST, MAX_PUSH_QUEUED_PER_USER, MAX_PUSH_RESPONSE_DRAIN, PUSH_TIMEOUT,
};
use super::webpush::{self, VapidKey};

/// What a delivery reports its outcome to: the endpoint's status code, or 0
/// for a delivery dropped beyond a queue bound or one that got no answer.
pub type DoneFn = Box<dyn FnOnce(u16) + Send>;

/// Go's buffered channel used as a semaphore.
struct Semaphore {
    held: Mutex<usize>,
    cv: Condvar,
    max: usize,
}

impl Semaphore {
    fn new(max: usize) -> Arc<Semaphore> {
        Arc::new(Semaphore {
            held: Mutex::new(0),
            cv: Condvar::new(),
            max,
        })
    }

    fn acquire(self: &Arc<Self>) -> Permit {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        while *held >= self.max {
            held = self.cv.wait(held).unwrap_or_else(|e| e.into_inner());
        }
        *held += 1;
        Permit(self.clone())
    }
}

struct Permit(Arc<Semaphore>);

impl Drop for Permit {
    fn drop(&mut self) {
        *self.0.held.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
        self.0.cv.notify_one();
    }
}

/// A delivery's registration, as it was when the delivery was handed over,
/// its payload, and what it reports to.
struct QueuedPush {
    registration: PushRegistration,
    payload: Vec<u8>,
    done: Option<DoneFn>,
}

/// Bounds concurrent deliveries to one push host; queued counts the
/// deliveries waiting for it or running, so an unused lane is forgotten.
struct PushLane {
    slots: Arc<Semaphore>,
    queued: usize,
}

#[derive(Default)]
struct Queues {
    queued: usize,
    users: BTreeMap<String, usize>,
    hosts: BTreeMap<String, PushLane>,
    /// Each badge delivery that has not started, by registration, so a
    /// newer count replaces its payload and its done.
    latest: BTreeMap<String, Arc<Mutex<QueuedPush>>>,
}

/// POSTs push payloads in the background, off the paths that deliver
/// messages. Each push host has its own lane of bounded concurrency and
/// queue, so a slow or stalling host delays only pushes to itself. Unless
/// insecure pushes are allowed, it refuses to connect to loopback, private,
/// link-local, and other non-public addresses, checked on the dialed
/// address so DNS cannot redirect it.
pub struct PushDeliverer {
    client: Client,
    slots: Arc<Semaphore>,
    pending: WaitGroup,
    /// Signs webpush deliveries, with subject as their contact.
    pub vapid: OnceLock<Arc<VapidKey>>,
    pub subject: String,
    queues: Mutex<Queues>,
}

impl PushDeliverer {
    pub fn new(allow_internal: bool, subject: String) -> Arc<PushDeliverer> {
        let check = if allow_internal {
            outbound::any_address()
        } else {
            outbound::public_only()
        };
        let check_redirect: rust_stdlib::net::http::client::CheckRedirect =
            Arc::new(|_, _| Err(Box::new(ERR_USE_LAST_RESPONSE) as BoxError));
        let client = outbound::client(check, PUSH_TIMEOUT, check_redirect, |transport| {
            // Push services serve many pushes over one HTTP/2 connection.
            transport.force_attempt_http2 = true;
            transport.max_idle_conns_per_host = MAX_PUSH_PER_HOST as i64;
        });
        Arc::new(PushDeliverer {
            client,
            slots: Semaphore::new(MAX_CONCURRENT_PUSH_POST),
            pending: WaitGroup::new(),
            vapid: OnceLock::new(),
            subject,
            queues: Mutex::new(Queues::default()),
        })
    }

    fn queues(&self) -> std::sync::MutexGuard<'_, Queues> {
        self.queues.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The host lanes in use and the deliveries waiting or running for a
    /// user, for the tests.
    #[cfg(test)]
    pub(crate) fn lanes(&self) -> usize {
        self.queues().hosts.len()
    }

    #[cfg(test)]
    pub(crate) fn queued_for(&self, user_id: &str) -> usize {
        self.queues().users.get(user_id).copied().unwrap_or(0)
    }

    /// POSTs payload to a registration's url. With latest, the key of a
    /// badge delivery, a delivery for the same key that has not started
    /// takes the registration, as registered now, payload, and done in place
    /// of its own, and the replaced done is never called. done receives the
    /// endpoint's status code, or 0 for a delivery dropped beyond the
    /// user's, the host's, or the server's queue bound, or one that gets no
    /// answer.
    pub fn deliver(
        self: &Arc<Self>,
        registration: PushRegistration,
        payload: Vec<u8>,
        urgency: &'static str,
        latest: String,
        done: DoneFn,
    ) {
        let Ok(parsed) = url::parse(&registration.url) else {
            self.dropped(done);
            return;
        };
        let host = parsed.host.to_lowercase();
        let mut queues = self.queues();
        if !latest.is_empty() {
            if let Some(waiting) = queues.latest.get(&latest) {
                let mut waiting = waiting.lock().unwrap_or_else(|e| e.into_inner());
                waiting.registration = registration;
                waiting.payload = payload;
                waiting.done = Some(done);
                return;
            }
        }
        let user_id = registration.user_id.clone();
        if queues.queued >= MAX_PUSH_QUEUED
            || queues.users.get(&user_id).copied().unwrap_or(0) >= MAX_PUSH_QUEUED_PER_USER
            || queues
                .hosts
                .get(&host)
                .is_some_and(|lane| lane.queued >= MAX_PUSH_QUEUED_PER_HOST)
        {
            drop(queues);
            self.dropped(done);
            return;
        }
        queues.queued += 1;
        *queues.users.entry(user_id.clone()).or_default() += 1;
        let lane = queues
            .hosts
            .entry(host.clone())
            .or_insert_with(|| PushLane {
                slots: Semaphore::new(MAX_PUSH_PER_HOST),
                queued: 0,
            });
        lane.queued += 1;
        let lane_slots = lane.slots.clone();
        let waiting = Arc::new(Mutex::new(QueuedPush {
            registration,
            payload,
            done: Some(done),
        }));
        if !latest.is_empty() {
            queues.latest.insert(latest.clone(), waiting.clone());
        }
        drop(queues);
        self.pending.add(1);
        let deliverer = self.clone();
        thread::spawn(move || {
            {
                // The host's lane first, then a shared slot: a stalled host
                // holds at most its lane's share of the slots.
                let _lane = lane_slots.acquire();
                let _slot = deliverer.slots.acquire();
                let (registration, payload, done) = {
                    let mut queues = deliverer.queues();
                    if !latest.is_empty() {
                        queues.latest.remove(&latest);
                    }
                    let mut waiting = waiting.lock().unwrap_or_else(|e| e.into_inner());
                    (
                        waiting.registration.clone(),
                        std::mem::take(&mut waiting.payload),
                        waiting.done.take(),
                    )
                };
                let status = deliverer.post(&registration, &payload, urgency);
                if let Some(done) = done {
                    done(status);
                }
            }
            deliverer.release(&user_id, &host);
            deliverer.pending.done();
        });
    }

    /// One delivery's POST, and the status it was answered with, 0 for none.
    fn post(&self, registration: &PushRegistration, payload: &[u8], urgency: &str) -> u16 {
        let (ctx, cancel) = Context::background().with_timeout(PUSH_TIMEOUT);
        let status = match self.request(&ctx, registration, payload, urgency) {
            Ok(request) => match self.client.do_request(request) {
                Ok(response) => {
                    if let Some(body) = &response.body {
                        // Reading the answer lets the connection be reused.
                        let _ = std::io::copy(
                            &mut body.clone().take(MAX_PUSH_RESPONSE_DRAIN),
                            &mut std::io::sink(),
                        );
                        let _ = body.close();
                    }
                    response.status_code
                }
                Err(_) => 0,
            },
            Err(_) => 0,
        };
        cancel();
        status
    }

    /// Tells done of a delivery dropped before it started, apart, since the
    /// caller may hold the lock done takes.
    fn dropped(&self, done: DoneFn) {
        let pending = self.pending.clone();
        pending.add(1);
        thread::spawn(move || {
            done(0);
            pending.done();
        });
    }

    /// Builds a delivery (§4.9), with TTL and Urgency for every kind.
    /// relay: the payload as JSON, or, with keys, encrypted as for webpush,
    /// with the token, if any, as bearer. webpush (RFC 8030): the payload
    /// encrypted for the subscription (RFC 8291), with a VAPID Authorization
    /// (RFC 8292).
    fn request(
        &self,
        ctx: &Context,
        registration: &PushRegistration,
        payload: &[u8],
        urgency: &str,
    ) -> Result<HttpRequest, BoxError> {
        let (body, content_type) = match &registration.keys {
            Some(keys) => (
                webpush::encrypt_push(payload, keys)?,
                "application/octet-stream",
            ),
            None => (payload.to_vec(), "application/json"),
        };
        let mut request = HttpRequest::new("POST", &registration.url)?
            .with_body(body)
            .with_context(ctx);
        request.header.set("Content-Type", content_type);
        if registration.keys.is_some() {
            request.header.set("Content-Encoding", "aes128gcm");
        }
        request.header.set("TTL", webpush::PUSH_TTL);
        request.header.set("Urgency", urgency);
        if registration.kind == "webpush" {
            let (Some(vapid), Some(_)) = (self.vapid.get(), &registration.keys) else {
                return Err("webpush needs a VAPID key and subscription keys".into());
            };
            let authorization =
                vapid.authorization(&registration.url, &self.subject, &time::now())?;
            request.header.set("Authorization", &authorization);
        } else if !registration.token.is_empty() {
            request
                .header
                .set("Authorization", &format!("Bearer {}", registration.token));
        }
        Ok(request)
    }

    /// Ends a delivery's accounting, forgetting an unused host lane.
    fn release(&self, user_id: &str, host: &str) {
        let mut queues = self.queues();
        queues.queued -= 1;
        if let Some(n) = queues.users.get_mut(user_id) {
            *n -= 1;
            if *n == 0 {
                queues.users.remove(user_id);
            }
        }
        if let Some(lane) = queues.hosts.get_mut(host) {
            lane.queued -= 1;
            if lane.queued == 0 {
                queues.hosts.remove(host);
            }
        }
    }

    pub fn wait(&self) {
        self.pending.wait();
    }
}
