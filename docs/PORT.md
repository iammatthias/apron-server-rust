# Port plan and log

Source: apron-server-go at `f137c64`, protocol v9 (`testdata/apron` at
`233ec54`).

## Definition of done

`aprond` built from this repository passes the Go repository's browser
interop suites (`desktop`, `mobile`, `push`) through `tools/interop/run.sh`.
The behavior tests ported from the Go `*_test.go` files pass under
`cargo test`. Every remaining difference is listed in `docs/DEVIATIONS.md`.

## Phases

Each phase ends at a gate. A phase is not done until its gate ran and passed.

| # | Scope (Go files) | Gate | Status |
|---|---|---|---|
| 0 | Scaffold, spikes: rust-stdlib resolves as a dependency, WebSocket over a hijacked connection, JSON round trip of unknown keys | Spike binary echoes over WS to Node's client | done |
| 1a | `store/*`, `ws.rs`, `rate.rs`, `protocol.go`, `server.go`, `users.go`, `rooms.go`, `messages.go`, `persist.go`, `unread.go`, and the model half of `status.go` | Ported `store_test`, `protocol_test`, `server_test`, `persist_test` (see "Tests held for later phases" below) | done |
| 1b | The `status` request of `status.go`, `commands.go`, `embeds.go` | Ported `status_test`, `reference_test`, `limits_test`, `ext_test`, and the held tests below; interop `chat`, `responsive`, `reference`, `seen` | done, except interop `seen`, whose two tests sign up with a passkey (2a; rerun after the merge below) |
| 2a | `webauthn.go` | Ported `webauthn_test`, `fixtures/webauthn.json`; interop `webauthn` | done: `src/server/webauthn.rs`, `src/server/tests/webauthn_test.rs`, cross-open (`tools/crossopen/run.sh`), interop `webauthn` |
| 2b | `email.go`, `cmd/aprond/email.go` | Ported `email_test`s | done: `src/server/email.rs`, `src/server/tests/email_test.rs` (all 18 run, the 3 that register passkeys since the merge with 2a), email smoke against Go below. The SMTP sender of `cmd/aprond/email.go` is `src/aprond/email.rs`, merged in phase 3 |
| 2c | `push.go`, `webpush.go` | Ported `push_test`, `webpush_test`, `fixtures/push.json`; interop `push` | done, except interop `push`, 3 of 4, held by the idle-connection gap in "Pending rust-stdlib fixes" (see "Web Push" below): `src/server/push.rs`, `src/server/webpush.rs`, `src/server/tests/push_test.rs` (26), `webpush_test.rs` (4), `push_fixture_test.rs`, the Web Push differential |
| 3 | `cmd/aprond/main.go`, `config.go`: flags, TOML, `--print-config`, static dir, TLS, ACME, debug listener, signals | Ported `config_test`; ACME against Pebble | done: helpers in `src/aprond`, `run` in `src/bin/aprond/main.rs`, static dir in `server.rs`; `config_test`, `email_test`, `TestHTTPEndpoints`, `tests/aprond.rs` against the Go binary, and the Pebble gate (with `PEBBLE_BIN_DIR`) pass. Real-binary checks below. Adds the `--apple.app-id` extension |
| 4 | Whole-branch review (`/pstack:thermos`), fixes | All gates green | |

Phases 2a, 2b, and 2c run in parallel once phase 1 lands.

## Decisions

| Date | Decision | Why |
|---|---|---|
| 2026-10-27 | The tests and tools find the Go clone through `APRON_GO_DIR`, and keep the clone unmodified. | Tests read fixtures and run Go comparisons from the clone at the commit `UPSTREAM` pins. |
| 2026-10-27 | rust-stdlib comes in through a local git URL on the `dogfood/apron` branch. | A path dependency would follow whatever branch that checkout has open. The git dependency pins a commit in `Cargo.lock`, and fixes reach this crate only after a merge into `dogfood/apron`. |
| 2026-10-27 | `Cargo.lock` is updated only with `cargo update -p <crate>`. | The lock was first seeded with the yanked `crypto-bigint 0.7.5`; `fix/crypto-bigint-yank` moved it to 0.7.10, so that caveat is gone, but a targeted update keeps every other pin where the last gate left it. |
| 2026-10-27 | Thread per connection, with one `Mutex` guarding server state, as the Go server's `s.mu` does. | rust-stdlib has no async runtime. Keeping Go's locking shape makes the port checkable line by line against the Go source. |
| 2026-10-27 | The browser gate runs the Go repository's Playwright suites through a `go` shim on `PATH`. | This reuses the real web client and the Go suites without changing the clone. |
| 2026-10-27 | Go's `Server` is `Arc<Server>` with one `Mutex<State>` in place of `s.mu`. Every `*Locked` Go method is a method on `State`; every method that takes the lock is on `Server`. `Server::lock()` returns a guard whose `Drop` runs `flush_locked`, Go's `s.unlock()`. | Timer callbacks (`time::after_func`) and the per-connection writer and ping threads capture the `Arc`. The flushing guard keeps the invariant that every release of the lock writes the dirty state to the store, without a `defer s.unlock()` at each site. |
| 2026-10-27 | Go's pointer graph is normalized under the lock: `records: BTreeMap<i64, LogRecord>` keyed by log_id; a room's `log` and a message's `records` are `Vec<i64>`; `parent`, `children`, `members`, `joined`, `creator`, `owner` are IDs (`String`, `BTreeSet<String>`). `UserState` has a `generation` counter so a timer callback can check it fires for the identity it was scheduled for, as Go's `s.users[u.id] == u` does. | Go's `redactLocked` rewrites one `*logRecord` that two room logs and a message share; ID references give the same single owner without `Rc<RefCell>`. The IDs are what persist.go stores already. BTreeSet keeps a deterministic order where Go sorts map keys. |
| 2026-10-27 | Wire values are one dynamic `protocol::Json` enum (`Null`, `Bool`, `Number(f64)`, `String`, `Array`, `Object(BTreeMap)`, `Ext(BTreeMap<String, jsontext::Value>)`) with a hand-written `MarshalTo`; the `stored*` types of persist.go are structs with the `MarshalTo`/`UnmarshalFrom` derives of `rust-stdlib-derive`. | Go keeps everything on the wire as `map[string]any` and only persist.go is typed, so the port is typed in the same places. rust-stdlib's `json::Any` cannot hold an ext value as raw bytes, which §4.12 needs so numbers beyond 2^53 and keys such as `__proto__` round-trip byte for byte; the `Ext` variant is that raw object. `BTreeMap` gives `json.Deterministic` ordering. |
| 2026-10-27 | A connection is `Arc<Client>` (the outgoing `sync_channel`, `closing`/`pinged`/`last_frame` atomics, the WebSocket) plus a `State`-guarded `Conn { client, user: Option<String>, idle }` in `State.clients`. `LogRecord.raw` and rendered frames are `Arc<[u8]>`. | Go guards `c.user` and `c.idle` with `s.mu` and reads the rest lock-free; the split keeps that. Shared byte slices let `deliverLocked` render once for many connections, as Go does. |
| 2026-10-27 | Passkey state is ID-normalized like the rest: a user's `passkey` is `Option<PasskeyUser { handle, credentials }>`; Go's `credentials` map is `State.credentials: credential ID -> user_id`, and Go's `passkeys` map is the users whose `passkey` is set. Sessions are `State.sessions: SHA-256 of token -> Session { user, origin, expires }`; a connection's pending ceremony and token hash live on its `Conn`. One borrowed view implements `webauthn::User` for both Go's `passkeyUser` and `labelledPasskeyUser`. | Go's passkeyUser points back at its user and both maps share it; the IDs give the same single owner. A successful login updates the stored credential's counter in memory without touching the user, as Go does, so it reaches the store with the user's next change. |
| 2026-10-27 | Phase 1a runs with push disabled, no WebAuthn, no email sender, and no upload directory, whatever the config asks, and the `status` and `command` operations answer `codeUnsupported`. The function names of those seams are Go's, so phases 1b and 2 fill them in place. Phase 1b brought the upload directory, `status`, and `command`; phases 2a and 2b lifted the WebAuthn and email overrides; phase 2c lifted the push override. | The Go server with those features disabled is exactly what phase 1a can test. See `docs/DEVIATIONS.md` for the client-visible effects, each marked as interim. |
| 2026-10-27 | Hosted embeds (embeds.go) key by id, as the rest of the graph does: `State.embeds` holds each `EmbedState`, `writes` maps an unused write token to its embed, and `uploads` is a `BTreeSet<(seq, embed_id)>` in place of Go's `container/list`, oldest first. Go's `e.removed` flag is gone: a handler that drops the lock around body IO re-locks and looks the embed up again, and absence is removal. A stream is an `Arc<StreamBuffer>` (one `Mutex`, one `Condvar`, a change counter in place of Go's replaced `changed` channel) shared by the embed, the writer's body thread, the max-duration timer, and each reader. | Go holds `*embedState` pointers across lock drops and needs the flag to notice a removal; lookups by id give the same answer without a second source of truth. |
| 2026-10-27 | `golang.org/x/image/webp` is not Go's standard library, so rust-stdlib has no WebP. aprond only ever calls `image.DecodeConfig` on uploads (dimensions and format; never pixels), and x/image's configuration path is the RIFF container, the VP8 key frame header, the VP8L header, and the VP8X chunk, about 150 lines. `src/webp.rs` ports exactly that and registers "webp" with rust-stdlib's `image` under Go's magic, with a `decode` that fails. No crate, no allowlist row, no deviation: the accept and reject edges are x/image's, and the Go test's WebP vector (`TestAvatarUploadsMustBeImages`) passes. | A WebP crate would decode pixels nobody asks for, need an allowlist row, and have its own idea of a malformed header. |
| 2026-10-27 | Email proposals live in `State.email.proposals`, keyed by a counter; `Conn.proposal` and `EmailState.links` hold the key, and Go's `dropped` flag is the key's absence. `detach_locked` drops a closed connection's proposal unless a link names it. `container/list` is `email::Lru`, a map plus a tick-ordered index. Delivery slots are an `AtomicUsize` that only the lock holder increments; `Server.mailing` is Go's `s.mailing`. | The same pointer-to-ID normalization as the rest of the state. Go's garbage collector frees an unlinked proposal when its connection goes; here `detach_locked` does it. |
| 2026-10-27 | Phase 2b ported the bearer token sessions email sign-in needs (`Session`, `State.sessions`, `Conn.token`, `sign_in_locked`, `prune_sessions_locked`, `authenticate_token`, session persistence) under Go's names, matching phase 2a's text, with the email fallback in `authenticate_token`. | `approveLocked` signs in through `signInLocked`, and a token resume is part of the 2b gate. The merge of 2b into 2a took 2a's versions and kept the `may_approve_locked` branch, as in Go's `authenticateToken`. |
| 2026-10-27 | `EmailSender::send_sign_in_code(&Context, &SignInEmail)` is Go's interface. `src/aprond/email.rs`'s `SmtpSender::send_sign_in_code(ctx, to, code, add, text)` is adapted to it by `SmtpEmailSender` in `src/bin/aprond/main.rs`. | Keeps `SignInEmail` (and `text()`) the server's type, as in Go. |
| 2026-10-27 | `github.com/go-webauthn/webauthn` v0.18.2 becomes `src/webauthn/` (Go `webauthn` package) and `src/webauthn/protocol/` (Go `protocol`, with `webauthncose`), ported for the subset aprond calls. The Go-to-Rust map is the table at the top of `src/webauthn/mod.rs`. | Phase 2a ports `internal/server/webauthn.go` call for call against it. |
| 2026-10-27 | CBOR is a hand-written strict decoder, `src/cbor.rs`, with the options go-webauthn gives fxamacker/cbor (`webauthncbor`): definite lengths only, no tags, duplicate keys rejected, depth 5, 131072 items, valid UTF-8, trailing bytes rejected by `unmarshal`. It decodes in fxamacker's two passes and reproduces its struct, `map[string]any` and `any` rules, and re-encodes credential public keys as CTAP2 canonical CBOR as Go stores them. | WebAuthn needs a small, fixed subset; a third-party crate would need an allowlist row and would not share fxamacker's accept/reject edges, which the differential pins. |
| 2026-10-27 | Attestation: `none` and `packed` self attestation are verified as Go verifies them. `packed` with `x5c`, `tpm`, `android-key`, `android-safetynet`, `fido-u2f`, `apple` and `compound` are rejected as unsupported (docs/DEVIATIONS.md). | Without a metadata service go-webauthn accepts all of them, but aprond leaves the conveyance preference unset (`none`), and a conforming client then replaces every statement but self attestation with `none` (§5.4.7). Porting X.509 chain, TPM, SafetyNet JWT and Android key description checks would serve only clients that ignore the preference. |
| 2026-10-27 | Options and `Credential` serialize through `encoding::json::v2` derives, to the bytes Go's `encoding/json/v2` writes with aprond's options. Responses parse with `encoding/json` v1 rules, as go-webauthn parses them, and `Credential` reads back through v1 as Go's `Credential.UnmarshalJSON` does. | The browser receives Go's option JSON, and the store keeps Go's credential JSON. |
| 2026-10-27 | Push registrations stay in one map, `State.pushes`, keyed by Go's `pushKey` (user_id, a space, url), so a user's registrations are a key range ordered by url, Go's `sortedPushes`. Each registration takes a `generation` from `State.next_generation`; a delivery's outcome (in flight, the accepted count, removal on 404 or 410) applies only when the registration under its key still has that generation. | Go keeps the registration in `u.pushes` and `s.pushes` and compares pointers in `removePushLocked` and the `done` closure, so a late answer for a replaced registration changes nothing. One map and a generation give the same answer, as `UserState.generation` does for timers. |
| 2026-10-27 | The push deliverer is a thread per delivery, as Go starts a goroutine, waiting on the host's lane and then on the shared slots; both are counting semaphores (a `Mutex` and a `Condvar`) in place of Go's buffered channels. Its transport is `rust_stdlib_sysnet::transport()` with Go's settings (10 s timeouts, HTTP/2 attempted, 8 idle connections per host), no proxy, and a `rust_stdlib_sys::net::Dialer` whose `control` refuses non-public dialed addresses, as Go's `Dialer.Control` does. `rust-stdlib-sys` became a direct dependency for that `Dialer`; the root crate's `Dialer.control` is unsupported. | Go's `http.Transport` has no `Proxy`; the environment's proxy would carry pushes past the check on the dialed address. |
| 2026-10-27 | `Server.badges` and the deliverer's `pending` are `WaitGroup`s, as in Go: a badge timer adds one when scheduled and finishes it when its callback returns, or when `stop_badge_locked` stops it before it fires. `shutdown` sets `Server.stopped`, which ends the hourly sweep, and waits for the connections, the badge timers, the deliveries, and the mail, in Go's order. The badge delay is `State.badge_delay`, which the tests set as Go's set `app.badgeDelay`. | Without the count, a shutdown with a pending badge (`TestShutdownCancelsPendingBadges`) would wait out its hour. |
| 2026-10-27 | WebAuthn gates: `tests/webauthn_differential.rs` replays vectors that `tools/differential/webauthn` (its own `go.mod`, go-webauthn v0.18.2) records from a software authenticator: 127 registrations (P-256, P-384, P-521, Ed25519, RSA PKCS #1 v1.5 and PSS; valid and mutated), 57 assertions, the creation and request options byte for byte after normalizing the challenge, and the fixture's credential. Verdict, error type, details and info, and the stored credential bytes must match, except the seven attestation deviations, which must fail. `tests/webauthn_fixture.rs` checks `fixtures/webauthn.json`: our options carry every member it shows with its value, except a random `challenge`, the ten-entry `pubKeyCredParams`, and the `attestation` and empty `allowCredentials` members Go omits; its finish credential parses and fails at its synthetic attestation, as in Go. Regenerate vectors with `go run . > vectors.json` in `tools/differential/webauthn`. Both tests encode with the server's own `protocol::encode_json`, so they compare the bytes the server sends and stores. | The fixture holds wire shapes with synthetic bytes, so it cannot be a byte gate; the differential is. |
| 2026-10-27 | cmd/aprond's helpers live in `src/aprond/` as library modules; `src/bin/aprond/main.rs` keeps only `main` and `run`. | The core wires the server in `run`; options, config, email, ACME, listener and debug code need no server types and merge without touching `src/server`. |
| 2026-10-27 | go-flags is ported as a small parser in `src/aprond/options.rs`, not built on rust-stdlib's `flag`. | rust-stdlib's `flag` is Go's `flag`, and main.go uses go-flags, which differs in four ways a user sees: it keeps parsing after a non-option argument, its error texts differ (``unknown flag `x'``, ``expected argument for flag `--addr'``), it has `choice` validation and namespaced groups, and its `--help` layout differs. Conversions still use rust-stdlib's `strconv`, so the embedded `strconv.ParseInt` texts are Go's. |
| 2026-10-27 | TOML decoding uses the `toml` crate (`=1.1.8`, `parse` and `serde` features); `--print-config` uses a hand-written encoder. | A hand-written strict decoder would reject files Go accepts wherever it misses part of the TOML grammar (multi-line and literal strings, dotted keys, inline tables, numbers with underscores, dates). The encoder side is five value shapes, so it is written out to match BurntSushi's `dblQuotedReplacer` and layout exactly. Every decoded value goes through Go's `fmt.Sprint` and back through the option's `Set`, as config.go does, so `addr = 9000` and `max-mb = 5.0` behave as in Go. |
| 2026-10-27 | `serverConfig` is `settings::server_settings`, returning `Settings`, a mirror of the `server.Config` fields it sets. | `server.Config` belongs to the core. The mirror lets the five `serverConfig` tests of config_test.go run here with Go's check order and messages; the core maps `Settings` onto `server::Config` and builds WebAuthn from `Settings.webauthn`. |
| 2026-10-27 | `SmtpSender::send_sign_in_code` takes `to`, `code`, `add` and the rendered `text` rather than a `server::SignInEmail`. | It keeps `src/aprond` free of server types. The core's `EmailSender` adapter passes `m.text()`. |
| 2026-10-27 | `limit_listener` releases a slot when a connection is closed or dropped. | Go releases only on `Close`; a Rust connection dropped without `close` is closed too, so not releasing it would leak the slot. |
| 2026-10-27 | `--help` and `--print-config` are compared byte for byte with the Go `aprond` by `cargo test` (`test_help_and_errors_match_go`, `test_print_config_matches_go`) always, against the Go clone. Since phase 3 they live in `tests/aprond.rs` and run the built binary, next to `test_startup_errors_match_go`, which compares the errors `run` stops with (log times dropped). | The comparison is the gate for go-flags' layout and BurntSushi's encoder. Without `go` or the clone the tests fail, unless `APRON_SKIP_GO=1`; a skipped run prints `SKIPPED` and does not count as the gate passing (AGENTS.md, Verification). |
| 2026-10-27 | `run` is Go's: `server_settings`, then `server_config` maps `Settings` onto `server::Config` (counts at or below 0 become 0, Go's unlimited) and builds WebAuthn. `signal::notify_context` from `rust-stdlib-sys` watches SIGINT and SIGTERM under a cancellable parent context; each `http::Server` serves on its own thread, and the first serve error other than `ERR_SERVER_CLOSED` cancels the parent, as errgroup does. Shutdown gives `Server::shutdown` and each `http::Server::shutdown` one 10-second context. The text handler logger is `run`'s own; the server keeps `slog::default`, as Go's does. | The errgroup and `NotifyContext` pair is one context in Go; here the parent context carries the errgroup half. |
| 2026-10-27 | autocert is ported as `aprond::acme`: an RFC 8555 client (`client.rs`), ES256 JWS and challenge certificates over rust-stdlib-crypto (`jws.rs`), `DirCache` (`cache.rs`) and `Manager` (`manager.rs`). | golang.org/x/crypto is not Go's standard library, so rust-stdlib has no counterpart. The port keeps autocert's cache names (`<domain>`, `<domain>+token`, `<token>+http-01`, `acme_account+key`) and file layout (PEM key, then the PEM chain), so a cache directory moves between the Go and Rust aprond. `tools/differential/acme` checks thumbprints, key authorizations, JWS signatures, the TLS-ALPN-01 certificate, and cache files in both directions against x/crypto/acme v0.57.0. |
| 2026-10-27 | The ACME gate runs Pebble v2.10.1 and pebble-challtestsrv from `cargo test` (`acme::pebble_test`). The test fails when they are missing, unless `APRON_SKIP_PEBBLE=1`; AGENTS.md, Verification, gives the install command and the lookup order (`$PEBBLE_BIN_DIR`, `PATH`, `$(go env GOPATH)/bin`). | It issues over TLS-ALPN-01 through a real handshake, verifies the chain against Pebble's root, reuses the certificate, renews it, and has Go's autocert read the cache. Pebble's validator sends HTTP-01 requests with `Host: <domain>:5002`, which `HostWhitelist` rejects in Go and here alike, so HTTP-01 is checked by the handler tests, not against Pebble. |

## Passkeys for a native iOS client

A native iOS app signs in with the server's passkeys when the app and the
domain name each other. The app's Associated Domains entitlement lists
`webcredentials:<domain>`. The server, an extension Go lacks
(docs/DEVIATIONS.md), lists the app at
`https://<domain>/.well-known/apple-app-site-association`. Start `aprond`
with all three of:

```sh
aprond --webauthn.rp-id <domain> \
  --webauthn.origin https://<domain> \
  --apple.app-id <team ID>.<bundle ID>
```

Apple fetches the file over HTTPS from the domain itself, through its CDN,
so the server must answer on port 443 for `<domain>`, directly with
`--tls.domain` or behind a proxy. Repeat `--webauthn.origin` to keep the
web client's origins, and `--apple.app-id` for each app, such as a
development build with its own bundle ID.

The native client gets its bearer token from another signed-in client,
with `/add-device [label]`, an extension Go lacks (docs/DEVIATIONS.md). Run
it in the web client while signed in with a passkey or email. The
`~private` reply holds the token and the origin, each in a code block with
a Copy button. The app stores both, sends that origin as its `Origin`
header, and authenticates with `{"scheme": "token", "token": ...}` (§3.2).
The token resumes the account only from that origin, and lapses after 30
days unused. No command revokes one token: it ends when unused for 30 days,
or when the app signs in again on a connection holding it. An account adds
five devices at once, then one each 12 minutes.

## Smoke check

`tools/smoke/run.sh` runs both sessions below against both servers and
compares them, as AGENTS.md's gate 3 describes. The rest of this section
records the runs made by hand before it existed.

`tools/smoke/session.mjs` runs one guest session with Node 22's WebSocket
(guest auth, a message with an ext, a timed mute, a room mute set and
cleared, /help, an unknown command, a message with an upload embed and the
upload's PUT, history, room_list, ping) and prints every frame. Run it
against `go run ./cmd/aprond --store memory --addr 127.0.0.1:8081
--push.disable --webauthn.rp-id= --upload.dir <tmp>` in the Go clone and
against `aprond --store memory --addr 127.0.0.1:8082 --webauthn.rp-id=`
(passkeys are on by default since phase 2a), then compare the two
transcripts with `node tools/smoke/compare.mjs go.txt rust.txt`. It maps
each distinct log_id to its order of first appearance, so it checks that
every frame names the same record relative to the others, where masking
the ids would hide a frame naming an older record; the listen address,
write tokens, and file secrets are masked. The phase 1a transcripts compare
identical under it, and so do the phase 1b ones (33 lines). After the merge
of phase 1b with phases 2a and 2b they compared identical again, 33 lines,
with the Go server on `--store sqlite:<tmp>/go.db --upload.dir <tmp>/up`.

The same session also checked the SQLite store in both directions: a
database the Go server wrote, opened by this `aprond`, served the Go-era
room record, message, and the retired guest's leave, and assigned `guest_2`;
a database this `aprond` wrote did the same under the Go server, which also
found its `meta/vapid` entry untouched.

The email session, `tools/smoke/email.mjs`, reads codes from the server
log: connection A proposes and signs in with a code, B resumes with the
bearer token, and C, a guest, adds an address. After phases 2a and 2b were
merged, it ran against the Go `aprond` with `--store sqlite:<tmp>/go.db
--upload.dir <tmp>/up --addr 127.0.0.1:8081 --email.enable --email.sender
log --email.link-url http://127.0.0.1:8081/login --push.disable` and this
`aprond` with `--store memory --addr 127.0.0.1:8082 --email.enable
--email.sender log --email.link-url http://127.0.0.1:8081/login`, passkeys
at their defaults on both. `compare.mjs` found the 28-line transcripts
identical, the server frames included: both list `auth` as `webauthn`,
`email`, `token`, `guest` and `signup` as `webauthn`, `email`, `guest`.
The script prints each connection's frames together, since the order
across connections depends on scheduling. After the merge with phase 1b, the
same two commands gave identical 28-line transcripts again.

After the merge of phase 3 into 2c, both scripts ran against the Go and
the Rust `aprond` with the same flags, `--store sqlite:<tmp>/aprond.db
--upload.dir <tmp>/up --push.disable` (plus the email flags above for
`email.mjs`), and compared identical: 33 and 28 lines. `cargo test` passed
312 with 1 ignored (`TestNamesAreNormalized`), Pebble and the Go
comparisons included, three runs in a row, and `tools/interop/run.sh`
passed 43 of 44, the failure being push.spec.ts:257 (Web Push below).

## aprond end to end

After phase 3 the built `aprond` was checked against the Go `aprond` (built
from the clone), each with a temp `--store` and `--upload.dir`:

- `--print-config` with a temp store, upload and cache directory: `diff`
  shows only the trailing `[apple]` group (5 lines) after Go's 123.
  `tests/aprond.rs` also compares `--help`, flag and TOML errors, and the
  errors `run` stops with (busy port, unknown store, `sqlite:` without a
  path, a file that is not a database, a bad role, VAPID subject, and
  insecure push).
- A `--config` file setting `addr`, `store`, `static-dir` and
  `[upload] dir` serves, in `test_config_file_and_static_dir`.
- `--static-dir` on the web client's build (`.apron-web/build`): `/`,
  `/index.html` (301 to `./`), `/manifest.webmanifest`, an immutable
  entry chunk, `/service-worker.js`, `/_app/` (404) and an unknown path
  give the same status, content type, redirect and body from both.
  `/.well-known/apple-app-site-association` is 404 in Go and, with
  `--apple.app-id`, the JSON document here.
- SIGTERM and SIGINT end both servers in under 10 ms with status 0. With a
  WebSocket open, both send `-32002 Server is shutting down` with
  `retry_after` 5 and close the connection (the client sees 1006).
- TLS: the Pebble gate test issued a certificate for `aprond.test`, and its
  cache directory was copied out. Both binaries, started with
  `--tls.domain aprond.test --tls.cache-dir <copy> --tls.addr ...
  --tls.http-addr ...`, served HTTPS from it over HTTP/2 and HTTP/1.1,
  verified by curl against Pebble's root. The HTTP listener answered `302`
  to `https://aprond.test/some/path?q=1` for the domain and `403` for an
  ACME challenge on another host. The binary itself cannot order from Pebble:
  like Go's, it hardcodes the Let's Encrypt directory and the system roots.
  The order, renewal and cache path go through the same `acme::Manager`
  in the Pebble gate.
- `--max-listener-connections 1`: while one TCP connection is held open,
  a second request gets no answer within 2 seconds on both servers; once
  it closes, the request gets 200.

## Passkey cross-open

`tools/crossopen/run.sh` builds both `aprond`s and a Go client with the
software authenticator of `webauthn_test.go`. In each direction one server
registers a guest's passkey on a SQLite database and stops; the other opens
the database, resumes the bearer token, and signs in with the passkey. After
phase 2a both directions passed: the Go-written user and session open here,
and the Rust-written ones open in Go. The stored user records have the same
`passkey` shape; the Rust one also carries `"left_at":{}` and `"pings":{}`,
the empty-map difference listed in `docs/DEVIATIONS.md`.

Playwright's `--project` takes several values, so run one spec as
`tools/interop/run.sh --project=desktop webauthn.spec.ts`; with a space, the
spec name is read as a second project. After phase 2a, and again after the
merge with 2b, `webauthn.spec.ts` passed 4 of 4.

## Web Push

Phase 2c's gates. `cargo test` runs the 26 tests of push_test.go and the 4
of webpush_test.go, all unignored, with `TestServerFrame` and
`TestProfileAndPushSizeLimits` in full (their push-less siblings are gone),
and `push_fixture_test.rs`, which checks `fixtures/push.json`: every payload
case against PushPayload's rules and the 2048-byte bound, the valid ones with
a message as `push_payload` makes them from a stored snapshot (the text of
`long-text-that-fits` cut to push.go's 1000 characters), and the
registration cases against a server, with real keys in place of the
synthetic ones and `ext:apns` refused as an unknown kind, as in Go.

`tools/differential/webpush/run.sh` checks both directions against Go's
code, copied into a Go program with its own `go.mod`. Rust opened all 14
of Go's payloads in `vectors.json` (RFC 8291's example, five with fixed keys
and salts from 0 to 3993 bytes, eight with random keys) and encrypted the six
fixed ones to Go's exact bytes; Go opened all 6 Rust-encrypted payloads and
verified all 4 Rust VAPID tokens (ES256 over r || s, `aud` the origin, `exp`
12 hours on, `sub`). A tampered body and a changed subject made the Go check
fail, so it is not vacuous.

`tools/interop/run.sh --project=push` passed 3 of 4: both seen.spec.ts
tests and the status test of push.spec.ts pass, and the web push test
(push.spec.ts:257) fails at its reply push, the first delivery after the
capture server's connection sat idle past Node's 5-second keep-alive
timeout. The transport reuses the connection the server closed and the POST
fails with `EOF`, so the delivery reports status 0 and is dropped (the
transport row of "Pending rust-stdlib fixes"). A diagnostic run with
`disable_keep_alives: true` on the push transport, not committed, passed 4
of 4.

`aprond` started with the interop flags (`--push.allow-insecure
--push.vapid-private-key bXTr... --push.vapid-subject mailto:...`) sends
`server.push` with relay, the five wake scopes, and webpush with the key's
public half.

## Tests held for later phases

Each Go test below is ported under its name and marked `#[ignore]` with the
phase or deviation that holds it, so `cargo test -- --ignored` lists what is
left. A sibling test proves the rest of its behavior, named beside it.

| Go test | Held for | Sibling |
|---|---|---|
| `TestNamesAreNormalized` | the PRECIS deviation (docs/DEVIATIONS.md, Display names): its fullwidth row needs NFKC | `test_names_are_normalized_without_nfkc`, the other five rows |

After the merge of phases 2a and 2b, every test held for passkeys or token
sessions runs in full: `TestRolesAndWelcome`, `TestStateSurvivesRestart`
with its passkey and upload halves, the three email tests that register
passkeys (`TestEmailAdditions`, `TestEmailProposalsEndWithTheirIdentity`,
`TestEmailAddsToAPasskeyAccount`), the 18 account tests of
status_test.go, and `TestConcurrentSavesOfDifferentExtKeysBothSurvive`.
Their guest-only siblings were deleted: `state_survives_restart_for_guests`,
`restore_after_a_crash_retires_guests` (phase 1b's
`test_restore_after_a_crash` covers it),
`status_values_and_derivation_for_guests`, `invisible_privacy_for_guests`,
`mute_echo_to_all_connections_for_guests`,
`after_auth_mutes_and_statuses_for_guests`,
`repeat_auth_is_no_sign_in_for_guests`, `seen_with_invisible_for_guests`,
and `listings_carry_seen_for_guests`.

## Pending rust-stdlib fixes

rust-stdlib is frozen while its history is reset, so these are recorded
here, not fixed upstream yet.

| Symbol | Problem | Go behavior |
|---|---|---|
| `net::http` transport, idle connection reuse (`idle_conn_healthy`, transport.rs:2582 at 535533a) | A request on a pooled idle connection that the server has since closed fails with `EOF` rather than dialing a new one. Repro: POST twice, 6.5 s apart, to a Node `http.createServer` (default 5 s `keepAliveTimeout`) through `Client::default()` or a `Client` on `rust_stdlib_sysnet::transport()`; the first gets 201, the second `Post "...": EOF`, and the server logs only one request. The likely cause, inferred from the code and not traced: the health check reads the idle connection with a past deadline, which can report a timeout before the peer's FIN is seen, so the connection passes as healthy; the request is written into it and, being a POST, is not retried after the read fails. For push, a delivery to a host that closed its idle connection reports status 0 and is lost (docs/DEVIATIONS.md, Push delivery); interop `push.spec.ts:257` fails on it. Any other pooled client connection in the port has the same exposure. | `persistConn.readLoop` reads the idle connection, sees the peer's EOF, and removes it from the pool, so the next request dials; a request that wrote nothing on a reused connection is retried. |
| `net::http` transport, `BodyState::finish_conn` (transport.rs:1814 at 535533a) | After a response arrives while the request body is still being written, `Response.body.close()` joins the body writer thread, so it blocks until the caller closes its end of the body. Repro: `Request::new("PUT", url).with_body(RequestBody::reader(pipe_reader))` through `DEFAULT_CLIENT.do_request` against a server that answers before reading the body to EOF, with `pipe_writer` kept open; `do_request` returns the response, and `response.body.close()` blocks until `pipe_writer.close()`. The server side is right: a raw TCP chunked PUT with its body open gets `410 Gone` with `Connection: close` within about 45 ms. | `persistConn.readLoop` sees `wroteRequest()` false when the response arrives first, closes the connection without waiting, and `Body.Close()` returns at once. `test_refused_write_does_not_wait_for_its_body` and `test_saving_without_a_stream_ends_it` close the pipe before the response body, the reverse of the Go tests' order, with a comment at each; their assertions are unchanged. |
| `rust_stdlib_tls` client verifier, `verify_tls12_signature` and `verify_tls13_signature` in `backends/tls/src/tls/glue.rs` | With `insecure_skip_verify` set, a handshake with a server whose leaf has an unknown critical extension fails with `tls: failed to verify certificate: Other(OtherError(UnsupportedCriticalExtension))`. The handshake signature goes through `rustls::crypto::verify_tls1x_signature`, which parses the leaf with webpki. Repro: In `src/aprond/acme/manager_test.rs`, `test_tls_config_answers_acme_tls_1_with_the_token_cert`, dial with `handshake(&addr, "aprond.test", &[ALPN_PROTO], None)` instead of the Go client. | `crypto/tls` with `InsecureSkipVerify` completes the handshake: it checks the signature with the leaf's public key, and `crypto/x509` keeps the extension in `UnhandledCriticalExtensions` without failing the parse. aprond does not need this (CAs dial the TLS-ALPN-01 port), so it blocks nothing here. |

## rust-stdlib fixes

rust-stdlib's public history starts at one root commit, b75d03a, which folds in the crypto-bigint, rustls, derive, and json error-path fixes below. The json-v2-time fix was held out of that root. It went upstream as rust-stdlib PR #1, squash-merged as 0765d02, which `Cargo.toml` pins over https; the `dogfood/apron` branch is retired. The commit hashes in the table below are from the history before the reset. Only b75d03a and fc6b1d3 exist after it.

Without json-v2-time, b75d03a does not build this crate: `src/server/persist.rs` derives `MarshalTo` and `UnmarshalFrom` for structs with `time::Time` fields.

| Branch | Problem | Status |
|---|---|---|
| `fix/crypto-bigint-yank` | `crates/crypto` pins a yanked `crypto-bigint`, so downstream crates cannot resolve it | merged into `dogfood/apron` (015e9c8) |
| `fix/json-v2-time` | `encoding::json::v2` had no `MarshalTo`/`UnmarshalFrom` for `time::Time` (and `Duration`), so a derived struct with a `time.Time` field, such as persist.go's `storedMute.Until`, did not compile. Go v2 writes RFC 3339 with nanoseconds; `Duration` has no default representation. | merged into `dogfood/apron` (c4ea7c3; fix 71b960d) |
| `fix/derive-skip-string-zero` (4513695) | The `MarshalTo` derive compared a `#[json(skip)]` field with `Default::default()`, which does not type-check for `String` | merged into `dogfood/apron` (c970e59) |
| `fix/rustls-advisories` (d6cf8a4) | rustls 0.23.45 and rustls-webpki 0.103.15 carried RUSTSEC-2026-0346/0347/0348/0349 and RUSTSEC-2026-0382 | merged into `dogfood/apron` (074898d) |
| `fix/json-unmarshaler-error-path` (1904de8) | A type error returned by a `json::Unmarshaler` got the enclosing field names prefixed, without a separator; Go returns it as the method made it | merged into `dogfood/apron` (40b11f3) |
