# Port plan and log

Source: apron-server-go at `f137c64`, protocol v9 (`testdata/apron` at
`233ec54`).

## Definition of done

`aprond` matches apron-server-cloudflare's `SPEC.md` and its ported tests,
except the rows in `docs/DEVIATIONS.md`. `REFERENCE` pins the Cloudflare and
protocol commits that were last reviewed, and `tools/reference/check.sh`
lists what changed since.

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
| 2026-10-28 | `/invite-device <name>` replaces `/add-device [label]`. Device tokens are a store kind of their own, `device`, keyed by the hex SHA-256 of the token and holding `{user, name, created}`, rather than sessions. The per-account session cap and the `/add-device` limiter are gone. | The official server (apron-server-cloudflare) has `/invite-device` for the same job, so clients can give one instruction everywhere. Its tokens sign in from any origin and never expire, which sessions, bound to an origin and renewed on use, cannot express without sentinel values a Go `aprond` would misread. Go loads only the kinds it knows, so it ignores `device` entries and never deletes them. The cap and limiter existed only because `/add-device` minted sessions without bound; three named tokens per account bound the new store kind. |
| 2026-10-28 | The `/invite-device` notice carries Cloudflare's sign-in link line when a public URL is configured, and none otherwise. | A client can open the link or draw it as a QR code for a phone to scan. Cloudflare builds it from the URL each connection reached. This server builds it from the public URL (`--public-url`, or `--tls.domain`) only, not from the request's `Host`, so a server without one never writes a link for an address it may not be reachable at. |
| 2026-10-28 | `/invite-bot` gives an account one bot, `bot_<user_id>`, named after it, with a token of its own store kind, `bot`, keyed by the hex SHA-256 of the token and holding `{bot, owner, created}`; one token per bot, revoked before the new one is stored. A bot is a `UserState` with `owner` set, stored as a `bot` member of its `user` entry. `account()` stays a credential check, so a bot runs no account commands; the new `persists()` (account or bot) decides retirement in `attach_locked`, `detach_locked` and the restore loop, and `grant_roles_locked` gives a bot `["bot"]` only. A bot may not add a passkey or an email address, and `requestable` reserves `bot_`. | It follows apron-server-cloudflare's `/invite-bot`, which the owner needs to test a bot here. An owner field is the smallest change that makes a bot durable without making it an account: every `account()` gate (`/invite-device`, `/invite-bot`, session and device restore) keeps excluding it for free. A passkey or address would turn the bot into an account that could mint its own tokens, so both are refused. Go skips unknown members and kinds, but it takes the bot for a guest and retires it (docs/DEVIATIONS.md). |
| 2026-10-28 | A replaced device or bot token's connections are signed out under the lock that replaces the token (`revoke_connection_locked`: the connection leaves its user, its ceremony and proposal go, and the user's status is announced), and `process_frame` ignores the frames of a connection whose close is queued; `authenticate` denies an `auth` that was read before. | A security review of the first `/invite-bot` commit found that `close_with_error` only queued the error behind the outgoing batches, so a revoked connection kept running requests as the user until its writer drained. Signing it out under the lock covers a request already past the read loop, because every handler resolves its identity with `client_user` under its own lock; ignoring later frames stops it signing in again. Go runs a closing connection's frames, but it closes with an error only at shutdown and at the connection cap (docs/DEVIATIONS.md). The tests run the replacing command while holding the state lock, so they check the revoked connection before its writer can drain and detach it; without that, a fast test writer hides the bug. |
| 2026-10-28 | A guest's passkey registration makes a new account with apron-server-cloudflare's user_id, `<slug>_<4 digits>` from the requested name or `u_<random>`, rather than keeping `guest_<n>` in place as Go does. `begin` picks the id with `candidate_user_id` against `user_id_taken_locked`, which `claim_user_id_locked` now calls too, and carries it in `PasskeyCeremony.candidate_id`; `finish` claims it, inserts a new `UserState` with the passkey, and switches the connection, which retires the guest through the usual `attach_locked` path. The account joins the guest's rooms with `add_member_locked`, and `notify_user_id_change_locked` sends `user` with `new` and `old`. Existing `guest_<n>` accounts are not migrated. | The owner's rule is to follow the official servers, and Cloudflare where Go and Cloudflare differ (docs/DEVIATIONS.md, Account user_ids). Retiring the guest and making a fresh account reuses the code a guest's departure and a new account already have, so nothing bound to the guest needs rekeying: a guest has no sessions, device tokens or bots, and its push registrations go with it, as a Cloudflare guest has none. The guest-adds-email path has no Cloudflare counterpart, so it keeps Go's in-place account. |
| 2026-10-28 | A connection keeps its device token's key in `Conn.device`, apart from `Conn.token`, which holds its session or bot token. Each `PushRegistration` records the `device` of the connection that made it, stored as the `device` member of its `push` entry, and a replacement removes only the registrations made under the old token; one stored without it loads as zero and stays. The asking connection's `device` moves to the replacement. | It ports apron-server-go 7019765 (branch `invite-device`), which fixes two bugs the review of its pull request #21 found, and which this port had too. One field held both keys, so a device connection that then ran passkey `register`, or resumed a session, lost its device key and stayed open when the device token was replaced. A replacement also removed every push registration on the account, so the account's other devices stopped getting pushes until they registered again. Unlike Go's, this port shipped `/invite-device` before the fix, so a device connection may have stored a registration without `device`. Such a registration stays at a replacement, as Go's untagged ones do; the device's next `push_register` of its url tags it. |
| 2026-10-28 | Link previews (`--unfurl.enable`, off by default) live in `src/server/unfurl/`: `text.rs` finds URLs, `page.rs` reads `<meta>` tags, `fetch.rs` fetches, `cache.rs` keeps results, and `mod.rs` runs jobs; `embeds.rs` builds the embed (`add_link_embed_locked`). A preview is a `link` embed held as an `EmbedState` with `owned = {url, og}` and, for its image, the fields of a finished upload, so embed identity, saves, release on delete, `/files/`, eviction and the store handle it with no new code or store kind. The fetcher's rust-stdlib `Client` comes from `outbound::client`, as push's does: no proxy, and a dial `control` that checks each dialed address, redirect hops included, here with `unfurl::dial_check` (public addresses on ports 80 and 443). The job runs on its own thread, outside the state lock, and waits for a thread per URL until the unfurl timeout, then lands with one `republish_locked`; `shutdown` awaits running jobs, which that timeout bounds. Pages are parsed by a small scanner over `<meta>` and `<title>`, with rust-stdlib's `html::unescape`. | AGENTS.md rules out an async runtime and new crates without need: a meta-tag scanner is about 150 lines, and an HTML5 parser crate would be the largest dependency here for five attributes. Reusing the upload machinery keeps one code path for hosted media, so a Go `aprond` opening the store serves the images too (docs/DEVIATIONS.md). The dial check is a `DialCheck` closure so tests can admit one local fixture port and refuse another, which proves a redirect to a refused address is never dialed. |
| 2026-10-28 | Read-only guests (`Config.guest_posting`, then `--guest.read-only`) are one check in `process_frame` before deduplication: `users::guest_write` names the methods a read-only guest is denied outright, `ServerCommand.writes` marks the commands it is denied, and `activity_locked` drops its activity. The flag is negative because go-flags booleans take no value, so a `true` default could not be turned off; `Config` keeps apron-server-cloudflare's positive name. `ext.settings` carries only the keys that are not the default, so the default `server` frame stays Go's. | One boundary keeps the policy in a table rather than in each handler, and a denial is an error, which deduplication never caches. Dropping activity, not answering it, follows §1.1: activity is a notification. |
| 2026-10-28 | History retention (`--history.retention`, `Config.retention`) lives in `src/server/retention.rs` as one `State::expire_history_locked(now)`, run by the existing hourly sweep (renamed `Server::sweep` from `sweep_pushes`) and once at `open` after the restore. It splits `State.records` at the new floor, trims each room log and message, drops reaction sets by a new `ReactionSet.log_id`, removes messages with `remove_embed_locked` for their files, and removes emptied leaf threads. Room delivery fields take the floor (`RoomState::history_log_id(floor)`). `entries_for` now deletes a dirty record, room or message missing from the state, as it already did for users, embeds and pushes, so the normal flush persists the discard. `State.rooms_removed_at` turns a `room_list` delta from before a removal into a full listing. | Taking `now` as a parameter is the injectable clock the tests need, without a clock abstraction the rest of the server lacks. Expiring by `log_id` reuses the commit time the log already carries; apron-server-cloudflare keeps a separate commit time because its IDs and clock are separate. Making the flush delete missing entries is what keeps discarded records from coming back at the next start; without it the store kept every row. |
| 2026-10-28 | `tests/aprond.rs` checks `--help`, `--print-config` and the startup errors against golden files in `tests/golden` (`check_golden`, rewritten with `APRON_UPDATE_GOLDEN=1`) instead of building the Go `aprond`. The files were frozen from the output that last matched Go byte for byte, now with the extension groups included. | apron-server-cloudflare is now the reference and Go only a fallback, so new flags break a byte comparison with Go on purpose. The golden files keep the go-flags layout and error texts checked without Go. The `aprond::acme` differential still runs Go, against x/crypto rather than the Go server, so `APRON_SKIP_GO` stays for it. |
| 2026-10-28 | Guests only read by default: `Config.guest_posting` defaults to false and `--guest.posting` turns posting on, replacing `--guest.read-only`. Guest `auth` takes the next `guest_<n>` with the name `Guest <n>` (`next_guest_id_locked`), ignoring a requested `name` or `user_id`. `server.ext.settings` always carries `guest_posting`, `read_cursors` and `add_members`, and `private_rooms` unless `--max-private-rooms` is 0, which now defaults to 20. The tests ported from Go take `tests::helpers::default_config`, the server default with guest posting on. | apron-server-cloudflare is the reference, and these are its defaults (`GUEST_POSTING` off, `privateMembershipsPerUser` 20). Activity has no switch here yet, so `read_cursors` and `add_members` are always true. The ported tests sign in as guests to post; a test-only default keeps them about what they test, and `guest_posting_test` checks the real default. A guest's `me` name change stays accepted for now (docs/DEVIATIONS.md, Guests). |
| 2026-10-28 | `State::welcome` picks `server.welcome` (`--welcome`, else `general`'s description, else `sign_in_summary`), and `State::welcome_notice` is queued right after the `server` frame under the same lock. The test helpers read the notice in `dial_headers`; `dial_server_frame` leaves it unread for tests about it. | Reading `general` at each connection makes an edit show on the next sign-in screen, as apron-server-cloudflare reads it per connection. Consuming the notice in one helper keeps the ported tests about what they test. |
| 2026-10-28 | Frame bounds are `Config.frame`, a `protocol::FrameLimits` that replaces `read_limit`. `parse_request` checks the request id's length and then `json_shape`, which counts values and nesting with rust-stdlib's `jsontext::Decoder` over the already validated frame; a name is told from a value by its object's odd token count. `validate_body` takes the text bound. A WebSocket frame header past the read limit now closes with 1009, as a message past it does, rather than 1002. Tests that reach the ext, description and history-page limits use `large_frames_config`. | apron-server-cloudflare's values are the defaults. The token decoder keeps the scan to the library's grammar instead of a second hand-written one. The 1002 came from treating an oversized header as a protocol error; RFC 6455 §7.4.1 gives 1009 for a message too big to process. |
| 2026-10-27 | autocert is ported as `aprond::acme`: an RFC 8555 client (`client.rs`), ES256 JWS and challenge certificates over rust-stdlib-crypto (`jws.rs`), `DirCache` (`cache.rs`) and `Manager` (`manager.rs`). | golang.org/x/crypto is not Go's standard library, so rust-stdlib has no counterpart. The port keeps autocert's cache names (`<domain>`, `<domain>+token`, `<token>+http-01`, `acme_account+key`) and file layout (PEM key, then the PEM chain), so a cache directory moves between the Go and Rust aprond. `tools/differential/acme` checks thumbprints, key authorizations, JWS signatures, the TLS-ALPN-01 certificate, and cache files in both directions against x/crypto/acme v0.57.0. |
| 2026-10-27 | The ACME gate runs Pebble v2.10.1 and pebble-challtestsrv from `cargo test` (`acme::pebble_test`). The test fails when they are missing, unless `APRON_SKIP_PEBBLE=1`; AGENTS.md, Verification, gives the install command and the lookup order (`$PEBBLE_BIN_DIR`, `PATH`, `$(go env GOPATH)/bin`). | It issues over TLS-ALPN-01 through a real handshake, verifies the chain against Pebble's root, reuses the certificate, renews it, and has Go's autocert read the cache. Pebble's validator sends HTTP-01 requests with `Host: <domain>:5002`, which `HostWhitelist` rejects in Go and here alike, so HTTP-01 is checked by the handler tests, not against Pebble. |
| 2026-10-29 | Reaction records are logged with their entries qualified: `parse_emojis` normalizes a `reactions` request before `commit_reactions_locked` logs it, and a move re-logs the stored sets, which load qualified (d74f625); `reactions_test` checks the record `history` serves. Records logged before d74f625 keep the form they were sent in, and no migration rewrites them. A logged record is what was broadcast under its `log_id`, which clients may already hold, so the log stays append-only; the current sets were already rewritten qualified when they loaded, so `room_list` and every new record agree, and a client reading an old record compares entries without U+FE0F (§4.7). |
| 2026-10-29 | `/purge` (`src/server/purge.rs`) erases users in one pass under the lock, `erase_users_locked`, and is the first code that deletes a record from the middle of the log (`remove_record_locked`, which also drops it from every room log that holds it). Its test, `purge_test::test_purge_leaves_nothing_behind`, builds a user holding one of everything and checks that the user_id appears nowhere in the state's store entries (`dump_locked`, now over every record rather than the room logs' only) or the maps kept in memory, and `test_purge_persists` checks the store itself after a restart. Each erase step was mutation-checked against those tests: removing any one of them fails a test. | A purge touches some 25 places that key or name a user. A test that searches every place for the user_id finds a missed one without a test per place, and the same search checks `/rename`. `dump_locked` read records only through the room logs, so a record dropped from a log but left in `State.records` was invisible to it. |
| 2026-10-29 | `/rename` (`src/server/rename.rs`) moves a user in one pass under the lock, `move_user_locked`, re-keying `State.users` and every map that names the user, and rewriting the user objects of logged records in place, as Cloudflare's `renameIdentity` does. The user's timers are stopped and set again under the new id. `rename_test::test_rename_moves_everything` checks that every place `purge_test::traces` found under the old user_id before the rename holds the new one after it, but the sessions, and that only `used_ids` and the bot's entries keep the old one. | PROTOCOL.md §3.3.3 has logged records keep a user_id, and Cloudflare rewrites them for `/rename` as its one exception; this server follows Cloudflare, so the user's past messages stay editable. Comparing the places before and after catches a move that leaves anything behind without a test per field. |
| 2026-10-29 | apron-server-cloudflare 2d6f54c (`/emoji` for the roles `admin`, `mod` and `friend`) is ported: `Audience::Roles(EMOJI_ROLES)` in `src/server/commands.rs`, with Cloudflare's refusal text and `/help` listing. The `REFERENCE` pin had been moved past it to 834c0e7 without the port, and 834c0e7 (`ACCOUNTING_RECOVERY`, a Workers accounting stop) is skipped: nothing a client sees. A command's `invalid_params` no longer count as policy violations where Cloudflare's `handleCommand` does not count them (`RpcError.forgiven`): an unknown command or a line with no `/`, and the usage or user_id errors of `/invite-device`, `/passkeys`, `/emoji`, `/server`, `/admin`, `/role`, `/kick`, `/rename`, `/purge`, `/toggle`, `/invite-token` and `/invite`. Errors found before the command runs (no body, an unknown room, a `message_id`), `/avatar`'s usage, and every other error kind still count. | One mechanism, a flag on the error, keeps the choice beside each command's table entry. |
| 2026-10-29 | `UPSTREAM` and `tools/upstream/check.sh` give way to `REFERENCE`, which pins apron-chat/apron-server-cloudflare and shazow/apron at the commits last reviewed, and `tools/reference/check.sh`, which lists each repository's commits since its pin that touch `SPEC.md`, `src/`, `docs/`, `PROTOCOL.md` or `EXTENSIONS.md`. `tools/crossopen` is deleted. `tools/smoke/frame-diff.mjs` compares the `server` frame's shape with the live reference at wss://server.apron.chat/. | Cloudflare is the reference and Go a fallback, so drift is measured against Cloudflare and the protocol, as a review queue rather than a rule to port every commit. Store compatibility with a Go `aprond` is no longer a goal, so a check of it guards nothing. |

## Migrating a guest_<n> account

Accounts registered before 2026-10-28, such as the live `guest_1` with its
bot `bot_guest_1`, keep their user_ids until an admin moves them with
`/rename <old_user_id> <new_user_id>` (`src/server/rename.rs`,
docs/DEVIATIONS.md). The live `guest_1` became `matthias` on 2026-10-29,
after a copy of the `apron_data` volume was kept on the host in
`~/apron-backups/pre-rename-202610291340`. For the account itself:

- Its passkeys, device tokens, invite token, roles, memberships, read
  cursors, rooms it created, messages, reactions, avatar, push
  registrations, mutes and status move to the new id, and its logged
  messages, reaction sets and memberships are rewritten to it.
- Its connections stay open as the new id and get `user` `you`.
- Its sessions are deleted. A web client that resumes one is told to sign
  in again, and signs in with its passkey as the new id.
- A native client signed in with a device token keeps working: the token
  now signs in as the new id, and the `auth` result names it.
- Its bot keeps `bot_<old>` and its token, and the new id owns it.
  `/invite-bot` then gives that bot a new token, and `/purge <new>`
  removes it with its owner.
- `--role` grants given to the old id are not given again. A grant naming
  the new id is given when the rename makes it exist.

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
with `/invite-device <name>`, an extension Go lacks that matches
apron-server-cloudflare's (docs/DEVIATIONS.md). Send it in the web client
while signed in with a passkey or email, and paste the token from the
`~private` reply, which shows it in a code block with a Copy button. With
`--public-url` or `--tls.domain` set, the reply also has a link.apron.chat
sign-in link for the server's `/ws` endpoint and the token, which a client
can open or show as a QR code. The app authenticates with
`{"scheme": "token", "token": ...}` (§3.2), from any origin or none. The token does not expire. An account holds at most three,
one per name; running `/invite-device` with a held name again mints a new
token for it, revokes the old one, and closes the connections that signed
in with the old one.

## Smoke check

`tools/smoke/run.sh` once ran both sessions below against both servers and
compared them. With apron-server-cloudflare the reference (Track E), it runs
them against this server alone and checks each transcript with `check.mjs`,
as AGENTS.md's gate 3 describes; `compare.mjs` is gone. The rest of this
section records the Go comparisons, which no longer run.

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

Retired on 2026-10-29 with Go store compatibility as a goal; the tool is in
the history before that date. `tools/crossopen/run.sh` built both `aprond`s and a Go client with the
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
| `rust_stdlib_sys::net::Dialer::dial_context` (crates/sys/src/net/dial.rs:474 at 0765d02) | The dial deadline does not cover name resolution. `dial_context` builds its `Ctx` with the deadline from `timeout`/`deadline` (dial.rs:480), then calls `resolve_addr_list` (dial.rs:481), which reaches `lookup_ip` (crates/sys/src/net/resolve.rs:333) and `(host, 0u16).to_socket_addrs()` (resolve.rs:343): a blocking `getaddrinfo` that takes neither the deadline nor `ctx`. With a nameserver that drops queries, a dial, and so `Client.timeout`, waits out the system resolver's own retries (tens of seconds) before the deadline applies. Link previews (`src/server/unfurl/mod.rs`, `Unfurler::previews`) work around it: each URL is fetched on its own thread and the job stops waiting at its timeout, leaving the thread to finish. Push has the same exposure, bounded only by its lane and queue limits. | `Dialer.DialContext` resolves through `Resolver.LookupIPAddr` with the deadline's context; the lookup runs on a goroutine (`lookupGroup.DoChan`) and the caller selects on `ctx.Done()`, so the dial returns at the deadline while the lookup finishes alone. The fix here is the same shape: resolve on a thread and `recv_timeout` until the deadline. |
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
