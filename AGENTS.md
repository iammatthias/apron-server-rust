# AGENTS.md

Instructions for AI coding agents and contributors working in this repository.

## What this is

`apron-server-rust` is a Rust server for the
[Apron](https://github.com/shazow/apron) chat protocol, version 9. It builds
one binary, `aprond`.

The reference is
[apron-chat/apron-server-cloudflare](https://github.com/apron-chat/apron-server-cloudflare):
its `SPEC.md` and its behavior, with its defaults. Port a Cloudflare
behavior with its integration tests where they exist, and record what still
differs in `docs/DEVIATIONS.md`.

The server began as a port of
[apron-chat/apron-server-go](https://github.com/apron-chat/apron-server-go).
Go is now a fallback only where Cloudflare says nothing, and there is no Go
upstream work. Two Go-era shapes remain:

- The command line is go-flags' layout: namespaced groups (`--upload.dir`),
  the same `--help` format and error texts, and a TOML config file whose
  tables are those groups (`src/aprond/options.rs`). Flags Go has keep
  their names, and the groups this server added follow the same layout.
- The store holds Go's entry kinds (`meta`, `used_id`, `record`, `room`, `message`,
  `user`, `session`, `embed`, `push`) with kinds of this server's own added
  (`device`, `bot`, `invite`, `dedup`), as `src/server/persist.rs` lists.
  The format is this server's own. A Go `aprond` opening it is not
  supported or tested.

Some tests and tools still read a local Go clone at `$APRON_GO_DIR`, which
defaults to `~/Developer/forks/apron-server-go`, for the shared fixtures
and the browser suites. Keep the clone unmodified.

The server also dogfoods [rust-stdlib](https://github.com/iammatthias/rust-stdlib),
Go 1.27's standard library for Rust. Where it needs a Go standard package,
it uses the matching rust-stdlib module.

## Layout

| Path | Holds |
|---|---|
| `src/bin/aprond/main.rs` | `main` and `run`: settings to `server::Config`, the listeners, signals and shutdown |
| `src/aprond/` | The binary's helpers as a library, so tests share them: flags (`options.rs`), the TOML config (`config.rs`), settings checks (`settings.rs`), the SMTP sender (`email.rs`), ACME (`acme/`), the listener cap (`listener.rs`) and the debug server (`debug.rs`) |
| `src/server/` | The protocol server, grouped below |
| `src/store/` | The `Store` trait with memory and SQLite backends |
| `src/webauthn/` | The subset of go-webauthn the server calls, with `src/cbor.rs` (tests in `src/cbor/tests.rs`) |
| `src/ws.rs` | RFC 6455 over a hijacked rust-stdlib connection |
| `src/rate.rs` | A token bucket, ported from `golang.org/x/time/rate` |
| `src/webp.rs` | WebP dimensions for `image::decode_config`, from `golang.org/x/image/webp` |
| `src/test_gate.rs` | The gates that need `go` or Pebble (Verification, below) |

`src/server/` modules by concern. Each module's `//!` header says more.

- **Core.** `server.rs` holds `Server`, `State` behind one mutex, the
  connection lifecycle and the HTTP handler. `config.rs` holds `Config`
  and its defaults. `client.rs` is one connection's queue, writer and
  pinger. `dispatch.rs` is the method table and `process_frame`.
  `protocol.rs` is the request envelope and the dynamic JSON value.
  `dedup.rs` replays retried requests (§1.2). `server_frame.rs` builds the
  `server` frame and the welcome notice. `metadata.rs` holds the server's
  title, description and avatar.
- **Persistence.** `persist.rs` writes marked state to the store when the
  lock is released. `restore.rs` rebuilds `State` from the store at start.
  `retention.rs` expires history for `--history.retention`.
- **Users and sign-in.** `users.rs` (users, guests, roles, attach and
  detach), `user_ids.rs` (display names and new user_ids), `webauthn.rs`
  (passkeys and sessions), `passkeys.rs` (`/passkeys`), `email.rs` (email
  sign-in), `admin.rs` (the admin token), `tokens.rs` (the table behind
  sessions and device, invite and bot tokens), `devices.rs`
  (`/invite-device`), `invites.rs` (`/invite-token` and `/invite`) and
  `bots.rs` (`/invite-bot` and the idle bot sweep).
- **Rooms and messages.** `rooms.rs` (rooms, memberships and delivery),
  `room_set.rs`, `room_list.rs`, `history.rs`, `messages.rs` (saves,
  edits, moves and reactions), `emoji.rs` with `emoji_qualified.txt`
  (reaction entries), `activity.rs` (typing and read cursors), `status.rs`
  and `unread.rs`.
- **Commands.** `commands.rs` holds the command table and the small
  commands. `toggles.rs`, `custom_emoji.rs`, `purge.rs` and `rename.rs`
  hold the larger ones. `remap.rs` is the one walk over every place
  `State` keeps a user_id, which `/purge` and `/rename` share.
- **Embeds and media.** `embeds.rs` (hosted embeds and their write URLs),
  `uploads.rs` (`/write/` and `/files/`), `streams.rs` (`/streams/`),
  `media_types.rs` (type sniffing) and `unfurl/` (link previews:
  `text.rs`, `page.rs`, `fetch.rs`, `cache.rs`, `mod.rs`).
- **Push.** `push.rs` (registrations, wake scopes and the payload),
  `push_delivery.rs` (the delivery queues and lanes), `wake.rs` (whom a
  message wakes, and when), `webpush.rs` (encryption and VAPID) and
  `outbound.rs` (the HTTP clients for push and unfurls, with the dial
  check).
- **Limits.** `limits.rs` holds the rate and count limits and every
  `charge_*_locked` function. Five per-user limiters (push registrations,
  status, typing, read relays and unfurls) use `crate::rate::Limiter` on
  `UserState` instead.
- **Tests.** `tests/` holds the server's integration tests, split by
  area and topic (`push_*_test.rs`, `status_*_test.rs` and so on), with shared helpers and fixtures in `tests/helpers/` (server,
  client, frames, rooms, uploads and accounts).

`docs/PORT.md` holds the port's history: the phase plan, gate results and
the decision log. `docs/DEVIATIONS.md` lists every known difference from
apron-server-cloudflare a client can see, and the extensions and choices
where Cloudflare is silent.

## Rules

- **No async runtime.** rust-stdlib serves HTTP with one thread per
  connection. For background work, start a thread or reuse a worker. For a
  timer, use rust-stdlib's `time` package (`time::after_func`).
- **Use rust-stdlib for Go standard packages.** If rust-stdlib is missing
  something or gets it wrong, fix it upstream. Do not work around it here.
  The fix follows that repository's `AGENTS.md` and lands on its `main` as a
  squash-merged pull request. While it is in review, a `[patch]` section may
  point this crate at the branch; never commit that. After the merge, move
  the `rev` of every rust-stdlib crate in `Cargo.toml` to the new commit,
  run `cargo update` on them, and record the fix in `docs/PORT.md`.
- **No first-party cryptography.** SHA-1 for the WebSocket handshake, VAPID
  (P-256 ECDH, HKDF, AES-GCM), ECDSA signing, and WebAuthn signature checks go
  through `rust-stdlib-crypto`. WebSocket framing and CBOR parsing are not
  cryptography, so they can live here.
- **Third-party crates need an entry in the allowlist below,** with the Go
  dependency they replace and why rust-stdlib cannot do it. Pin exact
  versions.
- **Port behavior, not just structure.** When you port a Cloudflare
  behavior, port its tests too: edge cases, codes and error text. Do not
  call a feature done until its tests pass.
- **Record every difference.** If this server behaves differently from
  apron-server-cloudflare in a way a client could see, or adds something
  Cloudflare lacks, add a section to `docs/DEVIATIONS.md`. Delete the
  section when the behavior matches Cloudflare. Prose elsewhere does not
  count.
- **Handle every new `State` field in `remap.rs`.** `remap_fields_locked`
  destructures `State` exhaustively, so a new field does not compile until
  the walk handles it or marks it as holding no user_id. The purge and
  rename tests check the result through `State::user_id_places`.
- Comments explain a non-obvious *why*. Keep the doc comments that carry
  protocol references such as `(§4.2.1)`. Drop the ones that only restate
  the code.
- No `todo!()` or `unimplemented!()` in code that ships. No `unsafe`.
- Never report a test as passing unless it ran and passed.
- **Clean up build output as you go.** A Rust `target/` reaches several
  gigabytes per checkout. When a worktree's work is merged or abandoned, run
  `git worktree remove --force <path>`; the branch keeps the commits. Delete
  throwaway crates (spikes, downstream checks) as soon as they have answered
  their question. Run `cargo clean` in a worktree you are leaving idle. Before
  handing back, report what you removed and what you left, with its size.
- Nothing in this repository gets pushed or published without the owner's
  go-ahead.

## Reference parity

`REFERENCE` pins apron-chat/apron-server-cloudflare and shazow/apron (the
protocol) at the commits last reviewed. Check it at the start of every
session and before every pull request:

```sh
tools/reference/check.sh
```

It keeps a blobless clone of each repository under `$APRON_REFERENCE_DIR`
(default `~/.cache/apron-reference`), fetches it, and lists the commits
since each pin that touch `SPEC.md`, `src/`, `docs/`, `PROTOCOL.md` or
`EXTENSIONS.md`. It exits 0 when there are none, 1 when there are, and 2
when a pin is no longer an ancestor of `main`. The list is a review queue,
not a rule to port every commit: for each commit, port the behavior with
its tests, record a difference you keep in `docs/DEVIATIONS.md`, or skip a
commit that changes nothing a client sees (a Cloudflare budget, say). Then
move the pin in the same change. If the script reports rewritten history,
stop and compare by hand.

`tools/smoke/frame-diff.mjs` compares the shape of this server's `server`
frame (its keys and capabilities, not their values) with the live
reference at wss://server.apron.chat/, as one read-only guest connection
from the web client's origin.

## Third-party allowlist

| Crate | Replaces | Why |
|---|---|---|
| `rust-stdlib`, `rust-stdlib-crypto`, `rust-stdlib-derive`, `rust-stdlib-tls`, `rust-stdlib-sys`, `rust-stdlib-sysnet` | Go's standard library (`rust-stdlib-derive` stands in for `reflect` with `encoding/json` struct tags; `rust-stdlib-sys` holds `os/signal`, which the root crate cannot, per its ADR 0004) | The dogfooding target |
| `rusqlite` (bundled) | `modernc.org/sqlite` | rust-stdlib has `database/sql` but no SQLite driver |
| `toml` (`parse` and `serde` features only; builds `toml_parser`, `toml_datetime`, `serde_spanned`, `serde_core`, `winnow`. `Cargo.lock` also lists its optional `indexmap`, `hashbrown`, `equivalent` and `toml_writer`, which are not built, and moves `serde` to 1.0.229, whose `serde_derive` builds `syn` 3) | `github.com/BurntSushi/toml` (decoding only) | Go's standard library has no TOML, so rust-stdlib has none. The encoder `--print-config` needs is written by hand to match BurntSushi byte for byte |

## Verification

The gates are listed from cheapest to most thorough.

1. **Unit and integration tests.** `cargo test`. They include the tests
   ported from apron-server-go's `*_test.go` files and from
   apron-server-cloudflare's integration tests, and the tests of this
   server's own extensions.
2. **Shared fixtures.** `cargo test` loads two of the JSON vector files in
   the Go clone's `testdata/apron/tests/fixtures`, from
   `$APRON_GO_DIR/testdata/apron`: `push.json`
   (`src/server/tests/push_fixture_test.rs`) and `webauthn.json`
   (`tests/webauthn_fixture.rs`). No test loads the third file,
   `history.json`. Its cases are the web client's recovery arithmetic, and
   the protocol repository runs it in the web client's tests only
   (`testdata/apron/DEVELOPMENT.md`).
3. **Smoke.** `tools/smoke/run.sh` builds the Rust `aprond` in release and
   starts a fresh one on a free port, with its own SQLite `--store` and
   `--upload.dir`, for each of two scripted WebSocket sessions:
   `session.mjs` (a guest session) and `email.mjs` (an email sign-in, a
   token resume, and a guest adding an address). `check.mjs` checks each
   transcript: every request got exactly one reply, none an
   `internal_error`, and the `server` frame lists the extensions
   apron-server-cloudflare's does. The script exits non-zero on a failed
   check and removes its servers and temp files. It needs Node 22 and
   `curl`.
   `tools/differential` holds the Go programs that record the ACME,
   WebAuthn and Web Push vectors `cargo test` and
   `tools/differential/webpush/run.sh` check.
4. **Browser interop.** `tools/interop/run.sh [playwright args]` runs the Go
   repository's Playwright suites against this binary, with the real web
   client. It puts a `go` shim first on `PATH` that answers
   `go run ./cmd/aprond ...` with the Rust `aprond`. Projects: `desktop`
   (`chat`, `reference`, `webauthn`), `mobile` (`responsive`), and `push`
   (`push`, `seen`). The shim adds the flags that restore the Go server's open
   defaults where they are configurable: guest posting, any push host, no
   limits, and status changes sent at once. The tests that still fail by
   design, where this server follows apron-server-cloudflare, are listed in
   `tools/interop/expected-failures.md`. Any other failure is a regression.

Some `cargo test` gates run tools outside Cargo. When a tool is missing, the
test fails, so a green run proves the gate ran. To skip a gate on purpose,
set its variable to `1`. The test then passes and prints `SKIPPED` (shown
with `-- --nocapture`), and the run does not count as that gate passing.

| Gate | Needs | Skip with |
|---|---|---|
| ACME differential: the `aprond::acme` tests that run `tools/differential/acme` against x/crypto | `go` on `PATH` | `APRON_SKIP_GO=1` |
| ACME against Pebble: `aprond::acme::pebble_test` | `pebble` and `pebble-challtestsrv`, and Pebble's module in the Go module cache (or `$PEBBLE_DIR`) | `APRON_SKIP_PEBBLE=1` |

The Pebble test looks for its binaries in `$PEBBLE_BIN_DIR`, then on `PATH`,
then in `$(go env GOPATH)/bin` (by default `~/go/bin`). Install them there
once:

```sh
go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1 \
  github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@v2.10.1
```

`go install` also puts Pebble's module in the module cache. To keep the
binaries elsewhere, set `GOBIN` for the install and `PEBBLE_BIN_DIR` for the
tests. The Pebble test binds ports 5001, 8053, 8055, 14000 and 15000.

`tests/aprond.rs` checks `--help`, `--print-config` and the startup errors
against the golden files in `tests/golden`. When a flag change is intended,
rerun it with `APRON_UPDATE_GOLDEN=1` and review the diff of those files.

Before any commit:

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

## Deployment

A public test server runs at https://apron.farfield.systems behind Caddy and
a Cloudflare Tunnel. It is for testing the iOS client Ladle against a real
deployment.

```sh
tools/deploy/deploy.sh
```

The script deploys the committed `HEAD` to the Docker host named by
`APRON_DEPLOY_HOST`, set in the environment or in `tools/deploy/local.env`,
which git ignores. The script's header lists the other settings. It bundles
the crate, `cargo vendor` output with its `.cargo/config.toml`, `deploy/`,
and a build of the web client in `deploy/web`. It rsyncs the bundle to the
host and runs `docker compose -f deploy/compose.yaml up -d --build` there.
Then it waits for `/healthz` through the public URL and prints the container
table. Rerunning it is safe: the SQLite store and uploads live in the
`apron_data` volume, which a deploy never removes.

The script also makes the admin token on the host when it is missing, over
ssh: `umask 077; openssl rand -hex 32` into `admin_token` in
`APRON_SECRETS_DIR` (default `~/apron-secrets`), a 0700 directory outside the
bundle, so rsync `--delete` never removes it. The file is 0644 so aprond's
non-root container user can read it through the bind mount that Compose
mounts at `/run/secrets/apron_admin_token` for `--admin-token-file`. The
script never prints the token and never replaces an existing one. Fetch it
for `tools/deploy/live-check.mjs` with `ssh host 'cat ~/apron-secrets/admin_token'`
into a 0600 file named by `APRON_ADMIN_TOKEN_FILE`. The live check makes
`livecheck_` accounts and purges them, and those earlier runs left, at the
end of each run.

The web client is [apron-web](https://github.com/apron-chat/apron-web), not
code in this repository. `APRON_WEB_BUILD` names a finished build to ship as
is. Without it, the script builds the checkout at `APRON_WEB_DIR` (default
`~/Developer/forks/apron-web`) with `VITE_DEFAULT_SERVER_URL=` and
`VITE_TRUSTED_MEDIA_ORIGINS=`, so the client connects to the origin that
serves it. The build needs Node 24. The homelab currently sets
`APRON_WEB_BUILD` in `local.env` to a build of the `show-sign-in-qr` branch,
the sign-in QR code change in apron-web pull request #143. Once that merges,
check out apron-web's `main` there and unset `APRON_WEB_BUILD`.

The Compose project runs three containers behind one hostname:

- `aprond`, built by `deploy/Dockerfile` offline (`--locked --offline`) from
  the vendored sources, runs as a non-root user on `debian:bookworm-slim`.
  It publishes no port and serves no web client. `deploy/compose.yaml` holds
  every `aprond` flag.
- `web`, the `web` target of `deploy/caddy.Dockerfile`, serves the web build
  with `deploy/web.Caddyfile`, as `--static-dir` did: no fallback to
  `index.html` (apron-web routes by URL fragment) and no dotfiles.
- `router`, the `router` target, sends aprond's paths to `aprond` and every
  other path to `web` (`deploy/router.Caddyfile`). It publishes
  `172.17.0.1:8901`, the docker bridge gateway, which is where a reverse
  proxy's `host.docker.internal` upstream points. Set `APRON_PUBLISH` to
  publish elsewhere, such as `127.0.0.1:18901` on a Mac.

aprond's paths come from `Server::handler` in `src/server/server.rs`: `/ws`,
`/healthz`, `/write/`, `/files/`, `/streams/`, `/emoji/`, and
`/.well-known/apple-app-site-association`. A new route there needs the same
path in the router's `@aprond` matcher.

`--client-ip-header` is `Cf-Connecting-IP`, not `X-Forwarded-For`. Each proxy
replaces or appends to `X-Forwarded-For`, so its last entry is the same for
every visitor. The host's Caddy and the router pass `Cf-Connecting-IP`
through unchanged.

`tools/deploy/proof/run.sh` proves sign-in end to end against the deployment.
Set `LADLE_DIR` to a checkout of Ladle's `live-proof` branch. A Playwright page
(the Go clone's `tests/interop` dependencies, Chrome's virtual authenticator)
makes a passkey account named `ladle-proof` in the web client, posts, and runs
`/invite-device phone`. It passes the notice's token and the server's origin
to Ladle's `LiveServerProofTests` in the environment. That test signs in with
the token as the same `user_id` and posts in `general`. The page then waits
for Ladle's message. Device tokens sign in from any origin, so a Ladle
`live-proof` branch that still expects the token refused from another origin
or without one fails until it is updated.
Each run leaves one more `ladle-proof` account, whose passkey went away with
the virtual authenticator.

The reverse proxy, the tunnel route, and DNS are set up once on the host and
in Cloudflare. The script does not manage them.

## Commands

```sh
cargo run --bin aprond -- --store memory          # serve on 127.0.0.1:8080
cargo run --bin aprond -- --help
tools/interop/run.sh --project desktop            # browser interop
```
