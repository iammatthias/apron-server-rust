# AGENTS.md

Instructions for AI coding agents and contributors working in this repository.

## What this is

`apron-server-rust` is a Rust port of
[apron-chat/apron-server-go](https://github.com/apron-chat/apron-server-go),
the reference server for the [Apron](https://github.com/shazow/apron) chat
protocol, version 9. It builds one binary, `aprond`, that should behave the
way the Go `aprond` does: same flags, same TOML config, same wire frames,
same storage format.

The Go source is the spec where `PROTOCOL.md` leaves room for choice. Tests
and tools read a local clone at `$APRON_GO_DIR`, which defaults to
`~/Developer/forks/apron-server-go`. Keep the clone unmodified. Its
`SERVER.md` documents the server's choices, and its tests define the expected
behavior.

The port also dogfoods [rust-stdlib](https://github.com/iammatthias/rust-stdlib),
Go 1.27's standard library for Rust. Wherever the Go server imports a Go
standard package, this port uses the matching rust-stdlib module.

## Layout

The Go files map one to one onto Rust modules:

| Go | Rust |
|---|---|
| `internal/server/*.go` | `src/server/*.rs` |
| `internal/store/*.go` | `src/store/*.rs` |
| `cmd/aprond/main.go`: `main` and `run` | `src/bin/aprond/main.rs` |
| `cmd/aprond/*.go`: options, config, email, ACME, listener and debug helpers | `src/aprond/*.rs` (library, so tests and the binary share it) |
| `github.com/coder/websocket` | `src/ws.rs` (RFC 6455 over a hijacked rust-stdlib connection) |
| `golang.org/x/time/rate` | `src/rate.rs` |
| `golang.org/x/image/webp` | `src/webp.rs` (the `DecodeConfig` path only, registered with rust-stdlib's `image`) |

`docs/PORT.md` holds the plan, the phase status, and the decision log.
`docs/DEVIATIONS.md` lists every known difference from the Go server.

## Rules

- **No async runtime.** rust-stdlib serves HTTP with one thread per
  connection. Where Go starts a goroutine, start a thread or reuse a worker.
  Where Go uses `time.AfterFunc`, use rust-stdlib's `time` package.
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
- **Port behavior, not just structure.** When you port a Go function, port
  its tests too: tables, edge cases, and error text. Do not mark a feature
  done until its gate in `docs/PORT.md` passes.
- **Record every difference.** If the Rust server behaves differently from
  the Go server in a way a client could see, add it to `docs/DEVIATIONS.md`.
  Prose elsewhere does not count.
- Comments explain a non-obvious *why*. Keep the Go doc comments that carry
  protocol references such as `(§4.2.1)`. Drop the ones that only restate the
  code.
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

## Upstream parity

This port tracks apron-server-go's `main`. `UPSTREAM` pins the Go commit the
port matches. Check it at the start of every session and before every pull
request:

```sh
tools/upstream/check.sh
```

It fetches the Go clone's remote refs (the checkout stays unmodified), exits 0
when the pin is upstream `main`, and otherwise exits 1 and lists the new
commits with the Rust file each changed Go path maps to. When upstream is
ahead:

1. Port each new commit in order, as its own commit here, with tests: port
   the Go test changes, and rerun the gates the paths point at (fixtures for a
   `testdata/apron` move, `tools/interop/run.sh` for `.apron-web` or
   `tests/interop` changes).
2. Update the clone's checkout to the ported commit
   (`git -C "$APRON_GO_DIR" checkout <sha>` and
   `git -C "$APRON_GO_DIR" submodule update --init`), so
   tests read the matching fixtures and suites.
3. Move `UPSTREAM` to that commit in the same change, and note it in
   `docs/PORT.md`.

Parity work comes before new features. A difference you decide not to port
goes in `docs/DEVIATIONS.md`, never just skipped. If the script reports
rewritten history (exit 2), stop and compare by hand.

## Third-party allowlist

| Crate | Replaces | Why |
|---|---|---|
| `rust-stdlib`, `rust-stdlib-crypto`, `rust-stdlib-derive`, `rust-stdlib-tls`, `rust-stdlib-sys`, `rust-stdlib-sysnet` | Go's standard library (`rust-stdlib-derive` stands in for `reflect` with `encoding/json` struct tags; `rust-stdlib-sys` holds `os/signal`, which the root crate cannot, per its ADR 0004) | The dogfooding target |
| `rusqlite` (bundled) | `modernc.org/sqlite` | rust-stdlib has `database/sql` but no SQLite driver |
| `toml` (`parse` and `serde` features only; builds `toml_parser`, `toml_datetime`, `serde_spanned`, `serde_core`, `winnow`. `Cargo.lock` also lists its optional `indexmap`, `hashbrown`, `equivalent` and `toml_writer`, which are not built, and moves `serde` to 1.0.229, whose `serde_derive` builds `syn` 3) | `github.com/BurntSushi/toml` (decoding only) | Go's standard library has no TOML, so rust-stdlib has none. The encoder `--print-config` needs is written by hand to match BurntSushi byte for byte |

## Verification

The gates are listed from cheapest to most thorough. `docs/PORT.md` names
which gate each phase must pass.

1. **Unit tests.** `cargo test`. These are ported from the Go `*_test.go`
   files.
2. **Shared fixtures.** `cargo test` loads two of the JSON vector files in
   the Go clone's `testdata/apron/tests/fixtures`, from
   `$APRON_GO_DIR/testdata/apron`: `push.json`
   (`src/server/tests/push_fixture_test.rs`) and `webauthn.json`
   (`tests/webauthn_fixture.rs`). The third file, `history.json`, has
   no server-side cases. Its checkpoint and floor cases are the web client's
   recovery arithmetic, and its room cases model a server that discards old
   history, which the Go server never does: its `history_log_id` is the
   room's creation record, and null only for a history of no rooms. The Go
   repository runs it in the web client's tests only
   (`testdata/apron/DEVELOPMENT.md`), and no test here loads it.
3. **Differential.** `tools/smoke/run.sh` builds the Go `aprond` from the
   clone and the Rust one in release, and starts a fresh pair on free ports,
   each with its own SQLite `--store` and `--upload.dir`, for each of two
   scripted WebSocket sessions: `session.mjs` (a guest session) and
   `email.mjs` (an email sign-in, a token resume, and a guest adding an
   address). `compare.mjs` diffs the two transcripts after numbering
   log_ids by first appearance and masking addresses, write tokens and file
   secrets. The script exits non-zero on any difference and removes its
   servers and temp files. It needs `go`, Node 22 and `curl`.
   `tools/differential` holds the Go programs that record the ACME,
   WebAuthn and Web Push vectors `cargo test` and
   `tools/differential/webpush/run.sh` check.
4. **Browser interop.** `tools/interop/run.sh [playwright args]` runs the Go
   repository's Playwright suites against this binary, with the real web
   client. It puts a `go` shim first on `PATH` that answers
   `go run ./cmd/aprond ...` with the Rust `aprond`. Projects: `desktop`
   (`chat`, `reference`, `webauthn`), `mobile` (`responsive`), and `push`
   (`push`, `seen`).

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
`/healthz`, `/write/`, `/files/`, `/streams/`, and
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
