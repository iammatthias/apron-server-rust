# apron-server-rust

An unofficial Rust server for [Apron](https://github.com/shazow/apron), a
small, open chat protocol over WebSockets. It builds one binary, `aprond`,
that follows
[apron-server-cloudflare](https://github.com/apron-chat/apron-server-cloudflare):
its `SPEC.md`, its behavior and its defaults.

Apron and its servers belong to their authors. This repository is not part
of the Apron project, and its maintainers do not review it. Report a
problem with this server here, not upstream.

The server runs on [rust-stdlib](https://github.com/iammatthias/rust-stdlib),
a port of Go's standard library to Rust, and has no async runtime. One
thread serves each connection, and one mutex guards server state.

## Status

The server began as a port of
[apron-server-go](https://github.com/apron-chat/apron-server-go) at commit
[`f137c64`](https://github.com/apron-chat/apron-server-go/commit/f137c64c3f2fe1b3fbc6464619e9d9e5c4a76127),
protocol version 9. It keeps that server's command-line flags and TOML
config layout, and adds flags of its own. Its reference is now
apron-server-cloudflare. Go is a fallback only where Cloudflare is silent.
The `REFERENCE` file pins the Cloudflare and protocol commits last
reviewed, and `tools/reference/check.sh` lists the commits since then that
change the behavior contract.

These checks pass at the current commit:

- `cargo test` runs the tests ported from apron-server-go's `*_test.go`
  files and from apron-server-cloudflare's integration tests, the shared
  JSON fixtures of the protocol repository, the WebAuthn, Web Push and ACME
  vectors recorded from Go libraries, and ACME certificates issued by
  Pebble. One test, `TestNamesAreNormalized`, is ignored because it needs
  NFKC normalization.
- `tools/smoke/run.sh` runs a guest session and an email sign-in session
  against this server. It checks that every request is answered once,
  without an internal error, and that the `server` frame lists the
  extensions apron-server-cloudflare's does.
- `tools/interop/run.sh` runs apron-server-go's Playwright suites, with the
  real web client, against this binary. The tests that fail by design,
  where this server follows Cloudflare, are listed in
  `tools/interop/expected-failures.md`. Any other failure is a regression.

One expected failure, `push.spec.ts:257`, is a bug: it sends a Web Push
delivery after the push host has closed its idle connection. rust-stdlib's
HTTP client reuses the closed connection, so the delivery fails. The fix
belongs in rust-stdlib.

[docs/DEVIATIONS.md](docs/DEVIATIONS.md) lists every known difference from
apron-server-cloudflare a client can see, and the extensions it lacks, such
as email sign-in, link previews, `--apple.app-id` and read receipts.
[docs/PORT.md](docs/PORT.md) holds the port's history: the phase plan, the
gate results, and the decision log.

## Build and run

You need Rust 1.87 or later.

```sh
cargo run --bin aprond -- --store memory
```

The server listens on `127.0.0.1:8080`, with the WebSocket endpoint at
`/ws`. Point the [Apron web client](https://github.com/apron-chat/apron-web)
at it, or serve a build of the web client from the same origin with
`--static-dir`. Run `aprond --help` for every flag.

For a persistent server, use SQLite:

```sh
cargo build --release
target/release/aprond --store sqlite:aprond.db --upload.dir uploads
```

## Test

`cargo test` loads two shared fixtures, `push.json` and `webauthn.json`,
from a checkout of apron-server-go, whose `testdata/apron` submodule holds
the protocol repository. The browser suites in `tools/interop` come from
the same checkout. Clone it once at the commit the port started from, and
point `APRON_GO_DIR` at it:

```sh
git clone --recurse-submodules https://github.com/apron-chat/apron-server-go
git -C apron-server-go checkout f137c64c3f2fe1b3fbc6464619e9d9e5c4a76127
git -C apron-server-go submodule update --init
export APRON_GO_DIR=$PWD/apron-server-go
cargo test
```

Two gates run tools outside Cargo. The ACME differential needs Go 1.27 on
`PATH`, and the ACME issuance test needs Pebble. Set `APRON_SKIP_GO=1` or
`APRON_SKIP_PEBBLE=1` to skip one on purpose. [AGENTS.md](AGENTS.md) lists
the install commands and the other gates.

## Deploy

`deploy/` holds the Compose project for the public test server at
https://apron.farfield.systems. It runs three containers on one origin:
`aprond`, `web`, which serves a build of
[apron-web](https://github.com/apron-chat/apron-web), and `router`, which
sends aprond's paths to aprond and everything else to `web`. The server and
the web client deploy as separate images.

`tools/deploy/deploy.sh` builds a source bundle with vendored dependencies
and the web build, copies it to a Docker host over SSH, and starts it there.
Set `APRON_DEPLOY_HOST` to the SSH destination. The script's header lists the
other settings. To run your own server, change the URLs and `--apple.app-id`
in `deploy/compose.yaml`.

## The rust-stdlib dependency

`Cargo.toml` takes every rust-stdlib crate from
https://github.com/iammatthias/rust-stdlib at a pinned `rev`, so a fresh
checkout builds with no other setup.

When this server needs a rust-stdlib fix, the fix goes to rust-stdlib first,
as its own pull request. While it is in review, a `[patch]` section or a
temporary local git URL points this crate at the branch. After the pull
request merges, the pinned `rev` moves to the new commit.

## License

[MIT](LICENSE). [NOTICE](NOTICE) lists the Go code this crate ports and the
license of each.
