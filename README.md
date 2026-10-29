# apron-server-rust

An unofficial Rust port of
[apron-server-go](https://github.com/apron-chat/apron-server-go), the
reference server for [Apron](https://github.com/shazow/apron), a small, open
chat protocol over WebSockets. It builds one binary, `aprond`, with the Go
server's flags, config file, wire frames, and storage format.

Apron and apron-server-go belong to their authors. This repository is not
part of either project, and their maintainers do not review it. Report a
problem with this port here, not upstream.

The port runs on [rust-stdlib](https://github.com/iammatthias/rust-stdlib),
a port of Go's standard library to Rust, and has no async runtime. One
thread serves each connection, and one mutex guards server state, as in the
Go server.

## Status

The port matches apron-server-go at commit
[`f137c64`](https://github.com/apron-chat/apron-server-go/commit/f137c64c3f2fe1b3fbc6464619e9d9e5c4a76127),
protocol version 9. The `UPSTREAM` file pins that commit, and
`tools/upstream/check.sh` lists the upstream commits not yet ported.

These checks pass at the current commit:

- `cargo test` runs 321 tests, ported from the Go `*_test.go` files. One more,
  `TestNamesAreNormalized`, is ignored because it needs NFKC normalization.
  The run includes comparisons against the Go binary, the shared JSON
  fixtures from the Go repository, and ACME certificates issued by Pebble.
- `tools/smoke/run.sh` runs a guest session and an email sign-in session
  against this server and checks that every request is answered once,
  without an internal error.

`docs/PORT.md` records two more results from earlier in the port:

- `tools/crossopen/run.sh` registered a passkey on one server's SQLite
  database and signed in with it on the other, in both directions.
- `tools/interop/run.sh` runs the Go repository's Playwright suites, with
  the real web client, against this binary. The last recorded run passed 43
  of 44 tests.

The failing interop test, `push.spec.ts:257`, sends a Web Push delivery
after the push host has closed its idle connection. rust-stdlib's HTTP
client reuses the closed connection, so the delivery fails. The fix belongs
in rust-stdlib.

[docs/DEVIATIONS.md](docs/DEVIATIONS.md) lists every known difference a
client can see, including two extensions the Go server lacks:
`--apple.app-id` and the `/invite-device` command.
[docs/PORT.md](docs/PORT.md) holds the port plan, the gate results, and the
decision log.

## Build and run

You need Rust 1.87 or later.

```sh
cargo run --bin aprond -- --store memory
```

The server listens on `127.0.0.1:8080`, with the WebSocket endpoint at
`/ws`. Point the [Apron web client](https://github.com/apron-chat/apron-web)
at it, or serve a build of the web client from the same origin with
`--static-dir`. Run `aprond --help` for every flag. The flags are the Go
server's, so apron-server-go's
[SERVER.md](https://github.com/apron-chat/apron-server-go/blob/main/SERVER.md)
describes them too.

For a persistent server, use SQLite:

```sh
cargo build --release
target/release/aprond --store sqlite:aprond.db --upload.dir uploads
```

## Test

The full test run compares against a clone of apron-server-go and needs Go
1.27:

```sh
git clone --recurse-submodules https://github.com/apron-chat/apron-server-go
git -C apron-server-go checkout f137c64c3f2fe1b3fbc6464619e9d9e5c4a76127
git -C apron-server-go submodule update --init
export APRON_GO_DIR=$PWD/apron-server-go
cargo test
```

The ACME test also needs Pebble. [AGENTS.md](AGENTS.md) lists the install
command, the other gates, and the variables that skip a gate on purpose.

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

When this port needs a rust-stdlib fix, the fix goes to rust-stdlib first,
as its own pull request. While it is in review, a `[patch]` section or a
temporary local git URL points this crate at the branch. After the pull
request merges, the pinned `rev` moves to the new commit.

## License

[MIT](LICENSE). [NOTICE](NOTICE) lists the Go code this crate ports and the
license of each.
