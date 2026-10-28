#!/usr/bin/env bash
# Runs the Web Push differential both ways: Rust opens Go's payloads and
# matches its fixed-key bytes (vectors.json), then Go opens Rust's payloads
# and verifies Rust's VAPID tokens.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
WEBPUSH_RUST_VECTORS="$out/rust.json" cargo test --locked --manifest-path "$root/Cargo.toml" --test webpush_differential
cd "$here"
go run . check "$out/rust.json"
