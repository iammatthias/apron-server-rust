#!/usr/bin/env bash
# Runs the smoke sessions against the Rust aprond and checks each transcript
# with check.mjs: session.mjs (a guest session) and email.mjs (an email
# sign-in, a token resume, and an address added by a guest). Each session
# gets a fresh server on a free port with its own SQLite store and upload
# directory. Exits non-zero if a check fails, a script fails, or the server
# does not come up. It needs Node 22 and curl.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
smoke="$root/tools/smoke"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/apron-smoke.XXXXXX")
pids=()
cleanup() {
	for pid in "${pids[@]+"${pids[@]}"}"; do
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
	rm -rf "$tmp"
}
trap cleanup EXIT

cargo build --release --locked --bin aprond --manifest-path "$root/Cargo.toml"
aprond="$root/target/release/aprond"

free_port() {
	node -e 'const s = require("node:net").createServer(); s.listen(0, "127.0.0.1", () => { console.log(s.address().port); s.close(); });'
}

# start <session> <port> [flags...]: starts a server with its own store and
# upload directory, logging to $tmp/<session>.log, and waits for /healthz.
# The guest session posts, which takes --guest.posting.
start() {
	local session=$1 port=$2
	shift 2
	local dir="$tmp/$session"
	mkdir -p "$dir/up"
	"$aprond" --addr "127.0.0.1:$port" --store "sqlite:$dir/aprond.db" \
		--upload.dir "$dir/up" --push.disable --guest.posting "$@" >"$tmp/$session.log" 2>&1 &
	pids+=($!)
	for _ in $(seq 100); do
		if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
			return
		fi
		sleep 0.1
	done
	echo "aprond did not start on port $port:" >&2
	cat "$tmp/$session.log" >&2
	exit 1
}

failed=0
run() {
	local session=$1 port
	port=$(free_port)
	local flags=()
	local args=("ws://127.0.0.1:$port/ws")
	if [[ $session == email ]]; then
		flags=(--email.enable --email.sender log --email.link-url "http://127.0.0.1:$port/login")
		args+=("$tmp/$session.log")
	fi
	start "$session" "$port" "${flags[@]+"${flags[@]}"}"
	node "$smoke/$session.mjs" "${args[@]}" >"$tmp/$session.txt"
	echo "$session.mjs:"
	if ! node "$smoke/check.mjs" "$tmp/$session.txt"; then
		failed=1
	fi
}

run session
run email
exit "$failed"
