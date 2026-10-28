#!/usr/bin/env bash
# Runs the smoke sessions against the Go and the Rust aprond and compares
# the transcripts: session.mjs (a guest session) and email.mjs (an email
# sign-in, a token resume, and an address added by a guest). Each session
# gets a fresh pair of servers on free ports, each with its own SQLite store
# and upload directory. Exits non-zero if a transcript differs, a script
# fails, or a server does not come up.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
go_dir=${APRON_GO_DIR:-$HOME/Developer/forks/apron-server-go}
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

echo "building the Go aprond from $go_dir"
(cd "$go_dir" && go build -o "$tmp/aprond-go" ./cmd/aprond)
echo "building the Rust aprond"
cargo build --release --locked --bin aprond --manifest-path "$root/Cargo.toml"
cp "$root/target/release/aprond" "$tmp/aprond-rust"

free_port() {
	node -e 'const s = require("node:net").createServer(); s.listen(0, "127.0.0.1", () => { console.log(s.address().port); s.close(); });'
}

# start <impl> <session> <port> [flags...]: starts one server with its own
# store and upload directory, logging to $tmp/<session>-<impl>.log, and
# waits for /healthz.
start() {
	local impl=$1 session=$2 port=$3
	shift 3
	local dir="$tmp/$session-$impl"
	mkdir -p "$dir/up"
	"$tmp/aprond-$impl" --addr "127.0.0.1:$port" --store "sqlite:$dir/aprond.db" \
		--upload.dir "$dir/up" --push.disable "$@" >"$tmp/$session-$impl.log" 2>&1 &
	pids+=($!)
	for _ in $(seq 100); do
		if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
			return
		fi
		sleep 0.1
	done
	echo "the $impl aprond did not start on port $port:" >&2
	cat "$tmp/$session-$impl.log" >&2
	exit 1
}

failed=0
# run <session>: runs <session>.mjs against both servers and compares.
run() {
	local session=$1
	for impl in go rust; do
		local port
		port=$(free_port)
		local flags=()
		local args=("ws://127.0.0.1:$port/ws")
		if [[ $session == email ]]; then
			flags=(--email.enable --email.sender log --email.link-url "http://127.0.0.1:$port/login")
			args+=("$tmp/$session-$impl.log")
		fi
		start "$impl" "$session" "$port" "${flags[@]+"${flags[@]}"}"
		node "$smoke/$session.mjs" "${args[@]}" >"$tmp/$session-$impl.txt"
	done
	echo "$session.mjs:"
	if ! node "$smoke/compare.mjs" "$tmp/$session-go.txt" "$tmp/$session-rust.txt"; then
		failed=1
	fi
}

run session
run email
exit "$failed"
