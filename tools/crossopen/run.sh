#!/usr/bin/env bash
# Registers a passkey user with one aprond on a SQLite database, then opens
# that database with the other and resumes the user's token and signs in with
# the passkey, in both directions (Go to Rust, Rust to Go).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
go_dir=${APRON_GO_DIR:-$HOME/Developer/forks/apron-server-go}
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; tail -n 5 "$work"/*.log >&2; rm -rf "$work"' EXIT
cargo build --release --bin aprond --manifest-path "$root/Cargo.toml" >&2
(cd "$go_dir" && go build -o "$work/go-aprond" ./cmd/aprond)
(cd "$here" && go build -o "$work/crossopen" .)
origin=http://localhost:5173
port=18190
pid=

serve() { # implementation database
	local cmd=("$work/go-aprond" --upload.dir "$work/uploads")
	[[ $1 == rust ]] && cmd=("$root/target/release/aprond")
	port=$((port + 1))
	if curl -s "http://127.0.0.1:$port/healthz" >/dev/null; then
		echo "port $port is taken" >&2; exit 1
	fi
	"${cmd[@]}" --store "sqlite:$2" --addr "127.0.0.1:$port" 2>>"$work/$1.log" &
	pid=$!
	for _ in $(seq 100); do curl -sf "http://127.0.0.1:$port/healthz" >/dev/null && return; sleep 0.1; done
	echo "$1 aprond did not start" >&2; cat "$work/$1.log" >&2; exit 1
}

# Background jobs ignore SIGINT in a script, and the interim Rust aprond has
# no graceful shutdown before phase 3, so give the store writer a moment and
# terminate.
stop() { sleep 1; kill -TERM "$pid"; wait "$pid" 2>/dev/null || true; }

for pair in "go rust" "rust go"; do
	set -- $pair
	db="$work/$1-wrote.db"
	serve "$1" "$db"
	read -r user token < <("$work/crossopen" register "ws://127.0.0.1:$port/ws" "$origin" "$work/$1.key")
	stop
	serve "$2" "$db"
	resumed=$("$work/crossopen" resume "ws://127.0.0.1:$port/ws" "$origin" "$token")
	signed=$("$work/crossopen" login "ws://127.0.0.1:$port/ws" "$origin" "$work/$1.key")
	stop
	echo "$1 registered $user; $2 resumed the token as $resumed and signed in with the passkey as $signed"
	[[ "$resumed" == "$user" && "$signed" == "$user" ]]
	echo "stored passkey user: $(sqlite3 "$db" "select value from entries where kind='user' and id='$user'" 2>/dev/null )"
done
echo "cross-open: ok"
