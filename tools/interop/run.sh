#!/usr/bin/env bash
# Runs apron-server-go's Playwright suites against the Rust aprond.
# Arguments go to `playwright test`, such as `--project=desktop chat.spec.ts`.
#
# The Go suites hard-code ports 8080 (aprond) and 5173 (Vite) in the config,
# the specs, and the web client's Vite proxy. To leave the clone unmodified and
# not collide with other local servers, this builds a shadow tree of the
# suites and the web client with the ports moved to APRON_INTEROP_PORT
# (18080) and APRON_INTEROP_WEB_PORT (15173), and runs Playwright there.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
go_dir=${APRON_GO_DIR:-$HOME/Developer/forks/apron-server-go}
port=${APRON_INTEROP_PORT:-18080}
web_port=${APRON_INTEROP_WEB_PORT:-15173}
shadow=${APRON_INTEROP_SHADOW:-$root/target/interop-shadow}

if [[ ! -f "$go_dir/.apron-web/package.json" || ! -d "$go_dir/tests/interop/node_modules" || ! -d "$go_dir/.apron-web/node_modules" ]]; then
	echo "Run 'make install' in $go_dir first (Node 24)." >&2
	exit 1
fi
for p in "$port" "$web_port"; do
	if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
		echo "Port $p is in use; set APRON_INTEROP_PORT or APRON_INTEROP_WEB_PORT." >&2
		exit 1
	fi
done

cargo build --release --bin aprond --manifest-path "$root/Cargo.toml"
export APROND_BIN="$root/target/release/aprond"
export PATH="$root/tools/interop/bin:$PATH"

mkdir -p "$shadow"
excludes=(--exclude node_modules --exclude build --exclude .svelte-kit --exclude test-results --exclude playwright-report)
rsync -a --delete "${excludes[@]}" "$go_dir/tests/interop/" "$shadow/tests/interop/"
rsync -a --delete "${excludes[@]}" "$go_dir/.apron-web/" "$shadow/.apron-web/"
ln -sfn "$go_dir/tests/interop/node_modules" "$shadow/tests/interop/node_modules"
ln -sfn "$go_dir/.apron-web/node_modules" "$shadow/.apron-web/node_modules"
ln -sfn "$go_dir/testdata" "$shadow/testdata"

sed -i '' -E "s/:8080/:$port/g; s/:5173/:$web_port/g; s/--port 5173/--port $web_port/g" \
	"$shadow"/tests/interop/*.ts "$shadow/.apron-web/vite.config.ts"
# Passkey origins default to the unmoved ports, and uploads to the user's
# Application Support directory.
uploads=$(mktemp -d "${TMPDIR:-/tmp}/apron-interop-uploads.XXXXXX")
trap 'rm -rf "$uploads"' EXIT
sed -i '' -E "s|'--addr 127\.0\.0\.1:$port',|'--addr 127.0.0.1:$port', '--webauthn.origin http://localhost:$web_port', '--webauthn.origin http://localhost:$port', '--upload.dir $uploads',|" \
	"$shadow/tests/interop/playwright.config.ts"
if grep -rnE ':(8080|5173)\b' "$shadow"/tests/interop/*.ts "$shadow/.apron-web/vite.config.ts"; then
	echo "Unmoved port references remain (above)." >&2
	exit 1
fi

# Without Playwright's own Chromium, use an installed Chrome; the Go config reads this variable.
chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if [[ -z "${PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH:-}" && -x "$chrome" ]]; then
	export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$chrome"
fi
cd "$shadow/tests/interop"
# The web client needs Node 24 (.node-version in the Go repository).
mise exec node@24 -- npx playwright test "$@"
