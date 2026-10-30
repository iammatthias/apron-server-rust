#!/usr/bin/env bash
# Proves sign-in end to end against the deployed server: a Playwright page
# makes a passkey account in the real web client, runs /invite-device add, and hands
# the token to Ladle's ServerSession (LiveServerProofTests on Ladle's
# live-proof branch) in the environment, never on disk. The page then checks
# that the message Ladle posted arrives. Arguments go to `playwright test`.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
go_dir=${APRON_GO_DIR:-$HOME/Developer/forks/apron-server-go}
export LADLE_DIR=${LADLE_DIR:?set LADLE_DIR to a checkout of Ladle's live-proof branch}

if [[ ! -f "$LADLE_DIR/Packages/ApronKit/Tests/ApronKitIntegrationTests/LiveServerProofTests.swift" ]]; then
	echo "No LiveServerProofTests in $LADLE_DIR; set LADLE_DIR to a checkout of Ladle's live-proof branch." >&2
	exit 1
fi
if [[ ! -d "$go_dir/tests/interop/node_modules" ]]; then
	echo "Run 'make install' in $go_dir first (Node 24)." >&2
	exit 1
fi
chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if [[ -z "${PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH:-}" && -x "$chrome" ]]; then
	export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$chrome"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/apron-proof.XXXXXX")
trap 'rm -rf "$work"' EXIT
cp "$here/live.spec.ts" "$here/playwright.config.ts" "$work/"
ln -s "$go_dir/tests/interop/node_modules" "$work/node_modules"
cd "$go_dir/tests/interop"
mise exec node@24 -- npx playwright test --config "$work/playwright.config.ts" "$@"
