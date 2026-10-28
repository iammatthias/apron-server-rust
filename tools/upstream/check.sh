#!/usr/bin/env bash
# Lists what changed in apron-server-go since the commit in UPSTREAM, and where
# each change lands in this port. Exits 1 when upstream main is ahead, so it
# can gate a session or a PR. Fetching updates only the clone's remote refs;
# the clone's checkout stays as it is.
#
#   tools/upstream/check.sh            # fetch, then report
#   tools/upstream/check.sh --no-fetch # report from the refs already fetched
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
go_dir=${APRON_GO_DIR:-$HOME/Developer/forks/apron-server-go}
pinned=$(awk '$1 == "apron-server-go" {print $2}' "$root/UPSTREAM")

if [[ "${1:-}" != --no-fetch ]]; then
	git -C "$go_dir" fetch -q origin
fi
head=$(git -C "$go_dir" rev-parse origin/main)
if [[ "$head" == "$pinned" ]]; then
	echo "In parity: UPSTREAM matches apron-server-go origin/main (${pinned:0:7})."
	exit 0
fi
if ! git -C "$go_dir" merge-base --is-ancestor "$pinned" "$head"; then
	echo "UPSTREAM ${pinned:0:7} is not an ancestor of origin/main ${head:0:7}: upstream history was rewritten. Compare by hand." >&2
	exit 2
fi

# Where a Go path is ported. Keep in step with the layout table in AGENTS.md.
target() {
	case "$1" in
	internal/server/helpers_test.go) echo "src/server/tests/helpers.rs" ;;
	internal/server/*_test.go) echo "src/server/tests/$(basename "$1" .go).rs" ;;
	internal/server/*.go) echo "src/server/$(basename "$1" .go).rs" ;;
	internal/store/*_test.go) echo "src/store/ tests" ;;
	internal/store/*.go) echo "src/store/$(basename "$1" .go | sed 's/^store$/mod/').rs" ;;
	cmd/aprond/*) echo "src/aprond/ and src/bin/aprond/main.rs" ;;
	cmd/apron-hammer/*) echo "not ported (load tool)" ;;
	testdata/apron) echo "protocol and fixtures: diff PROTOCOL.md and tests/fixtures between the two submodule commits" ;;
	.apron-web) echo "web client pin: rerun tools/interop/run.sh" ;;
	tests/interop/*) echo "browser suites: rerun tools/interop/run.sh (run.sh moves their ports)" ;;
	go.mod | go.sum) echo "dependencies: check the libraries this port replaces (webauthn, websocket, autocert, toml, flags)" ;;
	SERVER.md | DEVELOPMENT.md | README.md) echo "docs: server behavior notes; check docs/DEVIATIONS.md" ;;
	*) echo "review" ;;
	esac
}

count=$(git -C "$go_dir" rev-list --count "$pinned..$head")
echo "apron-server-go origin/main is $count commit(s) ahead of UPSTREAM (${pinned:0:7} -> ${head:0:7}):"
echo
git -C "$go_dir" log --reverse --format='  %h %s' "$pinned..$head"
echo
echo "Changed paths and where they land here:"
git -C "$go_dir" diff --name-only "$pinned" "$head" | while read -r path; do
	printf '  %-40s -> %s\n' "$path" "$(target "$path")"
done
if git -C "$go_dir" diff --quiet "$pinned" "$head" -- testdata/apron; then :; else
	echo
	echo "testdata/apron moved:"
	git -C "$go_dir" diff "$pinned" "$head" -- testdata/apron | grep '^[-+]Subproject' | sed 's/^/  /'
fi
exit 1
