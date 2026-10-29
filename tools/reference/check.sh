#!/usr/bin/env bash
# Lists the commits since each pin in REFERENCE that touch a reference's
# behavior contract (SPEC.md, src/, docs/, PROTOCOL.md, EXTENSIONS.md), as a
# review queue. Exits 0 when no repository has such a commit, 1 when one has,
# and 2 when a pin is no longer an ancestor of main (history was rewritten).
#
#   tools/reference/check.sh            # fetch, then report
#   tools/reference/check.sh --no-fetch # report from the refs already fetched
#
# Each repository is kept as a bare, blobless clone under
# $APRON_REFERENCE_DIR (default ~/.cache/apron-reference).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cache=${APRON_REFERENCE_DIR:-$HOME/.cache/apron-reference}
paths=(SPEC.md src docs PROTOCOL.md EXTENSIONS.md)
status=0

while read -r repo pinned; do
	dir="$cache/${repo//\//_}.git"
	if [[ ! -d "$dir" ]]; then
		git clone -q --bare --filter=blob:none "https://github.com/$repo.git" "$dir"
	elif [[ "${1:-}" != --no-fetch ]]; then
		git -C "$dir" fetch -q origin '+refs/heads/main:refs/heads/main'
	fi
	head=$(git -C "$dir" rev-parse main)
	if ! git -C "$dir" merge-base --is-ancestor "$pinned" "$head"; then
		echo "$repo: pin ${pinned:0:7} is not an ancestor of main ${head:0:7}; history was rewritten. Compare by hand." >&2
		status=2
		continue
	fi
	commits=$(git -C "$dir" log --reverse --date=short --format='  %h %ad %s' "$pinned..$head" -- "${paths[@]}")
	if [[ -z "$commits" ]]; then
		echo "$repo: nothing to review since ${pinned:0:7} (main ${head:0:7})."
		continue
	fi
	echo "$repo: to review, ${pinned:0:7} -> ${head:0:7}:"
	echo "$commits"
	echo
	[[ $status == 0 ]] && status=1
done < <(grep -v '^\s*\(#\|$\)' "$root/REFERENCE")
exit $status
