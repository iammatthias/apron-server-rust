#!/usr/bin/env bash
# Deploys the committed HEAD over SSH to a Docker host that serves
# deploy/compose.yaml, and waits for its public URL to answer /healthz.
#
# Settings come from the environment or from tools/deploy/local.env, which
# git ignores:
#   APRON_DEPLOY_HOST  the SSH destination, such as user@host (required)
#   APRON_DEPLOY_DIR   the bundle directory on the host (default: apron)
#   APRON_SECRETS_DIR  a directory on the host, outside the bundle, that holds
#                      the admin token (default: ~/apron-secrets)
#   APRON_PUBLIC_URL   the URL to check (default: https://apron.farfield.systems)
#   APRON_WEB_DIR      a checkout of apron-chat/apron-web (default:
#                      ~/Developer/forks/apron-web)
#   APRON_WEB_BUILD    a built web client to ship as is; unset, the script
#                      builds $APRON_WEB_DIR same-origin and ships its build/
#
# The host builds offline, so this ships a source bundle instead of a git
# checkout: the crate at HEAD, `cargo vendor` output with its
# .cargo/config.toml, deploy/, and the web build in deploy/web. Rerunning it
# converges: rsync --delete replaces the bundle, compose rebuilds and
# recreates only what changed, and the data volume is kept.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
if [[ -f "$root/tools/deploy/local.env" ]]; then
	source "$root/tools/deploy/local.env"
fi
host=${APRON_DEPLOY_HOST:?set APRON_DEPLOY_HOST to the SSH destination, in the environment or tools/deploy/local.env}
dest=${APRON_DEPLOY_DIR:-apron}
url=${APRON_PUBLIC_URL:-https://apron.farfield.systems}
web_dir=${APRON_WEB_DIR:-$HOME/Developer/forks/apron-web}

if [[ -n ${APRON_WEB_BUILD:-} ]]; then
	web=$APRON_WEB_BUILD
else
	# Empty URLs build a client that connects to the origin serving it.
	(cd "$web_dir" && npm ci && VITE_DEFAULT_SERVER_URL= VITE_TRUSTED_MEDIA_ORIGINS= npm run build)
	web=$web_dir/build
fi
if [[ ! -f "$web/index.html" ]]; then
	echo "No web build at $web." >&2
	exit 1
fi
if [[ -n $(git -C "$root" status --porcelain -- Cargo.toml Cargo.lock src deploy) ]]; then
	echo "Uncommitted changes under Cargo.toml, Cargo.lock, src or deploy; this deploys HEAD only." >&2
fi

bundle=$(mktemp -d "${TMPDIR:-/tmp}/apron-bundle.XXXXXX")
trap 'rm -rf "$bundle"' EXIT
git -C "$root" archive HEAD Cargo.toml Cargo.lock src deploy | tar -x -C "$bundle"
mkdir -p "$bundle/.cargo"
(cd "$bundle" && cargo vendor --locked vendor >.cargo/config.toml 2>/dev/null)
grep -q vendored-sources "$bundle/.cargo/config.toml"
rsync -a --delete "$web/" "$bundle/deploy/web/"

ssh -o BatchMode=yes "$host" "mkdir -p $dest"
rsync -az --delete -e 'ssh -o BatchMode=yes' "$bundle/" "$host:$dest/"
# The admin token is made once and never replaced or printed. The directory
# is 0700, so only the host user reaches the 0644 file, which aprond's
# non-root container user needs to read through the bind mount.
secrets=$(ssh -o BatchMode=yes "$host" 'bash -s' -- "${APRON_SECRETS_DIR:-}" <<'REMOTE'
set -euo pipefail
dir=${1:-$HOME/apron-secrets}
umask 077
mkdir -p "$dir"
if [[ ! -s $dir/admin_token ]]; then
	openssl rand -hex 32 >"$dir/admin_token.tmp"
	mv "$dir/admin_token.tmp" "$dir/admin_token"
fi
chmod 0644 "$dir/admin_token"
cd "$dir" && pwd
REMOTE
)
ssh -o BatchMode=yes "$host" "cd $dest && APRON_SECRETS_DIR='$secrets' docker compose -f deploy/compose.yaml up -d --build \
	&& docker image prune -f --filter label=systems.farfield.project=apron >/dev/null"

echo "Deployed $(git -C "$root" rev-parse --short HEAD); waiting for $url/healthz"
for _ in $(seq 60); do
	if curl -fsS -A apron-deploy -o /dev/null "$url/healthz"; then
		ssh -o BatchMode=yes "$host" "cd $dest && APRON_SECRETS_DIR='$secrets' docker compose -f deploy/compose.yaml ps"
		exit 0
	fi
	sleep 2
done
echo "$url/healthz did not answer 200. The containers are up; check the reverse proxy in front of them." >&2
ssh -o BatchMode=yes "$host" "cd $dest && export APRON_SECRETS_DIR='$secrets' && docker compose -f deploy/compose.yaml ps && docker compose -f deploy/compose.yaml logs --tail 20"
exit 1
