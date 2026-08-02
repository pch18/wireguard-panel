#!/bin/sh

set -eu

script_directory="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
project_directory="$(dirname "$script_directory")"

git_setting() {
  git -C "$project_directory" config --get "$1" 2>/dev/null || true
}

deploy_host="${WIREGUARD_PANEL_DEPLOY_HOST:-$(git_setting wireguard-panel.deployHost)}"
deploy_user="${WIREGUARD_PANEL_DEPLOY_USER:-$(git_setting wireguard-panel.deployUser)}"
deploy_identity="${WIREGUARD_PANEL_DEPLOY_IDENTITY:-$(git_setting wireguard-panel.deployIdentity)}"
deploy_ssh_port="${WIREGUARD_PANEL_DEPLOY_SSH_PORT:-$(git_setting wireguard-panel.deploySshPort)}"
panel_port="${WIREGUARD_PANEL_DEPLOY_PANEL_PORT:-$(git_setting wireguard-panel.deployPanelPort)}"

deploy_user="${deploy_user:-root}"
deploy_ssh_port="${deploy_ssh_port:-22}"
panel_port="${panel_port:-8080}"

[ -n "$deploy_host" ] || {
  printf 'Missing deployment host. Set WIREGUARD_PANEL_DEPLOY_HOST or git config wireguard-panel.deployHost.\n' >&2
  exit 1
}
if [ -n "$deploy_identity" ] && [ ! -f "$deploy_identity" ]; then
  printf 'Deployment identity does not exist: %s\n' "$deploy_identity" >&2
  exit 1
fi

ssh_target="${deploy_user}@${deploy_host}"
ssh_run() {
  if [ -n "$deploy_identity" ]; then
    ssh -o BatchMode=yes -o IdentitiesOnly=yes \
      -p "$deploy_ssh_port" -i "$deploy_identity" "$ssh_target" "$@"
  else
    ssh -o BatchMode=yes -o IdentitiesOnly=yes \
      -p "$deploy_ssh_port" "$ssh_target" "$@"
  fi
}

check_remote() {
  ssh_run sh -s -- "$panel_port" <<'REMOTE'
set -eu
panel_port="$1"
[ -f /etc/alpine-release ]
[ "$(uname -m)" = "x86_64" ]
rc-service wireguard-panel status
rc-update show default | grep -q wireguard-panel
ss -lnt | grep -q ":${panel_port}"
curl -fsS --max-time 5 "http://127.0.0.1:${panel_port}/api/health"
REMOTE
  printf '\nExternal health: '
  curl -fsS --max-time 10 "http://${deploy_host}:${panel_port}/api/health"
  printf '\n'
}

if [ "${1:-}" = "--check" ]; then
  check_remote
  exit 0
fi

release_tag="${1:-}"
if [ -z "$release_tag" ]; then
  release_tag="$({
    curl -fsSL https://api.github.com/repos/pch18/wireguard-panel/releases/latest
  } | sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
fi
case "$release_tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *)
    printf 'Invalid or unavailable release tag: %s\n' "$release_tag" >&2
    exit 1
    ;;
esac

printf 'Deploying WireGuard Panel %s to %s...\n' "$release_tag" "$ssh_target"
ssh_run sh -s -- "$release_tag" "$panel_port" <<'REMOTE'
set -eu
release_tag="$1"
panel_port="$2"

[ "$(id -u)" -eq 0 ]
[ -f /etc/alpine-release ]
[ "$(uname -m)" = "x86_64" ]

missing_packages=""
for package in curl wireguard-tools iproute2; do
  if ! apk info -e "$package" >/dev/null 2>&1; then
    missing_packages="${missing_packages} ${package}"
  fi
done
if [ -n "$missing_packages" ]; then
  # Package names are selected from the fixed list above.
  apk add --no-cache $missing_packages
fi

installer_path="$(mktemp /tmp/wireguard-panel-install.XXXXXX)"
pinned_installer_path="${installer_path}.pinned"
trap 'rm -f "$installer_path" "$pinned_installer_path"' EXIT HUP INT TERM
curl -fsSL \
  "https://raw.githubusercontent.com/pch18/wireguard-panel/${release_tag}/install-alpine.sh" \
  -o "$installer_path"
# Older installers always use Latest Release. Pin their download URL as well,
# so deploying or rolling back an old tag can never install a different tag.
sed \
  "s#https://github.com/pch18/wireguard-panel/releases/latest/download#https://github.com/pch18/wireguard-panel/releases/download/${release_tag}#g" \
  "$installer_path" >"$pinned_installer_path"
chmod 0700 "$pinned_installer_path"
WIREGUARD_PANEL_RELEASE_TAG="$release_tag" "$pinned_installer_path"

attempt=0
until curl -fsS --max-time 2 \
  "http://127.0.0.1:${panel_port}/api/health" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 10 ] || {
    printf 'Panel health check failed after deployment.\n' >&2
    exit 1
  }
  sleep 1
done
REMOTE

check_remote
printf 'WireGuard Panel %s deployed successfully.\n' "$release_tag"
