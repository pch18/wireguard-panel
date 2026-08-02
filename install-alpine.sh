#!/bin/sh

set -eu

asset="wireguard-panel_linux_amd64.tar.gz"
release_tag="${WIREGUARD_PANEL_RELEASE_TAG:-}"
if [ -n "$release_tag" ] && ! printf '%s\n' "$release_tag" | \
  grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  printf 'wireguard-panel installer: invalid release tag: %s\n' "$release_tag" >&2
  exit 1
fi
if [ -n "$release_tag" ]; then
  release="https://github.com/pch18/wireguard-panel/releases/download/${release_tag}"
else
  release="https://github.com/pch18/wireguard-panel/releases/latest/download"
fi
binary="/usr/local/bin/wireguard-panel"
service="/etc/init.d/wireguard-panel"

fail() {
  printf 'wireguard-panel installer: %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ -f /etc/alpine-release ] || fail "only Alpine Linux is supported"
[ "$(uname -m)" = "x86_64" ] || fail "only Linux AMD64 is supported"

for command in curl sha256sum tar install cp mv rc-update rc-service; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

for command in wg wg-quick ip; do
  command -v "$command" >/dev/null 2>&1 || \
    fail "$command is required (install wireguard-tools and iproute2 first)"
done

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

printf 'Downloading WireGuard Panel...\n'
curl -fsSL "${release}/${asset}" -o "${temporary_directory}/${asset}"
curl -fsSL "${release}/${asset}.sha256" -o "${temporary_directory}/${asset}.sha256"

(
  cd "$temporary_directory"
  sha256sum -c "${asset}.sha256"
)
tar -xzf "${temporary_directory}/${asset}" -C "$temporary_directory"

had_previous_binary=false
if [ -f "$binary" ]; then
  cp -p "$binary" "${temporary_directory}/wireguard-panel.previous"
  had_previous_binary=true
fi
had_previous_service=false
if [ -f "$service" ]; then
  cp -p "$service" "${temporary_directory}/wireguard-panel.openrc.previous"
  had_previous_service=true
fi
had_previous_default=false
if rc-update show default 2>/dev/null | \
  grep -Eq '(^|[[:space:]])wireguard-panel([[:space:]]|$)'; then
  had_previous_default=true
fi
had_previous_running=false
if [ "$had_previous_service" = true ] && \
  rc-service wireguard-panel status >/dev/null 2>&1; then
  had_previous_running=true
fi

panel_port=8080
if [ -r /etc/conf.d/wireguard-panel ]; then
  # OpenRC sources this root-owned file before starting the service. Source the
  # same file so the health check verifies the port the process actually uses.
  APP_PORT=""
  # shellcheck disable=SC1091
  . /etc/conf.d/wireguard-panel
  panel_port="${APP_PORT:-8080}"
fi
case "$panel_port" in
  ''|*[!0-9]*) fail "APP_PORT must be numeric" ;;
esac

panel_is_healthy() {
  rc-service wireguard-panel status >/dev/null 2>&1 &&
    curl -fsS --max-time 2 \
      "http://127.0.0.1:${panel_port}/api/health" >/dev/null 2>&1
}

wait_for_panel() {
  attempt=0
  while ! panel_is_healthy; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 10 ] || return 1
    sleep 1
  done
}

rollback_installation() {
  reason="$1"
  rc-service wireguard-panel stop >/dev/null 2>&1 || true

  if [ "$had_previous_binary" = true ]; then
    install -m 0755 "${temporary_directory}/wireguard-panel.previous" "$binary"
  else
    rm -f "$binary"
  fi
  if [ "$had_previous_service" = true ]; then
    install -m 0755 \
      "${temporary_directory}/wireguard-panel.openrc.previous" "$service"
  else
    rm -f "$service"
  fi
  if [ "$had_previous_default" = true ]; then
    rc-update add wireguard-panel default >/dev/null 2>&1 || true
  else
    rc-update del wireguard-panel default >/dev/null 2>&1 || true
  fi

  if [ "$had_previous_running" = true ]; then
    if rc-service wireguard-panel start >/dev/null 2>&1 && wait_for_panel; then
      fail "$reason; the previous panel was restored and is healthy"
    fi
    fail "$reason; restoring the previous panel did not recover a healthy service"
  fi
  fail "$reason; the previous stopped or uninstalled state was restored"
}

install -m 0755 "${temporary_directory}/wireguard-panel" "${binary}.new"
mv "${binary}.new" "$binary"

cat >"${temporary_directory}/wireguard-panel.openrc" <<'OPENRC'
#!/sbin/openrc-run

name="wireguard-panel"
description="WireGuard configuration panel"
export GIN_MODE="release"
command="/usr/local/bin/wireguard-panel"
command_user="root:root"
supervisor="supervise-daemon"
respawn_delay=5
respawn_max=0

depend() {
  need net
  after firewall
}
OPENRC
install -m 0755 "${temporary_directory}/wireguard-panel.openrc" "$service"

if ! rc-update add wireguard-panel default >/dev/null; then
  rollback_installation "the panel could not be registered with OpenRC"
fi
if ! rc-service wireguard-panel restart; then
  rollback_installation "the new panel failed to start"
fi
if ! wait_for_panel; then
  rollback_installation "the new panel started but did not become healthy"
fi

printf '\nWireGuard Panel installed: http://SERVER_IP:%s\n' "$panel_port"
printf 'Default login: admin/admin5555\n'
printf 'Change the password from the account menu after signing in.\n'
