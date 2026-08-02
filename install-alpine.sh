#!/bin/sh

set -eu

asset="wireguard-panel_linux_amd64.tar.gz"
release="https://github.com/pch18/wireguard-panel/releases/latest/download"
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

rc-update add wireguard-panel default >/dev/null
if ! rc-service wireguard-panel restart; then
  if [ "$had_previous_binary" = true ]; then
    install -m 0755 "${temporary_directory}/wireguard-panel.previous" "$binary"
    if [ "$had_previous_service" = true ]; then
      install -m 0755 "${temporary_directory}/wireguard-panel.openrc.previous" "$service"
    fi
    rc-service wireguard-panel restart >/dev/null 2>&1 || true
    fail "the new panel failed to start; the previous binary was restored"
  fi
  fail "the panel failed to start; WireGuard interfaces were not restarted"
fi

printf '\nWireGuard Panel installed: http://SERVER_IP:8080\n'
printf 'Default login: admin/admin5555\n'
printf 'Change the password from the account menu after signing in.\n'
