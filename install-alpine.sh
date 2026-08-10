#!/bin/sh

set -eu

asset="wireguard-panel_linux_amd64.tar.gz"
binary="/usr/local/bin/wireguard-panel"
service="/etc/init.d/wireguard-panel"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

# 下载并安装最新 Release 中的二进制。
wget -qO "${temporary_directory}/${asset}" \
  "https://github.com/pch18/wireguard-panel/releases/latest/download/${asset}"
tar -xzf "${temporary_directory}/${asset}" -C "$temporary_directory" wireguard-panel
install -m 0755 "${temporary_directory}/wireguard-panel" "${binary}.new"
mv "${binary}.new" "$binary"

# 添加 OpenRC 服务。
cat >"$service" <<'OPENRC'
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
chmod 0755 "$service"

rc-update add wireguard-panel default
rc-service wireguard-panel restart
