#!/bin/sh

set -eu

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail '请以 root 运行此安装脚本。'
[ -r /etc/os-release ] || fail '此脚本仅支持 Debian。'
# shellcheck source=/dev/null
. /etc/os-release
[ "${ID:-}" = debian ] || fail '此脚本仅支持 Debian。'
[ "$(dpkg --print-architecture)" = amd64 ] || fail '当前 Release 仅提供 AMD64 安装包。'
if [ ! -d /run/systemd/system ] || ! systemctl show --property=Version --value >/dev/null; then
  fail '此脚本需要正在运行的 systemd。'
fi

exec 9>/run/wireguard-panel-install.lock
flock -n 9 || fail '已有 WireGuard Panel 安装任务在运行。'

asset="wireguard-panel_linux_amd64.tar.gz"
release_url="https://github.com/pch18/wireguard-panel/releases/latest/download"
binary="/usr/local/bin/wireguard-panel"
service="/etc/systemd/system/wireguard-panel.service"
sysctl_config="/etc/sysctl.d/99-wireguard-panel.conf"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
trap 'exit 1' HUP INT TERM

# 管道安装时，标准输入承载脚本内容。
apt-get update </dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl wireguard-tools iproute2 iptables procps </dev/null

# 校验完整的 Release 安装包后再替换已安装的程序。
(
  cd "$temporary_directory"
  curl -fsSL --retry 3 -o "$asset" "$release_url/$asset"
  curl -fsSL --retry 3 -o "$asset.sha256" "$release_url/$asset.sha256"
  IFS=' ' read -r checksum filename <"$asset.sha256"
  [ "$filename" = "$asset" ] || fail 'Release 校验文件中的文件名不匹配。'
  printf '%s  %s\n' "$checksum" "$asset" | sha256sum --check --strict
  tar --warning=no-unknown-keyword -xzf "$asset" wireguard-panel
)

printf '%s\n' 'net.ipv4.ip_forward = 1' >"$temporary_directory/ip-forward.conf"
sysctl -p "$temporary_directory/ip-forward.conf"
install -m 0644 "$temporary_directory/ip-forward.conf" "$sysctl_config"

cat >"$temporary_directory/wireguard-panel.service" <<'SYSTEMD'
[Unit]
Description=WireGuard configuration panel
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
Environment=GIN_MODE=release
EnvironmentFile=-/etc/default/wireguard-panel
ExecStart=/usr/local/bin/wireguard-panel
Restart=on-failure
RestartSec=5s
# Give the panel time to roll back in-flight WireGuard operations on shutdown.
KillMode=mixed
TimeoutStopSec=150s

[Install]
WantedBy=multi-user.target
SYSTEMD

mkdir -p /usr/local/bin
install -m 0755 "$temporary_directory/wireguard-panel" "$binary.new"
mv -fT "$binary.new" "$binary"
install -m 0644 "$temporary_directory/wireguard-panel.service" "$service"

systemctl daemon-reload
systemctl enable wireguard-panel.service
systemctl restart wireguard-panel.service
