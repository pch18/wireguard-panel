#!/bin/sh

set -eu

asset="wireguard-panel_linux_amd64.tar.gz"
binary="/usr/local/bin/wireguard-panel"
service="/etc/init.d/wireguard-panel"
release_tag="${WIREGUARD_PANEL_RELEASE_TAG:-}"

fail() {
  printf 'wireguard-panel installer: %s\n' "$*" >&2
  exit 1
}

# 统一使用 Alpine 自带的 wget 下载文件，参数顺序为“URL、保存路径”。
download_file() {
  wget -qO "$2" "$1"
}

# 健康检查只关心请求是否成功，不输出响应正文。
health_request() {
  wget -q -T 2 -O /dev/null "$1" >/dev/null 2>&1
}

# 服务启动后最多等待约 10 秒，避免 OpenRC 已启动但 HTTP 端口尚未就绪。
wait_for_panel() {
  attempt=0
  until rc-service wireguard-panel status >/dev/null 2>&1 &&
    health_request "http://127.0.0.1:${panel_port}/api/health"; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 10 ] || return 1
    sleep 1
  done
}

# 有备份时恢复原文件；首次安装没有备份时删除新写入的文件。
restore_file() {
  if [ -f "$1" ]; then
    install -m 0755 "$1" "$2"
  else
    rm -f "$2"
  fi
}

# 安装失败时恢复二进制、OpenRC 配置、开机启动状态和原运行状态。
rollback() {
  reason="$1"
  rc-service wireguard-panel stop >/dev/null 2>&1 || true
  restore_file "$previous_binary" "$binary"
  restore_file "$previous_service" "$service"
  if [ "$was_enabled" = true ]; then
    rc-update add wireguard-panel default >/dev/null 2>&1 || true
  else
    rc-update del wireguard-panel default >/dev/null 2>&1 || true
  fi

  if [ "$was_running" = true ]; then
    if rc-service wireguard-panel start >/dev/null 2>&1 && wait_for_panel; then
      fail "$reason; the previous panel was restored and is healthy"
    fi
    fail "$reason; restoring the previous panel did not recover a healthy service"
  fi
  fail "$reason; the previous stopped or uninstalled state was restored"
}

# 仅支持以 root 在 Alpine Linux AMD64 上安装，并依赖系统自带的 wget。
[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ -f /etc/alpine-release ] || fail "only Alpine Linux is supported"
[ "$(uname -m)" = "x86_64" ] || fail "only Linux AMD64 is supported"
command -v wget >/dev/null 2>&1 || fail "wget is required"

# 指定 WIREGUARD_PANEL_RELEASE_TAG 时固定版本；未指定时使用最新正式版。
if [ -n "$release_tag" ]; then
  printf '%s\n' "$release_tag" | \
    grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || fail "invalid release tag: $release_tag"
  release_url="https://github.com/pch18/wireguard-panel/releases/download/${release_tag}"
else
  release_url="https://github.com/pch18/wireguard-panel/releases/latest/download"
fi

# apk add 本身具有幂等性，直接声明完整依赖比逐个判断更简洁可靠。
printf 'Installing WireGuard dependencies...\n'
apk add --no-cache wireguard-tools iproute2 iptables

# 所有下载、解压和备份文件统一放入临时目录，退出时自动清理。
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

# 持久化转发设置，并立即应用到当前内核。
printf 'Enabling IP forwarding...\n'
forwarding_config="/etc/sysctl.d/99-wireguard-panel-forwarding.conf"
install -d -m 0755 /etc/sysctl.d
{
  printf '%s\n' 'net.ipv4.ip_forward = 1'
  if [ -e /proc/sys/net/ipv6/conf/all/forwarding ]; then
    printf '%s\n' 'net.ipv6.conf.all.forwarding = 1'
  fi
  if [ -e /proc/sys/net/ipv6/conf/default/forwarding ]; then
    printf '%s\n' 'net.ipv6.conf.default.forwarding = 1'
  fi
} >"${temporary_directory}/wireguard-panel-forwarding.conf"
install -m 0644 \
  "${temporary_directory}/wireguard-panel-forwarding.conf" \
  "$forwarding_config"
if ! sysctl -p "$forwarding_config" >/dev/null ||
  ! rc-update add sysctl boot >/dev/null; then
  fail "IP forwarding could not be enabled and persisted"
fi

# 先下载并校验 Release，校验成功前不修改正在运行的安装。
printf 'Downloading WireGuard Panel...\n'
download_file "${release_url}/${asset}" "${temporary_directory}/${asset}"
download_file "${release_url}/${asset}.sha256" "${temporary_directory}/${asset}.sha256"

(
  cd "$temporary_directory"
  sha256sum -c "${asset}.sha256"
)
tar -xzf "${temporary_directory}/${asset}" -C "$temporary_directory"

# 记录升级前的文件和 OpenRC 状态，供失败回滚使用。
previous_binary="${temporary_directory}/previous-binary"
previous_service="${temporary_directory}/previous-service"
[ ! -f "$binary" ] || cp -p "$binary" "$previous_binary"
[ ! -f "$service" ] || cp -p "$service" "$previous_service"

was_enabled=false
if rc-update show default 2>/dev/null | \
  grep -Eq '(^|[[:space:]])wireguard-panel([[:space:]]|$)'; then
  was_enabled=true
fi
was_running=false
if [ -f "$previous_service" ] && \
  rc-service wireguard-panel status >/dev/null 2>&1; then
  was_running=true
fi

panel_port=5555
if [ -r /etc/conf.d/wireguard-panel ]; then
  # 健康检查必须使用服务实际监听的端口。
  APP_PORT=""
  # shellcheck disable=SC1091
  . /etc/conf.d/wireguard-panel
  panel_port="${APP_PORT:-5555}"
fi
case "$panel_port" in
  ''|*[!0-9]*) fail "APP_PORT must be numeric" ;;
esac

install -m 0755 "${temporary_directory}/wireguard-panel" "${binary}.new"
# 先写临时文件再原子替换，避免留下半写入的可执行文件。
mv "${binary}.new" "$binary"

# OpenRC 服务固定以 root 运行，并在网络和防火墙就绪后启动。
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

# 只有新服务成功启动并通过健康检查，升级才算完成；否则立即回滚。
if ! rc-update add wireguard-panel default >/dev/null ||
  ! rc-service wireguard-panel restart ||
  ! wait_for_panel; then
  rollback "the new panel could not be enabled, started, or verified"
fi

printf '\nWireGuard Panel installed: http://SERVER_IP:%s\n' "$panel_port"
printf 'Default login: admin/admin5555\n'
printf 'Change the password from the account menu after signing in.\n'
