#!/bin/sh

set -eu

# 固定项目目录，避免调用脚本时的当前工作目录影响 Git 配置读取。
script_directory="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
project_directory="$(dirname "$script_directory")"

# 部署目标优先读取环境变量，未提供时回退到仓库本地 Git 配置。
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
panel_port="${panel_port:-5555}"

# 本机和远端统一使用 wget 获取 Release 与执行健康检查。
command -v wget >/dev/null 2>&1 || {
  printf 'wget is required.\n' >&2
  exit 1
}
[ -n "$deploy_host" ] || {
  printf 'Missing deployment host. Set WIREGUARD_PANEL_DEPLOY_HOST or git config wireguard-panel.deployHost.\n' >&2
  exit 1
}
if [ -n "$deploy_identity" ] && [ ! -f "$deploy_identity" ]; then
  printf 'Deployment identity does not exist: %s\n' "$deploy_identity" >&2
  exit 1
fi

ssh_target="${deploy_user}@${deploy_host}"
# 所有 SSH 调用统一启用批处理模式和严格身份选择，避免意外交互或选错密钥。
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
  # 先在服务器内部检查依赖、OpenRC、监听端口和回环健康接口。
  ssh_run sh -s -- "$panel_port" <<'REMOTE'
set -eu
panel_port="$1"
[ -f /etc/alpine-release ]
[ "$(uname -m)" = "x86_64" ]
for command in wget wg wg-quick ip iptables; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'Required command is unavailable: %s\n' "$command" >&2
    exit 1
  }
done
rc-service wireguard-panel status
rc-update show default | grep -q wireguard-panel
ss -lnt | grep -q ":${panel_port}"
wget -q -T 5 -O- "http://127.0.0.1:${panel_port}/api/health"
REMOTE
  # 再从部署端访问一次公网地址，确认外部链路同样可用。
  printf '\nExternal health: '
  wget -q -T 10 -O- "http://${deploy_host}:${panel_port}/api/health"
  printf '\n'
}

if [ "${1:-}" = "--check" ]; then
  check_remote
  exit 0
fi

release_tag="${1:-}"
# 未指定标签时读取 GitHub Latest Release；指定标签时始终部署该不可变版本。
if [ -z "$release_tag" ]; then
  release_tag="$({
    wget -qO- https://api.github.com/repos/pch18/wireguard-panel/releases/latest
  } | sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
fi
if ! printf '%s\n' "$release_tag" | \
  grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  printf 'Invalid or unavailable release tag: %s\n' "$release_tag" >&2
  exit 1
fi

printf 'Deploying WireGuard Panel %s to %s...\n' "$release_tag" "$ssh_target"
# 远端安装阶段只补齐必要依赖，不主动重启任何 WireGuard Interface。
ssh_run sh -s -- "$release_tag" "$panel_port" <<'REMOTE'
set -eu
release_tag="$1"
panel_port="$2"

[ "$(id -u)" -eq 0 ]
[ -f /etc/alpine-release ]
[ "$(uname -m)" = "x86_64" ]

missing_packages=""
for package in wireguard-tools iproute2 iptables; do
  if ! apk info -e "$package" >/dev/null 2>&1; then
    missing_packages="${missing_packages} ${package}"
  fi
done
if [ -n "$missing_packages" ]; then
  # 包名来自上面的固定列表，可以安全展开为空格分隔参数。
  # shellcheck disable=SC2086
  apk add --no-cache $missing_packages
fi

for command in wget wg wg-quick ip iptables; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'Required command is unavailable after dependency installation: %s\n' "$command" >&2
    exit 1
  }
done

installer_path="$(mktemp /tmp/wireguard-panel-install.XXXXXX)"
pinned_installer_path="${installer_path}.pinned"
trap 'rm -f "$installer_path" "$pinned_installer_path"' EXIT HUP INT TERM
wget -qO "$installer_path" \
  "https://raw.githubusercontent.com/pch18/wireguard-panel/${release_tag}/install-alpine.sh"
# 兼容旧版安装器：把其中的 Latest URL 固定到目标标签，防止部署或回滚时串版本。
sed \
  "s#https://github.com/pch18/wireguard-panel/releases/latest/download#https://github.com/pch18/wireguard-panel/releases/download/${release_tag}#g" \
  "$installer_path" >"$pinned_installer_path"
chmod 0700 "$pinned_installer_path"
WIREGUARD_PANEL_RELEASE_TAG="$release_tag" "$pinned_installer_path"

# 安装器返回后再次等待回环健康接口，避免立即进行外部检查造成偶发误判。
attempt=0
until wget -q -T 2 -O /dev/null \
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
