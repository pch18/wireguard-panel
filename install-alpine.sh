#!/bin/sh

set -eu

repository="${WIREGUARD_PANEL_REPOSITORY:-pch18/wireguard-panel}"
version="${WIREGUARD_PANEL_VERSION:-latest}"
asset="wireguard-panel_linux_amd64.tar.gz"
install_root="${WIREGUARD_PANEL_INSTALL_ROOT:-}"
skip_packages="${WIREGUARD_PANEL_SKIP_PACKAGES:-0}"
no_start="${WIREGUARD_PANEL_NO_START:-0}"
github_token="${WIREGUARD_PANEL_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"

say() {
  printf '%s\n' "$*"
}

fail() {
  printf 'wireguard-panel installer: %s\n' "$*" >&2
  exit 1
}

root_path() {
  printf '%s%s' "$install_root" "$1"
}

shell_quote() {
  printf "'"
  printf '%s' "$1" | sed "s/'/'\\\\''/g"
  printf "'"
}

write_export() {
  name="$1"
  value="$2"
  printf 'export %s=' "$name"
  shell_quote "$value"
  printf '\n'
}

[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ -f "$(root_path /etc/alpine-release)" ] ||
  [ "${WIREGUARD_PANEL_ALLOW_NON_ALPINE:-0}" = "1" ] ||
  fail "only Alpine Linux is currently supported"

case "$(uname -m)" in
  x86_64 | amd64) ;;
  *) fail "this release only provides Linux AMD64; current architecture is $(uname -m)" ;;
esac

case "$repository" in
  */*/* | "" | /* | */)
    fail "invalid repository; set WIREGUARD_PANEL_REPOSITORY=OWNER/REPO"
    ;;
  */*) ;;
  *) fail "invalid repository; expected OWNER/REPO" ;;
esac

if [ "$version" = "latest" ]; then
  release_base="https://github.com/${repository}/releases/latest/download"
else
  release_base="https://github.com/${repository}/releases/download/${version}"
fi
release_base="${WIREGUARD_PANEL_DOWNLOAD_BASE:-$release_base}"

if [ "$skip_packages" != "1" ]; then
  say "Installing Alpine runtime dependencies..."
  apk add --no-cache ca-certificates curl jq openrc wireguard-tools
fi

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

download_asset() {
  asset_name="$1"
  output_path="$2"
  if [ -n "${WIREGUARD_PANEL_DOWNLOAD_BASE:-}" ] ||
    [ -z "$github_token" ]; then
    curl --fail --location --show-error --silent \
      "${release_base}/${asset_name}" \
      --output "$output_path"
    return
  fi

  command -v jq >/dev/null 2>&1 ||
    fail "jq is required when downloading a private GitHub Release"
  if [ "$version" = "latest" ]; then
    release_api="https://api.github.com/repos/${repository}/releases/latest"
  else
    release_api="https://api.github.com/repos/${repository}/releases/tags/${version}"
  fi
  asset_api="$(
    curl --fail --location --show-error --silent \
      --header "Authorization: Bearer ${github_token}" \
      --header "X-GitHub-Api-Version: 2022-11-28" \
      "$release_api" |
      jq -r --arg name "$asset_name" \
        '.assets[] | select(.name == $name) | .url' |
      sed -n '1p'
  )"
  [ -n "$asset_api" ] && [ "$asset_api" != "null" ] ||
    fail "release asset ${asset_name} was not found"
  curl --fail --location --show-error --silent \
    --header "Authorization: Bearer ${github_token}" \
    --header "Accept: application/octet-stream" \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    "$asset_api" \
    --output "$output_path"
}

say "Downloading ${repository} ${version} for Linux AMD64..."
download_asset "$asset" "${temporary_directory}/${asset}"
download_asset "${asset}.sha256" "${temporary_directory}/${asset}.sha256"

(
  cd "$temporary_directory"
  sha256sum -c "${asset}.sha256"
)
tar -xzf "${temporary_directory}/${asset}" -C "$temporary_directory"
[ -f "${temporary_directory}/wireguard-panel" ] ||
  fail "release archive does not contain wireguard-panel"

install -d -m 0755 "$(root_path /usr/local/bin)"
install -m 0755 \
  "${temporary_directory}/wireguard-panel" \
  "$(root_path /usr/local/bin/wireguard-panel)"
install -d -m 0700 "$(root_path /etc/wireguard)"
install -d -m 0755 "$(root_path /etc/conf.d)" "$(root_path /etc/init.d)"
install -d -m 0755 "$(root_path /var/log)"

configuration="$(root_path /etc/conf.d/wireguard-panel)"
created_configuration=0
if [ ! -e "$configuration" ]; then
  {
    write_export APP_PORT "${APP_PORT:-8080}"
    write_export APP_USERNAME "${APP_USERNAME:-admin}"
    write_export APP_PASSWORD "${APP_PASSWORD:-admin}"
    write_export APP_COOKIE_SECURE "${APP_COOKIE_SECURE:-false}"
    write_export WG_CONFIG_DIR "${WG_CONFIG_DIR:-/etc/wireguard}"
    write_export GIN_MODE "release"
  } >"$configuration"
  chmod 0600 "$configuration"
  created_configuration=1
else
  say "Keeping existing ${configuration}"
fi

service_file="$(root_path /etc/init.d/wireguard-panel)"
cat >"$service_file" <<'OPENRC'
#!/sbin/openrc-run

name="wireguard-panel"
description="WireGuard native configuration panel"
command="/usr/local/bin/wireguard-panel"
command_user="root:root"
supervisor="supervise-daemon"
respawn_delay=5
respawn_max=0
output_log="/var/log/wireguard-panel.log"
error_log="/var/log/wireguard-panel.err"

depend() {
  need net
  after firewall
}

start_pre() {
  checkpath --directory --mode 0700 /etc/wireguard
  checkpath --file --mode 0600 "$output_log"
  checkpath --file --mode 0600 "$error_log"
}
OPENRC
chmod 0755 "$service_file"

if [ -z "$install_root" ]; then
  rc-update add wireguard-panel default >/dev/null
  if [ "$no_start" = "1" ]; then
    say "Service registered but not started (WIREGUARD_PANEL_NO_START=1)."
  else
    rc-service wireguard-panel restart
  fi
else
  say "Installation root is set; skipped rc-update and service start."
fi

say ""
say "WireGuard Panel installed successfully."
say "Configuration: ${configuration}"
say "WireGuard files: $(root_path /etc/wireguard)"
say "Web address: http://SERVER_IP:${APP_PORT:-8080}"
if [ "$created_configuration" = "1" ] && [ "${APP_PASSWORD:-admin}" = "admin" ]; then
  say "WARNING: default login is admin/admin. Change APP_PASSWORD in ${configuration}."
fi
