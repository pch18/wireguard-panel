#!/bin/sh

set -eu

script_directory="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
project_directory="$(dirname "$script_directory")"
output_directory="${1:-${project_directory}/dist}"
asset="wireguard-panel_linux_amd64.tar.gz"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

mkdir -p "$output_directory"

(
  cd "${project_directory}/web"
  pnpm build
)

(
  cd "${project_directory}/srv"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o "${temporary_directory}/wireguard-panel" .
)

chmod 0755 "${temporary_directory}/wireguard-panel"
cp "${project_directory}/install-alpine.sh" "$temporary_directory/"
cp "${project_directory}/README.md" "$temporary_directory/"

tar -C "$temporary_directory" -czf "${output_directory}/${asset}" \
  wireguard-panel install-alpine.sh README.md

(
  cd "$output_directory"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$asset" >"${asset}.sha256"
  else
    shasum -a 256 "$asset" >"${asset}.sha256"
  fi
)

printf 'Created:\n  %s\n  %s\n' \
  "${output_directory}/${asset}" \
  "${output_directory}/${asset}.sha256"
