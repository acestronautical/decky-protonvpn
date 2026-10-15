#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PNPM_VERSION="9.15.9"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/decky-protonvpn/pnpm-${PNPM_VERSION}"
VSCODE_BIN="${VSCODE_BIN:-}"

if [[ -z "$VSCODE_BIN" ]]; then
  if [[ -x /app/extra/vscode/code ]]; then
    VSCODE_BIN=/app/extra/vscode/code
  elif command -v code >/dev/null 2>&1; then
    VSCODE_BIN="$(command -v code)"
  fi
fi

run_pnpm() {
  if command -v pnpm >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
    pnpm --dir "$ROOT_DIR" "$@"
    return
  fi

  if [[ -z "$VSCODE_BIN" || ! -x "$VSCODE_BIN" ]]; then
    printf 'Install Node.js and pnpm, or set VSCODE_BIN to the VS Code executable.\n' >&2
    return 1
  fi

  local pnpm_cli="$CACHE_DIR/package/bin/pnpm.cjs"
  if [[ ! -f "$pnpm_cli" ]]; then
    mkdir -p "$CACHE_DIR"
    curl -fsSL "https://registry.npmjs.org/pnpm/-/pnpm-${PNPM_VERSION}.tgz" -o "$CACHE_DIR/pnpm.tgz"
    tar -xzf "$CACHE_DIR/pnpm.tgz" -C "$CACHE_DIR"
    rm -f "$CACHE_DIR/pnpm.tgz"
  fi

  mkdir -p "$CACHE_DIR/bin"
  ln -sfn "$VSCODE_BIN" "$CACHE_DIR/bin/node"
  PATH="$CACHE_DIR/bin:$PATH" ELECTRON_RUN_AS_NODE=1 \
    "$VSCODE_BIN" "$pnpm_cli" --dir "$ROOT_DIR" "$@"
}

package_plugin() {
  run_pnpm run build
  command -v zip >/dev/null 2>&1 || {
    printf 'The zip utility is required to create a Decky test package.\n' >&2
    return 1
  }

  local output_dir="$ROOT_DIR/out"
  local archive="$output_dir/decky-protonvpn-dev.zip"
  local staging_dir
  staging_dir="$(mktemp -d "${TMPDIR:-/tmp}/decky-protonvpn.XXXXXX")"

  mkdir -p "$output_dir" "$staging_dir/Proton VPN/dist"
  cp "$ROOT_DIR/LICENSE" "$ROOT_DIR/main.py" "$ROOT_DIR/package.json" \
    "$ROOT_DIR/plugin.json" "$ROOT_DIR/README.md" "$staging_dir/Proton VPN/"
  cp -a "$ROOT_DIR/dist/." "$staging_dir/Proton VPN/dist/"
  rm -f "$archive"
  (cd "$staging_dir" && zip -qr "$archive" "Proton VPN")
  rm -rf -- "$staging_dir"
  printf 'Created %s\n' "$archive"
}

serve_package() {
  local archive="$ROOT_DIR/out/decky-protonvpn-dev.zip"
  local port="${DECKY_DEV_PORT:-8765}"
  if [[ ! -f "$archive" ]]; then
    printf 'Package not found. Run: %s package\n' "$0" >&2
    return 1
  fi

  printf 'Install URL: http://127.0.0.1:%s/decky-protonvpn-dev.zip\n' "$port"
  if command -v flatpak-spawn >/dev/null 2>&1; then
    exec flatpak-spawn --host python3 -m http.server "$port" --bind 127.0.0.1 --directory "$ROOT_DIR/out"
  fi
  exec python3 -m http.server "$port" --bind 127.0.0.1 --directory "$ROOT_DIR/out"
}

command_name="${1:-}"
if [[ $# -gt 0 ]]; then
  shift
fi

case "$command_name" in
  install)
    run_pnpm install --frozen-lockfile
    ;;
  test)
    cd "$ROOT_DIR"
    python3 -m unittest discover -s tests
    ;;
  build)
    run_pnpm run build
    ;;
  package)
    package_plugin
    ;;
  serve)
    serve_package
    ;;
  *)
    printf 'Usage: %s {install|test|build|package|serve}\n' "$0" >&2
    exit 2
    ;;
esac
