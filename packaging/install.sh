#!/usr/bin/env bash
# vpsguard installer.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/ceorkm/vpsguard/main/packaging/install.sh | sudo bash
#
# Or from a local checkout:
#   sudo ./packaging/install.sh
#
# What it does:
#   1. Detects arch (amd64 / arm64)
#   2. Downloads or copies the binary into /usr/local/bin/vpsguard
#   3. Drops a sample config to /etc/vpsguard/config.yml (only if none exists)
#   4. Installs the systemd unit
#   5. Tells you to edit the config, then run `vpsguard test-alert`
#
# Idempotent: safe to re-run.

set -euo pipefail

# ---- config ----
REPO="${VPSGUARD_REPO:-ceorkm/vpsguard}"
VERSION="${VPSGUARD_VERSION:-latest}"
BIN_DST="/usr/local/bin/vpsguard"
CONF_DIR="/etc/vpsguard"
CONF_DST="${CONF_DIR}/config.yml"
STATE_DIR="/var/lib/vpsguard"
UNIT_SRC=""           # set later — local checkout vs download
UNIT_DST="/etc/systemd/system/vpsguard.service"

# ---- helpers ----
say() { printf '\033[1;32m=>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! \033[0m%s\n' "$*" >&2; }
die() { printf '\033[1;31mxx \033[0m%s\n' "$*" >&2; exit 1; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This installer must run as root (try: sudo $0)"
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
}

detect_os() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        die "vpsguard only runs on Linux (got: $(uname -s))"
    fi
}

# ---- main ----
main() {
    require_root
    detect_os
    local arch
    arch="$(detect_arch)"

    say "Installing vpsguard for linux/${arch}..."

    # Find the binary: prefer a local ./dist/ build (when running from a
    # cloned checkout), fall back to downloading from GitHub releases.
    local script_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    local repo_root
    repo_root="$(dirname "$script_dir")"

    local local_bin="${repo_root}/dist/vpsguard-linux-${arch}"
    local local_unit="${script_dir}/systemd/vpsguard.service"
    local local_config_example="${script_dir}/config.example.yml"

    if [[ -x "$local_bin" ]]; then
        say "Using locally-built binary: $local_bin"
        install -m 0755 "$local_bin" "$BIN_DST"
    else
        say "Downloading vpsguard from github.com/${REPO}..."
        local url
        if [[ "$VERSION" == "latest" ]]; then
            url="https://github.com/${REPO}/releases/latest/download/vpsguard-linux-${arch}"
        else
            url="https://github.com/${REPO}/releases/download/${VERSION}/vpsguard-linux-${arch}"
        fi
        if ! curl -fsSL -o "$BIN_DST.tmp" "$url"; then
            die "download failed: $url"
        fi
        chmod 0755 "$BIN_DST.tmp"
        mv "$BIN_DST.tmp" "$BIN_DST"
    fi

    say "Installed binary: $BIN_DST"
    "$BIN_DST" version

    # Config dir + sample.
    install -d -m 0755 "$CONF_DIR"
    install -d -m 0750 "$STATE_DIR"

    if [[ -f "$CONF_DST" ]]; then
        say "Config already exists at $CONF_DST (left untouched)"
    elif [[ -f "$local_config_example" ]]; then
        install -m 0600 "$local_config_example" "$CONF_DST"
        say "Sample config installed at $CONF_DST"
    else
        warn "No sample config found — you'll need to create $CONF_DST manually"
    fi

    # systemd unit.
    if [[ -f "$local_unit" ]]; then
        UNIT_SRC="$local_unit"
    else
        warn "Local systemd unit not found, downloading..."
        local unit_url="https://raw.githubusercontent.com/${REPO}/main/packaging/systemd/vpsguard.service"
        UNIT_SRC="$(mktemp)"
        if ! curl -fsSL -o "$UNIT_SRC" "$unit_url"; then
            die "unit download failed: $unit_url"
        fi
    fi
    install -m 0644 "$UNIT_SRC" "$UNIT_DST"
    systemctl daemon-reload
    say "systemd unit installed at $UNIT_DST"

    say "Enabling and starting vpsguard service..."
    if systemctl enable --now vpsguard; then
        say "vpsguard service is running"
    else
        warn "systemd start failed. Check: sudo journalctl -u vpsguard -n 100 --no-pager"
    fi

    cat <<EOF

vpsguard is installed and systemd has been asked to start it.

Next steps:

  1. Edit your config:
       sudo \$EDITOR $CONF_DST
     (set telegram.bot_token, telegram.chat_id, and optionally healthcheck_url)

  2. Verify Telegram delivery:
       sudo vpsguard test-alert

  3. Reload after config changes:
       sudo systemctl restart vpsguard

  4. Watch live events:
       sudo journalctl -u vpsguard -f

Uninstall: sudo rm $BIN_DST $UNIT_DST && sudo rm -rf $CONF_DIR $STATE_DIR
EOF
}

main "$@"
