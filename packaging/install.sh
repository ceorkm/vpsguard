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
#   4. Installs systemd, watchdog, and auditd rule files
#   5. Runs interactive Telegram setup when a TTY is available
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
UNIT_TMP=""
UNIT_DST="/etc/systemd/system/vpsguard.service"
WATCHDOG_DST="/etc/systemd/system/vpsguard-watchdog.service"
AUDIT_RULE_DST="/etc/audit/rules.d/80-vpsguard.rules"

# ---- helpers ----
say() { printf '\033[1;32m=>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! \033[0m%s\n' "$*" >&2; }
die() { printf '\033[1;31mxx \033[0m%s\n' "$*" >&2; exit 1; }
raw_url() { printf 'https://raw.githubusercontent.com/%s/main/%s' "$REPO" "$1"; }

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
    local local_watchdog="${script_dir}/systemd/vpsguard-watchdog.service"
    local local_audit_rules="${script_dir}/audit/80-vpsguard.rules"
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
        local config_url config_tmp
        config_url="$(raw_url "packaging/config.example.yml")"
        config_tmp="$(mktemp)"
        if curl -fsSL -o "$config_tmp" "$config_url"; then
            install -m 0600 "$config_tmp" "$CONF_DST"
            say "Sample config installed at $CONF_DST"
        else
            warn "sample config download failed; interactive setup can still create $CONF_DST"
        fi
        rm -f "$config_tmp"
    fi

    # systemd units.
    if [[ -f "$local_unit" ]]; then
        UNIT_SRC="$local_unit"
    else
        warn "Local systemd unit not found, downloading..."
        local unit_url
        unit_url="$(raw_url "packaging/systemd/vpsguard.service")"
        UNIT_SRC="$(mktemp)"
        UNIT_TMP="$UNIT_SRC"
        if ! curl -fsSL -o "$UNIT_SRC" "$unit_url"; then
            die "unit download failed: $unit_url"
        fi
    fi
    install -m 0644 "$UNIT_SRC" "$UNIT_DST"
    [[ -n "$UNIT_TMP" ]] && rm -f "$UNIT_TMP"
    say "systemd unit installed at $UNIT_DST"

    if [[ -f "$local_watchdog" ]]; then
        install -m 0644 "$local_watchdog" "$WATCHDOG_DST"
        say "watchdog unit installed at $WATCHDOG_DST"
    else
        local watchdog_url
        watchdog_url="$(raw_url "packaging/systemd/vpsguard-watchdog.service")"
        if curl -fsSL -o "$WATCHDOG_DST.tmp" "$watchdog_url"; then
            install -m 0644 "$WATCHDOG_DST.tmp" "$WATCHDOG_DST"
            rm -f "$WATCHDOG_DST.tmp"
            say "watchdog unit installed at $WATCHDOG_DST"
        else
            warn "watchdog unit download failed; main service still installed"
        fi
    fi

    if [[ -f "$local_audit_rules" ]]; then
        install -d -m 0755 "$(dirname "$AUDIT_RULE_DST")"
        install -m 0640 "$local_audit_rules" "$AUDIT_RULE_DST"
        say "audit rules installed at $AUDIT_RULE_DST"
    else
        install -d -m 0755 "$(dirname "$AUDIT_RULE_DST")"
        local audit_url
        audit_url="$(raw_url "packaging/audit/80-vpsguard.rules")"
        if curl -fsSL -o "$AUDIT_RULE_DST.tmp" "$audit_url"; then
            install -m 0640 "$AUDIT_RULE_DST.tmp" "$AUDIT_RULE_DST"
            rm -f "$AUDIT_RULE_DST.tmp"
            say "audit rules installed at $AUDIT_RULE_DST"
        else
            warn "audit rule download failed; audit detector can still read existing audit logs"
        fi
    fi

    systemctl daemon-reload

    if [[ -r /dev/tty && -w /dev/tty ]] && { [[ ! -f "$CONF_DST" ]] || grep -Eq "REPLACE_WITH_BOT_TOKEN|REPLACE_WITH_CHAT_ID" "$CONF_DST" 2>/dev/null; }; then
        say "Launching Telegram setup..."
        if "$BIN_DST" configure --force </dev/tty >/dev/tty; then
            say "Telegram setup completed"
        else
            warn "setup did not complete; run sudo vpsguard configure later"
        fi
    fi

    say "Enabling and starting vpsguard service..."
    if systemctl enable --now vpsguard; then
        say "vpsguard service is running"
    else
        warn "systemd start failed. Check: sudo journalctl -u vpsguard -n 100 --no-pager"
    fi

    systemctl enable --now vpsguard-watchdog >/dev/null 2>&1 || warn "watchdog start failed"

    cat <<EOF

vpsguard is installed and systemd has been asked to start it.

Next steps:

  1. Configure Telegram if you skipped setup:
       sudo vpsguard configure

  2. Verify Telegram delivery:
       sudo vpsguard test-alert

  3. Watch live events:
       sudo journalctl -u vpsguard -f

Uninstall:
  sudo vpsguard uninstall
EOF
}

main "$@"
