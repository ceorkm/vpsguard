#!/usr/bin/env sh
# vpsguard package post-install hook.
#
# Goal: leave the user with a running, configured agent if at all possible,
# without breaking unattended (apt-get -y) installs.
set -eu

mkdir -p /var/lib/vpsguard
chmod 0750 /var/lib/vpsguard

# Reload systemd so the new unit file is picked up.
systemctl daemon-reload >/dev/null 2>&1 || true

# If config still has placeholders AND we have an interactive tty AND the
# DEBIAN_FRONTEND isn't 'noninteractive', walk the user through setup.
if [ -t 0 ] && [ -t 1 ] && [ "${DEBIAN_FRONTEND:-}" != "noninteractive" ]; then
    if grep -q "REPLACE_WITH_BOT_TOKEN\|REPLACE_WITH_CHAT_ID" /etc/vpsguard/config.yml 2>/dev/null; then
        echo
        echo "vpsguard is installed. Run setup now? (Y/n)"
        if [ -e /dev/tty ]; then
            read -r answer < /dev/tty || answer=Y
        else
            answer=N
        fi
        case "${answer:-Y}" in
            n|N)
                echo "Skipping setup. Run 'sudo vpsguard configure' anytime."
                ;;
            *)
                /usr/local/bin/vpsguard configure --force </dev/tty >/dev/tty 2>&1 || \
                    echo "Setup did not complete. Re-run 'sudo vpsguard configure' to retry."
                ;;
        esac
    fi
fi

# Try to enable + start. If config is still unconfigured the agent will
# happily run with stdout-only output until the user runs `configure`.
systemctl enable --now vpsguard >/dev/null 2>&1 || true

cat <<'EOF'

vpsguard installed.
  Configure Telegram alerts:  sudo vpsguard configure
  Live logs:                  sudo journalctl -u vpsguard -f
  Service status:             sudo systemctl status vpsguard
  Source:                     https://github.com/ceorkm/vpsguard

EOF
