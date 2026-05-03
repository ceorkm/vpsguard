#!/usr/bin/env sh
set -eu
mkdir -p /var/lib/vpsguard
systemctl daemon-reload || true
systemctl enable --now vpsguard || true
