#!/usr/bin/env sh
set -eu
systemctl disable --now vpsguard || true
systemctl disable --now vpsguard-watchdog || true
