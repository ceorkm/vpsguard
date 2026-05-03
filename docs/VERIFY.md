# Manual Linux verification procedure

The unit-test suite is platform-agnostic and runs on darwin in CI. The `process`, `cpu`, and `filewatch` detectors only do real work on Linux. This document is the hands-on procedure to confirm v0.1 actually catches the attacker behaviors described in the PRD.

Run on a disposable Linux VPS or VM. Do **not** plant the test artifacts (mock miner, /tmp executables, cron jobs) on a production box.

## 0. Setup

Pick any throwaway Linux host (Ubuntu 22.04+ recommended). On macOS dev:

```bash
# OrbStack: orb create ubuntu vpsguard-test
# Multipass: multipass launch --name vpsguard-test 22.04
# Hetzner: spin up cheapest CX11
```

Copy the binary:

```bash
GOOS=linux GOARCH=amd64 go build -o dist/vpsguard-linux-amd64 ./cmd/vpsguard
scp dist/vpsguard-linux-amd64 root@TEST_VPS:/usr/local/bin/vpsguard
ssh root@TEST_VPS chmod +x /usr/local/bin/vpsguard
```

Run interactively in one terminal so you can watch JSON events:

```bash
ssh root@TEST_VPS
vpsguard run | tee /tmp/vpsguard.jsonl
```

In a **second** SSH session (or the host shell), run the trigger commands below and confirm each event fires.

## 1. SSH detector

From a different IP (your laptop), brute-force the test VPS:

```bash
for u in admin oracle ftp test postgres; do
  sshpass -p wrong ssh -o StrictHostKeyChecking=no $u@TEST_VPS_IP true || true
done
```

**Expected events**

- 5x `ssh.login.invalid_user` (one per non-existent user)
- 5x `ssh.login.failed`

Then log in successfully:

```bash
ssh ubuntu@TEST_VPS_IP
```

Expected: `ssh.login.success` with `severity: medium`.

## 2. Process detector — suspicious path

In the second SSH session on the VPS:

```bash
cp /bin/sleep /tmp/sleep && /tmp/sleep 30 &
```

Within 10s vpsguard should emit:

```json
{"type":"process.suspicious","severity":"high","fields":{"exe":"/tmp/sleep","reason":"exe_in_tmp",...}}
```

Clean up: `rm /tmp/sleep`.

## 3. Process detector — known miner

The simplest non-malicious test:

```bash
cp /bin/sleep /usr/local/bin/xmrig && /usr/local/bin/xmrig 30 &
```

Expected within 10s:

```json
{"type":"process.known_miner","severity":"high","fields":{"cmdline":"/usr/local/bin/xmrig 30","exe":"/usr/local/bin/xmrig",...}}
```

Clean up: `rm /usr/local/bin/xmrig`.

## 4. Process detector — deleted binary

```bash
cp /bin/sleep /tmp/ghost && /tmp/ghost 60 & rm /tmp/ghost
```

Expected within 10s: `process.suspicious` with `reason: exe_deleted`.

(This case is also a `suspicious_path` because `/tmp/...` matches both. Either tag is fine.)

## 5. CPU spike

Install stress-ng:

```bash
apt install -y stress-ng
stress-ng --cpu $(nproc) --timeout 360s &
```

Expected after ~5min of sustained load: `cpu.spike` event with `usage_pct >= 90` and `sustained_seconds >= 300`.

(For a faster smoke test, lower the threshold by editing `cpu.Detector.SustainSeconds` in `main.go` to e.g. 30, rebuild, and run `stress-ng --cpu 1 --timeout 60s`.)

## 6. Filewatch — cron

```bash
echo '* * * * * root /bin/false' > /etc/cron.d/vpsguard-test
```

Expected immediately: `cron.modified` event with `path: /etc/cron.d/vpsguard-test`.

Clean up: `rm /etc/cron.d/vpsguard-test`.

## 7. Filewatch — sudoers

```bash
echo '# vpsguard test marker' >> /etc/sudoers
sed -i '/vpsguard test marker/d' /etc/sudoers
```

Expected: 2x `sudoer.modified`, severity `critical`.

## 8. Filewatch — SSH key

```bash
echo 'ssh-rsa AAAAB...test@vpsguard' >> /root/.ssh/authorized_keys
sed -i '/test@vpsguard/d' /root/.ssh/authorized_keys
```

Expected: 2x `ssh_key.added` with `path: /root/.ssh/authorized_keys`, severity `critical`.

## 9. Filewatch — new user

```bash
useradd -m vpsguard-test-user
userdel -r vpsguard-test-user
```

Expected: events for `/etc/passwd`, `/etc/shadow`, `/etc/group` modifications.

## 10. Filewatch — systemd unit

```bash
cat > /etc/systemd/system/vpsguard-test.service <<'EOF'
[Unit]
Description=vpsguard test
[Service]
ExecStart=/bin/true
EOF
rm /etc/systemd/system/vpsguard-test.service
```

Expected: 2x `systemd.service.created`, severity `high`.

## 11. Heartbeat / agent silence

In the running terminal: `Ctrl-C` the agent. Verify:

- `agent.stopped` event was the last one written.
- No goroutine leak warning (we have a unit test for this).

In v0.2+ the silence will trigger a healthchecks.io ping, which then alerts you on Telegram. Manual silence verification is sufficient for v0.1.

---

## Pass criteria for v0.1

All 11 sections above produce the expected events within their stated timing window, with no false positives during a 10-minute idle period afterward.

Once verified on at least one Ubuntu 22.04 and one Debian 12 host, mark this task done and tag the release.
