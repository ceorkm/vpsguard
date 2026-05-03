package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ceorkm/vpsguard/internal/detector/audit"
)

const (
	installBinPath   = "/usr/local/bin/vpsguard"
	installConfDir   = "/etc/vpsguard"
	installConfPath  = "/etc/vpsguard/config.yml"
	installStateDir  = "/var/lib/vpsguard"
	installUnitPath  = "/etc/systemd/system/vpsguard.service"
	watchdogUnitPath = "/etc/systemd/system/vpsguard-watchdog.service"
	auditRulesPath   = "/etc/audit/rules.d/80-vpsguard.rules"
)

func installCmd(args []string) {
	fs := flagSet("install")
	noStart := fs.Bool("no-start", false, "install files but do not start service")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	requireLinuxRoot("install")

	exe, err := os.Executable()
	if err != nil {
		fatalf("install: executable path: %v", err)
	}
	if err := installFile(exe, installBinPath, 0o755); err != nil {
		fatalf("install: binary: %v", err)
	}
	if err := os.MkdirAll(installConfDir, 0o755); err != nil {
		fatalf("install: config dir: %v", err)
	}
	if err := os.MkdirAll(installStateDir, 0o750); err != nil {
		fatalf("install: state dir: %v", err)
	}
	if _, err := os.Stat(installConfPath); os.IsNotExist(err) {
		if err := os.WriteFile(installConfPath, []byte(defaultConfigYAML), 0o600); err != nil {
			fatalf("install: config: %v", err)
		}
	}
	if err := os.WriteFile(installUnitPath, []byte(systemdUnit), 0o644); err != nil {
		fatalf("install: unit: %v", err)
	}
	if err := os.WriteFile(watchdogUnitPath, []byte(watchdogUnit), 0o644); err != nil {
		fatalf("install: watchdog unit: %v", err)
	}
	_ = os.MkdirAll(filepath.Dir(auditRulesPath), 0o755)
	_ = os.WriteFile(auditRulesPath, []byte(audit.Rules), 0o640)
	_ = runQuiet("systemctl", "daemon-reload")
	if !*noStart {
		if err := runQuiet("systemctl", "enable", "--now", "vpsguard"); err != nil {
			fatalf("install: start service: %v", err)
		}
		_ = runQuiet("systemctl", "enable", "--now", "vpsguard-watchdog")
	}
	fmt.Fprintf(os.Stderr, "vpsguard installed at %s\n", installBinPath)
	fmt.Fprintf(os.Stderr, "config: %s\n", installConfPath)
}

func uninstallCmd(args []string) {
	fs := flagSet("uninstall")
	keepConfig := fs.Bool("keep-config", false, "keep /etc/vpsguard and /var/lib/vpsguard")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	requireLinuxRoot("uninstall")

	_ = runQuiet("systemctl", "disable", "--now", "vpsguard")
	_ = runQuiet("systemctl", "disable", "--now", "vpsguard-watchdog")
	_ = os.Remove(installUnitPath)
	_ = os.Remove(watchdogUnitPath)
	_ = os.Remove(auditRulesPath)
	_ = runQuiet("systemctl", "daemon-reload")
	_ = os.Remove(installBinPath)
	if !*keepConfig {
		_ = os.RemoveAll(installConfDir)
		_ = os.RemoveAll(installStateDir)
	}
	fmt.Fprintln(os.Stderr, "vpsguard uninstalled")
}

func updateCmd(args []string) {
	fs := flagSet("update")
	repo := fs.String("repo", "ceorkm/vpsguard", "GitHub repo owner/name")
	version := fs.String("version", "latest", "release version or latest")
	restart := fs.Bool("restart", true, "restart vpsguard after update")
	skipVerify := fs.Bool("insecure-skip-verify", false, "skip checksum verification (dangerous)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	requireLinuxRoot("update")
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		fatalf("update: unsupported arch %s", arch)
	}

	binaryName := fmt.Sprintf("vpsguard-linux-%s", arch)
	releaseBase := fmt.Sprintf("https://github.com/%s/releases/latest/download", *repo)
	if *version != "latest" {
		releaseBase = fmt.Sprintf("https://github.com/%s/releases/download/%s", *repo, *version)
	}
	binURL := releaseBase + "/" + binaryName
	checksumsURL := releaseBase + "/checksums.txt"
	bundleURL := releaseBase + "/checksums.txt.bundle"

	tmpBin := installBinPath + ".update"
	if err := downloadFile(binURL, tmpBin); err != nil {
		fatalf("update: %v", err)
	}

	if !*skipVerify {
		// 1. Pull checksums.txt and verify the binary's SHA-256.
		tmpChecksums := tmpBin + ".sha256"
		defer os.Remove(tmpChecksums)
		if err := downloadFile(checksumsURL, tmpChecksums); err != nil {
			os.Remove(tmpBin)
			fatalf("update: download checksums.txt: %v", err)
		}
		want, err := readChecksum(tmpChecksums, binaryName)
		if err != nil {
			os.Remove(tmpBin)
			fatalf("update: checksums.txt: %v", err)
		}
		got, err := fileSHA256(tmpBin)
		if err != nil {
			os.Remove(tmpBin)
			fatalf("update: hash binary: %v", err)
		}
		if got != want {
			os.Remove(tmpBin)
			fatalf("update: checksum mismatch — refusing to install (want %s, got %s)", want, got)
		}
		fmt.Fprintf(os.Stderr, "✓ sha256 verified: %s\n", got)

		// 2. If cosign is on PATH, verify checksums.txt against the
		//    GitHub Actions OIDC identity that produced the release.
		//    Without cosign installed we still have the sha256 chain;
		//    with cosign we add transparency-log verification.
		if cosignAvailable() {
			tmpBundle := tmpBin + ".bundle"
			defer os.Remove(tmpBundle)
			if err := downloadFile(bundleURL, tmpBundle); err != nil {
				fmt.Fprintf(os.Stderr, "! cosign bundle download failed: %v (skipping signature verify)\n", err)
			} else if err := cosignVerifyBlob(tmpBundle, tmpChecksums, *repo); err != nil {
				os.Remove(tmpBin)
				fatalf("update: cosign verify failed: %v", err)
			} else {
				fmt.Fprintln(os.Stderr, "✓ cosign signature verified")
			}
		} else {
			fmt.Fprintln(os.Stderr, "! cosign not installed — sha256 only (install cosign for full chain-of-custody verification)")
		}
	} else {
		fmt.Fprintln(os.Stderr, "!! --insecure-skip-verify set — installing unverified binary")
	}

	if err := os.Chmod(tmpBin, 0o755); err != nil {
		fatalf("update: chmod: %v", err)
	}
	if err := os.Rename(tmpBin, installBinPath); err != nil {
		fatalf("update: replace binary: %v", err)
	}
	if *restart {
		_ = runQuiet("systemctl", "restart", "vpsguard")
	}
	fmt.Fprintf(os.Stderr, "vpsguard updated from %s\n", binURL)
}

// readChecksum reads a `sha256sum`-style checksums file and returns the
// hex digest matching the named filename. Skips lines that don't look
// right and ignores leading "*" or "./" path prefixes that some tools
// emit.
func readChecksum(path, fileName string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimLeft(fields[1], "*./")
		if name == fileName {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("no entry for %q in checksums.txt", fileName)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func cosignAvailable() bool {
	_, err := exec.LookPath("cosign")
	return err == nil
}

// cosignVerifyBlob runs `cosign verify-blob` against the GitHub Actions
// OIDC identity for the configured repo. Refuses anything not signed
// by a workflow inside the repo's GitHub Actions environment.
func cosignVerifyBlob(bundlePath, blobPath, repo string) error {
	identityRegex := fmt.Sprintf(`^https://github.com/%s/`, regexEscape(repo))
	cmd := exec.Command("cosign", "verify-blob",
		"--bundle", bundlePath,
		"--certificate-identity-regexp", identityRegex,
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
		blobPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// regexEscape is a tiny helper that escapes the `/` and `.` characters
// in a github.com/<owner>/<repo> string for use inside a regex literal.
// We avoid importing the full regexp package here because we only need
// to escape two characters.
func regexEscape(s string) string {
	r := strings.NewReplacer(".", `\.`, "+", `\+`, "?", `\?`, "(", `\(`, ")", `\)`, "[", `\[`, "]", `\]`)
	return r.Replace(s)
}

func downloadFile(url, dst string) error {
	if !strings.HasPrefix(url, "https://github.com/") {
		return fmt.Errorf("refusing non-GitHub HTTPS URL: %s", url)
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("download %s returned HTTP %d", url, resp.StatusCode)
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func flagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ExitOnError)
}

func requireLinuxRoot(action string) {
	if runtime.GOOS != "linux" {
		fatalf("%s: vpsguard installs only on Linux VPS hosts", action)
	}
	if os.Geteuid() != 0 {
		fatalf("%s: run as root or with sudo", action)
	}
}

func installFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func runQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "vpsguard: "+format+"\n", args...)
	os.Exit(1)
}

const defaultConfigYAML = `# vpsguard config - /etc/vpsguard/config.yml
server_name: my-vps
min_severity: medium

telegram:
  bot_token: "REPLACE_WITH_BOT_TOKEN"
  chat_id: "REPLACE_WITH_CHAT_ID"

# trusted_ips:
#   - 203.0.113.10

# known_bad_ips:
#   - 203.0.113.66
# known_bad_domains:
#   - malware.example

cpu:
  threshold: 90
  sustain_seconds: 300
`

const systemdUnit = `[Unit]
Description=vpsguard - VPS security agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vpsguard run
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vpsguard
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/vpsguard
PrivateTmp=true
PrivateDevices=false
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
SystemCallArchitectures=native
LimitNOFILE=65536
MemoryMax=256M
TasksMax=64

[Install]
WantedBy=multi-user.target
`

const watchdogUnit = `[Unit]
Description=vpsguard watchdog
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/sh -c 'while true; do systemctl is-active --quiet vpsguard || systemctl restart vpsguard; sleep 30; done'
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`
