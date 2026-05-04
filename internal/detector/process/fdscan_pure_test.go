package process

import (
	"net/netip"
	"strings"
	"testing"
)

func TestIsSensitivePath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/etc/shadow", true},
		{"/etc/sudoers", false},
		{"/etc/sudoers.d/90-cloud-init", false},
		{"/etc/ssh/ssh_host_rsa_key", true},
		{"/root/.ssh/id_rsa", true},
		{"/root/.ssh/id_ed25519", true},
		{"/root/.aws/credentials", true},
		{"/root/.docker/config.json", true},
		{"/root/.kube/config", true},
		{"/root/.npmrc", true},
		{"/root/.git-credentials", true},
		{"/root/.bash_history", true},
		{"/dev/input/event0", true},
		{"/dev/uinput", true},
		{"/home/femi/.ssh/id_rsa", true},
		{"/home/femi/.aws/credentials", true},
		{"/home/femi/.kube/config", true},
		{"/home/femi/.config/gh/hosts.yml", true},
		{"/home/femi/.bash_history", true},

		// SSH agent sockets / k8s tokens
		{"/tmp/ssh-XXXX1234/agent.5678", true},
		{"/run/user/1000/keyring/ssh", true},
		{"/run/user/1000/gnupg/S.gpg-agent.ssh", true},
		{"/var/run/secrets/kubernetes.io/serviceaccount/token", true},
		{"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", true},

		{"/etc/hosts", false},
		{"/etc/passwd", false},
		{"/tmp/ssh-XXXX1234/random.txt", false}, // dir prefix only, no agent.
		{"/run/user/1000/pulse/native", false},  // unrelated user runtime file
		{"/home/femi/notes.txt", false},
		{"/var/log/auth.log", false},
		{"/usr/bin/sshd", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isSensitivePath(c.path); got != c.want {
			t.Errorf("isSensitivePath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestScanTCPForPublicOutbound(t *testing.T) {
	sample := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 ffff
   1: 0100007F:1F90 0100007F:E22A 01 00000000:00000000 00:00000000 00000000     0        0 67890 1 ffff
   2: 040A640A:E92E 8908080F:0016 01 00000000:00000000 00:00000000 00000000     0        0 11111 1 ffff
`
	if !scanTCPForPublicOutbound(strings.NewReader(sample)) {
		t.Error("expected public outbound (row 2 → 15.8.8.137:22) to be detected")
	}

	listenOnly := `  sl
   0: 0100007F:0050 00000000:0000 0A
`
	if scanTCPForPublicOutbound(strings.NewReader(listenOnly)) {
		t.Error("listen-only socket should not count as outbound public")
	}

	loopback := `  sl
   1: 0100007F:1F90 0100007F:E22A 01
`
	if scanTCPForPublicOutbound(strings.NewReader(loopback)) {
		t.Error("loopback-only ESTABLISHED should not count as public")
	}

	synSent := `  sl
   3: 040A640A:E92E 8908080F:0050 02
`
	if !scanTCPForPublicOutbound(strings.NewReader(synSent)) {
		t.Error("SYN_SENT to public IP should be detected")
	}
}

func TestIsPublicAddr(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":           true,
		"1.1.1.1":           true,
		"185.220.101.45":    true,
		"127.0.0.1":         false,
		"127.5.6.7":         false,
		"10.0.0.1":          false,
		"172.16.0.1":        false,
		"172.31.255.255":    false,
		"172.32.0.1":        true,
		"192.168.1.1":       false,
		"169.254.169.254":   false,
		"100.64.0.1":        false,
		"::1":               false,
		"fe80::1":           false,
		"fc00::1":           false,
		"2606:4700:4700::1": true,
	}
	for ip, want := range cases {
		addr, _ := netip.ParseAddr(ip)
		if got := isPublicAddr(addr); got != want {
			t.Errorf("isPublicAddr(%s) = %v, want %v", ip, got, want)
		}
	}
}
