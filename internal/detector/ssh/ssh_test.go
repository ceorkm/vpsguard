package ssh

import (
	"testing"

	"github.com/ceorkm/vpsguard/internal/event"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantType string
		wantSev  event.Severity
		wantUser string
		wantIP   string
		wantMeth string
	}{
		{
			name:     "failed password root",
			line:     "May  2 21:14:01 main-vps sshd[1234]: Failed password for root from 185.220.101.45 port 55322 ssh2",
			wantType: event.TypeSSHLoginFailed,
			wantSev:  event.SevLow,
			wantUser: "root",
			wantIP:   "185.220.101.45",
		},
		{
			name:     "failed password invalid user",
			line:     "May  2 21:14:08 main-vps sshd[1236]: Failed password for invalid user admin from 45.227.255.215 port 41234 ssh2",
			wantType: event.TypeSSHLoginFailed,
			wantSev:  event.SevLow,
			wantUser: "admin",
			wantIP:   "45.227.255.215",
		},
		{
			name:     "failed publickey",
			line:     "May  2 21:14:01 main-vps sshd[1234]: Failed publickey for root from 185.220.101.45 port 55322 ssh2",
			wantType: event.TypeSSHLoginFailed,
			wantSev:  event.SevLow,
			wantUser: "root",
			wantIP:   "185.220.101.45",
		},
		{
			name:     "invalid user lowercase",
			line:     "May  2 21:14:05 main-vps sshd[1235]: Invalid user admin from 45.227.255.215 port 41234",
			wantType: event.TypeSSHInvalidUser,
			wantSev:  event.SevLow,
			wantUser: "admin",
			wantIP:   "45.227.255.215",
		},
		{
			name:     "invalid user no port",
			line:     "Apr 17 03:21:09 host sshd[2200]: Invalid user oracle from 192.0.2.10",
			wantType: event.TypeSSHInvalidUser,
			wantSev:  event.SevLow,
			wantUser: "oracle",
			wantIP:   "192.0.2.10",
		},
		{
			name:     "accepted password",
			line:     "May  2 21:14:30 main-vps sshd[1238]: Accepted password for ubuntu from 102.89.34.12 port 51123 ssh2",
			wantType: event.TypeSSHLoginSuccess,
			wantSev:  event.SevMedium,
			wantUser: "ubuntu",
			wantIP:   "102.89.34.12",
			wantMeth: "password",
		},
		{
			name:     "accepted publickey",
			line:     "May  2 21:14:45 main-vps sshd[1239]: Accepted publickey for root from 102.89.34.12 port 51124 ssh2",
			wantType: event.TypeSSHLoginSuccess,
			wantSev:  event.SevMedium,
			wantUser: "root",
			wantIP:   "102.89.34.12",
			wantMeth: "publickey",
		},
		{
			name:     "max auth attempts with error prefix",
			line:     "May  2 21:14:50 main-vps sshd[1240]: error: maximum authentication attempts exceeded for invalid user test from 45.227.255.215 port 41234 ssh2 [preauth]",
			wantType: event.TypeSSHLoginFailed,
			wantSev:  event.SevMedium,
			wantUser: "test",
			wantIP:   "45.227.255.215",
		},
		{
			name:     "max auth attempts without error prefix",
			line:     "May  2 21:14:50 main-vps sshd[1240]: maximum authentication attempts exceeded for root from 1.2.3.4 port 22 ssh2 [preauth]",
			wantType: event.TypeSSHLoginFailed,
			wantSev:  event.SevMedium,
			wantUser: "root",
			wantIP:   "1.2.3.4",
		},
		{
			name:     "ipv6 address",
			line:     "May  2 21:14:01 main-vps sshd[1234]: Failed password for root from 2001:db8::1 port 55322 ssh2",
			wantType: event.TypeSSHLoginFailed,
			wantSev:  event.SevLow,
			wantUser: "root",
			wantIP:   "2001:db8::1",
		},
		{
			name:     "username with hyphen and dot",
			line:     "May  2 21:14:08 main-vps sshd[1236]: Failed password for git-user.bot from 45.227.255.215 port 41234 ssh2",
			wantType: event.TypeSSHLoginFailed,
			wantUser: "git-user.bot",
			wantIP:   "45.227.255.215",
			wantSev:  event.SevLow,
		},
		{
			name:     "keyboard-interactive pam",
			line:     "May  2 21:14:08 main-vps sshd[1236]: Failed keyboard-interactive/pam for root from 1.2.3.4 port 22 ssh2",
			wantType: event.TypeSSHLoginFailed,
			wantUser: "root",
			wantIP:   "1.2.3.4",
			wantSev:  event.SevLow,
		},
		{
			name: "non-ssh syslog line — must not match",
			line: "May  2 21:15:02 main-vps systemd[1]: session-42.scope: Succeeded.",
		},
		{
			name: "completely unrelated line",
			line: "May  2 21:15:02 main-vps kernel: TCP: out of memory -- consider tuning tcp_mem",
		},
		{
			name: "sshd info line we don't care about",
			line: "May  2 21:15:02 main-vps sshd[1240]: Received disconnect from 1.2.3.4 port 22:11: disconnected by user",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := match(tc.line)

			if tc.wantType == "" {
				if got != nil {
					t.Fatalf("expected no match, got event %+v", got)
				}
				return
			}

			if got == nil {
				t.Fatalf("expected match for line %q, got nil", tc.line)
			}
			if got.Type != tc.wantType {
				t.Errorf("type: got %q want %q", got.Type, tc.wantType)
			}
			if got.Severity != tc.wantSev {
				t.Errorf("severity: got %q want %q", got.Severity, tc.wantSev)
			}
			if u, _ := got.Fields["user"].(string); u != tc.wantUser {
				t.Errorf("user: got %q want %q", u, tc.wantUser)
			}
			if ip, _ := got.Fields["ip"].(string); ip != tc.wantIP {
				t.Errorf("ip: got %q want %q", ip, tc.wantIP)
			}
			if got.Source != Name {
				t.Errorf("source: got %q want %q", got.Source, Name)
			}
			if tc.wantMeth != "" {
				if method, _ := got.Fields["method"].(string); method != tc.wantMeth {
					t.Errorf("method: got %q want %q", method, tc.wantMeth)
				}
			}
		})
	}
}
