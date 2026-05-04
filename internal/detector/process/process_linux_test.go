//go:build linux

package process

import "testing"

func TestIsBenignDeletedProcess(t *testing.T) {
	cases := []struct {
		name    string
		exe     string
		cmdline string
		want    bool
	}{
		{
			name:    "ubuntu unattended upgrade shutdown helper",
			exe:     "/usr/bin/python3.12",
			cmdline: "/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal",
			want:    true,
		},
		{
			name:    "other deleted python is not automatically safe",
			exe:     "/usr/bin/python3.12",
			cmdline: "/usr/bin/python3 /tmp/payload.py",
			want:    false,
		},
		{
			name:    "non-python unattended string is not enough",
			exe:     "/tmp/python3.12",
			cmdline: "/tmp/python3.12 /usr/share/unattended-upgrades/unattended-upgrade-shutdown",
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isBenignDeletedProcess(tc.exe, tc.cmdline); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
