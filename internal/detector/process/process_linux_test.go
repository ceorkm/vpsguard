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
			name:    "vpsguard after self update or reinstall",
			exe:     "/usr/local/bin/vpsguard",
			cmdline: "/usr/local/bin/vpsguard run",
			want:    true,
		},
		{
			name:    "ubuntu unattended-upgrades shutdown helper",
			exe:     "/usr/bin/python3.12",
			cmdline: "/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal",
			want:    true,
		},
		{
			name:    "networkd-dispatcher after python package upgrade",
			exe:     "/usr/bin/python3.12",
			cmdline: "/usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers",
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

func TestIsBenignSensitiveFDReader(t *testing.T) {
	if !isBenignSensitiveFDReader(
		"/usr/lib/xorg/Xorg",
		"/usr/lib/xorg/Xorg -core :0 -seat seat0",
		"/dev/input/event0",
	) {
		t.Fatal("Xorg reading /dev/input should be treated as normal desktop/session behavior")
	}
	if !isBenignSensitiveFDReader(
		"/usr/lib/systemd/systemd-logind",
		"/usr/lib/systemd/systemd-logind",
		"/dev/input/event0",
	) {
		t.Fatal("systemd-logind reading /dev/input should be treated as normal session behavior")
	}
	if isBenignSensitiveFDReader("/tmp/keylogger", "/tmp/keylogger", "/dev/input/event0") {
		t.Fatal("unknown process reading /dev/input should still alert")
	}
}
