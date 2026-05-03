package logpattern

import (
	"testing"
)

func TestMatchMailIP(t *testing.T) {
	d := DefaultDetectors()[0]
	ip := d.matchIP("dovecot: imap-login: Disconnected: auth failed, rip=198.51.100.10, lip=10.0.0.1")
	if ip != "198.51.100.10" {
		t.Fatalf("got %q", ip)
	}
}

func TestMatchWebIP(t *testing.T) {
	d := DefaultDetectors()[1]
	ip := d.matchIP(`203.0.113.9 - - [x] "POST /wp-login.php HTTP/1.1" 401 12`)
	if ip != "203.0.113.9" {
		t.Fatalf("got %q", ip)
	}
}

func TestMatchPanelIP(t *testing.T) {
	d := DefaultDetectors()[2]
	ip := d.matchIP("login error from 192.0.2.44 user admin")
	if ip != "192.0.2.44" {
		t.Fatalf("got %q", ip)
	}
}
