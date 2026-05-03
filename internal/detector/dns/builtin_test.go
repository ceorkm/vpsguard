package dns

import "testing"

func TestBuiltinBadDomains_MatchesWithoutConfig(t *testing.T) {
	// Caller passes nil/empty user list — the built-in defaults
	// must still catch popular exfil hosts.
	cases := map[string]string{
		"transfer.sh":                     "transfer.sh",
		"sub.transfer.sh":                 "transfer.sh",
		"x-y.0x0.st":                      "0x0.st",
		"my-tunnel.ngrok-free.app":        "ngrok-free.app",
		// matcher returns whichever entry matches first; either parent
		// or specific is acceptable.
		"webhook.cdn.discordapp.com":      "discordapp.com",
		"randomtoken.oast.fun":            "oast.fun",
		"ifconfig.me":                     "ifconfig.me",

		// Legitimate domains must NOT match.
		"github.com":                      "",
		"api.openai.com":                  "",
		"sub.unrelated.example":           "",
	}
	for domain, want := range cases {
		got := MatchKnownBadDomain(domain, nil)
		if got != want {
			t.Errorf("MatchKnownBadDomain(%q, nil) = %q, want %q", domain, got, want)
		}
	}
}

func TestBuiltinBadDomains_UserExtensions(t *testing.T) {
	user := []string{"my-c2.example"}
	cases := map[string]string{
		"my-c2.example":          "my-c2.example",
		"sub.my-c2.example":      "my-c2.example",
		"transfer.sh":            "transfer.sh", // built-in still active
	}
	for domain, want := range cases {
		got := MatchKnownBadDomain(domain, user)
		if got != want {
			t.Errorf("MatchKnownBadDomain(%q, user) = %q, want %q", domain, got, want)
		}
	}
}
