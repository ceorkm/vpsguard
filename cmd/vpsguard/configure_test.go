package main

import (
	"strings"
	"testing"
)

func TestValidateTelegramToken(t *testing.T) {
	good := []string{
		"123456789:AAHrealtokenABCDEFG",
		"5555555:abcdefghijklmnopqrstu",
	}
	for _, v := range good {
		if err := validateTelegramToken(v); err != nil {
			t.Errorf("expected %q valid, got %v", v, err)
		}
	}

	bad := map[string]string{
		"":                       "empty",
		"123":                    "too short",
		"abcdef":                 "no colon",
		"REPLACE_WITH_BOT_TOKEN": "placeholder",
		"YOUR_TOKEN_HERE_xxxxxx": "placeholder",
	}
	for v, why := range bad {
		if err := validateTelegramToken(v); err == nil {
			t.Errorf("%q should be rejected (%s)", v, why)
		}
	}
}

func TestValidateChatID(t *testing.T) {
	good := []string{"987654321", "-1001234567890"}
	for _, v := range good {
		if err := validateChatID(v); err != nil {
			t.Errorf("expected %q valid, got %v", v, err)
		}
	}
	bad := []string{"", "abc", "12.34", "+12345"}
	for _, v := range bad {
		if err := validateChatID(v); err == nil {
			t.Errorf("%q should be rejected", v)
		}
	}
}

func TestBuildConfigYAML(t *testing.T) {
	body := buildConfigYAML(configValues{
		ServerName:     "main-vps",
		BotToken:       "123456789:AAH",
		ChatID:         "987654321",
		HealthcheckURL: "https://hc-ping.com/abc",
		MinSeverity:    "high",
	})
	mustContain(t, body, `server_name: "main-vps"`)
	mustContain(t, body, `bot_token: "123456789:AAH"`)
	mustContain(t, body, `chat_id:   "987654321"`)
	mustContain(t, body, `healthcheck_url: "https://hc-ping.com/abc"`)
	mustContain(t, body, "min_severity: high")
}

func TestBuildConfigYAML_OmitsEmptyHealthcheck(t *testing.T) {
	body := buildConfigYAML(configValues{
		ServerName:  "x",
		BotToken:    "123:abc",
		ChatID:      "1",
		MinSeverity: "medium",
	})
	if strings.Contains(body, "healthcheck_url") {
		t.Errorf("empty healthcheck must be omitted, got:\n%s", body)
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected %q in:\n%s", needle, haystack)
	}
}
