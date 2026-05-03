// Package telegram sends MarkdownV2 messages to a single Telegram bot+chat.
//
// Threat-model note: the bot token lives on the VPS we're protecting.
// That's intentional — it's a notification webhook, not a credential of
// material value. If a root attacker reads it, the worst they can do is
// silence alerts (which the healthchecks.io watchdog catches) or spam
// the user's own chat (which screams "I'm here"). Token rotation via
// @BotFather is 30 seconds.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultAPI     = "https://api.telegram.org"
	defaultTimeout = 10 * time.Second
	maxRetries     = 3
)

type Sender struct {
	BotToken string
	ChatID   string

	// Optional overrides for tests.
	APIBase string
	HTTP    *http.Client
}

type sendRequest struct {
	ChatID      string                `json:"chat_id"`
	Text        string                `json:"text"`
	ParseMode   string                `json:"parse_mode,omitempty"`
	ReplyMarkup *InlineKeyboardMarkup `json:"reply_markup,omitempty"`
}

type InlineKeyboardMarkup struct {
	InlineKeyboard [][]InlineKeyboardButton `json:"inline_keyboard"`
}

type InlineKeyboardButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data,omitempty"`
}

type sendResponse struct {
	OK          bool   `json:"ok"`
	ErrorCode   int    `json:"error_code"`
	Description string `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// Send delivers a MarkdownV2-formatted message. Retries on 5xx and 429
// (respecting Retry-After). Returns nil on success.
func (s *Sender) Send(ctx context.Context, text string) error {
	return s.send(ctx, text, nil)
}

func (s *Sender) SendWithAck(ctx context.Context, text, alertID string) error {
	alertID = strings.TrimSpace(alertID)
	if alertID == "" {
		return s.Send(ctx, text)
	}
	markup := &InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{{
		{Text: "Acknowledge", CallbackData: "ack:" + compactCallback(alertID)},
		{Text: "False positive", CallbackData: "fp:" + compactCallback(alertID)},
	}}}
	return s.send(ctx, text, markup)
}

func (s *Sender) send(ctx context.Context, text string, markup *InlineKeyboardMarkup) error {
	if s.BotToken == "" || s.ChatID == "" {
		return errors.New("telegram: bot_token and chat_id required")
	}
	body := sendRequest{
		ChatID:      s.ChatID,
		Text:        text,
		ParseMode:   "MarkdownV2",
		ReplyMarkup: markup,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("telegram: marshal: %w", err)
	}

	api := s.APIBase
	if api == "" {
		api = defaultAPI
	}
	url := fmt.Sprintf("%s/bot%s/sendMessage", api, s.BotToken)

	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		retryAfter, err := s.attempt(ctx, client, url, payload)
		if err == nil {
			return nil
		}
		lastErr = err

		// 4xx (except 429): permanent failure, do not retry.
		var perm *permanentError
		if errors.As(err, &perm) {
			return err
		}

		// Backoff: respect Retry-After if present, else exponential.
		wait := time.Duration(retryAfter) * time.Second
		if wait <= 0 {
			wait = time.Duration(1<<attempt) * time.Second
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return fmt.Errorf("telegram: send failed after %d attempts: %w", maxRetries, lastErr)
}

func compactCallback(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == ':', r == '.':
			return r
		default:
			return '_'
		}
	}, s)
	if len(s) > 56 {
		return s[:56]
	}
	return s
}

type permanentError struct{ msg string }

func (p *permanentError) Error() string { return p.msg }

// attempt does one HTTP send. Returns retryAfter seconds (>0) if the
// server told us to wait specifically. permanentError signals "do not
// retry, the message is malformed or auth is wrong".
func (s *Sender) attempt(ctx context.Context, client *http.Client, url string, payload []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err // network error — retry
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var apiResp sendResponse
	_ = json.Unmarshal(bodyBytes, &apiResp)

	if resp.StatusCode == http.StatusOK && apiResp.OK {
		return 0, nil
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		// Rate limited — retry after specified delay.
		return apiResp.Parameters.RetryAfter, fmt.Errorf("telegram: 429 rate limited (%s)", apiResp.Description)
	case resp.StatusCode >= 500:
		// Server error — retry with backoff.
		return 0, fmt.Errorf("telegram: %d server error (%s)", resp.StatusCode, apiResp.Description)
	default:
		// 4xx (other): bad token, bad chat ID, malformed message. Don't
		// hammer Telegram with retries that will keep failing.
		return 0, &permanentError{
			msg: fmt.Sprintf("telegram: %d %s (%s)", resp.StatusCode, http.StatusText(resp.StatusCode), apiResp.Description),
		}
	}
}

// EscapeMarkdownV2 escapes the characters Telegram MarkdownV2 reserves.
// Apply this to any user-supplied substring (usernames, IPs, paths)
// before interpolating into a template. Markdown markers in the template
// itself (e.g. *bold*) must NOT be escaped.
//
// Reserved per Telegram Bot API docs: _ * [ ] ( ) ~ ` > # + - = | { } . !
func EscapeMarkdownV2(s string) string {
	const reserved = "_*[]()~`>#+-=|{}.!"
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		if strings.ContainsRune(reserved, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
