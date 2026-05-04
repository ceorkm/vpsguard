package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSend_Success(t *testing.T) {
	var called int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&called, 1)
		if !strings.HasSuffix(r.URL.Path, "/sendMessage") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var req sendRequest
		_ = json.Unmarshal(body, &req)
		if req.ChatID != "987654321" {
			t.Errorf("chat_id: %q", req.ChatID)
		}
		if req.ParseMode != "MarkdownV2" {
			t.Errorf("parse_mode: %q", req.ParseMode)
		}
		if !strings.Contains(req.Text, "hello") {
			t.Errorf("text: %q", req.Text)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	s := &Sender{BotToken: "TKN", ChatID: "987654321", APIBase: srv.URL}
	if err := s.Send(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&called) != 1 {
		t.Errorf("expected 1 call, got %d", called)
	}
}

func TestSend_PermanentBadToken(t *testing.T) {
	var called int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&called, 1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":401,"description":"Unauthorized"}`))
	}))
	defer srv.Close()

	s := &Sender{BotToken: "BAD", ChatID: "1", APIBase: srv.URL}
	err := s.Send(context.Background(), "hi")
	if err == nil {
		t.Fatal("expected permanent error")
	}
	var perm *permanentError
	if !errors.As(err, &perm) {
		t.Errorf("expected permanentError, got %T: %v", err, err)
	}
	if atomic.LoadInt32(&called) != 1 {
		t.Errorf("permanent failure must not retry, got %d calls", called)
	}
}

func TestSend_FallsBackToPlainTextOnMarkdownParseError(t *testing.T) {
	var called int32
	var fallback sendRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&called, 1)
		body, _ := io.ReadAll(r.Body)
		if n == 1 {
			var req sendRequest
			_ = json.Unmarshal(body, &req)
			if req.ParseMode != "MarkdownV2" {
				t.Fatalf("first request parse_mode = %q", req.ParseMode)
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: can't parse entities: Character '.' is reserved"}`))
			return
		}
		_ = json.Unmarshal(body, &fallback)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	s := &Sender{BotToken: "T", ChatID: "1", APIBase: srv.URL}
	if err := s.Send(context.Background(), "*Path:* `/tmp/a.b`"); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&called) != 2 {
		t.Fatalf("expected markdown send + plain fallback, got %d calls", called)
	}
	if fallback.ParseMode != "" {
		t.Fatalf("fallback parse_mode = %q, want empty", fallback.ParseMode)
	}
	if fallback.Text != "Path: /tmp/a.b" {
		t.Fatalf("fallback text = %q", fallback.Text)
	}
}

func TestSend_DoesNotFallbackForOtherPermanentErrors(t *testing.T) {
	var called int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&called, 1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":403,"description":"Forbidden"}`))
	}))
	defer srv.Close()

	s := &Sender{BotToken: "T", ChatID: "1", APIBase: srv.URL}
	if err := s.Send(context.Background(), "*hello*"); err == nil {
		t.Fatal("expected error")
	}
	if atomic.LoadInt32(&called) != 1 {
		t.Fatalf("expected no fallback for non-parse permanent error, got %d calls", called)
	}
}

func TestSend_RetriesOn500(t *testing.T) {
	var called int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&called, 1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"ok":false,"description":"oops"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	s := &Sender{BotToken: "T", ChatID: "1", APIBase: srv.URL}
	if err := s.Send(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&called) != 3 {
		t.Errorf("expected 3 attempts, got %d", called)
	}
}

func TestSend_429RespectsRetryAfter(t *testing.T) {
	var called int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&called, 1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"ok":false,"error_code":429,"description":"flood","parameters":{"retry_after":1}}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	s := &Sender{BotToken: "T", ChatID: "1", APIBase: srv.URL}
	start := time.Now()
	if err := s.Send(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < time.Second {
		t.Errorf("expected to wait >=1s for retry_after, waited %v", d)
	}
	if atomic.LoadInt32(&called) != 2 {
		t.Errorf("expected 2 attempts, got %d", called)
	}
}

func TestSend_ContextCancelDuringBackoff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"ok":false}`))
	}))
	defer srv.Close()

	s := &Sender{BotToken: "T", ChatID: "1", APIBase: srv.URL}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	err := s.Send(ctx, "x")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestSend_RequiresTokenAndChat(t *testing.T) {
	if err := (&Sender{}).Send(context.Background(), "x"); err == nil {
		t.Error("expected error for missing creds")
	}
	if err := (&Sender{BotToken: "T"}).Send(context.Background(), "x"); err == nil {
		t.Error("expected error for missing chat_id")
	}
}

func TestEscapeMarkdownV2(t *testing.T) {
	cases := []struct{ in, want string }{
		{"hello", "hello"},
		{"1.2.3.4", `1\.2\.3\.4`},
		{"user_name", `user\_name`},
		{"a*b*c", `a\*b\*c`},
		{"x[y](z)", `x\[y\]\(z\)`},
		{"foo!bar?baz.", `foo\!bar?baz\.`},
		{"100% safe", "100% safe"}, // % is not reserved
	}
	for _, c := range cases {
		if got := EscapeMarkdownV2(c.in); got != c.want {
			t.Errorf("Escape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPlainTextFromMarkdownV2(t *testing.T) {
	got := PlainTextFromMarkdownV2(`*Path:* ` + "`/tmp/a\\.b`" + ` and user\_name`)
	want := "Path: /tmp/a.b and user_name"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
