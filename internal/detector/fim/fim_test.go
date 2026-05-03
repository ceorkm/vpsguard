package fim

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotChanges(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(p, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := snapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := snapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("snapshot did not change")
	}
}
