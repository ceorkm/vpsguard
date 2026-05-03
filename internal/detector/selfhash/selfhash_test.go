package selfhash

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashFileChangesWithContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpsguard")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	h1, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	h2, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Fatal("hash did not change after file content changed")
	}
}
