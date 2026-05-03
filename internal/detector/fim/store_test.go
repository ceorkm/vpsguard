package fim

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStorePersistsSnapshots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fim.db")
	s, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	want := snap{hash: "abc", size: 42, mode: 0o600}
	if err := s.Put("/etc/passwd", want); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got := s.LoadAll()["/etc/passwd"]
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	if err := s.Delete("/etc/passwd"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.LoadAll()["/etc/passwd"]; ok {
		t.Fatal("deleted snapshot still present")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("db permissions = %v, want 0600", info.Mode().Perm())
	}
}
