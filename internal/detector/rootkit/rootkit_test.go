package rootkit

import (
	"os"
	"testing"
)

func TestDetectorName(t *testing.T) {
	if (&Detector{}).Name() != Name {
		t.Fatal("wrong name")
	}
}

func TestAbsDiff(t *testing.T) {
	if absDiff(10, 3) != 7 || absDiff(3, 10) != 7 {
		t.Fatal("bad abs diff")
	}
}

func TestFileSizeBySeek(t *testing.T) {
	path := t.TempDir() + "/sample"
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := fileSizeBySeek(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("got %d, want 5", n)
	}
}
