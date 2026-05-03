package ssh

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixture-driven test. Asserts how many lines match in each curated
// real-world auth.log sample.
func TestMatchFixtures(t *testing.T) {
	cases := []struct {
		file        string
		minMatches  int // matchCount must be >= this
		exactMatches int // -1 to skip, otherwise must match exactly
	}{
		{file: "sshd-common.log", minMatches: 8, exactMatches: 8},
		{file: "sshd-edge-cases.log", minMatches: 6, exactMatches: -1},
		{file: "sshd-noise.log", minMatches: 0, exactMatches: 0},
	}

	root := repoRoot(t)
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			path := filepath.Join(root, "testdata", "fixtures", tc.file)
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			matches := 0
			s := bufio.NewScanner(f)
			for s.Scan() {
				line := s.Text()
				if strings.TrimSpace(line) == "" {
					continue
				}
				if match(line) != nil {
					matches++
				}
			}
			if err := s.Err(); err != nil {
				t.Fatal(err)
			}

			if matches < tc.minMatches {
				t.Errorf("%s: got %d matches, want >= %d", tc.file, matches, tc.minMatches)
			}
			if tc.exactMatches >= 0 && matches != tc.exactMatches {
				t.Errorf("%s: got %d matches, want exactly %d", tc.file, matches, tc.exactMatches)
			}
		})
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// internal/detector/ssh -> three levels up
	return filepath.Join(wd, "..", "..", "..")
}
