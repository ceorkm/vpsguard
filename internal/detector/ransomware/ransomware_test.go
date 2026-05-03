package ransomware

import "testing"

func TestRansomwareNames(t *testing.T) {
	if !encryptedName("/home/a/file.locked") {
		t.Fatal("encrypted extension missed")
	}
	if !ransomName("/home/a/HOW_TO_DECRYPT.txt") {
		t.Fatal("ransom note missed")
	}
	if encryptedName("/home/a/file.txt") || ransomName("/home/a/notes.txt") {
		t.Fatal("false positive")
	}
}
