package ransomware

import (
	"testing"

	"github.com/fsnotify/fsnotify"
)

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

func TestIsDestructiveMassOp(t *testing.T) {
	if isDestructiveMassOp(fsnotify.Write) {
		t.Fatal("ordinary writes must not count toward ransomware mass activity")
	}
	if isDestructiveMassOp(fsnotify.Create) {
		t.Fatal("ordinary creates must not count toward ransomware mass activity")
	}
	if !isDestructiveMassOp(fsnotify.Rename) {
		t.Fatal("renames should count toward ransomware mass activity")
	}
	if !isDestructiveMassOp(fsnotify.Remove) {
		t.Fatal("removes should count toward ransomware mass activity")
	}
}
