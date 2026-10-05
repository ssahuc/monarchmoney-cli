package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreSaveTightensExistingLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := NewStore(path).Save(&Session{Profile: "default", Token: "token"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	assertFilePerms(t, path, 0o600)
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory has %d entries, want only session.json (temp file left behind)", len(entries))
	}
}
