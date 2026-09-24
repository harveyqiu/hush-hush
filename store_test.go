package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func statMode(path string) (fs.FileMode, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Mode().Perm(), nil
}

func TestCheckDBPerms_WarnsWhenTooOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "open.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	logs := captureLogs(t)
	checkDBPerms(path)
	if logs.Len() != 0 {
		t.Errorf("0600 file in 0700 dir should not warn, got: %s", logs.String())
	}

	if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- deliberately too open for the test
		t.Fatal(err)
	}
	checkDBPerms(path)
	if !strings.Contains(logs.String(), "wider than 0600") {
		t.Errorf("expected a permission warning, got: %s", logs.String())
	}
}
