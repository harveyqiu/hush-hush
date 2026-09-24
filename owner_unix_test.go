//go:build unix

package main

import (
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"
)

// fakeInfo lets checkOwner be tested for any owner without chown (which
// needs root).
type fakeInfo struct{ sys any }

func (f fakeInfo) Name() string       { return "hush.db" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return 0o600 }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return f.sys }

func TestCheckOwner(t *testing.T) {
	me := uint32(os.Geteuid()) // #nosec G115 -- test
	if err := checkOwner(fakeInfo{&syscall.Stat_t{Uid: me}}); err != nil {
		t.Errorf("own file: %v", err)
	}
	if err := checkOwner(fakeInfo{&syscall.Stat_t{Uid: me + 1}}); err == nil {
		t.Error("someone else's file must be refused")
	}
	if err := checkOwner(fakeInfo{nil}); err != nil {
		t.Errorf("no owner information: %v", err)
	}
}

// openAdminDB surfaces the owner check.
func TestOpenAdminDB_OwnerMismatch(t *testing.T) {
	path := newTestDBFile(t)
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	if err := os.Chown(path, 12345, 12345); err != nil {
		t.Skip(err)
	}
	if r := runCLI(t, "", "token", "list", "--db", path); r.code != 1 {
		t.Errorf("code %d, want 1", r.code)
	}
}
