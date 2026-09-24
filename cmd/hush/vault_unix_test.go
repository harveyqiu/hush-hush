//go:build linux

package main

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
	"testing"
)

// A failing write (here: RLIMIT_FSIZE, as on a full disk) must not leave a
// half-written vault behind that would block every later `hush init`.
func TestSaveNewVault_WriteFailureCleansUp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)

	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Skip(err)
	}
	lim := old
	lim.Cur = 8
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
		t.Skip(err)
	}
	err := saveNewVault(VaultConfig{Version: 1, Verify: "hh2:x"})
	_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old)

	if err == nil || errors.Is(err, errVaultExists) {
		t.Fatalf("err = %v, want a write error", err)
	}
	p, _ := vaultPath()
	if _, statErr := os.Stat(p); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("partial vault left behind: %v", statErr)
	}
}
