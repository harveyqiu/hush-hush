//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// checkOwner refuses to proceed when the current user doesn't own the
// database file. Running the admin CLI as root against the service's DB
// would leave root-owned WAL/SHM files the service can no longer open.
func checkOwner(fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if euid := os.Geteuid(); uint32(euid) != st.Uid { // #nosec G115 -- euid is never negative on unix
		return fmt.Errorf("database is owned by uid %d but this process runs as uid %d; run as the owner (e.g. sudo -u hush ...)", st.Uid, euid)
	}
	return nil
}
