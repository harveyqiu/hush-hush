package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Maintenance subcommands that would otherwise need the sqlite3 shell,
// which the distroless image doesn't have.

// cmdBackup writes a consistent copy of the live database with
// VACUUM INTO. It is safe while the server runs (SQLite takes a read
// snapshot) and the copy is a normal, compacted database file.
//
// --out - streams the copy to stdout, so from the host
//
//	docker compose exec -T hush hush-hush backup --out - > backup.db
//
// works in an image with no shell or rm: the temporary file is created
// next to the database and removed before the command exits.
func cmdBackup(args []string, stdout, stderr io.Writer) error {
	fs, dbPath := newFlagSet("backup")
	out := fs.String("out", "", `destination file (must not exist), or "-" for stdout (required)`)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return usageErr("backup: --out is required")
	}
	toStdout := *out == "-"
	dst := filepath.Clean(*out)
	if toStdout {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		dst = filepath.Join(filepath.Dir(*dbPath), ".backup-"+hex.EncodeToString(b)+".db")
	}
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("backup: %s already exists", dst)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("backup: %w", err)
	}
	db, err := openAdminDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if toStdout {
		defer func() { _ = os.Remove(dst) }()
	}
	if _, err := db.ExecContext(context.Background(), `VACUUM INTO ?`, dst); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	// The copy holds the same ciphertexts and token hashes as the live DB.
	if err := os.Chmod(dst, 0o600); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if !toStdout {
		fmt.Fprintf(stdout, "backup written to %s (store it apart from the master key)\n", dst)
		return nil
	}
	f, err := os.Open(dst) // #nosec G304 -- path generated above, next to the DB
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	defer f.Close()
	if _, err := io.Copy(stdout, f); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	fmt.Fprintln(stderr, "backup streamed to stdout (store it apart from the master key)")
	return nil
}

// cmdAuditPrune deletes audit rows older than --older-than. The table
// otherwise grows forever.
func cmdAuditPrune(args []string, stdout io.Writer) error {
	fs, dbPath := newFlagSet("audit-prune")
	olderThan := fs.String("older-than", "", "age such as 180d (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *olderThan == "" {
		return usageErr("audit-prune: --older-than is required (e.g. 180d)")
	}
	d, err := parseExpiry(*olderThan)
	if err != nil {
		return usageErr("audit-prune: invalid --older-than %q", *olderThan)
	}
	db, err := openAdminDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	cutoff := time.Now().Add(-d).Unix()
	res, err := db.ExecContext(context.Background(), `DELETE FROM audit_log WHERE ts < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("audit-prune: %w", err)
	}
	n, _ := res.RowsAffected()
	fmt.Fprintf(stdout, "deleted %d audit rows older than %s\n", n, time.Unix(cutoff, 0).UTC().Format(time.RFC3339))
	return nil
}
