package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// migrations brings a database from schema version i to i+1 when
// migrations[i] is applied. Shipped entries are append-only: never edit or
// reorder one, because deployed databases have already recorded it.
var migrations = []string{
	// 1: the v0.1.0 secrets table. IF NOT EXISTS makes this a no-op on
	// databases created by v0.1.0, which predate schema_version, so their
	// rows (and ciphertexts) are left untouched.
	`CREATE TABLE IF NOT EXISTS secrets (
		name       TEXT PRIMARY KEY,
		ciphertext BLOB NOT NULL,
		nonce      BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);`,

	// 2: per-caller bearer tokens. Only the SHA-256 of the token is
	// stored; prefixes is a JSON array of strings (agent tokens only).
	`CREATE TABLE tokens (
		id           INTEGER PRIMARY KEY,
		name         TEXT    NOT NULL UNIQUE,
		token_hash   BLOB    NOT NULL UNIQUE,
		role         TEXT    NOT NULL CHECK (role IN ('admin', 'agent')),
		prefixes     TEXT    NOT NULL DEFAULT '[]',
		revoked_at   INTEGER,
		expires_at   INTEGER,
		created_at   INTEGER NOT NULL,
		last_used_at INTEGER
	);`,
}

// dbDSN is the connection string shared by the server and the admin CLI.
// _txlock=immediate takes the write lock at BEGIN so two processes
// migrating the same file at once serialize instead of deadlocking.
func dbDSN(path string) string {
	return path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_txlock=immediate"
}

// openDB opens (creating if needed) the database at path and brings its
// schema up to date. A new file is created 0600 before SQLite touches it;
// SQLite would otherwise create it with the process umask (usually 0644).
func openDB(path string) (*sql.DB, error) {
	if err := ensureDBFile(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbDSN(path))
	if err != nil {
		return nil, err
	}
	// SQLite serializes writers; capping the pool at 1 avoids spurious
	// SQLITE_BUSY at the database/sql layer for this workload.
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

func ensureDBFile(path string) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create db file: %w", err)
	}
	return f.Close()
}

// migrate applies every pending migration in a single transaction, so a
// failure leaves the schema exactly as it was. Safe to call on every start.
func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL DEFAULT (unixepoch())
	)`); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var current int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&current); err != nil {
		return err
	}
	if current > len(migrations) {
		// Written by a newer binary. Refuse rather than guess at a schema
		// we don't understand.
		return fmt.Errorf("database schema version %d is newer than this binary supports (%d)",
			current, len(migrations))
	}
	for v := current; v < len(migrations); v++ {
		if _, err := tx.Exec(migrations[v]); err != nil {
			return fmt.Errorf("migration %d: %w", v+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version (version) VALUES (?)`, v+1); err != nil {
			return fmt.Errorf("record migration %d: %w", v+1, err)
		}
	}
	return tx.Commit()
}

// checkDBPerms warns (it does not refuse to start) when the database file
// or its directory is readable by anyone other than the owner. The DB
// holds token hashes and ciphertexts; the directory also holds WAL files.
func checkDBPerms(path string) {
	if strings.HasPrefix(path, ":memory:") || strings.HasPrefix(path, "file:") {
		return
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		slog.Warn("database file permissions are wider than 0600; run chmod 600",
			"path", path, "mode", fmt.Sprintf("%#o", fi.Mode().Perm()))
	}
	dir := filepath.Dir(path)
	if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm()&0o077 != 0 {
		slog.Warn("database directory permissions are wider than 0700; run chmod 700",
			"path", dir, "mode", fmt.Sprintf("%#o", fi.Mode().Perm()))
	}
}
