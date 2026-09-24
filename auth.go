package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	roleAdmin = "admin"
	roleAgent = "agent"

	// legacyTokenName identifies the deprecated AUTH_TOKEN env var in logs
	// and audit rows. The colon is outside tokenNameRe, so no DB token can
	// ever collide with it.
	legacyTokenName = "env:AUTH_TOKEN" // #nosec G101 -- a display label, not a credential
)

var tokenNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)

// errUnauthenticated covers every "who are you?" failure: no header, unknown
// token, revoked, expired. Callers must not distinguish between them.
var errUnauthenticated = errors.New("unauthenticated")

// principal is the authenticated caller of a request.
type principal struct {
	name     string
	role     string
	prefixes []string
}

func hashToken(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

// bearerToken extracts the token from an Authorization header. TrimSpace
// handles benign client mistakes (extra space after the scheme, trailing
// whitespace) per RFC 7230 §3.2.4.
func bearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	return tok, tok != ""
}

// authenticate resolves the request's bearer token to a principal.
// It returns errUnauthenticated for any credential problem and a different
// error only for infrastructure failures (DB down), which map to 500.
func (s *server) authenticate(ctx context.Context, r *http.Request) (*principal, error) {
	tok, ok := bearerToken(r)
	if !ok {
		return nil, errUnauthenticated
	}
	// Hash first so every comparison is over 32 bytes; ConstantTimeCompare
	// short-circuits on length mismatch and would otherwise leak length.
	given := hashToken(tok)

	if s.legacyTokenHash != nil && subtle.ConstantTimeCompare(given[:], s.legacyTokenHash[:]) == 1 {
		return &principal{name: legacyTokenName, role: roleAdmin}, nil
	}

	// The lookup is keyed on the hash, never the plaintext. The row's hash
	// is compared again in constant time so the decision does not rest on
	// the SQL engine's comparison alone.
	var (
		id                   int64
		name, role, prefJSON string
		stored               []byte
		revokedAt, expiresAt sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, token_hash, role, prefixes, revoked_at, expires_at
		FROM tokens WHERE token_hash = ?`, given[:],
	).Scan(&id, &name, &stored, &role, &prefJSON, &revokedAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(given[:], stored) != 1 {
		return nil, errUnauthenticated
	}
	now := s.now().Unix()
	if revokedAt.Valid || (expiresAt.Valid && now >= expiresAt.Int64) {
		return nil, errUnauthenticated
	}
	if role != roleAdmin && role != roleAgent {
		return nil, errUnauthenticated
	}
	var prefixes []string
	if err := json.Unmarshal([]byte(prefJSON), &prefixes); err != nil {
		// Fail closed: a corrupted grant must not become a broader grant.
		slog.ErrorContext(ctx, "token prefixes unreadable; rejecting", "token_name", name)
		return nil, errUnauthenticated
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE tokens SET last_used_at = ? WHERE id = ?`, now, id); err != nil {
		// Bookkeeping only; don't fail the request over it.
		slog.WarnContext(ctx, "update last_used_at failed", "token_name", name, "error", err)
	}
	return &principal{name: name, role: role, prefixes: prefixes}, nil
}

// tokenSpec describes a token row to insert. Validation of name, role and
// prefixes happens in the CLI layer before this is called.
type tokenSpec struct {
	name      string
	role      string
	prefixes  []string
	expiresAt *time.Time
}

// insertToken stores the SHA-256 of plaintext; the plaintext itself never
// reaches the database.
func insertToken(ctx context.Context, db *sql.DB, spec tokenSpec, plaintext string, now time.Time) error {
	prefixes := spec.prefixes
	if prefixes == nil {
		prefixes = []string{}
	}
	pj, err := json.Marshal(prefixes)
	if err != nil {
		return err
	}
	var exp sql.NullInt64
	if spec.expiresAt != nil {
		exp = sql.NullInt64{Int64: spec.expiresAt.Unix(), Valid: true}
	}
	h := hashToken(plaintext)
	_, err = db.ExecContext(ctx, `
		INSERT INTO tokens (name, token_hash, role, prefixes, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		spec.name, h[:], spec.role, string(pj), exp, now.Unix())
	return err
}
