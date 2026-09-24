package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Token management shared by the admin CLI and the admin HTTP API, so both
// enforce exactly the same rules. Callers handle presentation and the "*"
// confirmation; these functions never print and never return a token hash.

// dbtx is satisfied by both *sql.DB and *sql.Tx, so the HTTP API can run
// a change and its audit row in one transaction while the CLI runs
// directly against the database.
type dbtx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// tokenPrefix marks hush tokens so secret scanners (gitleaks etc.) can be
// taught to spot a leaked one.
const tokenPrefix = "hush_"

var (
	errTokenExists   = errors.New("a token with this name already exists (names are never reused, even after revoke)")
	errTokenNotFound = errors.New("no token with this name")
	errTokenRevoked  = errors.New("token is revoked")
	errNotAgentToken = errors.New("only agent tokens have prefixes")
)

// grantError marks a rejected prefix set (the caller's input was wrong),
// as opposed to a lookup or database failure.
type grantError struct{ error }

func (e grantError) Unwrap() error { return e.error }

// tokenInfo is the public view of a token row. It deliberately has no hash
// field, so no caller can leak one by accident.
type tokenInfo struct {
	Name          string   `json:"name"`
	Role          string   `json:"role"`
	Prefixes      []string `json:"prefixes"`
	WritePrefixes []string `json:"write_prefixes"`
	Status        string   `json:"status"` // active | revoked | expired
	ExpiresAt     *int64   `json:"expires_at"`
	LastUsedAt    *int64   `json:"last_used_at"`
	RevokedAt     *int64   `json:"revoked_at"`
	CreatedAt     int64    `json:"created_at"`
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return tokenPrefix + hex.EncodeToString(b), nil
}

// grantsAll reports whether a read-prefix list is the "*" wildcard, which
// both front ends make the operator confirm explicitly.
func grantsAll(prefixes []string) bool {
	return len(prefixes) == 1 && prefixes[0] == allSecrets
}

// validateTokenSpec checks everything about a new token that doesn't need
// the database.
func validateTokenSpec(spec tokenSpec) error {
	if !tokenNameRe.MatchString(spec.name) {
		return fmt.Errorf("name must match %s", tokenNameRe)
	}
	return validateGrants(spec.role, spec.prefixes, spec.writePrefixes)
}

// createToken validates spec, refuses a reused name, stores the hash and
// returns the plaintext (the only time it exists) plus any warnings.
func createToken(ctx context.Context, q dbtx, spec tokenSpec, now time.Time) (string, []string, error) {
	if err := validateTokenSpec(spec); err != nil {
		return "", nil, err
	}
	if exists, err := tokenExists(ctx, q, spec.name); err != nil {
		return "", nil, err
	} else if exists {
		return "", nil, errTokenExists
	}
	warnings, err := writeNamespaceOverlaps(ctx, q, spec.name, spec.writePrefixes)
	if err != nil {
		return "", nil, err
	}
	plaintext, err := generateToken()
	if err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	if err := insertToken(ctx, q, spec, plaintext, now); err != nil {
		return "", nil, err
	}
	return plaintext, warnings, nil
}

func tokenExists(ctx context.Context, q dbtx, name string) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM tokens WHERE name = ?`, name).Scan(&n)
	return n > 0, err
}

func nullToPtr(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	return &v.Int64
}

// listTokens returns every token, sorted by name. token_hash is never
// selected.
func listTokens(ctx context.Context, q dbtx, now time.Time) ([]tokenInfo, error) {
	rows, err := q.QueryContext(ctx, `SELECT name, role, prefixes, write_prefixes, revoked_at, expires_at, last_used_at, created_at
		FROM tokens ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []tokenInfo{}
	for rows.Next() {
		var t tokenInfo
		var prefJSON, writeJSON string
		var revoked, expires, lastUsed sql.NullInt64
		if err := rows.Scan(&t.Name, &t.Role, &prefJSON, &writeJSON, &revoked, &expires, &lastUsed, &t.CreatedAt); err != nil {
			return nil, err
		}
		t.Prefixes, t.WritePrefixes = decodeGrant(prefJSON), decodeGrant(writeJSON)
		t.ExpiresAt, t.LastUsedAt, t.RevokedAt = nullToPtr(expires), nullToPtr(lastUsed), nullToPtr(revoked)
		t.Status = "active"
		switch {
		case revoked.Valid:
			t.Status = "revoked"
		case expires.Valid && now.Unix() >= expires.Int64:
			t.Status = "expired"
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// decodeGrant renders a stored prefix array; unreadable JSON shows as a
// marker rather than hiding the problem.
func decodeGrant(raw string) []string {
	p := []string{}
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return []string{"<unreadable>"}
	}
	return p
}

// grantUpdate replaces an agent token's read and/or write prefixes. A nil
// field keeps the current list; an empty non-nil slice clears it.
type grantUpdate struct {
	prefixes      *[]string
	writePrefixes *[]string
}

// updateTokenGrants applies u to an active agent token and returns the
// resulting lists plus any warnings.
func updateTokenGrants(ctx context.Context, q dbtx, name string, u grantUpdate) (read, write, warnings []string, err error) {
	var role, curRead, curWrite string
	var revoked sql.NullInt64
	err = q.QueryRowContext(ctx, `SELECT role, prefixes, write_prefixes, revoked_at FROM tokens WHERE name = ?`, name).
		Scan(&role, &curRead, &curWrite, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, errTokenNotFound
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if role != roleAgent {
		return nil, nil, nil, errNotAgentToken
	}
	if revoked.Valid {
		return nil, nil, nil, errTokenRevoked
	}
	// An unreadable current value is treated as empty.
	read, write = []string{}, []string{}
	_ = json.Unmarshal([]byte(curRead), &read)
	_ = json.Unmarshal([]byte(curWrite), &write)
	if u.prefixes != nil {
		read = append([]string{}, *u.prefixes...)
	}
	if u.writePrefixes != nil {
		write = append([]string{}, *u.writePrefixes...)
	}
	if err := validateGrants(roleAgent, read, write); err != nil {
		return nil, nil, nil, grantError{err}
	}
	if u.writePrefixes != nil {
		if warnings, err = writeNamespaceOverlaps(ctx, q, name, write); err != nil {
			return nil, nil, nil, err
		}
	}
	rj, err := json.Marshal(read)
	if err != nil {
		return nil, nil, nil, err
	}
	wj, err := json.Marshal(write)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := q.ExecContext(ctx, `UPDATE tokens SET prefixes = ?, write_prefixes = ? WHERE name = ?`,
		string(rj), string(wj), name); err != nil {
		return nil, nil, nil, err
	}
	return read, write, warnings, nil
}

// revokeToken permanently revokes name. alreadyRevoked is true (with a nil
// error) when there was nothing to do.
func revokeToken(ctx context.Context, q dbtx, name string, now time.Time) (alreadyRevoked bool, err error) {
	res, err := q.ExecContext(ctx, `UPDATE tokens SET revoked_at = ? WHERE name = ? AND revoked_at IS NULL`,
		now.Unix(), name)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return false, nil
	}
	exists, err := tokenExists(ctx, q, name)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, errTokenNotFound
	}
	return true, nil
}

// writeNamespaceOverlaps returns a warning for each write prefix that
// overlaps another active agent's. Create-only writes can't overwrite, but
// two agents sharing a namespace can still squat on or plant names the
// other expects, so one namespace per agent is the recommended setup.
func writeNamespaceOverlaps(ctx context.Context, q dbtx, self string, writePrefixes []string) ([]string, error) {
	if len(writePrefixes) == 0 {
		return nil, nil
	}
	rows, err := q.QueryContext(ctx, `SELECT name, write_prefixes FROM tokens
		WHERE name != ? AND role = 'agent' AND revoked_at IS NULL`, self)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var warnings []string
	for rows.Next() {
		var other, raw string
		if err := rows.Scan(&other, &raw); err != nil {
			return nil, err
		}
		var theirs []string
		if json.Unmarshal([]byte(raw), &theirs) != nil {
			continue
		}
		for _, mine := range writePrefixes {
			for _, t := range theirs {
				if strings.HasPrefix(mine, t) || strings.HasPrefix(t, mine) {
					warnings = append(warnings, fmt.Sprintf("write prefix %q overlaps %q on token %q; agents sharing a write namespace can create names the other relies on. Prefer one namespace per agent.", mine, t, other))
				}
			}
		}
	}
	return warnings, rows.Err()
}
