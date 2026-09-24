package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	// writePrefixes are create-only grants: an agent may PUT a new name
	// under them but never overwrite or delete.
	writePrefixes []string
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
		writeJSON            string
		stored               []byte
		revokedAt, expiresAt sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, token_hash, role, prefixes, write_prefixes, revoked_at, expires_at
		FROM tokens WHERE token_hash = ?`, given[:],
	).Scan(&id, &name, &stored, &role, &prefJSON, &writeJSON, &revokedAt, &expiresAt)
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
	var prefixes, writePrefixes []string
	if err := errors.Join(json.Unmarshal([]byte(prefJSON), &prefixes),
		json.Unmarshal([]byte(writeJSON), &writePrefixes)); err != nil {
		// Fail closed: a corrupted grant must not become a broader grant.
		slog.ErrorContext(ctx, "token prefixes unreadable; rejecting", "token_name", name)
		return nil, errUnauthenticated
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE tokens SET last_used_at = ? WHERE id = ?`, now, id); err != nil {
		// Bookkeeping only; don't fail the request over it.
		slog.WarnContext(ctx, "update last_used_at failed", "token_name", name, "error", err)
	}
	return &principal{name: name, role: role, prefixes: prefixes, writePrefixes: writePrefixes}, nil
}

// tokenSpec describes a token row to insert. Validation of name, role and
// prefixes happens in the CLI layer before this is called.
type tokenSpec struct {
	name     string
	role     string
	prefixes []string
	// writePrefixes: create-only grants (agent only).
	writePrefixes []string
	expiresAt     *time.Time
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
	wp := spec.writePrefixes
	if wp == nil {
		wp = []string{}
	}
	wj, err := json.Marshal(wp)
	if err != nil {
		return err
	}
	var exp sql.NullInt64
	if spec.expiresAt != nil {
		exp = sql.NullInt64{Int64: spec.expiresAt.Unix(), Valid: true}
	}
	h := hashToken(plaintext)
	_, err = db.ExecContext(ctx, `
		INSERT INTO tokens (name, token_hash, role, prefixes, write_prefixes, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		spec.name, h[:], spec.role, string(pj), string(wj), exp, now.Unix())
	return err
}

func principalFrom(ctx context.Context) *principal {
	p, _ := ctx.Value(principalKey{}).(*principal)
	return p
}

// requireCreateOrAdmin gates PUT. Admins pass; an agent passes only for a
// name under one of its write prefixes (the handler then refuses to
// overwrite). Like requireAdmin it runs before body parsing or any DB
// access, so an agent learns nothing about names outside its grant.
func requireCreateOrAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := principalFrom(r.Context())
		if p == nil || (p.role != roleAdmin && !p.canCreate(r.PathValue("name"))) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		h(w, r)
	}
}

// requireAdmin gates mutating routes. It runs before any request parsing or
// database access so an agent learns nothing beyond "not allowed".
func requireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p := principalFrom(r.Context()); p == nil || p.role != roleAdmin {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		h(w, r)
	}
}

// allSecrets is the wildcard grant. It must be the only prefix on a token
// and the CLI makes the operator confirm it explicitly.
const allSecrets = "*"

// prefixRe: name characters, at least one before the trailing separator,
// and a mandatory trailing '.' or '_'. The separator is what stops "llm."
// from matching "llmx.key".
var prefixRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,127}[._]$`)

// validatePrefixes enforces the grant rules for a role. Admin tokens carry
// no prefixes (they can read everything by role); agent tokens need at
// least one, and "*" cannot be mixed with others.
func validatePrefixes(role string, prefixes []string) error {
	return validateGrants(role, prefixes, nil)
}

// validateGrants checks a token's full grant: read prefixes as in
// validatePrefixes, plus create-only write prefixes. An agent needs at
// least one of the two. Write prefixes never accept "*": a token that can
// create any name is an admin in all but name.
func validateGrants(role string, prefixes, writePrefixes []string) error {
	switch role {
	case roleAdmin:
		if len(prefixes) > 0 || len(writePrefixes) > 0 {
			return errors.New("admin tokens do not take --prefix or --write-prefix (they can read and write everything)")
		}
		return nil
	case roleAgent:
	default:
		return fmt.Errorf("role must be %q or %q", roleAdmin, roleAgent)
	}
	if len(prefixes) == 0 && len(writePrefixes) == 0 {
		return errors.New("agent tokens need at least one --prefix or --write-prefix")
	}
	seenW := map[string]bool{}
	for _, p := range writePrefixes {
		if p == allSecrets {
			return errors.New(`"*" is not allowed as a write prefix; use a dedicated namespace such as agent-name.`)
		}
		if !prefixRe.MatchString(p) {
			return fmt.Errorf("invalid write prefix %q: must be name characters ending in '.' or '_' (e.g. crawler.)", p)
		}
		if seenW[p] {
			return fmt.Errorf("duplicate write prefix %q", p)
		}
		seenW[p] = true
	}
	seen := map[string]bool{}
	for _, p := range prefixes {
		if p == allSecrets {
			if len(prefixes) != 1 {
				return errors.New(`"*" must be the only prefix`)
			}
			continue
		}
		if !prefixRe.MatchString(p) {
			return fmt.Errorf("invalid prefix %q: must be name characters ending in '.' or '_' (e.g. llm.)", p)
		}
		if seen[p] {
			return fmt.Errorf("duplicate prefix %q", p)
		}
		seen[p] = true
	}
	return nil
}

// grantedPrefixes returns the agent's usable prefixes. Stored prefixes are
// re-validated on every use so a hand-edited row (say, an empty string,
// which would prefix-match everything) can never widen access.
func (p *principal) grantedPrefixes() (all bool, prefixes []string) {
	if p.role == roleAdmin {
		return true, nil
	}
	if len(p.prefixes) == 1 && p.prefixes[0] == allSecrets {
		return true, nil
	}
	for _, pre := range p.prefixes {
		if prefixRe.MatchString(pre) {
			prefixes = append(prefixes, pre)
		}
	}
	return false, prefixes
}

// canRead reports whether p may read the secret called name. It does not
// touch the database, so an out-of-scope name gets 403 whether or not it
// exists.
func (p *principal) canRead(name string) bool {
	all, prefixes := p.grantedPrefixes()
	if all {
		return true
	}
	for _, pre := range prefixes {
		if strings.HasPrefix(name, pre) {
			return true
		}
	}
	return false
}

// canCreate reports whether an agent may create the secret called name.
// Only admins and names under a write prefix qualify; "*" and malformed
// stored prefixes never grant anything (re-validated as for reads).
func (p *principal) canCreate(name string) bool {
	if p.role == roleAdmin {
		return true
	}
	if !nameRe.MatchString(name) {
		return false
	}
	for _, pre := range p.writePrefixes {
		if prefixRe.MatchString(pre) && strings.HasPrefix(name, pre) {
			return true
		}
	}
	return false
}
