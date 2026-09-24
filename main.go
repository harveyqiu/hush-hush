package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	maxValueBytes      = 64 * 1024
	maxBodyBytes       = maxValueBytes + 1024
	shutdownGrace      = 10 * time.Second
	cryptoVersion byte = 0x01
	// listLimit caps the LIST response to bound memory for accidental
	// bulk imports. Personal scale should never approach this.
	listLimit = 1000
)

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,128}$`)

// requestIDRe restricts inbound X-Request-ID values: permissive enough
// for common formats (UUID, ULID, hex) but strict enough to defeat
// log-injection (no CRLF, no quote, bounded length).
var requestIDRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

type server struct {
	db  *sql.DB
	gcm cipher.AEAD
	// legacyTokenHash is set only when the deprecated AUTH_TOKEN env var
	// is in use; it then authenticates as an admin.
	legacyTokenHash *[32]byte
	now             func() time.Time
	// tokenLimiter is keyed by authenticated token name; ipLimiter by
	// client IP and consumed only by requests that fail authentication.
	tokenLimiter *rateLimiter
	ipLimiter    *rateLimiter
	// trustProxy makes clientIP honour X-Forwarded-For from a loopback
	// peer (the co-located reverse proxy).
	trustProxy bool
}

type secretRow struct {
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// serve runs the HTTP API until SIGINT/SIGTERM. It is the default when the
// binary is started without a subcommand, preserving v0.1.0 behaviour.
func serve() {
	// JSON to stdout — Railway's log viewer parses it; jq-friendly locally.
	// contextHandler picks up request_id from r.Context() so handlers don't
	// have to thread it manually.
	slog.SetDefault(slog.New(&contextHandler{
		Handler: slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
	}))

	cfg, err := loadConfig(os.Getenv, os.ReadFile)
	if err != nil {
		fatal("invalid configuration", "error", err)
	}
	for _, w := range cfg.warnings {
		slog.Warn(w)
	}
	dbPath := cfg.dbPath

	db, err := openDB(dbPath)
	if err != nil {
		fatal("database open failed", "error", err)
	}
	defer db.Close()
	checkDBPerms(dbPath)

	s, err := newServer(db, cfg.key, cfg.legacyToken)
	if err != nil {
		fatal("server init failed", "error", err)
	}
	// The cipher has its own expanded copy; drop ours.
	clear(cfg.key)
	s.tokenLimiter = newRateLimiter(cfg.rateLimitPerMinute)
	s.ipLimiter = newRateLimiter(cfg.unauthRateLimitPerMinute)
	s.trustProxy = cfg.trustProxy
	if n, err := s.activeTokenCount(); err != nil {
		fatal("token count failed", "error", err)
	} else if n == 0 && cfg.legacyToken == "" {
		slog.Warn("no active tokens: every API request will be rejected until one is created with `token create`")
	}

	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           withRequestID(s.routes()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		// key_source says where the key came from; the key itself is
		// never logged.
		slog.Info("listening", "addr", cfg.listenAddr, "db_path", dbPath,
			"key_source", cfg.keySource, "trust_proxy_headers", cfg.trustProxy,
			"rate_limit_per_minute", cfg.rateLimitPerMinute,
			"unauth_rate_limit_per_minute", cfg.unauthRateLimitPerMinute)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal("listen failed", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutdown: draining connections", "grace", shutdownGrace.String())
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown failed", "error", err)
	}
	slog.Info("shutdown: done")
}

// newServer constructs a server from already-validated dependencies.
// Extracted from main() so tests can build a server against an in-memory
// database without parsing env vars or duplicating crypto setup.
// legacyToken is the deprecated AUTH_TOKEN value, or "" when unset.
func newServer(db *sql.DB, key []byte, legacyToken string) (*server, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &server{
		db:           db,
		gcm:          gcm,
		now:          time.Now,
		tokenLimiter: newRateLimiter(defaultRateLimitPerMinute),
		ipLimiter:    newRateLimiter(defaultUnauthRateLimitPerMinute),
	}
	if legacyToken != "" {
		slog.Warn("AUTH_TOKEN is deprecated: it is accepted as an admin token but cannot be scoped or revoked individually; create named tokens with `token create` and unset AUTH_TOKEN")
		h := hashToken(legacyToken)
		s.legacyTokenHash = &h
	}
	return s, nil
}

func (s *server) activeTokenCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens
		WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
		s.now().Unix()).Scan(&n)
	return n, err
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /v1/secrets", s.secretsRoute(actionList, s.list))
	mux.HandleFunc("GET /v1/secrets/{name}", s.secretsRoute(actionGet, s.get))
	mux.HandleFunc("PUT /v1/secrets/{name}", s.secretsRoute(actionPut, requireCreateOrAdmin(s.put)))
	mux.HandleFunc("DELETE /v1/secrets/{name}", s.secretsRoute(actionDelete, requireAdmin(s.del)))
	// Catch-alls so every other request under /v1/secrets (wrong method,
	// nested path) is still authenticated, rate limited and audited
	// instead of being answered by the mux without a trace.
	mux.HandleFunc("/v1/secrets", s.secretsRoute(actionOther, unmatched))
	mux.HandleFunc("/v1/secrets/", s.secretsRoute(actionOther, unmatched))
	return mux
}

type principalKey struct{}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) list(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	all, prefixes := p.grantedPrefixes()
	if !all && len(prefixes) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"secrets": []secretRow{}})
		return
	}
	// Agents get the prefix filter in SQL so LIMIT applies to what they
	// may see. substr() rather than LIKE: '_' is a LIKE wildcard and is
	// also a legal prefix separator.
	query := `SELECT name, created_at, updated_at FROM secrets`
	var args []any
	if !all {
		conds := make([]string, len(prefixes))
		for i, pre := range prefixes {
			conds[i] = `substr(name, 1, ?) = ?`
			args = append(args, len(pre), pre)
		}
		query += ` WHERE ` + strings.Join(conds, ` OR `) // #nosec G202 -- joins constant placeholders only; values are bound as args
	}
	query += ` ORDER BY name LIMIT ?`
	args = append(args, listLimit)

	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		slog.ErrorContext(r.Context(), "list query failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	out := []secretRow{}
	for rows.Next() {
		var sr secretRow
		if err := rows.Scan(&sr.Name, &sr.CreatedAt, &sr.UpdatedAt); err != nil {
			slog.ErrorContext(r.Context(), "list scan failed", "error", err)
			writeErr(w, http.StatusInternalServerError, "db error")
			return
		}
		// Belt and braces: the SQL filter should already guarantee this.
		if !p.canRead(sr.Name) {
			continue
		}
		out = append(out, sr)
	}
	if err := rows.Err(); err != nil {
		slog.ErrorContext(r.Context(), "list rows iteration failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secrets": out})
}

func (s *server) get(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !nameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid name")
		return
	}
	// Checked before the lookup so an agent gets 403 for every name outside
	// its grant, existing or not; 404 would let it probe for names.
	if !principalFrom(r.Context()).canRead(name) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var ct, nonce []byte
	var createdAt, updatedAt int64
	err := s.db.QueryRowContext(r.Context(),
		`SELECT ciphertext, nonce, created_at, updated_at FROM secrets WHERE name = ?`, name,
	).Scan(&ct, &nonce, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "get query failed", "name", name, "error", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if len(ct) < 1 {
		slog.ErrorContext(r.Context(), "ciphertext empty", "name", name)
		writeErr(w, http.StatusInternalServerError, "decrypt failed")
		return
	}
	if ct[0] != cryptoVersion {
		slog.ErrorContext(r.Context(), "unsupported ciphertext version",
			"name", name,
			"version", fmt.Sprintf("0x%02x", ct[0]),
			"expected", fmt.Sprintf("0x%02x", cryptoVersion),
		)
		writeErr(w, http.StatusInternalServerError, "decrypt failed")
		return
	}
	pt, err := s.gcm.Open(nil, nonce, ct[1:], aad(name))
	if err != nil {
		slog.ErrorContext(r.Context(), "decrypt failed", "name", name, "error", err)
		writeErr(w, http.StatusInternalServerError, "decrypt failed")
		return
	}
	writeJSON(w, http.StatusOK, secretRow{
		Name:      name,
		Value:     string(pt),
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	})
}

func (s *server) put(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !nameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid name")
		return
	}
	// Reject anything that doesn't claim to be JSON. mime.ParseMediaType
	// handles RFC-correct case-insensitivity ("Application/JSON") and
	// strips parameters ("application/json; charset=utf-8" → ok).
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeErr(w, http.StatusUnsupportedMediaType, "content-type must be application/json")
		return
	}
	// Read one byte beyond the cap so an oversized body returns a clear
	// "too large" error instead of a confusing "invalid json" from a
	// silently truncated payload.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body")
		return
	}
	if len(body) > maxBodyBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	var in struct {
		Value string `json:"value"`
	}
	// Strict JSON: reject unknown fields (so a future struct change can't
	// be silently mass-assigned) and reject trailing bytes after the
	// object (so a malformed body can't slip through past a valid prefix).
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if dec.More() {
		writeErr(w, http.StatusBadRequest, "trailing data after json")
		return
	}
	if in.Value == "" {
		writeErr(w, http.StatusBadRequest, "value required")
		return
	}
	if len(in.Value) > maxValueBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "value too large")
		return
	}

	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		writeErr(w, http.StatusInternalServerError, "rng failed")
		return
	}
	// 1-byte version prefix lets us migrate algorithms later without
	// losing access to existing rows. Version is also bound into AAD
	// so flipping the prefix byte is rejected by the AEAD tag.
	ct := append([]byte{cryptoVersion}, s.gcm.Seal(nil, nonce, []byte(in.Value), aad(name))...)

	now := time.Now().Unix()
	// The upsert and its audit row commit together: a write either happens
	// and is recorded, or neither happens.
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		slog.ErrorContext(r.Context(), "put begin failed", "name", name, "error", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer func() { _ = tx.Rollback() }()
	// Admins upsert. Agents (let through by requireCreateOrAdmin only for
	// names under a write prefix) may create but never overwrite: DO
	// NOTHING returns no row for an existing name, which becomes 409.
	// Doing it in one statement leaves no check-then-insert race.
	onConflict := `DO UPDATE SET
			ciphertext = excluded.ciphertext,
			nonce      = excluded.nonce,
			updated_at = excluded.updated_at`
	if principalFrom(r.Context()).role != roleAdmin {
		onConflict = `DO NOTHING`
	}
	var createdAt int64
	err = tx.QueryRowContext(r.Context(), `
		INSERT INTO secrets (name, ciphertext, nonce, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(name) `+onConflict+`
		RETURNING created_at
	`, name, ct, nonce, now, now).Scan(&createdAt) // #nosec G202 -- onConflict is one of two constants
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusConflict, "already exists")
		return
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "put exec failed", "name", name, "error", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if err := s.commitWithAudit(r.Context(), tx); err != nil {
		slog.ErrorContext(r.Context(), "put commit failed", "name", name, "error", err)
		writeErr(w, http.StatusInternalServerError, "audit failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":       name,
		"created_at": createdAt,
		"updated_at": now,
	})
}

func (s *server) del(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !nameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid name")
		return
	}
	// Idempotent (admin only; agents are stopped by requireAdmin): a
	// network retry of a successful DELETE should not surface as an error.
	// We don't distinguish "deleted" from "wasn't there"; both end states
	// are identical. As with PUT, the delete and its audit row commit
	// together.
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		slog.ErrorContext(r.Context(), "delete begin failed", "name", name, "error", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM secrets WHERE name = ?`, name); err != nil {
		slog.ErrorContext(r.Context(), "delete exec failed", "name", name, "error", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if err := s.commitWithAudit(r.Context(), tx); err != nil {
		slog.ErrorContext(r.Context(), "delete commit failed", "name", name, "error", err)
		writeErr(w, http.StatusInternalServerError, "audit failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	// Defense in depth against any CDN (Fastly sits in front on Railway)
	// caching authenticated responses.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// aad binds both the secret name AND the ciphertext version into the AEAD
// associated data. Name binding prevents row-rebinding (moving ciphertext
// between names); version binding prevents algorithm-downgrade attacks if
// a future cryptoVersion is introduced.
func aad(name string) []byte {
	out := make([]byte, 0, 1+len(name))
	out = append(out, cryptoVersion)
	out = append(out, name...)
	return out
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		fatal("missing required env var", "key", k)
	}
	return v
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ---- logging / request-id middleware ----

// ctxKey is unexported and unique-per-package, the canonical Go pattern
// for stuffing values into request context without colliding.
type ctxKey struct{}

// contextHandler wraps an slog.Handler so any record logged with a
// context-bearing call (slog.ErrorContext etc.) automatically gets the
// request_id attribute attached. Handlers therefore don't need to
// thread the ID through every log call manually.
type contextHandler struct{ slog.Handler }

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if id, ok := ctx.Value(ctxKey{}).(string); ok && id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

// withRequestID resolves a request ID for each request, stashes it in
// the request context, and echoes it in X-Request-ID so a client can
// correlate a server log line to the response they received.
//
// Resolution order:
//  1. Inbound X-Request-ID (e.g. an upstream Railway / CDN trace) if it
//     passes requestIDRe — preserves end-to-end correlation.
//  2. Fresh 16-hex-char value from crypto/rand.
//  3. The string "rng-failed" as a last-resort sentinel so log lines
//     are still correlatable instead of orphaned. rand.Read failing on
//     Linux is essentially impossible but the empty-ID branch was a
//     silent observability hole.
func withRequestID(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !requestIDRe.MatchString(id) {
			b := make([]byte, 8)
			if _, err := rand.Read(b); err == nil {
				id = hex.EncodeToString(b)
			} else {
				id = "rng-failed"
			}
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), ctxKey{}, id)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// fatal emits a structured error log line and exits 1. Used for startup
// failures where slog's lack of Fatal-level would otherwise force every
// caller to repeat the os.Exit(1) themselves.
func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
