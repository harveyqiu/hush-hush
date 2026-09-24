package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Test tokens are deliberately low-entropy so secret scanners don't flag
// them as leaked credentials.
const (
	agentToken  = "hush_agent-token-for-tests"
	otherToken  = "hush_other-token-for-tests"
	legacyToken = "legacy-env-token-for-tests"
)

func reqWithToken(method, path, token string, body []byte) *http.Request {
	req := authReq(method, path, body)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func mustInsertToken(t *testing.T, s *server, spec tokenSpec, plaintext string) {
	t.Helper()
	if err := insertToken(context.Background(), s.db, spec, plaintext, time.Now()); err != nil {
		t.Fatalf("insert token %q: %v", spec.name, err)
	}
}

func decodeErrBody(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", rr.Body.String(), err)
	}
	return body.Error
}

func TestAuth_MultipleTokens(t *testing.T) {
	s, h := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "second-admin", role: roleAdmin}, otherToken)

	for _, tok := range []string{testToken, otherToken} {
		if rr := do(h, reqWithToken("GET", "/v1/secrets", tok, nil)); rr.Code != http.StatusOK {
			t.Errorf("token %q: got %d, want 200", tok, rr.Code)
		}
	}
}

// Every credential failure must produce the same status and body so a
// caller can't tell "never existed" from "revoked" from "expired".
func TestAuth_FailuresAreIndistinguishable(t *testing.T) {
	s, h := newTestServer(t)
	past := time.Now().Add(-time.Minute)
	mustInsertToken(t, s, tokenSpec{name: "expired", role: roleAdmin, expiresAt: &past}, "hush_expired-token")
	mustInsertToken(t, s, tokenSpec{name: "revoked", role: roleAdmin}, "hush_revoked-token")
	if _, err := s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE name = 'revoked'`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"no header": "",
		"unknown":   "Bearer hush_never-issued",
		"expired":   "Bearer hush_expired-token",
		"revoked":   "Bearer hush_revoked-token",
		"no scheme": testToken,
		"empty":     "Bearer ",
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/v1/secrets", nil)
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			rr := do(h, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", rr.Code)
			}
			if got := decodeErrBody(t, rr); got != "unauthorized" {
				t.Errorf("error = %q, want %q", got, "unauthorized")
			}
			if got := rr.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}

func TestAuth_RevocationIsImmediate(t *testing.T) {
	s, h := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "soon-revoked", role: roleAdmin}, otherToken)

	if rr := do(h, reqWithToken("GET", "/v1/secrets", otherToken, nil)); rr.Code != http.StatusOK {
		t.Fatalf("before revoke: got %d, want 200", rr.Code)
	}
	if _, err := s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE name = ?`, time.Now().Unix(), "soon-revoked"); err != nil {
		t.Fatal(err)
	}
	if rr := do(h, reqWithToken("GET", "/v1/secrets", otherToken, nil)); rr.Code != http.StatusUnauthorized {
		t.Errorf("after revoke: got %d, want 401", rr.Code)
	}
}

func TestAuth_Expiry(t *testing.T) {
	s, h := newTestServer(t)
	exp := time.Now().Add(time.Hour)
	mustInsertToken(t, s, tokenSpec{name: "short-lived", role: roleAdmin, expiresAt: &exp}, otherToken)

	if rr := do(h, reqWithToken("GET", "/v1/secrets", otherToken, nil)); rr.Code != http.StatusOK {
		t.Fatalf("before expiry: got %d, want 200", rr.Code)
	}
	s.now = func() time.Time { return exp.Add(time.Second) }
	if rr := do(h, reqWithToken("GET", "/v1/secrets", otherToken, nil)); rr.Code != http.StatusUnauthorized {
		t.Errorf("after expiry: got %d, want 401", rr.Code)
	}
}

func TestAuth_UpdatesLastUsed(t *testing.T) {
	s, h := newTestServer(t)
	do(h, authReq("GET", "/v1/secrets", nil))
	var lastUsed sql.NullInt64
	if err := s.db.QueryRow(`SELECT last_used_at FROM tokens WHERE name = 'test-admin'`).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if !lastUsed.Valid || lastUsed.Int64 == 0 {
		t.Errorf("last_used_at not set after a successful request")
	}
}

// The tokens table must hold only SHA-256 hashes, never the plaintext.
func TestTokens_OnlyHashStored(t *testing.T) {
	s, _ := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "agent-x", role: roleAgent, prefixes: []string{"llm."}}, agentToken)

	rows, err := s.db.Query(`SELECT name, token_hash, role, prefixes FROM tokens`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, role, prefixes string
		var h []byte
		if err := rows.Scan(&name, &h, &role, &prefixes); err != nil {
			t.Fatal(err)
		}
		if len(h) != 32 {
			t.Errorf("%s: token_hash length %d, want 32", name, len(h))
		}
		for _, plain := range []string{testToken, agentToken} {
			if bytes.Contains(h, []byte(plain)) || strings.Contains(name+role+prefixes, plain) {
				t.Errorf("%s: plaintext token found in row", name)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := hashToken(agentToken)
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE token_hash = ?`, want[:]).Scan(&n); err != nil || n != 1 {
		t.Errorf("expected exactly one row keyed by the SHA-256 of the token (n=%d, err=%v)", n, err)
	}
}

// captureLogs redirects the default slog logger into a buffer for the
// duration of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(&contextHandler{Handler: slog.NewJSONHandler(&buf, nil)}))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestLegacyAuthToken_ActsAsAdminWithWarning(t *testing.T) {
	logs := captureLogs(t)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	s, err := newServer(db, testKey(), legacyToken)
	if err != nil {
		t.Fatal(err)
	}
	h := s.routes()

	if !strings.Contains(logs.String(), "AUTH_TOKEN is deprecated") {
		t.Errorf("expected a deprecation warning, logs: %s", logs.String())
	}
	if strings.Contains(logs.String(), legacyToken) {
		t.Errorf("legacy token plaintext leaked into logs")
	}

	// Admin powers: write, read, delete.
	if rr := do(h, reqWithToken("PUT", "/v1/secrets/legacy.test", legacyToken, []byte(`{"value":"v"}`))); rr.Code != http.StatusOK {
		t.Fatalf("PUT with legacy token: got %d", rr.Code)
	}
	if rr := do(h, reqWithToken("GET", "/v1/secrets/legacy.test", legacyToken, nil)); rr.Code != http.StatusOK {
		t.Fatalf("GET with legacy token: got %d", rr.Code)
	}
	if rr := do(h, reqWithToken("DELETE", "/v1/secrets/legacy.test", legacyToken, nil)); rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE with legacy token: got %d", rr.Code)
	}
	// And nothing else authenticates.
	if rr := do(h, reqWithToken("GET", "/v1/secrets", "not-"+legacyToken, nil)); rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: got %d, want 401", rr.Code)
	}
}

// v010Schema is the exact DDL from v0.1.0's initSchema.
const v010Schema = `
		CREATE TABLE IF NOT EXISTS secrets (
			name       TEXT PRIMARY KEY,
			ciphertext BLOB NOT NULL,
			nonce      BLOB NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);
	`

// TestMigrate_V010Database builds a database the way v0.1.0 did (its DDL,
// its ciphertext layout, encrypted independently of the server code) and
// checks the new binary opens it, migrates it, and decrypts the rows.
func TestMigrate_V010Database(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v010.db")
	old, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(v010Schema); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(testKey())
	gcm, _ := cipher.NewGCM(block)
	const name, value = "legacy.api_key", "value-written-by-v0.1.0"
	nonce := bytes.Repeat([]byte{7}, 12)
	ad := append([]byte{0x01}, name...)
	ct := append([]byte{0x01}, gcm.Seal(nil, nonce, []byte(value), ad)...)
	if _, err := old.Exec(`INSERT INTO secrets VALUES (?, ?, ?, 100, 200)`, name, ct, nonce); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	// Open twice: the second open must be a no-op migration.
	for i := 0; i < 2; i++ {
		db, err := openDB(path)
		if err != nil {
			t.Fatalf("openDB #%d: %v", i+1, err)
		}
		var version int
		if err := db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&version); err != nil {
			t.Fatal(err)
		}
		if version != len(migrations) {
			t.Errorf("schema version = %d, want %d", version, len(migrations))
		}
		s, err := newServer(db, testKey(), "")
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			mustInsertToken(t, s, tokenSpec{name: "admin", role: roleAdmin}, testToken)
		}
		rr := do(s.routes(), authReq("GET", "/v1/secrets/"+name, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("GET legacy secret: got %d (%s)", rr.Code, rr.Body.String())
		}
		var got secretRow
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Value != value || got.CreatedAt != 100 || got.UpdatedAt != 200 {
			t.Errorf("got %+v, want value %q created 100 updated 200", got, value)
		}
		db.Close()
	}
}

func TestMigrate_RefusesNewerSchema(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_version (version) VALUES (?)`, len(migrations)+1); err != nil {
		t.Fatal(err)
	}
	if err := migrate(db); err == nil {
		t.Error("migrate on a newer schema should fail")
	}
}

func TestOpenDB_CreatesFile0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.db")
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	fi, err := statMode(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi != 0o600 {
		t.Errorf("new db file mode = %#o, want 0600", fi)
	}
}

func decodeJSON(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode %q: %v", b, err)
	}
}
