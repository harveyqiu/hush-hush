package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Fixed, low-entropy markers: every one contains "MARKER", so a single
// substring check catches any of them leaking, and none looks like a real
// credential to secret scanners.
const (
	markerValue      = "MARKER-SECRET-VALUE-7f3a"
	markerOtherValue = "MARKER-SECRET-VALUE-other"
	markerAdmin      = "hush_MARKER-TOKEN-ADMIN"
	markerAgent      = "hush_MARKER-TOKEN-AGENT"
	markerBogus      = "hush_MARKER-TOKEN-BOGUS"
	markerRevoked    = "hush_MARKER-TOKEN-REVOKED"
	markerExpired    = "hush_MARKER-TOKEN-EXPIRED"
	markerSubstring  = "MARKER"
)

var allMarkers = []string{markerValue, markerOtherValue, markerAdmin, markerAgent,
	markerBogus, markerRevoked, markerExpired}

// assertNoMarkers fails if text contains any marker, or the SHA-256 hex of
// any marker token (a hash in a log is almost as useful to an attacker
// correlating tokens as the token itself).
func assertNoMarkers(t *testing.T, where, text string) {
	t.Helper()
	if strings.Contains(text, markerSubstring) {
		for _, m := range allMarkers {
			if strings.Contains(text, m) {
				t.Errorf("%s contains marker %q", where, m)
			}
		}
		t.Errorf("%s contains %q:\n%s", where, markerSubstring, text)
	}
	for _, m := range allMarkers {
		h := hashToken(m)
		if strings.Contains(strings.ToLower(text), hex.EncodeToString(h[:])) {
			t.Errorf("%s contains the SHA-256 of %q", where, m)
		}
	}
}

// Acceptance: the audit log, slog output and error responses never contain
// a secret value or token plaintext, across every request path.
func TestLeak_NoSecretsOrTokensAnywhere(t *testing.T) {
	logs := captureLogs(t)
	path := newTestDBFile(t)
	s, _ := serverOn(t, path)
	h := withRequestID(s.routes())
	mustInsertToken(t, s, tokenSpec{name: "leak-admin", role: roleAdmin}, markerAdmin)
	mustInsertToken(t, s, tokenSpec{name: "leak-agent", role: roleAgent, prefixes: []string{"llm."}}, markerAgent)
	mustInsertToken(t, s, tokenSpec{name: "leak-revoked", role: roleAdmin}, markerRevoked)
	past := time.Now().Add(-time.Hour)
	mustInsertToken(t, s, tokenSpec{name: "leak-expired", role: roleAdmin, expiresAt: &past}, markerExpired)
	if _, err := s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE name = 'leak-revoked'`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	type step struct {
		desc     string
		h        http.Handler
		method   string
		path     string
		auth     string // full Authorization header; "" sends none
		body     string
		ctype    string
		wantCode int
	}
	bearer := func(tok string) string { return "Bearer " + tok }
	valueBody := `{"value":"` + markerValue + `"}`
	steps := []step{
		{"admin put", h, "PUT", "/v1/secrets/llm.key", bearer(markerAdmin), valueBody, "application/json", 200},
		{"admin put other", h, "PUT", "/v1/secrets/github.token", bearer(markerAdmin), `{"value":"` + markerOtherValue + `"}`, "application/json", 200},
		{"put truncated json", h, "PUT", "/v1/secrets/llm.key", bearer(markerAdmin), `{"value":"` + markerValue, "application/json", 400},
		{"put unknown field", h, "PUT", "/v1/secrets/llm.key", bearer(markerAdmin), `{"value":"x","` + markerValue + `":1}`, "application/json", 400},
		{"put trailing data", h, "PUT", "/v1/secrets/llm.key", bearer(markerAdmin), valueBody + valueBody, "application/json", 400},
		{"put wrong content type", h, "PUT", "/v1/secrets/llm.key", bearer(markerAdmin), valueBody, "text/plain", 415},
		{"put oversized", h, "PUT", "/v1/secrets/llm.big", bearer(markerAdmin), `{"value":"` + markerValue + strings.Repeat("x", maxValueBytes) + `"}`, "application/json", 413},
		{"agent get allowed", h, "GET", "/v1/secrets/llm.key", bearer(markerAgent), "", "", 200},
		{"agent get denied", h, "GET", "/v1/secrets/github.token", bearer(markerAgent), "", "", 403},
		{"agent get not found", h, "GET", "/v1/secrets/llm.missing", bearer(markerAgent), "", "", 404},
		{"agent put", h, "PUT", "/v1/secrets/llm.key", bearer(markerAgent), valueBody, "application/json", 403},
		{"agent delete", h, "DELETE", "/v1/secrets/llm.key", bearer(markerAgent), "", "", 403},
		{"agent list", h, "GET", "/v1/secrets", bearer(markerAgent), "", "", 200},
		{"admin list", h, "GET", "/v1/secrets", bearer(markerAdmin), "", "", 200},
		{"bad name", h, "GET", "/v1/secrets/bad$name", bearer(markerAdmin), "", "", 400},
		{"bogus token", h, "GET", "/v1/secrets/llm.key", bearer(markerBogus), "", "", 401},
		{"bogus token list", h, "GET", "/v1/secrets", bearer(markerBogus), "", "", 401},
		{"token without scheme", h, "GET", "/v1/secrets/llm.key", markerAgent, "", "", 401},
		{"wrong scheme", h, "GET", "/v1/secrets/llm.key", "Token " + markerAgent, "", "", 401},
		{"revoked token", h, "GET", "/v1/secrets/llm.key", bearer(markerRevoked), "", "", 401},
		{"expired token", h, "GET", "/v1/secrets/llm.key", bearer(markerExpired), "", "", 401},
		{"no token", h, "GET", "/v1/secrets/llm.key", "", "", "", 401},
		{"admin put 2", h, "PUT", "/v1/secrets/llm.second", bearer(markerAdmin), valueBody, "application/json", 200},
		{"admin delete", h, "DELETE", "/v1/secrets/llm.second", bearer(markerAdmin), "", "", 204},
	}

	var sawValue bool
	check := func(st step, rr *httptest.ResponseRecorder) {
		t.Helper()
		body := rr.Body.String()
		if rr.Code != st.wantCode {
			t.Errorf("%s: status %d, want %d (%s)", st.desc, rr.Code, st.wantCode, body)
		}
		// Only a successful single-secret GET may carry the value.
		if rr.Code == http.StatusOK && st.method == "GET" && st.path != "/v1/secrets" {
			sawValue = sawValue || strings.Contains(body, markerValue)
			return
		}
		assertNoMarkers(t, st.desc+" response body", body)
		for k, vs := range rr.Header() {
			assertNoMarkers(t, st.desc+" header "+k, strings.Join(vs, " "))
		}
		if rr.Code < 400 {
			return
		}
		// Error bodies are a single generic message: no secret names, token
		// names or grant prefixes.
		var e map[string]string
		decodeJSON(t, rr.Body.Bytes(), &e)
		if len(e) != 1 || e["error"] == "" {
			t.Errorf("%s: error body has unexpected shape: %s", st.desc, body)
		}
		for _, name := range []string{"llm.", "github", "leak-", tokenPrefix} {
			if strings.Contains(body, name) {
				t.Errorf("%s: error body mentions %q: %s", st.desc, name, body)
			}
		}
		if rr.Code == http.StatusForbidden && body != "{\"error\":\"forbidden\"}\n" {
			t.Errorf("%s: 403 body = %q, want exactly {\"error\":\"forbidden\"}", st.desc, body)
		}
	}
	for _, st := range steps {
		req := httptest.NewRequest(st.method, st.path, strings.NewReader(st.body))
		if st.auth != "" {
			req.Header.Set("Authorization", st.auth)
		}
		if st.ctype != "" {
			req.Header.Set("Content-Type", st.ctype)
		}
		check(st, do(st.h, req))
	}
	if !sawValue {
		t.Error("sanity: no successful GET returned the marker value; the test is not exercising reads")
	}

	// Tampered ciphertext: the decrypt-failure path logs and returns 500.
	var ct []byte
	if err := s.db.QueryRow(`SELECT ciphertext FROM secrets WHERE name = 'github.token'`).Scan(&ct); err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0xFF
	if _, err := s.db.Exec(`UPDATE secrets SET ciphertext = ? WHERE name = 'github.token'`, ct); err != nil {
		t.Fatal(err)
	}
	check(step{desc: "tampered ciphertext", method: "GET", path: "/v1/secrets/github.token", wantCode: 500},
		do(h, reqWithToken("GET", "/v1/secrets/github.token", markerAdmin, nil)))

	// Audit rows: every column of every row.
	rows, err := s.db.Query(`SELECT * FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var dump strings.Builder
	n := 0
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			fmt.Fprintf(&dump, "%s=%v ", cols[i], v)
		}
		dump.WriteString("\n")
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if n != len(steps)+1 {
		t.Errorf("audit_log has %d rows, want %d (one per request)", n, len(steps)+1)
	}
	assertNoMarkers(t, "audit_log", dump.String())

	// Admin CLI output built from the same tables.
	for _, args := range [][]string{
		{"audit", "--db", path, "--limit", "1000"},
		{"token", "list", "--db", path},
	} {
		r := runCLI(t, "", args...)
		if r.code != 0 {
			t.Fatalf("%v: code %d stderr %s", args, r.code, r.stderr)
		}
		assertNoMarkers(t, strings.Join(args[:2], " ")+" stdout", r.stdout)
		assertNoMarkers(t, strings.Join(args[:2], " ")+" stderr", r.stderr)
	}
	if r := runCLI(t, "", "audit", "--db", path, "--result", "denied"); !strings.Contains(r.stdout, "leak-agent") {
		t.Errorf("sanity: audit output lacks the denied agent rows:\n%s", r.stdout)
	}

	// Everything slog wrote during the test, including the decrypt / auth
	// failure logs.
	out := logs.String()
	if !strings.Contains(out, "decrypt failed") {
		t.Errorf("sanity: expected failure-path logs were not captured:\n%s", out)
	}
	assertNoMarkers(t, "slog output", out)
}
