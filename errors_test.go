package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Error paths, mostly driven by the fault-injecting driver in
// faultdb_test.go against the real handlers and a real database.

// errReader fails every read, to exercise "can't read the body" paths.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func bodyErrReq(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, errReader{})
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestSecretsHandlers_DBFaults(t *testing.T) {
	cases := []struct {
		name     string
		op, sql  string
		req      func() *http.Request
		wantCode int
	}{
		{"list query", "query", "FROM secrets", func() *http.Request { return authReq("GET", "/v1/secrets", nil) }, 500},
		{"list iteration", "next", "FROM secrets", func() *http.Request { return authReq("GET", "/v1/secrets", nil) }, 500},
		{"put begin", "begin", "", func() *http.Request { return authReq("PUT", "/v1/secrets/a.b", []byte(`{"value":"v"}`)) }, 500},
		{"put insert", "query", "INSERT INTO secrets", func() *http.Request { return authReq("PUT", "/v1/secrets/a.b", []byte(`{"value":"v"}`)) }, 500},
		{"delete begin", "begin", "", func() *http.Request { return authReq("DELETE", "/v1/secrets/a.b", nil) }, 500},
		{"delete exec", "exec", "DELETE FROM secrets", func() *http.Request { return authReq("DELETE", "/v1/secrets/a.b", nil) }, 500},
		{"delete commit", "commit", "", func() *http.Request { return authReq("DELETE", "/v1/secrets/a.b", nil) }, 500},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newFaultServer(t)
			seedSecrets(t, s.routes(), "a.b")
			injectFault(t, c.op, c.sql, 0)
			if rr := do(s.routes(), c.req()); rr.Code != c.wantCode {
				t.Errorf("got %d, want %d (%s)", rr.Code, c.wantCode, rr.Body.String())
			}
		})
	}
	t.Run("list scan", func(t *testing.T) {
		s, _ := newFaultServer(t)
		seedSecrets(t, s.routes(), "a.b")
		injectNullColumn(t, "FROM secrets", 1)
		if rr := do(s.routes(), authReq("GET", "/v1/secrets", nil)); rr.Code != 500 {
			t.Errorf("got %d, want 500", rr.Code)
		}
	})
}

func TestSecretsHandlers_BadInput(t *testing.T) {
	s, h := newTestServer(t)
	if rr := do(h, bodyErrReq("PUT", "/v1/secrets/a.b")); rr.Code != 400 {
		t.Errorf("unreadable body: %d", rr.Code)
	}
	huge := append([]byte(`{"value":"`), bytes.Repeat([]byte("x"), maxBodyBytes)...)
	huge = append(huge, `"}`...)
	if rr := do(h, authReq("PUT", "/v1/secrets/a.b", huge)); rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: %d", rr.Code)
	}
	if rr := do(h, authReq("DELETE", "/v1/secrets/bad!", nil)); rr.Code != 400 {
		t.Errorf("delete invalid name: %d", rr.Code)
	}
	// A stored row with an empty ciphertext is corrupt, not a value.
	seedSecrets(t, h, "a.empty")
	if _, err := s.db.Exec(`UPDATE secrets SET ciphertext = x'' WHERE name = 'a.empty'`); err != nil {
		t.Fatal(err)
	}
	if rr := do(h, authReq("GET", "/v1/secrets/a.empty", nil)); rr.Code != 500 {
		t.Errorf("empty ciphertext: %d", rr.Code)
	}
}

func TestAuthenticate_DefensiveChecks(t *testing.T) {
	t.Run("hash mismatch after lookup", func(t *testing.T) {
		s, _ := newFaultServer(t)
		injectNullColumn(t, "FROM tokens WHERE token_hash", 2)
		if rr := do(s.routes(), authReq("GET", "/v1/secrets", nil)); rr.Code != 401 {
			t.Errorf("got %d, want 401", rr.Code)
		}
	})
	t.Run("unknown role", func(t *testing.T) {
		s, h := newTestServer(t)
		if _, err := s.db.Exec(`PRAGMA ignore_check_constraints = ON`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`UPDATE tokens SET role = 'root' WHERE name = 'test-admin'`); err != nil {
			t.Fatal(err)
		}
		if rr := do(h, authReq("GET", "/v1/secrets", nil)); rr.Code != 401 {
			t.Errorf("got %d, want 401", rr.Code)
		}
	})
	t.Run("last_used update failure is not fatal", func(t *testing.T) {
		logs := captureLogs(t)
		s, _ := newFaultServer(t)
		injectFault(t, "exec", "SET last_used_at", 0)
		if rr := do(s.routes(), authReq("GET", "/v1/secrets", nil)); rr.Code != 200 {
			t.Errorf("got %d, want 200", rr.Code)
		}
		if !strings.Contains(logs.String(), "update last_used_at failed") {
			t.Error("expected a warning")
		}
	})
	t.Run("canCreate", func(t *testing.T) {
		admin := &principal{role: roleAdmin}
		agent := &principal{role: roleAgent, writePrefixes: []string{"a."}}
		if !admin.canCreate("anything") || agent.canCreate("a.bad!") || !agent.canCreate("a.ok") {
			t.Error("canCreate returned the wrong answer")
		}
	})
}

func TestAuditPipeline_EdgeCases(t *testing.T) {
	s, h := newTestServer(t)
	// commitWithAudit refuses to commit without an audit entry.
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.commitWithAudit(context.Background(), tx); err == nil {
		t.Error("commit without an audit entry must fail")
	}
	_ = tx.Rollback()

	// A handler that writes nothing, or a body without WriteHeader, is 200.
	for name, hf := range map[string]http.HandlerFunc{
		"silent":    func(http.ResponseWriter, *http.Request) {},
		"body only": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) },
	} {
		rr := do(s.secretsRoute(actionOther, hf), authReq("GET", "/v1/x", nil))
		if rr.Code != 200 {
			t.Errorf("%s: %d", name, rr.Code)
		}
	}
	// whoami is not a data read, so it is still answered when auditing fails.
	if _, err := s.db.Exec(`DROP TABLE audit_log`); err != nil {
		t.Fatal(err)
	}
	if code, _ := adminJSON(t, h, testToken, "GET", "/v1/admin/me", nil); code != 200 {
		t.Errorf("whoami with audit down: %d", code)
	}
}

func TestAuditCommitFault(t *testing.T) {
	s, _ := newFaultServer(t)
	injectFault(t, "commit", "", 0)
	if rr := do(s.routes(), authReq("PUT", "/v1/secrets/a.b", []byte(`{"value":"v"}`))); rr.Code != 500 {
		t.Errorf("commit failure: %d", rr.Code)
	}
}

func TestAdminAPI_Faults(t *testing.T) {
	create := map[string]any{"name": "n1", "role": "agent", "prefixes": []string{"a."}, "write_prefixes": []string{"w."}}
	cases := []struct {
		name, op, sql, method, path string
		body                        any
	}{
		{"list query", "query", "ORDER BY name", "GET", "/v1/admin/tokens", nil},
		{"create begin", "begin", "", "POST", "/v1/admin/tokens", create},
		{"create exists check", "query", "COUNT(*) FROM tokens WHERE name", "POST", "/v1/admin/tokens", create},
		{"create overlap check", "query", "write_prefixes FROM tokens", "POST", "/v1/admin/tokens", create},
		{"create insert", "exec", "INSERT INTO tokens", "POST", "/v1/admin/tokens", create},
		{"update begin", "begin", "", "PATCH", "/v1/admin/tokens/ag", map[string]any{"prefixes": []string{"b."}}},
		{"update lookup", "query", "revoked_at FROM tokens WHERE name", "PATCH", "/v1/admin/tokens/ag", map[string]any{"prefixes": []string{"b."}}},
		{"update overlap check", "query", "write_prefixes FROM tokens", "PATCH", "/v1/admin/tokens/ag", map[string]any{"write_prefixes": []string{"b."}}},
		{"update exec", "exec", "UPDATE tokens SET prefixes", "PATCH", "/v1/admin/tokens/ag", map[string]any{"prefixes": []string{"b."}}},
		{"update commit", "commit", "", "PATCH", "/v1/admin/tokens/ag", map[string]any{"prefixes": []string{"b."}}},
		{"revoke begin", "begin", "", "DELETE", "/v1/admin/tokens/ag", nil},
		{"revoke exec", "exec", "SET revoked_at", "DELETE", "/v1/admin/tokens/ag", nil},
		{"revoke exists check", "query", "COUNT(*) FROM tokens WHERE name", "DELETE", "/v1/admin/tokens/nobody", nil},
		{"audit query", "query", "FROM audit_log", "GET", "/v1/admin/audit", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			captureLogs(t)
			s, _ := newFaultServer(t)
			mustInsertToken(t, s, tokenSpec{name: "ag", role: roleAgent, prefixes: []string{"a."}}, agentToken)
			injectFault(t, c.op, c.sql, 0)
			if code, out := adminJSON(t, s.routes(), testToken, c.method, c.path, c.body); code != 500 {
				t.Errorf("got %d %v, want 500", code, out)
			}
		})
	}
}

func TestAdminAPI_InputEdges(t *testing.T) {
	_, h := newTestServer(t)
	if code, _ := adminJSON(t, h, testToken, "GET", "/v1/admin/nope", nil); code != 404 {
		t.Errorf("unknown admin path: %d", code)
	}
	if rr := do(h, bodyErrReq("POST", "/v1/admin/tokens")); rr.Code != 400 {
		t.Errorf("unreadable body: %d", rr.Code)
	}
	big := append([]byte(`{"name":"`), bytes.Repeat([]byte("x"), maxAdminBody)...)
	if rr := do(h, reqWithToken("POST", "/v1/admin/tokens", testToken, big)); rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: %d", rr.Code)
	}
	if rr := do(h, reqWithToken("POST", "/v1/admin/tokens", testToken, []byte(`{"name":"a","role":"admin","expires":"1d"}{}`))); rr.Code != 400 {
		t.Errorf("trailing data: %d", rr.Code)
	}
	if code, _ := adminJSON(t, h, testToken, "PATCH", "/v1/admin/tokens/bad%20name", map[string]any{"prefixes": []string{"a."}}); code != 400 {
		t.Errorf("update bad name: %d", code)
	}
	if rr := do(h, reqWithToken("PATCH", "/v1/admin/tokens/test-admin", testToken, []byte(`not json`))); rr.Code != 400 {
		t.Errorf("update bad json: %d", rr.Code)
	}
	since := time.Now().Add(-time.Hour).Unix()
	if code, _ := adminJSON(t, h, testToken, "GET", "/v1/admin/audit?since="+itoa(since), nil); code != 200 {
		t.Errorf("numeric since: %d", code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestTokens_Faults(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	withDB := func(t *testing.T) *sql.DB {
		_, db := newFaultServer(t)
		mustInsertToken(t, &server{db: db}, tokenSpec{name: "ag", role: roleAgent, prefixes: []string{"a."}, writePrefixes: []string{"w."}}, agentToken)
		return db
	}
	t.Run("create validation", func(t *testing.T) {
		if _, _, err := createToken(ctx, withDB(t), tokenSpec{name: "bad name", role: roleAdmin}, now); err == nil {
			t.Error("want error")
		}
	})
	t.Run("list scan", func(t *testing.T) {
		db := withDB(t)
		injectNullColumn(t, "ORDER BY name", 0)
		if _, err := listTokens(ctx, db, now); err == nil {
			t.Error("want error")
		}
	})
	t.Run("unreadable grant is shown, not hidden", func(t *testing.T) {
		db := withDB(t)
		if _, err := db.Exec(`UPDATE tokens SET prefixes = 'nope' WHERE name = 'ag'`); err != nil {
			t.Fatal(err)
		}
		list, err := listTokens(ctx, db, now)
		if err != nil || list[0].Prefixes[0] != "<unreadable>" {
			t.Errorf("list = %+v err %v", list, err)
		}
	})
	t.Run("update revoked", func(t *testing.T) {
		db := withDB(t)
		if _, err := revokeToken(ctx, db, "ag", now); err != nil {
			t.Fatal(err)
		}
		p := []string{"b."}
		if _, _, _, err := updateTokenGrants(ctx, db, "ag", grantUpdate{prefixes: &p}); !errors.Is(err, errTokenRevoked) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("overlap scan and bad json", func(t *testing.T) {
		db := withDB(t)
		mustInsertToken(t, &server{db: db}, tokenSpec{name: "other", role: roleAgent, writePrefixes: []string{"x."}}, otherToken)
		if _, err := db.Exec(`UPDATE tokens SET write_prefixes = 'nope' WHERE name = 'other'`); err != nil {
			t.Fatal(err)
		}
		if w, err := writeNamespaceOverlaps(ctx, db, "ag", []string{"w."}); err != nil || len(w) != 0 {
			t.Errorf("unreadable neighbour grant: %v %v", w, err)
		}
		injectNullColumn(t, "write_prefixes FROM tokens", 0)
		if _, err := writeNamespaceOverlaps(ctx, db, "ag", []string{"w."}); err == nil {
			t.Error("want scan error")
		}
	})
}

func TestStore_Faults(t *testing.T) {
	open := func(t *testing.T) *sql.DB {
		db, err := sql.Open(faultDriverName, ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() { db.Close() })
		return db
	}
	for name, f := range map[string][2]string{
		"schema_version table": {"exec", "CREATE TABLE IF NOT EXISTS schema_version"},
		"begin":                {"begin", ""},
		"read version":         {"query", "MAX(version)"},
		"apply migration":      {"exec", "CREATE TABLE tokens"},
		"record migration":     {"exec", "INSERT INTO schema_version"},
		"commit":               {"commit", ""},
	} {
		t.Run(name, func(t *testing.T) {
			db := open(t)
			injectFault(t, f[0], f[1], 0)
			if err := migrate(db); err == nil {
				t.Error("want error")
			}
		})
	}
	t.Run("openDB unknown driver", func(t *testing.T) {
		prev := sqliteDriver
		sqliteDriver = "no-such-driver"
		defer func() { sqliteDriver = prev }()
		if _, err := openDB(filepath.Join(t.TempDir(), "x.db")); err == nil {
			t.Error("want error")
		}
	})
	t.Run("openDB not a database", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "junk.db")
		if err := os.WriteFile(path, bytes.Repeat([]byte("junk"), 1024), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := openDB(path); err == nil {
			t.Error("want error")
		}
	})
	t.Run("checkDBPerms", func(t *testing.T) {
		logs := captureLogs(t)
		checkDBPerms(":memory:")
		dir := filepath.Join(t.TempDir(), "open")
		if err := os.Mkdir(dir, 0o755); err != nil { // #nosec G301 -- deliberately too open
			t.Fatal(err)
		}
		path := filepath.Join(dir, "h.db")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		checkDBPerms(path)
		if !strings.Contains(logs.String(), "wider than 0700") {
			t.Errorf("expected a directory warning: %s", logs.String())
		}
	})
}
