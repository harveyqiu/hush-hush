package main

import (
	"net/http"
	"testing"
)

func secretExists(t *testing.T, s *server, name string) bool {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM secrets WHERE name = ?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// A write and its audit row commit together: if the audit row can't be
// written, the write is rolled back and the caller is told it failed.
func TestAudit_WritesAreAtomicWithAudit(t *testing.T) {
	s, h := newTestServer(t)
	seedSecrets(t, h, "keep.me")
	if _, err := s.db.Exec(`DROP TABLE audit_log`); err != nil {
		t.Fatal(err)
	}

	rr := do(h, authReq("PUT", "/v1/secrets/new.one", []byte(`{"value":"v"}`)))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("PUT with audit down: got %d, want 500", rr.Code)
	}
	if secretExists(t, s, "new.one") {
		t.Error("PUT was committed without an audit row")
	}

	rr = do(h, authReq("DELETE", "/v1/secrets/keep.me", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("DELETE with audit down: got %d, want 500", rr.Code)
	}
	if !secretExists(t, s, "keep.me") {
		t.Error("DELETE was committed without an audit row")
	}
}

// The successful write path records exactly one "allowed" row, inside the
// transaction, and secretsRoute doesn't add a second.
func TestAudit_WriteRecordedOnce(t *testing.T) {
	s, h := newTestServer(t)
	for _, req := range []*http.Request{
		authReq("PUT", "/v1/secrets/a.b", []byte(`{"value":"v"}`)),
		authReq("DELETE", "/v1/secrets/a.b", nil),
	} {
		before := auditCount(t, s.db)
		rr := do(h, req)
		if rr.Code >= 300 {
			t.Fatalf("%s: %d", req.Method, rr.Code)
		}
		if n := auditCount(t, s.db) - before; n != 1 {
			t.Errorf("%s wrote %d audit rows, want 1", req.Method, n)
		}
		if row := lastAuditRow(t, s.db); row.result != resultAllowed || row.secretName != "a.b" || row.tokenName != "test-admin" {
			t.Errorf("%s audit row = %+v", req.Method, row)
		}
	}
}

// Requests under /v1/secrets that match no route are still authenticated
// and audited, instead of being answered by the mux with no record.
func TestAudit_UnmatchedRequestsAreAudited(t *testing.T) {
	s, h := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "agent-llm", role: roleAgent, prefixes: []string{"llm."}}, agentToken)

	tests := []struct {
		name      string
		req       *http.Request
		wantCode  int
		wantAllow string
		wantToken string
		wantRes   string
	}{
		{"POST collection", authReq("POST", "/v1/secrets", []byte(`{}`)), http.StatusMethodNotAllowed, "GET", "test-admin", resultBadRequest},
		{"PATCH item", authReq("PATCH", "/v1/secrets/llm.x", []byte(`{}`)), http.StatusMethodNotAllowed, "GET, PUT, DELETE", "test-admin", resultBadRequest},
		{"nested path", authReq("GET", "/v1/secrets/a/b", nil), http.StatusNotFound, "", "test-admin", resultNotFound},
		{"trailing slash", authReq("GET", "/v1/secrets/", nil), http.StatusNotFound, "", "test-admin", resultNotFound},
		{"agent POST", reqWithToken("POST", "/v1/secrets/llm.x", agentToken, nil), http.StatusMethodNotAllowed, "GET, PUT, DELETE", "agent-llm", resultBadRequest},
		{"no token", reqWithToken("POST", "/v1/secrets", "", nil), http.StatusUnauthorized, "", "", resultUnauthenticated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantToken == "" {
				tt.req.Header.Del("Authorization")
			}
			before := auditCount(t, s.db)
			rr := do(h, tt.req)
			if rr.Code != tt.wantCode {
				t.Fatalf("got %d, want %d (%s)", rr.Code, tt.wantCode, rr.Body.String())
			}
			if got := rr.Header().Get("Allow"); got != tt.wantAllow {
				t.Errorf("Allow = %q, want %q", got, tt.wantAllow)
			}
			if rr.Header().Get("Cache-Control") != "no-store" {
				t.Error("missing Cache-Control: no-store")
			}
			if n := auditCount(t, s.db) - before; n != 1 {
				t.Fatalf("%d audit rows, want 1", n)
			}
			row := lastAuditRow(t, s.db)
			if row.action != actionOther || row.tokenName != tt.wantToken || row.result != tt.wantRes {
				t.Errorf("audit row = %+v, want action=other token=%q result=%s", row, tt.wantToken, tt.wantRes)
			}
		})
	}

	// And the new action is queryable from the CLI.
	if r := runCLI(t, "", "audit", "--db", newTestDBFile(t), "--action", actionOther); r.code != 0 {
		t.Errorf("--action other rejected: %s", r.stderr)
	}
}
