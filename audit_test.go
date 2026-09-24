package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

type auditRow struct {
	ts                                                         int64
	tokenName, action, secretName, result, requestID, remoteIP string
}

func lastAuditRow(t *testing.T, db *sql.DB) auditRow {
	t.Helper()
	var r auditRow
	err := db.QueryRow(`SELECT ts, token_name, action, secret_name, result, request_id, remote_addr
		FROM audit_log ORDER BY id DESC LIMIT 1`).
		Scan(&r.ts, &r.tokenName, &r.action, &r.secretName, &r.result, &r.requestID, &r.remoteIP)
	if err != nil {
		t.Fatalf("read last audit row: %v", err)
	}
	return r
}

func auditCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// Every /v1/secrets request, allowed or not, must leave exactly one row
// describing who did what to which secret and how it ended.
func TestAudit_OneRowPerRequest(t *testing.T) {
	s, _ := newTestServer(t)
	h := withRequestID(s.routes())
	mustInsertToken(t, s, tokenSpec{name: "agent-llm", role: roleAgent, prefixes: []string{"llm."}}, agentToken)

	cases := []struct {
		desc                   string
		method, path, token    string
		body                   []byte
		wantCode               int
		wantToken, wantAction  string
		wantSecret, wantResult string
	}{
		{"admin put", "PUT", "/v1/secrets/llm.key", testToken, []byte(`{"value":"v"}`), 200, "test-admin", actionPut, "llm.key", resultAllowed},
		{"agent get in scope", "GET", "/v1/secrets/llm.key", agentToken, nil, 200, "agent-llm", actionGet, "llm.key", resultAllowed},
		{"agent get out of scope", "GET", "/v1/secrets/github.token", agentToken, nil, 403, "agent-llm", actionGet, "github.token", resultDenied},
		{"agent put", "PUT", "/v1/secrets/llm.key", agentToken, []byte(`{"value":"x"}`), 403, "agent-llm", actionPut, "llm.key", resultDenied},
		{"agent delete", "DELETE", "/v1/secrets/llm.key", agentToken, nil, 403, "agent-llm", actionDelete, "llm.key", resultDenied},
		{"missing in scope", "GET", "/v1/secrets/llm.missing", agentToken, nil, 404, "agent-llm", actionGet, "llm.missing", resultNotFound},
		{"no token", "GET", "/v1/secrets/llm.key", "", nil, 401, "", actionGet, "llm.key", resultUnauthenticated},
		{"wrong token", "GET", "/v1/secrets/llm.key", "hush_never-issued", nil, 401, "", actionGet, "llm.key", resultUnauthenticated},
		// Invalid names are recorded as empty, never as raw client bytes.
		{"bad name", "GET", "/v1/secrets/bad$name", testToken, nil, 400, "test-admin", actionGet, "", resultBadRequest},
		{"agent list", "GET", "/v1/secrets", agentToken, nil, 200, "agent-llm", actionList, "", resultAllowed},
		{"admin delete", "DELETE", "/v1/secrets/llm.key", testToken, nil, 204, "test-admin", actionDelete, "llm.key", resultAllowed},
	}
	for i, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			before := auditCount(t, s.db)
			req := authReq(c.method, c.path, c.body)
			req.Header.Del("Authorization")
			if c.token != "" {
				req.Header.Set("Authorization", "Bearer "+c.token)
			}
			reqID := fmt.Sprintf("audit-req-%d", i)
			req.Header.Set("X-Request-ID", reqID)

			if rr := do(h, req); rr.Code != c.wantCode {
				t.Fatalf("status %d, want %d (%s)", rr.Code, c.wantCode, rr.Body.String())
			}
			if n := auditCount(t, s.db) - before; n != 1 {
				t.Fatalf("request wrote %d audit rows, want exactly 1", n)
			}
			got := lastAuditRow(t, s.db)
			if got.remoteIP == "" || got.ts == 0 {
				t.Errorf("remote_addr %q / ts %d not recorded", got.remoteIP, got.ts)
			}
			got.ts, got.remoteIP = 0, ""
			want := auditRow{tokenName: c.wantToken, action: c.wantAction, secretName: c.wantSecret,
				result: c.wantResult, requestID: reqID}
			if got != want {
				t.Errorf("audit row = %+v, want %+v", got, want)
			}
		})
	}

	// Health checks are not secret access and are not audited.
	before := auditCount(t, s.db)
	do(h, authReq("GET", "/healthz", nil))
	if n := auditCount(t, s.db); n != before {
		t.Errorf("/healthz wrote %d audit rows", n-before)
	}
}

// If the audit row can't be written, a read must not hand out data.
func TestAudit_FailClosedOnReads(t *testing.T) {
	s, h := newTestServer(t)
	const value = "fail-closed-value"
	if rr := do(h, authReq("PUT", "/v1/secrets/fc.key", []byte(`{"value":"`+value+`"}`))); rr.Code != http.StatusOK {
		t.Fatalf("seed: %d", rr.Code)
	}
	logs := captureLogs(t)
	if _, err := s.db.Exec(`DROP TABLE audit_log`); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/secrets/fc.key", "/v1/secrets"} {
		rr := do(h, authReq("GET", path, nil))
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("GET %s: got %d, want 500", path, rr.Code)
		}
		if strings.Contains(rr.Body.String(), value) || strings.Contains(rr.Body.String(), "fc.key") {
			t.Errorf("GET %s: body leaked data despite audit failure: %s", path, rr.Body.String())
		}
	}
	if !strings.Contains(logs.String(), "audit write failed") {
		t.Errorf("audit failure not logged: %s", logs.String())
	}
}

func TestAudit_MigrationCreatesIndexes(t *testing.T) {
	s, _ := newTestServer(t)
	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'audit_log'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		got[n] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"audit_log_ts", "audit_log_token", "audit_log_secret"} {
		if !got[want] {
			t.Errorf("missing index %s (have %v)", want, got)
		}
	}
}

// ---- hush-hush audit CLI ----

func insertAuditRow(t *testing.T, db *sql.DB, ts int64, token, action, secret, result, reqID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO audit_log (ts, token_name, action, secret_name, result, request_id, remote_addr)
		VALUES (?, ?, ?, ?, ?, ?, '192.0.2.1')`, ts, token, action, secret, result, reqID); err != nil {
		t.Fatalf("insert audit row: %v", err)
	}
}

// auditLines runs the audit CLI and returns its data rows split into
// columns, checking the header and column count on the way.
func auditLines(t *testing.T, path string, args ...string) [][]string {
	t.Helper()
	r := runCLI(t, "", append([]string{"audit", "--db", path}, args...)...)
	if r.code != 0 {
		t.Fatalf("audit %v: code %d stderr %s", args, r.code, r.stderr)
	}
	lines := strings.Split(strings.TrimRight(r.stdout, "\n"), "\n")
	if got := strings.Join(strings.Fields(lines[0]), " "); got != "TIME TOKEN ACTION SECRET RESULT REMOTE REQUEST_ID" {
		t.Fatalf("header = %q", lines[0])
	}
	var out [][]string
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) != 7 {
			t.Fatalf("row %q has %d columns, want 7", l, len(f))
		}
		out = append(out, f)
	}
	return out
}

func requestIDs(rows [][]string) string {
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r[6]
	}
	return strings.Join(ids, ",")
}

func TestCLI_Audit_Filters(t *testing.T) {
	path := newTestDBFile(t)
	s, _ := serverOn(t, path)
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).Unix()
	insertAuditRow(t, s.db, base, "agent-a", actionGet, "llm.a", resultAllowed, "r1")
	insertAuditRow(t, s.db, base+60, "agent-a", actionGet, "github.x", resultDenied, "r2")
	insertAuditRow(t, s.db, base+120, "agent-b", actionList, "", resultAllowed, "r3")
	insertAuditRow(t, s.db, base+180, "", actionGet, "llm.a", resultUnauthenticated, "r4")
	insertAuditRow(t, s.db, base+240, "admin", actionPut, "llm.a", resultAllowed, "r5")
	// Same second as r5 but inserted later: id breaks the tie.
	insertAuditRow(t, s.db, base+240, "admin", actionDelete, "llm.b", resultAllowed, "r6")

	rfc := func(ts int64) string { return time.Unix(ts, 0).UTC().Format(time.RFC3339) }
	tests := []struct {
		args []string
		want string
	}{
		{nil, "r6,r5,r4,r3,r2,r1"},
		{[]string{"--token", "agent-a"}, "r2,r1"},
		{[]string{"--secret", "llm.a"}, "r5,r4,r1"},
		{[]string{"--action", "get"}, "r4,r2,r1"},
		{[]string{"--result", "denied"}, "r2"},
		{[]string{"--result", "unauthenticated"}, "r4"},
		{[]string{"--since", rfc(base + 120)}, "r6,r5,r4,r3"},
		{[]string{"--until", rfc(base + 120)}, "r2,r1"}, // until is exclusive
		{[]string{"--since", rfc(base + 60), "--until", rfc(base + 240)}, "r4,r3,r2"},
		{[]string{"--limit", "2"}, "r6,r5"},
		{[]string{"--token", "agent-a", "--result", "allowed"}, "r1"},
		{[]string{"--token", "nobody"}, ""},
	}
	for _, tt := range tests {
		if got := requestIDs(auditLines(t, path, tt.args...)); got != tt.want {
			t.Errorf("audit %v = %s, want %s", tt.args, got, tt.want)
		}
	}

	rows := auditLines(t, path)
	byID := map[string][]string{}
	for _, r := range rows {
		byID[r[6]] = r
	}
	if got := strings.Join(byID["r1"], " "); got != "2026-09-01T00:00:00Z agent-a get llm.a allowed 192.0.2.1 r1" {
		t.Errorf("r1 rendered as %q", got)
	}
	if byID["r3"][3] != "-" {
		t.Errorf("empty secret_name should print as -, got %q", byID["r3"][3])
	}
	if byID["r4"][1] != "-" {
		t.Errorf("empty token_name should print as -, got %q", byID["r4"][1])
	}
}

func TestCLI_Audit_RelativeTimes(t *testing.T) {
	path := newTestDBFile(t)
	s, _ := serverOn(t, path)
	now := time.Now().Unix()
	insertAuditRow(t, s.db, now-3*24*3600, "a", actionGet, "x.old", resultAllowed, "old")
	insertAuditRow(t, s.db, now-2*3600, "a", actionGet, "x.new", resultAllowed, "recent")

	if got := requestIDs(auditLines(t, path, "--since", "24h")); got != "recent" {
		t.Errorf("--since 24h = %s, want recent", got)
	}
	if got := requestIDs(auditLines(t, path, "--since", "7d")); got != "recent,old" {
		t.Errorf("--since 7d = %s, want recent,old", got)
	}
	if got := requestIDs(auditLines(t, path, "--until", "2d")); got != "old" {
		t.Errorf("--until 2d = %s, want old", got)
	}
}

func TestCLI_Audit_DefaultLimit(t *testing.T) {
	path := newTestDBFile(t)
	s, _ := serverOn(t, path)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 150; i++ {
		if _, err := tx.Exec(`INSERT INTO audit_log (ts, token_name, action, secret_name, result, request_id, remote_addr)
			VALUES (?, 'a', 'get', 'x.k', 'allowed', ?, '192.0.2.1')`, 1_700_000_000+i, fmt.Sprintf("n%03d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	rows := auditLines(t, path)
	if len(rows) != auditDefaultLimit {
		t.Fatalf("default output has %d rows, want %d", len(rows), auditDefaultLimit)
	}
	if rows[0][6] != "n149" || rows[99][6] != "n050" {
		t.Errorf("default window = %s..%s, want newest n149..n050", rows[0][6], rows[99][6])
	}
	if rows := auditLines(t, path, "--limit", "1000"); len(rows) != 150 {
		t.Errorf("--limit 1000 printed %d rows, want all 150", len(rows))
	}
}

func TestCLI_Audit_Errors(t *testing.T) {
	path := newTestDBFile(t)
	usage := map[string][]string{
		"zero limit":        {"--limit", "0"},
		"negative limit":    {"--limit", "-5"},
		"huge limit":        {"--limit", "10001"},
		"non-numeric limit": {"--limit", "many"},
		"unknown action":    {"--action", "read"},
		"unknown result":    {"--result", "ok"},
		"bad since":         {"--since", "yesterday"},
		"bad until":         {"--until", "2026-13-01T00:00:00Z"},
		"zero duration":     {"--since", "0d"},
		"since after until": {"--since", "1h", "--until", "2d"},
		"unknown flag":      {"--verbose"},
		"stray argument":    {"extra"},
	}
	for name, args := range usage {
		t.Run(name, func(t *testing.T) {
			r := runCLI(t, "", append([]string{"audit", "--db", path}, args...)...)
			if r.code != 2 {
				t.Errorf("code %d, want 2 (stderr %s)", r.code, r.stderr)
			}
			if r.stdout != "" {
				t.Errorf("stdout should be empty on error, got %q", r.stdout)
			}
		})
	}
	if r := runCLI(t, "", "audit", "--db", path+".missing"); r.code != 1 {
		t.Errorf("missing database: code %d, want 1", r.code)
	}
	if r := runCLI(t, "", "help"); !strings.Contains(r.stdout, "hush-hush audit") {
		t.Errorf("usage does not mention audit:\n%s", r.stdout)
	}
}
