package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func adminJSON(t *testing.T, h http.Handler, token, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	req := reqWithToken(method, path, token, raw)
	if body == nil {
		req.Header.Del("Content-Type")
	}
	rr := do(h, req)
	out := map[string]any{}
	if rr.Body.Len() > 0 {
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
	}
	return rr.Code, out
}

var plainTokenRe = regexp.MustCompile(`^hush_[0-9a-f]{64}$`)

func TestAdminAPI_OnlyAdmins(t *testing.T) {
	s, h := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "agent-x", role: roleAgent, prefixes: []string{"llm."}}, agentToken)
	routes := []struct {
		method, path string
		body         any
	}{
		{"GET", "/v1/admin/tokens", nil},
		{"POST", "/v1/admin/tokens", map[string]any{"name": "evil", "role": "admin"}},
		{"PATCH", "/v1/admin/tokens/agent-x", map[string]any{"prefixes": []string{"*"}, "confirm_all": true}},
		{"DELETE", "/v1/admin/tokens/test-admin", nil},
		{"GET", "/v1/admin/audit", nil},
		{"GET", "/v1/admin/whatever", nil},
	}
	for _, r := range routes {
		before := auditCount(t, s.db)
		if code, _ := adminJSON(t, h, agentToken, r.method, r.path, r.body); code != http.StatusForbidden {
			t.Errorf("agent %s %s: %d, want 403", r.method, r.path, code)
		}
		if code, _ := adminJSON(t, h, "hush_nope", r.method, r.path, r.body); code != http.StatusUnauthorized {
			t.Errorf("bad token %s %s: %d, want 401", r.method, r.path, code)
		}
		if n := auditCount(t, s.db) - before; n != 2 {
			t.Errorf("%s %s: %d audit rows, want 2", r.method, r.path, n)
		}
	}
	// Nothing changed.
	if exists, _ := tokenExists(t.Context(), s.db, "evil"); exists {
		t.Error("agent created a token")
	}
}

func TestAdminAPI_CreateUseRevoke(t *testing.T) {
	logs := captureLogs(t)
	s, h := newTestServer(t)
	seedSecrets(t, h, "llm.openai", "github.pat")

	code, out := adminJSON(t, h, testToken, "POST", "/v1/admin/tokens", map[string]any{
		"name": "crawler", "role": "agent", "prefixes": []string{"llm."}, "write_prefixes": []string{"crawler."}, "expires": "30d",
	})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	plain, _ := out["token"].(string)
	if !plainTokenRe.MatchString(plain) {
		t.Fatalf("token %q has the wrong format", plain)
	}
	row := lastAuditRow(t, s.db)
	if row.action != actionTokenCreate || row.result != resultAllowed || row.tokenName != "test-admin" || row.secretName != "crawler" {
		t.Errorf("create audit row = %+v", row)
	}

	// The new token works with exactly its grant.
	if rr := do(h, reqWithToken("GET", "/v1/secrets/llm.openai", plain, nil)); rr.Code != http.StatusOK {
		t.Errorf("new token read: %d", rr.Code)
	}
	if rr := do(h, reqWithToken("GET", "/v1/secrets/github.pat", plain, nil)); rr.Code != http.StatusForbidden {
		t.Errorf("new token out of scope: %d", rr.Code)
	}

	// Listing never exposes a hash or the plaintext.
	rr := do(h, reqWithToken("GET", "/v1/admin/tokens", testToken, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d", rr.Code)
	}
	body := rr.Body.String()
	h256 := hashToken(plain)
	if strings.Contains(body, plain[len(tokenPrefix):]) || strings.Contains(body, "hash") || strings.Contains(body, string(h256[:4])) {
		t.Errorf("token list leaks secret material: %s", body)
	}
	var list struct{ Tokens []tokenInfo }
	decodeJSON(t, rr.Body.Bytes(), &list)
	var found *tokenInfo
	for i := range list.Tokens {
		if list.Tokens[i].Name == "crawler" {
			found = &list.Tokens[i]
		}
	}
	if found == nil || found.Status != "active" || found.ExpiresAt == nil || strings.Join(found.WritePrefixes, ",") != "crawler." {
		t.Errorf("crawler in list = %+v", found)
	}

	// Update, then revoke.
	code, out = adminJSON(t, h, testToken, "PATCH", "/v1/admin/tokens/crawler", map[string]any{"prefixes": []string{"github."}})
	if code != http.StatusOK {
		t.Fatalf("update: %d %v", code, out)
	}
	if rr := do(h, reqWithToken("GET", "/v1/secrets/github.pat", plain, nil)); rr.Code != http.StatusOK {
		t.Errorf("after update: %d, want 200", rr.Code)
	}
	if code, _ := adminJSON(t, h, testToken, "DELETE", "/v1/admin/tokens/crawler", nil); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	if rr := do(h, reqWithToken("GET", "/v1/secrets/github.pat", plain, nil)); rr.Code != http.StatusUnauthorized {
		t.Errorf("after revoke: %d, want 401", rr.Code)
	}
	if row := lastAuditRow(t, s.db); row.action != actionGet || row.result != resultUnauthenticated {
		t.Errorf("last audit row = %+v", row)
	}

	// The plaintext never reached the logs or the audit table.
	if strings.Contains(logs.String(), plain) {
		t.Error("new token plaintext found in logs")
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE token_name LIKE ? OR secret_name LIKE ? OR request_id LIKE ?`,
		"%"+plain+"%", "%"+plain+"%", "%"+plain+"%").Scan(&n); err != nil || n != 0 {
		t.Errorf("plaintext in audit_log (n=%d err=%v)", n, err)
	}
}

func TestAdminAPI_CreateValidation(t *testing.T) {
	_, h := newTestServer(t)
	cases := []struct {
		name string
		body any
		want int
	}{
		{"bad prefix", map[string]any{"name": "a1", "role": "agent", "prefixes": []string{"llm"}}, http.StatusBadRequest},
		{"agent without grants", map[string]any{"name": "a2", "role": "agent"}, http.StatusBadRequest},
		{"admin with prefix", map[string]any{"name": "a3", "role": "admin", "prefixes": []string{"llm."}}, http.StatusBadRequest},
		{"bad name", map[string]any{"name": "has space", "role": "admin"}, http.StatusBadRequest},
		{"colon not allowed in names", map[string]any{"name": "env:AUTH_TOKEN", "role": "admin"}, http.StatusBadRequest},
		{"write wildcard", map[string]any{"name": "a4", "role": "agent", "write_prefixes": []string{"*"}}, http.StatusBadRequest},
		{"wildcard without confirm", map[string]any{"name": "a5", "role": "agent", "prefixes": []string{"*"}}, http.StatusBadRequest},
		{"bad expires", map[string]any{"name": "a6", "role": "admin", "expires": "soon"}, http.StatusBadRequest},
		{"unknown field", map[string]any{"name": "a7", "role": "admin", "is_root": true}, http.StatusBadRequest},
		{"duplicate", map[string]any{"name": "test-admin", "role": "admin", "expires": "30d"}, http.StatusConflict},
		{"wildcard confirmed", map[string]any{"name": "a8", "role": "agent", "prefixes": []string{"*"}, "confirm_all": true}, http.StatusCreated},
	}
	for _, c := range cases {
		if code, out := adminJSON(t, h, testToken, "POST", "/v1/admin/tokens", c.body); code != c.want {
			t.Errorf("%s: %d %v, want %d", c.name, code, out, c.want)
		} else if code != http.StatusCreated && out["token"] != nil {
			t.Errorf("%s: a token was returned on failure", c.name)
		}
	}
	// Content type is enforced like PUT /v1/secrets.
	req := reqWithToken("POST", "/v1/admin/tokens", testToken, []byte(`{"name":"x","role":"admin"}`))
	req.Header.Set("Content-Type", "text/plain")
	if rr := do(h, req); rr.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d, want 415", rr.Code)
	}
}

func TestAdminAPI_UpdateAndRevokeErrors(t *testing.T) {
	s, h := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "ag", role: roleAgent, prefixes: []string{"llm."}}, agentToken)
	mustInsertToken(t, s, tokenSpec{name: "adm2", role: roleAdmin}, otherToken)
	cases := []struct {
		name, method, path string
		body               any
		want               int
	}{
		{"update unknown", "PATCH", "/v1/admin/tokens/nobody", map[string]any{"prefixes": []string{"a."}}, http.StatusNotFound},
		{"update admin", "PATCH", "/v1/admin/tokens/adm2", map[string]any{"prefixes": []string{"a."}}, http.StatusConflict},
		{"update bad prefix", "PATCH", "/v1/admin/tokens/ag", map[string]any{"prefixes": []string{"bad"}}, http.StatusBadRequest},
		{"update clears everything", "PATCH", "/v1/admin/tokens/ag", map[string]any{"prefixes": []string{}}, http.StatusBadRequest},
		{"update nothing", "PATCH", "/v1/admin/tokens/ag", map[string]any{}, http.StatusBadRequest},
		{"update wildcard unconfirmed", "PATCH", "/v1/admin/tokens/ag", map[string]any{"prefixes": []string{"*"}}, http.StatusBadRequest},
		{"revoke unknown", "DELETE", "/v1/admin/tokens/nobody", nil, http.StatusNotFound},
		{"revoke self", "DELETE", "/v1/admin/tokens/test-admin", nil, http.StatusConflict},
		{"revoke bad name", "DELETE", "/v1/admin/tokens/bad%20name", nil, http.StatusBadRequest},
	}
	for _, c := range cases {
		if code, out := adminJSON(t, h, testToken, c.method, c.path, c.body); code != c.want {
			t.Errorf("%s: %d %v, want %d", c.name, code, out, c.want)
		}
	}
	// Still usable after all the refused changes.
	if rr := do(h, reqWithToken("GET", "/v1/secrets", agentToken, nil)); rr.Code != http.StatusOK {
		t.Errorf("agent after refused updates: %d", rr.Code)
	}
	if rr := do(h, authReq("GET", "/v1/secrets", nil)); rr.Code != http.StatusOK {
		t.Errorf("self-revoke was not refused: %d", rr.Code)
	}
	// Revoking twice reports it.
	if code, out := adminJSON(t, h, testToken, "DELETE", "/v1/admin/tokens/ag", nil); code != http.StatusOK || out["already_revoked"] != false {
		t.Errorf("first revoke: %d %v", code, out)
	}
	if code, out := adminJSON(t, h, testToken, "DELETE", "/v1/admin/tokens/ag", nil); code != http.StatusOK || out["already_revoked"] != true {
		t.Errorf("second revoke: %d %v", code, out)
	}
}

// A token change and its audit row commit together.
func TestAdminAPI_MutationsAtomicWithAudit(t *testing.T) {
	s, h := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "ag", role: roleAgent, prefixes: []string{"llm."}}, agentToken)
	if _, err := s.db.Exec(`DROP TABLE audit_log`); err != nil {
		t.Fatal(err)
	}
	if code, out := adminJSON(t, h, testToken, "POST", "/v1/admin/tokens", map[string]any{"name": "new", "role": "admin", "expires": "30d"}); code != http.StatusInternalServerError || out["token"] != nil {
		t.Errorf("create with audit down: %d %v", code, out)
	}
	if exists, _ := tokenExists(t.Context(), s.db, "new"); exists {
		t.Error("token created without an audit row")
	}
	if code, _ := adminJSON(t, h, testToken, "DELETE", "/v1/admin/tokens/ag", nil); code != http.StatusInternalServerError {
		t.Errorf("revoke with audit down: %d", code)
	}
	if rr := do(h, reqWithToken("GET", "/v1/secrets", agentToken, nil)); rr.Code == http.StatusUnauthorized {
		t.Error("token revoked without an audit row")
	}
	// Reads that can't be audited are withheld too.
	if code, out := adminJSON(t, h, testToken, "GET", "/v1/admin/tokens", nil); code != http.StatusInternalServerError || out["tokens"] != nil {
		t.Errorf("list with audit down: %d %v", code, out)
	}
}

func TestAdminAPI_Audit(t *testing.T) {
	s, h := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "ag", role: roleAgent, prefixes: []string{"llm."}}, agentToken)
	do(h, reqWithToken("GET", "/v1/secrets/github.x", agentToken, nil)) // denied
	do(h, reqWithToken("GET", "/v1/secrets/llm.x", agentToken, nil))    // not_found

	code, out := adminJSON(t, h, testToken, "GET", "/v1/admin/audit?token=ag&result=denied&since=1h", nil)
	if code != http.StatusOK {
		t.Fatalf("audit: %d %v", code, out)
	}
	recs, _ := out["records"].([]any)
	if len(recs) != 1 {
		t.Fatalf("records = %v, want exactly the denied read", recs)
	}
	if r := recs[0].(map[string]any); r["secret_name"] != "github.x" || r["action"] != "get" {
		t.Errorf("record = %v", r)
	}
	for _, q := range []string{"limit=0", "limit=abc", "action=nope", "result=nope", "since=yesterday", "since=1h&until=2h"} {
		if code, _ := adminJSON(t, h, testToken, "GET", "/v1/admin/audit?"+q, nil); code != http.StatusBadRequest {
			t.Errorf("?%s: %d, want 400", q, code)
		}
	}
	if row := lastAuditRow(t, s.db); row.action != actionAuditRead {
		t.Errorf("audit reads are audited too; last row = %+v", row)
	}
}

func TestAdminAPI_Disabled(t *testing.T) {
	s, _ := newTestServer(t)
	s.adminAPI = false
	h := s.routes()
	for _, p := range []string{"/v1/admin/tokens", "/v1/admin/audit", "/ui/", "/ui/app.js"} {
		if rr := do(h, authReq("GET", p, nil)); rr.Code != http.StatusNotFound {
			t.Errorf("ADMIN_API=false %s: %d, want 404", p, rr.Code)
		}
	}
	// The secret API is unaffected.
	if rr := do(h, authReq("GET", "/v1/secrets", nil)); rr.Code != http.StatusOK {
		t.Errorf("secrets with admin API off: %d", rr.Code)
	}
}

func TestUI_ServedWithSecurityHeaders(t *testing.T) {
	_, h := newTestServer(t)
	for path, ctype := range map[string]string{"/ui/": "text/html", "/ui/app.js": "javascript", "/ui/style.css": "text/css"} {
		rr := do(h, httptest.NewRequest("GET", path, nil))
		if rr.Code != http.StatusOK {
			t.Errorf("%s: %d", path, rr.Code)
			continue
		}
		if !strings.Contains(rr.Header().Get("Content-Type"), ctype) {
			t.Errorf("%s: Content-Type %q", path, rr.Header().Get("Content-Type"))
		}
		csp := rr.Header().Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q missing %q", path, csp, want)
			}
		}
		if rr.Header().Get("X-Frame-Options") != "DENY" || rr.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing frame/nosniff headers", path)
		}
	}
	rr := do(h, httptest.NewRequest("GET", "/", nil))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/ui/" {
		t.Errorf("/: %d -> %q, want redirect to /ui/", rr.Code, rr.Header().Get("Location"))
	}
	// The page must not rely on inline script or style (the CSP forbids it).
	page := do(h, httptest.NewRequest("GET", "/ui/", nil)).Body.String()
	if regexp.MustCompile(`<script>|<style|\sstyle=|\son[a-z]+=`).MatchString(page) {
		t.Error("index.html contains inline script/style/handlers the CSP would block")
	}
}
