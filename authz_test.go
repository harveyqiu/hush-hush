package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func secretValue(t *testing.T, s *server, name string) (string, bool) {
	t.Helper()
	rr := do(s.routes(), authReq("GET", "/v1/secrets/"+name, nil))
	if rr.Code == http.StatusNotFound {
		return "", false
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("admin GET %s: %d", name, rr.Code)
	}
	var got secretRow
	decodeJSON(t, rr.Body.Bytes(), &got)
	return got.Value, true
}

// Agents are read-only: PUT and DELETE are 403 and leave data unchanged,
// even for names inside the agent's own prefixes.
func TestAgent_CannotWriteOrDelete(t *testing.T) {
	s, h := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "agent-llm", role: roleAgent, prefixes: []string{"llm."}}, agentToken)
	if rr := do(h, authReq("PUT", "/v1/secrets/llm.openai", []byte(`{"value":"original"}`))); rr.Code != http.StatusOK {
		t.Fatalf("admin PUT: %d", rr.Code)
	}

	cases := []struct {
		method, path string
		body         []byte
	}{
		{"PUT", "/v1/secrets/llm.openai", []byte(`{"value":"overwritten"}`)},
		{"PUT", "/v1/secrets/llm.new", []byte(`{"value":"created"}`)},
		{"PUT", "/v1/secrets/github.token", []byte(`{"value":"x"}`)},
		{"DELETE", "/v1/secrets/llm.openai", nil},
		{"DELETE", "/v1/secrets/llm.never-existed", nil},
	}
	for _, c := range cases {
		rr := do(h, reqWithToken(c.method, c.path, agentToken, c.body))
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s %s: got %d, want 403", c.method, c.path, rr.Code)
			continue
		}
		if got := decodeErrBody(t, rr); got != "forbidden" {
			t.Errorf("%s %s: error = %q, want forbidden", c.method, c.path, got)
		}
	}

	if v, ok := secretValue(t, s, "llm.openai"); !ok || v != "original" {
		t.Errorf("llm.openai = %q (exists=%v), want unchanged %q", v, ok, "original")
	}
	if _, ok := secretValue(t, s, "llm.new"); ok {
		t.Error("agent PUT created llm.new")
	}
}

func seedSecrets(t *testing.T, h http.Handler, names ...string) {
	t.Helper()
	for _, n := range names {
		if rr := do(h, authReq("PUT", "/v1/secrets/"+n, []byte(`{"value":"v-`+n+`"}`))); rr.Code != http.StatusOK {
			t.Fatalf("seed %s: %d", n, rr.Code)
		}
	}
}

func TestAgent_PrefixScopedReads(t *testing.T) {
	s, h := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "agent-llm", role: roleAgent, prefixes: []string{"llm."}}, agentToken)
	seedSecrets(t, h, "llm.openai", "github.token", "llmx.key", "llm")

	cases := []struct {
		name string
		want int
	}{
		{"llm.openai", http.StatusOK},
		{"github.token", http.StatusForbidden},
		{"llmx.key", http.StatusForbidden}, // separator stops "llm." matching "llmx."
		{"llm", http.StatusForbidden},      // the prefix itself without separator
		{"llm.missing", http.StatusNotFound},
		{"github.missing", http.StatusForbidden}, // out of scope: 403 even though absent
		{"nope", http.StatusForbidden},
	}
	for _, c := range cases {
		rr := do(h, reqWithToken("GET", "/v1/secrets/"+c.name, agentToken, nil))
		if rr.Code != c.want {
			t.Errorf("GET %s: got %d, want %d", c.name, rr.Code, c.want)
		}
		if rr.Code == http.StatusForbidden {
			if got := decodeErrBody(t, rr); got != "forbidden" {
				t.Errorf("GET %s: body error %q, want forbidden", c.name, got)
			}
		}
	}
}

// An out-of-scope name must be rejected without touching the database:
// with the DB closed, an in-scope lookup fails (500) while an out-of-scope
// one is still a clean 403.
func TestAgent_OutOfScopeDoesNotQueryDB(t *testing.T) {
	s, _ := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "agent-llm", role: roleAgent, prefixes: []string{"llm."}}, agentToken)
	p := &principal{name: "agent-llm", role: roleAgent, prefixes: []string{"llm."}}
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]int{"github.token": http.StatusForbidden, "llm.openai": http.StatusInternalServerError} {
		req := reqWithToken("GET", "/v1/secrets/"+name, agentToken, nil)
		req.SetPathValue("name", name)
		req = req.WithContext(context.WithValue(req.Context(), principalKey{}, p))
		rr := httptest.NewRecorder()
		s.get(rr, req)
		if rr.Code != want {
			t.Errorf("%s: got %d, want %d", name, rr.Code, want)
		}
	}
}

func listNames(t *testing.T, h http.Handler, token string) []string {
	t.Helper()
	rr := do(h, reqWithToken("GET", "/v1/secrets", token, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d", rr.Code)
	}
	var resp struct {
		Secrets []secretRow `json:"secrets"`
	}
	decodeJSON(t, rr.Body.Bytes(), &resp)
	names := []string{}
	for _, s := range resp.Secrets {
		if s.Value != "" {
			t.Errorf("list leaked a value for %s", s.Name)
		}
		names = append(names, s.Name)
	}
	return names
}

func TestList_FilteredByPrefix(t *testing.T) {
	s, h := newTestServer(t)
	seedSecrets(t, h, "github.token", "llm.anthropic", "llm.openai", "llmx.key", "llm_old", "llm_x.k", "ops_db")
	mustInsertToken(t, s, tokenSpec{name: "agent-llm", role: roleAgent, prefixes: []string{"llm.", "ops_"}}, agentToken)
	mustInsertToken(t, s, tokenSpec{name: "agent-all", role: roleAgent, prefixes: []string{"*"}}, otherToken)
	mustInsertToken(t, s, tokenSpec{name: "agent-under", role: roleAgent, prefixes: []string{"llm_"}}, "hush_underscore-agent")

	tests := []struct {
		token string
		want  []string
	}{
		{agentToken, []string{"llm.anthropic", "llm.openai", "ops_db"}},
		// '_' is literal, not a LIKE wildcard: "llm_" must not match "llmx.key".
		{"hush_underscore-agent", []string{"llm_old", "llm_x.k"}},
		{otherToken, []string{"github.token", "llm.anthropic", "llm.openai", "llm_old", "llm_x.k", "llmx.key", "ops_db"}},
		{testToken, []string{"github.token", "llm.anthropic", "llm.openai", "llm_old", "llm_x.k", "llmx.key", "ops_db"}},
	}
	for _, tt := range tests {
		got := listNames(t, h, tt.token)
		if strings.Join(got, ",") != strings.Join(tt.want, ",") {
			t.Errorf("token %s: got %v, want %v", tt.token, got, tt.want)
		}
	}
}

// A hand-edited or corrupted grant must never widen access.
func TestAgent_InvalidStoredPrefixIgnored(t *testing.T) {
	s, h := newTestServer(t)
	seedSecrets(t, h, "llm.openai", "github.token")
	mustInsertToken(t, s, tokenSpec{name: "agent-bad", role: roleAgent, prefixes: []string{"llm."}}, agentToken)
	if _, err := s.db.Exec(`UPDATE tokens SET prefixes = '["", "g", "*", "llm."]' WHERE name = 'agent-bad'`); err != nil {
		t.Fatal(err)
	}
	if got := listNames(t, h, agentToken); strings.Join(got, ",") != "llm.openai" {
		t.Errorf("list = %v, want only llm.openai", got)
	}
	if rr := do(h, reqWithToken("GET", "/v1/secrets/github.token", agentToken, nil)); rr.Code != http.StatusForbidden {
		t.Errorf("GET github.token: got %d, want 403", rr.Code)
	}
}

func TestValidatePrefixes(t *testing.T) {
	tests := []struct {
		role     string
		prefixes []string
		ok       bool
	}{
		{roleAgent, []string{"llm."}, true},
		{roleAgent, []string{"llm.", "github_"}, true},
		{roleAgent, []string{"a.b.c."}, true},
		{roleAgent, []string{"*"}, true},
		{roleAgent, nil, false},
		{roleAgent, []string{"llm"}, false},
		{roleAgent, []string{"llm-"}, false},
		{roleAgent, []string{"."}, false},
		{roleAgent, []string{""}, false},
		{roleAgent, []string{"ll m."}, false},
		{roleAgent, []string{"*", "llm."}, false},
		{roleAgent, []string{"llm.*"}, false},
		{roleAgent, []string{"llm.", "llm."}, false},
		{roleAdmin, nil, true},
		{roleAdmin, []string{"llm."}, false},
		{"root", nil, false},
	}
	for _, tt := range tests {
		err := validateGrants(tt.role, tt.prefixes, nil)
		if (err == nil) != tt.ok {
			t.Errorf("validateGrants(%s, %q) err=%v, want ok=%v", tt.role, tt.prefixes, err, tt.ok)
		}
	}
}
