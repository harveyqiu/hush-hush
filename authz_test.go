package main

import (
	"net/http"
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
