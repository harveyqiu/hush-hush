package main

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// newTestDBFile creates an initialized database file for CLI tests.
func newTestDBFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hush.db")
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	return path
}

type cliResult struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, stdin string, args ...string) cliResult {
	t.Helper()
	var out, errb bytes.Buffer
	prev := captureLogsPrev()
	defer restoreLogs(prev)
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return cliResult{code, out.String(), errb.String()}
}

// serverOn builds an HTTP handler over an existing database file, as the
// running service would see it.
func serverOn(t *testing.T, path string) (*server, http.Handler) {
	t.Helper()
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := newServer(db, testKey())
	if err != nil {
		t.Fatal(err)
	}
	return s, s.routes()
}

var tokenFormatRe = regexp.MustCompile(`^hush_[0-9a-f]{64}$`)

func TestCLI_TokenCreate_AgentEndToEnd(t *testing.T) {
	path := newTestDBFile(t)
	admin := runCLI(t, "", "token", "create", "--db", path, "--name", "admin", "--role", "admin", "--expires", "30d")
	agent := runCLI(t, "", "token", "create", "--db", path, "--name", "agent-llm", "--role", "agent",
		"--prefix", "llm.", "--prefix", "github.", "--expires", "90d")
	for _, r := range []cliResult{admin, agent} {
		if r.code != 0 {
			t.Fatalf("create failed: code %d stderr %s", r.code, r.stderr)
		}
		if !tokenFormatRe.MatchString(strings.TrimSpace(r.stdout)) {
			t.Fatalf("stdout %q is not a hush_ + 64-hex token", r.stdout)
		}
		if strings.Contains(r.stderr, strings.TrimSpace(r.stdout)) {
			t.Errorf("token plaintext also printed to stderr")
		}
	}
	adminTok, agentTok := strings.TrimSpace(admin.stdout), strings.TrimSpace(agent.stdout)
	if adminTok == agentTok {
		t.Fatal("two creates returned the same token")
	}

	s, h := serverOn(t, path)
	if rr := do(h, reqWithToken("PUT", "/v1/secrets/github.pat", adminTok, []byte(`{"value":"x"}`))); rr.Code != http.StatusOK {
		t.Fatalf("admin PUT: %d", rr.Code)
	}
	if rr := do(h, reqWithToken("GET", "/v1/secrets/github.pat", agentTok, nil)); rr.Code != http.StatusOK {
		t.Errorf("agent GET in scope: %d", rr.Code)
	}
	if rr := do(h, reqWithToken("PUT", "/v1/secrets/github.pat", agentTok, []byte(`{"value":"y"}`))); rr.Code != http.StatusForbidden {
		t.Errorf("agent PUT: %d, want 403", rr.Code)
	}

	// Only hashes on disk.
	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatal(err)
	}
	wal, _ := os.ReadFile(path + "-wal") // #nosec G304 -- test-controlled path
	for _, tok := range []string{adminTok, agentTok} {
		if bytes.Contains(raw, []byte(tok)) || bytes.Contains(wal, []byte(tok)) {
			t.Errorf("token plaintext found in database files")
		}
		if bytes.Contains(raw, []byte(tok[len(tokenPrefix):])) || bytes.Contains(wal, []byte(tok[len(tokenPrefix):])) {
			t.Errorf("token hex found in database files")
		}
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE expires_at IS NOT NULL AND name = 'agent-llm'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("expiry not stored for agent-llm (n=%d err=%v)", n, err)
	}
}

func TestCLI_TokenCreate_Rejections(t *testing.T) {
	path := newTestDBFile(t)
	if r := runCLI(t, "", "token", "create", "--db", path, "--name", "dup", "--role", "admin", "--expires", "30d"); r.code != 0 {
		t.Fatalf("setup create: %s", r.stderr)
	}
	cases := map[string][]string{
		"prefix without separator":   {"--name", "a1", "--role", "agent", "--prefix", "llm"},
		"prefix ends with dash":      {"--name", "a2", "--role", "agent", "--prefix", "llm-"},
		"one good one bad prefix":    {"--name", "a3", "--role", "agent", "--prefix", "llm.", "--prefix", "gh"},
		"agent without prefix":       {"--name", "a4", "--role", "agent"},
		"admin with prefix":          {"--name", "a5", "--role", "admin", "--prefix", "llm."},
		"unknown role":               {"--name", "a6", "--role", "root"},
		"missing role":               {"--name", "a7"},
		"bad name":                   {"--name", "bad name", "--role", "admin"},
		"colon not allowed in names": {"--name", "env:AUTH_TOKEN", "--role", "admin"},
		"duplicate name":             {"--name", "dup", "--role", "admin", "--expires", "30d"},
		"bad expiry":                 {"--name", "a8", "--role", "admin", "--expires", "soon"},
		"negative expiry":            {"--name", "a9", "--role", "admin", "--expires", "-1d"},
		"stray argument":             {"--name", "a10", "--role", "admin", "extra"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			r := runCLI(t, "", append([]string{"token", "create", "--db", path}, args...)...)
			if r.code == 0 {
				t.Fatalf("expected failure, got success: %s", r.stdout)
			}
			if r.stdout != "" {
				t.Errorf("no token may be printed on failure, got %q", r.stdout)
			}
		})
	}
	s, _ := serverOn(t, path)
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&n); err != nil || n != 1 {
		t.Errorf("rejected creates wrote rows: count=%d err=%v", n, err)
	}
}

func TestCLI_WildcardNeedsConfirmation(t *testing.T) {
	path := newTestDBFile(t)
	args := []string{"token", "create", "--db", path, "--name", "agent-all", "--role", "agent", "--prefix", "*"}

	for _, in := range []string{"", "yes\n", "agent-al\n"} {
		if r := runCLI(t, in, args...); r.code == 0 || r.stdout != "" {
			t.Errorf("stdin %q: wildcard created without matching confirmation", in)
		}
	}
	r := runCLI(t, "agent-all\n", args...)
	if r.code != 0 || !tokenFormatRe.MatchString(strings.TrimSpace(r.stdout)) {
		t.Fatalf("confirmed wildcard create failed: %d %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "EVERY secret") {
		t.Errorf("expected a warning on stderr, got %q", r.stderr)
	}
}

func TestCLI_TokenList(t *testing.T) {
	path := newTestDBFile(t)
	created := runCLI(t, "", "token", "create", "--db", path, "--name", "agent-llm", "--role", "agent", "--prefix", "llm.")
	runCLI(t, "", "token", "create", "--db", path, "--name", "old", "--role", "admin", "--expires", "30d")
	runCLI(t, "", "token", "revoke", "--db", path, "--name", "old")

	r := runCLI(t, "", "token", "list", "--db", path)
	if r.code != 0 {
		t.Fatalf("list: %s", r.stderr)
	}
	for _, want := range []string{"NAME", "agent-llm", "agent", "llm.", "active", "old", "revoked", "LAST_USED"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("list output missing %q:\n%s", want, r.stdout)
		}
	}
	tok := strings.TrimSpace(created.stdout)
	h := hashToken(tok)
	if strings.Contains(r.stdout, tok[len(tokenPrefix):]) || strings.Contains(r.stdout, hex.EncodeToString(h[:])) {
		t.Errorf("list output leaks token or hash:\n%s", r.stdout)
	}
}

func TestCLI_RevokeIsImmediate(t *testing.T) {
	path := newTestDBFile(t)
	tok := strings.TrimSpace(runCLI(t, "", "token", "create", "--db", path, "--name", "a", "--role", "admin", "--expires", "30d").stdout)
	_, h := serverOn(t, path)
	if rr := do(h, reqWithToken("GET", "/v1/secrets", tok, nil)); rr.Code != http.StatusOK {
		t.Fatalf("before revoke: %d", rr.Code)
	}
	if r := runCLI(t, "", "token", "revoke", "--db", path, "--name", "a"); r.code != 0 {
		t.Fatalf("revoke: %s", r.stderr)
	}
	// Same server instance, no restart: the very next request is refused.
	if rr := do(h, reqWithToken("GET", "/v1/secrets", tok, nil)); rr.Code != http.StatusUnauthorized {
		t.Errorf("after revoke: %d, want 401", rr.Code)
	}
	if r := runCLI(t, "", "token", "revoke", "--db", path, "--name", "a"); r.code != 0 || !strings.Contains(r.stdout, "already") {
		t.Errorf("second revoke: code %d out %q", r.code, r.stdout)
	}
	if r := runCLI(t, "", "token", "revoke", "--db", path, "--name", "missing"); r.code == 0 {
		t.Error("revoking an unknown token should fail")
	}
}

func TestCLI_TokenUpdate(t *testing.T) {
	path := newTestDBFile(t)
	adminTok := strings.TrimSpace(runCLI(t, "", "token", "create", "--db", path, "--name", "adm", "--role", "admin", "--expires", "30d").stdout)
	agentTok := strings.TrimSpace(runCLI(t, "", "token", "create", "--db", path, "--name", "ag", "--role", "agent", "--prefix", "llm.").stdout)
	_, h := serverOn(t, path)
	seed := func(name string) {
		if rr := do(h, reqWithToken("PUT", "/v1/secrets/"+name, adminTok, []byte(`{"value":"x"}`))); rr.Code != http.StatusOK {
			t.Fatalf("seed %s: %d", name, rr.Code)
		}
	}
	seed("llm.k")
	seed("github.k")

	if r := runCLI(t, "", "token", "update", "--db", path, "--name", "ag", "--prefix", "github."); r.code != 0 {
		t.Fatalf("update: %s", r.stderr)
	}
	if rr := do(h, reqWithToken("GET", "/v1/secrets/github.k", agentTok, nil)); rr.Code != http.StatusOK {
		t.Errorf("new prefix: %d, want 200", rr.Code)
	}
	if rr := do(h, reqWithToken("GET", "/v1/secrets/llm.k", agentTok, nil)); rr.Code != http.StatusForbidden {
		t.Errorf("old prefix: %d, want 403 (update replaces the set)", rr.Code)
	}

	for name, args := range map[string][]string{
		"bad prefix":  {"--name", "ag", "--prefix", "github"},
		"no prefix":   {"--name", "ag"},
		"admin token": {"--name", "adm", "--prefix", "llm."},
		"unknown":     {"--name", "nobody", "--prefix", "llm."},
	} {
		if r := runCLI(t, "", append([]string{"token", "update", "--db", path}, args...)...); r.code == 0 {
			t.Errorf("%s: expected failure", name)
		}
	}
	if r := runCLI(t, "", "token", "update", "--db", path, "--name", "ag", "--prefix", "*"); r.code == 0 {
		t.Error("wildcard update without confirmation should fail")
	}
}

func TestCLI_MissingDatabaseIsNotCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "typo.db")
	if r := runCLI(t, "", "token", "list", "--db", path); r.code == 0 {
		t.Error("expected failure on a missing database")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("admin CLI created %s", path)
	}
}

func TestCLI_UsageErrors(t *testing.T) {
	for _, args := range [][]string{{"bogus"}, {"token"}, {"token", "bogus"}, {"serve", "extra"}} {
		if r := runCLI(t, "", args...); r.code != 2 {
			t.Errorf("%v: code %d, want 2", args, r.code)
		}
	}
	if r := runCLI(t, "", "help"); r.code != 0 || !strings.Contains(r.stdout, "token create") {
		t.Errorf("help: code %d out %q", r.code, r.stdout)
	}
}

func TestParseExpiry(t *testing.T) {
	for in, ok := range map[string]bool{"90d": true, "1d": true, "12h": true, "30m": true, "0d": false, "d": false, "-2h": false, "x": false} {
		if _, err := parseExpiry(in); (err == nil) != ok {
			t.Errorf("parseExpiry(%q) err=%v, want ok=%v", in, err, ok)
		}
	}
}
