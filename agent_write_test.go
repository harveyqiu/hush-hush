package main

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"
)

const writerToken = "hush_writer-token-for-tests"

// newWriterServer: an agent that can create under crawler. and read
// under crawler. and llm.
func newWriterServer(t *testing.T) (*server, http.Handler) {
	t.Helper()
	s, h := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "agent-crawler", role: roleAgent,
		prefixes: []string{"crawler.", "llm."}, writePrefixes: []string{"crawler."}}, writerToken)
	return s, h
}

func putAs(h http.Handler, token, name, value string) int {
	return do(h, reqWithToken("PUT", "/v1/secrets/"+name, token, []byte(`{"value":"`+value+`"}`))).Code
}

func TestAgentWrite_CreateUnderWritePrefix(t *testing.T) {
	s, h := newWriterServer(t)
	if code := putAs(h, writerToken, "crawler.session", "v1"); code != http.StatusOK {
		t.Fatalf("create: got %d, want 200", code)
	}
	row := lastAuditRow(t, s.db)
	if row.tokenName != "agent-crawler" || row.action != actionPut || row.result != resultAllowed || row.secretName != "crawler.session" {
		t.Errorf("audit row = %+v", row)
	}
	if v, ok := secretValue(t, s, "crawler.session"); !ok || v != "v1" {
		t.Errorf("stored value = %q (exists=%v), want v1", v, ok)
	}
}

// Create-only: an agent can never overwrite, whether the existing value was
// written by an admin or by itself.
func TestAgentWrite_NoOverwrite(t *testing.T) {
	s, h := newWriterServer(t)
	seedSecrets(t, h, "crawler.admin-set")
	if code := putAs(h, writerToken, "crawler.mine", "first"); code != http.StatusOK {
		t.Fatalf("setup create: %d", code)
	}
	for _, name := range []string{"crawler.admin-set", "crawler.mine"} {
		before, _ := secretValue(t, s, name)
		rr := do(h, reqWithToken("PUT", "/v1/secrets/"+name, writerToken, []byte(`{"value":"overwritten"}`)))
		if rr.Code != http.StatusConflict {
			t.Errorf("%s: got %d, want 409", name, rr.Code)
		}
		if got := decodeErrBody(t, rr); got != "already exists" {
			t.Errorf("%s: error %q", name, got)
		}
		// Checked before secretValue, whose admin GET adds its own row.
		if row := lastAuditRow(t, s.db); row.result != resultConflict || row.tokenName != "agent-crawler" {
			t.Errorf("%s: audit row = %+v, want result conflict", name, row)
		}
		if after, _ := secretValue(t, s, name); after != before {
			t.Errorf("%s: value changed from %q to %q", name, before, after)
		}
	}
	// Admin can still overwrite.
	if code := putAs(h, testToken, "crawler.mine", "admin-updated"); code != http.StatusOK {
		t.Errorf("admin overwrite: %d", code)
	}
}

func TestAgentWrite_OutsideWritePrefixForbidden(t *testing.T) {
	s, h := newWriterServer(t)
	// llm. is readable but not writable; crawlerx. shares letters but not
	// the separator; github. is outside every grant.
	for _, name := range []string{"llm.new", "crawlerx.k", "github.token", "crawler"} {
		if code := putAs(h, writerToken, name, "x"); code != http.StatusForbidden {
			t.Errorf("PUT %s: got %d, want 403", name, code)
		}
		if secretExists(t, s, name) {
			t.Errorf("PUT %s created a row", name)
		}
	}
}

func TestAgentWrite_DeleteStillForbidden(t *testing.T) {
	s, h := newWriterServer(t)
	if code := putAs(h, writerToken, "crawler.tmp", "x"); code != http.StatusOK {
		t.Fatalf("create: %d", code)
	}
	if rr := do(h, reqWithToken("DELETE", "/v1/secrets/crawler.tmp", writerToken, nil)); rr.Code != http.StatusForbidden {
		t.Errorf("DELETE: got %d, want 403", rr.Code)
	}
	if !secretExists(t, s, "crawler.tmp") {
		t.Error("agent DELETE removed the secret")
	}
}

// A write grant does not imply read: a write-only agent can create but not
// read back or list.
func TestAgentWrite_WriteDoesNotImplyRead(t *testing.T) {
	s, h := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "drop-box", role: roleAgent, writePrefixes: []string{"inbox."}}, otherToken)
	if code := putAs(h, otherToken, "inbox.item", "x"); code != http.StatusOK {
		t.Fatalf("create: %d", code)
	}
	if rr := do(h, reqWithToken("GET", "/v1/secrets/inbox.item", otherToken, nil)); rr.Code != http.StatusForbidden {
		t.Errorf("GET: got %d, want 403", rr.Code)
	}
	if got := listNames(t, h, otherToken); len(got) != 0 {
		t.Errorf("list = %v, want empty", got)
	}
}

// Stored grants are re-validated: "*" or an empty string in write_prefixes
// must never allow creating anything, and unreadable JSON rejects the token.
func TestAgentWrite_CorruptedGrant(t *testing.T) {
	s, h := newWriterServer(t)
	if _, err := s.db.Exec(`UPDATE tokens SET write_prefixes = '["", "*", "c"]' WHERE name = 'agent-crawler'`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"crawler.x", "anything", "c.x"} {
		if code := putAs(h, writerToken, name, "x"); code != http.StatusForbidden {
			t.Errorf("PUT %s with corrupted grant: got %d, want 403", name, code)
		}
	}
	if _, err := s.db.Exec(`UPDATE tokens SET write_prefixes = 'not json' WHERE name = 'agent-crawler'`); err != nil {
		t.Fatal(err)
	}
	if rr := do(h, reqWithToken("GET", "/v1/secrets/llm.x", writerToken, nil)); rr.Code != http.StatusUnauthorized {
		t.Errorf("unreadable write_prefixes: got %d, want 401", rr.Code)
	}
}

// Tokens created before migration 4 get no write grant.
func TestMigrate_ExistingTokensGetNoWriteGrant(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL DEFAULT (unixepoch()))`); err != nil {
		t.Fatal(err)
	}
	for v := 0; v < 3; v++ {
		if _, err := db.Exec(migrations[v]); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO schema_version (version) VALUES (?)`, v+1); err != nil {
			t.Fatal(err)
		}
	}
	h := hashToken(agentToken)
	if _, err := db.Exec(`INSERT INTO tokens (name, token_hash, role, prefixes, created_at)
		VALUES ('old-agent', ?, 'agent', '["crawler."]', 1)`, h[:]); err != nil {
		t.Fatal(err)
	}
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	var wp string
	if err := db.QueryRow(`SELECT write_prefixes FROM tokens WHERE name = 'old-agent'`).Scan(&wp); err != nil || wp != "[]" {
		t.Fatalf("write_prefixes = %q (err %v), want []", wp, err)
	}
	s, err := newServer(db, testKey())
	if err != nil {
		t.Fatal(err)
	}
	if code := putAs(s.routes(), agentToken, "crawler.x", "v"); code != http.StatusForbidden {
		t.Errorf("pre-migration agent PUT: got %d, want 403", code)
	}
}

func TestValidateGrants(t *testing.T) {
	tests := []struct {
		role        string
		read, write []string
		ok          bool
	}{
		{roleAgent, nil, []string{"crawler."}, true},
		{roleAgent, []string{"llm."}, []string{"crawler.", "tmp_"}, true},
		{roleAgent, nil, nil, false},
		{roleAgent, nil, []string{"*"}, false},
		{roleAgent, []string{"*"}, []string{"*"}, false},
		{roleAgent, nil, []string{"crawler"}, false},
		{roleAgent, nil, []string{""}, false},
		{roleAgent, nil, []string{"a.", "a."}, false},
		{roleAdmin, nil, []string{"crawler."}, false},
	}
	for _, tt := range tests {
		if err := validateGrants(tt.role, tt.read, tt.write); (err == nil) != tt.ok {
			t.Errorf("validateGrants(%s, %q, %q) err=%v, want ok=%v", tt.role, tt.read, tt.write, err, tt.ok)
		}
	}
}

func TestCLI_WritePrefixes(t *testing.T) {
	path := newTestDBFile(t)
	r := runCLI(t, "", "token", "create", "--db", path, "--name", "crawler", "--role", "agent", "--write-prefix", "crawler.")
	if r.code != 0 {
		t.Fatalf("create write-only agent: %s", r.stderr)
	}
	tok := strings.TrimSpace(r.stdout)

	for name, args := range map[string][]string{
		"wildcard write": {"--name", "w1", "--role", "agent", "--write-prefix", "*"},
		"bad write":      {"--name", "w2", "--role", "agent", "--write-prefix", "crawler"},
		"admin write":    {"--name", "w3", "--role", "admin", "--write-prefix", "crawler."},
	} {
		if r := runCLI(t, "", append([]string{"token", "create", "--db", path}, args...)...); r.code == 0 || r.stdout != "" {
			t.Errorf("%s: expected failure", name)
		}
	}

	// A second agent on an overlapping namespace is allowed, with a warning.
	r = runCLI(t, "", "token", "create", "--db", path, "--name", "other", "--role", "agent", "--write-prefix", "crawler.cache.")
	if r.code != 0 || !strings.Contains(r.stderr, "overlaps") {
		t.Errorf("overlap: code %d stderr %q, want success with warning", r.code, r.stderr)
	}

	_, h := serverOn(t, path)
	if code := putAs(h, tok, "crawler.a", "x"); code != http.StatusOK {
		t.Fatalf("PUT via CLI-made token: %d", code)
	}

	// update: add a read prefix, write set untouched.
	if r := runCLI(t, "", "token", "update", "--db", path, "--name", "crawler", "--prefix", "crawler."); r.code != 0 {
		t.Fatalf("update read: %s", r.stderr)
	}
	if rr := do(h, reqWithToken("GET", "/v1/secrets/crawler.a", tok, nil)); rr.Code != http.StatusOK {
		t.Errorf("GET after adding read prefix: %d", rr.Code)
	}
	if code := putAs(h, tok, "crawler.b", "x"); code != http.StatusOK {
		t.Errorf("write grant lost after read-only update: %d", code)
	}
	// --no-write clears the write set.
	if r := runCLI(t, "", "token", "update", "--db", path, "--name", "crawler", "--no-write"); r.code != 0 {
		t.Fatalf("update --no-write: %s", r.stderr)
	}
	if code := putAs(h, tok, "crawler.c", "x"); code != http.StatusForbidden {
		t.Errorf("PUT after --no-write: %d, want 403", code)
	}
	// Clearing the last grant is refused.
	runCLI(t, "", "token", "create", "--db", path, "--name", "wo", "--role", "agent", "--write-prefix", "wo.")
	if r := runCLI(t, "", "token", "update", "--db", path, "--name", "wo", "--no-write"); r.code == 0 {
		t.Error("removing an agent's only grant should fail")
	}
	if r := runCLI(t, "", "token", "update", "--db", path, "--name", "wo", "--no-write", "--write-prefix", "x."); r.code != 2 {
		t.Errorf("--no-write with --write-prefix: code %d, want 2", r.code)
	}

	list := runCLI(t, "", "token", "list", "--db", path)
	for _, want := range []string{"WRITE", "crawler.cache.", "wo."} {
		if !strings.Contains(list.stdout, want) {
			t.Errorf("list missing %q:\n%s", want, list.stdout)
		}
	}
	if r := runCLI(t, "", "audit", "--db", path, "--result", resultConflict); r.code != 0 {
		t.Errorf("--result conflict rejected: %s", r.stderr)
	}
}
