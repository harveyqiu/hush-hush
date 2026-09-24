package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCLI_Backup(t *testing.T) {
	path := newTestDBFile(t)
	tok := strings.TrimSpace(runCLI(t, "", "token", "create", "--db", path, "--name", "adm", "--role", "admin", "--expires", "30d").stdout)
	_, h := serverOn(t, path)
	if rr := do(h, reqWithToken("PUT", "/v1/secrets/llm.k", tok, []byte(`{"value":"backed-up"}`))); rr.Code != 200 {
		t.Fatalf("seed: %d", rr.Code)
	}

	out := filepath.Join(t.TempDir(), "backup.db")
	if r := runCLI(t, "", "backup", "--db", path, "--out", out); r.code != 0 {
		t.Fatalf("backup: %s", r.stderr)
	}
	if mode, _ := statMode(out); mode != 0o600 {
		t.Errorf("backup mode = %#o, want 0600", mode)
	}
	// The copy is a working database: same secret decrypts, same token works.
	_, h2 := serverOn(t, out)
	if v := do(h2, reqWithToken("GET", "/v1/secrets/llm.k", tok, nil)); v.Code != 200 || !strings.Contains(v.Body.String(), "backed-up") {
		t.Errorf("restored read: %d %s", v.Code, v.Body.String())
	}
	// Streaming mode: the bytes on stdout are a usable database and no
	// temporary file is left next to the live one.
	r := runCLI(t, "", "backup", "--db", path, "--out", "-")
	if r.code != 0 || !strings.HasPrefix(r.stdout, "SQLite format 3") {
		t.Fatalf("stream backup: code %d, stderr %q, header %q", r.code, r.stderr, r.stdout[:min(16, len(r.stdout))])
	}
	streamed := filepath.Join(t.TempDir(), "streamed.db")
	if err := os.WriteFile(streamed, []byte(r.stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	_, h3 := serverOn(t, streamed)
	if v := do(h3, reqWithToken("GET", "/v1/secrets/llm.k", tok, nil)); v.Code != 200 {
		t.Errorf("streamed copy read: %d", v.Code)
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".backup-*"))
	if len(leftovers) != 0 {
		t.Errorf("temporary backup files left behind: %v", leftovers)
	}

	if r := runCLI(t, "", "backup", "--db", path, "--out", out); r.code == 0 {
		t.Error("overwriting an existing backup should fail")
	}
	if r := runCLI(t, "", "backup", "--db", path); r.code != 2 {
		t.Errorf("missing --out: code %d, want 2", r.code)
	}
}

func TestCLI_AuditPrune(t *testing.T) {
	path := newTestDBFile(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for _, age := range []int64{400, 200, 10, 0} {
		insertAuditRow(t, db, now-age*86400, "t", actionGet, "s", resultAllowed, "")
	}
	db.Close()

	r := runCLI(t, "", "audit-prune", "--db", path, "--older-than", "180d")
	if r.code != 0 || !strings.Contains(r.stdout, "deleted 2") {
		t.Fatalf("prune: code %d out %q err %q", r.code, r.stdout, r.stderr)
	}
	for _, bad := range [][]string{{}, {"--older-than", "soon"}, {"--older-than", "0d"}} {
		if r := runCLI(t, "", append([]string{"audit-prune", "--db", path}, bad...)...); r.code != 2 {
			t.Errorf("%v: code %d, want 2", bad, r.code)
		}
	}
}
