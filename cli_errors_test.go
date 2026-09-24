package main

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// CLI error paths: bad flags, missing database, failing database, failing
// stdin/stdout.

func TestCLI_UsageAndMissingDB(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none.db")
	cases := []struct {
		args []string
		code int
	}{
		{[]string{"token", "list", "--bogus"}, 2},
		{[]string{"token", "revoke", "--bogus"}, 2},
		{[]string{"token", "revoke"}, 2},
		{[]string{"token", "update", "--bogus"}, 2},
		{[]string{"token", "update", "--prefix", "a."}, 2},
		{[]string{"backup", "--bogus"}, 2},
		{[]string{"audit-prune", "--bogus"}, 2},
		{[]string{"healthcheck", "extra"}, 2},
		{[]string{"token", "create", "--db", missing, "--name", "a", "--role", "admin", "--expires", "1d"}, 1},
		{[]string{"token", "list", "--db", missing}, 1},
		{[]string{"token", "revoke", "--db", missing, "--name", "a"}, 1},
		{[]string{"token", "update", "--db", missing, "--name", "a", "--prefix", "a."}, 1},
		{[]string{"audit", "--db", missing}, 1},
		{[]string{"backup", "--db", missing, "--out", "-"}, 1},
		{[]string{"audit-prune", "--db", missing, "--older-than", "1d"}, 1},
	}
	for _, c := range cases {
		if r := runCLI(t, "", c.args...); r.code != c.code {
			t.Errorf("%v: code %d, want %d (%s)", c.args, r.code, c.code, r.stderr)
		}
	}
}

func TestCLI_DBFaults(t *testing.T) {
	useFaultDriver(t)
	cases := []struct {
		name, op, sql string
		args          []string
	}{
		{"create exists check", "query", "COUNT(*) FROM tokens WHERE name", []string{"token", "create", "--name", "n", "--role", "admin", "--expires", "1d"}},
		{"create insert", "exec", "INSERT INTO tokens", []string{"token", "create", "--name", "n", "--role", "admin", "--expires", "1d"}},
		{"list", "query", "ORDER BY name", []string{"token", "list"}},
		{"audit query", "query", "FROM audit_log", []string{"audit"}},
		{"audit scan", "nullcol", "FROM audit_log", []string{"audit"}},
		{"backup", "exec", "VACUUM INTO", []string{"backup", "--out", "-"}},
		{"audit-prune", "exec", "DELETE FROM audit_log", []string{"audit-prune", "--older-than", "1d"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := newTestDBFile(t)
			// Something to scan for the scan fault.
			db, err := openDB(path)
			if err != nil {
				t.Fatal(err)
			}
			insertAuditRow(t, db, 1, "t", actionGet, "s", resultAllowed, "")
			db.Close()
			if c.op == "nullcol" {
				injectNullColumn(t, c.sql, 0)
			} else {
				injectFault(t, c.op, c.sql, 0)
			}
			args := append([]string{c.args[0]}, c.args[1:]...)
			// --db goes after the subcommand words.
			at := 1
			if args[0] == "token" {
				at = 2
			}
			args = append(args[:at], append([]string{"--db", path}, args[at:]...)...)
			if r := runCLI(t, "", args...); r.code != 1 {
				t.Errorf("code %d, want 1 (%s)", r.code, r.stderr)
			}
			if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".backup-*")); len(leftovers) != 0 {
				t.Errorf("backup left files behind: %v", leftovers)
			}
		})
	}
}

// failWriter fails every write, like a closed pipe.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestCLI_BackupStreamWriteFails(t *testing.T) {
	path := newTestDBFile(t)
	if err := cmdBackup([]string{"--db", path, "--out", "-"}, failWriter{}, &strings.Builder{}); err == nil {
		t.Error("want an error when stdout can't be written")
	}
}

// errStdin fails reads, to cover the "*" confirmation prompt's error path.
func TestCLI_ConfirmReadError(t *testing.T) {
	if err := confirmAllSecrets("x", errReader{}, &strings.Builder{}); err == nil {
		t.Error("want an error")
	}
}

func TestQueryAudit_ValidatesFilter(t *testing.T) {
	s, _ := newTestServer(t)
	if _, err := queryAudit(t.Context(), s.db, auditFilter{Limit: 0}); err == nil {
		t.Error("limit 0 should be rejected")
	}
}

func TestHealthcheck_Edges(t *testing.T) {
	// Via run(): no server on the default address -> exit 1.
	t.Setenv("LISTEN_ADDR", "127.0.0.1:1")
	if r := runCLI(t, "", "healthcheck"); r.code != 1 {
		t.Errorf("healthcheck with nothing listening: %d", r.code)
	}
	empty := func(string) string { return "" }
	// Default address when LISTEN_ADDR is unset; whatever answers there, it
	// must not panic and must return a result.
	_ = cmdHealthcheck(nil, empty)
	env := func(v string) func(string) string { return func(string) string { return v } }
	if err := cmdHealthcheck(nil, env("127.0.0.1:not a port")); err == nil {
		t.Error("an unusable port must fail")
	}
	// IPv6 wildcard binds are probed on ::1.
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if err := cmdHealthcheck(nil, env("[::]:"+port)); err != nil {
		t.Errorf("[::] probe: %v", err)
	}
}
