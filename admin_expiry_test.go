package main

import (
	"database/sql"
	"net/http"
	"testing"
	"time"
)

// Admin tokens are for humans and must expire within 90 days, whichever
// front end creates them.
func TestAdminTokens_MustExpire(t *testing.T) {
	path := newTestDBFile(t)
	for args, ok := range map[string]bool{"": false, "91d": false, "2400h": false, "90d": true, "12h": true} {
		cli := []string{"token", "create", "--db", path, "--name", "adm-" + args, "--role", "admin"}
		if args != "" {
			cli = append(cli, "--expires", args)
		} else {
			cli[5] = "adm-none"
		}
		if r := runCLI(t, "", cli...); (r.code == 0) != ok {
			t.Errorf("CLI --expires %q: code %d (%s), want ok=%v", args, r.code, r.stderr, ok)
		}
	}
	// Agents may still be permanent.
	if r := runCLI(t, "", "token", "create", "--db", path, "--name", "ag", "--role", "agent", "--prefix", "llm."); r.code != 0 {
		t.Errorf("agent without expiry: %s", r.stderr)
	}

	_, h := newTestServer(t)
	for exp, want := range map[string]int{"": 400, "91d": 400, "90d": 201} {
		body := map[string]any{"name": "api-adm" + map[string]string{"": "0", "91d": "1", "90d": "2"}[exp], "role": "admin"}
		if exp != "" {
			body["expires"] = exp
		}
		if code, out := adminJSON(t, h, testToken, "POST", "/v1/admin/tokens", body); code != want {
			t.Errorf("API expires %q: %d %v, want %d", exp, code, out, want)
		}
	}
}

// A hand-edited admin row without an expiry is refused at authentication.
func TestAdminTokens_NoExpiryRejected(t *testing.T) {
	s, h := newTestServer(t)
	if _, err := s.db.Exec(`UPDATE tokens SET expires_at = NULL WHERE name = 'test-admin'`); err != nil {
		t.Fatal(err)
	}
	if rr := do(h, authReq("GET", "/v1/secrets", nil)); rr.Code != http.StatusUnauthorized {
		t.Errorf("admin without expiry: %d, want 401", rr.Code)
	}
}

// Migration 5 gives never-expiring or long-lived admin tokens 30 days, and
// leaves short-lived admins, revoked tokens and agents alone.
func TestMigrate_AdminExpiryBackfill(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL DEFAULT (unixepoch()))`); err != nil {
		t.Fatal(err)
	}
	for v := 0; v < 4; v++ {
		if _, err := db.Exec(migrations[v]); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO schema_version (version) VALUES (?)`, v+1); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().Unix()
	day := int64(86400)
	rows := []struct {
		name, role string
		expires    any
		revoked    any
	}{
		{"never", "admin", nil, nil},
		{"long", "admin", now + 365*day, nil},
		{"short", "admin", now + 10*day, nil},
		{"revoked", "admin", nil, now},
		{"agent", "agent", nil, nil},
	}
	for i, r := range rows {
		if _, err := db.Exec(`INSERT INTO tokens (name, token_hash, role, expires_at, revoked_at, created_at) VALUES (?, ?, ?, ?, ?, 1)`,
			r.name, []byte{byte(i)}, r.role, r.expires, r.revoked); err != nil {
			t.Fatal(err)
		}
	}
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	get := func(name string) sql.NullInt64 {
		var v sql.NullInt64
		if err := db.QueryRow(`SELECT expires_at FROM tokens WHERE name = ?`, name).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, name := range []string{"never", "long"} {
		if v := get(name); !v.Valid || v.Int64 < now+29*day || v.Int64 > now+31*day {
			t.Errorf("%s: expires_at = %v, want about 30 days out", name, v)
		}
	}
	if v := get("short"); v.Int64 != now+10*day {
		t.Errorf("short-lived admin changed: %v", v)
	}
	if get("revoked").Valid || get("agent").Valid {
		t.Error("revoked admin or agent token was given an expiry")
	}
}

func TestAdminAPI_Me(t *testing.T) {
	s, h := newTestServer(t)
	mustInsertToken(t, s, tokenSpec{name: "ag", role: roleAgent, prefixes: []string{"llm."}}, agentToken)
	code, out := adminJSON(t, h, testToken, "GET", "/v1/admin/me", nil)
	if code != http.StatusOK || out["name"] != "test-admin" || out["role"] != "admin" || out["expires_at"] == nil {
		t.Errorf("me: %d %v", code, out)
	}
	if code, _ := adminJSON(t, h, agentToken, "GET", "/v1/admin/me", nil); code != http.StatusForbidden {
		t.Errorf("agent /me: %d, want 403", code)
	}
}

func TestAdminTokensExpiringWithin(t *testing.T) {
	s, _ := newTestServer(t) // test-admin expires in 30 days
	soon := time.Now().Add(3 * 24 * time.Hour)
	mustInsertToken(t, s, tokenSpec{name: "soon", role: roleAdmin, expiresAt: &soon}, otherToken)
	names, err := s.adminTokensExpiringWithin(7 * 24 * time.Hour)
	if err != nil || len(names) != 1 || names[0] != "soon" {
		t.Errorf("expiring = %v (err %v), want [soon]", names, err)
	}
}
