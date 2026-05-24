package main

// Tests for cmdMigrate — the one-shot v1 → v2 conversion. Uses the
// existing fakeServer helper from crud_test.go and the testKDFParams /
// initVault helpers from vault_test.go.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCmdMigrate_NoVaultErrors(t *testing.T) {
	t.Setenv("HUSH_CONFIG_DIR", t.TempDir())
	envClient(t, "https://example")

	var out bytes.Buffer
	err := cmdMigrate(context.Background(), nil, &out, constPrompt("anything"))
	if err == nil {
		t.Fatal("expected error when no vault configured")
	}
	if !strings.Contains(err.Error(), "hush init") {
		t.Errorf("got %v, want error pointing at `hush init`", err)
	}
}

func TestCmdMigrate_HappyPath_AllV1(t *testing.T) {
	srv := newFakeServer(t)
	srv.gets["alpha"] = Secret{Name: "alpha", Value: "v1-alpha"}
	srv.gets["beta"] = Secret{Name: "beta", Value: "v1-beta"}
	srv.listResp = []Secret{{Name: "alpha"}, {Name: "beta"}}
	withTestVault(t, "pw")
	envClient(t, srv.srv.URL)

	var out bytes.Buffer
	if err := cmdMigrate(context.Background(), nil, &out, constPrompt("pw")); err != nil {
		t.Fatalf("cmdMigrate: %v", err)
	}
	// Both secrets should now be hh2: blobs on the server.
	for _, name := range []string{"alpha", "beta"} {
		if !strings.HasPrefix(srv.gets[name].Value, vaultPrefix) {
			t.Errorf("%s: server still has plaintext %q", name, srv.gets[name].Value)
		}
	}
	if !strings.Contains(out.String(), "2 migrated") {
		t.Errorf("expected '2 migrated' summary, got %q", out.String())
	}
}

func TestCmdMigrate_MixedV1V2_SkipsV2(t *testing.T) {
	srv := newFakeServer(t)
	withTestVault(t, "pw")
	envClient(t, srv.srv.URL)

	// One pre-existing v2 secret (using the production encrypt path so
	// the prefix and AAD are correct) plus one v1 plaintext.
	key, err := unlockIfPresent(constPrompt("pw"))
	if err != nil {
		t.Fatal(err)
	}
	already, err := encryptWireFormat(key, []byte("already-encrypted"), []byte("v2name"))
	if err != nil {
		t.Fatal(err)
	}
	srv.gets["v2name"] = Secret{Name: "v2name", Value: already}
	srv.gets["v1name"] = Secret{Name: "v1name", Value: "still-plaintext"}
	srv.listResp = []Secret{{Name: "v1name"}, {Name: "v2name"}}

	var out bytes.Buffer
	if err := cmdMigrate(context.Background(), nil, &out, constPrompt("pw")); err != nil {
		t.Fatalf("cmdMigrate: %v", err)
	}
	if srv.gets["v2name"].Value != already {
		t.Errorf("already-v2 secret was rewritten")
	}
	if !strings.HasPrefix(srv.gets["v1name"].Value, vaultPrefix) {
		t.Errorf("v1 secret was not migrated")
	}
	if !strings.Contains(out.String(), "1 migrated") || !strings.Contains(out.String(), "1 skipped") {
		t.Errorf("expected '1 migrated, 1 skipped' summary, got %q", out.String())
	}
}

func TestCmdMigrate_DryRun_WritesNothing(t *testing.T) {
	srv := newFakeServer(t)
	srv.gets["foo"] = Secret{Name: "foo", Value: "v1-foo"}
	srv.listResp = []Secret{{Name: "foo"}}
	withTestVault(t, "pw")
	envClient(t, srv.srv.URL)

	var out bytes.Buffer
	if err := cmdMigrate(context.Background(), []string{"--dry-run"}, &out, constPrompt("pw")); err != nil {
		t.Fatalf("cmdMigrate --dry-run: %v", err)
	}
	if srv.gets["foo"].Value != "v1-foo" {
		t.Errorf("dry-run wrote to server: got %q, want unchanged plaintext", srv.gets["foo"].Value)
	}
	if !strings.Contains(out.String(), "would migrate: foo") {
		t.Errorf("expected dry-run hint, got %q", out.String())
	}
	if !strings.Contains(out.String(), "1 would migrate") {
		t.Errorf("expected dry-run summary, got %q", out.String())
	}
}

func TestCmdMigrate_WrongPassphraseFailsBeforeNetwork(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer srv.Close()
	withTestVault(t, "pw")
	envClient(t, srv.URL)

	var out bytes.Buffer
	err := cmdMigrate(context.Background(), nil, &out, constPrompt("WRONG"))
	if !errors.Is(err, errBadPassphrase) {
		t.Errorf("got %v, want errBadPassphrase", err)
	}
	if called {
		t.Errorf("server was hit despite wrong passphrase — unlock must precede all I/O")
	}
}

func TestCmdMigrate_ContinuesPastPerSecretError(t *testing.T) {
	// Server returns 500 on Get for one specific name; migrate should
	// log the error and keep processing the rest.
	withTestVault(t, "pw")
	var listCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/secrets":
			listCalls++
			_, _ = w.Write([]byte(`{"secrets":[{"name":"good","created_at":1,"updated_at":1},{"name":"flaky","created_at":1,"updated_at":1}]}`))
		case r.Method == "GET" && r.URL.Path == "/v1/secrets/good":
			_, _ = w.Write([]byte(`{"name":"good","value":"plain","created_at":1,"updated_at":1}`))
		case r.Method == "GET" && r.URL.Path == "/v1/secrets/flaky":
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"error":"db down"}`))
		case r.Method == "PUT" && r.URL.Path == "/v1/secrets/good":
			_, _ = w.Write([]byte(`{"name":"good","created_at":1,"updated_at":2}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	envClient(t, srv.URL)

	var out bytes.Buffer
	err := cmdMigrate(context.Background(), nil, &out, constPrompt("pw"))
	if err == nil {
		t.Fatal("expected non-nil error so exit code is 1")
	}
	if !strings.Contains(err.Error(), "1 secret(s) failed") {
		t.Errorf("got %v, want failure-count error", err)
	}
	if !strings.Contains(out.String(), "migrated: good") {
		t.Errorf("expected 'good' to migrate despite 'flaky' failing, got %q", out.String())
	}
	if !strings.Contains(out.String(), "error: flaky: get:") {
		t.Errorf("expected per-secret error line for 'flaky', got %q", out.String())
	}
	if !strings.Contains(out.String(), "1 migrated") || !strings.Contains(out.String(), "1 errors") {
		t.Errorf("expected mixed summary, got %q", out.String())
	}
	if listCalls != 1 {
		t.Errorf("list called %d times, want 1", listCalls)
	}
}

func TestCmdMigrate_EmptyServerNoOp(t *testing.T) {
	srv := newFakeServer(t)
	srv.listResp = nil
	withTestVault(t, "pw")
	envClient(t, srv.srv.URL)

	var out bytes.Buffer
	if err := cmdMigrate(context.Background(), nil, &out, constPrompt("pw")); err != nil {
		t.Fatalf("cmdMigrate: %v", err)
	}
	if !strings.Contains(out.String(), "0 migrated") || !strings.Contains(out.String(), "0 errors") {
		t.Errorf("got %q", out.String())
	}
}

func TestCmdMigrate_ExtraArgsRejected(t *testing.T) {
	withTestVault(t, "pw")
	envClient(t, "https://example")
	var out bytes.Buffer
	err := cmdMigrate(context.Background(), []string{"unexpected"}, &out, constPrompt("pw"))
	if err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
		t.Errorf("got %v", err)
	}
}

func TestCmdMigrate_BadFlagRejected(t *testing.T) {
	withTestVault(t, "pw")
	envClient(t, "https://example")
	var out bytes.Buffer
	err := cmdMigrate(context.Background(), []string{"--bogus"}, &out, constPrompt("pw"))
	if err == nil || !strings.Contains(err.Error(), "migrate:") {
		t.Errorf("got %v, want wrapped flag-parse error", err)
	}
}

func TestCmdMigrate_ListFailureAborts(t *testing.T) {
	// If the initial /v1/secrets call fails we have nothing to iterate;
	// surface the error without claiming any partial success.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secrets" {
			w.WriteHeader(503)
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()
	withTestVault(t, "pw")
	envClient(t, srv.URL)

	var out bytes.Buffer
	err := cmdMigrate(context.Background(), nil, &out, constPrompt("pw"))
	if err == nil || !strings.Contains(err.Error(), "migrate: list") {
		t.Errorf("got %v, want wrapped list error", err)
	}
}

func TestCmdMigrate_PutFailureCountedNotFatal(t *testing.T) {
	// PUT failing on one secret should be logged + counted, NOT abort
	// the whole loop. Sibling secrets must still migrate.
	withTestVault(t, "pw")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/secrets":
			_, _ = w.Write([]byte(`{"secrets":[{"name":"good","created_at":1,"updated_at":1},{"name":"bad","created_at":1,"updated_at":1}]}`))
		case r.Method == "GET":
			name := strings.TrimPrefix(r.URL.Path, "/v1/secrets/")
			_, _ = w.Write([]byte(`{"name":"` + name + `","value":"plain","created_at":1,"updated_at":1}`))
		case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/bad"):
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"error":"db down"}`))
		case r.Method == "PUT":
			_, _ = w.Write([]byte(`{"name":"good","created_at":1,"updated_at":2}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	envClient(t, srv.URL)

	var out bytes.Buffer
	err := cmdMigrate(context.Background(), nil, &out, constPrompt("pw"))
	if err == nil || !strings.Contains(err.Error(), "1 secret(s) failed") {
		t.Errorf("got %v, want '1 secret(s) failed'", err)
	}
	if !strings.Contains(out.String(), "migrated: good") {
		t.Errorf("'good' should have migrated despite 'bad' failing on PUT: %q", out.String())
	}
	if !strings.Contains(out.String(), "error: bad: put:") {
		t.Errorf("expected per-secret put error line for 'bad': %q", out.String())
	}
}

func TestCmdMigrate_ContextCanceledMidLoop(t *testing.T) {
	// Cancellation between iterations should surface as "interrupted"
	// without touching subsequent secrets. We can't reliably cancel
	// strictly after the first secret's PUT response is delivered
	// (the same ctx is in-flight), so we cancel BEFORE the migrate
	// even starts — the loop's top-of-iteration ctx.Err() check
	// catches it before the first request escapes.
	withTestVault(t, "pw")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the List call should fly out; once we're inside the loop,
		// ctx.Err() trips the early return before any further requests.
		if r.URL.Path == "/v1/secrets" && r.Method == "GET" {
			_, _ = w.Write([]byte(`{"secrets":[{"name":"first"},{"name":"second"}]}`))
			return
		}
		t.Errorf("unexpected request after pre-canceled context: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()
	envClient(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled before cmdMigrate starts

	var out bytes.Buffer
	err := cmdMigrate(ctx, nil, &out, constPrompt("pw"))
	if err == nil {
		t.Fatal("expected context-canceled error")
	}
	// Either wrapErr("migrate: list", ...) or wrapErr("migrate", ...)
	// is acceptable depending on whether the cancel lands during List
	// or at the top of the first loop iteration; both map context.Canceled
	// to "interrupted".
	if err.Error() != "interrupted" {
		t.Errorf("got %q, want %q (wrapErr should map context.Canceled)", err.Error(), "interrupted")
	}
}

func TestRun_MigrateDispatch(t *testing.T) {
	// Like the init dispatch test: a no-vault state lets us hit the
	// run() switch case and the migrate-specific early-exit without
	// needing a real TTY.
	t.Setenv("HUSH_CONFIG_DIR", t.TempDir())
	envClient(t, "https://example")

	var stdout, stderr bytes.Buffer
	code := run([]string{"migrate"}, nil, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (no vault)", code)
	}
	if !strings.Contains(stderr.String(), "hush init") {
		t.Errorf("stderr missing hint, got %q", stderr.String())
	}
}
