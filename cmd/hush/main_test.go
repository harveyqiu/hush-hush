package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_HelpExitsZero(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"help"}, nil, &out, &errBuf)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "hush") {
		t.Errorf("expected usage text in stdout, got %q", out.String())
	}
}

func TestRun_NoArgsExitsTwo(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run(nil, nil, &out, &errBuf)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRun_UnknownCommandExitsTwo(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"nosuch"}, nil, &out, &errBuf)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "unknown command") {
		t.Errorf("expected 'unknown command' in stderr, got %q", errBuf.String())
	}
}

func TestRun_LoginDispatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)
	var out, errBuf bytes.Buffer
	code := run([]string{"login", "--url", "https://example", "--token", "tok"}, nil, &out, &errBuf)
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (stderr=%s)", code, errBuf.String())
	}
}

func TestRun_LoginMissingFlagsExitsOne(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)
	var out, errBuf bytes.Buffer
	code := run([]string{"login", "--url", "https://example"}, nil, &out, &errBuf)
	if code != 1 {
		t.Errorf("exit code = %d, want 1, stderr=%s", code, errBuf.String())
	}
}

func TestCmdLogin_WritesConfigAndReportsPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)

	var out bytes.Buffer
	if err := cmdLogin([]string{"--url", "https://example", "--token", "tok"}, &out); err != nil {
		t.Fatalf("cmdLogin: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	if !strings.Contains(string(raw), "https://example") || !strings.Contains(string(raw), "tok") {
		t.Errorf("config missing expected values: %s", raw)
	}
	if !strings.Contains(out.String(), "config saved to") {
		t.Errorf("expected success message on injected stdout, got %q", out.String())
	}
}

func TestCmdLogin_MissingFlags(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)

	var out bytes.Buffer
	if err := cmdLogin([]string{"--url", "https://example"}, &out); err == nil {
		t.Error("expected error when --token missing")
	}
	if err := cmdLogin([]string{"--token", "tok"}, &out); err == nil {
		t.Error("expected error when --url missing")
	}
}

func TestCmdLogin_UnknownFlagReturnsError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)

	var out bytes.Buffer
	err := cmdLogin([]string{"--url", "https://example", "--token", "tok", "--bogus"}, &out)
	if err == nil {
		t.Fatal("expected parse error from unknown flag, got nil")
	}
	if !strings.Contains(err.Error(), "login:") {
		t.Errorf("expected error to be wrapped with 'login:', got %v", err)
	}
}

func TestCmdHealth_ReachableAndAuthOK(t *testing.T) {
	var healthHit, listHit bool
	var listAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			healthHit = true
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		case "/v1/secrets":
			listHit = true
			listAuth = r.Header.Get("Authorization")
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []any{}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)
	t.Setenv("HUSH_URL", "")
	t.Setenv("HUSH_TOKEN", "")

	var out bytes.Buffer
	err := cmdHealth(context.Background(), []string{"--url", srv.URL, "--token", "tok"}, &out)
	if err != nil {
		t.Fatalf("cmdHealth: %v", err)
	}
	if !healthHit {
		t.Error("/healthz not hit")
	}
	if !listHit {
		t.Error("/v1/secrets not hit")
	}
	if listAuth != "Bearer tok" {
		t.Errorf("auth header = %q, want %q", listAuth, "Bearer tok")
	}
	if !strings.Contains(out.String(), "reachable") || !strings.Contains(out.String(), "auth: ok") {
		t.Errorf("expected reachable + auth ok on injected stdout, got %q", out.String())
	}
}

func TestCmdHealth_NoTokenSkipsAuthCheck(t *testing.T) {
	var listHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secrets" {
			listHit = true
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)
	t.Setenv("HUSH_URL", "")
	t.Setenv("HUSH_TOKEN", "")

	var out bytes.Buffer
	err := cmdHealth(context.Background(), []string{"--url", srv.URL}, &out)
	if err != nil {
		t.Fatalf("cmdHealth: %v", err)
	}
	if listHit {
		t.Error("/v1/secrets should not be hit when no token is configured")
	}
	if !strings.Contains(out.String(), "auth: skipped") {
		t.Errorf("expected 'auth: skipped' on injected stdout, got %q", out.String())
	}
}

func TestCmdHealth_NoURLConfigured(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)
	t.Setenv("HUSH_URL", "")
	t.Setenv("HUSH_TOKEN", "")

	var out bytes.Buffer
	err := cmdHealth(context.Background(), nil, &out)
	if err == nil {
		t.Fatal("expected error when no URL configured")
	}
	if !strings.Contains(err.Error(), "no URL configured") {
		t.Errorf("got %v, want 'no URL configured' error", err)
	}
}

func TestCmdHealth_AuthCheckFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secrets" {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)
	t.Setenv("HUSH_URL", "")
	t.Setenv("HUSH_TOKEN", "")

	var out bytes.Buffer
	err := cmdHealth(context.Background(), []string{"--url", srv.URL, "--token", "wrong"}, &out)
	if err == nil {
		t.Fatal("expected auth error")
	}
	if !strings.Contains(err.Error(), "auth check failed") {
		t.Errorf("got %v, want 'auth check failed'", err)
	}
}

func TestCmdHealth_ContextCanceledShowsFriendlyMessage(t *testing.T) {
	// Server hangs so the context cancellation wins the race.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)
	t.Setenv("HUSH_URL", "")
	t.Setenv("HUSH_TOKEN", "")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled — first request returns context.Canceled

	var out bytes.Buffer
	err := cmdHealth(ctx, []string{"--url", srv.URL, "--token", "tok"}, &out)
	if err == nil {
		t.Fatal("expected error from canceled context")
	}
	if err.Error() != "interrupted" {
		t.Errorf("got %q, want %q", err.Error(), "interrupted")
	}
}
