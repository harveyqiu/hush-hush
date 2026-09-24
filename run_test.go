package main

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serverEnv is a minimal valid environment for runServer on a temp DB and
// a random loopback port.
func serverEnv(t *testing.T, extra map[string]string) (map[string]string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hush.db")
	env := map[string]string{
		"MASTER_KEY":  base64.StdEncoding.EncodeToString(testKey()),
		"DB_PATH":     path,
		"LISTEN_ADDR": "127.0.0.1:0",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env, path
}

// startServer runs runServer in the background and returns its address
// and a stop function that cancels it and returns runServer's error.
func startServer(t *testing.T, env map[string]string) (string, func() error) {
	t.Helper()
	getenv, readFile := fakeEnv(env, nil)
	ctx, cancel := context.WithCancel(context.Background())
	addrc := make(chan string, 1)
	errc := make(chan error, 1)
	go func() { errc <- runServer(ctx, getenv, readFile, func(a string) { addrc <- a }) }()
	select {
	case addr := <-addrc:
		return addr, func() error { cancel(); return <-errc }
	case err := <-errc:
		cancel()
		t.Fatalf("runServer exited early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("runServer did not start")
	}
	return "", nil
}

func TestRunServer_ServesAndShutsDown(t *testing.T) {
	logs := captureLogs(t)
	env, path := serverEnv(t, map[string]string{"PORT": "1"}) // removed setting -> warning
	// An admin token close to expiry triggers the startup reminder.
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	soon := time.Now().Add(2 * 24 * time.Hour)
	if err := insertToken(context.Background(), db, tokenSpec{name: "adm", role: roleAdmin, expiresAt: &soon}, testToken, time.Now()); err != nil {
		t.Fatal(err)
	}
	db.Close()

	addr, stop := startServer(t, env)
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-Request-ID") == "" {
		t.Errorf("healthz: %d, request id %q", resp.StatusCode, resp.Header.Get("X-Request-ID"))
	}
	req, _ := http.NewRequest("GET", "http://"+addr+"/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Errorf("authenticated list: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}
	if err := stop(); err != nil {
		t.Errorf("shutdown: %v", err)
	}
	for _, want := range []string{"PORT is no longer supported", "admin tokens expire within 7 days", "listening", "shutdown: done"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs missing %q", want)
		}
	}
	if strings.Contains(logs.String(), env["MASTER_KEY"]) {
		t.Error("master key in logs")
	}
}

func TestRunServer_WarnsWithoutTokens(t *testing.T) {
	logs := captureLogs(t)
	env, _ := serverEnv(t, nil)
	_, stop := startServer(t, env)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "no active tokens") {
		t.Errorf("expected the no-tokens warning: %s", logs.String())
	}
}

func TestRunServer_StartupErrors(t *testing.T) {
	captureLogs(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	cases := map[string]map[string]string{
		"bad config":  {"MASTER_KEY": "not-base64!"},
		"db dir gone": {"DB_PATH": filepath.Join(t.TempDir(), "missing", "hush.db")},
		"port in use": {"LISTEN_ADDR": busy.Addr().String()},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			env, _ := serverEnv(t, extra)
			getenv, readFile := fakeEnv(env, nil)
			if err := runServer(context.Background(), getenv, readFile, nil); err == nil {
				t.Error("want an error")
			}
		})
	}
}

// Database failures during the startup checks stop the server.
func TestRunServer_StartupCheckFailures(t *testing.T) {
	captureLogs(t)
	useFaultDriver(t)
	for name, match := range map[string]string{
		"token count":  "SELECT COUNT(*) FROM tokens",
		"expiry query": "expires_at <= ?",
	} {
		t.Run(name, func(t *testing.T) {
			env, _ := serverEnv(t, nil)
			injectFault(t, "query", match, 0)
			getenv, readFile := fakeEnv(env, nil)
			if err := runServer(context.Background(), getenv, readFile, nil); err == nil {
				t.Error("want an error")
			}
		})
	}
	t.Run("expiry scan", func(t *testing.T) {
		env, path := serverEnv(t, nil)
		db, err := openDB(path)
		if err != nil {
			t.Fatal(err)
		}
		soon := time.Now().Add(time.Hour)
		if err := insertToken(context.Background(), db, tokenSpec{name: "adm", role: roleAdmin, expiresAt: &soon}, testToken, time.Now()); err != nil {
			t.Fatal(err)
		}
		db.Close()
		injectNullColumn(t, "expires_at <= ?", 0)
		getenv, readFile := fakeEnv(env, nil)
		if err := runServer(context.Background(), getenv, readFile, nil); err == nil {
			t.Error("want an error")
		}
	})
}

func TestNewServer_RejectsBadKey(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a 16-byte key must panic")
		}
	}()
	newServer(nil, make([]byte, 16))
}
