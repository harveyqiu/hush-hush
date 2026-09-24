package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Error paths of the CLI client: bad flags, unusable config/vault paths,
// network and decode failures.

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func runCode(args ...string) int {
	var out strings.Builder
	return run(args, strings.NewReader(""), &out, &out)
}

func TestRun_BadFlagsPerCommand(t *testing.T) {
	setEnvConfig(t, "http://127.0.0.1:1", "tok")
	for _, cmd := range []string{"health", "get", "put", "delete", "list", "init", "migrate"} {
		if code := runCode(cmd, "--bogus"); code != 1 {
			t.Errorf("%s --bogus: exit %d, want 1", cmd, code)
		}
	}
}

// Every network command fails cleanly when no URL is configured or the
// config file is unreadable.
func TestNetworkCommands_ConfigErrors(t *testing.T) {
	cmds := [][]string{{"health"}, {"get", "a"}, {"put", "a", "v"}, {"delete", "a"}, {"list"}, {"migrate"}}
	t.Run("no URL", func(t *testing.T) {
		t.Setenv("HUSH_CONFIG_DIR", t.TempDir())
		t.Setenv("HUSH_URL", "")
		t.Setenv("HUSH_TOKEN", "tok")
		for _, c := range cmds[:5] {
			if code := runCode(c...); code != 1 {
				t.Errorf("%v: exit %d", c, code)
			}
		}
	})
	t.Run("corrupt config", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HUSH_CONFIG_DIR", dir)
		t.Setenv("HUSH_URL", "")
		t.Setenv("HUSH_TOKEN", "")
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, c := range cmds[:5] {
			if code := runCode(c...); code != 1 {
				t.Errorf("%v: exit %d", c, code)
			}
		}
	})
	t.Run("migrate with a vault but no URL", func(t *testing.T) {
		t.Setenv("HUSH_CONFIG_DIR", t.TempDir())
		t.Setenv("HUSH_URL", "")
		withTestVault(t, "pw")
		if err := cmdMigrate(context.Background(), nil, &strings.Builder{}, constPrompt("pw")); err == nil {
			t.Error("want an error")
		}
	})
}

// No HUSH_CONFIG_DIR, XDG_CONFIG_HOME or HOME: the OS config dir can't be
// resolved, and every path-dependent operation says so.
func TestConfigPath_Unresolvable(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "plan9" {
		t.Skip("os.UserConfigDir uses other variables here")
	}
	t.Setenv("HUSH_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("HUSH_URL", "")
	t.Setenv("HUSH_TOKEN", "")
	if _, err := configPath(); err == nil {
		t.Fatal("expected configPath to fail")
	}
	if _, err := loadConfigFile(); err == nil {
		t.Error("loadConfigFile")
	}
	if _, err := resolveConfig("", ""); err == nil {
		t.Error("resolveConfig")
	}
	if _, err := saveConfigFile(Config{}); err == nil {
		t.Error("saveConfigFile")
	}
	if _, err := vaultPath(); err == nil {
		t.Error("vaultPath")
	}
	if _, err := loadVault(); err == nil {
		t.Error("loadVault")
	}
	if err := saveNewVault(VaultConfig{}); err == nil {
		t.Error("saveNewVault")
	}
	if err := cmdInit(nil, &strings.Builder{}, neverPrompt(t)); err == nil {
		t.Error("cmdInit")
	}
}

// Paths that exist but are the wrong kind of thing.
func TestConfigAndVault_UnusablePaths(t *testing.T) {
	t.Run("config.json is a directory", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HUSH_CONFIG_DIR", dir)
		if err := os.Mkdir(filepath.Join(dir, "config.json"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfigFile(); err == nil {
			t.Error("load")
		}
		if _, err := saveConfigFile(Config{URL: "u"}); err == nil {
			t.Error("save")
		}
	})
	t.Run("config dir is a file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HUSH_CONFIG_DIR", filepath.Join(file, "sub"))
		if code := runCode("login", "--url", "u", "--token", "t"); code != 1 {
			t.Errorf("login: exit %d", code)
		}
		if err := saveNewVault(VaultConfig{}); err == nil {
			t.Error("saveNewVault")
		}
		// stat of vault.json fails with ENOTDIR rather than "not found".
		t.Setenv("HUSH_CONFIG_DIR", file)
		if err := cmdInit(nil, &strings.Builder{}, neverPrompt(t)); err == nil {
			t.Error("cmdInit")
		}
	})
	t.Run("vault.json is a directory", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HUSH_CONFIG_DIR", dir)
		if err := os.Mkdir(filepath.Join(dir, vaultFileName), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := loadVault(); err == nil || errors.Is(err, errVaultMissing) {
			t.Errorf("loadVault: %v", err)
		}
		if _, err := unlockIfPresent(neverPrompt(t)); err == nil {
			t.Error("unlockIfPresent")
		}
	})
	t.Run("vault dir can't hold files", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("uses /proc")
		}
		// /proc/self exists but new files can't be created in it, even
		// as root: the O_EXCL create itself fails.
		t.Setenv("HUSH_CONFIG_DIR", "/proc/self")
		if err := saveNewVault(VaultConfig{}); err == nil || errors.Is(err, errVaultExists) {
			t.Errorf("saveNewVault: %v", err)
		}
		if err := cmdInit(nil, &strings.Builder{}, constPrompt("pw")); err == nil {
			t.Error("cmdInit")
		}
	})
}

func TestCmdInit_PromptErrors(t *testing.T) {
	calls := 0
	failSecond := func(string) (string, error) {
		calls++
		if calls == 2 {
			return "", errors.New("eof")
		}
		return "pw", nil
	}
	for name, fn := range map[string]func(string) (string, error){
		"first prompt":  func(string) (string, error) { return "", errors.New("eof") },
		"second prompt": failSecond,
	} {
		t.Setenv("HUSH_CONFIG_DIR", t.TempDir())
		if err := cmdInit(nil, &strings.Builder{}, fn); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	// Prompt failure while unlocking an existing vault.
	t.Setenv("HUSH_CONFIG_DIR", t.TempDir())
	withTestVault(t, "pw")
	if _, err := unlockIfPresent(func(string) (string, error) { return "", errors.New("eof") }); err == nil {
		t.Error("unlock prompt error")
	}
}

func TestClient_TransportAndDecodeErrors(t *testing.T) {
	ctx := context.Background()
	// Unbuildable request.
	bad := newClient("http://bad host\x7f", "t")
	if _, err := bad.Get(ctx, "a"); err == nil {
		t.Error("bad URL")
	}
	// Nothing listening.
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	down := newClient(closed.URL, "t")
	if err := down.AuthCheck(ctx); err == nil {
		t.Error("AuthCheck")
	}
	if _, err := down.Get(ctx, "a"); err == nil {
		t.Error("Get")
	}
	if _, err := down.Put(ctx, "a", "v"); err == nil {
		t.Error("Put")
	}
	if err := down.Delete(ctx, "a"); err == nil {
		t.Error("Delete")
	}
	// 200 with a body that isn't JSON.
	junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	defer junk.Close()
	jc := newClient(junk.URL, "t")
	if _, err := jc.Get(ctx, "a"); err == nil {
		t.Error("Get decode")
	}
	if _, err := jc.Put(ctx, "a", "v"); err == nil {
		t.Error("Put decode")
	}
	if _, err := jc.List(ctx); err == nil {
		t.Error("List decode")
	}
}

func TestValue_ReadErrors(t *testing.T) {
	if _, err := readFromStream(errReader{}); err == nil {
		t.Error("readFromStream")
	}
}

func TestPromptNoEcho(t *testing.T) {
	prev := readPassword
	t.Cleanup(func() { readPassword = prev })
	readPassword = func(int) ([]byte, error) { return []byte("s3cret"), nil }
	if v, err := promptNoEcho("p: "); err != nil || v != "s3cret" {
		t.Errorf("got %q %v", v, err)
	}
	readPassword = func(int) ([]byte, error) { return nil, errors.New("not a tty") }
	if _, err := promptNoEcho("p: "); err == nil {
		t.Error("want error")
	}
}

// Ctrl+C between secrets stops the migration without touching the rest.
func TestCmdMigrate_CancelledMidway(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secrets" {
			cancel()
			_, _ = w.Write([]byte(`{"secrets":[{"name":"a"},{"name":"b"}]}`))
			return
		}
		t.Errorf("unexpected request %s after cancel", r.URL.Path)
	}))
	defer srv.Close()
	setEnvConfig(t, srv.URL, "tok")
	withTestVault(t, "pw")
	err := cmdMigrate(ctx, nil, &strings.Builder{}, constPrompt("pw"))
	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Errorf("err = %v, want interrupted", err)
	}
}
