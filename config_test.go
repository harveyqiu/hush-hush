package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	envKeyB64  = base64.StdEncoding.EncodeToString(testKey())
	fileKey    = bytes.Repeat([]byte{0xAB}, 32)
	fileKeyB64 = base64.StdEncoding.EncodeToString(fileKey)
)

// fakeEnv returns getenv/readFile stand-ins backed by maps, so loadConfig
// can be tested without touching the process environment or disk.
func fakeEnv(env map[string]string, files map[string]string) (func(string) string, func(string) ([]byte, error)) {
	getenv := func(k string) string { return env[k] }
	readFile := func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
	}
	return getenv, readFile
}

func mustLoad(t *testing.T, env, files map[string]string) config {
	t.Helper()
	c, err := loadConfig(fakeEnv(env, files))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	return c
}

func TestLoadConfig_Defaults(t *testing.T) {
	c := mustLoad(t, map[string]string{"MASTER_KEY": envKeyB64}, nil)
	if c.listenAddr != "127.0.0.1:8080" {
		t.Errorf("listenAddr = %q, want 127.0.0.1:8080 (never all interfaces by default)", c.listenAddr)
	}
	if c.dbPath != "./hush.db" {
		t.Errorf("dbPath = %q", c.dbPath)
	}
	if c.rateLimitPerMinute != 60 || c.unauthRateLimitPerMinute != 10 {
		t.Errorf("rate limits = %d/%d, want 60/10", c.rateLimitPerMinute, c.unauthRateLimitPerMinute)
	}
	if len(c.trustedProxies) != 0 {
		t.Error("no proxy should be trusted by default")
	}
	if !c.adminAPI {
		t.Error("admin API should default to on")
	}
	if c.legacyToken != "" || len(c.warnings) != 0 {
		t.Errorf("legacyToken=%q warnings=%v, want none", c.legacyToken, c.warnings)
	}
	if !bytes.Equal(c.key, testKey()) || c.keySource != keySourceEnv {
		t.Errorf("key source %q, key mismatch=%v", c.keySource, !bytes.Equal(c.key, testKey()))
	}
}

func TestLoadConfig_ListenAddr(t *testing.T) {
	tests := []struct {
		name, listen, port, want string
		wantWarn, wantErr        bool
	}{
		{name: "default is loopback", want: "127.0.0.1:8080"},
		{name: "LISTEN_ADDR honoured", listen: "0.0.0.0:9000", want: "0.0.0.0:9000"},
		{name: "IPv6 LISTEN_ADDR", listen: "[::1]:8080", want: "[::1]:8080"},
		{name: "PORT is ignored with a warning", port: "3000", want: "127.0.0.1:8080", wantWarn: true},
		{name: "LISTEN_ADDR without port", listen: "0.0.0.0", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := map[string]string{"MASTER_KEY": envKeyB64, "LISTEN_ADDR": tt.listen, "PORT": tt.port}
			c, err := loadConfig(fakeEnv(env, nil))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got addr %q", c.listenAddr)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if c.listenAddr != tt.want {
				t.Errorf("listenAddr = %q, want %q", c.listenAddr, tt.want)
			}
			if (len(c.warnings) > 0) != tt.wantWarn {
				t.Errorf("warnings = %v, want warning=%v", c.warnings, tt.wantWarn)
			}
		})
	}
}

func TestLoadConfig_MasterKey(t *testing.T) {
	const path = "/run/secrets/master_key"
	tests := []struct {
		name       string
		env        map[string]string
		files      map[string]string
		wantKey    []byte
		wantSource string
		wantErr    string
	}{
		{name: "env", env: map[string]string{"MASTER_KEY": envKeyB64}, wantKey: testKey(), wantSource: keySourceEnv},
		{name: "file, trailing newline trimmed", env: map[string]string{"MASTER_KEY_FILE": path},
			files: map[string]string{path: fileKeyB64 + "\n"}, wantKey: fileKey, wantSource: keySourceFile},
		{name: "both set is ambiguous", env: map[string]string{"MASTER_KEY_FILE": path, "MASTER_KEY": envKeyB64},
			files: map[string]string{path: fileKeyB64}, wantErr: "only one"},
		{name: "file missing", env: map[string]string{"MASTER_KEY_FILE": path}, wantErr: "not found"},
		{name: "file bad base64", env: map[string]string{"MASTER_KEY_FILE": path},
			files: map[string]string{path: "!!!"}, wantErr: "invalid base64"},
		{name: "file wrong length", env: map[string]string{"MASTER_KEY_FILE": path},
			files: map[string]string{path: base64.StdEncoding.EncodeToString([]byte("short"))}, wantErr: "32 bytes"},
		{name: "env wrong length", env: map[string]string{"MASTER_KEY": base64.StdEncoding.EncodeToString([]byte("short"))}, wantErr: "32 bytes"},
		{name: "nothing set", env: map[string]string{}, wantErr: "master key missing"},
		{name: "systemd credentials no longer read", env: map[string]string{"CREDENTIALS_DIRECTORY": "/run/credentials/x"},
			files: map[string]string{"/run/credentials/x/master_key": fileKeyB64}, wantErr: "master key missing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := loadConfig(fakeEnv(tt.env, tt.files))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if !bytes.Equal(c.key, tt.wantKey) || c.keySource != tt.wantSource {
				t.Errorf("source = %q, key match = %v", c.keySource, bytes.Equal(c.key, tt.wantKey))
			}
		})
	}
}

// An unreadable key file (as opposed to an absent one) is an error.
func TestLoadConfig_KeyFileReadError(t *testing.T) {
	getenv, _ := fakeEnv(map[string]string{"MASTER_KEY_FILE": "/run/secrets/master_key"}, nil)
	readFile := func(string) ([]byte, error) { return nil, fs.ErrPermission }
	if _, err := loadConfig(getenv, readFile); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err = %v, want permission error", err)
	}
}

// Exercises the real os.ReadFile path, as serve() uses it.
func TestLoadConfig_KeyFileOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master_key")
	if err := os.WriteFile(path, []byte(fileKeyB64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	getenv, _ := fakeEnv(map[string]string{"MASTER_KEY_FILE": path}, nil)
	c, err := loadConfig(getenv, os.ReadFile)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !bytes.Equal(c.key, fileKey) || c.keySource != keySourceFile {
		t.Errorf("source = %q, key match = %v", c.keySource, bytes.Equal(c.key, fileKey))
	}
}

// Error messages go to the log; they must never echo the key.
func TestLoadConfig_ErrorsDoNotLeakKey(t *testing.T) {
	secretish := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdefXX"))
	for _, env := range []map[string]string{
		{"MASTER_KEY": secretish},
		{"MASTER_KEY": secretish + "!"},
	} {
		_, err := loadConfig(fakeEnv(env, nil))
		if err == nil {
			t.Fatal("want error")
		}
		if strings.Contains(err.Error(), secretish[:8]) {
			t.Errorf("error %q contains key material", err)
		}
	}
}

func TestLoadConfig_RateLimits(t *testing.T) {
	tests := []struct {
		name, perToken, unauth string
		wantToken, wantUnauth  int
		wantErr                string
	}{
		{name: "defaults", wantToken: 60, wantUnauth: 10},
		{name: "overrides", perToken: "120", unauth: "5", wantToken: 120, wantUnauth: 5},
		{name: "zero", perToken: "0", wantErr: "RATE_LIMIT_PER_MINUTE"},
		{name: "negative", perToken: "-1", wantErr: "RATE_LIMIT_PER_MINUTE"},
		{name: "not an integer", perToken: "1.5", wantErr: "RATE_LIMIT_PER_MINUTE"},
		{name: "unauth garbage", unauth: "ten", wantErr: "UNAUTH_RATE_LIMIT_PER_MINUTE"},
		{name: "unauth zero", unauth: "0", wantErr: "UNAUTH_RATE_LIMIT_PER_MINUTE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := map[string]string{
				"MASTER_KEY":                   envKeyB64,
				"RATE_LIMIT_PER_MINUTE":        tt.perToken,
				"UNAUTH_RATE_LIMIT_PER_MINUTE": tt.unauth,
			}
			c, err := loadConfig(fakeEnv(env, nil))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if c.rateLimitPerMinute != tt.wantToken || c.unauthRateLimitPerMinute != tt.wantUnauth {
				t.Errorf("got %d/%d, want %d/%d", c.rateLimitPerMinute, c.unauthRateLimitPerMinute, tt.wantToken, tt.wantUnauth)
			}
		})
	}
}

func TestLoadConfig_TrustedProxies(t *testing.T) {
	tests := []struct {
		val     string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"172.17.0.1", 1, false},
		{"172.16.0.0/12, 10.0.0.0/8", 2, false},
		{"::1, fd00::/8", 2, false},
		{"0.0.0.0/0", 0, true},
		{"::/0", 0, true},
		{"not-an-ip", 0, true},
		{"10.0.0.0/33", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.val, func(t *testing.T) {
			env := map[string]string{"MASTER_KEY": envKeyB64, "TRUSTED_PROXIES": tt.val}
			c, err := loadConfig(fakeEnv(env, nil))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && len(c.trustedProxies) != tt.want {
				t.Errorf("got %d networks, want %d", len(c.trustedProxies), tt.want)
			}
		})
	}
	// The removed variable must not be silently ignored.
	env := map[string]string{"MASTER_KEY": envKeyB64, "TRUST_PROXY_HEADERS": "true"}
	if _, err := loadConfig(fakeEnv(env, nil)); err == nil || !strings.Contains(err.Error(), "TRUSTED_PROXIES") {
		t.Errorf("TRUST_PROXY_HEADERS: err = %v, want a pointer to TRUSTED_PROXIES", err)
	}
}

func TestLoadConfig_AdminAPI(t *testing.T) {
	for val, want := range map[string]bool{"": true, "true": true, "false": false, "0": false} {
		c := mustLoad(t, map[string]string{"MASTER_KEY": envKeyB64, "ADMIN_API": val}, nil)
		if c.adminAPI != want {
			t.Errorf("ADMIN_API=%q: got %v, want %v", val, c.adminAPI, want)
		}
	}
	if _, err := loadConfig(fakeEnv(map[string]string{"MASTER_KEY": envKeyB64, "ADMIN_API": "maybe"}, nil)); err == nil {
		t.Error("ADMIN_API=maybe should be rejected")
	}
}

func TestLoadConfig_PassThrough(t *testing.T) {
	c := mustLoad(t, map[string]string{
		"MASTER_KEY": envKeyB64,
		"DB_PATH":    "/var/lib/hush/hush.db",
		"AUTH_TOKEN": legacyToken,
	}, nil)
	if c.dbPath != "/var/lib/hush/hush.db" || c.legacyToken != legacyToken {
		t.Errorf("dbPath=%q legacyToken set=%v", c.dbPath, c.legacyToken == legacyToken)
	}
}
