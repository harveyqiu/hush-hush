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
	credKey    = bytes.Repeat([]byte{0xAB}, 32)
	credKeyB64 = base64.StdEncoding.EncodeToString(credKey)
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
	if c.trustProxy {
		t.Error("trustProxy defaults to true, want false")
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
		name     string
		listen   string
		port     string
		want     string
		wantWarn bool
		wantErr  bool
	}{
		{name: "default is loopback", want: "127.0.0.1:8080"},
		{name: "PORT alone stays on loopback", port: "3000", want: "127.0.0.1:3000", wantWarn: true},
		{name: "LISTEN_ADDR honoured", listen: "0.0.0.0:9000", want: "0.0.0.0:9000"},
		{name: "LISTEN_ADDR wins over PORT", listen: "127.0.0.1:9000", port: "3000", want: "127.0.0.1:9000"},
		{name: "IPv6 LISTEN_ADDR", listen: "[::1]:8080", want: "[::1]:8080"},
		{name: "LISTEN_ADDR without port", listen: "0.0.0.0", wantErr: true},
		{name: "PORT not a number", port: "http", wantErr: true},
		{name: "PORT out of range", port: "70000", wantErr: true},
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
			gotWarn := len(c.warnings) > 0
			if gotWarn != tt.wantWarn {
				t.Fatalf("warnings = %v, want warning=%v", c.warnings, tt.wantWarn)
			}
			if gotWarn && !strings.Contains(c.warnings[0], "LISTEN_ADDR=0.0.0.0:"+tt.port) {
				t.Errorf("warning %q should tell the operator how to expose the port", c.warnings[0])
			}
		})
	}
}

func TestLoadConfig_MasterKey(t *testing.T) {
	const dir = "/run/credentials/hush.service"
	credPath := filepath.Join(dir, "master_key")
	tests := []struct {
		name       string
		env        map[string]string
		files      map[string]string
		wantKey    []byte
		wantSource string
		wantErr    string
	}{
		{
			name:       "env only",
			env:        map[string]string{"MASTER_KEY": envKeyB64},
			wantKey:    testKey(),
			wantSource: keySourceEnv,
		},
		{
			name:       "credential preferred over env",
			env:        map[string]string{"MASTER_KEY": envKeyB64, "CREDENTIALS_DIRECTORY": dir},
			files:      map[string]string{credPath: credKeyB64},
			wantKey:    credKey,
			wantSource: keySourceCredentials,
		},
		{
			name:       "credential whitespace trimmed",
			env:        map[string]string{"CREDENTIALS_DIRECTORY": dir},
			files:      map[string]string{credPath: "  " + credKeyB64 + "\n"},
			wantKey:    credKey,
			wantSource: keySourceCredentials,
		},
		{
			name:       "credentials dir without master_key falls back to env",
			env:        map[string]string{"MASTER_KEY": envKeyB64, "CREDENTIALS_DIRECTORY": dir},
			wantKey:    testKey(),
			wantSource: keySourceEnv,
		},
		{
			name:    "credentials dir without master_key and no env",
			env:     map[string]string{"CREDENTIALS_DIRECTORY": dir},
			wantErr: "master key missing",
		},
		{
			name:    "neither source",
			env:     map[string]string{},
			wantErr: "master key missing",
		},
		{
			// A broken credential must not silently fall back to a
			// different key from the environment.
			name:    "bad base64 credential does not fall back",
			env:     map[string]string{"MASTER_KEY": envKeyB64, "CREDENTIALS_DIRECTORY": dir},
			files:   map[string]string{credPath: "not*base64!"},
			wantErr: "invalid base64",
		},
		{
			name:    "short credential",
			env:     map[string]string{"CREDENTIALS_DIRECTORY": dir},
			files:   map[string]string{credPath: base64.StdEncoding.EncodeToString(make([]byte, 16))},
			wantErr: "must decode to 32 bytes, got 16",
		},
		{
			name:    "env bad base64",
			env:     map[string]string{"MASTER_KEY": "%%%"},
			wantErr: "MASTER_KEY: invalid base64",
		},
		{
			name:    "env wrong length",
			env:     map[string]string{"MASTER_KEY": base64.StdEncoding.EncodeToString(make([]byte, 33))},
			wantErr: "MASTER_KEY: must decode to 32 bytes, got 33",
		},
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
				t.Errorf("source = %q (want %q), key match = %v", c.keySource, tt.wantSource, bytes.Equal(c.key, tt.wantKey))
			}
		})
	}
}

// An unreadable credential (as opposed to an absent one) is an error.
func TestLoadConfig_CredentialReadError(t *testing.T) {
	getenv, _ := fakeEnv(map[string]string{"MASTER_KEY": envKeyB64, "CREDENTIALS_DIRECTORY": "/creds"}, nil)
	readFile := func(string) ([]byte, error) { return nil, fs.ErrPermission }
	if _, err := loadConfig(getenv, readFile); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err = %v, want permission error", err)
	}
}

// Exercises the real os.ReadFile path, as serve() uses it.
func TestLoadConfig_CredentialFileOnDisk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "master_key"), []byte(credKeyB64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	getenv, _ := fakeEnv(map[string]string{"CREDENTIALS_DIRECTORY": dir}, nil)
	c, err := loadConfig(getenv, os.ReadFile)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !bytes.Equal(c.key, credKey) || c.keySource != keySourceCredentials {
		t.Errorf("source = %q, key match = %v", c.keySource, bytes.Equal(c.key, credKey))
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

func TestLoadConfig_TrustProxyHeaders(t *testing.T) {
	tests := []struct {
		val     string
		want    bool
		wantErr bool
	}{
		{"", false, false},
		{"false", false, false},
		{"true", true, false},
		{"1", true, false},
		{"yes", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.val, func(t *testing.T) {
			env := map[string]string{"MASTER_KEY": envKeyB64, "TRUST_PROXY_HEADERS": tt.val}
			c, err := loadConfig(fakeEnv(env, nil))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && c.trustProxy != tt.want {
				t.Errorf("trustProxy = %v, want %v", c.trustProxy, tt.want)
			}
		})
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
