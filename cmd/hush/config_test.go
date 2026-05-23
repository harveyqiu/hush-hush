package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveConfig_Precedence(t *testing.T) {
	tests := []struct {
		name      string
		file      *Config
		envURL    string
		envToken  string
		flagURL   string
		flagToken string
		wantURL   string
		wantToken string
	}{
		{
			name:      "file only",
			file:      &Config{URL: "https://file.example", Token: "file-tok"},
			wantURL:   "https://file.example",
			wantToken: "file-tok",
		},
		{
			name:      "env overrides file (url only)",
			file:      &Config{URL: "https://file.example", Token: "file-tok"},
			envURL:    "https://env.example",
			wantURL:   "https://env.example",
			wantToken: "file-tok",
		},
		{
			name:      "flag overrides env and file",
			file:      &Config{URL: "https://file.example", Token: "file-tok"},
			envURL:    "https://env.example",
			envToken:  "env-tok",
			flagURL:   "https://flag.example",
			flagToken: "flag-tok",
			wantURL:   "https://flag.example",
			wantToken: "flag-tok",
		},
		{
			name:      "missing file is not an error",
			envURL:    "https://env-only.example",
			envToken:  "env-only-tok",
			wantURL:   "https://env-only.example",
			wantToken: "env-only-tok",
		},
		{
			name: "empty result when nothing set",
		},
		{
			name:      "empty flag string does not override env",
			envURL:    "https://env.example",
			envToken:  "env-tok",
			flagURL:   "",
			flagToken: "",
			wantURL:   "https://env.example",
			wantToken: "env-tok",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("HUSH_CONFIG_DIR", dir)
			t.Setenv("HUSH_URL", tt.envURL)
			t.Setenv("HUSH_TOKEN", tt.envToken)

			if tt.file != nil {
				if err := saveConfigFile(*tt.file); err != nil {
					t.Fatalf("save config: %v", err)
				}
			}

			got, err := resolveConfig(tt.flagURL, tt.flagToken)
			if err != nil {
				t.Fatalf("resolveConfig: %v", err)
			}
			if got.URL != tt.wantURL {
				t.Errorf("URL: got %q, want %q", got.URL, tt.wantURL)
			}
			if got.Token != tt.wantToken {
				t.Errorf("Token: got %q, want %q", got.Token, tt.wantToken)
			}
		})
	}
}

func TestSaveConfigFile_PermsAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)

	cfg := Config{URL: "https://example", Token: "tok-123"}
	if err := saveConfigFile(cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	p := filepath.Join(dir, "config.json")
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Windows doesn't round-trip Unix-style perm bits through os.Stat;
	// the perm guarantee only meaningfully applies on Unix-likes.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("perm: got %o, want 0600", info.Mode().Perm())
	}

	loaded, err := loadConfigFile()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded != cfg {
		t.Errorf("round trip: got %+v, want %+v", loaded, cfg)
	}
}

func TestLoadConfigFile_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigFile(); err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestConfigPath_DefaultsToOSUserConfigDir(t *testing.T) {
	// With HUSH_CONFIG_DIR explicitly empty, configPath falls back to
	// os.UserConfigDir + "hush/config.json".
	t.Setenv("HUSH_CONFIG_DIR", "")
	p, err := configPath()
	if err != nil {
		t.Fatalf("configPath: %v", err)
	}
	if !strings.HasSuffix(filepath.ToSlash(p), "hush/config.json") {
		t.Errorf("path %q does not end with hush/config.json", p)
	}
}

func TestLoadConfigFile_Missing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HUSH_CONFIG_DIR", dir)
	cfg, err := loadConfigFile()
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if cfg != (Config{}) {
		t.Errorf("expected zero Config, got %+v", cfg)
	}
}
