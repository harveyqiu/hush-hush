package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the resolved CLI configuration. Precedence applied by
// resolveConfig is flag > env > file (highest wins).
type Config struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// resolveConfig merges file, env vars, and flag values. Empty-string flag
// values are treated as "not set" so they never override a populated
// env or file value.
func resolveConfig(flagURL, flagToken string) (Config, error) {
	cfg, err := loadConfigFile()
	if err != nil {
		return Config{}, err
	}
	if v := os.Getenv("HUSH_URL"); v != "" {
		cfg.URL = v
	}
	if v := os.Getenv("HUSH_TOKEN"); v != "" {
		cfg.Token = v
	}
	if flagURL != "" {
		cfg.URL = flagURL
	}
	if flagToken != "" {
		cfg.Token = flagToken
	}
	return cfg, nil
}

// loadConfigFile reads the config file if present. A missing file is not
// an error (env/flag may supply everything), but a corrupt file IS an
// error so the user notices instead of silently falling back.
func loadConfigFile() (Config, error) {
	var cfg Config
	p, err := configPath()
	if err != nil {
		return cfg, err
	}
	// #nosec G304 -- p is computed by configPath() from our own constants
	// (HUSH_CONFIG_DIR override or os.UserConfigDir). There is no untrusted
	// external input on this path; the user is reading their own config
	// file from their own machine.
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", p, err)
	}
	return cfg, nil
}

// saveConfigFile writes cfg to the config path with mode 0600. Creates the
// parent directory with 0700 if it doesn't exist.
func saveConfigFile(cfg Config) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// configPath returns the canonical config file location.
//
// HUSH_CONFIG_DIR is an explicit override (useful for tests and for users
// who want the file outside the OS-default config dir). Otherwise we use
// os.UserConfigDir, which resolves to ~/.config on Linux (honoring
// XDG_CONFIG_HOME), %AppData% on Windows, and ~/Library/Application Support
// on macOS.
func configPath() (string, error) {
	if dir := os.Getenv("HUSH_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "config.json"), nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "hush", "config.json"), nil
}
