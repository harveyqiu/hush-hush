package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultListenAddr = "127.0.0.1:8080"
	defaultDBPath     = "./hush.db"
	// credentialKeyFile is the systemd credential name for the master key
	// (LoadCredential=master_key:/etc/hush/master_key in the unit).
	credentialKeyFile = "master_key"

	keySourceCredentials = "credentials"
	keySourceEnv         = "env"
)

// config is everything serve() needs from the environment, already
// validated. The key is held here only long enough to build the server.
type config struct {
	listenAddr               string
	dbPath                   string
	key                      []byte
	keySource                string
	legacyToken              string
	rateLimitPerMinute       int
	unauthRateLimitPerMinute int
	trustProxy               bool
	// warnings are non-fatal problems for the caller to log; loadConfig
	// itself stays free of side effects so it can be tested directly.
	warnings []string
}

// loadConfig reads and validates the server configuration. getenv and
// readFile are injected (os.Getenv / os.ReadFile in production) so tests
// can exercise every branch without touching the process environment.
// Returned errors never contain key material.
func loadConfig(getenv func(string) string, readFile func(string) ([]byte, error)) (config, error) {
	c := config{
		dbPath:      defaultDBPath,
		legacyToken: getenv("AUTH_TOKEN"),
	}
	if v := getenv("DB_PATH"); v != "" {
		c.dbPath = v
	}

	addr, warn, err := listenAddr(getenv("LISTEN_ADDR"), getenv("PORT"))
	if err != nil {
		return config{}, err
	}
	c.listenAddr = addr
	if warn != "" {
		c.warnings = append(c.warnings, warn)
	}

	if c.key, c.keySource, err = masterKey(getenv, readFile); err != nil {
		return config{}, err
	}

	if c.rateLimitPerMinute, err = positiveInt(getenv, "RATE_LIMIT_PER_MINUTE", defaultRateLimitPerMinute); err != nil {
		return config{}, err
	}
	if c.unauthRateLimitPerMinute, err = positiveInt(getenv, "UNAUTH_RATE_LIMIT_PER_MINUTE", defaultUnauthRateLimitPerMinute); err != nil {
		return config{}, err
	}

	if v := getenv("TRUST_PROXY_HEADERS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return config{}, fmt.Errorf("TRUST_PROXY_HEADERS: must be true or false, got %q", v)
		}
		c.trustProxy = b
	}
	return c, nil
}

// listenAddr resolves the bind address. The default is loopback-only:
// hush is meant to sit behind a reverse proxy, and binding every interface
// must be an explicit choice. PORT (set by Railway) is still honoured for
// the port number but stays on loopback.
func listenAddr(listen, port string) (addr, warning string, err error) {
	switch {
	case listen != "":
		if _, _, err := net.SplitHostPort(listen); err != nil {
			return "", "", fmt.Errorf("LISTEN_ADDR: want host:port (e.g. 127.0.0.1:8080), got %q", listen)
		}
		return listen, "", nil
	case port != "":
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return "", "", fmt.Errorf("PORT: want a number between 1 and 65535, got %q", port)
		}
		addr = net.JoinHostPort("127.0.0.1", port)
		return addr, fmt.Sprintf("PORT is set without LISTEN_ADDR: listening on %s (loopback only); "+
			"to accept external connections set LISTEN_ADDR=0.0.0.0:%s", addr, port), nil
	default:
		return defaultListenAddr, "", nil
	}
}

// masterKey prefers a systemd credential ($CREDENTIALS_DIRECTORY/master_key)
// over the MASTER_KEY env var: credentials are not visible in
// /proc/<pid>/environ or inherited by child processes. A credential file
// that exists but is unreadable or invalid is an error, not a silent
// fallback to the env var, so a broken deployment can't quietly use a
// different key than the operator intended.
func masterKey(getenv func(string) string, readFile func(string) ([]byte, error)) ([]byte, string, error) {
	if dir := getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		path := filepath.Join(dir, credentialKeyFile)
		raw, err := readFile(path)
		switch {
		case err == nil:
			key, err := decodeKey(string(raw))
			if err != nil {
				return nil, "", fmt.Errorf("credential %s: %w", path, err)
			}
			return key, keySourceCredentials, nil
		case !errors.Is(err, fs.ErrNotExist):
			return nil, "", fmt.Errorf("credential %s: %w", path, err)
		}
	}
	v := getenv("MASTER_KEY")
	if v == "" {
		return nil, "", errors.New("master key missing: set MASTER_KEY or provide the systemd credential " + credentialKeyFile)
	}
	key, err := decodeKey(v)
	if err != nil {
		return nil, "", fmt.Errorf("MASTER_KEY: %w", err)
	}
	return key, keySourceEnv, nil
}

// decodeKey validates base64 and length. The wrapped base64 error carries
// only a byte offset, never input bytes.
func decodeKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("must decode to 32 bytes, got %d", len(key))
	}
	return key, nil
}

func positiveInt(getenv func(string) string, name string, def int) (int, error) {
	v := getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: must be a positive integer, got %q", name, v)
	}
	return n, nil
}
