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

	keySourceFile = "file"
	keySourceEnv  = "env"
)

// removedEnv are settings earlier versions read. They are ignored, with a
// startup warning so a stale deployment config doesn't fail silently.
var removedEnv = []string{"AUTH_TOKEN", "PORT", "TRUST_PROXY_HEADERS"}

// config is everything serve() needs from the environment, already
// validated. The key is held here only long enough to build the server.
type config struct {
	listenAddr               string
	dbPath                   string
	key                      []byte
	keySource                string
	rateLimitPerMinute       int
	unauthRateLimitPerMinute int
	// trustedProxies are the peers whose X-Forwarded-For is believed.
	trustedProxies []*net.IPNet
	// adminAPI enables /v1/admin/* and the web UI.
	adminAPI bool
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
		dbPath:     defaultDBPath,
		listenAddr: defaultListenAddr,
	}
	if v := getenv("DB_PATH"); v != "" {
		c.dbPath = v
	}

	if v := getenv("LISTEN_ADDR"); v != "" {
		if _, _, err := net.SplitHostPort(v); err != nil {
			return config{}, fmt.Errorf("LISTEN_ADDR: want host:port (e.g. 127.0.0.1:8080), got %q", v)
		}
		c.listenAddr = v
	}
	for _, name := range removedEnv {
		if getenv(name) != "" {
			c.warnings = append(c.warnings, name+" is no longer supported and is ignored; see docs/docker.md")
		}
	}

	var err error
	if c.key, c.keySource, err = masterKey(getenv, readFile); err != nil {
		return config{}, err
	}

	if c.rateLimitPerMinute, err = positiveInt(getenv, "RATE_LIMIT_PER_MINUTE", defaultRateLimitPerMinute); err != nil {
		return config{}, err
	}
	if c.unauthRateLimitPerMinute, err = positiveInt(getenv, "UNAUTH_RATE_LIMIT_PER_MINUTE", defaultUnauthRateLimitPerMinute); err != nil {
		return config{}, err
	}

	if c.trustedProxies, err = parseTrustedProxies(getenv("TRUSTED_PROXIES")); err != nil {
		return config{}, err
	}

	c.adminAPI = true
	if v := getenv("ADMIN_API"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return config{}, fmt.Errorf("ADMIN_API: must be true or false, got %q", v)
		}
		c.adminAPI = b
	}
	return c, nil
}

// parseTrustedProxies accepts a comma-separated list of CIDRs or bare IPs.
// Empty means X-Forwarded-For is never trusted. 0.0.0.0/0 and ::/0 are
// refused: trusting every peer lets any client pick its own audit address
// and dodge the failed-auth rate limit.
func parseTrustedProxies(v string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("TRUSTED_PROXIES: %q is not an IP or CIDR", part)
			}
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			part = fmt.Sprintf("%s/%d", ip, bits)
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES: %q is not an IP or CIDR", part)
		}
		if ones, _ := n.Mask.Size(); ones == 0 {
			return nil, fmt.Errorf("TRUSTED_PROXIES: %q would trust every client", part)
		}
		out = append(out, n)
	}
	return out, nil
}

// masterKey reads the key from MASTER_KEY_FILE (a Docker secret such as
// /run/secrets/master_key) or the MASTER_KEY env var. A file keeps the key
// out of `docker inspect` and /proc/<pid>/environ. Setting both is an
// error so a deployment can't quietly use a different key than intended.
func masterKey(getenv func(string) string, readFile func(string) ([]byte, error)) ([]byte, string, error) {
	path, env := getenv("MASTER_KEY_FILE"), getenv("MASTER_KEY")
	switch {
	case path != "" && env != "":
		return nil, "", errors.New("set only one of MASTER_KEY_FILE and MASTER_KEY")
	case path != "":
		raw, err := readFile(filepath.Clean(path))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, "", fmt.Errorf("MASTER_KEY_FILE %s: file not found", path)
			}
			return nil, "", fmt.Errorf("MASTER_KEY_FILE %s: %w", path, err)
		}
		key, err := decodeKey(string(raw))
		if err != nil {
			return nil, "", fmt.Errorf("MASTER_KEY_FILE %s: %w", path, err)
		}
		return key, keySourceFile, nil
	case env != "":
		key, err := decodeKey(env)
		if err != nil {
			return nil, "", fmt.Errorf("MASTER_KEY: %w", err)
		}
		return key, keySourceEnv, nil
	default:
		return nil, "", errors.New("master key missing: set MASTER_KEY_FILE (recommended) or MASTER_KEY")
	}
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
