package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// cmdHealthcheck probes this container's own server so a Docker
// HEALTHCHECK works in an image with no shell or curl. It needs no key or
// database access: it only reads LISTEN_ADDR and calls GET /healthz on the
// loopback interface.
func cmdHealthcheck(args []string, getenv func(string) string) error {
	if len(args) > 0 {
		return usageErr("healthcheck takes no arguments")
	}
	addr := getenv("LISTEN_ADDR")
	if addr == "" {
		addr = defaultListenAddr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("healthcheck: bad LISTEN_ADDR %q", addr)
	}
	// A wildcard bind is reachable on loopback; probe there rather than
	// on an address that means "any".
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
		if ip != nil && ip.To4() == nil {
			host = "::1"
		}
	}
	u := "http://" + net.JoinHostPort(host, port) + "/healthz"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req) // #nosec G107 -- URL built from our own LISTEN_ADDR
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: status %d", resp.StatusCode)
	}
	return nil
}
