package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthcheck(t *testing.T) {
	_, h := newTestServer(t)
	srv := httptest.NewServer(h)
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "LISTEN_ADDR" {
				return v
			}
			return ""
		}
	}
	for _, addr := range []string{"127.0.0.1:" + port, "0.0.0.0:" + port, ":" + port} {
		if err := cmdHealthcheck(nil, env(addr)); err != nil {
			t.Errorf("LISTEN_ADDR=%s: %v", addr, err)
		}
	}
	if err := cmdHealthcheck(nil, env("127.0.0.1:1")); err == nil {
		t.Error("nothing listening should fail")
	}
	if err := cmdHealthcheck(nil, env("nonsense")); err == nil {
		t.Error("bad LISTEN_ADDR should fail")
	}

	// A non-200 answer is unhealthy.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer bad.Close()
	if err := cmdHealthcheck(nil, env(bad.Listener.Addr().String())); err == nil {
		t.Error("503 should be unhealthy")
	}
}
