//go:build unix

package main

import (
	"bytes"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The real entry point: run("serve") reads the process environment,
// serves, and returns 0 on SIGTERM.
func TestServe_EntryPointStopsOnSIGTERM(t *testing.T) {
	prev := captureLogsPrev()
	defer restoreLogs(prev)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	t.Setenv("MASTER_KEY", base64.StdEncoding.EncodeToString(testKey()))
	t.Setenv("DB_PATH", filepath.Join(t.TempDir(), "hush.db"))
	t.Setenv("LISTEN_ADDR", addr)

	done := make(chan int, 1)
	var out bytes.Buffer
	go func() { done <- run([]string{"serve"}, strings.NewReader(""), &out, &out) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server never came up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code %d", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop on SIGTERM")
	}
}
