package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewClient_TrimsTrailingSlash(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://example.com", "https://example.com"},
		{"https://example.com/", "https://example.com"},
		{"https://example.com///", "https://example.com"},
	}
	for _, tc := range cases {
		c := newClient(tc.in, "tok")
		if c.baseURL != tc.want {
			t.Errorf("newClient(%q): baseURL = %q, want %q", tc.in, c.baseURL, tc.want)
		}
	}
}

func TestDecodeError_StructuredJSON(t *testing.T) {
	resp := &http.Response{
		StatusCode: 401,
		Body:       io.NopCloser(strings.NewReader(`{"error":"invalid token"}`)),
	}
	err := decodeError(resp)
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %T, want *apiError", err)
	}
	if apiErr.Status != 401 || apiErr.Message != "invalid token" {
		t.Errorf("got %+v", apiErr)
	}
}

func TestDecodeError_NonJSONBodyFallsBackToStatusText(t *testing.T) {
	resp := &http.Response{
		StatusCode: 502,
		Body:       io.NopCloser(strings.NewReader(`<html>Bad Gateway</html>`)),
	}
	err := decodeError(resp)
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %T, want *apiError", err)
	}
	if apiErr.Status != 502 || apiErr.Message != "Bad Gateway" {
		t.Errorf("got %+v", apiErr)
	}
}

func TestDecodeError_EmptyBody(t *testing.T) {
	resp := &http.Response{
		StatusCode: 500,
		Body:       io.NopCloser(strings.NewReader("")),
	}
	err := decodeError(resp)
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %T, want *apiError", err)
	}
	if apiErr.Message != "Internal Server Error" {
		t.Errorf("got message %q, want StatusText fallback", apiErr.Message)
	}
}

func TestHealth_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	c := newClient(srv.URL, "")
	if err := c.Health(context.Background()); err != nil {
		t.Errorf("Health: %v", err)
	}
}

func TestHealth_NonOKSurfacesServerMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "starting up"})
	}))
	defer srv.Close()

	c := newClient(srv.URL, "")
	err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "starting up") {
		t.Errorf("error missing server message: %v", err)
	}
}

func TestAuthCheck_SendsBearer(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []any{}})
	}))
	defer srv.Close()

	c := newClient(srv.URL, "my-token")
	if err := c.AuthCheck(context.Background()); err != nil {
		t.Fatalf("AuthCheck: %v", err)
	}
	if gotAuth != "Bearer my-token" {
		t.Errorf("auth header = %q, want %q", gotAuth, "Bearer my-token")
	}
}

func TestAuthCheck_401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
	}))
	defer srv.Close()

	c := newClient(srv.URL, "bad")
	err := c.AuthCheck(context.Background())
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %T, want *apiError", err)
	}
	if apiErr.Status != 401 {
		t.Errorf("status = %d, want 401", apiErr.Status)
	}
}
