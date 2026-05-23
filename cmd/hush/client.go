package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultTimeout = 30 * time.Second

// client wraps the hush-hush HTTP API. baseURL is normalized at construction
// so callers don't have to worry about trailing-slash duplication.
type client struct {
	baseURL string
	token   string
	http    *http.Client
}

func newClient(baseURL, token string) *client {
	return &client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: defaultTimeout},
	}
}

// do builds a request and dispatches it. Caller owns the returned response
// body and must close it.
func (c *client) do(ctx context.Context, method, path string, auth bool, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.http.Do(req)
}

// apiError is a structured representation of the server's JSON error
// payload, preserving the HTTP status for callers that want to switch
// on it (e.g. 401 vs 404).
type apiError struct {
	Status  int    `json:"-"`
	Message string `json:"error"`
}

func (e *apiError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.Status, e.Message)
}

// decodeError reads a non-2xx response and returns an *apiError. Falls back
// to http.StatusText when the body is empty or not valid JSON so we never
// lose the status code on weird upstream responses (CDN HTML pages, etc.).
func decodeError(resp *http.Response) error {
	defer resp.Body.Close()
	e := &apiError{Status: resp.StatusCode}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, e)
	}
	if e.Message == "" {
		e.Message = http.StatusText(resp.StatusCode)
	}
	return e
}

// Health probes the unauthenticated /healthz endpoint to verify the
// server is reachable.
func (c *client) Health(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/healthz", false, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decodeError(resp)
	}
	return nil
}

// AuthCheck verifies the configured token is accepted by hitting an
// auth-protected endpoint. We use LIST because it's already there and
// returns 200 on success; the response body is discarded.
func (c *client) AuthCheck(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/v1/secrets", true, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decodeError(resp)
	}
	return nil
}
