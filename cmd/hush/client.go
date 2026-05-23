package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// nameRe mirrors the server's name validation. Validating client-side
// fails fast with a clear error instead of round-tripping for a 400.
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,128}$`)

// Secret is the CLI's view of a stored secret. Value is empty for list
// responses (the server doesn't return values in /v1/secrets).
type Secret struct {
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// PutResult is the response from a successful PUT — created_at lets the
// caller distinguish a create from an update by comparing it to updated_at.
type PutResult struct {
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

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
//
// #nosec G107 G104 G704 -- this is a CLI HTTP client. The "tainted" inputs
// gosec flags (c.baseURL from --url/config, name from `hush get NAME`) ARE
// the user's intended destination. SSRF taint analysis is the wrong threat
// model for client-side software the user runs against their own server.
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

// Get fetches a single secret by name.
func (c *client) Get(ctx context.Context, name string) (Secret, error) {
	var s Secret
	if !nameRe.MatchString(name) {
		return s, fmt.Errorf("invalid name %q (must match %s)", name, nameRe)
	}
	resp, err := c.do(ctx, http.MethodGet, "/v1/secrets/"+url.PathEscape(name), true, nil)
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return s, decodeError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return s, fmt.Errorf("decode response: %w", err)
	}
	return s, nil
}

// Put creates or updates a secret. Returns the server's response so the
// caller can distinguish create-vs-update from the timestamps.
func (c *client) Put(ctx context.Context, name, value string) (PutResult, error) {
	var pr PutResult
	if !nameRe.MatchString(name) {
		return pr, fmt.Errorf("invalid name %q (must match %s)", name, nameRe)
	}
	body, err := json.Marshal(map[string]string{"value": value})
	if err != nil {
		return pr, err
	}
	resp, err := c.do(ctx, http.MethodPut, "/v1/secrets/"+url.PathEscape(name), true, bytes.NewReader(body))
	if err != nil {
		return pr, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return pr, decodeError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return pr, fmt.Errorf("decode response: %w", err)
	}
	return pr, nil
}

// Delete removes a secret. The server treats DELETE as idempotent, so a
// missing name is not an error and returns 204.
func (c *client) Delete(ctx context.Context, name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid name %q (must match %s)", name, nameRe)
	}
	resp, err := c.do(ctx, http.MethodDelete, "/v1/secrets/"+url.PathEscape(name), true, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return decodeError(resp)
	}
	return nil
}

// List returns all stored secrets (without values; the server's list
// endpoint omits ciphertext for cost + ergonomic reasons).
func (c *client) List(ctx context.Context) ([]Secret, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/secrets", true, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, decodeError(resp)
	}
	var body struct {
		Secrets []Secret `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return body.Secrets, nil
}
