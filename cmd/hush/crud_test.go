package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- client method tests ----

// neverPrompt is a stub passed to cmdGet/cmdPut in tests where no vault
// is configured, so promptFn must never be invoked. If it is, t.Fatalf
// breaks the test immediately — silent default-on-call would let a
// regression silently bypass an unexpected vault prompt.
func neverPrompt(t *testing.T) func(string) (string, error) {
	return func(prompt string) (string, error) {
		t.Helper()
		t.Fatalf("unexpected prompt: %q", prompt)
		return "", nil
	}
}

func TestClient_GetRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secrets/api-key" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("auth = %q, want Bearer tok", got)
		}
		_ = json.NewEncoder(w).Encode(Secret{
			Name: "api-key", Value: "shhh", CreatedAt: 1700000000, UpdatedAt: 1700000100,
		})
	}))
	defer srv.Close()

	c := newClient(srv.URL, "tok")
	s, err := c.Get(context.Background(), "api-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if s.Value != "shhh" {
		t.Errorf("Value = %q, want %q", s.Value, "shhh")
	}
}

func TestClient_GetInvalidName(t *testing.T) {
	c := newClient("https://example", "tok")
	if _, err := c.Get(context.Background(), "bad/name"); err == nil {
		t.Fatal("expected name-validation error")
	}
}

func TestClient_GetNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer srv.Close()

	c := newClient(srv.URL, "tok")
	_, err := c.Get(context.Background(), "missing")
	var apiErr *apiError
	if !errors.As(err, &apiErr) || apiErr.Status != 404 {
		t.Fatalf("got %v, want apiError 404", err)
	}
}

func TestClient_PutRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}
		var body struct{ Value string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.Value != "v1" {
			t.Errorf("value = %q", body.Value)
		}
		_ = json.NewEncoder(w).Encode(PutResult{
			Name: "foo", CreatedAt: 1700000000, UpdatedAt: 1700000000,
		})
	}))
	defer srv.Close()

	c := newClient(srv.URL, "tok")
	res, err := c.Put(context.Background(), "foo", "v1")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if res.Name != "foo" {
		t.Errorf("Name = %q", res.Name)
	}
}

func TestClient_DeleteReturnsNilOn204(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	c := newClient(srv.URL, "tok")
	if err := c.Delete(context.Background(), "foo"); err != nil {
		t.Errorf("Delete: %v", err)
	}
}

func TestClient_ListDecodesEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secrets": []Secret{
				{Name: "a", CreatedAt: 1, UpdatedAt: 1},
				{Name: "b", CreatedAt: 2, UpdatedAt: 3},
			},
		})
	}))
	defer srv.Close()

	c := newClient(srv.URL, "tok")
	got, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "b" {
		t.Errorf("got %+v", got)
	}
}

// ---- valueSource tests ----

func TestValueSource_Arg(t *testing.T) {
	v, err := valueSource{arg: "hello"}.resolve()
	if err != nil || v != "hello" {
		t.Errorf("got %q, %v", v, err)
	}
}

func TestValueSource_File(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s")
	if err := os.WriteFile(p, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := valueSource{fromFile: p}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if v != "secret" {
		t.Errorf("got %q, want %q (trailing newline should be stripped)", v, "secret")
	}
}

func TestValueSource_Stdin(t *testing.T) {
	v, err := valueSource{fromStdin: true, stdin: strings.NewReader("piped\n")}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if v != "piped" {
		t.Errorf("got %q", v)
	}
}

func TestValueSource_TTYPrompt(t *testing.T) {
	called := false
	v, err := valueSource{
		isTTY: func() bool { return true },
		readPass: func(_ string) (string, error) {
			called = true
			return "from-tty", nil
		},
	}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("readPass was not called")
	}
	if v != "from-tty" {
		t.Errorf("got %q", v)
	}
}

func TestValueSource_MultipleSourcesError(t *testing.T) {
	_, err := valueSource{arg: "x", fromStdin: true}.resolve()
	if !errors.Is(err, errMultipleValueSources) {
		t.Errorf("got %v, want errMultipleValueSources", err)
	}
}

func TestValueSource_NoSourceNonTTYError(t *testing.T) {
	_, err := valueSource{isTTY: func() bool { return false }}.resolve()
	if !errors.Is(err, errNoValueSource) {
		t.Errorf("got %v, want errNoValueSource", err)
	}
}

// ---- subcommand tests (httptest-backed) ----

type fakeServer struct {
	t        *testing.T
	srv      *httptest.Server
	gets     map[string]Secret
	listResp []Secret
	calls    []string // method + " " + path
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{t: t, gets: map[string]Secret{}}
	fs.srv = httptest.NewServer(http.HandlerFunc(fs.handle))
	t.Cleanup(fs.srv.Close)
	return fs
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/secrets":
		_ = json.NewEncoder(w).Encode(map[string]any{"secrets": f.listResp})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/secrets/"):
		name := strings.TrimPrefix(r.URL.Path, "/v1/secrets/")
		s, ok := f.gets[name]
		if !ok {
			w.WriteHeader(404)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		_ = json.NewEncoder(w).Encode(s)
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/secrets/"):
		name := strings.TrimPrefix(r.URL.Path, "/v1/secrets/")
		var body struct{ Value string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		now := int64(1700000000)
		existing, exists := f.gets[name]
		created := now
		if exists {
			created = existing.CreatedAt
			now = existing.UpdatedAt + 1 // distinct updated_at so create vs update is detectable
		}
		f.gets[name] = Secret{Name: name, Value: body.Value, CreatedAt: created, UpdatedAt: now}
		_ = json.NewEncoder(w).Encode(PutResult{Name: name, CreatedAt: created, UpdatedAt: now})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/secrets/"):
		delete(f.gets, strings.TrimPrefix(r.URL.Path, "/v1/secrets/"))
		w.WriteHeader(204)
	default:
		f.t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
	}
}

func setEnvConfig(t *testing.T, url, token string) {
	t.Helper()
	t.Setenv("HUSH_CONFIG_DIR", t.TempDir())
	t.Setenv("HUSH_URL", url)
	t.Setenv("HUSH_TOKEN", token)
}

func TestCmdGet_PrintsValue(t *testing.T) {
	fs := newFakeServer(t)
	fs.gets["api-key"] = Secret{Name: "api-key", Value: "shhh", CreatedAt: 1, UpdatedAt: 2}
	setEnvConfig(t, fs.srv.URL, "tok")

	var out bytes.Buffer
	if err := cmdGet(context.Background(), []string{"api-key"}, &out, neverPrompt(t)); err != nil {
		t.Fatalf("cmdGet: %v", err)
	}
	if out.String() != "shhh" {
		t.Errorf("stdout = %q, want %q (no trailing newline)", out.String(), "shhh")
	}
}

func TestCmdGet_MissingNameError(t *testing.T) {
	setEnvConfig(t, "https://example", "tok")
	var out bytes.Buffer
	err := cmdGet(context.Background(), nil, &out, neverPrompt(t))
	if err == nil || !strings.Contains(err.Error(), "NAME is required") {
		t.Errorf("got %v", err)
	}
}

func TestCmdPut_PositionalValueSaves(t *testing.T) {
	srv := newFakeServer(t)
	setEnvConfig(t, srv.srv.URL, "tok")

	var out bytes.Buffer
	err := cmdPut(context.Background(), []string{"foo", "bar"}, nil, &out, neverPrompt(t))
	if err != nil {
		t.Fatalf("cmdPut: %v", err)
	}
	if !strings.Contains(out.String(), "foo: saved") {
		t.Errorf("expected 'foo: saved', got %q", out.String())
	}
	if srv.gets["foo"].Value != "bar" {
		t.Errorf("server didn't receive value: %+v", srv.gets["foo"])
	}
}

func TestCmdPut_ValueAfterFlags(t *testing.T) {
	// `hush put foo --url=X bar` — stdlib flag stops parsing positionals
	// at the first non-flag, but cmdPut should still pick up "bar" as the
	// value if it's the only trailing positional.
	srv := newFakeServer(t)
	setEnvConfig(t, "https://wrong.invalid", "tok") // force --url override path
	var out bytes.Buffer
	err := cmdPut(context.Background(), []string{"foo", "--url=" + srv.srv.URL, "bar"}, nil, &out, neverPrompt(t))
	if err != nil {
		t.Fatalf("cmdPut: %v", err)
	}
	if srv.gets["foo"].Value != "bar" {
		t.Errorf("server got %q, want %q", srv.gets["foo"].Value, "bar")
	}
}

func TestCmdPut_FromStdin(t *testing.T) {
	srv := newFakeServer(t)
	setEnvConfig(t, srv.srv.URL, "tok")

	var out bytes.Buffer
	stdin := strings.NewReader("piped-value\n")
	err := cmdPut(context.Background(), []string{"foo", "--from-stdin"}, stdin, &out, neverPrompt(t))
	if err != nil {
		t.Fatalf("cmdPut: %v", err)
	}
	if srv.gets["foo"].Value != "piped-value" {
		t.Errorf("server got %q, want %q", srv.gets["foo"].Value, "piped-value")
	}
}

func TestCmdPut_FromFile(t *testing.T) {
	srv := newFakeServer(t)
	setEnvConfig(t, srv.srv.URL, "tok")

	dir := t.TempDir()
	p := filepath.Join(dir, "v")
	if err := os.WriteFile(p, []byte("file-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := cmdPut(context.Background(), []string{"foo", "--from-file=" + p}, nil, &out, neverPrompt(t))
	if err != nil {
		t.Fatalf("cmdPut: %v", err)
	}
	if srv.gets["foo"].Value != "file-value" {
		t.Errorf("got %q", srv.gets["foo"].Value)
	}
}

func TestCmdPut_SecondPutAlsoSaves(t *testing.T) {
	srv := newFakeServer(t)
	setEnvConfig(t, srv.srv.URL, "tok")

	var out bytes.Buffer
	if err := cmdPut(context.Background(), []string{"foo", "first"}, nil, &out, neverPrompt(t)); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := cmdPut(context.Background(), []string{"foo", "second"}, nil, &out, neverPrompt(t)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "foo: saved") {
		t.Errorf("expected 'foo: saved' on second put, got %q", out.String())
	}
	if srv.gets["foo"].Value != "second" {
		t.Errorf("value not updated: %+v", srv.gets["foo"])
	}
}

func TestCmdPut_NoValueSourceErrors(t *testing.T) {
	srv := newFakeServer(t)
	setEnvConfig(t, srv.srv.URL, "tok")

	var out bytes.Buffer
	// stdin is nil and we can't fake a TTY in unit tests; resolve() falls
	// through to errNoValueSource.
	err := cmdPut(context.Background(), []string{"foo"}, nil, &out, neverPrompt(t))
	if err == nil {
		t.Fatal("expected error when no value source available")
	}
	if !strings.Contains(err.Error(), "no value source") {
		t.Errorf("got %v", err)
	}
}

func TestCmdDelete_PrintsConfirmation(t *testing.T) {
	srv := newFakeServer(t)
	srv.gets["foo"] = Secret{Name: "foo"}
	setEnvConfig(t, srv.srv.URL, "tok")

	var out bytes.Buffer
	if err := cmdDelete(context.Background(), []string{"foo"}, &out); err != nil {
		t.Fatalf("cmdDelete: %v", err)
	}
	if !strings.Contains(out.String(), "foo: deleted") {
		t.Errorf("got %q", out.String())
	}
	if _, present := srv.gets["foo"]; present {
		t.Error("server still has 'foo'")
	}
}

func TestCmdList_TableOutput(t *testing.T) {
	srv := newFakeServer(t)
	srv.listResp = []Secret{
		{Name: "a", CreatedAt: 1700000000, UpdatedAt: 1700000000},
		{Name: "longer-name", CreatedAt: 1700000100, UpdatedAt: 1700000200},
	}
	setEnvConfig(t, srv.srv.URL, "tok")

	var out bytes.Buffer
	if err := cmdList(context.Background(), nil, &out); err != nil {
		t.Fatalf("cmdList: %v", err)
	}
	if !strings.Contains(out.String(), "NAME") || !strings.Contains(out.String(), "longer-name") {
		t.Errorf("table output missing expected content: %q", out.String())
	}
}

func TestCmdList_JSONOutput(t *testing.T) {
	srv := newFakeServer(t)
	srv.listResp = []Secret{{Name: "x", CreatedAt: 1, UpdatedAt: 1}}
	setEnvConfig(t, srv.srv.URL, "tok")

	var out bytes.Buffer
	if err := cmdList(context.Background(), []string{"--json"}, &out); err != nil {
		t.Fatalf("cmdList: %v", err)
	}
	var got []Secret
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out.String())
	}
	if len(got) != 1 || got[0].Name != "x" {
		t.Errorf("got %+v", got)
	}
}

func TestCmdList_EmptyShowsPlaceholder(t *testing.T) {
	srv := newFakeServer(t)
	setEnvConfig(t, srv.srv.URL, "tok")

	var out bytes.Buffer
	if err := cmdList(context.Background(), nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no secrets") {
		t.Errorf("got %q", out.String())
	}
}

func TestRun_GetDispatch(t *testing.T) {
	srv := newFakeServer(t)
	srv.gets["foo"] = Secret{Name: "foo", Value: "v"}
	setEnvConfig(t, srv.srv.URL, "tok")

	var out, errBuf bytes.Buffer
	code := run([]string{"get", "foo"}, nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, errBuf.String())
	}
	if out.String() != "v" {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestResolveClient_MissingTokenError(t *testing.T) {
	t.Setenv("HUSH_CONFIG_DIR", t.TempDir())
	t.Setenv("HUSH_URL", "https://example")
	t.Setenv("HUSH_TOKEN", "")
	if _, err := resolveClient("", ""); err == nil || !strings.Contains(err.Error(), "no token configured") {
		t.Errorf("got %v", err)
	}
}

func TestSplitNameAndRest(t *testing.T) {
	cases := []struct {
		in       []string
		wantName string
		wantRest []string
	}{
		{nil, "", nil},
		{[]string{}, "", []string{}},
		{[]string{"--url=x"}, "", []string{"--url=x"}},
		{[]string{"foo"}, "foo", []string{}},
		{[]string{"foo", "--url=x"}, "foo", []string{"--url=x"}},
	}
	for _, tc := range cases {
		gotName, gotRest := splitNameAndRest(tc.in)
		if gotName != tc.wantName {
			t.Errorf("in %v: name = %q, want %q", tc.in, gotName, tc.wantName)
		}
		if !equalStrings(gotRest, tc.wantRest) {
			t.Errorf("in %v: rest = %v, want %v", tc.in, gotRest, tc.wantRest)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFmtTime_ZeroIsDash(t *testing.T) {
	if got := fmtTime(0); got != "-" {
		t.Errorf("got %q, want %q", got, "-")
	}
}

func TestClient_PutInvalidName(t *testing.T) {
	c := newClient("https://example", "tok")
	if _, err := c.Put(context.Background(), "bad/name", "v"); err == nil {
		t.Fatal("expected name-validation error")
	}
}

func TestClient_DeleteInvalidName(t *testing.T) {
	c := newClient("https://example", "tok")
	if err := c.Delete(context.Background(), "bad/name"); err == nil {
		t.Fatal("expected name-validation error")
	}
}

func TestClient_PutSurfaceServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "db down"})
	}))
	defer srv.Close()
	c := newClient(srv.URL, "tok")
	_, err := c.Put(context.Background(), "foo", "v")
	var apiErr *apiError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 {
		t.Errorf("got %v, want apiError 500", err)
	}
}

func TestClient_ListSurfaceServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
	}))
	defer srv.Close()
	c := newClient(srv.URL, "tok")
	_, err := c.List(context.Background())
	var apiErr *apiError
	if !errors.As(err, &apiErr) || apiErr.Status != 401 {
		t.Errorf("got %v, want apiError 401", err)
	}
}

func TestValueSource_FileMissingPath(t *testing.T) {
	_, err := valueSource{fromFile: filepath.Join(t.TempDir(), "missing")}.resolve()
	if err == nil {
		t.Fatal("expected error reading missing file")
	}
}

func TestValueSource_StdinNilReader(t *testing.T) {
	_, err := valueSource{fromStdin: true, stdin: nil}.resolve()
	if err == nil {
		t.Fatal("expected error when stdin reader is nil")
	}
}

func TestValueSource_TTYWithoutPromptFunc(t *testing.T) {
	_, err := valueSource{isTTY: func() bool { return true }, readPass: nil}.resolve()
	if err == nil {
		t.Fatal("expected error when TTY but no prompt func wired")
	}
}

func TestCmdGet_NotFoundSurfaceError(t *testing.T) {
	fs := newFakeServer(t)
	// gets is empty so any GET returns 404
	setEnvConfig(t, fs.srv.URL, "tok")

	var out bytes.Buffer
	err := cmdGet(context.Background(), []string{"missing"}, &out, neverPrompt(t))
	if err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestCmdPut_ServerErrorSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "db down"})
	}))
	defer srv.Close()
	setEnvConfig(t, srv.URL, "tok")

	var out bytes.Buffer
	err := cmdPut(context.Background(), []string{"foo", "v"}, nil, &out, neverPrompt(t))
	if err == nil {
		t.Fatal("expected server error to surface")
	}
}

func TestCmdList_ServerErrorSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	setEnvConfig(t, srv.URL, "tok")

	var out bytes.Buffer
	err := cmdList(context.Background(), nil, &out)
	if err == nil {
		t.Fatal("expected server error to surface")
	}
}

func TestCmdDelete_ServerErrorSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	setEnvConfig(t, srv.URL, "tok")

	var out bytes.Buffer
	err := cmdDelete(context.Background(), []string{"foo"}, &out)
	if err == nil {
		t.Fatal("expected server error to surface")
	}
}

func TestCmdDelete_MissingNameError(t *testing.T) {
	setEnvConfig(t, "https://example", "tok")
	var out bytes.Buffer
	err := cmdDelete(context.Background(), nil, &out)
	if err == nil || !strings.Contains(err.Error(), "NAME is required") {
		t.Errorf("got %v", err)
	}
}

func TestCmdGet_ExtraPositionalErrors(t *testing.T) {
	setEnvConfig(t, "https://example", "tok")
	var out bytes.Buffer
	err := cmdGet(context.Background(), []string{"foo", "extra"}, &out, neverPrompt(t))
	if err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
		t.Errorf("got %v", err)
	}
}

func TestCmdDelete_ExtraPositionalErrors(t *testing.T) {
	setEnvConfig(t, "https://example", "tok")
	var out bytes.Buffer
	err := cmdDelete(context.Background(), []string{"foo", "extra"}, &out)
	if err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
		t.Errorf("got %v", err)
	}
}

func TestCmdList_ExtraPositionalErrors(t *testing.T) {
	setEnvConfig(t, "https://example", "tok")
	var out bytes.Buffer
	err := cmdList(context.Background(), []string{"unexpected"}, &out)
	if err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
		t.Errorf("got %v", err)
	}
}

func TestCmdPut_TooManyPositionalsErrors(t *testing.T) {
	setEnvConfig(t, "https://example", "tok")
	var out bytes.Buffer
	// `hush put foo bar --url=X baz` — bar takes the value slot, baz is left over.
	err := cmdPut(context.Background(), []string{"foo", "bar", "--url=https://x", "baz"}, nil, &out, neverPrompt(t))
	if err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
		t.Errorf("got %v", err)
	}
}

func TestTrimOneTrailingNewline(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"abc", "abc"},
		{"abc\n", "abc"},
		{"abc\r\n", "abc"},
		{"abc\r", "abc"},
		{"abc\n\n", "abc\n"},     // only one stripped
		{"abc\n\n\n", "abc\n\n"}, // only one stripped
		{"abc\r\n\r\n", "abc\r\n"},
		{"\n", ""},
	}
	for _, tc := range cases {
		if got := trimOneTrailingNewline(tc.in); got != tc.want {
			t.Errorf("trim(%q): got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCmdPut_MissingNameError(t *testing.T) {
	setEnvConfig(t, "https://example", "tok")
	var out bytes.Buffer
	err := cmdPut(context.Background(), nil, nil, &out, neverPrompt(t))
	if err == nil || !strings.Contains(err.Error(), "NAME is required") {
		t.Errorf("got %v", err)
	}
}

func TestClient_DeleteSurfaceServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "db down"})
	}))
	defer srv.Close()
	c := newClient(srv.URL, "tok")
	err := c.Delete(context.Background(), "foo")
	var apiErr *apiError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 {
		t.Errorf("got %v, want apiError 500", err)
	}
}
