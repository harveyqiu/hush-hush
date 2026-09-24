package main

// Integration tests for v2 client-side encryption end-to-end through
// the CLI subcommands. The unit tests in vault_test.go pin the crypto
// primitives; these pin the full cmdGet / cmdPut wiring against an
// httptest server.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withTestVault initializes a vault using fast-mode KDF params in a
// throwaway HUSH_CONFIG_DIR and returns the passphrase. The
// promptFn-based unlock flow in subcommands picks this up automatically.
func withTestVault(t *testing.T, passphrase string) {
	t.Helper()
	t.Setenv("HUSH_CONFIG_DIR", t.TempDir())
	if _, err := initVault(passphrase, testKDFParams(t)); err != nil {
		t.Fatalf("test setup: initVault: %v", err)
	}
}

// constPrompt returns a promptFn that always returns the same answer.
// Lets a test inject a deterministic passphrase without going near a TTY.
func constPrompt(answer string) func(string) (string, error) {
	return func(string) (string, error) { return answer, nil }
}

// envClient pre-sets the network config so cmdGet/cmdPut talk to the
// fake server. Returned function is for chaining when t.Setenv would
// be awkward.
func envClient(t *testing.T, url string) {
	t.Helper()
	t.Setenv("HUSH_URL", url)
	t.Setenv("HUSH_TOKEN", "tok")
}

func TestCmdPut_WithVault_EncryptsBeforeSend(t *testing.T) {
	srv := newFakeServer(t)
	withTestVault(t, "hunter2")
	envClient(t, srv.srv.URL)

	var out bytes.Buffer
	if err := cmdPut(context.Background(), []string{"foo", "plain-value"}, nil, &out, constPrompt("hunter2")); err != nil {
		t.Fatalf("cmdPut: %v", err)
	}
	stored := srv.gets["foo"].Value
	if !strings.HasPrefix(stored, vaultPrefix) {
		t.Errorf("server stored %q, expected %q-prefixed ciphertext", stored, vaultPrefix)
	}
	if stored == "plain-value" {
		t.Errorf("server received plaintext under active vault")
	}
}

func TestCmdGet_WithVault_DecryptsRoundTrip(t *testing.T) {
	srv := newFakeServer(t)
	withTestVault(t, "hunter2")
	envClient(t, srv.srv.URL)

	// Use put-then-get against the fake to lock the end-to-end shape.
	var put, get bytes.Buffer
	if err := cmdPut(context.Background(), []string{"foo", "the-real-value"}, nil, &put, constPrompt("hunter2")); err != nil {
		t.Fatalf("cmdPut: %v", err)
	}
	if err := cmdGet(context.Background(), []string{"foo"}, &get, constPrompt("hunter2")); err != nil {
		t.Fatalf("cmdGet: %v", err)
	}
	if get.String() != "the-real-value" {
		t.Errorf("round trip: got %q, want %q", get.String(), "the-real-value")
	}
}

func TestCmdGet_WithVault_V1PlaintextSurfacesMigrationHint(t *testing.T) {
	srv := newFakeServer(t)
	// Pre-seed a v1 plaintext secret directly (server-side only state).
	srv.gets["legacy"] = Secret{Name: "legacy", Value: "v1-plaintext"}
	withTestVault(t, "hunter2")
	envClient(t, srv.srv.URL)

	var out bytes.Buffer
	err := cmdGet(context.Background(), []string{"legacy"}, &out, constPrompt("hunter2"))
	if err == nil {
		t.Fatal("expected error pointing at hush migrate")
	}
	if !strings.Contains(err.Error(), "hush migrate") {
		t.Errorf("got %v, want error mentioning `hush migrate`", err)
	}
	if strings.Contains(out.String(), "v1-plaintext") {
		t.Errorf("stdout leaked the plaintext under active vault: %q", out.String())
	}
}

func TestCmdGet_WithVault_WrongPassphraseRejected(t *testing.T) {
	srv := newFakeServer(t)
	withTestVault(t, "hunter2")
	envClient(t, srv.srv.URL)
	// Pre-seed an encrypted secret so the get path reaches decrypt.
	if err := cmdPut(context.Background(), []string{"foo", "v"}, nil, &bytes.Buffer{}, constPrompt("hunter2")); err != nil {
		t.Fatalf("put fixture: %v", err)
	}

	var out bytes.Buffer
	err := cmdGet(context.Background(), []string{"foo"}, &out, constPrompt("WRONG"))
	if err == nil {
		t.Fatal("expected wrong-passphrase error")
	}
	if !errors.Is(err, errBadPassphrase) {
		t.Errorf("got %v, want errBadPassphrase", err)
	}
}

func TestCmdPut_WithVault_WrongPassphraseFailsBeforeNetwork(t *testing.T) {
	// If the passphrase is wrong, unlock should fail BEFORE we hit the
	// server — otherwise we'd risk pushing junk under the wrong key.
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer srv.Close()
	withTestVault(t, "hunter2")
	envClient(t, srv.URL)

	var out bytes.Buffer
	err := cmdPut(context.Background(), []string{"foo", "v"}, nil, &out, constPrompt("WRONG"))
	if err == nil {
		t.Fatal("expected wrong-passphrase error")
	}
	if called {
		t.Errorf("server was hit on wrong-passphrase put — should fail before any I/O")
	}
}

func TestCmdGet_NoVault_HH2PrefixPassesThrough(t *testing.T) {
	// Without a vault we have no key. A value with the hh2: prefix can
	// only be (a) a legacy plaintext that happens to start with hh2: or
	// (b) leftover ciphertext from a now-lost vault. cmdPut refuses (a)
	// going forward, and (b) is unrecoverable anyway — passthrough is
	// the honest answer.
	srv := newFakeServer(t)
	srv.gets["foo"] = Secret{Name: "foo", Value: vaultPrefix + "abcdef"}
	t.Setenv("HUSH_CONFIG_DIR", t.TempDir())
	envClient(t, srv.srv.URL)

	var out bytes.Buffer
	if err := cmdGet(context.Background(), []string{"foo"}, &out, neverPrompt(t)); err != nil {
		t.Fatalf("cmdGet: %v", err)
	}
	if out.String() != vaultPrefix+"abcdef" {
		t.Errorf("got %q, want passthrough of %q", out.String(), vaultPrefix+"abcdef")
	}
}

func TestCmdPut_NoVault_RejectsHH2Prefix(t *testing.T) {
	// Reserving the hh2: prefix on plaintext writes prevents the
	// ambiguity that would otherwise hit a user who runs `hush init`
	// later. cmdGet's collision-avoidance leans on this being enforced.
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer srv.Close()
	t.Setenv("HUSH_CONFIG_DIR", t.TempDir())
	envClient(t, srv.URL)

	var out bytes.Buffer
	err := cmdPut(context.Background(), []string{"foo", vaultPrefix + "looks-like-ciphertext"}, nil, &out, neverPrompt(t))
	if err == nil {
		t.Fatal("expected reservation error")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Errorf("got %v, want error mentioning the reserved prefix", err)
	}
	if called {
		t.Errorf("server was hit despite the rejection — write should fail before any I/O")
	}
}

func TestCmdGet_NoVault_PlaintextPassesThrough(t *testing.T) {
	srv := newFakeServer(t)
	srv.gets["foo"] = Secret{Name: "foo", Value: "v1-plain"}
	t.Setenv("HUSH_CONFIG_DIR", t.TempDir())
	envClient(t, srv.srv.URL)

	var out bytes.Buffer
	if err := cmdGet(context.Background(), []string{"foo"}, &out, neverPrompt(t)); err != nil {
		t.Fatalf("cmdGet: %v", err)
	}
	if out.String() != "v1-plain" {
		t.Errorf("got %q, want %q", out.String(), "v1-plain")
	}
}

func TestUnlockIfPresent_NoVault(t *testing.T) {
	t.Setenv("HUSH_CONFIG_DIR", t.TempDir())
	key, err := unlockIfPresent(neverPrompt(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Errorf("expected nil key when no vault, got %v", key)
	}
}

func TestUnlockIfPresent_VaultPresent(t *testing.T) {
	withTestVault(t, "hunter2")
	key, err := unlockIfPresent(constPrompt("hunter2"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) != keyBytes {
		t.Errorf("key length = %d, want %d", len(key), keyBytes)
	}
}

func TestUnlockIfPresent_WrongPassphrase(t *testing.T) {
	withTestVault(t, "hunter2")
	_, err := unlockIfPresent(constPrompt("wrong"))
	if !errors.Is(err, errBadPassphrase) {
		t.Errorf("got %v, want errBadPassphrase", err)
	}
}

func TestUnlockIfPresent_PromptErrorPropagates(t *testing.T) {
	withTestVault(t, "hunter2")
	want := errors.New("terminal broken")
	_, err := unlockIfPresent(func(string) (string, error) { return "", want })
	if !errors.Is(err, want) {
		t.Errorf("got %v, want wrapped %v", err, want)
	}
}

func TestMaybeDecrypt_TableDriven(t *testing.T) {
	// Pin maybeDecrypt's decision tree explicitly. The integration
	// tests above hit each leaf, but having a focused test catches
	// regressions that wouldn't surface as a black-box CLI failure —
	// including the name-AAD-binding case, which would otherwise only
	// fail in the primitive test in vault_test.go (i.e. a wiring bug
	// that hardcoded the name in cmdGet wouldn't be caught here).
	key := make([]byte, keyBytes)
	for i := range key {
		key[i] = 0x42
	}
	encrypted := encryptWireFormat(key, []byte("real-value"), []byte("foo"))

	cases := []struct {
		desc       string
		key        []byte
		secretName string
		wireValue  string
		want       string
		wantErr    error  // expected sentinel via errors.Is; nil = check wantErrHas
		wantErrHas string // substring; "" = expect nil err
	}{
		{"no vault + plaintext passes through", nil, "foo", "plain", "plain", nil, ""},
		{"no vault + hh2 prefix also passes through", nil, "foo", encrypted, encrypted, nil, ""},
		{"vault + plaintext nudges migrate", key, "foo", "plain", "", nil, "hush migrate"},
		{"vault + ciphertext decrypts", key, "foo", encrypted, "real-value", nil, ""},
		{"vault + ciphertext with mismatched name rejects", key, "bar", encrypted, "", errBadPassphrase, ""},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := maybeDecrypt(tc.key, tc.secretName, tc.wireValue)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("got %v, want %v", err, tc.wantErr)
				}
			case tc.wantErrHas != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErrHas) {
					t.Errorf("got %v, want error containing %q", err, tc.wantErrHas)
				}
			default:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.want {
					t.Errorf("got %q, want %q", got, tc.want)
				}
			}
		})
	}
}
