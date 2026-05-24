package main

// Client-side encryption for hush-hush v2.
//
// The user types a passphrase; we derive a key with Argon2id and seal each
// secret value with XChaCha20-Poly1305 before sending it to the server.
// The server's existing AES-GCM-at-rest layer is preserved underneath —
// two independent layers, defense in depth.
//
// Wire format for an encrypted value:
//   "hh2:" + base64( nonce(24 bytes) || sealed_payload )
// where sealed_payload = XChaCha20-Poly1305(plaintext, key, nonce, aad=name).
//
// The "hh2:" prefix is human-recognizable in DB dumps and lets the CLI
// distinguish v2 client-encrypted values from legacy v1 plaintext values
// without ambiguity. Binding the secret name into the AEAD's AAD prevents
// row-rebinding (swapping a ciphertext between two secrets) — the same
// defense the server uses on its own layer.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	vaultFileName    = "vault.json"
	vaultPrefix      = "hh2:"
	kdfAlgorithmName = "argon2id"
	// verifyPlaintext is encrypted under the derived key and stored in
	// vault.json so unlock can reject a wrong passphrase BEFORE the user
	// gets a misleading "decrypt failed" later. Treat as an opaque sentinel.
	verifyPlaintext = "hush-vault-v1"
	// verifyAAD is the AAD bound into the verify blob's AEAD. Distinct from
	// any secret name so a verify blob can't be replayed as a secret value.
	verifyAAD = "hush-vault-verify"

	vaultSaltBytes = 16
	keyBytes       = chacha20poly1305.KeySize     // 32
	nonceBytes     = chacha20poly1305.NonceSizeX  // 24
	vaultFileMode  = 0o600
)

// KDFParams holds the Argon2id parameters used to derive a vault key
// from a passphrase. Stored in vault.json so future param changes can
// roll forward without breaking existing vaults.
type KDFParams struct {
	Algorithm   string `json:"algorithm"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	Salt        string `json:"salt"` // base64
}

// defaultKDFParams returns the production-recommended Argon2id parameters
// (OWASP 2025 guidance: m=64 MiB, t=3, p=4). Roughly 500 ms on commodity
// laptop hardware in 2026.
func defaultKDFParams(salt []byte) KDFParams {
	return KDFParams{
		Algorithm:   kdfAlgorithmName,
		MemoryKiB:   64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		Salt:        base64.StdEncoding.EncodeToString(salt),
	}
}

// VaultConfig is the on-disk representation of a vault — written by
// `hush init`, read by every subsequent network command.
type VaultConfig struct {
	Version int       `json:"version"` // currently 1
	KDF     KDFParams `json:"kdf"`
	// Verify is the wire-format-encoded encryption of verifyPlaintext under
	// the derived key. Used to detect wrong-passphrase up front.
	Verify string `json:"verify"`
}

var (
	errBadPassphrase  = errors.New("wrong passphrase")
	errVaultExists    = errors.New("vault already exists")
	errVaultMissing   = errors.New("vault not initialized (run `hush init`)")
	errBadKDFAlgo     = errors.New("unsupported KDF algorithm in vault.json")
	errBadVaultFormat = errors.New("vault.json is malformed or unsupported version")
	errNotEncrypted   = errors.New("value is not in v2 client-encrypted format")
	errBadWireFormat  = errors.New("encrypted value is malformed")
)

// vaultPath returns the canonical location of vault.json — same dir as
// config.json so both files travel together when a user relocates their
// config dir.
func vaultPath() (string, error) {
	cfg, err := configPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), vaultFileName), nil
}

// initVault creates a new vault.json with the given passphrase and KDF
// params. Returns errVaultExists if the file is already present —
// re-initialization would silently strand existing client-encrypted
// secrets, so we refuse explicitly. The existence check happens during
// the actual write via O_EXCL so two concurrent inits can't both pass a
// pre-check and overwrite each other.
func initVault(passphrase string, params KDFParams) (VaultConfig, error) {
	key, err := deriveKey(passphrase, params)
	if err != nil {
		return VaultConfig{}, err
	}
	verify, err := encryptWireFormat(key, []byte(verifyPlaintext), []byte(verifyAAD))
	if err != nil {
		return VaultConfig{}, fmt.Errorf("create verify blob: %w", err)
	}
	cfg := VaultConfig{Version: 1, KDF: params, Verify: verify}
	if err := saveNewVault(cfg); err != nil {
		return VaultConfig{}, err
	}
	return cfg, nil
}

// loadVault reads vault.json. Returns errVaultMissing if the file
// doesn't exist (so callers can distinguish "not set up" from "broken")
// and errBadVaultFormat for any structural defect — missing/zero KDF
// params, empty Verify, undecodable salt. Validating up front means
// downstream decrypt failures can only mean "wrong passphrase".
func loadVault() (VaultConfig, error) {
	var cfg VaultConfig
	p, err := vaultPath()
	if err != nil {
		return cfg, err
	}
	// #nosec G304 -- p is computed from configPath() (HUSH_CONFIG_DIR or
	// os.UserConfigDir). No untrusted external input.
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, errVaultMissing
	}
	if err != nil {
		return cfg, fmt.Errorf("read vault: %w", err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("%w: parse: %v", errBadVaultFormat, err)
	}
	if cfg.Version != 1 {
		return cfg, fmt.Errorf("%w: version %d", errBadVaultFormat, cfg.Version)
	}
	if cfg.KDF.Algorithm != kdfAlgorithmName {
		return cfg, fmt.Errorf("%w: %s", errBadKDFAlgo, cfg.KDF.Algorithm)
	}
	if cfg.Verify == "" {
		return cfg, fmt.Errorf("%w: missing verify blob", errBadVaultFormat)
	}
	if cfg.KDF.MemoryKiB == 0 || cfg.KDF.Iterations == 0 || cfg.KDF.Parallelism == 0 {
		return cfg, fmt.Errorf("%w: zero KDF cost params", errBadVaultFormat)
	}
	salt, err := base64.StdEncoding.DecodeString(cfg.KDF.Salt)
	if err != nil || len(salt) == 0 {
		return cfg, fmt.Errorf("%w: invalid KDF salt", errBadVaultFormat)
	}
	return cfg, nil
}

// saveNewVault writes vault.json with 0600 perms using O_EXCL so the
// write fails atomically if a vault already exists. Two concurrent
// `hush init` calls can't both succeed — exactly one wins, the other
// surfaces errVaultExists. Creates the parent dir with 0700 if missing.
func saveNewVault(cfg VaultConfig) error {
	p, err := vaultPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("create vault dir: %w", err)
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// O_EXCL is the race-free version of "create iff not exist". Pairs
	// with the user-facing errVaultExists so the CLI can map it to a
	// friendly message.
	// #nosec G304 -- p is computed from configPath(); see loadVault.
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, vaultFileMode)
	if errors.Is(err, os.ErrExist) {
		return errVaultExists
	}
	if err != nil {
		return fmt.Errorf("write vault: %w", err)
	}
	if _, werr := f.Write(raw); werr != nil {
		_ = f.Close()
		// Clean up the empty/partial file so retries don't dead-end on
		// errVaultExists. Ignore the remove error: if it also fails the
		// user has a worse problem than we can hide.
		_ = os.Remove(p)
		return fmt.Errorf("write vault: %w", werr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(p)
		return fmt.Errorf("write vault: %w", cerr)
	}
	return nil
}

// unlockIfPresent is the standard "do I have a vault, and if so, get me
// the key" entry point for network subcommands. Returns (nil, nil) when
// no vault exists — callers should treat that as "operate in v1 plaintext
// passthrough mode." Returns (key, nil) when a vault exists and the
// user-supplied passphrase unlocks it. promptFn is called exactly once.
func unlockIfPresent(promptFn func(prompt string) (string, error)) ([]byte, error) {
	cfg, err := loadVault()
	if errors.Is(err, errVaultMissing) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pass, err := promptFn("vault passphrase: ")
	if err != nil {
		return nil, err
	}
	return unlock(cfg, pass)
}

// unlock derives the vault key from the passphrase and validates it
// against the stored verify blob. Returns errBadPassphrase on tag
// mismatch — distinguishable from corruption / IO errors so the CLI can
// re-prompt instead of bailing.
func unlock(cfg VaultConfig, passphrase string) ([]byte, error) {
	key, err := deriveKey(passphrase, cfg.KDF)
	if err != nil {
		return nil, err
	}
	if _, err := decryptWireFormat(key, cfg.Verify, []byte(verifyAAD)); err != nil {
		if errors.Is(err, errBadPassphrase) || errors.Is(err, errBadWireFormat) {
			return nil, errBadPassphrase
		}
		return nil, err
	}
	return key, nil
}

// deriveKey runs Argon2id with the given params. Returns a 32-byte key
// suitable for XChaCha20-Poly1305.
func deriveKey(passphrase string, p KDFParams) ([]byte, error) {
	if p.Algorithm != kdfAlgorithmName {
		return nil, fmt.Errorf("%w: %s", errBadKDFAlgo, p.Algorithm)
	}
	if p.MemoryKiB == 0 || p.Iterations == 0 || p.Parallelism == 0 {
		return nil, errors.New("invalid KDF params (zero memory/iterations/parallelism)")
	}
	salt, err := base64.StdEncoding.DecodeString(p.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	if len(salt) == 0 {
		return nil, errors.New("invalid KDF params (empty salt)")
	}
	return argon2.IDKey([]byte(passphrase), salt, p.Iterations, p.MemoryKiB, p.Parallelism, keyBytes), nil
}

// encryptWireFormat produces "hh2:<base64(nonce || ciphertext)>" for
// the given plaintext and AAD. The 24-byte XChaCha20 nonce is generated
// with crypto/rand — XChaCha20's 192-bit nonce means random nonces are
// safe to the birthday bound (no per-key counter needed).
func encryptWireFormat(key, plaintext, aad []byte) (string, error) {
	if len(key) != keyBytes {
		return "", fmt.Errorf("key must be %d bytes, got %d", keyBytes, len(key))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce rng: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)
	blob := make([]byte, 0, len(nonce)+len(ct))
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	return vaultPrefix + base64.StdEncoding.EncodeToString(blob), nil
}

// decryptWireFormat reverses encryptWireFormat. Returns errNotEncrypted
// if the value doesn't have the v2 prefix (so callers can detect "this
// is a v1 plaintext secret — needs migration"). Returns errBadPassphrase
// on AEAD tag failure so the CLI can map to a clear user-facing message.
func decryptWireFormat(key []byte, wireValue string, aad []byte) ([]byte, error) {
	if !strings.HasPrefix(wireValue, vaultPrefix) {
		return nil, errNotEncrypted
	}
	if len(key) != keyBytes {
		return nil, fmt.Errorf("key must be %d bytes, got %d", keyBytes, len(key))
	}
	blob, err := base64.StdEncoding.DecodeString(wireValue[len(vaultPrefix):])
	if err != nil {
		return nil, fmt.Errorf("%w: base64: %v", errBadWireFormat, err)
	}
	if len(blob) < nonceBytes+chacha20poly1305.Overhead {
		return nil, errBadWireFormat
	}
	nonce, ct := blob[:nonceBytes], blob[nonceBytes:]
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		// AEAD tag mismatch means either the key is wrong (passphrase)
		// or the ciphertext / AAD was tampered with. The CLI surfaces
		// this as "wrong passphrase" because the alternative requires
		// an attacker with write access to the DB, in which case the
		// user has bigger problems.
		return nil, errBadPassphrase
	}
	return pt, nil
}

// newSalt returns a freshly-generated salt of the standard size, or an
// error if the platform RNG is exhausted (essentially impossible on
// modern Unix-likes; surfaced explicitly so callers don't proceed with
// a zero salt).
func newSalt() ([]byte, error) {
	salt := make([]byte, vaultSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("salt rng: %w", err)
	}
	return salt, nil
}

