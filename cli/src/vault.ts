// Client-side encryption ("v2"). The user types a passphrase; Argon2id turns
// it into a key; each secret value is sealed with XChaCha20-Poly1305 before it
// leaves the machine. The server never sees the passphrase or the key, and its
// own AES-GCM layer sits underneath as a second, independent layer.
//
// The format is byte-compatible with the Go `hush` client this replaces, so
// vault.json files and `hh2:` values written by either work with both:
//
//   value      = "hh2:" + base64( nonce(24) || XChaCha20-Poly1305(plaintext, aad=name) )
//   vault.json = { version: 1, kdf: { algorithm, memory_kib, iterations, parallelism, salt }, verify }
//
// where `verify` is the value-format encryption of a fixed sentinel under the
// derived key, used to reject a wrong passphrase before any network traffic.
// Design rationale: docs/adr/0001-client-side-encryption.md.

import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { argon2id } from "@noble/hashes/argon2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

export const VAULT_FILE = "vault.json";
export const VAULT_PREFIX = "hh2:";
const KDF_ALGORITHM = "argon2id";
// Encrypted under the derived key and stored in vault.json so unlock can
// reject a wrong passphrase up front. Opaque sentinels; the AAD is distinct
// from any secret name so a verify blob can't be replayed as a secret value.
const VERIFY_PLAINTEXT = "hush-vault-v1";
const VERIFY_AAD = "hush-vault-verify";
const SALT_BYTES = 16;
const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const TAG_BYTES = 16;

// A vault.json is trusted input only up to a point: refuse cost parameters that
// would make the client allocate absurd amounts of memory or burn minutes of
// CPU. These are far above the defaults (64 MiB, t=3, p=4).
const MAX_MEMORY_KIB = 1024 * 1024; // 1 GiB
const MAX_ITERATIONS = 64;
const MAX_PARALLELISM = 64;

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: false });

export type VaultErrorCode =
  | "bad_passphrase"
  | "exists"
  | "missing"
  | "bad_kdf"
  | "bad_format"
  | "not_encrypted"
  | "bad_wire";

const MESSAGES: Record<VaultErrorCode, string> = {
  bad_passphrase: "wrong passphrase",
  exists: "vault already exists",
  missing: "vault not initialized (run `hush init`)",
  bad_kdf: "unsupported KDF algorithm in vault.json",
  bad_format: "vault.json is malformed or unsupported version",
  not_encrypted: "value is not in v2 client-encrypted format",
  bad_wire: "encrypted value is malformed",
};

export class VaultError extends Error {
  constructor(
    readonly code: VaultErrorCode,
    detail?: string,
  ) {
    super(detail ? `${MESSAGES[code]}: ${detail}` : MESSAGES[code]);
  }
}

export interface KdfParams {
  algorithm: string;
  memory_kib: number;
  iterations: number;
  parallelism: number;
  /** base64 */
  salt: string;
}

export interface VaultConfig {
  version: number;
  kdf: KdfParams;
  verify: string;
}

/** OWASP 2025 guidance for Argon2id: m=64 MiB, t=3, p=4 (about half a second on a laptop). */
export function defaultKdfParams(salt: Uint8Array): KdfParams {
  return {
    algorithm: KDF_ALGORITHM,
    memory_kib: 64 * 1024,
    iterations: 3,
    parallelism: 4,
    salt: Buffer.from(salt).toString("base64"),
  };
}

export function newSalt(): Uint8Array {
  return new Uint8Array(randomBytes(SALT_BYTES));
}

/** Standard padded base64 only (Go's StdEncoding is strict; Node's decoder is not). */
function decodeBase64Strict(s: string): Uint8Array | null {
  if (s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const buf = Buffer.from(s, "base64");
  return buf.toString("base64") === s ? new Uint8Array(buf) : null;
}

const isPositiveInt = (n: unknown): n is number => typeof n === "number" && Number.isInteger(n) && n > 0;

function checkKdf(p: KdfParams): Uint8Array {
  if (p.algorithm !== KDF_ALGORITHM) throw new VaultError("bad_kdf", String(p.algorithm));
  if (!isPositiveInt(p.memory_kib) || !isPositiveInt(p.iterations) || !isPositiveInt(p.parallelism)) {
    throw new VaultError("bad_format", "zero or invalid KDF cost params");
  }
  if (p.memory_kib > MAX_MEMORY_KIB || p.iterations > MAX_ITERATIONS || p.parallelism > MAX_PARALLELISM) {
    throw new VaultError("bad_format", "KDF cost params exceed the supported maximum");
  }
  const salt = typeof p.salt === "string" ? decodeBase64Strict(p.salt) : null;
  if (salt === null || salt.length === 0) throw new VaultError("bad_format", "invalid KDF salt");
  return salt;
}

/** Argon2id over the UTF-8 passphrase. Returns the 32-byte vault key. */
export function deriveKey(passphrase: string, p: KdfParams): Uint8Array {
  const salt = checkKdf(p);
  return argon2id(enc.encode(passphrase), salt, {
    t: p.iterations,
    m: p.memory_kib,
    p: p.parallelism,
    dkLen: KEY_BYTES,
  });
}

/**
 * "hh2:" + base64(nonce || ciphertext). XChaCha20's 192-bit nonce makes random
 * nonces safe to the birthday bound, so no per-key counter state is needed.
 * `nonce` is for tests only.
 */
export function encryptWire(key: Uint8Array, plaintext: string, aad: string, nonce?: Uint8Array): string {
  if (key.length !== KEY_BYTES) throw new Error(`key must be ${KEY_BYTES} bytes, got ${key.length}`);
  const n = nonce ?? new Uint8Array(randomBytes(NONCE_BYTES));
  const ct = xchacha20poly1305(key, n, enc.encode(aad)).encrypt(enc.encode(plaintext));
  const blob = new Uint8Array(n.length + ct.length);
  blob.set(n, 0);
  blob.set(ct, n.length);
  return VAULT_PREFIX + Buffer.from(blob).toString("base64");
}

/**
 * Reverses encryptWire. Throws "not_encrypted" for a value without the prefix
 * (a v1 plaintext), "bad_wire" for a malformed one, and "bad_passphrase" when
 * the AEAD tag fails: that means a wrong key, or a ciphertext/name that was
 * tampered with (which needs write access to the server, a bigger problem).
 */
export function decryptWire(key: Uint8Array, wire: string, aad: string): string {
  if (!wire.startsWith(VAULT_PREFIX)) throw new VaultError("not_encrypted");
  if (key.length !== KEY_BYTES) throw new Error(`key must be ${KEY_BYTES} bytes, got ${key.length}`);
  const blob = decodeBase64Strict(wire.slice(VAULT_PREFIX.length));
  if (blob === null) throw new VaultError("bad_wire", "base64");
  if (blob.length < NONCE_BYTES + TAG_BYTES) throw new VaultError("bad_wire");
  try {
    const pt = xchacha20poly1305(key, blob.subarray(0, NONCE_BYTES), enc.encode(aad)).decrypt(
      blob.subarray(NONCE_BYTES),
    );
    return dec.decode(pt);
  } catch {
    throw new VaultError("bad_passphrase");
  }
}

export function vaultPath(configDir: string): string {
  return join(configDir, VAULT_FILE);
}

/** Creates vault.json (mode 0600) for `passphrase`. Refuses to overwrite: that would strand existing secrets. */
export async function initVault(configDir: string, passphrase: string, params: KdfParams): Promise<VaultConfig> {
  const key = deriveKey(passphrase, params);
  const cfg: VaultConfig = {
    version: 1,
    kdf: params,
    verify: encryptWire(key, VERIFY_PLAINTEXT, VERIFY_AAD),
  };
  const path = vaultPath(configDir);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  try {
    // "wx" is the race-free "create iff absent": two concurrent inits can't both win.
    await writeFile(path, JSON.stringify(cfg, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new VaultError("exists");
    // Don't leave a partial file that would make retries dead-end on "exists".
    await rm(path, { force: true });
    throw e;
  }
  return cfg;
}

/**
 * Reads vault.json. "missing" means not set up; any structural defect is
 * "bad_format", so a later decrypt failure can only mean a wrong passphrase.
 */
export async function loadVault(configDir: string): Promise<VaultConfig> {
  let raw: string;
  try {
    raw = await readFile(vaultPath(configDir), "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") throw new VaultError("missing");
    throw e;
  }
  let cfg: VaultConfig;
  try {
    cfg = JSON.parse(raw) as VaultConfig;
  } catch (e) {
    throw new VaultError("bad_format", `parse: ${(e as Error).message}`);
  }
  if (typeof cfg !== "object" || cfg === null || typeof cfg.kdf !== "object" || cfg.kdf === null) {
    throw new VaultError("bad_format", "missing kdf");
  }
  if (cfg.version !== 1) throw new VaultError("bad_format", `version ${String(cfg.version)}`);
  if (cfg.kdf.algorithm !== KDF_ALGORITHM) throw new VaultError("bad_kdf", String(cfg.kdf.algorithm));
  if (typeof cfg.verify !== "string" || cfg.verify === "") throw new VaultError("bad_format", "missing verify blob");
  checkKdf(cfg.kdf);
  return cfg;
}

/** Derives the key and checks it against the verify blob. Throws "bad_passphrase" on mismatch. */
export function unlock(cfg: VaultConfig, passphrase: string): Uint8Array {
  const key = deriveKey(passphrase, cfg.kdf);
  try {
    decryptWire(key, cfg.verify, VERIFY_AAD);
  } catch (e) {
    if (e instanceof VaultError && (e.code === "bad_passphrase" || e.code === "bad_wire")) {
      throw new VaultError("bad_passphrase");
    }
    throw e;
  }
  return key;
}

/**
 * The standard entry point for network commands: no vault means v1 plaintext
 * passthrough (returns null); with a vault, prompts once and returns the key.
 */
export async function unlockIfPresent(
  configDir: string,
  prompt: (label: string) => Promise<string>,
): Promise<Uint8Array | null> {
  let cfg: VaultConfig;
  try {
    cfg = await loadVault(configDir);
  } catch (e) {
    if (e instanceof VaultError && e.code === "missing") return null;
    throw e;
  }
  return unlock(cfg, await prompt("vault passphrase: "));
}
