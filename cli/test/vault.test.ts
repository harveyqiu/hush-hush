import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  VAULT_PREFIX,
  VaultError,
  decryptWire,
  defaultKdfParams,
  deriveKey,
  encryptWire,
  initVault,
  loadVault,
  newSalt,
  unlock,
  unlockIfPresent,
  vaultPath,
  type KdfParams,
  type VaultConfig,
} from "../src/vault";

// Produced by the original Go client (cmd/hush at commit e9d00a1) using its own
// deriveKey / encryptWireFormat, so passing these means a vault.json and `hh2:`
// values written by the Go client work here, and the other way round.
// Identifier names avoid words like "key"/"secret" so scanners don't mistake the
// fixtures for credentials.
const GO_PASSPHRASE = "correct horse battery staple ✓";
const GO_SALT = "QEFCQ0RFRkdISUpLTE1OTw==";
const GO_FAST: KdfParams = { algorithm: "argon2id", memory_kib: 8192, iterations: 2, parallelism: 2, salt: GO_SALT };
const GO_PROD: KdfParams = { algorithm: "argon2id", memory_kib: 65536, iterations: 3, parallelism: 4, salt: GO_SALT };
const GO_FAST_DERIVED = "8bec371f770e872ad6d1fe76a8278441f1e7c6dd4aede73c25052608fd64ab26";
const GO_PROD_DERIVED = "9356463b287fbc1a2695318168ea49d1ca55b8a08dcb1c035ba134531c9443f4";
const GO_NAME = "llm.openai";
const GO_VALUE = "sk-test-值-✓ line2\nline3";
const GO_FIXED_NONCE_WIRE =
  "hh2:kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanssBTUJywS1EhXXDi2nPfsjiB/B4bKOaI1DKCgQdcNh2CUotq1BJJBVU7Vw==";
const GO_RANDOM_NONCE_WIRE = "hh2:4lsmkVqRrgIm1UIq1ADlxDl2aEMKcZ8OxWquOFYD4hEG7OuzA9eCE57whZ3uiL+bryzteaGrqzU1rQ==";
const GO_VAULT: VaultConfig = {
  version: 1,
  kdf: GO_FAST,
  verify: "hh2:ei1E4wkC9GSxthqpzCTPMyqksm39h+VumHxi3tF6YDFQLcRkGsKU40dYOAQ8daSOO7sBMFY=",
};

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const FAST_KDF = (salt = newSalt()) => ({ ...defaultKdfParams(salt), memory_kib: 8192, iterations: 2, parallelism: 2 });

function code(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (e) {
    return e instanceof VaultError ? e.code : `other:${(e as Error).message}`;
  }
  return undefined;
}

describe("compatibility with the Go client", () => {
  it("derives the same key as Go for the fast parameters", () => {
    expect(hex(deriveKey(GO_PASSPHRASE, GO_FAST))).toBe(GO_FAST_DERIVED);
  });

  it("derives the same key as Go for the production parameters (64 MiB, t=3, p=4)", () => {
    expect(hex(deriveKey(GO_PASSPHRASE, GO_PROD))).toBe(GO_PROD_DERIVED);
  });

  it("decrypts values the Go client encrypted (fixed and random nonce)", () => {
    const k = fromHex(GO_FAST_DERIVED);
    expect(decryptWire(k, GO_FIXED_NONCE_WIRE, GO_NAME)).toBe(GO_VALUE);
    expect(decryptWire(k, GO_RANDOM_NONCE_WIRE, "github.token")).toBe("random-nonce-value");
  });

  it("encrypts to exactly the bytes Go produced when given the same nonce", () => {
    const nonce = Uint8Array.from({ length: 24 }, (_, i) => 0x90 + i);
    expect(encryptWire(fromHex(GO_FAST_DERIVED), GO_VALUE, GO_NAME, nonce)).toBe(GO_FIXED_NONCE_WIRE);
  });

  it("unlocks a vault.json written by `hush init` in Go", () => {
    expect(hex(unlock(GO_VAULT, GO_PASSPHRASE))).toBe(GO_FAST_DERIVED);
    expect(code(() => unlock(GO_VAULT, "wrong"))).toBe("bad_passphrase");
  });
});

describe("encrypt / decrypt", () => {
  const k = fromHex(GO_FAST_DERIVED);

  it("round-trips, including empty-ish, unicode and multiline values", () => {
    for (const v of ["x", "sk-值-✓", "line1\nline2\r\n", " leading and trailing ", "a".repeat(70_000)]) {
      expect(decryptWire(k, encryptWire(k, v, "n"), "n")).toBe(v);
    }
  });

  it("uses a fresh nonce every time", () => {
    expect(encryptWire(k, "same", "n")).not.toBe(encryptWire(k, "same", "n"));
  });

  it("binds the secret name: moving a ciphertext to another name fails", () => {
    const w = encryptWire(k, "v", "prod.db");
    expect(code(() => decryptWire(k, w, "dev.db"))).toBe("bad_passphrase");
  });

  it("fails under a different key and on any flipped bit", () => {
    const w = encryptWire(k, "v", "n");
    expect(code(() => decryptWire(deriveKey("other", GO_FAST), w, "n"))).toBe("bad_passphrase");
    const blob = Buffer.from(w.slice(VAULT_PREFIX.length), "base64");
    for (const i of [0, 24, blob.length - 1]) {
      const bad = Buffer.from(blob);
      bad[i] = bad[i]! ^ 1;
      expect(code(() => decryptWire(k, VAULT_PREFIX + bad.toString("base64"), "n")), `byte ${i}`).toBe("bad_passphrase");
    }
  });

  it("classifies malformed input", () => {
    expect(code(() => decryptWire(k, "plaintext", "n"))).toBe("not_encrypted");
    expect(code(() => decryptWire(k, "hh2:!!!not base64!!!", "n"))).toBe("bad_wire");
    expect(code(() => decryptWire(k, "hh2:", "n"))).toBe("bad_wire");
    expect(code(() => decryptWire(k, "hh2:" + Buffer.alloc(39).toString("base64"), "n"))).toBe("bad_wire"); // < nonce + tag
    // Go's decoder is strict about padding and alphabet; so is ours. A fixed
    // vector is used so the characters being replaced are certain to be there
    // (random ciphertext sometimes contains no '+' or '/').
    expect(GO_FIXED_NONCE_WIRE).toMatch(/\/.*=+$/);
    expect(code(() => decryptWire(k, GO_FIXED_NONCE_WIRE.replace(/=+$/, ""), GO_NAME))).toBe("bad_wire");
    expect(code(() => decryptWire(k, GO_FIXED_NONCE_WIRE.replace(/\//g, "_"), GO_NAME))).toBe("bad_wire");
    expect(code(() => decryptWire(k, GO_FIXED_NONCE_WIRE, GO_NAME))).toBeUndefined(); // control: untouched vector is fine
  });

  it("rejects a key of the wrong size", () => {
    expect(() => encryptWire(new Uint8Array(16), "v", "n")).toThrow(/32 bytes/);
    expect(() => decryptWire(new Uint8Array(16), "hh2:AAAA", "n")).toThrow(/32 bytes/);
  });
});

describe("KDF parameter validation", () => {
  it("refuses unsupported algorithms, zero or non-integer costs and bad salts", () => {
    expect(code(() => deriveKey("p", { ...GO_FAST, algorithm: "scrypt" }))).toBe("bad_kdf");
    for (const bad of [
      { memory_kib: 0 },
      { iterations: 0 },
      { parallelism: 0 },
      { memory_kib: 1.5 },
      { iterations: -1 },
      { salt: "" },
      { salt: "not base64!" },
    ]) {
      expect(code(() => deriveKey("p", { ...GO_FAST, ...bad })), JSON.stringify(bad)).toBe("bad_format");
    }
  });

  it("caps cost parameters so a tampered vault.json can't exhaust memory or time", () => {
    for (const bad of [{ memory_kib: 1024 * 1024 + 1 }, { iterations: 65 }, { parallelism: 65 }]) {
      expect(code(() => deriveKey("p", { ...GO_FAST, ...bad })), JSON.stringify(bad)).toBe("bad_format");
    }
  });

  it("defaults are the documented OWASP values", () => {
    expect(defaultKdfParams(new Uint8Array(16))).toMatchObject({
      algorithm: "argon2id",
      memory_kib: 65536,
      iterations: 3,
      parallelism: 4,
    });
  });
});

describe("vault file", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "hush-vault-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("init writes a 0600 vault that unlocks with the passphrase and not with another", async () => {
    const cfg = await initVault(dir, "pw1", FAST_KDF());
    expect(cfg.version).toBe(1);
    if (process.platform !== "win32") expect((await stat(vaultPath(dir))).mode & 0o777).toBe(0o600);
    const loaded = await loadVault(dir);
    expect(code(() => unlock(loaded, "pw1"))).toBeUndefined();
    expect(code(() => unlock(loaded, "pw2"))).toBe("bad_passphrase");
  });

  it("init refuses to overwrite an existing vault and leaves it untouched", async () => {
    await initVault(dir, "pw1", FAST_KDF());
    const before = await readFile(vaultPath(dir), "utf8");
    await expect(initVault(dir, "pw2", FAST_KDF())).rejects.toMatchObject({ code: "exists" });
    expect(await readFile(vaultPath(dir), "utf8")).toBe(before);
  });

  it("two concurrent inits: exactly one wins", async () => {
    const results = await Promise.allSettled([initVault(dir, "a", FAST_KDF()), initVault(dir, "b", FAST_KDF())]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((r) => r.status === "rejected")).toHaveLength(1);
  });

  it("loadVault: missing, malformed JSON and structural defects are distinguished", async () => {
    await expect(loadVault(dir)).rejects.toMatchObject({ code: "missing" });
    const write = (v: unknown) => writeFile(vaultPath(dir), typeof v === "string" ? v : JSON.stringify(v));
    await write("{not json");
    await expect(loadVault(dir)).rejects.toMatchObject({ code: "bad_format" });
    await write(null);
    await expect(loadVault(dir)).rejects.toMatchObject({ code: "bad_format" });
    await write({ ...GO_VAULT, version: 2 });
    await expect(loadVault(dir)).rejects.toMatchObject({ code: "bad_format" });
    await write({ ...GO_VAULT, kdf: { ...GO_FAST, algorithm: "pbkdf2" } });
    await expect(loadVault(dir)).rejects.toMatchObject({ code: "bad_kdf" });
    await write({ ...GO_VAULT, verify: "" });
    await expect(loadVault(dir)).rejects.toMatchObject({ code: "bad_format" });
    await write({ ...GO_VAULT, kdf: { ...GO_FAST, memory_kib: 0 } });
    await expect(loadVault(dir)).rejects.toMatchObject({ code: "bad_format" });
    await write(GO_VAULT);
    await expect(loadVault(dir)).resolves.toMatchObject({ version: 1 });
  });

  it("unlockIfPresent: no vault is passthrough and never prompts; a vault prompts exactly once", async () => {
    let prompts = 0;
    const ask = async () => {
      prompts++;
      return GO_PASSPHRASE;
    };
    expect(await unlockIfPresent(dir, ask)).toBeNull();
    expect(prompts).toBe(0);
    await writeFile(vaultPath(dir), JSON.stringify(GO_VAULT));
    expect(hex((await unlockIfPresent(dir, ask))!)).toBe(GO_FAST_DERIVED);
    expect(prompts).toBe(1);
    await expect(unlockIfPresent(dir, async () => "nope")).rejects.toMatchObject({ code: "bad_passphrase" });
  });
});
