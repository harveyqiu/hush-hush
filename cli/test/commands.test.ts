import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { run } from "../src/main";
import { configPath } from "../src/config";
import { VAULT_PREFIX, defaultKdfParams, newSalt, vaultPath } from "../src/vault";
import { startMock, type MockServer } from "./mock-server";

let mock: MockServer;
let dir: string;
beforeEach(async () => {
  mock = await startMock();
  dir = await mkdtemp(join(tmpdir(), "hush-cli-"));
});
afterEach(async () => {
  await mock.close();
  await rm(dir, { recursive: true, force: true });
});

interface Opts {
  /** Answers to hidden prompts, in order. */
  prompts?: string[];
  stdin?: string;
  tty?: boolean;
  env?: Record<string, string>;
  noConn?: boolean;
}

/** Runs the CLI in-process against the mock server. */
async function hush(args: string[], o: Opts = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const asked: string[] = [];
  const answers = [...(o.prompts ?? [])];
  const stdin = Object.assign(Readable.from([o.stdin ?? ""]), { isTTY: o.tty === true });
  const code = await run(args, {
    stdout: { write: (s) => out.push(s) },
    stderr: { write: (s) => err.push(s) },
    stdin,
    env: o.noConn ? { ...o.env } : { HUSH_URL: mock.url, HUSH_TOKEN: mock.token, ...o.env },
    configDir: dir,
    prompt: async (label) => {
      asked.push(label);
      const a = answers.shift();
      if (a === undefined) throw new Error("test: unexpected prompt " + label);
      return a;
    },
    kdfParams: () => ({ ...defaultKdfParams(newSalt()), memory_kib: 8192, iterations: 2, parallelism: 2 }),
  });
  return { code, out: out.join(""), err: err.join(""), asked };
}

const PASS = "correct horse";
async function initVault() {
  const r = await hush(["init"], { prompts: [PASS, PASS] });
  expect(r.code).toBe(0);
}

describe("invocation", () => {
  it("no arguments or an unknown command: usage on stderr, exit 2", async () => {
    const a = await hush([]);
    expect(a.code).toBe(2);
    expect(a.err).toContain("Usage:");
    const b = await hush(["frobnicate"]);
    expect(b.code).toBe(2);
    expect(b.err).toContain("unknown command: frobnicate");
  });

  it("help and version exit 0", async () => {
    expect((await hush(["help"])).out).toContain("Commands:");
    expect((await hush(["--help"])).code).toBe(0);
    expect((await hush(["--version"])).out).toMatch(/^hush \S+\n$/);
  });

  it("rejects unknown flags and stray arguments", async () => {
    expect((await hush(["list", "--nope"])).err).toMatch(/list: .*--nope/);
    expect((await hush(["list", "extra"])).err).toContain("list: unexpected arguments: extra");
    expect((await hush(["get", "a", "b"])).err).toContain("get: unexpected arguments: b");
    expect((await hush(["get"])).err).toContain("get: NAME is required");
    expect((await hush(["put"])).err).toContain("put: NAME is required");
    expect((await hush(["delete"])).err).toContain("delete: NAME is required");
  });

  it("without URL or token configured it says how to set them", async () => {
    expect((await hush(["list"], { noConn: true })).err).toContain("no URL configured");
    expect((await hush(["list"], { noConn: true, env: { HUSH_URL: mock.url } })).err).toContain("no token configured");
  });
});

describe("login", () => {
  it("saves a 0600 config that later commands use", async () => {
    const r = await hush(["login", "--url", mock.url, "--token", mock.token], { noConn: true });
    expect(r.code).toBe(0);
    expect(r.out).toContain(configPath(dir));
    if (process.platform !== "win32") expect((await stat(configPath(dir))).mode & 0o777).toBe(0o600);
    expect((await hush(["list"], { noConn: true })).code).toBe(0);
  });

  it("needs both flags and refuses http to a remote host before saving anything", async () => {
    expect((await hush(["login", "--url", mock.url], { noConn: true })).err).toContain("--url and --token are required");
    const r = await hush(["login", "--url", "http://example.com", "--token", "t"], { noConn: true });
    expect(r.code).toBe(1);
    expect(r.err).toContain("only sent over https");
    await expect(readFile(configPath(dir), "utf8")).rejects.toThrow();
  });

  it("flags override the environment, which overrides the file", async () => {
    await hush(["login", "--url", "http://127.0.0.1:9", "--token", "x"], { noConn: true });
    expect((await hush(["list"], { noConn: true })).err).toMatch(/cannot reach the server/);
    expect((await hush(["list", "--url", mock.url, "--token", mock.token], { noConn: true })).code).toBe(0);
    expect((await hush(["list"], { noConn: true, env: { HUSH_URL: mock.url, HUSH_TOKEN: mock.token } })).code).toBe(0);
  });
});

describe("health", () => {
  it("reports reachable and auth ok", async () => {
    const r = await hush(["health"]);
    expect(r.code).toBe(0);
    expect(r.out).toBe(`${mock.url}: reachable\nauth: ok\n`);
  });
  it("skips the auth check without a token", async () => {
    const r = await hush(["health"], { noConn: true, env: { HUSH_URL: mock.url } });
    expect(r.out).toContain("auth: skipped (no token configured)");
    expect(r.code).toBe(0);
  });
  it("fails clearly on a bad token and on an unreachable server", async () => {
    const bad = await hush(["health", "--token", "hush_wrong"]);
    expect(bad.code).toBe(1);
    expect(bad.err).toContain("auth check failed: server returned 401: unauthorized");
    const down = await hush(["health", "--url", "http://127.0.0.1:9"]);
    expect(down.code).toBe(1);
    expect(down.err).toContain("reachability check failed: cannot reach the server");
  });
});

describe("put / get / delete / list without a vault (plaintext passthrough)", () => {
  it("stores the value as given and prints it back without a trailing newline", async () => {
    expect((await hush(["put", "llm.openai", "sk-1"])).out).toBe("llm.openai: saved\n");
    expect(mock.store.get("llm.openai")!.value).toBe("sk-1");
    expect((await hush(["get", "llm.openai"])).out).toBe("sk-1");
  });

  it("reads the value from stdin or a file, stripping one trailing newline", async () => {
    await hush(["put", "a", "--from-stdin"], { stdin: "from-stdin\n" });
    expect(mock.store.get("a")!.value).toBe("from-stdin");
    const f = join(dir, "v.txt");
    await writeFile(f, "line1\nline2\n\n");
    await hush(["put", "b", "--from-file", f]);
    expect(mock.store.get("b")!.value).toBe("line1\nline2\n");
  });

  it("prompts for the value when run from a terminal; without one it refuses", async () => {
    const r = await hush(["put", "c"], { tty: true, prompts: ["typed-secret"] });
    expect(r.asked).toEqual(["value: "]);
    expect(mock.store.get("c")!.value).toBe("typed-secret");
    expect((await hush(["put", "d"])).err).toContain("no value source");
  });

  it("refuses two value sources and an empty value", async () => {
    expect((await hush(["put", "a", "v", "--from-stdin"], { stdin: "x" })).err).toContain("at most one of");
    expect((await hush(["put", "a", "--from-stdin"], { stdin: "\n" })).err).toContain("value is empty");
    expect(mock.store.size).toBe(0);
  });

  it("reserves the hh2: prefix for client-encrypted values", async () => {
    const r = await hush(["put", "a", "hh2:looks-like-ciphertext"]);
    expect(r.code).toBe(1);
    expect(r.err).toContain("reserved for client-encrypted secrets");
    expect(mock.store.size).toBe(0);
  });

  it("delete is idempotent; get of a missing name is a clear 404", async () => {
    await hush(["put", "a", "v"]);
    expect((await hush(["delete", "a"])).out).toBe("a: deleted\n");
    expect((await hush(["delete", "a"])).code).toBe(0);
    const r = await hush(["get", "a"]);
    expect(r.code).toBe(1);
    expect(r.err).toBe("error: get: server returned 404: not found\n");
  });

  it("list prints an aligned table, JSON on request, and says when empty", async () => {
    expect((await hush(["list"])).out).toBe("(no secrets)\n");
    await hush(["put", "github.token", "1"]);
    await hush(["put", "a", "2"]);
    const table = (await hush(["list"])).out.trimEnd().split("\n");
    expect(table[0]).toMatch(/^NAME {2,}CREATED {2,}UPDATED$/);
    expect(table[1]).toMatch(/^a +\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ +\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    expect(table[2]).toMatch(/^github\.token /);
    const json = JSON.parse((await hush(["list", "--json"])).out) as { name: string }[];
    expect(json.map((s) => s.name)).toEqual(["a", "github.token"]);
  });

  it("server errors are reported with the command and the status", async () => {
    const r = await hush(["list", "--token", "hush_wrong"]);
    expect(r.err).toBe("error: list: server returned 401: unauthorized\n");
    mock.override.set("GET /v1/secrets", { status: 429, body: '{"error":"rate_limited"}', headers: { "Retry-After": "12" } });
    expect((await hush(["list"])).err).toContain("rate_limited (retry after 12s)");
  });
});

describe("hush init", () => {
  it("creates a 0600 vault and warns about the passphrase", async () => {
    const r = await hush(["init"], { prompts: [PASS, PASS] });
    expect(r.code).toBe(0);
    expect(r.asked).toEqual(["vault passphrase: ", "confirm passphrase: "]);
    expect(r.out).toContain("IMPORTANT: back up this passphrase");
    if (process.platform !== "win32") expect((await stat(vaultPath(dir))).mode & 0o777).toBe(0o600);
  });

  it("rejects an empty passphrase and a mismatch, creating nothing", async () => {
    expect((await hush(["init"], { prompts: [""] })).err).toContain("passphrase cannot be empty");
    expect((await hush(["init"], { prompts: ["a", "b"] })).err).toContain("passphrases do not match");
    await expect(stat(vaultPath(dir))).rejects.toThrow();
  });

  it("refuses to re-initialize, without even asking for a passphrase", async () => {
    await initVault();
    const before = await readFile(vaultPath(dir), "utf8");
    const r = await hush(["init"], { prompts: [] });
    expect(r.code).toBe(1);
    expect(r.err).toContain("vault already exists");
    expect(r.asked).toEqual([]);
    expect(await readFile(vaultPath(dir), "utf8")).toBe(before);
  });
});

describe("with a vault (client-side encryption)", () => {
  beforeEach(initVault);

  it("put encrypts before sending; the server never sees the plaintext; get decrypts", async () => {
    const r = await hush(["put", "llm.openai", "sk-plain-value"], { prompts: [PASS] });
    expect(r.code).toBe(0);
    const stored = mock.store.get("llm.openai")!.value;
    expect(stored.startsWith(VAULT_PREFIX)).toBe(true);
    expect(stored).not.toContain("sk-plain-value");
    expect(mock.requests.join("\n")).not.toContain("sk-plain-value");
    const g = await hush(["get", "llm.openai"], { prompts: [PASS] });
    expect(g.out).toBe("sk-plain-value");
    expect(g.asked).toEqual(["vault passphrase: "]); // exactly one prompt per command
  });

  it("a wrong passphrase makes NO network request and changes nothing", async () => {
    await hush(["put", "a", "v"], { prompts: [PASS] });
    mock.requests.length = 0;
    const before = mock.store.get("a")!.value;
    for (const args of [["get", "a"], ["put", "a", "new"], ["migrate"]]) {
      const r = await hush(args, { prompts: ["wrong"] });
      expect(r.code, args.join(" ")).toBe(1);
      expect(r.err).toContain("wrong passphrase");
    }
    expect(mock.requests).toEqual([]);
    expect(mock.store.get("a")!.value).toBe(before);
  });

  it("each secret gets a fresh nonce, so equal values encrypt differently", async () => {
    await hush(["put", "a", "same"], { prompts: [PASS] });
    await hush(["put", "b", "same"], { prompts: [PASS] });
    expect(mock.store.get("a")!.value).not.toBe(mock.store.get("b")!.value);
  });

  it("get refuses a plaintext value and points at migrate", async () => {
    mock.store.set("legacy", { value: "plain", created: 1, updated: 1 });
    const r = await hush(["get", "legacy"], { prompts: [PASS] });
    expect(r.code).toBe(1);
    expect(r.err).toContain("is a plaintext secret; run `hush migrate`");
  });

  it("get detects a ciphertext moved to another name, or modified, without blaming the passphrase", async () => {
    await hush(["put", "prod.db", "prod-value"], { prompts: [PASS] });
    mock.store.set("dev.db", { ...mock.store.get("prod.db")! });
    const moved = await hush(["get", "dev.db"], { prompts: [PASS] });
    expect(moved.code).toBe(1);
    expect(moved.err).toContain("modified or belongs to another name");
    expect(moved.err).not.toContain("wrong passphrase");

    const v = mock.store.get("prod.db")!;
    const raw = Buffer.from(v.value.slice(VAULT_PREFIX.length), "base64");
    raw[raw.length - 1] = raw[raw.length - 1]! ^ 1;
    mock.store.set("prod.db", { ...v, value: VAULT_PREFIX + raw.toString("base64") });
    expect((await hush(["get", "prod.db"], { prompts: [PASS] })).err).toContain("modified or belongs to another name");
  });

  it("delete and list need no passphrase", async () => {
    await hush(["put", "a", "v"], { prompts: [PASS] });
    expect((await hush(["list"], { prompts: [] })).code).toBe(0);
    expect((await hush(["delete", "a"], { prompts: [] })).code).toBe(0);
  });

  it("round-trips awkward values", async () => {
    for (const v of ["sk-值-✓", "  spaces  ", "a\nb\r\nc", "{\"json\":true}", "x".repeat(60_000)]) {
      await hush(["put", "k", "--from-stdin"], { prompts: [PASS], stdin: v + "\n" });
      expect((await hush(["get", "k"], { prompts: [PASS] })).out).toBe(v);
    }
  });
});

describe("hush migrate", () => {
  beforeEach(async () => {
    mock.store.set("a.plain", { value: "one", created: 1, updated: 1 });
    mock.store.set("b.plain", { value: "two", created: 1, updated: 1 });
    await initVault();
    await hush(["put", "c.done", "three"], { prompts: [PASS] });
  });

  it("needs a vault", async () => {
    await rm(vaultPath(dir));
    expect((await hush(["migrate"])).err).toContain("no vault configured");
  });

  it("encrypts the plaintext secrets, skips the already-encrypted one, and is safe to re-run", async () => {
    const r = await hush(["migrate"], { prompts: [PASS] });
    expect(r.code).toBe(0);
    expect(r.out).toContain("migrated: a.plain");
    expect(r.out).toContain("migrated: b.plain");
    expect(r.out).toContain("done: 2 migrated, 1 skipped (already encrypted), 0 errors");
    for (const n of ["a.plain", "b.plain", "c.done"]) expect(mock.store.get(n)!.value.startsWith(VAULT_PREFIX)).toBe(true);
    expect((await hush(["get", "a.plain"], { prompts: [PASS] })).out).toBe("one");
    expect((await hush(["migrate"], { prompts: [PASS] })).out).toContain("done: 0 migrated, 3 skipped");
  });

  it("--dry-run reports and writes nothing", async () => {
    const r = await hush(["migrate", "--dry-run"], { prompts: [PASS] });
    expect(r.out).toContain("would migrate: a.plain");
    expect(r.out).toContain("done: 2 would migrate, 1 skipped (already encrypted), 0 errors");
    expect(mock.store.get("a.plain")!.value).toBe("one");
  });

  it("carries on past a failing secret and exits 1", async () => {
    mock.override.set("PUT /v1/secrets/a.plain", { status: 500, body: '{"error":"db error"}' });
    const r = await hush(["migrate"], { prompts: [PASS] });
    expect(r.code).toBe(1);
    expect(r.out).toContain("error: a.plain: put:");
    expect(r.out).toContain("migrated: b.plain");
    expect(r.out).toContain("1 errors");
    expect(r.err).toContain("migrate: 1 secret(s) failed");
    expect(mock.store.get("a.plain")!.value).toBe("one"); // untouched
  });
});

describe("interoperability with the Go client", () => {
  // Written by the Go client at commit e9d00a1 (see vault.test.ts).
  const GO_VAULT = {
    version: 1,
    kdf: { algorithm: "argon2id", memory_kib: 8192, iterations: 2, parallelism: 2, salt: "QEFCQ0RFRkdISUpLTE1OTw==" },
    verify: "hh2:ei1E4wkC9GSxthqpzCTPMyqksm39h+VumHxi3tF6YDFQLcRkGsKU40dYOAQ8daSOO7sBMFY=",
  };
  const GO_WIRE =
    "hh2:kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanssBTUJywS1EhXXDi2nPfsjiB/B4bKOaI1DKCgQdcNh2CUotq1BJJBVU7Vw==";

  it("reads a value the Go client stored, using the vault.json the Go client wrote", async () => {
    await writeFile(vaultPath(dir), JSON.stringify(GO_VAULT));
    mock.store.set("llm.openai", { value: GO_WIRE, created: 1, updated: 1 });
    const r = await hush(["get", "llm.openai"], { prompts: ["correct horse battery staple ✓"] });
    expect(r.code).toBe(0);
    expect(r.out).toBe("sk-test-值-✓ line2\nline3");
  });
});
