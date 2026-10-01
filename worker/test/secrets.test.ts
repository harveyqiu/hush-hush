import { beforeEach, describe, expect, it } from "vitest";
import { auditRows, call, env, json, makeToken, resetAll } from "./helpers";

let admin: string;
beforeEach(async () => {
  await resetAll();
  admin = await makeToken({ name: "root", role: "admin" });
});

const put = (name: string, value: string, token = admin) =>
  call(`/v1/secrets/${name}`, { method: "PUT", token, body: { value } });

describe("health and routing", () => {
  it("GET /healthz needs no auth, is not audited and carries a request id", async () => {
    const res = await call("/healthz");
    expect(res.status).toBe(200);
    expect(await json(res)).toEqual({ status: "ok" });
    expect(res.headers.get("X-Request-ID")).toMatch(/^[0-9a-f]{16}$/);
    expect(await auditRows()).toHaveLength(0);
  });

  it("honours a well-formed inbound X-Request-ID and replaces a malformed one", async () => {
    const ok = await call("/healthz", { headers: { "X-Request-ID": "trace-123_ABC" } });
    expect(ok.headers.get("X-Request-ID")).toBe("trace-123_ABC");
    const bad = await call("/healthz", { headers: { "X-Request-ID": 'a"b c' } });
    expect(bad.headers.get("X-Request-ID")).toMatch(/^[0-9a-f]{16}$/);
  });

  it("unknown paths are a JSON 404", async () => {
    const res = await call("/nope");
    expect(res.status).toBe(404);
    expect(await json(res)).toEqual({ error: "not found" });
  });
});

describe("authentication", () => {
  it("rejects missing, malformed, unknown, revoked and expired tokens identically (401)", async () => {
    const revoked = await makeToken({ name: "gone", prefixes: ["a."], revokedAt: 1 });
    const expired = await makeToken({ name: "old", prefixes: ["a."], expiresAt: 1 });
    const cases: Record<string, Record<string, string>> = {
      none: {},
      basic: { Authorization: "Basic abc" },
      lowercase: { Authorization: "bearer " + admin },
      empty: { Authorization: "Bearer " },
      unknown: { Authorization: "Bearer hush_" + "0".repeat(64) },
      revoked: { Authorization: "Bearer " + revoked },
      expired: { Authorization: "Bearer " + expired },
    };
    for (const [label, headers] of Object.entries(cases)) {
      const res = await call("/v1/secrets", { headers, env: { UNAUTH_RATE_LIMIT_PER_MINUTE: "1000" } });
      expect(res.status, label).toBe(401);
      expect(await json(res), label).toEqual({ error: "unauthorized" });
    }
  });

  it("rejects an admin token that has no expiry (hand-edited row)", async () => {
    const t = await makeToken({ name: "forever", role: "admin", expiresAt: null });
    expect((await call("/v1/secrets", { token: t })).status).toBe(401);
  });

  it("rejects a token whose stored grant is corrupt instead of widening it", async () => {
    const t = await makeToken({ name: "broken", prefixes: ["a."] });
    await env.DB.prepare(`UPDATE tokens SET prefixes = 'not json' WHERE name = 'broken'`).run();
    expect((await call("/v1/secrets", { token: t })).status).toBe(401);
  });

  it("accepts a valid token and records last_used_at", async () => {
    expect((await call("/v1/secrets", { token: admin })).status).toBe(200);
    const row = await env.DB.prepare(`SELECT last_used_at FROM tokens WHERE name = 'root'`).first<{ last_used_at: number }>();
    expect(row?.last_used_at).toBeGreaterThan(0);
  });

  it("revocation takes effect on the next request", async () => {
    const t = await makeToken({ name: "bot", prefixes: ["a."] });
    expect((await call("/v1/secrets", { token: t })).status).toBe(200);
    await env.DB.prepare(`UPDATE tokens SET revoked_at = 1 WHERE name = 'bot'`).run();
    expect((await call("/v1/secrets", { token: t })).status).toBe(401);
  });
});

describe("PUT / GET / DELETE", () => {
  it("round-trips a secret, including non-ASCII, and keeps created_at on overwrite", async () => {
    const created = await put("llm.openai", "sk-值-✓");
    expect(created.status).toBe(200);
    const c = await json<{ name: string; created_at: number; updated_at: number }>(created);
    expect(c.name).toBe("llm.openai");

    const got = await json<{ value: string; created_at: number }>(await call("/v1/secrets/llm.openai", { token: admin }));
    expect(got.value).toBe("sk-值-✓");
    expect(got.created_at).toBe(c.created_at);

    const again = await json<{ created_at: number }>(await put("llm.openai", "second"));
    expect(again.created_at).toBe(c.created_at);
    expect((await json<{ value: string }>(await call("/v1/secrets/llm.openai", { token: admin }))).value).toBe("second");
  });

  it("stores ciphertext, never the plaintext, in the Go-compatible layout", async () => {
    await put("llm.k", "plaintext-value");
    const row = await env.DB.prepare(`SELECT ciphertext, nonce FROM secrets WHERE name = 'llm.k'`).first<{
      ciphertext: ArrayBuffer;
      nonce: ArrayBuffer;
    }>();
    const ct = new Uint8Array(row!.ciphertext);
    expect(ct[0]).toBe(0x01);
    expect(ct.length).toBe(1 + "plaintext-value".length + 16); // version + data + GCM tag
    expect(new Uint8Array(row!.nonce)).toHaveLength(12);
    expect(new TextDecoder().decode(ct)).not.toContain("plaintext-value");
  });

  it("uses a fresh nonce on every write", async () => {
    await put("llm.k", "same");
    const a = await env.DB.prepare(`SELECT nonce FROM secrets WHERE name = 'llm.k'`).first<{ nonce: ArrayBuffer }>();
    await put("llm.k", "same");
    const b = await env.DB.prepare(`SELECT nonce FROM secrets WHERE name = 'llm.k'`).first<{ nonce: ArrayBuffer }>();
    expect(Array.from(new Uint8Array(a!.nonce))).not.toEqual(Array.from(new Uint8Array(b!.nonce)));
  });

  it("GET of a missing secret is 404; invalid names are 400", async () => {
    expect((await call("/v1/secrets/missing", { token: admin })).status).toBe(404);
    expect((await call("/v1/secrets/bad%20name", { token: admin })).status).toBe(400);
    expect((await call("/v1/secrets/a%2Fb", { token: admin })).status).toBe(400);
    expect((await call("/v1/secrets/" + "x".repeat(129), { token: admin })).status).toBe(400);
    expect((await call("/v1/secrets/" + "x".repeat(128), { token: admin })).status).toBe(404);
  });

  it("DELETE is idempotent and returns 204", async () => {
    await put("llm.k", "v");
    expect((await call("/v1/secrets/llm.k", { method: "DELETE", token: admin })).status).toBe(204);
    expect((await call("/v1/secrets/llm.k", { method: "DELETE", token: admin })).status).toBe(204);
    expect((await call("/v1/secrets/llm.k", { token: admin })).status).toBe(404);
  });

  it("decrypt failures are a 500 that does not leak details", async () => {
    await put("llm.k", "v");
    await env.DB.prepare(`UPDATE secrets SET nonce = zeroblob(12) WHERE name = 'llm.k'`).run();
    const res = await call("/v1/secrets/llm.k", { token: admin });
    expect(res.status).toBe(500);
    expect(await json(res)).toEqual({ error: "decrypt failed" });
  });

  it("refuses a ciphertext with an unknown version byte", async () => {
    await put("llm.k", "v");
    await env.DB.prepare(`UPDATE secrets SET ciphertext = x'02' || substr(ciphertext, 2) WHERE name = 'llm.k'`).run();
    expect((await call("/v1/secrets/llm.k", { token: admin })).status).toBe(500);
  });
});

describe("PUT validation order and limits", () => {
  it("requires a JSON content type (415), ignoring case and parameters", async () => {
    const bad = await call("/v1/secrets/a", { method: "PUT", token: admin, body: '{"value":"x"}', headers: { "Content-Type": "text/plain" } });
    expect(bad.status).toBe(415);
    const none = await call("/v1/secrets/a", { method: "PUT", token: admin });
    expect(none.status).toBe(415);
    const ok = await call("/v1/secrets/a", { method: "PUT", token: admin, body: '{"value":"x"}', headers: { "Content-Type": "Application/JSON; charset=utf-8" } });
    expect(ok.status).toBe(200);
  });

  it("rejects bad JSON shapes with 400", async () => {
    for (const body of ['{"value":"x","extra":1}', '{"value":5}', "[]", "nope", '{"value":"x"} tail', "{}", '{"value":""}', '{"value":null}']) {
      const res = await call("/v1/secrets/a", { method: "PUT", token: admin, body });
      expect(res.status, body).toBe(400);
    }
  });

  it("enforces the value limit in bytes: 65536 ok, 65537 is 413", async () => {
    expect((await put("a", "x".repeat(65536))).status).toBe(200);
    expect((await put("a", "x".repeat(65537))).status).toBe(413);
    // 21846 three-byte characters = 65538 bytes though only 21846 characters
    expect((await put("a", "€".repeat(21846))).status).toBe(413);
  });

  it("rejects an oversized request body with 413 before decoding it", async () => {
    const res = await call("/v1/secrets/a", { method: "PUT", token: admin, body: '{"value":"' + "x".repeat(70_000) + '"}' });
    expect(res.status).toBe(413);
    expect(await json(res)).toEqual({ error: "request body too large" });
  });

  it("checks the name before the body", async () => {
    const res = await call("/v1/secrets/bad%20name", { method: "PUT", token: admin, body: "garbage" });
    expect(res.status).toBe(400);
    expect(await json(res)).toEqual({ error: "invalid name" });
  });
});

describe("agent scopes", () => {
  it("lists and reads only names under its read prefixes", async () => {
    await put("llm.a", "1");
    await put("llm.b", "2");
    await put("llmx.c", "3");
    await put("github.d", "4");
    const t = await makeToken({ name: "reader", prefixes: ["llm.", "github."] });

    const list = await json<{ secrets: { name: string; value?: string }[] }>(await call("/v1/secrets", { token: t }));
    expect(list.secrets.map((s) => s.name)).toEqual(["github.d", "llm.a", "llm.b"]);
    expect(list.secrets.every((s) => s.value === undefined)).toBe(true);

    expect((await call("/v1/secrets/llm.a", { token: t })).status).toBe(200);
    expect((await call("/v1/secrets/llmx.c", { token: t })).status).toBe(403);
  });

  it("answers 403, not 404, for names outside the grant whether or not they exist", async () => {
    await put("other.exists", "1");
    const t = await makeToken({ name: "reader", prefixes: ["llm."] });
    expect((await call("/v1/secrets/other.exists", { token: t })).status).toBe(403);
    expect((await call("/v1/secrets/other.missing", { token: t })).status).toBe(403);
  });

  it("'_' in a prefix is literal, not a LIKE wildcard", async () => {
    await put("a_b.key", "1");
    await put("aXb.key", "2");
    const t = await makeToken({ name: "u", prefixes: ["a_b."] });
    const list = await json<{ secrets: { name: string }[] }>(await call("/v1/secrets", { token: t }));
    expect(list.secrets.map((s) => s.name)).toEqual(["a_b.key"]);
  });

  it("'*' reads everything, including later additions", async () => {
    const t = await makeToken({ name: "all", prefixes: ["*"] });
    await put("zzz.new", "1");
    expect((await call("/v1/secrets/zzz.new", { token: t })).status).toBe(200);
    expect((await json<{ secrets: unknown[] }>(await call("/v1/secrets", { token: t }))).secrets).toHaveLength(1);
  });

  it("a write-only agent lists nothing", async () => {
    await put("llm.a", "1");
    const t = await makeToken({ name: "w", writePrefixes: ["crawler."] });
    expect(await json(await call("/v1/secrets", { token: t }))).toEqual({ secrets: [] });
  });

  it("agents can never delete or call admin routes", async () => {
    await put("llm.a", "1");
    const t = await makeToken({ name: "reader", prefixes: ["llm."] });
    expect((await call("/v1/secrets/llm.a", { method: "DELETE", token: t })).status).toBe(403);
    expect((await call("/v1/admin/tokens", { token: t })).status).toBe(403);
    expect((await call("/v1/admin/me", { token: t })).status).toBe(403);
    expect((await call("/v1/secrets/llm.a", { token: admin })).status).toBe(200);
  });

  it("list is capped at 1000 names", async () => {
    const stmts = Array.from({ length: 1005 }, (_, i) =>
      env.DB.prepare(`INSERT INTO secrets (name, ciphertext, nonce, created_at, updated_at) VALUES (?, x'01', x'00', 1, 1)`).bind(`n${String(i).padStart(4, "0")}`),
    );
    for (let i = 0; i < stmts.length; i += 100) await env.DB.batch(stmts.slice(i, i + 100));
    const list = await json<{ secrets: unknown[] }>(await call("/v1/secrets", { token: admin }));
    expect(list.secrets).toHaveLength(1000);
  });
});

describe("create-only write grants", () => {
  it("lets an agent create under a write prefix, but never overwrite", async () => {
    const t = await makeToken({ name: "crawler", writePrefixes: ["crawler."], prefixes: ["crawler."] });
    const first = await put("crawler.token", "v1", t);
    expect(first.status).toBe(200);
    const second = await put("crawler.token", "v2", t);
    expect(second.status).toBe(409);
    expect(await json(second)).toEqual({ error: "already exists" });
    // the original value is untouched
    expect((await json<{ value: string }>(await call("/v1/secrets/crawler.token", { token: t }))).value).toBe("v1");
    // an admin can still overwrite
    expect((await put("crawler.token", "v3")).status).toBe(200);
  });

  it("refuses names outside the write prefix with 403, before parsing the body", async () => {
    const t = await makeToken({ name: "crawler", writePrefixes: ["crawler."] });
    expect((await put("other.token", "v", t)).status).toBe(403);
    const res = await call("/v1/secrets/other.token", { method: "PUT", token: t, body: "garbage" });
    expect(res.status).toBe(403);
    expect((await call("/v1/secrets/crawler.token", { method: "DELETE", token: t })).status).toBe(403);
  });

  it("a read-only agent cannot write", async () => {
    const t = await makeToken({ name: "ro", prefixes: ["llm."] });
    expect((await put("llm.new", "v", t)).status).toBe(403);
  });
});

describe("unmatched /v1/secrets requests", () => {
  it("are authenticated first, then 405 with Allow or 404", async () => {
    expect((await call("/v1/secrets", { method: "POST" })).status).toBe(401);
    const post = await call("/v1/secrets", { method: "POST", token: admin });
    expect(post.status).toBe(405);
    expect(post.headers.get("Allow")).toBe("GET");
    const patch = await call("/v1/secrets/a", { method: "PATCH", token: admin });
    expect(patch.status).toBe(405);
    expect(patch.headers.get("Allow")).toBe("GET, PUT, DELETE");
    expect((await call("/v1/secrets/a/b", { token: admin })).status).toBe(404);
    expect((await call("/v1/secrets/", { token: admin })).status).toBe(404);
  });
});

describe("responses", () => {
  it("API responses are JSON and never cacheable", async () => {
    await put("llm.a", "1");
    for (const res of [await call("/v1/secrets", { token: admin }), await call("/v1/secrets/llm.a", { token: admin }), await call("/v1/secrets/x", { token: admin }), await call("/v1/secrets")]) {
      expect(res.headers.get("Content-Type")).toBe("application/json");
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      expect(res.headers.get("X-Request-ID")).toBeTruthy();
    }
  });
});

describe("configuration errors", () => {
  it("an invalid MASTER_KEY fails API requests with 500 but not /healthz", async () => {
    const res = await call("/v1/secrets", { token: admin, env: { MASTER_KEY: "not-a-key" } });
    expect(res.status).toBe(500);
    expect(await json(res)).toEqual({ error: "server misconfigured" });
    expect((await call("/healthz", { env: { MASTER_KEY: "not-a-key" } })).status).toBe(200);
  });
  it("a missing MASTER_KEY or bad numeric setting is also a 500", async () => {
    expect((await call("/v1/secrets", { token: admin, env: { MASTER_KEY: "" } })).status).toBe(500);
    expect((await call("/v1/secrets", { token: admin, env: { RATE_LIMIT_PER_MINUTE: "0" } })).status).toBe(500);
  });
});
