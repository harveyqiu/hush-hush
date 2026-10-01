import { beforeEach, describe, expect, it } from "vitest";
import { auditRows, call, env, json, makeToken, resetAll } from "./helpers";

let admin: string;
beforeEach(async () => {
  await resetAll();
  admin = await makeToken({ name: "root", role: "admin" });
});

const create = (body: unknown, token = admin) => call("/v1/admin/tokens", { method: "POST", token, body });
interface Created { name: string; token: string; warnings: string[] }
interface TokenInfo {
  name: string; role: string; prefixes: string[]; write_prefixes: string[]; status: string;
  expires_at: number | null; last_used_at: number | null; revoked_at: number | null; created_at: number;
}

describe("whoami", () => {
  it("returns the caller and its expiry", async () => {
    const res = await json<{ name: string; role: string; expires_at: number }>(await call("/v1/admin/me", { token: admin }));
    expect(res.name).toBe("root");
    expect(res.role).toBe("admin");
    expect(res.expires_at).toBeGreaterThan(Date.now() / 1000);
  });
});

describe("token create", () => {
  it("returns the plaintext once; the new token works; only its hash is stored", async () => {
    const res = await create({ name: "llm-agent", role: "agent", prefixes: ["llm."] });
    expect(res.status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = await json<Created>(res);
    expect(body.token).toMatch(/^hush_[0-9a-f]{64}$/);
    expect(body.warnings).toEqual([]);

    await call("/v1/secrets/llm.k", { method: "PUT", token: admin, body: { value: "v" } });
    expect((await call("/v1/secrets/llm.k", { token: body.token })).status).toBe(200);

    const row = await env.DB.prepare(`SELECT token_hash FROM tokens WHERE name = 'llm-agent'`).first<{ token_hash: ArrayBuffer }>();
    expect(new Uint8Array(row!.token_hash)).toHaveLength(32);
    expect(JSON.stringify(await auditRows())).not.toContain(body.token);
  });

  it("applies the expiry; admin tokens must expire within 90 days", async () => {
    const ok = await json<Created>(await create({ name: "a", role: "agent", prefixes: ["a."], expires: "12h" }));
    const row = await env.DB.prepare(`SELECT expires_at FROM tokens WHERE name = 'a'`).first<{ expires_at: number }>();
    expect(row!.expires_at - Date.now() / 1000).toBeGreaterThan(12 * 3600 - 10);
    expect(row!.expires_at - Date.now() / 1000).toBeLessThan(12 * 3600 + 10);
    expect(ok.token).toBeTruthy();

    const noExpiry = await create({ name: "adm", role: "admin" });
    expect(noExpiry.status).toBe(400);
    expect(await json(noExpiry)).toEqual({ error: "admin tokens must expire: set an expiry of at most 90d" });
    const tooLong = await create({ name: "adm", role: "admin", expires: "91d" });
    expect(tooLong.status).toBe(400);
    expect(await json(tooLong)).toEqual({ error: "admin tokens may live at most 90d" });
    expect((await create({ name: "adm", role: "admin", expires: "90d" })).status).toBe(201);
    expect((await create({ name: "adm2", role: "admin", expires: "2160h" })).status).toBe(201);
  });

  it("validates input with 400 and the Go error messages", async () => {
    const cases: [unknown, string][] = [
      [{ name: "bad name", role: "agent", prefixes: ["a."] }, "name must match ^[a-zA-Z0-9_.-]{1,64}$"],
      [{ name: "n", role: "root", prefixes: ["a."] }, 'role must be "admin" or "agent"'],
      [{ name: "n", role: "agent" }, "agent tokens need at least one --prefix or --write-prefix"],
      [{ name: "n", role: "agent", prefixes: ["llm"] }, 'invalid prefix "llm": must be name characters ending in \'.\' or \'_\' (e.g. llm.)'],
      [{ name: "n", role: "agent", write_prefixes: ["w"] }, 'invalid write prefix "w": must be name characters ending in \'.\' or \'_\' (e.g. crawler.)'],
      [{ name: "n", role: "agent", write_prefixes: ["*"] }, '"*" is not allowed as a write prefix; use a dedicated namespace such as agent-name.'],
      [{ name: "n", role: "agent", prefixes: ["*", "a."] }, '"*" must be the only prefix'],
      [{ name: "n", role: "agent", prefixes: ["a."], expires: "soon" }, "invalid expires (use e.g. 90d or 12h)"],
      [{ name: "n", role: "agent", prefixes: ["a."], expires: "-5d" }, "invalid expires (use e.g. 90d or 12h)"],
      [{ name: "n", role: "agent", prefixes: ["*"] }, 'prefix "*" grants every secret; resend with "confirm_all": true'],
      [{ name: "n", role: "admin", prefixes: ["a."], expires: "1d" }, "admin tokens do not take --prefix or --write-prefix (they can read and write everything)"],
    ];
    for (const [body, msg] of cases) {
      const res = await create(body);
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect((await json<{ error: string }>(res)).error, JSON.stringify(body)).toBe(msg);
    }
    expect((await env.DB.prepare(`SELECT COUNT(*) AS n FROM tokens`).first<{ n: number }>())?.n).toBe(1); // only root
  });

  it("'*' needs confirm_all", async () => {
    expect((await create({ name: "all", role: "agent", prefixes: ["*"], confirm_all: true })).status).toBe(201);
  });

  it("token names are never reused, even after revoke", async () => {
    expect((await create({ name: "bot", role: "agent", prefixes: ["a."] })).status).toBe(201);
    const dup = await create({ name: "bot", role: "agent", prefixes: ["a."] });
    expect(dup.status).toBe(409);
    expect((await json<{ error: string }>(dup)).error).toMatch(/already exists/);
    await call("/v1/admin/tokens/bot", { method: "DELETE", token: admin });
    expect((await create({ name: "bot", role: "agent", prefixes: ["a."] })).status).toBe(409);
  });

  it("warns when write namespaces overlap another active agent", async () => {
    await create({ name: "one", role: "agent", write_prefixes: ["shared."] });
    const res = await json<Created>(await create({ name: "two", role: "agent", write_prefixes: ["shared.sub."] }));
    expect(res.warnings).toHaveLength(1);
    expect(res.warnings[0]).toContain('overlaps "shared." on token "one"');
  });

  it("rejects bad bodies: content type, size, unknown fields, wrong types", async () => {
    expect((await call("/v1/admin/tokens", { method: "POST", token: admin, body: "{}", headers: { "Content-Type": "text/plain" } })).status).toBe(415);
    expect((await call("/v1/admin/tokens", { method: "POST", token: admin, body: "x".repeat(17 * 1024) })).status).toBe(413);
    expect((await create({ name: "n", role: "agent", prefixes: ["a."], surprise: 1 })).status).toBe(400);
    expect((await create({ name: "n", role: "agent", prefixes: "a." })).status).toBe(400);
    expect((await create({ name: 5 })).status).toBe(400);
  });

  it("records the new token's name as the audit target", async () => {
    await create({ name: "newbie", role: "agent", prefixes: ["a."] });
    expect((await auditRows()).map((r) => [r.action, r.secret_name, r.result])).toEqual([["token_create", "newbie", "allowed"]]);
  });
});

describe("token list", () => {
  it("lists every token by name, with status, and never a hash", async () => {
    await makeToken({ name: "zed", prefixes: ["z."] });
    await makeToken({ name: "dead", prefixes: ["d."], revokedAt: 5 });
    await makeToken({ name: "stale", prefixes: ["s."], expiresAt: 5 });
    const res = await call("/v1/admin/tokens", { token: admin });
    expect(await res.clone().text()).not.toMatch(/hash/);
    const { tokens } = await json<{ tokens: TokenInfo[] }>(res);
    expect(tokens.map((t) => [t.name, t.status])).toEqual([
      ["dead", "revoked"], ["root", "active"], ["stale", "expired"], ["zed", "active"],
    ]);
    expect(tokens.find((t) => t.name === "zed")).toMatchObject({ role: "agent", prefixes: ["z."], write_prefixes: [] });
  });
});

describe("token update", () => {
  beforeEach(async () => {
    await create({ name: "bot", role: "agent", prefixes: ["a."], write_prefixes: ["w."] });
  });
  const patch = (body: unknown, name = "bot") => call(`/v1/admin/tokens/${name}`, { method: "PATCH", token: admin, body });

  it("replaces only the lists that are present; [] clears", async () => {
    expect(await json(await patch({ prefixes: ["b.", "c."] }))).toEqual({ name: "bot", prefixes: ["b.", "c."], write_prefixes: ["w."], warnings: [] });
    expect(await json(await patch({ write_prefixes: [] }))).toEqual({ name: "bot", prefixes: ["b.", "c."], write_prefixes: [], warnings: [] });
  });

  it("applies immediately to the token's next request", async () => {
    const t = (await json<Created>(await create({ name: "live", role: "agent", prefixes: ["a."] }))).token;
    await call("/v1/secrets/b.k", { method: "PUT", token: admin, body: { value: "v" } });
    expect((await call("/v1/secrets/b.k", { token: t })).status).toBe(403);
    await patch({ prefixes: ["b."] }, "live");
    expect((await call("/v1/secrets/b.k", { token: t })).status).toBe(200);
  });

  it("validates", async () => {
    expect((await patch({})).status).toBe(400);
    expect((await patch({ prefixes: null })).status).toBe(400);
    expect((await patch({ prefixes: ["nodot"] })).status).toBe(400);
    expect((await patch({ prefixes: ["*"] })).status).toBe(400);
    expect((await patch({ prefixes: ["*"], confirm_all: true })).status).toBe(200);
    expect((await patch({ write_prefixes: ["*"] })).status).toBe(400);
    expect((await patch({ prefixes: [], write_prefixes: [] })).status).toBe(400); // would leave nothing
    expect((await patch({ prefixes: ["a."] }, "bad name")).status).toBe(400);
  });

  it("refuses admin, revoked and unknown tokens", async () => {
    expect((await patch({ prefixes: ["a."] }, "root")).status).toBe(409);
    await call("/v1/admin/tokens/bot", { method: "DELETE", token: admin });
    expect((await patch({ prefixes: ["a."] })).status).toBe(409);
    expect((await patch({ prefixes: ["a."] }, "nobody")).status).toBe(404);
  });
});

describe("token revoke", () => {
  it("revokes immediately and reports already_revoked on repeat", async () => {
    const t = (await json<Created>(await create({ name: "bot", role: "agent", prefixes: ["a."] }))).token;
    expect((await call("/v1/secrets", { token: t })).status).toBe(200);
    expect(await json(await call("/v1/admin/tokens/bot", { method: "DELETE", token: admin }))).toEqual({ name: "bot", revoked: true, already_revoked: false });
    expect((await call("/v1/secrets", { token: t })).status).toBe(401);
    expect(await json(await call("/v1/admin/tokens/bot", { method: "DELETE", token: admin }))).toEqual({ name: "bot", revoked: true, already_revoked: true });
  });

  it("refuses to revoke the token making the request; unknown is 404; bad name is 400", async () => {
    const self = await call("/v1/admin/tokens/root", { method: "DELETE", token: admin });
    expect(self.status).toBe(409);
    expect(await json(self)).toEqual({ error: "refusing to revoke the token used for this request" });
    expect((await call("/v1/admin/tokens/nobody", { method: "DELETE", token: admin })).status).toBe(404);
    expect((await call("/v1/admin/tokens/bad%20name", { method: "DELETE", token: admin })).status).toBe(400);
    expect((await call("/v1/secrets", { token: admin })).status).toBe(200);
  });

  it("a revoke of an unknown token is not recorded as allowed", async () => {
    await call("/v1/admin/tokens/nobody", { method: "DELETE", token: admin });
    expect((await auditRows()).map((r) => r.result)).toEqual(["not_found"]);
  });
});

describe("audit query", () => {
  beforeEach(async () => {
    const agent = await makeToken({ name: "reader", prefixes: ["llm."] });
    await call("/v1/secrets/llm.a", { method: "PUT", token: admin, body: { value: "v" } });
    await call("/v1/secrets/llm.a", { token: agent });
    await call("/v1/secrets/other.x", { token: agent });
    await env.DB.prepare(`DELETE FROM audit_log WHERE 0`).run();
  });
  const q = async (qs: string) => (await json<{ records: { token_name: string; action: string; secret_name: string; result: string; ts: number }[] }>(await call(`/v1/admin/audit?${qs}`, { token: admin }))).records;

  it("returns newest first and filters", async () => {
    const all = await q("");
    expect(all.map((r) => r.action).slice(0, 3)).toEqual(["get", "get", "put"]); // newest first
    expect((await q("token=reader")).every((r) => r.token_name === "reader")).toBe(true);
    expect((await q("result=denied")).map((r) => [r.token_name, r.secret_name])).toEqual([["reader", "other.x"]]);
    expect((await q("secret=llm.a&action=put")).map((r) => r.token_name)).toEqual(["root"]);
    expect(await q("limit=1")).toHaveLength(1);
  });

  it("filters by time: since/until accept unix seconds, RFC3339 and ages", async () => {
    const now = Math.floor(Date.now() / 1000);
    expect((await q(`since=${now - 60}`)).length).toBeGreaterThan(0);
    expect(await q(`until=${now - 3600}`)).toHaveLength(0);
    expect((await q("since=1h")).length).toBeGreaterThan(0);
    expect(await q("until=1h")).toHaveLength(0);
    expect((await q("since=2020-01-01T00:00:00Z")).length).toBeGreaterThan(0);
  });

  it("rejects invalid filters with 400", async () => {
    for (const qs of ["limit=abc", "limit=0", "limit=10001", "action=nope", "result=nope", "since=garbage", "until=garbage", `since=10&until=5`]) {
      expect((await call(`/v1/admin/audit?${qs}`, { token: admin })).status, qs).toBe(400);
    }
  });

  it("records the audit read itself", async () => {
    await q("");
    expect((await auditRows()).at(-1)).toMatchObject({ action: "audit_read", result: "allowed" });
  });
});

describe("route table", () => {
  it("unknown admin paths and unsupported methods are 404 after auth", async () => {
    expect((await call("/v1/admin/nope", { token: admin })).status).toBe(404);
    expect((await call("/v1/admin/tokens", { method: "PUT", token: admin })).status).toBe(404);
    expect((await call("/v1/admin/tokens/x/y", { method: "DELETE", token: admin })).status).toBe(404);
    expect((await call("/v1/admin/nope")).status).toBe(401); // unauthenticated learn nothing
    const agent = await makeToken({ name: "ag", prefixes: ["a."] });
    expect((await call("/v1/admin/nope", { token: agent })).status).toBe(403);
  });
});

describe("ADMIN_API=false", () => {
  it("removes the admin API and the UI entirely", async () => {
    const env = { ADMIN_API: "false" };
    expect((await call("/v1/admin/me", { token: admin, env })).status).toBe(404);
    expect((await call("/ui/", { env })).status).toBe(404);
    expect((await call("/", { env })).status).toBe(404);
    // the secrets API is unaffected
    expect((await call("/v1/secrets", { token: admin, env })).status).toBe(200);
  });
});
