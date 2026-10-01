import { beforeEach, describe, expect, it } from "vitest";
import { auditRows, call, env, json, makeToken, resetAll } from "./helpers";

let admin: string;
beforeEach(async () => {
  await resetAll();
  admin = await makeToken({ name: "root", role: "admin" });
});

const put = (name: string, value: string, token = admin) =>
  call(`/v1/secrets/${name}`, { method: "PUT", token, body: { value } });

describe("one audit row per request", () => {
  it("records each outcome with the right action and result", async () => {
    const agent = await makeToken({ name: "reader", prefixes: ["llm."], writePrefixes: ["w."] });
    await put("llm.a", "secret-value-1"); //                                       put / allowed
    await call("/v1/secrets/llm.a", { token: agent }); //                           get / allowed
    await call("/v1/secrets/other.a", { token: agent }); //                         get / denied
    await call("/v1/secrets/missing", { token: admin }); //                         get / not_found
    await call("/v1/secrets", { token: agent }); //                                 list / allowed
    await call("/v1/secrets/bad%20name", { token: admin }); //                      get / bad_request
    await call("/v1/secrets/llm.a", { method: "DELETE", token: agent }); //         delete / denied
    await call("/v1/secrets/llm.a", { method: "DELETE", token: admin }); //         delete / allowed
    await call("/v1/secrets/x", { method: "PATCH", token: admin }); //              other / bad_request (405)
    await call("/v1/secrets"); //                                                   list / unauthenticated

    const rows = (await auditRows()).map((r) => [r.token_name, r.action, r.secret_name, r.result]);
    expect(rows).toEqual([
      ["root", "put", "llm.a", "allowed"],
      ["reader", "get", "llm.a", "allowed"],
      ["reader", "get", "other.a", "denied"],
      ["root", "get", "missing", "not_found"],
      ["reader", "list", "", "allowed"],
      ["root", "get", "", "bad_request"], // malformed name is not recorded
      ["reader", "delete", "llm.a", "denied"],
      ["root", "delete", "llm.a", "allowed"],
      ["root", "other", "x", "bad_request"],
      ["", "list", "", "unauthenticated"],
    ]);
  });

  it("a refused agent create is recorded once, as conflict, not also as allowed", async () => {
    const t = await makeToken({ name: "crawler", writePrefixes: ["crawler."] });
    await put("crawler.k", "v", t);
    await put("crawler.k", "v2", t);
    const rows = (await auditRows()).map((r) => [r.action, r.secret_name, r.result]);
    expect(rows).toEqual([
      ["put", "crawler.k", "allowed"],
      ["put", "crawler.k", "conflict"],
    ]);
  });

  it("an idempotent delete of a missing name is still recorded as allowed", async () => {
    await call("/v1/secrets/ghost", { method: "DELETE", token: admin });
    expect((await auditRows()).map((r) => [r.action, r.secret_name, r.result])).toEqual([["delete", "ghost", "allowed"]]);
  });

  it("never stores secret values or tokens, and records request id, IP and time", async () => {
    await put("llm.a", "super-secret-plaintext");
    await call("/v1/secrets/llm.a", { token: admin, headers: { "X-Request-ID": "req-42", "CF-Connecting-IP": "203.0.113.9" } });
    const rows = await auditRows();
    const blob = JSON.stringify(rows);
    expect(blob).not.toContain("super-secret-plaintext");
    expect(blob).not.toContain(admin);
    const get = rows[1]!;
    expect(get.request_id).toBe("req-42");
    expect(get.remote_addr).toBe("203.0.113.9");
    expect(Math.abs(get.ts - Date.now() / 1000)).toBeLessThan(10);
  });

  it("ignores X-Forwarded-For: the audited address is CF-Connecting-IP", async () => {
    await call("/v1/secrets", { token: admin, headers: { "CF-Connecting-IP": "198.51.100.1", "X-Forwarded-For": "6.6.6.6" } });
    expect((await auditRows())[0]!.remote_addr).toBe("198.51.100.1");
    await call("/v1/secrets", { token: admin, headers: { "X-Forwarded-For": "6.6.6.6" } });
    expect((await auditRows())[1]!.remote_addr).toBe("unknown");
  });

  it("does not audit health checks", async () => {
    await call("/healthz");
    expect(await auditRows()).toHaveLength(0);
  });
});

describe("atomicity and fail-closed behaviour when the audit write fails", () => {
  const breakAudit = () => env.DB.prepare(`ALTER TABLE audit_log RENAME TO audit_log_broken`).run();
  const fixAudit = () => env.DB.prepare(`ALTER TABLE audit_log_broken RENAME TO audit_log`).run();

  it("a read whose audit row cannot be written returns 500 and no data", async () => {
    await put("llm.a", "do-not-leak");
    await breakAudit();
    const get = await call("/v1/secrets/llm.a", { token: admin });
    expect(get.status).toBe(500);
    expect(await json(get)).toEqual({ error: "audit failed" });
    const list = await call("/v1/secrets", { token: admin });
    expect(list.status).toBe(500);
    expect(await list.text()).not.toContain("llm.a");
    await fixAudit();
  });

  it("a PUT whose audit row cannot be written does not write the secret", async () => {
    await breakAudit();
    const res = await put("llm.a", "v");
    expect(res.status).toBe(500);
    await fixAudit();
    expect((await call("/v1/secrets/llm.a", { token: admin })).status).toBe(404);
  });

  it("a DELETE whose audit row cannot be written does not delete", async () => {
    await put("llm.a", "v");
    await breakAudit();
    expect((await call("/v1/secrets/llm.a", { method: "DELETE", token: admin })).status).toBe(500);
    await fixAudit();
    expect((await call("/v1/secrets/llm.a", { token: admin })).status).toBe(200);
  });

  it("a token create whose audit row cannot be written does not create the token", async () => {
    await breakAudit();
    const res = await call("/v1/admin/tokens", { method: "POST", token: admin, body: { name: "n", role: "agent", prefixes: ["a."] } });
    expect(res.status).toBe(500);
    await fixAudit();
    const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM tokens WHERE name = 'n'`).first<{ n: number }>();
    expect(row?.n).toBe(0);
  });
});
