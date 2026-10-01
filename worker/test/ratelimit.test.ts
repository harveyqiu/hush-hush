import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { auditRows, call, env, json, makeToken, resetAll } from "./helpers";

beforeEach(resetAll);

describe("per-token limit", () => {
  it("allows the budget, then 429 with Retry-After, and recovers per token", async () => {
    const a = await makeToken({ name: "a", prefixes: ["x."] });
    const b = await makeToken({ name: "b", prefixes: ["x."] });
    const env = { RATE_LIMIT_PER_MINUTE: "3" };
    for (let i = 0; i < 3; i++) expect((await call("/v1/secrets", { token: a, env })).status).toBe(200);
    const limited = await call("/v1/secrets", { token: a, env });
    expect(limited.status).toBe(429);
    expect(await json(limited)).toEqual({ error: "rate_limited" });
    // 3/min refills one token every 20s
    const retry = Number(limited.headers.get("Retry-After"));
    expect(retry).toBeGreaterThanOrEqual(1);
    expect(retry).toBeLessThanOrEqual(20);
    // a different token has its own bucket
    expect((await call("/v1/secrets", { token: b, env })).status).toBe(200);
  });

  it("records limited requests as rate_limited", async () => {
    const a = await makeToken({ name: "a", prefixes: ["x."] });
    const env = { RATE_LIMIT_PER_MINUTE: "1" };
    await call("/v1/secrets", { token: a, env });
    await call("/v1/secrets", { token: a, env });
    expect((await auditRows()).map((r) => r.result)).toEqual(["allowed", "rate_limited"]);
  });

  it("limits the admin API too", async () => {
    const admin = await makeToken({ name: "root", role: "admin" });
    const env = { RATE_LIMIT_PER_MINUTE: "2" };
    await call("/v1/admin/me", { token: admin, env });
    await call("/v1/admin/me", { token: admin, env });
    expect((await call("/v1/admin/me", { token: admin, env })).status).toBe(429);
  });
});

describe("per-IP limit on failed authentication", () => {
  const ip = (addr: string) => ({ "CF-Connecting-IP": addr });
  const env = { UNAUTH_RATE_LIMIT_PER_MINUTE: "2" };

  it("answers 401 within the budget, then 429", async () => {
    for (let i = 0; i < 2; i++) expect((await call("/v1/secrets", { headers: ip("203.0.113.5"), env })).status).toBe(401);
    const limited = await call("/v1/secrets", { headers: ip("203.0.113.5"), env });
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBeTruthy();
    // another IP is unaffected
    expect((await call("/v1/secrets", { headers: ip("203.0.113.6"), env })).status).toBe(401);
  });

  it("successful requests do not spend the IP budget, and valid tokens still work behind a limited IP", async () => {
    const t = await makeToken({ name: "a", prefixes: ["x."] });
    for (let i = 0; i < 5; i++) expect((await call("/v1/secrets", { token: t, headers: ip("203.0.113.5"), env })).status).toBe(200);
    for (let i = 0; i < 2; i++) await call("/v1/secrets", { headers: ip("203.0.113.5"), env });
    expect((await call("/v1/secrets", { headers: ip("203.0.113.5"), env })).status).toBe(429);
    expect((await call("/v1/secrets", { token: t, headers: ip("203.0.113.5"), env })).status).toBe(200);
  });

  it("groups IPv6 clients by /64", async () => {
    await call("/v1/secrets", { headers: ip("2001:db8:1:2::1"), env });
    await call("/v1/secrets", { headers: ip("2001:db8:1:2:ffff::9"), env });
    expect((await call("/v1/secrets", { headers: ip("2001:db8:1:2:1:2:3:4"), env })).status).toBe(429);
    expect((await call("/v1/secrets", { headers: ip("2001:db8:1:3::1"), env })).status).toBe(401);
  });

  it("ignores X-Forwarded-For when keying the limit", async () => {
    for (let i = 0; i < 3; i++) {
      await call("/v1/secrets", { headers: { "CF-Connecting-IP": "203.0.113.5", "X-Forwarded-For": `10.0.0.${i}` }, env });
    }
    const res = await call("/v1/secrets", { headers: { "CF-Connecting-IP": "203.0.113.5", "X-Forwarded-For": "10.9.9.9" }, env });
    expect(res.status).toBe(429);
  });
});

describe("limiter state cleans itself up", () => {
  it("drops a bucket once it has fully refilled, so sprayed IP keys don't pile up", async () => {
    await call("/v1/secrets", { headers: { "CF-Connecting-IP": "203.0.113.50" } }); // spends one failed-auth token
    const stub = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName("ip:203.0.113.50"));
    const stored = () => runInDurableObject(stub, (_i, state) => state.storage.get("bucket"));
    expect(await stored()).toBeDefined();
    expect(await runDurableObjectAlarm(stub)).toBe(true); // the alarm was scheduled
    expect(await stored()).toBeUndefined();
  });
});
