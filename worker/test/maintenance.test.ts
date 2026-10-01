import { createExecutionContext, createScheduledController, env, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/config";
import { makeToken, resetAll } from "./helpers";

beforeEach(resetAll);

const DAY = 86_400;
const now = () => Math.floor(Date.now() / 1000);

async function seedAudit() {
  const insert = (ts: number, secret: string) =>
    env.DB.prepare(
      `INSERT INTO audit_log (ts, token_name, action, secret_name, result) VALUES (?, 't', 'get', ?, 'allowed')`,
    ).bind(ts, secret);
  await env.DB.batch([insert(now() - 200 * DAY, "ancient"), insert(now() - 40 * DAY, "old"), insert(now() - DAY, "recent")]);
}

async function runCron(over: Partial<Env> = {}) {
  const ctx = createExecutionContext();
  await worker.scheduled(createScheduledController(), { ...env, ...over } as Env, ctx);
  await waitOnExecutionContext(ctx);
}

const secrets = async () =>
  (await env.DB.prepare(`SELECT secret_name FROM audit_log ORDER BY ts`).all<{ secret_name: string }>()).results.map((r) => r.secret_name);

describe("scheduled maintenance", () => {
  it("keeps all audit rows when AUDIT_RETENTION_DAYS is not set", async () => {
    await seedAudit();
    await makeToken({ name: "root", role: "admin" });
    await runCron();
    expect(await secrets()).toEqual(["ancient", "old", "recent"]);
  });

  it("prunes audit rows older than AUDIT_RETENTION_DAYS", async () => {
    await seedAudit();
    await runCron({ AUDIT_RETENTION_DAYS: "30" });
    expect(await secrets()).toEqual(["recent"]);
  });

  it("an invalid retention value deletes nothing", async () => {
    await seedAudit();
    await runCron({ AUDIT_RETENTION_DAYS: "soon" });
    await runCron({ AUDIT_RETENTION_DAYS: "0" });
    expect(await secrets()).toHaveLength(3);
  });

  it("runs on an empty database (no tokens) without throwing", async () => {
    await expect(runCron()).resolves.toBeUndefined();
  });
});
