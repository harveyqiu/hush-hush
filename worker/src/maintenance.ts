// Daily Cron: replaces the startup warnings of the Go version (a Worker has
// no startup) and, when AUDIT_RETENTION_DAYS is set, the `audit-prune`
// subcommand.

import type { Env } from "./config";
import { ConfigError, positiveInt } from "./config";
import { logEvent } from "./http";

const WEEK_SECONDS = 7 * 24 * 3600;

export async function runMaintenance(env: Env, nowSec: number): Promise<void> {
  const active = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM tokens WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
  )
    .bind(nowSec)
    .first<{ n: number }>();
  if ((active?.n ?? 0) === 0) {
    logEvent("WARN", "no active tokens: every API request will be rejected until one is created (see worker/README.md)");
  }

  const { results } = await env.DB.prepare(
    `SELECT name FROM tokens
     WHERE role = 'admin' AND revoked_at IS NULL AND expires_at > ? AND expires_at <= ? ORDER BY name`,
  )
    .bind(nowSec, nowSec + WEEK_SECONDS)
    .all<{ name: string }>();
  if (results.length > 0) {
    logEvent("WARN", "admin tokens expire within 7 days; create replacements before they lapse", {
      tokens: results.map((r) => r.name),
    });
  }

  let days: number | null = null;
  try {
    days = env.AUDIT_RETENTION_DAYS ? positiveInt(env.AUDIT_RETENTION_DAYS, "AUDIT_RETENTION_DAYS", 0) : null;
  } catch (e) {
    if (!(e instanceof ConfigError)) throw e;
    logEvent("ERROR", e.message);
  }
  if (days !== null) {
    const cutoff = nowSec - days * 86400;
    const res = await env.DB.prepare(`DELETE FROM audit_log WHERE ts < ?`).bind(cutoff).run();
    logEvent("INFO", "audit prune", { deleted: res.meta.changes ?? 0, older_than_days: days });
  }
}
