// Token-bucket rate limiting on D1 (docs/functional-spec.md section 7).
// Workers run as many isolates, so the in-process limiter of the Go version
// can't work here. The bucket lives in one D1 row per key and is updated by a
// single UPSERT, which D1 executes atomically, so concurrent requests can't
// both spend the same token.

import type { Env } from "./config";
import { logEvent } from "./http";

export interface LimitResult {
  ok: boolean;
  /** Milliseconds until the next request would be allowed (0 when ok). */
  waitMs: number;
}

/**
 * Consumes one request. `capacity` is the per-minute budget: the bucket
 * starts full, holds `capacity` tokens and refills at capacity/60 per second.
 */
async function allow(db: D1Database, key: string, capacity: number, now: number): Promise<LimitResult> {
  const perMs = capacity / 60000;
  // `t` is the refilled balance. A clock that steps backwards must not mint
  // tokens later, hence MAX(0, ...) on the elapsed time and on last_ms.
  const refilled = `MIN(?1, rate_limits.tokens + MAX(0, ?2 - rate_limits.last_ms) * ?3)`;
  const row = await db
    .prepare(
      `INSERT INTO rate_limits (key, tokens, last_ms, allowed)
       VALUES (?4, ?1 - 1, ?2, 1)
       ON CONFLICT (key) DO UPDATE SET
         allowed = (${refilled} >= 1),
         tokens  = CASE WHEN ${refilled} >= 1 THEN ${refilled} - 1 ELSE ${refilled} END,
         last_ms = MAX(rate_limits.last_ms, ?2)
       RETURNING tokens, allowed`,
    )
    .bind(capacity, now, perMs, key)
    .first<{ tokens: number; allowed: number }>();
  if (!row) throw new Error("rate limit upsert returned no row");
  if (row.allowed === 1) return { ok: true, waitMs: 0 };
  return { ok: false, waitMs: (1 - row.tokens) / perMs };
}

/**
 * Asks the limiter for `key`. A limiter failure lets the request through
 * (and logs): the limiter is abuse control, not an authentication boundary,
 * and failing closed would lock every legitimate caller out during an outage.
 */
export async function checkLimit(env: Env, key: string, capacity: number): Promise<LimitResult> {
  try {
    return await allow(env.DB, key, capacity, Date.now());
  } catch (e) {
    logEvent("ERROR", "rate limiter unavailable; allowing request", { error: String(e) });
    return { ok: true, waitMs: 0 };
  }
}

/**
 * Deletes buckets idle for over a minute. A bucket refills completely in 60
 * seconds whatever its capacity, so such a row carries no state; this keeps
 * keys an attacker sprays (per-IP buckets) from piling up.
 */
export async function pruneRateLimits(db: D1Database, nowMs: number): Promise<number> {
  const res = await db.prepare(`DELETE FROM rate_limits WHERE last_ms < ?`).bind(nowMs - 61000).run();
  return res.meta.changes ?? 0;
}
