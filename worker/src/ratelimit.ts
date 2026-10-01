// Token-bucket rate limiting on Durable Objects (docs/functional-spec.md
// section 7). Workers run as many isolates, so the in-process limiter of the
// Go version can't work here. One object per key; a Durable Object processes
// calls one at a time, which is exactly what a token bucket needs.

import { DurableObject } from "cloudflare:workers";
import type { Env } from "./config";
import { logEvent } from "./http";

interface Bucket {
  tokens: number;
  /** Unix ms of the last refill. */
  last: number;
}

export interface LimitResult {
  ok: boolean;
  /** Milliseconds until the next request would be allowed (0 when ok). */
  waitMs: number;
}

export class RateLimiter extends DurableObject<Env> {
  /**
   * Consumes one request. `capacity` is the per-minute budget: the bucket
   * starts full, holds `capacity` tokens and refills at capacity/60 per
   * second.
   */
  async allow(capacity: number): Promise<LimitResult> {
    const now = Date.now();
    const perSecond = capacity / 60;
    const stored = await this.ctx.storage.get<Bucket>("bucket");
    const b: Bucket = stored ?? { tokens: capacity, last: now };
    const elapsed = (now - b.last) / 1000;
    if (elapsed > 0) b.tokens = Math.min(capacity, b.tokens + elapsed * perSecond);
    // A clock that steps backwards must not mint tokens later.
    if (now > b.last) b.last = now;

    let result: LimitResult;
    if (b.tokens >= 1) {
      b.tokens -= 1;
      result = { ok: true, waitMs: 0 };
    } else {
      result = { ok: false, waitMs: ((1 - b.tokens) / perSecond) * 1000 };
    }
    await this.ctx.storage.put("bucket", b);
    // Once the bucket has fully refilled it carries no state: drop it, so
    // keys an attacker sprays (per-IP buckets) clean themselves up.
    await this.ctx.storage.setAlarm(now + ((capacity - b.tokens) / perSecond) * 1000 + 1000);
    return result;
  }

  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}

/**
 * Asks the limiter for `key`. A limiter failure lets the request through
 * (and logs): the limiter is abuse control, not an authentication boundary,
 * and failing closed would lock every legitimate caller out during an outage.
 */
export async function checkLimit(env: Env, key: string, capacity: number): Promise<LimitResult> {
  try {
    const stub = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(key));
    return await stub.allow(capacity);
  } catch (e) {
    logEvent("ERROR", "rate limiter unavailable; allowing request", { error: String(e) });
    return { ok: true, waitMs: 0 };
  }
}
