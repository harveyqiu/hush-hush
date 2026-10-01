import type { RateLimiter } from "./ratelimit";
import { decodeMasterKey, importMasterKey } from "./crypto";

export interface Env {
  DB: D1Database;
  RATE_LIMITER: DurableObjectNamespace<RateLimiter>;
  ASSETS: Fetcher;
  /** Secret: base64 of 32 random bytes. */
  MASTER_KEY: string;
  RATE_LIMIT_PER_MINUTE?: string;
  UNAUTH_RATE_LIMIT_PER_MINUTE?: string;
  ADMIN_API?: string;
  AUDIT_RETENTION_DAYS?: string;
}

export const DEFAULT_RATE_LIMIT_PER_MINUTE = 60;
export const DEFAULT_UNAUTH_RATE_LIMIT_PER_MINUTE = 10;

export interface Config {
  key: CryptoKey;
  rateLimitPerMinute: number;
  unauthRateLimitPerMinute: number;
  /** Enables /v1/admin/* and the web UI. */
  adminApi: boolean;
}

/** Misconfiguration. Messages never contain key material. */
export class ConfigError extends Error {}

export function positiveInt(v: string | undefined, name: string, def: number): number {
  if (v === undefined || v === "") return def;
  const n = /^[+-]?\d+$/.test(v) ? Number(v) : NaN;
  if (!Number.isSafeInteger(n) || n <= 0) throw new ConfigError(`${name}: must be a positive integer, got "${v}"`);
  return n;
}

/** Same literals as Go's strconv.ParseBool. */
export function parseBool(v: string | undefined, name: string, def: boolean): boolean {
  if (v === undefined || v === "") return def;
  if (["1", "t", "T", "TRUE", "true", "True"].includes(v)) return true;
  if (["0", "f", "F", "FALSE", "false", "False"].includes(v)) return false;
  throw new ConfigError(`${name}: must be true or false, got "${v}"`);
}

// Importing the key is async and the isolate is reused across requests.
let keyCache: { raw: string; key: CryptoKey } | undefined;

export async function loadConfig(env: Env): Promise<Config> {
  if (!env.MASTER_KEY) throw new ConfigError("master key missing: run `wrangler secret put MASTER_KEY`");
  if (keyCache?.raw !== env.MASTER_KEY) {
    let raw: Uint8Array;
    try {
      raw = decodeMasterKey(env.MASTER_KEY);
    } catch (e) {
      throw new ConfigError(`MASTER_KEY: ${(e as Error).message}`);
    }
    keyCache = { raw: env.MASTER_KEY, key: await importMasterKey(raw) };
  }
  return {
    key: keyCache.key,
    rateLimitPerMinute: positiveInt(env.RATE_LIMIT_PER_MINUTE, "RATE_LIMIT_PER_MINUTE", DEFAULT_RATE_LIMIT_PER_MINUTE),
    unauthRateLimitPerMinute: positiveInt(
      env.UNAUTH_RATE_LIMIT_PER_MINUTE,
      "UNAUTH_RATE_LIMIT_PER_MINUTE",
      DEFAULT_UNAUTH_RATE_LIMIT_PER_MINUTE,
    ),
    adminApi: parseBool(env.ADMIN_API, "ADMIN_API", true),
  };
}
