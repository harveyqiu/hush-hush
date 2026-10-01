import { applyD1Migrations, createExecutionContext, env, reset, waitOnExecutionContext } from "cloudflare:test";
import type { D1Migration } from "@cloudflare/vitest-pool-workers";
import worker from "../src/index";
import type { Env } from "../src/config";
import { bytesToHex, sha256 } from "../src/crypto";

declare global {
  namespace Cloudflare {
    interface Env {
      TEST_MIGRATIONS: D1Migration[];
    }
  }
}

export const BASE = "https://hush.test";

/** Empties every binding (D1, Durable Objects) and re-applies the schema. */
export async function resetAll(): Promise<void> {
  await reset();
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
}

export interface TokenOpts {
  name: string;
  role?: "admin" | "agent";
  prefixes?: string[];
  writePrefixes?: string[];
  /** Unix seconds; defaults to +1 day for admins, none for agents. */
  expiresAt?: number | null;
  revokedAt?: number | null;
}

const nowSec = () => Math.floor(Date.now() / 1000);

/** Inserts a token row directly (the way the bootstrap script does) and returns its plaintext. */
export async function makeToken(o: TokenOpts): Promise<string> {
  const plaintext = "hush_" + bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  const role = o.role ?? "agent";
  const expiresAt = o.expiresAt !== undefined ? o.expiresAt : role === "admin" ? nowSec() + 86400 : null;
  const hash = await sha256(plaintext);
  await env.DB.prepare(
    `INSERT INTO tokens (name, token_hash, role, prefixes, write_prefixes, expires_at, revoked_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      o.name,
      hash.buffer.slice(hash.byteOffset, hash.byteOffset + hash.byteLength),
      role,
      JSON.stringify(o.prefixes ?? []),
      JSON.stringify(o.writePrefixes ?? []),
      expiresAt,
      o.revokedAt ?? null,
      nowSec(),
    )
    .run();
  return plaintext;
}

export interface CallInit {
  method?: string;
  token?: string;
  /** Sent as JSON unless it is a string (then sent verbatim). */
  body?: unknown;
  headers?: Record<string, string>;
  env?: Partial<Env> & Record<string, unknown>;
}

/** Calls the Worker's fetch handler directly, optionally with overridden env vars. */
export async function call(path: string, init: CallInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (init.token !== undefined) headers.set("Authorization", `Bearer ${init.token}`);
  let body: string | undefined;
  if (init.body !== undefined) {
    body = typeof init.body === "string" ? init.body : JSON.stringify(init.body);
    if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  }
  const req = new Request(BASE + path, { method: init.method ?? "GET", headers, body });
  const ctx = createExecutionContext();
  const res = await worker.fetch(req, { ...env, ...init.env } as Env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

export async function json<T = Record<string, unknown>>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

export interface AuditRow {
  ts: number;
  token_name: string;
  action: string;
  secret_name: string;
  result: string;
  request_id: string;
  remote_addr: string;
}

export async function auditRows(): Promise<AuditRow[]> {
  const { results } = await env.DB.prepare(`SELECT * FROM audit_log ORDER BY id`).all<AuditRow>();
  return results;
}

export { env };
