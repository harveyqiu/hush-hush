// Token management rules, used by the admin HTTP API. They never return a
// token hash. (docs/functional-spec.md section 5.)

import {
  ALL_SECRETS,
  ROLE_ADMIN,
  ROLE_AGENT,
  TOKEN_NAME_RE,
  parseGrant,
  validateGrants,
} from "./auth";
import { sha256 } from "./crypto";
import { randomHex, toArrayBuffer } from "./http";

/** Marks hush tokens so secret scanners (gitleaks etc.) can be taught to spot a leaked one. */
export const TOKEN_PREFIX = "hush_";

/** An admin token can mint agent tokens, so its life is bounded. */
export const MAX_ADMIN_LIFETIME_MS = 90 * 24 * 3600 * 1000;

export type TokenErrorKind = "exists" | "notFound" | "revoked" | "notAgent" | "grant";

const TOKEN_ERROR_TEXT: Record<Exclude<TokenErrorKind, "grant">, string> = {
  exists: "a token with this name already exists (names are never reused, even after revoke)",
  notFound: "no token with this name",
  revoked: "token is revoked",
  notAgent: "only agent tokens have prefixes",
};

export class TokenError extends Error {
  constructor(
    readonly kind: TokenErrorKind,
    message?: string,
  ) {
    super(message ?? TOKEN_ERROR_TEXT[kind as Exclude<TokenErrorKind, "grant">]);
  }
}

export interface TokenSpec {
  name: string;
  role: string;
  prefixes: string[];
  writePrefixes: string[];
  /** Unix ms; null = never expires. */
  expiresAtMs: number | null;
}

export interface TokenInfo {
  name: string;
  role: string;
  prefixes: string[];
  write_prefixes: string[];
  status: "active" | "revoked" | "expired";
  expires_at: number | null;
  last_used_at: number | null;
  revoked_at: number | null;
  created_at: number;
}

export function generateToken(): string {
  return TOKEN_PREFIX + randomHex(32);
}

/** The read-prefix list is exactly the "*" wildcard (which callers must confirm explicitly). */
export function grantsAll(prefixes: string[]): boolean {
  return prefixes.length === 1 && prefixes[0] === ALL_SECRETS;
}

/** Everything about a new token that doesn't need the database. Returns an error message or null. */
export function validateTokenSpec(spec: TokenSpec, nowMs: number): string | null {
  if (!TOKEN_NAME_RE.test(spec.name)) return "name must match ^[a-zA-Z0-9_.-]{1,64}$";
  if (spec.role === ROLE_ADMIN) {
    if (spec.expiresAtMs === null) return "admin tokens must expire: set an expiry of at most 90d";
    if (spec.expiresAtMs - nowMs > MAX_ADMIN_LIFETIME_MS) return "admin tokens may live at most 90d";
  }
  return validateGrants(spec.role, spec.prefixes, spec.writePrefixes);
}

const jsonList = (p: string[]) => JSON.stringify(p);

async function tokenExists(db: D1Database, name: string): Promise<boolean> {
  const row = await db.prepare(`SELECT 1 AS x FROM tokens WHERE name = ?`).bind(name).first();
  return row !== null;
}

/**
 * Warnings for each write prefix that overlaps another active agent's.
 * Create-only writes can't overwrite, but two agents sharing a namespace can
 * still plant names the other relies on.
 */
export async function writeNamespaceOverlaps(db: D1Database, self: string, writePrefixes: string[]): Promise<string[]> {
  if (writePrefixes.length === 0) return [];
  const { results } = await db
    .prepare(`SELECT name, write_prefixes FROM tokens WHERE name != ? AND role = 'agent' AND revoked_at IS NULL`)
    .bind(self)
    .all<{ name: string; write_prefixes: string }>();
  const warnings: string[] = [];
  for (const other of results) {
    const theirs = parseGrant(other.write_prefixes);
    if (theirs === null) continue;
    for (const mine of writePrefixes) {
      for (const t of theirs) {
        if (mine.startsWith(t) || t.startsWith(mine)) {
          warnings.push(
            `write prefix ${JSON.stringify(mine)} overlaps ${JSON.stringify(t)} on token ${JSON.stringify(other.name)}; ` +
              `agents sharing a write namespace can create names the other relies on. Prefer one namespace per agent.`,
          );
        }
      }
    }
  }
  return warnings;
}

export interface PreparedCreate {
  /** Shown to the caller once; only its hash is stored. */
  plaintext: string;
  warnings: string[];
  insert: D1PreparedStatement;
}

/** Validates spec, refuses a reused name, and prepares the insert (the caller commits it with its audit row). */
export async function prepareCreateToken(db: D1Database, spec: TokenSpec, nowMs: number): Promise<PreparedCreate> {
  const bad = validateTokenSpec(spec, nowMs);
  if (bad !== null) throw new TokenError("grant", bad);
  if (await tokenExists(db, spec.name)) throw new TokenError("exists");
  const warnings = await writeNamespaceOverlaps(db, spec.name, spec.writePrefixes);
  const plaintext = generateToken();
  const hash = await sha256(plaintext);
  const insert = db
    .prepare(
      `INSERT INTO tokens (name, token_hash, role, prefixes, write_prefixes, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      spec.name,
      toArrayBuffer(hash),
      spec.role,
      jsonList(spec.prefixes),
      jsonList(spec.writePrefixes),
      spec.expiresAtMs === null ? null : Math.floor(spec.expiresAtMs / 1000),
      Math.floor(nowMs / 1000),
    );
  return { plaintext, warnings, insert };
}

/** A unique-constraint failure from a concurrent create with the same name. */
export function isUniqueViolation(e: unknown): boolean {
  return /UNIQUE constraint failed/i.test(String(e));
}

/** Every token sorted by name. token_hash is never selected. */
export async function listTokens(db: D1Database, nowSec: number): Promise<TokenInfo[]> {
  const { results } = await db
    .prepare(
      `SELECT name, role, prefixes, write_prefixes, revoked_at, expires_at, last_used_at, created_at
       FROM tokens ORDER BY name`,
    )
    .all<{
      name: string;
      role: string;
      prefixes: string;
      write_prefixes: string;
      revoked_at: number | null;
      expires_at: number | null;
      last_used_at: number | null;
      created_at: number;
    }>();
  return results.map((t) => {
    let status: TokenInfo["status"] = "active";
    if (t.revoked_at !== null) status = "revoked";
    else if (t.expires_at !== null && nowSec >= t.expires_at) status = "expired";
    return {
      name: t.name,
      role: t.role,
      // Unreadable JSON shows as a marker rather than hiding the problem.
      prefixes: parseGrant(t.prefixes) ?? ["<unreadable>"],
      write_prefixes: parseGrant(t.write_prefixes) ?? ["<unreadable>"],
      status,
      expires_at: t.expires_at,
      last_used_at: t.last_used_at,
      revoked_at: t.revoked_at,
      created_at: t.created_at,
    };
  });
}

export interface GrantUpdate {
  /** undefined keeps the current list; [] clears it. */
  prefixes?: string[];
  writePrefixes?: string[];
}

export interface PreparedUpdate {
  read: string[];
  write: string[];
  warnings: string[];
  update: D1PreparedStatement;
}

/**
 * Applies `u` to an active agent token: reads the row, validates the
 * resulting grant and prepares the UPDATE. (D1 has no read-then-write
 * transaction, so two admins editing the same token at once can overwrite
 * each other.)
 */
export async function prepareUpdateGrants(db: D1Database, name: string, u: GrantUpdate): Promise<PreparedUpdate> {
  const row = await db
    .prepare(`SELECT role, prefixes, write_prefixes, revoked_at FROM tokens WHERE name = ?`)
    .bind(name)
    .first<{ role: string; prefixes: string; write_prefixes: string; revoked_at: number | null }>();
  if (row === null) throw new TokenError("notFound");
  if (row.role !== ROLE_AGENT) throw new TokenError("notAgent");
  if (row.revoked_at !== null) throw new TokenError("revoked");
  // An unreadable current value is treated as empty.
  const read = u.prefixes ? [...u.prefixes] : (parseGrant(row.prefixes) ?? []);
  const write = u.writePrefixes ? [...u.writePrefixes] : (parseGrant(row.write_prefixes) ?? []);
  const bad = validateGrants(ROLE_AGENT, read, write);
  if (bad !== null) throw new TokenError("grant", bad);
  const warnings = u.writePrefixes ? await writeNamespaceOverlaps(db, name, write) : [];
  const update = db
    .prepare(`UPDATE tokens SET prefixes = ?, write_prefixes = ? WHERE name = ?`)
    .bind(jsonList(read), jsonList(write), name);
  return { read, write, warnings, update };
}

/** Permanently revokes `name`; `alreadyRevoked` means there is nothing left to do. */
export async function prepareRevokeToken(
  db: D1Database,
  name: string,
  nowSec: number,
): Promise<{ alreadyRevoked: boolean; revoke: D1PreparedStatement }> {
  const row = await db.prepare(`SELECT revoked_at FROM tokens WHERE name = ?`).bind(name).first<{ revoked_at: number | null }>();
  if (row === null) throw new TokenError("notFound");
  const revoke = db
    .prepare(`UPDATE tokens SET revoked_at = ? WHERE name = ? AND revoked_at IS NULL`)
    .bind(nowSec, name);
  return { alreadyRevoked: row.revoked_at !== null, revoke };
}
