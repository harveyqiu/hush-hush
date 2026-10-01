// Authentication and authorization rules (docs/functional-spec.md section 5).

import { blobToBytes, logEvent, toArrayBuffer, HttpError } from "./http";
import { sha256, timingSafeEqual } from "./crypto";

export const ROLE_ADMIN = "admin";
export const ROLE_AGENT = "agent";
export const ALL_SECRETS = "*";

export const TOKEN_NAME_RE = /^[a-zA-Z0-9_.-]{1,64}$/;
/**
 * Name characters, at least one before the trailing separator, and a
 * mandatory trailing '.' or '_'. The separator is what stops "llm." from
 * matching "llmx.key".
 */
export const PREFIX_RE = /^[a-zA-Z0-9_.-]{1,127}[._]$/;
/**
 * D1 allows 100 bound parameters per statement; the agent list query binds
 * one per read prefix. (The Go version has no such limit.)
 */
export const MAX_PREFIXES = 64;

export interface Principal {
  name: string;
  role: string;
  prefixes: string[];
  /** Create-only grants: PUT a new name under them, never overwrite/delete. */
  writePrefixes: string[];
  /** Unix seconds; null when the token never expires. */
  expiresAt: number | null;
}

export type AuthResult = { kind: "ok"; principal: Principal } | { kind: "unauthenticated" };

/** Extracts the token from `Authorization: Bearer <token>`. */
export function bearerToken(req: Request): string | null {
  const auth = req.headers.get("Authorization") ?? "";
  if (!auth.startsWith("Bearer ")) return null;
  const tok = auth.slice("Bearer ".length).trim();
  return tok === "" ? null : tok;
}

/** Stored grants must be a JSON array of strings; null means unreadable. */
export function parseGrant(raw: unknown): string[] | null {
  if (typeof raw !== "string") return null;
  try {
    const v: unknown = JSON.parse(raw);
    if (v === null) return [];
    if (Array.isArray(v) && v.every((x) => typeof x === "string")) return v as string[];
  } catch {
    // fall through
  }
  return null;
}

interface TokenRow {
  id: number;
  name: string;
  token_hash: unknown;
  role: string;
  prefixes: unknown;
  write_prefixes: unknown;
  revoked_at: number | null;
  expires_at: number | null;
}

/**
 * Resolves the request's bearer token to a principal. Every credential
 * problem (no header, unknown, revoked, expired, corrupt row) yields the same
 * "unauthenticated" result; only infrastructure failures throw.
 */
export async function authenticate(
  db: D1Database,
  ctx: ExecutionContext,
  request: Request,
  nowSec: number,
  requestId: string,
): Promise<AuthResult> {
  const unauth: AuthResult = { kind: "unauthenticated" };
  const tok = bearerToken(request);
  if (tok === null) return unauth;
  // Hash first so every comparison is over 32 bytes.
  const given = await sha256(tok);

  let row: TokenRow | null;
  try {
    row = await db
      .prepare(
        `SELECT id, name, token_hash, role, prefixes, write_prefixes, revoked_at, expires_at
         FROM tokens WHERE token_hash = ?`,
      )
      .bind(toArrayBuffer(given))
      .first<TokenRow>();
  } catch (e) {
    logEvent("ERROR", "token lookup failed", { error: String(e), request_id: requestId });
    throw new HttpError(500, "db error");
  }
  if (row === null) return unauth;
  // The lookup is keyed on the hash; compare again in constant time so the
  // decision does not rest on the SQL engine's comparison alone.
  if (!timingSafeEqual(given, blobToBytes(row.token_hash))) return unauth;
  if (row.revoked_at !== null || (row.expires_at !== null && nowSec >= row.expires_at)) return unauth;
  if (row.role !== ROLE_ADMIN && row.role !== ROLE_AGENT) return unauth;
  if (row.role === ROLE_ADMIN && row.expires_at === null) {
    // Admin tokens always expire; a row without expiry was edited by hand.
    logEvent("ERROR", "admin token without expiry; rejecting", { token_name: row.name, request_id: requestId });
    return unauth;
  }
  const prefixes = parseGrant(row.prefixes);
  const writePrefixes = parseGrant(row.write_prefixes);
  if (prefixes === null || writePrefixes === null) {
    // Fail closed: a corrupted grant must not become a broader grant.
    logEvent("ERROR", "token prefixes unreadable; rejecting", { token_name: row.name, request_id: requestId });
    return unauth;
  }
  // Bookkeeping only: never fail or delay the request over it.
  ctx.waitUntil(
    db
      .prepare(`UPDATE tokens SET last_used_at = ? WHERE id = ?`)
      .bind(nowSec, row.id)
      .run()
      .catch((e: unknown) =>
        logEvent("WARN", "update last_used_at failed", { token_name: row.name, error: String(e) }),
      ),
  );
  return { kind: "ok", principal: { name: row.name, role: row.role, prefixes, writePrefixes, expiresAt: row.expires_at } };
}

/**
 * Checks a token's grant. Returns an error message, or null when valid.
 * Admin tokens carry no prefixes. Agents need at least one read or write
 * prefix; "*" must stand alone and is never allowed as a write prefix (a
 * token that can create any name is an admin in all but name).
 */
export function validateGrants(role: string, prefixes: string[], writePrefixes: string[]): string | null {
  if (role === ROLE_ADMIN) {
    if (prefixes.length > 0 || writePrefixes.length > 0) {
      return "admin tokens do not take --prefix or --write-prefix (they can read and write everything)";
    }
    return null;
  }
  if (role !== ROLE_AGENT) return `role must be "${ROLE_ADMIN}" or "${ROLE_AGENT}"`;
  if (prefixes.length === 0 && writePrefixes.length === 0) {
    return "agent tokens need at least one --prefix or --write-prefix";
  }
  if (prefixes.length > MAX_PREFIXES || writePrefixes.length > MAX_PREFIXES) {
    return `at most ${MAX_PREFIXES} prefixes of each kind are allowed`;
  }
  const seenW = new Set<string>();
  for (const p of writePrefixes) {
    if (p === ALL_SECRETS) return `"*" is not allowed as a write prefix; use a dedicated namespace such as agent-name.`;
    if (!PREFIX_RE.test(p)) {
      return `invalid write prefix ${JSON.stringify(p)}: must be name characters ending in '.' or '_' (e.g. crawler.)`;
    }
    if (seenW.has(p)) return `duplicate write prefix ${JSON.stringify(p)}`;
    seenW.add(p);
  }
  const seen = new Set<string>();
  for (const p of prefixes) {
    if (p === ALL_SECRETS) {
      if (prefixes.length !== 1) return `"*" must be the only prefix`;
      continue;
    }
    if (!PREFIX_RE.test(p)) {
      return `invalid prefix ${JSON.stringify(p)}: must be name characters ending in '.' or '_' (e.g. llm.)`;
    }
    if (seen.has(p)) return `duplicate prefix ${JSON.stringify(p)}`;
    seen.add(p);
  }
  return null;
}

/**
 * The usable read prefixes. Stored prefixes are re-validated on every use so
 * a hand-edited row (say an empty string, which would prefix-match
 * everything) can never widen access.
 */
export function grantedPrefixes(p: Principal): { all: boolean; prefixes: string[] } {
  if (p.role === ROLE_ADMIN) return { all: true, prefixes: [] };
  if (p.prefixes.length === 1 && p.prefixes[0] === ALL_SECRETS) return { all: true, prefixes: [] };
  return { all: false, prefixes: p.prefixes.filter((x) => PREFIX_RE.test(x)) };
}

/**
 * May p read the secret called name? Never touches the database, so an
 * out-of-scope name gets 403 whether or not it exists.
 */
export function canRead(p: Principal, name: string): boolean {
  const { all, prefixes } = grantedPrefixes(p);
  return all || prefixes.some((pre) => name.startsWith(pre));
}

/**
 * May an agent create the secret called name? Only admins and names under a
 * write prefix qualify; "*" and malformed stored prefixes never grant
 * anything.
 */
export function canCreate(p: Principal, name: string, nameRe: RegExp): boolean {
  if (p.role === ROLE_ADMIN) return true;
  if (!nameRe.test(name)) return false;
  return p.writePrefixes.some((pre) => PREFIX_RE.test(pre) && name.startsWith(pre));
}
