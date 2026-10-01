// /v1/secrets handlers (docs/functional-spec.md sections 9.2 - 9.6).

import { ACTION, commitWithAudit, type Ctx } from "./audit";
import { ROLE_ADMIN, canCreate, canRead, grantedPrefixes } from "./auth";
import { open, seal } from "./crypto";
import {
  MAX_BODY_BYTES,
  MAX_VALUE_BYTES,
  NAME_RE,
  blobToBytes,
  dbOp,
  errResponse,
  jsonResponse,
  logEvent,
  nowSeconds,
  readJsonObject,
  toArrayBuffer,
} from "./http";

/** Hard cap on one LIST response; personal scale should never approach it. */
export const LIST_LIMIT = 1000;

export type Handler = (c: Ctx) => Promise<Response>;
export interface Route {
  action: string;
  handler: Handler;
  /** The decoded {name} path value, when the route has one. */
  name?: string;
}

/** Gates PUT: admins pass; agents only for names under a write prefix. Runs before any parsing or DB access. */
export function requireCreateOrAdmin(h: Handler): Handler {
  return (c) =>
    c.principal.role !== ROLE_ADMIN && !canCreate(c.principal, c.name, NAME_RE)
      ? Promise.resolve(errResponse(403, "forbidden"))
      : h(c);
}

/** Gates mutating routes; runs before any parsing or DB access. */
export function requireAdmin(h: Handler): Handler {
  return (c) => (c.principal.role !== ROLE_ADMIN ? Promise.resolve(errResponse(403, "forbidden")) : h(c));
}

const utf8Length = (s: string) => new TextEncoder().encode(s).length;

async function list(c: Ctx): Promise<Response> {
  const { all, prefixes } = grantedPrefixes(c.principal);
  if (!all && prefixes.length === 0) return jsonResponse(200, { secrets: [] });

  // Agents get the prefix filter in SQL so LIMIT applies to what they may
  // see. substr() rather than LIKE: '_' is a LIKE wildcard and is also a
  // legal prefix separator. The length is an integer literal (not
  // user-controlled text); the prefix itself is bound.
  let sql = `SELECT name, created_at, updated_at FROM secrets`;
  const args: (string | number)[] = [];
  if (!all) {
    sql += ` WHERE ` + prefixes.map((p) => `substr(name, 1, ${p.length}) = ?`).join(` OR `);
    args.push(...prefixes);
  }
  sql += ` ORDER BY name LIMIT ?`;
  args.push(LIST_LIMIT);

  const { results } = await dbOp("list query", c.audit.requestId, () =>
    c.db
      .prepare(sql)
      .bind(...args)
      .all<{ name: string; created_at: number; updated_at: number }>(),
  );
  return jsonResponse(200, { secrets: results });
}

async function get(c: Ctx): Promise<Response> {
  const name = c.name;
  if (!NAME_RE.test(name)) return errResponse(400, "invalid name");
  // Checked before the lookup so an agent gets 403 for every name outside
  // its grant, existing or not; 404 would let it probe for names.
  if (!canRead(c.principal, name)) return errResponse(403, "forbidden");

  const row = await dbOp("get query", c.audit.requestId, () =>
    c.db
      .prepare(`SELECT ciphertext, nonce, created_at, updated_at FROM secrets WHERE name = ?`)
      .bind(name)
      .first<{ ciphertext: unknown; nonce: unknown; created_at: number; updated_at: number }>(),
  );
  if (row === null) return errResponse(404, "not found");

  let value: string;
  try {
    value = await open(c.cfg.key, name, blobToBytes(row.ciphertext), blobToBytes(row.nonce));
  } catch (e) {
    logEvent("ERROR", "decrypt failed", { name, reason: (e as Error).message, request_id: c.audit.requestId });
    return errResponse(500, "decrypt failed");
  }
  return jsonResponse(200, { name, value, created_at: row.created_at, updated_at: row.updated_at });
}

async function put(c: Ctx): Promise<Response> {
  const name = c.name;
  if (!NAME_RE.test(name)) return errResponse(400, "invalid name");
  const body = await readJsonObject(c.request, MAX_BODY_BYTES, { value: "string" });
  if (!body.ok) return body.res;
  const value = (body.value["value"] as string | undefined) ?? "";
  if (value === "") return errResponse(400, "value required");
  if (utf8Length(value) > MAX_VALUE_BYTES) return errResponse(413, "value too large");

  const { ciphertext, nonce } = await seal(c.cfg.key, name, value);
  const now = nowSeconds();
  // Admins upsert. Agents (let through by requireCreateOrAdmin only for
  // names under a write prefix) may create but never overwrite: DO NOTHING
  // returns no row for an existing name, which becomes 409. One statement,
  // so there is no check-then-insert race.
  const onConflict =
    c.principal.role === ROLE_ADMIN
      ? `DO UPDATE SET ciphertext = excluded.ciphertext, nonce = excluded.nonce, updated_at = excluded.updated_at`
      : `DO NOTHING`;
  const insert = c.db
    .prepare(
      `INSERT INTO secrets (name, ciphertext, nonce, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(name) ${onConflict}
       RETURNING created_at`,
    )
    .bind(name, toArrayBuffer(ciphertext), toArrayBuffer(nonce), now, now);

  // The write and its audit row commit together. For a refused create the
  // audit row is skipped here and recorded as "conflict" by the pipeline.
  const [res] = await dbOp("put", c.audit.requestId, () => commitWithAudit(c, [insert], { onlyIfChanged: true }));
  const row = res?.results[0] as { created_at: number } | undefined;
  if (row === undefined) return errResponse(409, "already exists");
  return jsonResponse(200, { name, created_at: row.created_at, updated_at: now });
}

async function del(c: Ctx): Promise<Response> {
  const name = c.name;
  if (!NAME_RE.test(name)) return errResponse(400, "invalid name");
  // Idempotent: a retry of a successful DELETE must not surface as an error,
  // so "deleted" and "wasn't there" are indistinguishable.
  await dbOp("delete", c.audit.requestId, () =>
    commitWithAudit(c, [c.db.prepare(`DELETE FROM secrets WHERE name = ?`).bind(name)]),
  );
  return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
}

/**
 * Answers requests under /v1/secrets that no route handles: 405 for a known
 * path with an unsupported method, 404 for anything else. Runs after
 * authentication, so unauthenticated callers learn nothing about which
 * paths exist.
 */
async function unmatched(c: Ctx): Promise<Response> {
  const path = c.url.pathname;
  const rest = path.startsWith("/v1/secrets/") ? path.slice("/v1/secrets/".length) : null;
  if (path === "/v1/secrets") return errResponse(405, "method not allowed", { Allow: "GET" });
  if (rest !== null && rest !== "" && !rest.includes("/")) {
    return errResponse(405, "method not allowed", { Allow: "GET, PUT, DELETE" });
  }
  return errResponse(404, "not found");
}

function decodeSegment(seg: string): string {
  try {
    return decodeURIComponent(seg);
  } catch {
    return seg; // malformed escape: contains '%', so it fails NAME_RE later
  }
}

/** Resolves a /v1/secrets* request to its handler. HEAD is treated as GET, as net/http does. */
export function resolveSecretsRoute(method: string, path: string): Route {
  const m = method === "HEAD" ? "GET" : method;
  if (path === "/v1/secrets") {
    return m === "GET" ? { action: ACTION.list, handler: list } : { action: ACTION.other, handler: unmatched };
  }
  const rest = path.slice("/v1/secrets/".length);
  if (rest === "" || rest.includes("/")) return { action: ACTION.other, handler: unmatched };
  const name = decodeSegment(rest);
  switch (m) {
    case "GET":
      return { action: ACTION.get, handler: get, name };
    case "PUT":
      return { action: ACTION.put, handler: requireCreateOrAdmin(put), name };
    case "DELETE":
      return { action: ACTION.delete, handler: requireAdmin(del), name };
  }
  return { action: ACTION.other, handler: unmatched, name };
}
