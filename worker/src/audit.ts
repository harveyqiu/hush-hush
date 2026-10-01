// Audit log: one row per /v1/secrets or /v1/admin request, never holding
// values or tokens (docs/functional-spec.md section 6).

import type { Config, Env } from "./config";
import type { Principal } from "./auth";
import { logEvent } from "./http";

export const ACTION = {
  get: "get",
  list: "list",
  put: "put",
  delete: "delete",
  /** Requests under /v1/secrets or /v1/admin that match no route. */
  other: "other",
  tokenList: "token_list",
  tokenCreate: "token_create",
  tokenUpdate: "token_update",
  tokenRevoke: "token_revoke",
  auditRead: "audit_read",
  whoami: "whoami",
} as const;

export const RESULT = {
  allowed: "allowed",
  denied: "denied",
  notFound: "not_found",
  unauthenticated: "unauthenticated",
  rateLimited: "rate_limited",
  badRequest: "bad_request",
  /** An agent tried to create a name that already exists. */
  conflict: "conflict",
  error: "error",
} as const;

export const AUDIT_ACTIONS: string[] = Object.values(ACTION);
export const AUDIT_RESULTS: string[] = Object.values(RESULT);

export const AUDIT_DEFAULT_LIMIT = 100;
export const AUDIT_MAX_LIMIT = 10_000;

export interface AuditEntry {
  tokenName: string;
  action: string;
  secretName: string;
  result: string;
  requestId: string;
  remoteAddr: string;
  /** Set once a handler recorded this request atomically with its write. */
  written: boolean;
}

/** Everything a handler needs about one authenticated request. */
export interface Ctx {
  env: Env;
  ctx: ExecutionContext;
  cfg: Config;
  db: D1Database;
  request: Request;
  url: URL;
  principal: Principal;
  audit: AuditEntry;
  /** The {name} path value (decoded), or "". */
  name: string;
}

export function resultForStatus(status: number): string {
  if (status < 400) return RESULT.allowed;
  switch (status) {
    case 401:
      return RESULT.unauthenticated;
    case 403:
      return RESULT.denied;
    case 404:
      return RESULT.notFound;
    case 409:
      return RESULT.conflict;
    case 429:
      return RESULT.rateLimited;
  }
  return status < 500 ? RESULT.badRequest : RESULT.error;
}

/** Actions that return stored data; their responses are withheld when the audit row can't be written. */
export function readsData(action: string): boolean {
  return (
    action === ACTION.get || action === ACTION.list || action === ACTION.tokenList || action === ACTION.auditRead
  );
}

const COLUMNS = `(ts, token_name, action, secret_name, result, request_id, remote_addr)`;

function auditStmt(db: D1Database, e: AuditEntry, ts: number, onlyIfChanged: boolean): D1PreparedStatement {
  const values = [ts, e.tokenName, e.action, e.secretName, e.result, e.requestId, e.remoteAddr];
  // changes() is the previous statement in the same batch: the row is only
  // written when that statement actually wrote something.
  const sql = onlyIfChanged
    ? `INSERT INTO audit_log ${COLUMNS} SELECT ?, ?, ?, ?, ?, ?, ? WHERE changes() > 0`
    : `INSERT INTO audit_log ${COLUMNS} VALUES (?, ?, ?, ?, ?, ?, ?)`;
  return db.prepare(sql).bind(...values);
}

export async function writeAudit(db: D1Database, e: AuditEntry, ts: number): Promise<void> {
  await auditStmt(db, e, ts, false).run();
}

/**
 * Runs `stmts` and the request's "allowed" audit row as one D1 batch (a
 * single transaction): the change happens and is recorded, or neither does.
 * With `onlyIfChanged` the audit row is skipped when the last statement
 * changed nothing (an agent's create-only PUT hitting an existing name);
 * the caller then reports a conflict and the pipeline records that instead.
 * Returns the results of `stmts` only.
 */
export async function commitWithAudit(
  c: Ctx,
  stmts: D1PreparedStatement[],
  opts: { onlyIfChanged?: boolean } = {},
): Promise<D1Result[]> {
  const row: AuditEntry = { ...c.audit, result: RESULT.allowed };
  const ts = Math.floor(Date.now() / 1000);
  const results = await c.db.batch([...stmts, auditStmt(c.db, row, ts, opts.onlyIfChanged === true)]);
  const auditRes = results[results.length - 1]!;
  c.audit.written = (auditRes.meta.changes ?? 0) > 0;
  if (!c.audit.written && !opts.onlyIfChanged) {
    logEvent("ERROR", "audit row missing after commit", { request_id: c.audit.requestId });
  }
  return results.slice(0, -1);
}

export interface AuditFilter {
  token: string;
  secret: string;
  action: string;
  result: string;
  /** Unix seconds; since inclusive, until exclusive. */
  since: number | null;
  until: number | null;
  limit: number;
}

export interface AuditRecord {
  ts: number;
  token_name: string;
  action: string;
  secret_name: string;
  result: string;
  remote_addr: string;
  request_id: string;
}

/** Returns an error message suitable for a 400, or null. */
export function validateFilter(f: AuditFilter): string | null {
  if (!Number.isInteger(f.limit) || f.limit <= 0 || f.limit > AUDIT_MAX_LIMIT) {
    return `limit must be between 1 and ${AUDIT_MAX_LIMIT}, got ${f.limit}`;
  }
  if (f.action !== "" && !AUDIT_ACTIONS.includes(f.action)) return `action must be one of ${AUDIT_ACTIONS.join(", ")}`;
  if (f.result !== "" && !AUDIT_RESULTS.includes(f.result)) return `result must be one of ${AUDIT_RESULTS.join(", ")}`;
  if (f.since !== null && f.until !== null && f.since >= f.until) return "since must be earlier than until";
  return null;
}

/** Matching rows, newest first. The WHERE clause is built from constant fragments only. */
export async function queryAudit(db: D1Database, f: AuditFilter): Promise<AuditRecord[]> {
  const conds: string[] = [];
  const args: (string | number)[] = [];
  for (const [cond, val] of [
    ["token_name = ?", f.token],
    ["secret_name = ?", f.secret],
    ["action = ?", f.action],
    ["result = ?", f.result],
  ] as const) {
    if (val !== "") {
      conds.push(cond);
      args.push(val);
    }
  }
  if (f.since !== null) {
    conds.push("ts >= ?");
    args.push(f.since);
  }
  if (f.until !== null) {
    conds.push("ts < ?");
    args.push(f.until);
  }
  let sql = `SELECT ts, token_name, action, secret_name, result, remote_addr, request_id FROM audit_log`;
  if (conds.length > 0) sql += ` WHERE ${conds.join(" AND ")}`;
  sql += ` ORDER BY ts DESC, id DESC LIMIT ?`;
  args.push(f.limit);
  const { results } = await db.prepare(sql).bind(...args).all<AuditRecord>();
  return results;
}
