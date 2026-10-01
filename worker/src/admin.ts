// Admin HTTP API behind the web UI (docs/functional-spec.md section 9.7).
// Every route goes through the same pipeline as /v1/secrets (authentication,
// rate limit, one audit row) and requireAdmin, so agent tokens get 403 before
// any parsing.

import {
  ACTION,
  AUDIT_DEFAULT_LIMIT,
  commitWithAudit,
  queryAudit,
  validateFilter,
  type AuditFilter,
  type Ctx,
} from "./audit";
import { TOKEN_NAME_RE } from "./auth";
import { parseDurationMs, parseQueryTime } from "./duration";
import {
  MAX_ADMIN_BODY,
  NAME_RE,
  dbOp,
  errResponse,
  jsonResponse,
  logEvent,
  nowSeconds,
  readJsonObject,
} from "./http";
import { requireAdmin, type Route } from "./secrets";
import {
  TokenError,
  grantsAll,
  isUniqueViolation,
  listTokens,
  prepareCreateToken,
  prepareRevokeToken,
  prepareUpdateGrants,
  validateTokenSpec,
  type GrantUpdate,
  type TokenSpec,
} from "./tokens";

const CONFIRM_ALL_MSG = `prefix "*" grants every secret; resend with "confirm_all": true`;

/** Maps token-layer errors to HTTP; anything unrecognised is internal and not echoed. */
function tokenErrorResponse(c: Ctx, e: unknown): Response {
  if (e instanceof TokenError) {
    switch (e.kind) {
      case "exists":
      case "revoked":
      case "notAgent":
        return errResponse(409, e.message);
      case "notFound":
        return errResponse(404, "not found");
      case "grant":
        return errResponse(400, e.message);
    }
  }
  logEvent("ERROR", "admin token operation failed", { error: String(e), request_id: c.audit.requestId });
  return errResponse(500, "db error");
}

/** Records the object a request acts on when it isn't in the URL path. Only well-formed names are kept. */
function setAuditTarget(c: Ctx, name: string): void {
  if (NAME_RE.test(name)) c.audit.secretName = name;
}

/** Tells the UI which token it is using and when it expires, so the operator can rotate in time. */
async function me(c: Ctx): Promise<Response> {
  const p = c.principal;
  return jsonResponse(200, { name: p.name, role: p.role, expires_at: p.expiresAt });
}

async function tokenList(c: Ctx): Promise<Response> {
  try {
    return jsonResponse(200, { tokens: await listTokens(c.db, nowSeconds()) });
  } catch (e) {
    return tokenErrorResponse(c, e);
  }
}

async function tokenCreate(c: Ctx): Promise<Response> {
  const body = await readJsonObject(c.request, MAX_ADMIN_BODY, {
    name: "string",
    role: "string",
    prefixes: "strings",
    write_prefixes: "strings",
    expires: "string",
    confirm_all: "bool",
  });
  if (!body.ok) return body.res;
  const v = body.value;
  const name = (v["name"] as string | undefined) ?? "";
  const expires = (v["expires"] as string | undefined) ?? "";
  const prefixes = (v["prefixes"] as string[] | undefined) ?? [];
  setAuditTarget(c, name);

  const nowMs = Date.now();
  let expiresAtMs: number | null = null;
  if (expires !== "") {
    const d = parseDurationMs(expires);
    if (d === null) return errResponse(400, "invalid expires (use e.g. 90d or 12h)");
    expiresAtMs = nowMs + d;
  }
  const spec: TokenSpec = {
    name,
    role: (v["role"] as string | undefined) ?? "",
    prefixes,
    writePrefixes: (v["write_prefixes"] as string[] | undefined) ?? [],
    expiresAtMs,
  };
  const bad = validateTokenSpec(spec, nowMs);
  if (bad !== null) return errResponse(400, bad);
  if (grantsAll(prefixes) && v["confirm_all"] !== true) return errResponse(400, CONFIRM_ALL_MSG);

  try {
    const { plaintext, warnings, insert } = await prepareCreateToken(c.db, spec, nowMs);
    await commitWithAudit(c, [insert]);
    // The only time the plaintext exists outside the caller. The response is
    // no-store and is never logged.
    return jsonResponse(201, { name, token: plaintext, warnings });
  } catch (e) {
    // A concurrent create with the same name loses at the UNIQUE constraint.
    return tokenErrorResponse(c, isUniqueViolation(e) ? new TokenError("exists") : e);
  }
}

async function tokenUpdate(c: Ctx): Promise<Response> {
  const name = c.name;
  if (!TOKEN_NAME_RE.test(name)) return errResponse(400, "invalid name");
  const body = await readJsonObject(c.request, MAX_ADMIN_BODY, {
    prefixes: "strings",
    write_prefixes: "strings",
    confirm_all: "bool",
  });
  if (!body.ok) return body.res;
  // A missing (or null) field keeps the current list; [] clears it.
  const u: GrantUpdate = {};
  const prefixes = body.value["prefixes"] as string[] | undefined;
  const writePrefixes = body.value["write_prefixes"] as string[] | undefined;
  if (prefixes !== undefined) u.prefixes = prefixes;
  if (writePrefixes !== undefined) u.writePrefixes = writePrefixes;
  if (prefixes === undefined && writePrefixes === undefined) {
    return errResponse(400, "give prefixes and/or write_prefixes");
  }
  if (prefixes !== undefined && grantsAll(prefixes) && body.value["confirm_all"] !== true) {
    return errResponse(400, CONFIRM_ALL_MSG);
  }
  try {
    const { read, write, warnings, update } = await prepareUpdateGrants(c.db, name, u);
    await commitWithAudit(c, [update]);
    return jsonResponse(200, { name, prefixes: read, write_prefixes: write, warnings });
  } catch (e) {
    return tokenErrorResponse(c, e);
  }
}

async function tokenRevoke(c: Ctx): Promise<Response> {
  const name = c.name;
  if (!TOKEN_NAME_RE.test(name)) return errResponse(400, "invalid name");
  // Revoking the token making this request would lock the operator out of
  // the UI mid-session; use another admin token.
  if (c.principal.name === name) return errResponse(409, "refusing to revoke the token used for this request");
  try {
    const { alreadyRevoked, revoke } = await prepareRevokeToken(c.db, name, nowSeconds());
    await commitWithAudit(c, [revoke]);
    return jsonResponse(200, { name, revoked: true, already_revoked: alreadyRevoked });
  } catch (e) {
    return tokenErrorResponse(c, e);
  }
}

/** GET /v1/admin/audit?token=&secret=&action=&result=&since=&until=&limit= */
async function audit(c: Ctx): Promise<Response> {
  const qs = c.url.searchParams;
  const nowMs = Date.now();
  const f: AuditFilter = {
    token: qs.get("token") ?? "",
    secret: qs.get("secret") ?? "",
    action: qs.get("action") ?? "",
    result: qs.get("result") ?? "",
    since: null,
    until: null,
    limit: AUDIT_DEFAULT_LIMIT,
  };
  const limit = qs.get("limit");
  if (limit !== null && limit !== "") {
    if (!/^[+-]?\d+$/.test(limit)) return errResponse(400, "limit must be an integer");
    f.limit = Number(limit);
  }
  for (const key of ["since", "until"] as const) {
    const raw = qs.get(key);
    if (raw === null || raw === "") continue;
    const ts = parseQueryTime(raw, nowMs);
    if (ts === null) return errResponse(400, `invalid ${key}`);
    f[key] = ts;
  }
  const bad = validateFilter(f);
  if (bad !== null) return errResponse(400, bad);
  const records = await dbOp("audit query", c.audit.requestId, () => queryAudit(c.db, f));
  return jsonResponse(200, { records });
}

async function notFound(): Promise<Response> {
  return errResponse(404, "not found");
}

/** Resolves a /v1/admin/* request. Anything else under /v1/admin/ is still authenticated and audited. */
export function resolveAdminRoute(method: string, path: string): Route {
  const other: Route = { action: ACTION.other, handler: requireAdmin(notFound) };
  const rest = path.slice("/v1/admin/".length);
  const m = method === "HEAD" ? "GET" : method;
  if (rest === "me" && m === "GET") return { action: ACTION.whoami, handler: requireAdmin(me) };
  if (rest === "audit" && m === "GET") return { action: ACTION.auditRead, handler: requireAdmin(audit) };
  if (rest === "tokens") {
    if (m === "GET") return { action: ACTION.tokenList, handler: requireAdmin(tokenList) };
    if (m === "POST") return { action: ACTION.tokenCreate, handler: requireAdmin(tokenCreate) };
    return other;
  }
  if (rest.startsWith("tokens/") && !rest.slice("tokens/".length).includes("/") && rest.length > "tokens/".length) {
    let name = rest.slice("tokens/".length);
    try {
      name = decodeURIComponent(name);
    } catch {
      // keep raw; fails the name check
    }
    if (m === "PATCH") return { action: ACTION.tokenUpdate, handler: requireAdmin(tokenUpdate), name };
    if (m === "DELETE") return { action: ACTION.tokenRevoke, handler: requireAdmin(tokenRevoke), name };
  }
  return other;
}

