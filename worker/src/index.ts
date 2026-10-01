// Entry point: routing and the per-request pipeline (docs/functional-spec.md
// sections 6 and 9).

import { RESULT, readsData, resultForStatus, writeAudit, type AuditEntry } from "./audit";
import { resolveAdminRoute } from "./admin";
import { authenticate } from "./auth";
import { ConfigError, loadConfig, type Config, type Env } from "./config";
import {
  HttpError,
  NAME_RE,
  clientIp,
  errResponse,
  ipBucketKey,
  jsonResponse,
  logEvent,
  nowSeconds,
  rateLimitedResponse,
  resolveRequestId,
} from "./http";
import { runMaintenance } from "./maintenance";
import { checkLimit } from "./ratelimit";
import { resolveSecretsRoute, type Route } from "./secrets";

export { RateLimiter } from "./ratelimit";

// Forbids inline script/style and any third-party origin, so a secret or
// token name rendered by the page can't turn into markup or script even if
// escaping were ever missed.
const UI_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
  "img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

function withHeaders(res: Response, headers: Record<string, string>): Response {
  // Responses from ASSETS.fetch are immutable; rebuild to add headers.
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(headers)) out.headers.set(k, v);
  return out;
}

async function serveUi(request: Request, env: Env): Promise<Response> {
  const res = await env.ASSETS.fetch(request);
  return withHeaders(res, {
    "Content-Security-Policy": UI_CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
  });
}

/**
 * The pipeline every /v1/secrets* and /v1/admin* request goes through:
 * authentication, rate limit, handler, then exactly one audit row.
 */
async function runApi(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  cfg: Config,
  url: URL,
  route: Route,
  requestId: string,
): Promise<Response> {
  const audit: AuditEntry = {
    tokenName: "",
    action: route.action,
    // Only well-formed names are recorded, so arbitrary client bytes never
    // land in the audit table.
    secretName: route.name !== undefined && NAME_RE.test(route.name) ? route.name : "",
    result: "",
    requestId,
    remoteAddr: clientIp(request),
    written: false,
  };
  let res: Response;
  try {
    const auth = await authenticate(env.DB, ctx, request, nowSeconds(), requestId);
    if (auth.kind === "unauthenticated") {
      // Only failed authentications spend the per-IP budget, so a shared NAT
      // or proxy can't lock out valid tokens behind it.
      const lim = await checkLimit(env, `ip:${ipBucketKey(audit.remoteAddr)}`, cfg.unauthRateLimitPerMinute);
      res = lim.ok ? errResponse(401, "unauthorized") : rateLimitedResponse(lim.waitMs);
    } else {
      audit.tokenName = auth.principal.name;
      const lim = await checkLimit(env, `token:${auth.principal.name}`, cfg.rateLimitPerMinute);
      res = lim.ok
        ? await route.handler({
            env,
            ctx,
            cfg,
            db: env.DB,
            request,
            url,
            principal: auth.principal,
            audit,
            name: route.name ?? "",
          })
        : rateLimitedResponse(lim.waitMs);
    }
  } catch (e) {
    if (e instanceof HttpError) {
      res = errResponse(e.status, e.message);
    } else {
      logEvent("ERROR", "unhandled error", { error: String(e), request_id: requestId });
      res = errResponse(500, "internal error");
    }
  }

  audit.result = resultForStatus(res.status);
  // A successful write has already recorded itself atomically
  // (commitWithAudit); everything else is recorded here.
  if (!audit.written) {
    try {
      await writeAudit(env.DB, audit, nowSeconds());
    } catch (e) {
      logEvent("ERROR", "audit write failed", {
        error: String(e),
        token_name: audit.tokenName,
        action: audit.action,
        secret_name: audit.secretName,
        result: audit.result,
        request_id: requestId,
      });
      // Fail closed for reads: don't hand out data we couldn't record.
      if (audit.result === RESULT.allowed && readsData(route.action)) res = errResponse(500, "audit failed");
    }
  }
  logEvent("INFO", "secret access", {
    token_name: audit.tokenName,
    action: audit.action,
    secret_name: audit.secretName,
    result: audit.result,
    status: res.status,
    remote_addr: audit.remoteAddr,
    request_id: requestId,
  });
  return res;
}

async function route(request: Request, env: Env, ctx: ExecutionContext, requestId: string): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (path === "/healthz") {
    return method === "GET" || method === "HEAD"
      ? jsonResponse(200, { status: "ok" })
      : errResponse(405, "method not allowed", { Allow: "GET, HEAD" });
  }

  const isSecrets = path === "/v1/secrets" || path.startsWith("/v1/secrets/");
  const isAdmin = path.startsWith("/v1/admin/");
  const isUi = path === "/ui" || path.startsWith("/ui/") || path === "/";
  if (!isSecrets && !isAdmin && !isUi) return errResponse(404, "not found");

  let cfg: Config;
  try {
    cfg = await loadConfig(env);
  } catch (e) {
    if (!(e instanceof ConfigError)) throw e;
    logEvent("ERROR", "invalid configuration", { error: e.message, request_id: requestId });
    return errResponse(500, "server misconfigured");
  }

  if (isSecrets) return runApi(request, env, ctx, cfg, url, resolveSecretsRoute(method, path), requestId);

  // The admin API and the UI exist only when ADMIN_API is on.
  if (!cfg.adminApi) return errResponse(404, "not found");
  if (isAdmin) return runApi(request, env, ctx, cfg, url, resolveAdminRoute(method, path), requestId);

  if (method !== "GET" && method !== "HEAD") return errResponse(405, "method not allowed", { Allow: "GET, HEAD" });
  if (path === "/") return new Response(null, { status: 302, headers: { Location: "/ui/" } });
  if (path === "/ui") return new Response(null, { status: 301, headers: { Location: "/ui/" } });
  return serveUi(request, env);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const requestId = resolveRequestId(request);
    let res: Response;
    try {
      res = await route(request, env, ctx, requestId);
    } catch (e) {
      logEvent("ERROR", "unhandled error", { error: String(e), request_id: requestId });
      res = errResponse(500, "internal error");
    }
    // Echoed so a client can correlate a log line to the response it got.
    return withHeaders(res, { "X-Request-ID": requestId });
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      runMaintenance(env, nowSeconds()).catch((e: unknown) =>
        logEvent("ERROR", "maintenance failed", { error: String(e) }),
      ),
    );
  },
} satisfies ExportedHandler<Env>;
