// HTTP helpers shared by every handler: JSON responses, request IDs, client
// IP, bounded body reads and the strict JSON object decoder.

export const MAX_VALUE_BYTES = 64 * 1024;
export const MAX_BODY_BYTES = MAX_VALUE_BYTES + 1024;
// Admin request bodies carry names and prefix lists only.
export const MAX_ADMIN_BODY = 16 * 1024;

/** Secret (and audit target) names: ^[a-zA-Z0-9_.-]{1,128}$ */
export const NAME_RE = /^[a-zA-Z0-9_.-]{1,128}$/;

// Restricts inbound X-Request-ID: permissive for UUID/ULID/hex, strict enough
// to defeat log injection (no CRLF, no quote, bounded length).
const REQUEST_ID_RE = /^[a-zA-Z0-9_-]{1,128}$/;

export function randomHex(nBytes: number): string {
  const b = crypto.getRandomValues(new Uint8Array(nBytes));
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function resolveRequestId(req: Request): string {
  const id = req.headers.get("X-Request-ID") ?? "";
  return REQUEST_ID_RE.test(id) ? id : randomHex(8);
}

const JSON_HEADERS = {
  "Content-Type": "application/json",
  // Defense in depth against any CDN caching authenticated responses.
  "Cache-Control": "no-store",
};

export function jsonResponse(status: number, body: unknown, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(body) + "\n", { status, headers: { ...JSON_HEADERS, ...extra } });
}

export function errResponse(status: number, msg: string, extra?: Record<string, string>): Response {
  return jsonResponse(status, { error: msg }, extra);
}

/** 429 with Retry-After in whole seconds, rounded up, never 0. */
export function rateLimitedResponse(waitMs: number): Response {
  const secs = Math.max(1, Math.ceil(waitMs / 1000));
  return errResponse(429, "rate_limited", { "Retry-After": String(secs) });
}

/**
 * The caller's IP, or "unknown". A Worker is only reachable through
 * Cloudflare's edge, which sets CF-Connecting-IP itself, so it cannot be
 * chosen by the client (this replaces TRUSTED_PROXIES / X-Forwarded-For).
 */
export function clientIp(req: Request): string {
  const v = (req.headers.get("CF-Connecting-IP") ?? "").trim();
  if (v.length > 0 && v.length <= 45 && /^[0-9a-fA-F:.]+$/.test(v)) return v.toLowerCase();
  return "unknown";
}

/**
 * Rate-limit bucket key for an IP. IPv6 clients are grouped by /64: one host
 * normally controls a whole /64, so per-address buckets would be trivially
 * evaded. IPv4 (and "unknown") are used as-is.
 */
export function ipBucketKey(ip: string): string {
  if (!ip.includes(":") || ip.includes(".")) return ip;
  const sides = ip.split("::");
  if (sides.length > 2) return ip;
  const left = sides[0] ? sides[0].split(":") : [];
  const right = sides.length === 2 && sides[1] ? sides[1].split(":") : [];
  let groups: string[];
  if (sides.length === 2) {
    const fill = 8 - left.length - right.length;
    if (fill < 1) return ip;
    groups = [...left, ...Array<string>(fill).fill("0"), ...right];
  } else {
    groups = left;
  }
  if (groups.length !== 8) return ip;
  const head: string[] = [];
  for (const g of groups.slice(0, 4)) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return ip;
    head.push(parseInt(g, 16).toString(16));
  }
  return head.join(":") + "::/64";
}

export type BodyResult = { ok: true; bytes: Uint8Array } | { ok: false; reason: "too_large" | "read_error" };

/**
 * Reads at most `max` bytes. One byte beyond the cap is read so an oversized
 * body is reported as "too large" instead of being silently truncated; the
 * stream is cancelled as soon as the cap is exceeded.
 */
export async function readBodyLimited(req: Request, max: number): Promise<BodyResult> {
  if (!req.body) return { ok: true, bytes: new Uint8Array(0) };
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) {
        await reader.cancel().catch(() => {});
        return { ok: false, reason: "too_large" };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, reason: "read_error" };
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return { ok: true, bytes: out };
}

/** application/json, ignoring case and parameters ("; charset=utf-8"). */
export function isJsonContentType(header: string | null): boolean {
  if (!header) return false;
  const mt = header.split(";")[0]!.trim().toLowerCase();
  return mt === "application/json";
}

export type FieldType = "string" | "bool" | "strings";
export type FieldSpec = Record<string, FieldType>;

/**
 * Strict decoder for a JSON object body, mirroring Go's decoder with
 * DisallowUnknownFields: the top level must be an object, keys must name a
 * known field (exact match, else case-insensitive like encoding/json), and
 * values must have the field's type. A JSON null counts as absent. Returns
 * null for anything invalid.
 */
export function decodeFields(text: string, spec: FieldSpec): Record<string, unknown> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(parsed as Record<string, unknown>)) {
    let field: string | undefined = Object.hasOwn(spec, key) ? key : undefined;
    if (field === undefined) {
      const lower = key.toLowerCase();
      field = Object.keys(spec).find((f) => f.toLowerCase() === lower);
    }
    if (field === undefined) return null;
    if (val === null) continue;
    switch (spec[field]) {
      case "string":
        if (typeof val !== "string") return null;
        break;
      case "bool":
        if (typeof val !== "boolean") return null;
        break;
      case "strings":
        if (!Array.isArray(val) || !val.every((x) => typeof x === "string")) return null;
        break;
    }
    out[field] = val;
  }
  return out;
}

export type JsonBodyResult = { ok: true; value: Record<string, unknown> } | { ok: false; res: Response };

/**
 * Content-type check, bounded read, strict decode, in that order (so the
 * status codes match the Go handlers: 415, then 413, then 400).
 */
export async function readJsonObject(req: Request, maxBytes: number, spec: FieldSpec): Promise<JsonBodyResult> {
  if (!isJsonContentType(req.headers.get("Content-Type"))) {
    return { ok: false, res: errResponse(415, "content-type must be application/json") };
  }
  const body = await readBodyLimited(req, maxBytes);
  if (!body.ok) {
    return body.reason === "too_large"
      ? { ok: false, res: errResponse(413, "request body too large") }
      : { ok: false, res: errResponse(400, "read body") };
  }
  const value = decodeFields(new TextDecoder().decode(body.bytes), spec);
  if (value === null) return { ok: false, res: errResponse(400, "invalid json") };
  return { ok: true, value };
}

/** Thrown by handlers to end the request with a specific error response. */
export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Runs a database operation; any failure is logged (without values) and
 * becomes a 500 "db error", never echoed to the client.
 */
export async function dbOp<T>(what: string, requestId: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    logEvent("ERROR", `${what} failed`, { error: String(e), request_id: requestId });
    throw new HttpError(500, "db error");
  }
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** D1 wants ArrayBuffer for BLOB parameters. */
export function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

/** D1 may hand a BLOB back as ArrayBuffer, typed array or number[]. */
export function blobToBytes(v: unknown): Uint8Array {
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  if (Array.isArray(v)) return Uint8Array.from(v as number[]);
  return new Uint8Array(0);
}

/** One structured log line to Workers Logs; never pass values or tokens. */
export function logEvent(level: "INFO" | "WARN" | "ERROR", msg: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ time: new Date().toISOString(), level, msg, ...fields });
  if (level === "ERROR") console.error(line);
  else if (level === "WARN") console.warn(line);
  else console.log(line);
}
